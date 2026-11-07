#= profile.py  version 0.1.0 (2026-11-07)
#= Versioned sandbox profiles: a baseline plus approved grants. Every change makes an immutable vN.sb snapshot,
#= so any run can be reproduced and any grant can be revoked or diffed.
#= Layout:  <store>/profiles/<name>/{profile.json, baseline.sb, history.jsonl, v1.sb, v2.sb, ..., runs/}
from __future__ import annotations

import difflib
import json
import os
import re
import tempfile
import time
from typing import Dict, List, Optional, Tuple

from . import SCHEMAS
from .rules import Rule

NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_BASELINE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "baseline.sb")
_GRANT_HEADER = ";= --- grants managed by fsx (change them with `fsx profile`, not by hand) ---"


class ProfileError(Exception):
    pass


def default_store() -> str:
    return os.environ.get("FSX_HOME") or os.path.join(os.path.expanduser("~"), ".local", "share", "fsx")


def validate_sbpl(text: str) -> None:
    """Cheap structural check: parentheses balance outside strings and comments. Raises ProfileError."""
    depth = 0
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c == ";":                       #= comment to end of line
            while i < n and text[i] != "\n":
                i += 1
            continue
        if c == '"':                       #= string with backslash escapes
            i += 1
            while i < n and text[i] != '"':
                i += 2 if text[i] == "\\" else 1
            if i >= n:
                raise ProfileError("unterminated string in profile")
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth < 0:
                raise ProfileError("unbalanced ')' in profile")
        i += 1
    if depth != 0:
        raise ProfileError("unbalanced '(' in profile (%d open)" % depth)


def _clean(note: str, limit: int = 120) -> str:
    return " ".join("".join(ch if ch.isprintable() else " " for ch in note).split())[:limit]


def render_profile(baseline: str, grants: List[Dict]) -> str:
    out = [baseline.rstrip("\n"), "", _GRANT_HEADER]
    for g in grants:
        note = _clean(g.get("note", ""))
        out.append(";= grant %s v%d risk=%s%s" % (g["id"], g["version"], g["risk"], (" " + note) if note else ""))
        out.append(g["text"])
    return "\n".join(out) + "\n"


def _atomic_write(path: str, text: str) -> None:
    d = os.path.dirname(path)
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".tmp-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S%z")


class Profile:
    def __init__(self, directory: str, meta: Dict, baseline: str):
        self.dir = directory
        self.meta = meta
        self.baseline = baseline

    #= ---- construction -------------------------------------------------------------------------------
    @staticmethod
    def _dir(store: str, name: str) -> str:
        if not NAME_RE.match(name or ""):
            raise ProfileError("invalid profile name %r (letters, digits, . _ - ; max 64)" % name)
        return os.path.join(store, "profiles", name)

    @classmethod
    def create(cls, store: str, name: str, baseline: Optional[str] = None) -> "Profile":
        d = cls._dir(store, name)
        if os.path.exists(d):
            raise ProfileError("profile %r already exists" % name)
        text = baseline if baseline is not None else open(_BASELINE, encoding="utf-8").read()
        validate_sbpl(text)
        os.makedirs(d)
        meta = {"schema": SCHEMAS["profile"], "name": name, "version": 1, "grants": [], "created": _now()}
        p = cls(d, meta, text)
        _atomic_write(os.path.join(d, "baseline.sb"), text)
        _atomic_write(p.snapshot_path(1), render_profile(text, []))
        p._save_meta()
        p._history({"version": 1, "action": "create"})
        return p

    @classmethod
    def load(cls, store: str, name: str) -> "Profile":
        d = cls._dir(store, name)
        meta_path = os.path.join(d, "profile.json")
        if not os.path.isfile(meta_path):
            raise ProfileError("profile %r not found in %s" % (name, store))
        with open(meta_path, encoding="utf-8") as fh:
            meta = json.load(fh)
        with open(os.path.join(d, "baseline.sb"), encoding="utf-8") as fh:
            baseline = fh.read()
        return cls(d, meta, baseline)

    @staticmethod
    def list_names(store: str) -> List[str]:
        root = os.path.join(store, "profiles")
        if not os.path.isdir(root):
            return []
        return sorted(n for n in os.listdir(root) if os.path.isfile(os.path.join(root, n, "profile.json")))

    #= ---- accessors ----------------------------------------------------------------------------------
    @property
    def name(self) -> str:
        return self.meta["name"]

    @property
    def version(self) -> int:
        return int(self.meta["version"])

    @property
    def grants(self) -> List[Dict]:
        return list(self.meta["grants"])

    def snapshot_path(self, version: Optional[int] = None) -> str:
        v = self.version if version is None else int(version)
        return os.path.join(self.dir, "v%d.sb" % v)

    def snapshot(self, version: Optional[int] = None) -> str:
        path = self.snapshot_path(version)
        if not os.path.isfile(path):
            raise ProfileError("profile %r has no version %s" % (self.name, version))
        with open(path, encoding="utf-8") as fh:
            return fh.read()

    def runs_dir(self) -> str:
        return os.path.join(self.dir, "runs")

    #= ---- changes ------------------------------------------------------------------------------------
    def grant(self, rule: Rule, risk: str, note: str = "", source: str = "") -> Tuple[int, bool]:
        """Add a rule; returns (version, changed). Granting the same rule twice is a no-op."""
        rid = rule.id
        if any(g["id"] == rid for g in self.meta["grants"]):
            return self.version, False
        new_version = self.version + 1
        entry = {"id": rid, "text": rule.render(), "op": rule.op, "kind": rule.fkind, "value": rule.fvalue,
                 "risk": risk, "verified": rule.verified, "note": note or rule.note, "source": source,
                 "added": _now(), "version": new_version}
        grants = self.meta["grants"] + [entry]
        self._commit(new_version, grants, {"action": "grant", "grant": rid, "risk": risk})
        return new_version, True

    def revoke(self, grant_id: str) -> int:
        if not any(g["id"] == grant_id for g in self.meta["grants"]):
            raise ProfileError("no grant with id %r in profile %r" % (grant_id, self.name))
        new_version = self.version + 1
        grants = [g for g in self.meta["grants"] if g["id"] != grant_id]
        self._commit(new_version, grants, {"action": "revoke", "grant": grant_id})
        return new_version

    def _commit(self, new_version: int, grants: List[Dict], event: Dict) -> None:
        text = render_profile(self.baseline, grants)
        validate_sbpl(text)                        #= never persist a profile that does not even parse
        _atomic_write(self.snapshot_path(new_version), text)
        self.meta["grants"] = grants
        self.meta["version"] = new_version
        self._save_meta()
        event = dict(event, version=new_version)
        self._history(event)

    def _save_meta(self) -> None:
        _atomic_write(os.path.join(self.dir, "profile.json"), json.dumps(self.meta, indent=2) + "\n")

    def _history(self, event: Dict) -> None:
        event = dict(event, ts=_now())
        with open(os.path.join(self.dir, "history.jsonl"), "a", encoding="utf-8") as fh:
            fh.write(json.dumps(event) + "\n")

    #= ---- reading history ----------------------------------------------------------------------------
    def history(self) -> List[Dict]:
        path = os.path.join(self.dir, "history.jsonl")
        if not os.path.isfile(path):
            return []
        with open(path, encoding="utf-8") as fh:
            return [json.loads(line) for line in fh if line.strip()]

    def diff(self, a: int, b: int) -> str:
        return "".join(difflib.unified_diff(self.snapshot(a).splitlines(True), self.snapshot(b).splitlines(True),
                                            fromfile="v%d.sb" % a, tofile="v%d.sb" % b))
