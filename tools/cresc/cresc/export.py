#= export.py  version 0.1.0 (2026-11-08)
#= Evidence bundle: everything about ONE run, zipped, with a manifest of SHA-256 hashes so a reader can check that no
#= file was changed afterwards (`verify_bundle`). Tamper-EVIDENT, not tamper-proof: the manifest sits inside the zip, so
#= keep the zip's own hash (returned by build_bundle) somewhere separate if the bundle is used as proof.
#= Layout (under one top folder cresc-evidence-<profile>-run<N>/):
#=   README.md  manifest.json
#=   run/       result.json stdout.txt stderr.txt denials.jsonl           what happened
#=   analysis/  triage.json denials.csv compare-previous.json              what it means
#=   profile/   profile-v<N>.sb meta.json diff-from-previous.diff         the sandbox that was in force
#=   events/    events.jsonl                                              only when an eslogger capture is supplied
#= Safety: program output is escaped (control characters), text is size-capped, your home folder path is replaced by "~"
#= unless redact=False (other personal data is NOT removed: review before sharing), archive entry names are fixed
#= and checked, and verification refuses oversized or path-escaping archives.
from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import platform
import re
import time
import zipfile
from typing import Dict, List, Optional, Sequence, Tuple

from . import SCHEMAS, __version__
from .profile import Profile
from .session import compare_groups, load_run, safe_text
from .triage import summary, triage

MAX_TEXT = 1 << 20            #= per output stream / text file kept in a bundle
MAX_EVENTS = 50 << 20         #= events.jsonl cap
MAX_ENTRIES = 1000            #= verification limits (zip-bomb guard)
MAX_TOTAL = 512 << 20
NAME_OK = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,200}$")


class ExportError(Exception):
    pass


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _redactor(home: str, enabled: bool):
    homes = sorted({h for h in (home, os.path.realpath(home)) if h and h != "/"}, key=len, reverse=True)

    def redact(text: str) -> str:
        if not enabled:
            return text
        for h in homes:
            text = text.replace(h, "~")
        return text
    return redact


def _read_capped(path: str, limit: int) -> Tuple[str, bool, int]:
    """(text, truncated, total bytes) from the start of a file; missing files read as empty."""
    try:
        total = os.path.getsize(path)
        with open(path, "rb") as fh:
            raw = fh.read(limit)
    except OSError:
        return "", False, 0
    return raw.decode("utf-8", "replace"), total > limit, total


def _csv_text(rows: Sequence[Dict], columns: Sequence[str]) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(columns)
    for r in rows:
        writer.writerow([r.get(c, "") for c in columns])
    return buf.getvalue()


def default_bundle_path(store: str, profile: str, number: int) -> str:
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    return os.path.join(store, "exports", "%s-run%d-%s.zip" % (profile, number, stamp))


def build_bundle(profile: Profile, number: int, out_path: str, entries: Sequence[str], home: str,
                 redact: bool = True, force: bool = False, events_file: Optional[str] = None) -> Dict:
    """Write the evidence zip for one run. Returns {path, sha256, bytes, top, files}."""
    if not os.path.isabs(out_path) or not out_path.endswith(".zip"):
        raise ExportError("the output path must be absolute and end in .zip")
    if os.path.exists(out_path) and not force:
        raise ExportError("%s already exists (use force to replace it)" % out_path)
    try:
        res = load_run(profile, number)
    except Exception as exc:
        raise ExportError(str(exc))
    rd = _redactor(home, redact)
    top = "cresc-evidence-%s-run%d" % (profile.name, number)
    files: List[Tuple[str, str, bytes]] = []           #= (archive path, role, data)

    def add(path: str, role: str, text: str) -> None:
        files.append((top + "/" + path, role, rd(text).encode("utf-8")))

    #= ---- run/
    meta = dict(res.meta)
    for k in ("stdout", "stderr"):
        meta[k] = k + ".txt"                            #= the absolute paths on the author's disk mean nothing in a bundle
    add("run/result.json", "run record", json.dumps(meta, indent=2, sort_keys=True) + "\n")
    notes = []
    for stream in ("stdout", "stderr"):
        text, truncated, total = _read_capped(os.path.join(res.directory, stream + ".txt"), MAX_TEXT)
        body = safe_text(text)
        if truncated:
            body += "\n[cresc: truncated, first %d of %d bytes kept]\n" % (MAX_TEXT, total)
            notes.append("%s truncated to %d bytes" % (stream, MAX_TEXT))
        add("run/%s.txt" % stream, "program output (control characters escaped)", body)
    raw_denials, _, _ = _read_capped(os.path.join(res.directory, "denials.jsonl"), MAX_TEXT * 4)
    add("run/denials.jsonl", "sandbox denials as logged", raw_denials)

    #= ---- analysis/
    items = triage(res.groups, entries, home)
    payload = {"schema": SCHEMAS["triage"], "run": number, "summary": summary(items), "items": [i.to_dict() for i in items]}
    add("analysis/triage.json", "classification and suggested rules", json.dumps(payload, indent=2, sort_keys=True) + "\n")
    rows = []
    for i in items:
        d = i.to_dict()
        rows.append({"class": d["class"], "risk": d["risk"], "process": d["process"], "op": d["op"], "target": d["target"],
                     "count": d["count"], "rule": (d.get("rule") or {}).get("text", ""), "reason": d["reason"]})
    add("analysis/denials.csv", "denial groups as CSV", _csv_text(rows, ["class", "risk", "process", "op", "target", "count", "rule", "reason"]))
    previous = number - 1
    compared = None
    while previous >= 1 and compared is None:
        try:
            compared = load_run(profile, previous)
        except Exception:
            previous -= 1
    if compared is not None:
        cmp = compare_groups(compared.groups, res.groups)
        cmp.update({"schema": "cresc.compare/1", "a": previous, "b": number})
        add("analysis/compare-previous.json", "what changed since run %d" % previous, json.dumps(cmp, indent=2, sort_keys=True) + "\n")

    #= ---- profile/
    version = int(res.meta.get("profile_version", profile.version))
    try:
        add("profile/profile-v%d.sb" % version, "the sandbox profile this run used", profile.snapshot(version))
    except Exception as exc:
        notes.append("profile snapshot v%d unavailable: %s" % (version, exc))
    add("profile/meta.json", "profile grants and history (current state)",
        json.dumps({"name": profile.name, "version": profile.version, "grants": profile.grants, "history": profile.history()},
                   indent=2, sort_keys=True) + "\n")
    if version > 1:
        try:
            add("profile/diff-from-previous.diff", "profile change that led to this run", profile.diff(version - 1, version))
        except Exception:
            pass

    #= ---- events/ (optional)
    if events_file:
        if not os.path.isabs(events_file) or not os.path.isfile(events_file):
            raise ExportError("events_file must be an existing absolute path")
        text, truncated, total = _read_capped(events_file, MAX_EVENTS)
        if truncated:
            text = text[:text.rfind("\n") + 1] if "\n" in text else text      #= end on a whole line
            notes.append("events truncated to the first %d bytes of %d" % (MAX_EVENTS, total))
        add("events/events.jsonl", "eslogger capture supplied by the user", text)

    #= ---- README + manifest
    created = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    listing = "\n".join("- `%s` - %s" % (p[len(top) + 1:], role) for p, role, _ in files)
    readme = """---
title: "Evidence bundle: %(profile)s run %(run)d"
description: "Sandbox run record, denials, analysis and profile for one cresc run, with SHA-256 manifest."
slug: cresc-evidence-%(profile)s-run%(run)d
author: "cresc %(ver)s"
type: evidence
date-created: %(created)s
date-modified: %(created)s
date-published:
source: "cresc export"
domain: macos-security
url:
draft: true
tags:
  - sandbox
  - evidence
keywords:
  - cresc
  - sandbox-exec
---

# Evidence bundle: %(profile)s run %(run)d

Program: `%(target)s`  Exit: `%(exit)s`  Profile version: `%(version)d`  Created: %(created)s

## Files
%(listing)s
- `manifest.json` - SHA-256 and size of every file above

## Verify
```bash
python3 -m cresc verify-bundle <this-file>.zip
```
The manifest is inside the archive, so this shows the files are consistent with it, not who wrote it. For proof, record the
zip's own SHA-256 elsewhere when you create it.

## Notes
- Program output has control characters escaped; output is capped at %(cap)d bytes per stream.
- %(redaction)s
- Environment values are never stored (names only, in `run/result.json`).
%(notes)s
""" % {"profile": profile.name, "run": number, "ver": __version__, "created": created, "target": rd(str(res.meta.get("target", ""))),
       "exit": res.meta.get("exit"), "version": version, "listing": listing, "cap": MAX_TEXT,
       "redaction": ("Your home folder path was replaced by `~`. Other personal data (user name inside other strings, hostnames, "
                     "file names) is not removed: review before sharing.") if redact else "NOT redacted: paths are as on the original machine.",
       "notes": "".join("- %s\n" % n for n in notes)}
    files.insert(0, (top + "/README.md", "this file", readme.encode("utf-8")))

    manifest = {
        "schema": SCHEMAS["bundle"], "created": created, "tool": "cresc", "tool_version": __version__,
        "profile": profile.name, "run": number, "profile_version": version, "redacted": bool(redact),
        "host": {"system": platform.system(), "release": platform.release(), "machine": platform.machine(),
                 "macos": platform.mac_ver()[0], "python": platform.python_version()},
        "notes": notes,
        "files": [{"path": p[len(top) + 1:], "role": role, "bytes": len(data), "sha256": _sha256(data)} for p, role, data in files],
    }
    manifest_bytes = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")
    files.append((top + "/manifest.json", "manifest", manifest_bytes))

    #= ---- write (temp file, then rename: never a half-written zip under the final name)
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    tmp = out_path + ".part"
    stamp = time.gmtime()[:6]
    try:
        with zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as zf:
            for name, _role, data in files:
                if not NAME_OK.match(name) or ".." in name.split("/"):
                    raise ExportError("internal: unsafe archive name %r" % name)
                info = zipfile.ZipInfo(name, date_time=stamp)
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = 0o644 << 16
                zf.writestr(info, data)
        os.replace(tmp, out_path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    with open(out_path, "rb") as fh:
        blob = fh.read()
    return {"path": out_path, "sha256": _sha256(blob), "bytes": len(blob), "top": top,
            "files": [p[len(top) + 1:] for p, _r, _d in files]}


def verify_bundle(path: str) -> Dict:
    """Check an evidence zip against its manifest. Returns {ok, checked, problems, manifest}; never raises on bad content."""
    problems: List[str] = []
    try:
        zf = zipfile.ZipFile(path)
    except (OSError, zipfile.BadZipFile) as exc:
        return {"ok": False, "checked": 0, "problems": ["cannot open archive: %s" % exc], "manifest": None}
    with zf:
        infos = zf.infolist()
        if len(infos) > MAX_ENTRIES or sum(i.file_size for i in infos) > MAX_TOTAL:
            return {"ok": False, "checked": 0, "problems": ["archive is too large to verify safely"], "manifest": None}
        names = {}
        for i in infos:
            n = i.filename
            if n.startswith("/") or ".." in n.split("/") or "\\" in n:
                problems.append("unsafe entry name: %r" % n)
            names[n] = i
        tops = {n.split("/", 1)[0] for n in names}
        if len(tops) != 1:
            return {"ok": False, "checked": 0, "problems": problems + ["expected exactly one top folder"], "manifest": None}
        top = tops.pop()
        mname = top + "/manifest.json"
        if mname not in names:
            return {"ok": False, "checked": 0, "problems": problems + ["manifest.json is missing"], "manifest": None}
        try:
            manifest = json.loads(zf.read(mname).decode("utf-8"))
            listed = manifest["files"]
        except (ValueError, KeyError, UnicodeDecodeError):
            return {"ok": False, "checked": 0, "problems": problems + ["manifest.json is unreadable"], "manifest": None}
        checked = 0
        seen = set()
        for entry in listed:
            rel = entry.get("path", "") if isinstance(entry, dict) else ""
            full = top + "/" + rel
            seen.add(full)
            if full not in names:
                problems.append("missing: %s" % rel)
                continue
            data = zf.read(full)
            checked += 1
            if len(data) != entry.get("bytes"):
                problems.append("size differs: %s" % rel)
            if _sha256(data) != entry.get("sha256"):
                problems.append("hash differs: %s" % rel)
        for n in names:
            if n not in seen and n != mname and not n.endswith("/"):
                problems.append("not in manifest: %s" % n[len(top) + 1:])
    return {"ok": not problems, "checked": checked, "problems": problems, "manifest": manifest}
