#= rules.py  version 0.1.0 (2026-11-07)
#= Turns a denial into the narrowest SBPL allow rule that would permit it, and renders rules safely.
#= Generated rules are ALLOWS only (measured semantics: docs/sandbox-semantics.md).
#= Network grants are protocol+port only: sandbox filters accept only `*` or `localhost` as host.
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence

from .denials import Group

_OP_RE = re.compile(r"^[a-z][a-z0-9*\-]*$")
_PLAIN_FILTERS = {"literal", "subpath", "prefix", "sysctl-name", "sysctl-name-prefix",
                  "global-name", "iokit-property"}
_REMOTE_FILTERS = {"remote-tcp": "tcp", "remote-udp": "udp", "remote-ip": "ip"}
_FILE_READ_OPS = {"file-read-metadata", "file-read-data", "file-read*", "file-read-xattr",
                  "file-test-existence"}
_HOSTPORT = re.compile(r"^(?P<host>\*|localhost|\[[0-9a-fA-F:]+\]|[0-9a-fA-F:.]+):(?P<port>\d{1,5}|\*)$")


def q(value: str) -> str:
    """Quote a string for SBPL; control characters (including newlines) are refused."""
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in value):
        raise ValueError("control character in SBPL string")
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


@dataclass(frozen=True)
class Rule:
    op: str
    fkind: Optional[str] = None      #= literal | subpath | sysctl-name | global-name | remote-tcp | ...
    fvalue: Optional[str] = None
    verified: bool = True            #= syntax and semantics measured on a real macOS
    confirm: bool = False            #= needs an explicit confirmation before it is granted
    note: str = ""

    def render(self) -> str:
        if not _OP_RE.match(self.op):
            raise ValueError("invalid operation name: %r" % self.op)
        if self.fkind is None:
            return "(allow %s)" % self.op
        if self.fvalue is None:
            raise ValueError("filter value missing")
        if self.fkind in _PLAIN_FILTERS:
            return "(allow %s (%s %s))" % (self.op, self.fkind, q(self.fvalue))
        if self.fkind in _REMOTE_FILTERS:
            return "(allow %s (remote %s %s))" % (self.op, _REMOTE_FILTERS[self.fkind], q(self.fvalue))
        if self.fkind == "remote-unix-socket":
            return "(allow %s (remote unix-socket (path-literal %s)))" % (self.op, q(self.fvalue))
        raise ValueError("unknown filter kind: %r" % self.fkind)

    @property
    def id(self) -> str:
        return hashlib.sha1(self.render().encode("utf-8")).hexdigest()[:10]

    def to_dict(self) -> Dict:
        return {"id": self.id, "text": self.render(), "op": self.op, "kind": self.fkind,
                "value": self.fvalue, "verified": self.verified, "confirm": self.confirm, "note": self.note}


def _network_rule(op: str, target: str) -> Optional[Rule]:
    if target.startswith("/"):
        return Rule(op, "remote-unix-socket", target, verified=False, confirm=True,
                    note="Unix-domain socket; this rule's syntax has not been measured yet")
    m = _HOSTPORT.match(target)
    if not m:
        return None
    host = "localhost" if m.group("host") in ("localhost", "127.0.0.1", "::1", "[::1]") else "*"
    return Rule(op, "remote-tcp", "%s:%s" % (host, m.group("port")), verified=True, confirm=True,
                note="port-level only: sandbox filters accept just * or localhost as host; protocol assumed tcp")


def synthesize(group: Group) -> Optional[Rule]:
    """The narrowest allow rule for a denial, or None when no safe automatic rule exists."""
    op, t = group.op, group.target
    try:
        if op == "sysctl-read" and t:
            rule: Optional[Rule] = Rule(op, "sysctl-name", t)
        elif op in _FILE_READ_OPS and t.startswith("/"):
            rule = Rule(op, "literal", t)
        elif op.startswith("file-write") and t.startswith("/"):
            rule = Rule(op, "literal", t, confirm=True,
                        note="write grant: prefer a dedicated writable directory (--write-dir)")
        elif op == "mach-lookup" and t:
            rule = Rule(op, "global-name", t)
        elif op in ("process-exec", "process-exec*") and t.startswith("/"):
            rule = Rule(op, "literal", t, confirm=True, note="lets the program start another executable")
        elif op == "process-fork":
            rule = Rule(op, None, None, confirm=True, note="lets the program start child processes")
        elif op == "network-outbound":
            rule = _network_rule(op, t)
        else:
            rule = None
        if rule is not None:
            rule.render()   #= validate now so a bad target never reaches a profile
        return rule
    except ValueError:
        return None


def prefix_suggestions(rules: Sequence[Rule], min_group: int = 3) -> List[Rule]:
    """When several sysctl-name rules share a dotted prefix, offer one broader prefix rule as an alternative."""
    buckets: Dict[str, int] = {}
    for r in rules:
        if r.op == "sysctl-read" and r.fkind == "sysctl-name" and r.fvalue:
            parts = r.fvalue.split(".")
            if len(parts) >= 3:
                buckets["%s.%s." % (parts[0], parts[1])] = buckets.get("%s.%s." % (parts[0], parts[1]), 0) + 1
    return [Rule("sysctl-read", "sysctl-name-prefix", prefix, note="covers %d observed names; broader than needed" % n)
            for prefix, n in sorted(buckets.items()) if n >= min_group]
