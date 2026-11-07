#= denials.py  version 0.1.0 (2026-11-07)
#= Parses macOS Seatbelt denial log lines into records and folds duplicates.
#= Line shape (verified on macOS 27.2):  Sandbox: <process>(<pid>) deny(1) <operation> [<target>]
#= Accepted inputs: `log stream|show --style compact` text, `--style ndjson` lines, and bare messages.
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Tuple

_TS = re.compile(r"^\s*(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?)")
#= "N duplicate report(s) for" prefixes a line the kernel log collapsed; the original line was already seen,
#= so such a line adds N occurrences (not N+1).
_MSG = re.compile(
    r"(?:(?P<dups>\d+) duplicate reports? for )?"
    r"Sandbox: (?P<proc>.+?)\((?P<pid>\d+)\) deny\((?P<lvl>\d+)\) "
    r"(?P<op>[A-Za-z0-9_*:.\-]+)(?: (?P<target>.*))?$"
)
_JSON_KEYS = ("eventMessage", "composedMessage", "message")


@dataclass(frozen=True)
class Denial:
    process: str
    pid: int
    op: str
    target: str
    count: int = 1
    ts: Optional[str] = None

    def to_dict(self) -> Dict:
        return {"process": self.process, "pid": self.pid, "op": self.op,
                "target": self.target, "count": self.count, "ts": self.ts}

    @staticmethod
    def from_dict(d: Dict) -> "Denial":
        return Denial(process=str(d["process"]), pid=int(d["pid"]), op=str(d["op"]),
                      target=str(d.get("target", "")), count=int(d.get("count", 1)),
                      ts=d.get("ts"))


@dataclass
class Group:
    """All occurrences of the same (process, operation, target), regardless of pid."""
    process: str
    op: str
    target: str
    count: int = 0
    first_ts: Optional[str] = None
    last_ts: Optional[str] = None
    pids: List[int] = field(default_factory=list)

    @property
    def key(self) -> Tuple[str, str, str]:
        return (self.process, self.op, self.target)

    def to_dict(self) -> Dict:
        return {"process": self.process, "op": self.op, "target": self.target, "count": self.count,
                "first_ts": self.first_ts, "last_ts": self.last_ts, "pids": list(self.pids)}


def parse_line(line: str) -> Optional[Denial]:
    """Parse one log line; return None when it is not a Sandbox denial."""
    text = line.strip()
    if not text:
        return None
    ts: Optional[str] = None
    if text.startswith("{"):
        try:
            obj = json.loads(text)
        except ValueError:
            return None
        if not isinstance(obj, dict):
            return None
        msg = next((obj[k] for k in _JSON_KEYS if isinstance(obj.get(k), str)), None)
        if msg is None:
            return None
        stamp = obj.get("timestamp")
        ts = stamp if isinstance(stamp, str) else None
        text = msg
    else:
        m_ts = _TS.match(text)
        ts = m_ts.group(1) if m_ts else None
    m = _MSG.search(text)
    if not m:
        return None
    dups = m.group("dups")
    return Denial(process=m.group("proc").strip(), pid=int(m.group("pid")), op=m.group("op"),
                  target=(m.group("target") or "").strip(), count=int(dups) if dups else 1, ts=ts)


def parse_lines(lines: Iterable[str]) -> Tuple[List[Denial], int]:
    """Parse many lines. Returns (denials, number of non-empty lines that were not denials)."""
    out: List[Denial] = []
    skipped = 0
    for line in lines:
        if not line.strip():
            continue
        d = parse_line(line)
        if d is None:
            skipped += 1
        else:
            out.append(d)
    return out, skipped


def fold(denials: Iterable[Denial]) -> List[Group]:
    """Merge denials with the same (process, op, target); keep first-seen order."""
    groups: Dict[Tuple[str, str, str], Group] = {}
    for d in denials:
        key = (d.process, d.op, d.target)
        g = groups.get(key)
        if g is None:
            g = Group(process=d.process, op=d.op, target=d.target, first_ts=d.ts)
            groups[key] = g
        g.count += d.count
        if d.ts:
            g.last_ts = d.ts
            if g.first_ts is None:
                g.first_ts = d.ts
        if d.pid not in g.pids:
            g.pids.append(d.pid)
    return list(groups.values())
