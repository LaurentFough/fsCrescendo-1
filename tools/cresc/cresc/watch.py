#= watch.py  version 0.1.0 (2026-11-08)
#= Streams eslogger JSON lines through the normaliser and a scope filter, counting what was read, shown, skipped
#= and dropped. Privilege model: only Apple's eslogger runs as root (`sudo eslogger ... | cresc watch`);
#= cresc itself never needs root and just reads JSON from a file or a pipe.
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Callable, Dict, Iterable, Optional

from .events import Event, parse_event
from .scope import Filter
from .session import safe_text


@dataclass
class Stats:
    read: int = 0                  #= events parsed
    shown: int = 0                 #= events that passed the filter
    skipped: int = 0               #= non-empty lines that were not events
    dropped: int = 0               #= events missing according to gaps in global_seq_num
    by_kind: Dict[str, int] = field(default_factory=dict)
    last_seq: Optional[int] = None

    def to_dict(self) -> Dict:
        return {"read": self.read, "shown": self.shown, "skipped_lines": self.skipped, "dropped": self.dropped,
                "by_kind": dict(sorted(self.by_kind.items(), key=lambda kv: -kv[1]))}


def _clock(ts: Optional[str]) -> str:
    #= "2026-11-08T12:00:00.123456Z" -> "12:00:00.123"
    if ts and len(ts) >= 19 and ts[10] in "T ":
        return ts[11:23] if len(ts) >= 23 and ts[19] == "." else ts[11:19]
    return ""


def format_event(ev: Event) -> str:
    """One readable line. Everything here comes from files and programs we do not trust, so it is escaped."""
    if ev.kind == "proc.exec":
        args = " ".join(ev.details.get("args", [])[1:])
        what = ev.target + ((" " + args) if args else "")
    elif ev.kind == "proc.fork":
        what = "-> pid %s" % ev.details.get("child_pid", "?")
    elif ev.kind == "proc.exit":
        what = "status %s" % ev.details.get("status", "?")
    elif ev.kind == "file.rename":
        what = "%s -> %s" % (ev.target, ev.target2)
    elif ev.kind == "file.open":
        what = ("[write] " if ev.details.get("writing") else "") + ev.target
    elif ev.kind == "file.close":
        what = ("[modified] " if ev.details.get("modified") else "") + ev.target
    elif ev.kind == "sandbox.deny":
        what = ev.target
    else:
        what = ev.target + ((" -> " + ev.target2) if ev.target2 else "")
    return safe_text("%-12s %-13s %6s %-18s %s" % (_clock(ev.ts), ev.kind, ev.pid, ev.name[:18], what)).rstrip()


HEADER = "%-12s %-13s %6s %-18s %s" % ("TIME", "KIND", "PID", "PROCESS", "DETAIL")


def denial_event(process: str, pid: int, op: str, target: str, ts: Optional[str] = None) -> Event:
    return Event(kind="sandbox.deny", ts=ts, pid=pid, process=process, target="%s %s" % (op, target),
                 details={"op": op, "target": target})


def run_watch(lines: Iterable[str], flt: Filter, emit: Callable[[Event], None], stats: Optional[Stats] = None,
              limit: Optional[int] = None) -> Stats:
    st = stats or Stats()
    for line in lines:
        ev = parse_event(line)
        if ev is None:
            if line.strip():
                st.skipped += 1
            continue
        st.read += 1
        st.by_kind[ev.kind] = st.by_kind.get(ev.kind, 0) + 1
        if ev.seq is not None:
            if st.last_seq is not None and ev.seq > st.last_seq + 1:
                st.dropped += ev.seq - st.last_seq - 1        #= a gap in the global sequence = events we never saw
            st.last_seq = ev.seq if st.last_seq is None else max(st.last_seq, ev.seq)
        if flt.accept(ev):
            st.shown += 1
            emit(ev)
            if limit is not None and st.shown >= limit:
                break
    return st


def json_line(ev: Event) -> str:
    return json.dumps(ev.to_dict(), sort_keys=True)       #= control characters are \u-escaped by json
