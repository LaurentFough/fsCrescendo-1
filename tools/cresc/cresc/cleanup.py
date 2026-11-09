#= cleanup.py  version 0.1.0 (2026-11-09)
#= Cleanup ("pruning") modes for file changes (cresc.filechange/1): hide the transient noise that does not contribute to the
#= state left on disk, the way a file-activity monitor does.
#=   none      every change as it happened
#=   coalesce  repeated modified / attributes rows of one file collapse into one row (count, first_ts in details)
#=   prune     coalesce, plus
#=               - a file created and deleted inside the window (a temp file) disappears completely
#=               - "atomic save" (write a temp file, rename it over the target) becomes ONE modified row of the target,
#=                 and a created file that was only renamed becomes ONE created row at its final name
#= Files are followed by their current PATH through renames (inode alone is unreliable: hard links share one).
#= Streaming use: Cleaner.feed() per change, Cleaner.settle() on a timer, Cleaner.flush() at the end. Rows leave the cleaner
#= only after their file has been quiet for `window` seconds, so cleaned output lags live output by about that long.
#= Pure logic, no I/O; time is passed in, so tests do not sleep.
from __future__ import annotations

import time
from dataclasses import replace
from typing import Dict, List, Optional, Tuple

from .filechange import FileChange

MODES = ("none", "coalesce", "prune")


class _Obj:
    """One file as it is followed through the buffer."""

    def __init__(self, born: bool) -> None:
        self.rows: List[Tuple[int, FileChange]] = []      #= (arrival order, change)
        self.born = born                                  #= created at its current path inside the buffer
        self.deleted = False
        self.moved = False
        self.replaced = False                             #= arrived by renaming over an existing file
        self.last_seen = 0.0

    def add(self, order: int, change: FileChange, now: float) -> None:
        self.rows.append((order, change))
        self.last_seen = now


def _key(row: Tuple[int, FileChange]) -> Tuple[str, int, int]:
    order, c = row
    return (c.ts or "", c.seq if c.seq is not None else 0, order)


class Cleaner:
    def __init__(self, mode: str = "none", window: float = 2.0, max_open: int = 20000) -> None:
        if mode not in MODES:
            raise ValueError("cleanup mode must be one of %s" % ", ".join(MODES))
        self.mode = mode
        self.window = max(0.0, float(window))
        self.max_open = max_open
        self._live: Dict[str, _Obj] = {}                  #= current path -> file
        self._moving: Dict[str, _Obj] = {}                #= source path of a rename in flight -> file
        self._done: List[Tuple[int, FileChange]] = []     #= rows of closed files waiting to be emitted in order
        self._order = 0

    #= ---- feeding ---------------------------------------------------------------------------------------------
    def feed(self, c: FileChange, now: Optional[float] = None) -> List[FileChange]:
        if self.mode == "none":
            return [c]
        now = time.monotonic() if now is None else now
        self._order += 1
        order = self._order
        if c.category == "meta":
            out = self.flush()
            out.append(c)
            return out
        if c.category == "created":
            old = self._live.get(c.path)
            last = old.rows[-1][1] if old is not None and old.rows else None
            if (old is not None and old.born and not old.deleted and last is not None
                    and last.category == "created" and last.pid == c.pid):
                old.add(order, c, now)                    #= a clone (or link) announces its new file twice: still one creation
            else:
                if old is not None:
                    self._live.pop(c.path)
                    self._close(old)                      #= created over a path we still tracked: the old file is history
                obj = _Obj(born=True)
                obj.add(order, c, now)
                self._live[c.path] = obj
        elif c.category == "moved_from":
            obj = self._live.pop(c.path, None) or _Obj(born=False)
            obj.add(order, c, now)
            dest = str(c.details.get("destination", ""))
            self._moving[dest or c.path] = obj
        elif c.category == "moved_to":
            obj = self._moving.pop(c.path, None) or self._moving.pop(c.source_path, None) or _Obj(born=False)
            replaced = bool(c.details.get("replaced"))
            previous = self._live.pop(c.path, None)
            if replaced and previous is not None:
                #= the target we tracked is overwritten: its life and this one are the same lifetime of the PATH
                obj.rows = previous.rows + obj.rows
                obj.born = previous.born
            elif replaced:
                obj.born = False                          #= overwrote a file that already existed before the buffer
            elif previous is not None:
                self._close(previous)
            obj.moved = True
            obj.replaced = replaced or obj.replaced
            obj.add(order, c, now)
            self._live[c.path] = obj
        elif c.category == "deleted":
            obj = self._live.pop(c.path, None) or _Obj(born=False)
            obj.add(order, c, now)
            obj.deleted = True
            self._close(obj)
        else:                                             #= modified / attributes
            obj = self._live.get(c.path)
            if obj is None:
                obj = _Obj(born=False)
                self._live[c.path] = obj
            obj.add(order, c, now)
        if len(self._live) > self.max_open:
            return self.settle(now, force_oldest=len(self._live) - self.max_open)
        return self.settle(now)

    #= ---- emitting --------------------------------------------------------------------------------------------
    def settle(self, now: Optional[float] = None, force_oldest: int = 0) -> List[FileChange]:
        """Rows of files that have been quiet for `window` seconds (and of closed files whose window has passed)."""
        if self.mode == "none":
            return []
        now = time.monotonic() if now is None else now
        quiet = [p for p, o in self._live.items() if now - o.last_seen >= self.window]
        if force_oldest:
            quiet = sorted(self._live, key=lambda p: self._live[p].last_seen)[:force_oldest] + quiet
        for path in dict.fromkeys(quiet):
            obj = self._live.pop(path, None)
            if obj is not None:
                self._close(obj)
        return self._drain(now)

    def flush(self) -> List[FileChange]:
        """Everything still held (end of recording, or before a meta row)."""
        if self.mode == "none":
            return []
        for obj in list(self._moving.values()):           #= a rename whose second half never arrived
            if obj not in self._live.values():
                self._close(obj)
        self._moving.clear()
        for path in list(self._live):
            self._close(self._live.pop(path))
        return self._drain(float("inf"))

    def _drain(self, now: float) -> List[FileChange]:
        ready = sorted(self._done, key=_key)
        self._done = []
        return [c for _order, c in ready]

    def _close(self, obj: _Obj) -> None:
        self._done.extend(self._finalise(obj))

    #= ---- the rules -------------------------------------------------------------------------------------------
    def _finalise(self, obj: _Obj) -> List[Tuple[int, FileChange]]:
        rows = sorted(obj.rows, key=_key)
        if not rows:
            return []
        if self.mode == "prune":
            if obj.born and obj.deleted:
                return []                                 #= created and deleted: a temp file, nothing was left behind
            if rows[0][1].category == "created" and obj.moved and not obj.deleted:
                return [self._collapse_created_then_moved(obj, rows)]
        return self._coalesce(rows)

    @staticmethod
    def _collapse_created_then_moved(obj: _Obj, rows: List[Tuple[int, FileChange]]) -> Tuple[int, FileChange]:
        """created temp -> (modified...) -> renamed to its final name = one row at the final name."""
        first, last = rows[0][1], rows[-1]
        final = last[1]
        if obj.born:                                      #= the final name did not exist before
            category, text = "created", "Item Created"
        else:                                             #= it replaced an existing file: an atomic save
            category, text = "modified", "Content Replaced"
        merged = replace(first, category=category, event_type=text, path=final.path, ts=final.ts, seq=final.seq,
                         source_path=first.path, count=sum(max(1, r[1].count) for r in rows))
        merged.details = dict(first.details, collapsed=True, first_ts=first.ts, via="rename")
        return (last[0], merged)

    @staticmethod
    def _coalesce(rows: List[Tuple[int, FileChange]]) -> List[Tuple[int, FileChange]]:
        """Merge repeated modified / attributes rows of one file (same kind, text and process) even when other rows are
        interleaved; created / moved / deleted rows end a segment, because they change what the file is."""
        out: List[Tuple[int, FileChange]] = []
        segment: Dict[Tuple[str, str, str, int], int] = {}      #= (category, path, text, pid) -> index in out
        for order, c in rows:
            if c.category in ("modified", "attributes"):
                key = (c.category, c.path, c.event_type, c.pid)
                if key in segment:
                    i = segment[key]
                    prev = out[i][1]
                    merged = replace(c, count=prev.count + max(1, c.count))
                    merged.details = dict(c.details, first_ts=prev.details.get("first_ts", prev.ts), coalesced=True)
                    out[i] = (order, merged)                    #= the newest timestamp wins; output is re-sorted by time anyway
                else:
                    segment[key] = len(out)
                    out.append((order, c))
                continue
            prev = out[-1][1] if out else None
            if prev is not None and c.category == prev.category == "created" and prev.path == c.path and prev.pid == c.pid:
                merged = replace(prev, count=prev.count + max(1, c.count))      #= clone + create of one file: keep the first
                merged.details = dict(prev.details, coalesced=True)
                out[-1] = (order, merged)
                continue
            segment.clear()
            out.append((order, c))
        return out


def clean(changes: List[FileChange], mode: str = "prune") -> List[FileChange]:
    """Batch convenience (recordings, tests): feed everything at one instant, flush, return the cleaned rows."""
    cleaner = Cleaner(mode, window=float("inf"))      #= nothing settles early: all rows leave at flush()
    out: List[FileChange] = []
    for c in changes:
        out += cleaner.feed(c, now=0.0)
    out += cleaner.flush()
    out.sort(key=lambda c: (c.ts or "", c.seq if c.seq is not None else 0))      #= files closed at different moments: restore time order
    return out
