#= recording.py  version 0.1.0 (2026-11-09)
#= Recordings (`.crescrec`): saved activity that can be reopened, verified, exported and replayed.
#= Format: JSON lines.
#=   line 1   header  {"schema": "cresc.recording/1", "kind": "live-capture"|"run-session", "created", "tool_version", "host", ...}
#=   records  {"type": "change"|"event"|"denial"|"run"|"grant"|"note", "t": seconds since the start, "data": {...}}
#=   last     footer  {"type": "end", "records": N, "sha256": <hash of every byte before this line>, "ended", "duration_s"}
#= `change` data is cresc.filechange/1, `event` data is cresc.event/1. A recording without a footer (crash, or still being
#= written as <name>.part) can be read; verification then reports it as incomplete.
#= Verification is tamper-EVIDENT only (the hash is stored in the same file); keep the file's own SHA-256 elsewhere if it is proof.
#= The player replays records at their recorded cadence with speed, pause and seek, so a replay behaves like live capture.
from __future__ import annotations

import bisect
import csv
import hashlib
import io
import json
import os
import platform
import socket
import threading
import time
from typing import Any, Callable, Dict, Iterator, List, Optional

from . import SCHEMAS, __version__

EXT = ".crescrec"
MAX_RECORDS = 5_000_000
MAX_BYTES = 2 << 30
MAX_LINE = 4 << 20
KINDS = ("live-capture", "run-session")
RECORD_TYPES = ("change", "event", "denial", "run", "grant", "note")


class RecordingError(Exception):
    pass


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def make_header(kind: str = "live-capture", source: Optional[Dict] = None, scope: Optional[List[Dict]] = None,
                cleanup: str = "none", filters: Optional[Dict] = None, notes: str = "", include_host: bool = True) -> Dict:
    """Session information stored in every recording (host name and macOS version unless include_host is false)."""
    if kind not in KINDS:
        raise RecordingError("kind must be one of %s" % ", ".join(KINDS))
    host: Dict[str, Any] = {"system": platform.system(), "release": platform.release(), "machine": platform.machine(),
                            "macos": platform.mac_ver()[0], "python": platform.python_version()}
    if include_host:
        host["hostname"] = socket.gethostname()
    return {"schema": SCHEMAS["recording"], "kind": kind, "created": _now_iso(), "tool": "cresc", "tool_version": __version__,
            "host": host, "source": source or {}, "scope": scope or [], "cleanup": cleanup, "filters": filters or {},
            "notes": notes}


def _check_path(path: str, writing: bool) -> None:
    if not isinstance(path, str) or not os.path.isabs(path):
        raise RecordingError("the path must be absolute")
    if writing and not path.endswith(EXT):
        raise RecordingError("a recording file name must end in %s" % EXT)


#= ---- writing --------------------------------------------------------------------------------------------------------
class Recorder:
    """Appends records to <path>.part and renames it to <path> on close(). Thread-safe."""

    def __init__(self, path: str, header: Dict, force: bool = False) -> None:
        _check_path(path, writing=True)
        if os.path.exists(path) and not force:
            raise RecordingError("%s already exists (use force to replace it)" % path)
        self.path = path
        self._tmp = path + ".part"
        os.makedirs(os.path.dirname(path), exist_ok=True)
        self._fh = open(self._tmp, "wb")
        self._lock = threading.Lock()
        self._hash = hashlib.sha256()
        self._t0 = time.monotonic()
        self.records = 0
        self.bytes = 0
        self.closed = False
        self.truncated = False
        self.last_t = 0.0
        self._emit(header)

    def elapsed(self) -> float:
        return time.monotonic() - self._t0

    def rebase(self, origin: float) -> None:
        """Make `origin` (a time.monotonic() value, e.g. the first pre-roll row) the start of the recording."""
        with self._lock:
            self._t0 = origin

    def _emit(self, obj: Dict) -> None:
        raw = (json.dumps(obj, separators=(",", ":"), sort_keys=True) + "\n").encode("utf-8")
        self._fh.write(raw)
        self._hash.update(raw)
        self.bytes += len(raw)

    def write(self, rtype: str, data: Dict, t: Optional[float] = None) -> bool:
        """Add one record; False when the recording is closed or has reached its size limit."""
        if rtype not in RECORD_TYPES:
            raise RecordingError("unknown record type %r" % (rtype,))
        with self._lock:
            if self.closed or self.truncated:
                return False
            if self.records >= MAX_RECORDS or self.bytes >= MAX_BYTES:
                self.truncated = True
                return False
            stamp = round(self.elapsed() if t is None else max(0.0, t), 6)
            self.last_t = max(self.last_t, stamp)
            self._emit({"type": rtype, "t": stamp, "data": data})
            self.records += 1
            return True

    def close(self) -> Dict:
        with self._lock:
            if self.closed:
                return self.summary()
            self.closed = True
            footer = {"type": "end", "records": self.records, "sha256": self._hash.hexdigest(), "ended": _now_iso(),
                      "duration_s": round(self.last_t, 3), "truncated": self.truncated}
            raw = (json.dumps(footer, separators=(",", ":"), sort_keys=True) + "\n").encode("utf-8")
            self._fh.write(raw)
            self.bytes += len(raw)
            self._fh.close()
            os.replace(self._tmp, self.path)
            return self.summary()

    def summary(self) -> Dict:
        digest = ""
        if self.closed and os.path.isfile(self.path):
            with open(self.path, "rb") as fh:
                digest = hashlib.sha256(fh.read()).hexdigest()
        return {"path": self.path, "records": self.records, "bytes": self.bytes, "duration_s": round(self.last_t, 3),
                "file_sha256": digest, "truncated": self.truncated}

    def abort(self) -> None:
        """Discard a recording that should not be kept."""
        with self._lock:
            if not self.closed:
                self.closed = True
                self._fh.close()
                try:
                    os.unlink(self._tmp)
                except OSError:
                    pass


#= ---- reading --------------------------------------------------------------------------------------------------------
def _lines(path: str) -> Iterator[Dict]:
    _check_path(path, writing=False)
    try:
        size = os.path.getsize(path)
    except OSError as exc:
        raise RecordingError("cannot read %s: %s" % (path, exc))
    if size > MAX_BYTES:
        raise RecordingError("recording is larger than %d bytes" % MAX_BYTES)
    with open(path, "rb") as fh:
        for n, raw in enumerate(fh, 1):
            if len(raw) > MAX_LINE:
                raise RecordingError("line %d is too long" % n)
            raw = raw.strip()
            if not raw:
                continue
            try:
                obj = json.loads(raw.decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                raise RecordingError("line %d is not valid JSON" % n)
            if not isinstance(obj, dict):
                raise RecordingError("line %d is not an object" % n)
            yield obj


def read_header(path: str) -> Dict:
    for obj in _lines(path):
        if obj.get("schema") != SCHEMAS["recording"]:
            raise RecordingError("not a cresc recording (missing header)")
        return obj
    raise RecordingError("empty file")


def iter_records(path: str) -> Iterator[Dict]:
    """Records only (no header, no footer)."""
    first = True
    for obj in _lines(path):
        if first:
            first = False
            if obj.get("schema") != SCHEMAS["recording"]:
                raise RecordingError("not a cresc recording (missing header)")
            continue
        if obj.get("type") == "end":
            continue
        yield obj


def verify_recording(path: str) -> Dict:
    """{ok, complete, records, problems, header, footer}: checks the structure, the record count and the hash."""
    problems: List[str] = []
    try:
        size = os.path.getsize(path)
        if size > MAX_BYTES:
            raise RecordingError("recording is larger than %d bytes" % MAX_BYTES)
        with open(path, "rb") as fh:
            data = fh.read()
    except (OSError, RecordingError) as exc:
        return {"ok": False, "complete": False, "records": 0, "problems": [str(exc)], "header": None, "footer": None}
    lines = data.split(b"\n")
    if lines and lines[-1] == b"":
        lines.pop()
    header = footer = None
    records = 0
    offset = 0
    footer_offset = None
    last_t = -1.0
    for n, raw in enumerate(lines, 1):
        try:
            obj = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            problems.append("line %d is not valid JSON" % n)
            offset += len(raw) + 1
            continue
        if n == 1:
            if not isinstance(obj, dict) or obj.get("schema") != SCHEMAS["recording"]:
                problems.append("missing header")
            else:
                header = obj
        elif isinstance(obj, dict) and obj.get("type") == "end":
            footer, footer_offset = obj, offset
        elif isinstance(obj, dict) and obj.get("type") in RECORD_TYPES:
            records += 1
            t = obj.get("t")
            if not isinstance(t, (int, float)) or t < last_t - 1e-6:
                problems.append("line %d: time goes backwards or is missing" % n)
            else:
                last_t = float(t)
        else:
            problems.append("line %d: unknown record" % n)
        offset += len(raw) + 1
    complete = footer is not None
    if complete:
        if footer.get("records") != records:
            problems.append("record count differs (footer %s, found %d)" % (footer.get("records"), records))
        if hashlib.sha256(data[:footer_offset]).hexdigest() != footer.get("sha256"):
            problems.append("hash differs: the recording was changed after it was written")
    return {"ok": not problems, "complete": complete, "records": records, "problems": problems, "header": header, "footer": footer}


def summarise(path: str) -> Dict:
    """Header, counts and duration without loading every record into memory."""
    info = verify_recording(path)
    counts: Dict[str, int] = {}
    categories: Dict[str, int] = {}
    duration = 0.0
    for rec in iter_records(path):
        counts[rec["type"]] = counts.get(rec["type"], 0) + 1
        duration = max(duration, float(rec.get("t", 0)))
        if rec["type"] == "change" and isinstance(rec.get("data"), dict):
            cat = str(rec["data"].get("category", "?"))
            categories[cat] = categories.get(cat, 0) + 1
    return {"ok": info["ok"], "complete": info["complete"], "problems": info["problems"], "header": info["header"],
            "records": info["records"], "duration_s": round(duration, 3), "by_type": counts, "by_category": categories}


#= ---- export ---------------------------------------------------------------------------------------------------------
def change_line(d: Dict) -> str:
    """One text line for a change dict (date, category tag, pid, process, inode, path), like filechange.format_change."""
    from .filechange import TAGS
    proc = d.get("process") or {}
    ts = str(d.get("ts") or "")[:23].replace("T", " ").rstrip("Z")
    inode = (d.get("file") or {}).get("inode")
    path = d.get("path", "")
    if d.get("category") == "moved_to" and d.get("source_path"):
        path = "%s  <-  %s" % (path, d["source_path"])
    pid = proc.get("pid", -1)
    return "%-23s %-4s %-7s %-18s %-20s %s" % (ts, TAGS.get(d.get("category"), "?"), pid if isinstance(pid, int) and pid >= 0 else "-",
                                               str(proc.get("name", ""))[:18], "-" if inode is None else inode, path)


def export_recording(path: str, out: str, fmt: str = "jsonl", force: bool = False) -> Dict:
    """Write a recording as text, csv, json (one array) or jsonl (the records). Only file changes become text / csv rows."""
    if fmt not in ("text", "csv", "json", "jsonl"):
        raise RecordingError("format must be text, csv, json or jsonl")
    if not os.path.isabs(out):
        raise RecordingError("the output path must be absolute")
    if os.path.exists(out) and not force:
        raise RecordingError("%s already exists (use force to replace it)" % out)
    rows = 0
    buf = io.StringIO()
    if fmt == "csv":
        writer = csv.writer(buf, lineterminator="\n")
        writer.writerow(["t", "ts", "category", "event_type", "pid", "process", "inode", "path", "source_path", "count"])
    records: List[Dict] = []
    for rec in iter_records(path):
        data = rec.get("data") if isinstance(rec.get("data"), dict) else {}
        if fmt == "jsonl":
            buf.write(json.dumps(rec, separators=(",", ":"), sort_keys=True) + "\n")
        elif fmt == "json":
            records.append(rec)
        elif rec.get("type") == "change":
            proc = data.get("process") or {}
            if fmt == "text":
                buf.write(change_line(data) + "\n")
            else:
                writer.writerow([rec.get("t"), data.get("ts"), data.get("category"), data.get("event_type"), proc.get("pid"),
                                 proc.get("name"), (data.get("file") or {}).get("inode"), data.get("path"), data.get("source_path"),
                                 data.get("count", 1)])
        else:
            continue
        rows += 1
    if fmt == "json":
        buf.write(json.dumps({"header": read_header(path), "records": records}, indent=2, sort_keys=True) + "\n")
    tmp = out + ".part"
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(buf.getvalue())
    os.replace(tmp, out)
    return {"path": out, "format": fmt, "rows": rows, "bytes": os.path.getsize(out)}


#= ---- playing --------------------------------------------------------------------------------------------------------
class Player:
    """Replays a recording at its recorded cadence. `push(batch, position)` receives lists of records.
    Controls: pause / resume / seek(t) / set_speed(x) / stop(). Seek rebuilds from the start (push reset=True) so a client
    that keeps the rows can show exactly the state at time t."""

    BATCH = 400

    def __init__(self, path: str, push: Callable[[List[Dict], float, bool, bool], None], speed: float = 1.0,
                 start_t: float = 0.0, max_gap: float = 2.0) -> None:
        self.records: List[Dict] = [r for r in iter_records(path)]
        self.times = [float(r.get("t", 0)) for r in self.records]
        self.duration = self.times[-1] if self.times else 0.0
        self.push = push
        self.speed = max(0.05, float(speed))
        self.max_gap = max(0.0, float(max_gap))
        self._cv = threading.Condition()
        self._paused = False
        self._stopped = False
        self._seek: Optional[float] = start_t if start_t > 0 else None
        self._index = 0
        self.position = 0.0
        self.finished = False
        self.thread = threading.Thread(target=self._run, name="player", daemon=True)

    def start(self) -> None:
        self.thread.start()

    def pause(self) -> None:
        with self._cv:
            self._paused = True

    def resume(self) -> None:
        with self._cv:
            self._paused = False
            self._cv.notify_all()

    def seek(self, t: float) -> None:
        with self._cv:
            self._seek = max(0.0, float(t))
            self._cv.notify_all()

    def set_speed(self, speed: float) -> None:
        with self._cv:
            self.speed = max(0.05, float(speed))
            self._cv.notify_all()

    def stop(self) -> None:
        with self._cv:
            self._stopped = True
            self._cv.notify_all()

    def _run(self) -> None:
        try:
            while True:
                with self._cv:
                    if self._stopped:
                        return
                    while self._paused and not self._stopped and self._seek is None:
                        self._cv.wait(0.2)
                    if self._stopped:
                        return
                    target, self._seek = self._seek, None
                if target is not None:
                    self._fast_forward(target)
                    continue
                if self._index >= len(self.records):
                    self.finished = True
                    self.push([], self.duration, False, True)
                    return
                rec = self.records[self._index]
                t = self.times[self._index]
                gap = max(0.0, t - self.position)
                delay = min(gap, self.max_gap) / self.speed if gap > 0 else 0.0
                if delay > 0:
                    with self._cv:
                        self._cv.wait(delay)
                        if self._stopped:
                            return
                        if self._paused or self._seek is not None:
                            continue
                batch = [rec]
                self._index += 1
                while self._index < len(self.records) and self.times[self._index] <= t + 1e-9 and len(batch) < self.BATCH:
                    batch.append(self.records[self._index])
                    self._index += 1
                self.position = t
                self.push(batch, t, False, False)
        except Exception:                                      #= a failing client callback must not leave a zombie thread
            self.finished = True
            raise

    def _fast_forward(self, target: float) -> None:
        """Rebuild the state at `target`: everything up to it is pushed at once (first batch has reset=True), then normal
        playback continues from there."""
        target = min(max(0.0, target), self.duration)
        end = bisect.bisect_right(self.times, target)
        sent = 0
        first = True
        while True:
            chunk = self.records[sent:min(end, sent + self.BATCH)]
            self.push(chunk, self.times[sent + len(chunk) - 1] if chunk else 0.0, first, False)
            first = False
            sent += len(chunk)
            if sent >= end:
                break
        self._index = end
        self.position = target
