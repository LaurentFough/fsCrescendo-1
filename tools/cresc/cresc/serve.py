#= serve.py  version 0.1.0 (2026-11-08)
#= `cresc serve`: the machine-readable interface for a GUI. Line-delimited JSON over stdin/stdout (the app spawns it
#= as a child process); nothing listens on a network socket. See PROTOCOL.md for every method and event.
#=   request : {"id": 1, "method": "run.start", "params": {...}}
#=   response: {"id": 1, "ok": true, "result": {...}}   or   {"id": 1, "ok": false, "error": {"code", "message", "data"?}}
#=   push    : {"event": "run.denial", "data": {...}}     (no id; sent whenever something happens)
#= Framing safety: output is ASCII-only JSON (ensure_ascii), so U+2028 and friends can never split a line.
#= Limits: request lines are capped, parameters are validated, one bad request never stops the server.
from __future__ import annotations

import json
import os
import select
import stat
import sys
import threading
import time
import traceback
import uuid
from typing import Any, Callable, Dict, Iterator, List, Optional, Tuple

from . import SCHEMAS, __version__, esd
from .classify import path_entries
from .cli import CliError, apply_grants, manual_item, select_for_grant
from .denials import fold, parse_lines
from .profile import Profile, ProfileError
from .scope import Filter, parse_scope
from .session import (LogWatcher, SessionError, compare_groups, latest_run_number, list_runs, load_run, run_once,
                      safe_text)
from .triage import Item, suggested_prefixes, summary, triage
from .watch import Stats, denial_event, run_watch

PROTOCOL = 1
MAX_LINE = 1 << 20          #= largest accepted request line (1 MiB)
MAX_EVENT_LINE = 4 << 20    #= longest eslogger line a watch will read
MAX_WATCHES = 4


class ApiError(Exception):
    def __init__(self, code: str, message: str, data: Any = None):
        super().__init__(message)
        self.code, self.message, self.data = code, message, data

    def to_dict(self) -> Dict:
        d = {"code": self.code, "message": self.message}
        if self.data is not None:
            d["data"] = self.data
        return d


#= ---- parameter validation ---------------------------------------------------------------------------------
_MISSING = object()


def _get(p: Dict, key: str, required: bool, default: Any) -> Any:
    if key in p and p[key] is not None:
        return p[key]
    if required:
        raise ApiError("invalid_params", "missing required parameter: %s" % key)
    return default


def p_str(p: Dict, key: str, required: bool = True, default: Optional[str] = None, maxlen: int = 4096) -> Optional[str]:
    v = _get(p, key, required, default)
    if v is None:
        return None
    if not isinstance(v, str) or len(v) > maxlen or "\x00" in v:
        raise ApiError("invalid_params", "%s must be a string of at most %d characters" % (key, maxlen))
    return v


def p_int(p: Dict, key: str, required: bool = True, default: Optional[int] = None, lo: int = 0, hi: int = 10 ** 9) -> Optional[int]:
    v = _get(p, key, required, default)
    if v is None:
        return None
    if isinstance(v, bool) or not isinstance(v, int) or not (lo <= v <= hi):
        raise ApiError("invalid_params", "%s must be an integer between %d and %d" % (key, lo, hi))
    return v


def p_num(p: Dict, key: str, required: bool = False, default: Optional[float] = None, lo: float = 0, hi: float = 1e9) -> Optional[float]:
    v = _get(p, key, required, default)
    if v is None:
        return None
    if isinstance(v, bool) or not isinstance(v, (int, float)) or not (lo <= v <= hi):
        raise ApiError("invalid_params", "%s must be a number between %s and %s" % (key, lo, hi))
    return float(v)


def p_bool(p: Dict, key: str, default: bool = False) -> bool:
    v = _get(p, key, False, default)
    if not isinstance(v, bool):
        raise ApiError("invalid_params", "%s must be true or false" % key)
    return v


def p_list(p: Dict, key: str, required: bool = False, minitems: int = 0, maxitems: int = 64, maxlen: int = 4096) -> List[str]:
    v = _get(p, key, required, [])
    if not isinstance(v, list) or not (minitems <= len(v) <= maxitems) or not all(
            isinstance(x, str) and len(x) <= maxlen and "\x00" not in x for x in v):
        raise ApiError("invalid_params", "%s must be a list of %d-%d strings" % (key, minitems, maxitems))
    return list(v)


def run_ref(p: Dict, prof: Profile) -> int:
    v = p.get("run", "last")
    if v == "last":
        try:
            return latest_run_number(prof)
        except SessionError as exc:
            raise ApiError("not_found", str(exc))
    if isinstance(v, bool) or not isinstance(v, int) or v < 1:
        raise ApiError("invalid_params", "run must be a positive integer or \"last\"")
    return v


#= ---- watches (eslogger JSON from a file or a FIFO) --------------------------------------------------------
def line_source(path: str, stop: threading.Event, follow: bool) -> Iterator[str]:
    """Yield text lines from a file or FIFO without ever blocking past a stop request. A regular file ends at EOF
    (replay) unless `follow` is set; a FIFO stays open for the next writer and ends only on stop."""
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    try:
        keep_open = follow or stat.S_ISFIFO(os.fstat(fd).st_mode)
        buf = b""
        while not stop.is_set():
            ready, _, _ = select.select([fd], [], [], 0.3)
            if not ready:
                continue
            chunk = os.read(fd, 65536)
            if not chunk:
                if not keep_open:
                    break
                time.sleep(0.2)             #= FIFO without a writer, or a followed file with nothing new
                continue
            buf += chunk
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                yield line.decode("utf-8", "replace")
            if len(buf) > MAX_EVENT_LINE:
                buf = b""                    #= a single absurdly long line: drop it rather than grow without bound
        if buf and not stop.is_set():
            yield buf.decode("utf-8", "replace")
    finally:
        os.close(fd)


class WatchHandle:
    def __init__(self, watch_id: str):
        self.id = watch_id
        self.stop = threading.Event()
        self.stats = Stats()
        self.thread: Optional[threading.Thread] = None
        self.watcher: Optional[LogWatcher] = None


#= ---- the server -------------------------------------------------------------------------------------------
class Server:
    def __init__(self, store: str, inp: Any = None, out: Any = None):
        self.store = store
        self.inp = inp or sys.stdin
        self.out = out or sys.stdout
        self._wlock = threading.Lock()
        self._lock = threading.Lock()
        self._start_lock = threading.Lock()
        self.runs: Dict[Tuple[str, int], threading.Event] = {}
        self.watches: Dict[str, WatchHandle] = {}
        self.threads: List[threading.Thread] = []
        self.shutdown = threading.Event()
        self.methods: Dict[str, Callable[[Dict], Dict]] = {
            "hello": self.m_hello, "shutdown": self.m_shutdown,
            "profile.list": self.m_profile_list, "profile.new": self.m_profile_new, "profile.show": self.m_profile_show,
            "profile.history": self.m_profile_history, "profile.diff": self.m_profile_diff,
            "profile.grant": self.m_profile_grant, "profile.revoke": self.m_profile_revoke,
            "triage.run": self.m_triage_run, "triage.lines": self.m_triage_lines,
            "run.start": self.m_run_start, "run.stop": self.m_run_stop, "run.list": self.m_run_list,
            "run.get": self.m_run_get, "run.output": self.m_run_output, "run.compare": self.m_run_compare,
            "run.export": self.m_run_export, "bundle.verify": self.m_bundle_verify, "esd.status": self.m_esd_status, "watch.start": self.m_watch_start, "watch.stop": self.m_watch_stop, "watch.stats": self.m_watch_stats,
        }

    #= ---- output ------------------------------------------------------------------------------------------
    def send(self, obj: Dict) -> None:
        text = json.dumps(obj, separators=(",", ":"))      #= ensure_ascii=True (default): one object = exactly one line
        try:
            with self._wlock:
                self.out.write(text + "\n")
                self.out.flush()
        except (BrokenPipeError, ValueError, OSError):
            self.shutdown.set()                             #= the client went away

    def push(self, event: str, data: Dict) -> None:
        self.send({"event": event, "data": data})

    #= ---- main loop ---------------------------------------------------------------------------------------
    def serve_forever(self) -> int:
        try:
            while not self.shutdown.is_set():
                line = self.inp.readline(MAX_LINE + 1)
                if line == "":
                    break                                    #= EOF: the client closed the pipe
                if len(line) > MAX_LINE and not line.endswith("\n"):
                    while True:                              #= drain the rest of the oversized line
                        more = self.inp.readline(65536)
                        if more == "" or more.endswith("\n"):
                            break
                    self.send({"id": None, "ok": False, "error": ApiError("too_large", "request line exceeds %d bytes" % MAX_LINE).to_dict()})
                    continue
                if line.strip():
                    self.handle(line)
        finally:
            self.close()
        return 0

    def close(self) -> None:
        with self._lock:
            for cancel in self.runs.values():
                cancel.set()
            for w in self.watches.values():
                w.stop.set()
            threads = list(self.threads)
        deadline = time.time() + 8
        for t in threads:
            t.join(timeout=max(0.1, deadline - time.time()))

    def handle(self, line: str) -> None:
        rid: Any = None
        try:
            try:
                req = json.loads(line)
            except ValueError:
                raise ApiError("parse_error", "request is not valid JSON")
            if not isinstance(req, dict):
                raise ApiError("invalid_request", "request must be a JSON object")
            rid = req.get("id")
            if rid is not None and (isinstance(rid, bool) or not isinstance(rid, (int, str))):
                rid = None
                raise ApiError("invalid_request", "id must be a number or a string")
            method = req.get("method")
            params = req.get("params", {})
            if not isinstance(method, str) or method not in self.methods:
                raise ApiError("unknown_method", "unknown method: %s" % (safe_text(method) if isinstance(method, str) else method))
            if not isinstance(params, dict):
                raise ApiError("invalid_params", "params must be an object")
            self.send({"id": rid, "ok": True, "result": self.methods[method](params)})
        except ApiError as exc:
            self.send({"id": rid, "ok": False, "error": exc.to_dict()})
        except ProfileError as exc:
            self.send({"id": rid, "ok": False, "error": ApiError("profile_error", str(exc)).to_dict()})
        except SessionError as exc:
            self.send({"id": rid, "ok": False, "error": ApiError("session_error", str(exc)).to_dict()})
        except CliError as exc:
            self.send({"id": rid, "ok": False, "error": ApiError("refused", str(exc)).to_dict()})
        except Exception as exc:                              #= never let one request stop the server
            traceback.print_exc(file=sys.stderr)
            self.send({"id": rid, "ok": False, "error": ApiError("internal", "%s: %s" % (type(exc).__name__, exc)).to_dict()})

    #= ---- helpers -----------------------------------------------------------------------------------------
    def profile(self, p: Dict) -> Profile:
        return Profile.load(self.store, p_str(p, "name"))

    @staticmethod
    def triage_payload(items: List[Item], include_hidden: bool = False) -> Dict:
        shown = items if include_hidden else [i for i in items if i.klass == "candidate"]
        return {"summary": summary(items), "items": [i.to_dict() for i in shown],
                "prefix_suggestions": [r.to_dict() for r in suggested_prefixes(items)]}

    @staticmethod
    def context(p: Dict) -> Tuple[List[str], str]:
        home = p_str(p, "home", required=False, default=os.path.expanduser("~")) or os.path.expanduser("~")
        return path_entries(p_str(p, "path", required=False, default=os.environ.get("PATH", "")) or "", home), home

    #= ---- methods: general --------------------------------------------------------------------------------
    def m_hello(self, p: Dict) -> Dict:
        return {"protocol": PROTOCOL, "cresc": __version__, "schemas": SCHEMAS, "methods": sorted(self.methods),
                "store": self.store, "limits": {"max_request_bytes": MAX_LINE, "max_watches": MAX_WATCHES}}

    def m_shutdown(self, p: Dict) -> Dict:
        self.shutdown.set()
        return {"bye": True}

    #= ---- methods: profiles -------------------------------------------------------------------------------
    def m_profile_list(self, p: Dict) -> Dict:
        return {"profiles": Profile.list_names(self.store)}

    def m_profile_new(self, p: Dict) -> Dict:
        prof = Profile.create(self.store, p_str(p, "name"))
        return {"name": prof.name, "version": prof.version}

    def m_profile_show(self, p: Dict) -> Dict:
        prof = self.profile(p)
        version = p_int(p, "version", required=False, default=prof.version, lo=1)
        return {"name": prof.name, "version": prof.version, "shown_version": version, "grants": prof.grants,
                "text": prof.snapshot(version)}

    def m_profile_history(self, p: Dict) -> Dict:
        prof = self.profile(p)
        return {"name": prof.name, "version": prof.version, "history": prof.history()}

    def m_profile_diff(self, p: Dict) -> Dict:
        prof = self.profile(p)
        return {"diff": prof.diff(p_int(p, "a", lo=1), p_int(p, "b", lo=1))}

    def m_profile_revoke(self, p: Dict) -> Dict:
        prof = self.profile(p)
        return {"name": prof.name, "version": prof.revoke(p_str(p, "id"))}

    def m_profile_grant(self, p: Dict) -> Dict:
        prof = self.profile(p)
        ids = p_list(p, "ids")
        auto = p_str(p, "auto", required=False)
        if auto not in (None, "low", "medium"):
            raise ApiError("invalid_params", "auto must be \"low\" or \"medium\"")
        manual = p_list(p, "manual")
        confirm = p_bool(p, "confirm")
        note = p_str(p, "note", required=False, default="") or ""
        if not ids and not auto and not manual:
            raise ApiError("invalid_params", "choose what to grant: ids, auto and/or manual")
        selected: List[Item] = []
        if ids or auto:
            entries, home = self.context(p)
            if "denial_lines" in p:
                groups = fold(parse_lines(p_list(p, "denial_lines", maxitems=20000, maxlen=8192))[0])
            else:
                groups = load_run(prof, run_ref(p, prof)).groups
            try:
                selected = select_for_grant(triage(groups, entries, home), ids, auto)
            except CliError as exc:
                raise ApiError("not_found", str(exc))
        try:
            selected += [manual_item(m) for m in manual]
        except CliError as exc:
            raise ApiError("invalid_params", str(exc))
        risky = [i for i in selected if i.needs_confirm or not i.rule.verified]
        if risky and not confirm:                            #= all-or-nothing, and tell the GUI exactly what to ask about
            raise ApiError("confirmation_required", "these grants need confirmation; nothing was granted",
                           {"rules": [i.to_dict() for i in risky]})
        done = apply_grants(prof, selected, True, note)
        return {"name": prof.name, "version": prof.version, "grants": done}

    #= ---- methods: triage ---------------------------------------------------------------------------------
    def m_triage_run(self, p: Dict) -> Dict:
        prof = self.profile(p)
        number = run_ref(p, prof)
        entries, home = self.context(p)
        return dict(self.triage_payload(triage(load_run(prof, number).groups, entries, home), p_bool(p, "all")), run=number)

    def m_triage_lines(self, p: Dict) -> Dict:
        entries, home = self.context(p)
        denials, skipped = parse_lines(p_list(p, "lines", required=True, maxitems=20000, maxlen=8192))
        out = self.triage_payload(triage(fold(denials), entries, home), p_bool(p, "all"))
        out["skipped_lines"] = skipped
        return out

    #= ---- methods: runs -----------------------------------------------------------------------------------
    def m_run_start(self, p: Dict) -> Dict:
        prof = self.profile(p)
        name = prof.name
        target = p_str(p, "target")
        write_dirs = p_list(p, "write_dirs", required=True, minitems=1, maxitems=8)
        args = p_list(p, "args", maxitems=256, maxlen=8192)
        watch = p_list(p, "watch", maxitems=16, maxlen=256)
        timeout = p_num(p, "timeout", lo=0.1, hi=86400)
        settle = p_num(p, "settle", default=3.0, lo=0, hi=60)
        startup_wait = p_num(p, "startup_wait", default=1.0, lo=0, hi=30)
        pass_env = p_list(p, "pass_env", maxitems=64, maxlen=256)
        inherit_env = p_bool(p, "inherit_env")
        entries, home = self.context(p)
        cancel, started, box = threading.Event(), threading.Event(), {}

        def on_start(number: int, info: Dict) -> None:
            box["run"], box["version"] = number, info["profile_version"]
            with self._lock:
                self.runs[(name, number)] = cancel
            self.push("run.started", {"name": name, "run": number, "profile_version": info["profile_version"]})
            started.set()

        def on_denial(d) -> None:
            if "run" in box:
                self.push("run.denial", {"name": name, "run": box["run"], "denial": d.to_dict()})

        def worker() -> None:
            try:
                res = run_once(prof, target, write_dirs, args, watch, timeout, settle, startup_wait, on_denial=on_denial,
                               pass_env=pass_env, inherit_env=inherit_env, cancel=cancel, on_start=on_start)
                items = triage(res.groups, entries, home)
                self.push("run.finished", {"name": name, "run": res.number, "meta": res.meta,
                                           "triage": self.triage_payload(items)})
            except Exception as exc:
                box["error"] = exc
                if "run" in box:
                    self.push("run.error", {"name": name, "run": box["run"], "message": str(exc)})
                else:
                    traceback.print_exc(file=sys.stderr) if not isinstance(exc, (SessionError, ProfileError)) else None
            finally:
                started.set()
                if "run" in box:
                    with self._lock:
                        self.runs.pop((name, box["run"]), None)

        with self._start_lock:                                #= two starts must not race for the same run number
            t = threading.Thread(target=worker, daemon=True)
            t.start()
            with self._lock:
                self.threads.append(t)
            started.wait(30)
        if "run" not in box:
            err = box.get("error")
            if isinstance(err, SessionError):
                raise err
            raise ApiError("internal" if err else "timeout", str(err) if err else "the run did not start in time")
        return {"name": name, "run": box["run"], "profile_version": box["version"]}

    def m_run_stop(self, p: Dict) -> Dict:
        key = (p_str(p, "name"), p_int(p, "run", lo=1))
        with self._lock:
            cancel = self.runs.get(key)
        if cancel is None:
            raise ApiError("not_found", "no active run %s of profile %s" % (key[1], key[0]))
        cancel.set()
        return {"stopping": True, "name": key[0], "run": key[1]}

    def m_run_list(self, p: Dict) -> Dict:
        prof = self.profile(p)
        return {"name": prof.name, "runs": list_runs(prof)}

    def m_run_get(self, p: Dict) -> Dict:
        prof = self.profile(p)
        number = run_ref(p, prof)
        entries, home = self.context(p)
        try:
            res = load_run(prof, number)
        except SessionError as exc:
            raise ApiError("not_found", str(exc))
        return {"name": prof.name, "run": number, "meta": res.meta,
                "triage": self.triage_payload(triage(res.groups, entries, home))}

    def m_run_output(self, p: Dict) -> Dict:
        from .cli import read_head
        prof = self.profile(p)
        number = run_ref(p, prof)
        try:
            res = load_run(prof, number)
        except SessionError as exc:
            raise ApiError("not_found", str(exc))
        limit = p_int(p, "bytes", required=False, default=4000, lo=1, hi=1000000)
        m = res.meta
        return {"run": number, "exit": m["exit"], "args": m["args"], "cwd": m.get("cwd"), "profile_version": m["profile_version"],
                "stdout": read_head(os.path.join(res.directory, "stdout.txt"), limit),
                "stderr": read_head(os.path.join(res.directory, "stderr.txt"), limit)}

    def m_run_compare(self, p: Dict) -> Dict:
        prof = self.profile(p)
        try:
            a, b = load_run(prof, p_int(p, "a", lo=1)), load_run(prof, p_int(p, "b", lo=1))
        except SessionError as exc:
            raise ApiError("not_found", str(exc))
        return dict(compare_groups(a.groups, b.groups), a=a.meta, b=b.meta)

    def m_run_export(self, p: Dict) -> Dict:
        """Evidence bundle for one run. `path` (absolute, .zip) is optional; the default is <store>/exports/."""
        from .export import ExportError, build_bundle, default_bundle_path
        prof = self.profile(p)
        path = p_str(p, "path", required=False)
        if path is not None and not os.path.isabs(path):
            raise ApiError("invalid_params", "path must be absolute")
        number = run_ref(p, prof)
        entries, home = self.context(p)
        events_file = p_str(p, "events_file", required=False)
        try:
            result = build_bundle(prof, number, path or default_bundle_path(self.store, prof.name, number), entries, home,
                                  redact=p_bool(p, "redact", default=True), force=p_bool(p, "force"), events_file=events_file)
        except ExportError as exc:
            raise ApiError("session_error", str(exc))
        return dict(result, schema=SCHEMAS["bundle"], run=number)

    def m_bundle_verify(self, p: Dict) -> Dict:
        from .export import verify_bundle
        path = p_str(p, "path")
        if not os.path.isabs(path):
            raise ApiError("invalid_params", "path must be absolute")
        r = verify_bundle(path)
        return {"ok": r["ok"], "checked": r["checked"], "problems": r["problems"]}

    #= ---- methods: watches --------------------------------------------------------------------------------
    def m_esd_status(self, p: Dict) -> Dict:
        """State of the event daemon; an unreachable daemon is a normal answer (available=false), not an error."""
        path = p.get("socket", esd.DEFAULT_SOCKET)
        if not isinstance(path, str) or not os.path.isabs(path):
            raise ApiError("invalid_params", "socket must be an absolute path")
        try:
            info = esd.status(path)
        except esd.EsdError as exc:
            return {"available": False, "socket": path, "reason": str(exc)}
        info.pop("esd", None)
        return dict(info, available=True, socket=path)

    def m_watch_start(self, p: Dict) -> Dict:
        source = p.get("source")
        if not isinstance(source, dict):
            raise ApiError("invalid_params", "source must be {\"file\": ...} or {\"socket\": ..., \"events\": [...]}")
        sock_path = None
        sock_events: List[str] = list(esd.DEFAULT_EVENTS)
        if "socket" in source:
            sock_path = source["socket"] if isinstance(source["socket"], str) else ""
            if not os.path.isabs(sock_path):
                raise ApiError("invalid_params", "source.socket must be an absolute path")
            try:
                sock_events = esd.check_events(source.get("events", sock_events))
                esd.status(sock_path)                    #= fail now, not later in the background thread
            except esd.EsdError as exc:
                raise ApiError("session_error", str(exc))
            path = sock_path
        else:
            if not isinstance(source.get("file"), str):
                raise ApiError("invalid_params", "source must be {\"file\": \"/path/to/eslogger.jsonl or a FIFO\"}")
            path = source["file"]
            if not os.path.isabs(path) or not os.path.exists(path):
                raise ApiError("invalid_params", "source.file must be an existing absolute path")
        follow = bool(source.get("follow", False))
        scopes = []
        raw = p.get("scopes", [])
        if not isinstance(raw, list) or len(raw) > 64:
            raise ApiError("invalid_params", "scopes must be a list of {kind, value}")
        for s in raw:
            try:
                scopes.append(parse_scope(s["kind"], s["value"]))
            except (KeyError, TypeError, ValueError) as exc:
                raise ApiError("invalid_params", "bad scope: %s" % exc)
        mute = [] if p_bool(p, "no_mute") else None
        if mute is None and p_list(p, "mute"):
            from .scope import DEFAULT_MUTE
            mute = list(DEFAULT_MUTE) + p_list(p, "mute")
        flt = Filter(scopes, follow=not p_bool(p, "no_follow"), mute=mute, kinds=p_list(p, "kinds"))
        denials = p_list(p, "denials", maxitems=16, maxlen=256)
        settle = p_num(p, "settle", default=2.0, lo=0, hi=60)
        with self._lock:
            if len([w for w in self.watches.values() if w.thread and w.thread.is_alive()]) >= MAX_WATCHES:
                raise ApiError("limit", "at most %d watches at a time" % MAX_WATCHES)
            handle = WatchHandle(uuid.uuid4().hex[:12])
            self.watches[handle.id] = handle
        if denials:
            def on_denial(d) -> None:
                self.push("watch.event", {"watch_id": handle.id, "event": denial_event(d.process, d.pid, d.op, d.target, d.ts).to_dict()})
            handle.watcher = LogWatcher(denials, on_denial=on_denial)
            handle.watcher.start()
            handle.watcher.started.wait(5)
            if handle.watcher.error:
                with self._lock:
                    self.watches.pop(handle.id, None)
                raise ApiError("session_error", "cannot start the denial watcher: %s" % handle.watcher.error)

        def emit(ev) -> None:
            self.push("watch.event", {"watch_id": handle.id, "event": ev.to_dict()})

        def worker() -> None:
            try:
                run_watch(esd.socket_lines(path, sock_events, handle.stop) if sock_path
                          else line_source(path, handle.stop, follow), flt, emit, handle.stats)
                if handle.watcher and not handle.stop.is_set():
                    handle.stop.wait(settle)
            except Exception as exc:
                traceback.print_exc(file=sys.stderr)
                self.push("watch.error", {"watch_id": handle.id, "message": str(exc)})
            finally:
                if handle.watcher:
                    handle.watcher.stop()
                self.push("watch.ended", {"watch_id": handle.id, "stats": handle.stats.to_dict()})

        handle.thread = threading.Thread(target=worker, daemon=True)
        handle.thread.start()
        with self._lock:
            self.threads.append(handle.thread)
        return {"watch_id": handle.id}

    def _watch(self, p: Dict) -> WatchHandle:
        wid = p_str(p, "watch_id")
        with self._lock:
            w = self.watches.get(wid)
        if w is None:
            raise ApiError("not_found", "no such watch: %s" % wid)
        return w

    def m_watch_stop(self, p: Dict) -> Dict:
        w = self._watch(p)
        w.stop.set()
        return {"stopping": True, "watch_id": w.id}

    def m_watch_stats(self, p: Dict) -> Dict:
        w = self._watch(p)
        return {"watch_id": w.id, "running": bool(w.thread and w.thread.is_alive()), "stats": w.stats.to_dict()}
