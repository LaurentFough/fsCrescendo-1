#= session.py  version 0.1.0 (2026-11-07)
#= Managed sessions: run a program under a profile version with sandbox-exec, capture the Sandbox denials it causes,
#= stop its whole process tree, and let the caller restart it under an updated profile version.
#= A port of the validations in sandbox-run.sh. macOS runtime tools are injectable for tests:
#=   CRESC_SANDBOX_EXEC (default: sandbox-exec)   CRESC_LOG (default: /usr/bin/log)
#= Security notes: the program gets NO stdin and its stdout/stderr go to files in the run directory (never to the
#= terminal), so what it learns can only leave through those files and the write directories.
from __future__ import annotations

import json
import os
import re
import shutil
import signal
import subprocess
import threading
import time
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Sequence, Tuple

from . import SCHEMAS
from .denials import Denial, Group, fold, parse_line
from .profile import Profile, _atomic_write

MAX_WRITE_DIRS = 8     #= must equal the number of WRITE_DIR_n slots in the baseline profile


class SessionError(Exception):
    pass


#= ---- input validation (mirrors sandbox-run.sh) ------------------------------------------------------------
def resolve_write_dirs(dirs: Sequence[str], home: Optional[str] = None) -> List[str]:
    if not dirs:
        raise SessionError("at least one writable directory is required (--write-dir)")
    if len(dirs) > MAX_WRITE_DIRS:
        raise SessionError("too many write dirs (%d > %d)" % (len(dirs), MAX_WRITE_DIRS))
    home_real = os.path.realpath(home or os.path.expanduser("~"))
    out: List[str] = []
    for raw in dirs:
        if raw and raw.strip("/") == "":
            raise SessionError("refusing '/' as a write dir")
        d = raw.rstrip("/")
        if not d or not os.path.isabs(d):
            raise SessionError("write dir must be an absolute path: %r" % raw)
        if "\n" in d or "\0" in d:
            raise SessionError("write dir contains a control character: %r" % raw)
        if os.path.islink(d):
            raise SessionError("write dir is a symlink: %s" % d)
        if not os.path.isdir(d):
            os.makedirs(d, mode=0o700)      #= only directories WE create get tightened permissions
        c = os.path.realpath(d)
        if c == os.sep:
            raise SessionError("refusing '/' as a write dir")
        if home_real == c or (home_real + os.sep).startswith(c + os.sep):
            raise SessionError("refusing $HOME or an ancestor of it as a write dir: %s" % c)
        out.append(c)
    return out


def resolve_target(cmd: str) -> str:
    path = shutil.which(cmd) if os.sep not in cmd else cmd
    if not path:
        raise SessionError("command not found: %s" % cmd)
    path = os.path.abspath(path)
    target = os.path.join(os.path.realpath(os.path.dirname(path)), os.path.basename(path))
    if not (os.path.isfile(target) and os.access(target, os.X_OK)):
        raise SessionError("not an executable file: %s" % target)
    return target


def build_argv(sandbox_exec: str, profile_path: str, target: str, write_dirs: Sequence[str],
               args: Sequence[str]) -> List[str]:
    """sandbox-exec argv with all eight WRITE_DIR_n slots filled; unused slots repeat the first directory."""
    slots = list(write_dirs) + [write_dirs[0]] * (MAX_WRITE_DIRS - len(write_dirs))
    argv = [sandbox_exec]
    for i, d in enumerate(slots):
        argv += ["-D", "WRITE_DIR_%d=%s" % (i, d)]
    return argv + ["-D", "TARGET=%s" % target, "-f", profile_path, target] + list(args)


#= Variables the program receives by default. Everything else in cresc's environment (tokens, API keys, ...) is withheld:
#= a suspect binary could otherwise read secrets from its environment without touching any file.
SAFE_ENV = ("PATH", "HOME", "USER", "LOGNAME", "LANG", "LC_ALL", "LC_CTYPE", "TERM", "TMPDIR", "TZ")
_ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def child_env(pass_env: Sequence[str] = (), inherit: bool = False,
              base: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    """The environment for the sandboxed program: the safe variables plus those named in pass_env, or everything."""
    for name in pass_env:
        if not _ENV_NAME.match(name):
            raise SessionError("invalid environment variable name: %r" % name)
    src = dict(os.environ if base is None else base)
    if inherit:
        return src
    keep = set(SAFE_ENV) | set(pass_env)
    return {k: v for k, v in src.items() if k in keep}


def watch_predicate(names: Sequence[str]) -> str:
    parts = []
    for n in names:
        if not n or any(c in n for c in "\"'\\\n"):
            raise SessionError("unsupported character in process name: %r" % n)
        parts.append('eventMessage CONTAINS "%s"' % n)
    if not parts:
        raise SessionError("no process names to watch")
    return 'sender == "Sandbox" AND eventMessage CONTAINS "deny" AND (%s)' % " OR ".join(parts)


#= ---- denial watcher ---------------------------------------------------------------------------------------
class LogWatcher(threading.Thread):
    """Runs `log stream --style ndjson` for the watched process names and collects the denials."""

    def __init__(self, names: Sequence[str], log_bin: Optional[str] = None,
                 on_denial: Optional[Callable[[Denial], None]] = None):
        super().__init__(daemon=True)
        binary = log_bin or os.environ.get("CRESC_LOG") or "/usr/bin/log"
        self.cmd = [binary, "stream", "--style", "ndjson", "--predicate", watch_predicate(names)]
        self.error: Optional[str] = None
        self.started = threading.Event()
        self._denials: List[Denial] = []
        self._lock = threading.Lock()
        self._proc: Optional[subprocess.Popen] = None
        self._on_denial = on_denial

    def run(self) -> None:
        try:
            self._proc = subprocess.Popen(self.cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                          stderr=subprocess.DEVNULL, universal_newlines=True, bufsize=1)
        except OSError as exc:
            self.error = str(exc)
            self.started.set()
            return
        self.started.set()
        assert self._proc.stdout is not None
        for line in self._proc.stdout:
            d = parse_line(line)
            if d is None:
                continue
            with self._lock:
                self._denials.append(d)
            if self._on_denial:
                self._on_denial(d)

    def snapshot(self) -> List[Denial]:
        with self._lock:
            return list(self._denials)

    def stop(self) -> None:
        p = self._proc
        if p is not None and p.poll() is None:
            p.terminate()
            try:
                p.wait(timeout=2)
            except subprocess.TimeoutExpired:
                p.kill()
        self.join(timeout=3)


#= ---- stopping a process tree -------------------------------------------------------------------------------
def kill_tree(proc: subprocess.Popen, grace: float = 3.0) -> None:
    """SIGTERM the process group, wait `grace` seconds, then SIGKILL anything left. The program was started in
    its own session, so its children share the group and are stopped together."""
    try:
        pgid = os.getpgid(proc.pid)
    except ProcessLookupError:
        return
    try:
        os.killpg(pgid, signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        proc.wait(timeout=grace)
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(pgid, 0)                  #= is anything in the group still alive?
        os.killpg(pgid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        proc.wait(timeout=2)
    except subprocess.TimeoutExpired:
        pass


#= ---- runs -------------------------------------------------------------------------------------------------
@dataclass
class RunResult:
    number: int
    directory: str
    meta: Dict
    groups: List[Group]

    def to_dict(self) -> Dict:
        return dict(self.meta)


def next_run_number(profile: Profile) -> int:
    root = profile.runs_dir()
    if not os.path.isdir(root):
        return 1
    nums = [int(n) for n in os.listdir(root) if n.isdigit()]
    return (max(nums) + 1) if nums else 1


def run_once(profile: Profile, target: str, write_dirs: Sequence[str], args: Sequence[str] = (),
             watch: Sequence[str] = (), timeout: Optional[float] = None, settle: float = 3.0,
             startup_wait: float = 1.0, grace: float = 3.0, sandbox_exec: Optional[str] = None,
             log_bin: Optional[str] = None, on_denial: Optional[Callable[[Denial], None]] = None,
             pass_env: Sequence[str] = (), inherit_env: bool = False) -> RunResult:
    """Run `target` once under the profile's CURRENT version; return the run record (also saved on disk)."""
    sbx = sandbox_exec or os.environ.get("CRESC_SANDBOX_EXEC") or "sandbox-exec"
    target = resolve_target(target)
    dirs = resolve_write_dirs(write_dirs)
    names = [os.path.basename(target)] + [w for w in watch if w]
    version = profile.version
    number = next_run_number(profile)
    rdir = os.path.join(profile.runs_dir(), str(number))
    os.makedirs(rdir)
    argv = build_argv(sbx, profile.snapshot_path(version), target, dirs, args)
    env = child_env(pass_env, inherit_env)
    cwd = dirs[0]       #= start inside the first write dir: the program neither sees nor needs the launcher's directory

    watcher = LogWatcher(names, log_bin=log_bin, on_denial=on_denial)
    watcher.start()
    watcher.started.wait(5)
    if watcher.error:
        raise SessionError("cannot start the denial watcher (%s): %s" % (" ".join(watcher.cmd[:2]), watcher.error))
    time.sleep(startup_wait)                #= `log stream` needs a moment before it sees new messages

    out_path, err_path = os.path.join(rdir, "stdout.txt"), os.path.join(rdir, "stderr.txt")
    started_wall = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    t0 = time.time()
    timed_out = interrupted = False
    with open(out_path, "wb") as fout, open(err_path, "wb") as ferr:
        try:
            proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=fout, stderr=ferr, start_new_session=True,
                                    cwd=cwd, env=env)
        except OSError as exc:
            watcher.stop()
            raise SessionError("cannot start %s: %s" % (sbx, exc))
        try:
            try:
                proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
        except KeyboardInterrupt:
            interrupted = True
        finally:
            if proc.poll() is None:
                kill_tree(proc, grace)
            else:
                kill_tree_stragglers(proc)
    duration = time.time() - t0
    try:
        time.sleep(settle)                  #= let the asynchronous log catch up with the last denials
    except KeyboardInterrupt:
        interrupted = True
    watcher.stop()

    denials = watcher.snapshot()
    _atomic_write(os.path.join(rdir, "denials.jsonl"), "".join(json.dumps(d.to_dict()) + "\n" for d in denials))
    groups = fold(denials)
    with open(err_path, "rb") as fh:
        tail = fh.read()[-300:].decode("utf-8", "replace")
    meta = {"schema": SCHEMAS["run"], "run": number, "profile": profile.name, "profile_version": version,
            "target": target, "args": list(args), "write_dirs": dirs, "cwd": cwd, "watch": names, "argv": argv,
            "env_inherited": bool(inherit_env), "env_names": sorted(env),     #= names only, never values
            "exit": proc.returncode, "timed_out": timed_out, "interrupted": interrupted,
            "duration_s": round(duration, 3), "started": started_wall,
            "denials_total": sum(d.count for d in denials), "groups": len(groups),
            "stdout": out_path, "stderr": err_path, "stderr_tail": tail}
    _atomic_write(os.path.join(rdir, "result.json"), json.dumps(meta, indent=2) + "\n")
    return RunResult(number=number, directory=rdir, meta=meta, groups=groups)


def kill_tree_stragglers(proc: subprocess.Popen) -> None:
    """The leader already exited; make sure no child it left behind in the group keeps running."""
    try:
        pgid = os.getpgid(proc.pid)
    except (ProcessLookupError, PermissionError):
        pgid = proc.pid                     #= the group id equals the leader's pid (own session)
    try:
        os.killpg(pgid, 0)
        os.killpg(pgid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass


#= ---- reading runs back --------------------------------------------------------------------------------------
def load_run(profile: Profile, number: int) -> RunResult:
    rdir = os.path.join(profile.runs_dir(), str(number))
    path = os.path.join(rdir, "result.json")
    if not os.path.isfile(path):
        raise SessionError("run %s not found for profile %r" % (number, profile.name))
    with open(path, encoding="utf-8") as fh:
        meta = json.load(fh)
    denials: List[Denial] = []
    dpath = os.path.join(rdir, "denials.jsonl")
    if os.path.isfile(dpath):
        with open(dpath, encoding="utf-8") as fh:
            denials = [Denial.from_dict(json.loads(line)) for line in fh if line.strip()]
    return RunResult(number=number, directory=rdir, meta=meta, groups=fold(denials))


def list_runs(profile: Profile) -> List[Dict]:
    root = profile.runs_dir()
    if not os.path.isdir(root):
        return []
    out = []
    for n in sorted((int(x) for x in os.listdir(root) if x.isdigit())):
        try:
            out.append(load_run(profile, n).meta)
        except SessionError:
            continue
    return out


def latest_run_number(profile: Profile) -> int:
    runs = list_runs(profile)
    if not runs:
        raise SessionError("profile %r has no runs yet" % profile.name)
    return int(runs[-1]["run"])


def compare_groups(before: Sequence[Group], after: Sequence[Group]) -> Dict[str, List[Dict]]:
    """Which denials went away, which are new, and which persist between two runs."""
    a = {g.key: g for g in before}
    b = {g.key: g for g in after}
    def row(g: Group) -> Dict:
        return {"process": g.process, "op": g.op, "target": g.target, "count": g.count}
    return {"resolved": [row(a[k]) for k in a if k not in b],
            "new": [row(b[k]) for k in b if k not in a],
            "persisting": [row(b[k]) for k in b if k in a]}
