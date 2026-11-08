#= scope.py  version 0.1.0 (2026-11-08)
#= Decides which events to show: "everything" by default, or narrowed to an app (and its children), a directory,
#= a file or a pid. Pure logic over Event records; keeps a small process-tree tracker so children are followed.
#= Limits: filtering happens in user space after eslogger delivers an event (eslogger has no kernel-side filter),
#= and pid tracking is only as good as the fork/exec/exit events it sees (pids can be reused).
from __future__ import annotations

import fnmatch
import os
from dataclasses import dataclass
from typing import List, Optional, Sequence, Set

from .events import Event

#= noisy system processes hidden by default (they would drown everything else); `--no-mute` shows them
DEFAULT_MUTE = ("mds", "mds_stores", "mdworker", "mdworker_shared", "fseventsd", "logd", "syslogd", "distnoted",
                "cfprefsd", "trustd", "opendirectoryd", "diagnosticd", "powerd", "eslogger")


def under(path: str, root: str) -> bool:
    """True when path is root or lies inside it; a plain prefix is not enough (/a/out2 is not under /a/out)."""
    if not path or not root:
        return False
    root = root.rstrip("/") or "/"
    return path == root or path.startswith(root + "/") or root == "/"


@dataclass(frozen=True)
class Scope:
    kind: str          #= app | dir | file | pid
    value: str

    def matches_process(self, ev: Event) -> bool:
        if self.kind == "pid":
            return str(ev.pid) == self.value
        if self.kind != "app":
            return False
        if "/" in self.value:
            return under(ev.process, self.value)
        return ev.name == self.value or (bool(ev.signing_id) and ev.signing_id == self.value)

    def matches_paths(self, ev: Event) -> bool:
        if self.kind == "dir":
            return any(under(p, self.value) for p in ev.paths)
        if self.kind == "file":
            return any(p == self.value for p in ev.paths)
        return False


def parse_scope(kind: str, value: str) -> Scope:
    if kind not in ("app", "dir", "file", "pid"):
        raise ValueError("unknown scope kind %r (use app, dir, file or pid)" % (kind,))
    if not isinstance(value, str):
        raise ValueError("scope value must be a string")
    if kind in ("dir", "file"):
        if not os.path.isabs(value):
            raise ValueError("%s scope needs an absolute path: %r" % (kind, value))
        value = os.path.normpath(value)
    if kind == "pid" and not value.isdigit():
        raise ValueError("pid scope needs a number: %r" % value)
    if not value or "\n" in value:
        raise ValueError("empty or invalid %s scope" % kind)
    return Scope(kind, value)


class Filter:
    """accept(event) -> bool. Also maintains the set of followed pids for app/pid scopes."""

    def __init__(self, scopes: Sequence[Scope] = (), follow: bool = True, mute: Optional[Sequence[str]] = None,
                 kinds: Sequence[str] = (), self_pid: Optional[int] = None):
        self.scopes = list(scopes)
        self.follow = follow
        self.mute = tuple(DEFAULT_MUTE if mute is None else mute)
        self.kinds = tuple(kinds)
        self.self_pid = os.getpid() if self_pid is None else self_pid
        self.tracked: Set[int] = set()
        self._retired: Set[int] = set()       #= pids of pid-scopes whose process already exited
        self._proc_scopes = [s for s in self.scopes if s.kind in ("app", "pid")]
        self._path_scopes = [s for s in self.scopes if s.kind in ("dir", "file")]

    def _kind_ok(self, ev: Event) -> bool:
        return not self.kinds or any(fnmatch.fnmatchcase(ev.kind, pat) for pat in self.kinds)

    def _muted(self, ev: Event) -> bool:
        return ev.pid == self.self_pid or (bool(ev.name) and ev.name in self.mute)

    def _identity_match(self, ev: Event) -> bool:
        """Does the acting process match an app/pid scope right now (by its current image)?"""
        if ev.pid in self._retired:
            return False
        if any(s.matches_process(ev) for s in self._proc_scopes):
            return True
        if ev.kind == "proc.exec" and ev.target:             #= the image it is becoming (e.g. a shell exec'ing the program)
            new = Event(kind=ev.kind, pid=ev.pid, process=ev.target,
                        signing_id=ev.details.get("target_signing_id", ""))
            return any(s.matches_process(new) for s in self._proc_scopes)
        return False

    def _track(self, ev: Event) -> bool:
        """True when this event belongs to a followed process. With follow=True a matching process and all its
        descendants are remembered by pid; with follow=False only the process's current image counts."""
        if not self._proc_scopes:
            return False
        matched = self._identity_match(ev)
        if not self.follow:
            return matched
        if matched:
            self.tracked.add(ev.pid)
        if ev.pid not in self.tracked and ev.pid not in self._retired and ev.responsible_pid > 0 \
                and ev.responsible_pid in self.tracked:
            self.tracked.add(ev.pid)               #= e.g. an XPC helper launched on behalf of the followed app
        if ev.kind == "proc.fork" and ev.pid in self.tracked:
            child = ev.details.get("child_pid", -1)
            if child > 0:
                self.tracked.add(child)
        return ev.pid in self.tracked

    def accept(self, ev: Event) -> bool:
        shown = self._shown(ev, self._track(ev))
        if ev.kind == "proc.exit":
            self.tracked.discard(ev.pid)      #= forget the pid after reporting its exit (pids get reused)
            if any(s.kind == "pid" and s.value == str(ev.pid) for s in self._proc_scopes):
                self._retired.add(ev.pid)
        return shown

    def _shown(self, ev: Event, followed: bool) -> bool:
        if not self._kind_ok(ev) or self._muted(ev):
            return False
        if not self.scopes:
            return True
        return followed or any(s.matches_paths(ev) for s in self._path_scopes)
