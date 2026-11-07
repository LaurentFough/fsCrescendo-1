#= classify.py  version 0.1.0 (2026-11-07)
#= Decides what a denial is: harmless start-up noise, PATH-search noise, or a real candidate for a grant,
#= and how risky granting it would be. The tables come from denials observed on macOS 27.2 (see docs/).
from __future__ import annotations

import os
from typing import Iterable, List, Sequence, Tuple

from .denials import Group

#= (operation, exact target, reason): denials that are safe to ignore and should NOT be granted
BENIGN: Tuple[Tuple[str, str, str], ...] = (
    ("file-read-data", "/dev/dtracehelper",
     "DTrace probe registration at start-up; harmless"),
    ("file-read-metadata", "/System/Cryptexes/Rosetta",
     "Rosetta presence check; native arm64 binaries do not need it"),
    ("network-outbound", "/private/var/run/syslog",
     "syslogd socket; allowing it opens an outbound channel, denying it only loses the tool's own log messages"),
    ("mach-lookup", "com.apple.system.notification_center",
     "notify(3) bus; optional, and a low-bandwidth signalling channel"),
)

#= path fragments whose reads deserve extra caution (a segment boundary is required on both sides)
SENSITIVE = ("/.ssh", "/.aws", "/.gnupg", "/.kube", "/.docker", "/.config/gcloud", "/.netrc",
             "/Library/Keychains", "/Library/Cookies", "/etc/sudoers", "/private/etc/sudoers",
             "/private/var/db/dslocal")

_LOW_OPS = {"sysctl-read", "file-read-metadata"}
_MEDIUM_OPS = {"mach-lookup", "file-read-data", "file-read*", "file-read-xattr", "file-test-existence"}


def expand(path: str, home: str) -> str:
    """Expand a leading ~ and a leading $HOME using the given home directory."""
    if not home:
        return path
    if path == "~" or path.startswith("~/"):
        return home + path[1:]
    if path == "$HOME" or path.startswith("$HOME/"):
        return home + path[5:]
    return path


def path_entries(path_value: str, home: str = "") -> List[str]:
    """Split a PATH string into normalised absolute entries."""
    out: List[str] = []
    for entry in path_value.split(os.pathsep):
        entry = expand(entry.strip(), home).rstrip("/")
        if entry:
            out.append(entry)
    return out


def is_sensitive(target: str, home: str = "") -> bool:
    t = expand(target, home).rstrip("/") + "/"
    return any((frag + "/") in t for frag in SENSITIVE)


def is_path_search(op: str, target: str, entries: Sequence[str], home: str = "") -> bool:
    """A metadata stat of a PATH entry or of one of its ancestors: the program is searching PATH.
    Denying these is harmless (the search skips the entry) and keeps the home directory hidden."""
    if op != "file-read-metadata" or not target:
        return False
    t = expand(target, home).rstrip("/")
    if not t:
        return False
    return any(e == t or e.startswith(t + "/") for e in entries)


def classify(group: Group, entries: Sequence[str] = (), home: str = "") -> Tuple[str, str]:
    """Return (class, reason); class is one of: benign | path-search | candidate."""
    for op, target, reason in BENIGN:
        if group.op == op and group.target == target:
            return "benign", reason
    if is_path_search(group.op, group.target, entries, home):
        return "path-search", "PATH search: the program stats PATH entries; denying them is harmless and hides your home directory"
    return "candidate", ""


def risk(op: str, target: str, home: str = "") -> str:
    """low | medium | high. Reads of sensitive locations and every non-read operation are high."""
    if is_sensitive(target, home):
        return "high"
    if op in _LOW_OPS:
        return "low"
    if op in _MEDIUM_OPS:
        return "medium"
    return "high"
