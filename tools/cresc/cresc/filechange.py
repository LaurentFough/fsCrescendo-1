#= filechange.py  version 0.2.0 (2026-11-09)
#= Turns cresc.event/1 records (from eslogger) into FILE CHANGES in the vocabulary of a file-activity monitor:
#=   created | deleted | modified | attributes | moved_from | moved_to | meta        (schema cresc.filechange/1)
#= One event can yield several changes (a rename gives moved_from AND moved_to; exchangedata gives two modifications).
#= Pure logic, no I/O. Shapes are verified against a real capture (tests/fixtures/eslogger-file-events.jsonl, made with
#= scripts/capture-file-events.sh): create, rename (existing and new name), unlink, close, truncate, link, clone, exchangedata
#= and the attribute events. Not observed yet: `create` with destination_type 1 (a notify create reports the existing file).
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from . import SCHEMAS
from .events import Event

CATEGORIES = ("created", "deleted", "modified", "attributes", "moved_from", "moved_to", "meta")

#= eslogger event names to subscribe to for a file-activity view. `close` (with modified=true) stands for "content
#= modified" once per file instead of once per write(2); add "write" for write-by-write detail.
FILE_EVENTS = ("create", "rename", "unlink", "close", "truncate", "link", "clone", "exchangedata", "setattrlist",
               "setmode", "setowner", "setflags", "setextattr", "deleteextattr", "setacl", "utimes")

DATA_VOLUME = "/System/Volumes/Data"

#= event kind -> (category, event type text)
_SIMPLE = {
    "file.create": ("created", "Item Created"),
    "file.unlink": ("deleted", "Item Removed"),
    "file.truncate": ("modified", "Item Truncated"),
    "file.write": ("modified", "Content Written"),
    "file.link": ("created", "Item Linked"),
    "file.clone": ("created", "Item Cloned"),
}
#= attribute events are told apart by the eslogger event name kept in details by the parser (see Event.details["es_event"])
_ATTRS = {
    "setattrlist": "Attributes Changed", "setmode": "Mode Changed", "setowner": "Owner Changed",
    "setflags": "Flags Changed", "setextattr": "Xattrs Changed", "deleteextattr": "Xattrs Changed",
    "setacl": "ACL Changed", "utimes": "Times Changed",
}
TAGS = {"created": "CRE", "deleted": "DEL", "modified": "MOD", "attributes": "ATR", "moved_from": "MVF",
        "moved_to": "MVT", "meta": "META"}


@dataclass
class FileChange:
    category: str
    event_type: str
    ts: Optional[str] = None
    seq: Optional[int] = None
    path: str = ""
    source_path: str = ""                  #= for moved_to / created-by-link: where it came from
    inode: Optional[int] = None
    device: Optional[int] = None
    mode: Optional[int] = None
    uid: Optional[int] = None              #= owner of the FILE
    gid: Optional[int] = None
    size: Optional[int] = None
    created: Optional[str] = None
    modified: Optional[str] = None
    pid: int = -1
    ppid: int = -1
    process_path: str = ""
    signing_id: str = ""
    team_id: str = ""
    platform: bool = False
    actor_uid: int = -1                    #= effective uid / gid of the PROCESS
    actor_gid: int = -1
    responsible_pid: int = -1
    count: int = 1                         #= how many raw events this stands for (cleanup modes coalesce)
    details: Dict[str, Any] = field(default_factory=dict)

    @property
    def process_name(self) -> str:
        return self.process_path.rsplit("/", 1)[-1] if self.process_path else ""

    def to_dict(self) -> Dict:
        return {"schema": SCHEMAS["filechange"], "ts": self.ts, "seq": self.seq, "category": self.category,
                "event_type": self.event_type, "path": self.path, "source_path": self.source_path, "count": self.count,
                "file": {"inode": self.inode, "device": self.device, "mode": self.mode, "uid": self.uid, "gid": self.gid,
                         "size": self.size, "created": self.created, "modified": self.modified},
                "process": {"pid": self.pid, "ppid": self.ppid, "name": self.process_name, "path": self.process_path,
                            "signing_id": self.signing_id, "team_id": self.team_id, "platform": self.platform,
                            "uid": self.actor_uid, "gid": self.actor_gid, "responsible_pid": self.responsible_pid},
                "details": self.details}


def canonical_path(path: str, strip_data_volume: bool = True) -> str:
    """Paths from the kernel may carry the firmlink prefix /System/Volumes/Data; by default show the path users know."""
    if strip_data_volume and path and (path == DATA_VOLUME or path.startswith(DATA_VOLUME + "/")):
        return path[len(DATA_VOLUME):] or "/"
    return path


def meta_change(text: str, ts: Optional[str] = None) -> FileChange:
    """A marker row (recording started / stopped), like a monitor's meta event."""
    return FileChange(category="meta", event_type=text, ts=ts or time.strftime("%Y-%m-%dT%H:%M:%S.000000000Z", time.gmtime()),
                      path=text)


def _file_fields(stat: Optional[Dict]) -> Dict[str, Any]:
    if not stat:
        return {}
    return {"inode": stat.get("inode"), "device": stat.get("device"), "mode": stat.get("mode"), "uid": stat.get("uid"),
            "gid": stat.get("gid"), "size": stat.get("size"), "created": stat.get("created"), "modified": stat.get("modified")}


def from_event(ev: Event, strip_data_volume: bool = True) -> List[FileChange]:
    """The file changes an event stands for ([] when it is not a file change, e.g. a read-only close)."""
    kind = ev.kind
    es_event = ev.details.get("es_event", "")
    stat1, stat2 = ev.details.get("stat"), ev.details.get("stat2")

    def make(category: str, event_type: str, path: str, source: str = "", stat: Optional[Dict] = None, **extra: Any) -> FileChange:
        c = FileChange(category=category, event_type=event_type, ts=ev.ts, seq=ev.seq,
                       path=canonical_path(path, strip_data_volume), source_path=canonical_path(source, strip_data_volume),
                       pid=ev.pid, ppid=ev.ppid, process_path=ev.process, signing_id=ev.signing_id, team_id=ev.team_id,
                       platform=ev.platform, actor_uid=ev.euid, actor_gid=ev.egid, responsible_pid=ev.responsible_pid,
                       **_file_fields(stat))
        if extra:
            c.details.update(extra)
        return c

    if kind == "file.close":
        if ev.details.get("modified"):
            return [make("modified", "Content Modified", ev.target, stat=stat1)]
        return []
    if kind == "file.create":
        extra = {"mode_requested": ev.details["mode"]} if "mode" in ev.details else {}
        return [make("created", "Item Created", ev.target, stat=stat1, **extra)]
    if kind == "file.rename":
        return [make("moved_from", "Item Renamed", ev.target, stat=stat1, destination=ev.target2),
                make("moved_to", "Item Renamed", ev.target2, source=ev.target, stat=stat1, replaced=bool(ev.details.get("replaced")))]
    if kind == "file.exchange":
        return [make("modified", "Items Exchanged", ev.target, stat=stat1, other=ev.target2),
                make("modified", "Items Exchanged", ev.target2, stat=stat2, other=ev.target)]
    if kind in ("file.link", "file.clone"):
        category, text = _SIMPLE[kind]
        return [make(category, text, ev.target2 or ev.target, source=ev.target, stat=stat1)]
    if kind == "file.attr":
        what = {k: ev.details[k] for k in ("extattr", "flags", "mode_set", "atime", "mtime", "acl_set") if k in ev.details}
        return [make("attributes", _ATTRS.get(es_event, "Attributes Changed"), ev.target, stat=stat1, **what)]
    if kind in _SIMPLE:
        category, text = _SIMPLE[kind]
        return [make(category, text, ev.target, stat=stat1)]
    return []


FILES_HEADER = "%-23s %-4s %-7s %-18s %-20s %s" % ("DATE", "CAT", "PID", "PROCESS", "INODE", "PATH")


def format_change(c: FileChange) -> str:
    """One text line for a text view or a terminal: date, category tag, pid, process, inode, path."""
    ts = (c.ts or "")[:23].replace("T", " ").rstrip("Z")
    inode = "-" if c.inode is None else str(c.inode)
    path = c.path if not c.source_path or c.category != "moved_to" else "%s  <-  %s" % (c.path, c.source_path)
    return "%-23s %-4s %-7s %-18s %-20s %s" % (ts, TAGS.get(c.category, "?"), c.pid if c.pid >= 0 else "-",
                                               c.process_name[:18], inode, path)
