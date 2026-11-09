#= events.py  version 0.3.0 (2026-11-09)
#= Normalises `eslogger` JSON lines (Apple's Endpoint Security logger, macOS 13+) into one stable record: cresc.event/1.
#= The structure follows the Endpoint Security message layout (process / event_type / event.<name>.{...});
#= every field is optional here, because the layout varies by macOS release and event type.
#= Lines that are not JSON, or not events, are reported as None so the caller can count them.
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Tuple

from . import SCHEMAS

#= eslogger event name -> cresc kind
KINDS = {
    "exec": "proc.exec", "fork": "proc.fork", "exit": "proc.exit", "signal": "proc.signal",
    "open": "file.open", "close": "file.close", "write": "file.write", "create": "file.create",
    "rename": "file.rename", "unlink": "file.unlink", "truncate": "file.truncate", "link": "file.link",
    "clone": "file.clone", "exchangedata": "file.exchange", "mmap": "file.mmap",
    "setattrlist": "file.attr", "setmode": "file.attr", "setowner": "file.attr", "setflags": "file.attr",
    "setextattr": "file.attr", "deleteextattr": "file.attr", "setacl": "file.attr", "utimes": "file.attr",
    "mount": "fs.mount", "unmount": "fs.unmount",
    "uipc_connect": "ipc.connect", "uipc_bind": "ipc.bind",
}
FWRITE = 0x2          #= open(2) flag bit reported in `fflag`


@dataclass
class Event:
    kind: str
    ts: Optional[str] = None
    seq: Optional[int] = None                  #= global_seq_num when present (used to detect dropped events)
    pid: int = -1
    ppid: int = -1
    responsible_pid: int = -1                  #= the process macOS holds responsible (e.g. the app that launched an XPC helper)
    process: str = ""                          #= executable path of the process that acted
    signing_id: str = ""
    team_id: str = ""
    platform: bool = False
    euid: int = -1                              #= effective uid / gid of the acting process
    egid: int = -1
    target: str = ""
    target2: str = ""                          #= second path (rename/link destination)
    details: Dict[str, Any] = field(default_factory=dict)

    @property
    def paths(self) -> Tuple[str, ...]:
        return tuple(p for p in (self.target, self.target2) if p)

    @property
    def name(self) -> str:
        return self.process.rsplit("/", 1)[-1] if self.process else ""

    def to_dict(self) -> Dict:
        return {"schema": SCHEMAS["event"], "ts": self.ts, "seq": self.seq, "kind": self.kind,
                "actor": {"pid": self.pid, "ppid": self.ppid, "responsible_pid": self.responsible_pid,
                          "path": self.process, "signing_id": self.signing_id,
                          "team_id": self.team_id, "platform": self.platform, "euid": self.euid, "egid": self.egid},
                "target": self.target, "target2": self.target2, "details": self.details}


def _g(obj: Any, *keys: str) -> Any:
    """Safe nested get: _g(d, 'a', 'b') is d['a']['b'] or None."""
    for k in keys:
        if not isinstance(obj, dict):
            return None
        obj = obj.get(k)
    return obj


def _path(obj: Any) -> str:
    p = _g(obj, "path")
    return p if isinstance(p, str) else ""


def _int(value: Any, default: int = -1) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) else default


def _stat(obj: Any) -> Optional[Dict[str, Any]]:
    """The per-file stat eslogger attaches to every es_file_t (real captures: inode, device, mode, owner, ISO timestamps)."""
    st = _g(obj, "stat")
    if not isinstance(st, dict):
        return None

    def when(key: str) -> Optional[str]:
        v = st.get(key)
        return v if isinstance(v, str) else None
    return {"inode": _int(st.get("st_ino"), None), "device": _int(st.get("st_dev"), None), "mode": _int(st.get("st_mode"), None),
            "uid": _int(st.get("st_uid"), None), "gid": _int(st.get("st_gid"), None), "size": _int(st.get("st_size"), None),
            "nlink": _int(st.get("st_nlink"), None), "created": when("st_birthtimespec"), "modified": when("st_mtimespec"),
            "changed": when("st_ctimespec")}


_STAT_TARGET = ("close", "write", "truncate", "unlink", "setattrlist", "setmode", "setowner", "setflags", "setextattr",
                "deleteextattr", "setacl", "utimes")


def _stat_objects(name: str, p: Dict) -> Tuple[Any, Any]:
    """Which parts of the payload hold the file(s) a stat belongs to (primary, secondary)."""
    if name == "open":
        return p.get("file"), None
    if name in _STAT_TARGET:
        return p.get("target"), None
    if name == "create":
        return _g(p, "destination", "existing_file"), None
    if name == "rename":
        return p.get("source"), _g(p, "destination", "existing_file")
    if name in ("link", "clone"):
        return p.get("source"), None
    if name == "exchangedata":
        return p.get("file1"), p.get("file2")
    return None, None


def _new_path(dest: Any) -> str:
    """create/rename destinations are either an existing file or (directory + new file name)."""
    existing = _path(_g(dest, "existing_file"))
    if existing:
        return existing
    d = _path(_g(dest, "new_path", "dir"))
    name = _g(dest, "new_path", "filename")
    name = name if isinstance(name, str) else ""
    if d and name:
        return d.rstrip("/") + "/" + name
    return d or name


def parse_event(line: str) -> Optional[Event]:
    """One eslogger JSON line -> Event, or None when the line is not an event."""
    text = line.strip()
    if not text.startswith("{"):
        return None
    try:
        obj = json.loads(text)
    except ValueError:
        return None
    body = obj.get("event") if isinstance(obj, dict) else None
    if not isinstance(body, dict) or not body:
        return None
    name = next(iter(body))
    payload = body[name] if isinstance(body[name], dict) else {}

    proc = obj.get("process")
    ev = Event(kind=KINDS.get(name, "other." + str(name)),
               ts=obj["time"] if isinstance(obj.get("time"), str) else None,
               seq=_int(obj.get("global_seq_num"), default=-1) if "global_seq_num" in obj else None,
               pid=_int(_g(proc, "audit_token", "pid")), ppid=_int(_g(proc, "ppid")),
               responsible_pid=_int(_g(proc, "responsible_audit_token", "pid")),
               process=_path(_g(proc, "executable")),
               signing_id=_g(proc, "signing_id") if isinstance(_g(proc, "signing_id"), str) else "",
               team_id=_g(proc, "team_id") if isinstance(_g(proc, "team_id"), str) else "",
               platform=bool(_g(proc, "is_platform_binary")),
               euid=_int(_g(proc, "audit_token", "euid")), egid=_int(_g(proc, "audit_token", "egid")))
    ev.details["es_event"] = str(name)           #= the eslogger event name (tells setmode from setowner etc.)
    if ev.seq == -1:
        ev.seq = None

    if name == "exec":
        ev.target = _path(_g(payload, "target", "executable"))
        tsid = _g(payload, "target", "signing_id")
        if isinstance(tsid, str) and tsid:
            ev.details["target_signing_id"] = tsid       #= the actor above is still the OLD image
        args = payload.get("args")
        if isinstance(args, list):
            ev.details["args"] = [a for a in args if isinstance(a, str)]
        cwd = _path(payload.get("cwd"))
        if cwd:
            ev.details["cwd"] = cwd
    elif name == "fork":
        ev.target = _path(_g(payload, "child", "executable"))
        ev.details["child_pid"] = _int(_g(payload, "child", "audit_token", "pid"))
    elif name == "exit":
        ev.details["status"] = _int(payload.get("stat"))
    elif name == "open":
        ev.target = _path(payload.get("file"))
        flags = _int(payload.get("fflag"), default=0)
        ev.details.update({"fflag": flags, "writing": bool(flags & FWRITE)})
    elif name == "close":
        ev.target = _path(payload.get("target"))
        ev.details["modified"] = bool(payload.get("modified"))
    elif name == "exchangedata":                      #= assumed shape: es_event_exchangedata_t has file1 / file2
        ev.target = _path(payload.get("file1"))
        ev.target2 = _path(payload.get("file2"))
    elif name in ("write", "truncate", "mmap", "setmode", "setowner", "setflags", "setextattr",
                  "deleteextattr", "setacl", "setattrlist", "utimes"):
        ev.target = _path(payload.get("target")) or _path(payload.get("file"))
    elif name == "create":
        ev.target = _new_path(payload.get("destination"))
    elif name == "rename":
        ev.details["replaced"] = _int(payload.get("destination_type"), None) == 0     #= renamed OVER an existing file
        ev.target = _path(payload.get("source"))
        ev.target2 = _new_path(payload.get("destination"))
    elif name == "unlink":
        ev.target = _path(payload.get("target"))
    elif name in ("link", "clone"):
        ev.target = _path(payload.get("source"))
        #= link names the new file target_filename, clone target_name (assumed; both are accepted)
        new_name = payload.get("target_filename") or payload.get("target_name")
        ev.target2 = _new_path({"new_path": {"dir": payload.get("target_dir"), "filename": new_name}}) \
            or _path(payload.get("target"))
    elif name in ("uipc_connect", "uipc_bind"):
        #= real captures: connect has `file` (the socket path); bind has `dir` + `filename` (+ `mode`)
        bind_dir, bind_name = _path(payload.get("dir")), payload.get("filename")
        bound = (bind_dir.rstrip("/") + "/" + bind_name) if bind_dir and isinstance(bind_name, str) and bind_name else bind_dir
        ev.target = _path(payload.get("file")) or bound
        for k in ("domain", "type", "protocol"):
            if isinstance(payload.get(k), int):
                ev.details[k] = payload[k]
    elif name in ("mount", "unmount"):
        ev.target = str(_g(payload, "statfs", "f_mntonname") or "")
        for key, source in (("from", "f_mntfromname"), ("fstype", "f_fstypename")):
            value = _g(payload, "statfs", source)
            if isinstance(value, str) and value:
                ev.details[key] = value
    else:
        #= unknown event type: keep the first path-like thing so it can still be scoped
        for key in ("target", "file", "source", "dir"):
            p = _path(payload.get(key))
            if p:
                ev.target = p
                break
    primary, secondary = _stat_objects(name, payload)
    st1, st2 = _stat(primary), _stat(secondary)
    if st1:
        ev.details["stat"] = st1
    if st2:
        ev.details["stat2"] = st2
    if name == "close":
        ev.details["modified"] = bool(payload.get("modified"))
    #= what an attribute event changed (field names verified against a real capture)
    ext = payload.get("extattr")
    if isinstance(ext, str):
        ev.details["extattr"] = ext
    if name == "setflags" and _int(payload.get("flags"), None) is not None:
        ev.details["flags"] = payload["flags"]
    if name == "setmode" and _int(payload.get("mode"), None) is not None:
        ev.details["mode_set"] = payload["mode"]
    if name == "utimes":
        for key in ("atime", "mtime"):
            if isinstance(payload.get(key), str):
                ev.details[key] = payload[key]
    acl = _g(payload, "acl", "set")
    if name == "setacl" and isinstance(acl, str):
        ev.details["acl_set"] = acl
    mode = _g(payload, "destination", "new_path", "mode")
    if name == "create" and isinstance(mode, int) and not isinstance(mode, bool):
        ev.details["mode"] = mode                     #= requested permission bits when the file did not exist yet (assumed shape)
    return ev
