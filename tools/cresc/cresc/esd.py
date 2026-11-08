#= esd.py  version 0.1.0 (2026-11-08)
#= Client for the Crescendo event daemon (`crescendo-esd`, a root LaunchDaemon that runs /usr/bin/eslogger on request).
#= Wire protocol over a Unix-domain stream socket (client -> daemon, one text line each):
#=     status                    -> {"esd":1,"ok":true,"state":"idle|running","version":...,"events":[...]}
#=     start EVENT [EVENT ...]   -> {"esd":1,"ok":true,"state":"running",...}, then raw eslogger JSON lines
#=     stop                      -> {"esd":1,"ok":true,"state":"idle"}
#= Control replies are single JSON lines that start with {"esd"; everything else is an eslogger event line.
#= The socket belongs to the installing user (mode 0600) and the daemon verifies the peer uid.
from __future__ import annotations

import json
import re
import socket
import threading
from typing import Dict, Iterator, List, Sequence

DEFAULT_SOCKET = "/var/run/com.loff.crescendo.esd.sock"
DEFAULT_EVENTS = ("exec", "fork", "exit", "open", "close", "write", "create", "rename", "unlink", "truncate", "link")
EVENT_NAME = re.compile(r"^[a-z_]{1,40}$")
MAX_EVENTS = 40
MAX_CONTROL = 1 << 16


class EsdError(Exception):
    pass


def check_events(events: Sequence[str]) -> List[str]:
    """Event names are interpolated into a protocol line, so they are validated strictly."""
    if not isinstance(events, (list, tuple)) or not events or len(events) > MAX_EVENTS:
        raise EsdError("events must be a list of 1-%d names" % MAX_EVENTS)
    for e in events:
        if not isinstance(e, str) or not EVENT_NAME.match(e):
            raise EsdError("bad eslogger event name: %r" % (e,))
    return list(events)


def _connect(path: str, timeout: float = 3.0) -> socket.socket:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect(path)
    except OSError as exc:
        s.close()
        raise EsdError("cannot reach the event daemon at %s: %s" % (path, exc.strerror or exc))
    return s


def _control(line: bytes) -> Dict:
    try:
        obj = json.loads(line.decode("utf-8", "replace"))
    except ValueError:
        raise EsdError("unreadable reply from the event daemon")
    if not isinstance(obj, dict):
        raise EsdError("unexpected reply from the event daemon")
    return obj


def is_control(line: str) -> bool:
    return line.startswith('{"esd"')


def status(path: str = DEFAULT_SOCKET) -> Dict:
    """Ask the daemon for its state. Raises EsdError when it is not reachable."""
    s = _connect(path)
    try:
        s.sendall(b"status\n")
        buf = b""
        while b"\n" not in buf:
            chunk = s.recv(4096)
            if not chunk:
                raise EsdError("the event daemon closed the connection")
            buf += chunk
            if len(buf) > MAX_CONTROL:
                raise EsdError("reply too large")
        return _control(buf.split(b"\n", 1)[0])
    except socket.timeout:
        raise EsdError("the event daemon did not answer")
    finally:
        s.close()


def socket_lines(path: str, events: Sequence[str], stop: threading.Event) -> Iterator[str]:
    """Start the daemon's eslogger and yield its event lines until `stop` is set or the daemon ends the stream.
    Control lines are consumed here; a refusal raises EsdError."""
    names = check_events(events)
    s = _connect(path)
    try:
        s.sendall(("start " + " ".join(names) + "\n").encode("ascii"))
        s.settimeout(0.3)
        buf = b""
        while not stop.is_set():
            try:
                chunk = s.recv(65536)
            except socket.timeout:
                continue
            if not chunk:
                return                          #= the daemon closed the stream
            buf += chunk
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                text = line.decode("utf-8", "replace")
                if is_control(text):
                    reply = _control(line)
                    if not reply.get("ok", False):
                        raise EsdError(str(reply.get("error", "the event daemon refused the request")))
                    continue
                yield text
            if len(buf) > (1 << 22):
                buf = b""                       #= absurdly long line: drop it
    finally:
        try:
            s.settimeout(1.0)
            s.sendall(b"stop\n")                #= best effort; closing the socket also stops eslogger
        except OSError:
            pass
        s.close()
