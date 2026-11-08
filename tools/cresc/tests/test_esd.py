#= test_esd.py  version 0.1.0 (2026-11-08)
#= The event-daemon client (cresc/esd.py) and watch.start over a Unix socket, against a fake daemon that speaks the
#= same line protocol as crescendo-esd (status / start / stop, control replies start with {"esd").
import json
import os
import shutil
import socket
import tempfile
import threading
import unittest

from cresc import esd
from tests.test_serve import SAMPLE, ServeCase


class FakeDaemon(threading.Thread):
    """Accepts one client at a time; `start ...` streams the sample file, then keeps the stream open."""

    def __init__(self, path, refuse=False):
        super().__init__(daemon=True)
        self.path, self.refuse = path, refuse
        self.srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.srv.bind(path)
        self.srv.listen(4)
        self.stopped = threading.Event()
        self.commands = []
        self.start()

    def run(self):
        while not self.stopped.is_set():
            try:
                self.srv.settimeout(0.2)
                conn, _ = self.srv.accept()
            except (socket.timeout, OSError):
                continue
            threading.Thread(target=self.serve, args=(conn,), daemon=True).start()

    def reply(self, conn, **kw):
        obj = {"esd": 1}
        obj.update(kw)
        conn.sendall((json.dumps(obj, separators=(",", ":")) + "\n").encode())

    def serve(self, conn):
        f = conn.makefile("rb")
        try:
            for raw in f:
                cmd = raw.decode().strip()
                self.commands.append(cmd)
                if cmd == "status":
                    self.reply(conn, ok=True, state="idle", version="test", events=[], fda=False)
                    return
                if cmd.startswith("start"):
                    if self.refuse:
                        self.reply(conn, ok=False, error="denied for the test")
                        return
                    self.reply(conn, ok=True, state="running", events=cmd.split()[1:])
                    for line in open(SAMPLE).read().splitlines()[:6]:
                        conn.sendall((line + "\n").encode())
                if cmd == "stop":
                    self.reply(conn, ok=True, state="idle")
                    return
        except OSError:
            pass
        finally:
            conn.close()

    def close(self):
        self.stopped.set()
        self.srv.close()


class EsdClientTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="esd", dir="/tmp")          #= AF_UNIX paths are short (104 bytes on macOS)
        self.path = os.path.join(self.dir, "s")
        self.addCleanup(shutil.rmtree, self.dir, True)

    def test_status_and_unreachable(self):
        with self.assertRaises(esd.EsdError):
            esd.status(self.path)
        d = FakeDaemon(self.path)
        self.addCleanup(d.close)
        self.assertEqual(esd.status(self.path)["state"], "idle")
        self.assertIs(esd.status(self.path)["fda"], False)           #= the FDA probe result reaches the caller

    def test_stream_skips_control_lines_and_sends_stop(self):
        d = FakeDaemon(self.path)
        self.addCleanup(d.close)
        stop = threading.Event()
        got = []
        for line in esd.socket_lines(self.path, ["exec", "open"], stop):
            got.append(line)
            if len(got) == 6:
                stop.set()
        self.assertFalse(any(esd.is_control(l) for l in got))       #= control replies never reach the caller
        self.assertTrue(got[0].startswith('{"schema_version"'))
        self.assertEqual(d.commands[0], "start exec open")
        deadline = threading.Event()
        for _ in range(20):
            if "stop" in d.commands:
                break
            deadline.wait(0.1)
        self.assertIn("stop", d.commands)

    def test_refusal_raises(self):
        d = FakeDaemon(self.path, refuse=True)
        self.addCleanup(d.close)
        with self.assertRaises(esd.EsdError):
            list(esd.socket_lines(self.path, ["exec"], threading.Event()))

    def test_event_names_are_validated(self):
        for bad in ([], ["EXEC"], ["exec;rm"], ["a b"], "exec", [1], ["x"] * 41):
            with self.assertRaises(esd.EsdError):
                esd.check_events(bad)
        self.assertEqual(esd.check_events(["exec", "uipc_connect"]), ["exec", "uipc_connect"])


class EsdServeTests(ServeCase):
    """watch.start / esd.status through a real `cresc serve` process."""

    def test_status_and_socket_watch(self):
        d = tempfile.mkdtemp(prefix="esd", dir="/tmp")
        self.addCleanup(shutil.rmtree, d, True)
        path = os.path.join(d, "s")
        c = self.client()
        self.assertFalse(c.call("esd.status", socket=path)["available"])
        self.assertEqual(c.call("watch.start", expect_ok=False, source={"socket": path})["code"], "session_error")
        daemon = FakeDaemon(path)
        self.addCleanup(daemon.close)
        info = c.call("esd.status", socket=path)
        self.assertTrue(info["available"])
        self.assertEqual(info["state"], "idle")
        self.assertIs(info["fda"], False)
        w = c.call("watch.start", source={"socket": path, "events": ["exec", "open", "write"]}, kinds=["file.*"])
        kinds = [c.event("watch.event")["event"]["kind"] for _ in range(3)]
        self.assertEqual(kinds, ["file.open", "file.open", "file.write"])
        c.call("watch.stop", watch_id=w["watch_id"])
        c.event("watch.ended", timeout=20)
        self.assertEqual(c.call("watch.start", expect_ok=False, source={"socket": "relative"})["code"], "invalid_params")
        self.assertEqual(c.call("watch.start", expect_ok=False, source={"socket": path, "events": ["BAD!"]})["code"], "session_error")


if __name__ == "__main__":
    unittest.main()
