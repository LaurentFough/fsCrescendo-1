#= test_real_shape.py  version 0.1.0 (2026-11-08)
#= The parser against a fixture shaped like a REAL eslogger capture (macOS 27.2, message version 11): the structure,
#= key names, nulls and "\/" escaping come from the owner's actual output; names and ids are sanitised.
#= This validates exec, fork, exit, open, close, write, create, rename and unlink. NOT yet validated against real data:
#= create/rename with a NEW path (destination_type 1), uipc_connect/bind, mount, signal and the other event types.
import json
import os
import subprocess
import sys
import unittest

from cresc.events import parse_event
from cresc.watch import format_event

HERE = os.path.dirname(os.path.abspath(__file__))
PKG_ROOT = os.path.dirname(HERE)
FIXTURE = os.path.join(HERE, "fixtures", "eslogger-real-shape.jsonl")


def events():
    with open(FIXTURE, encoding="utf-8") as fh:
        return {e.kind: e for e in (parse_event(l) for l in fh) if e}


class RealShapeTests(unittest.TestCase):
    def setUp(self):
        self.ev = events()

    def test_every_line_is_an_event_and_slashes_are_json_escaped(self):
        raw = open(FIXTURE, encoding="utf-8").read()
        self.assertIn("\\/usr\\/libexec\\/xpcproxy", raw)                    #= eslogger writes "/" as "\/"
        self.assertEqual(len(self.ev), 9)
        self.assertEqual(sorted(self.ev), ["file.close", "file.create", "file.open", "file.rename", "file.unlink",
                                           "file.write", "proc.exec", "proc.exit", "proc.fork"])

    def test_exec(self):
        e = self.ev["proc.exec"]
        self.assertEqual((e.pid, e.ppid, e.process), (25991, 1, "/sbin/launchd"))        #= the actor is the OLD image
        self.assertEqual(e.target, "/usr/libexec/xpcproxy")                               #= the new image
        self.assertEqual(e.details["args"], ["xpcproxy", "com.apple.endpointsecurity.endpointsecurityd"])
        self.assertEqual((e.details["cwd"], e.details["target_signing_id"]), ("/", "com.apple.xpc.proxy"))
        self.assertTrue(e.platform)
        self.assertEqual(e.team_id, "")                                                   #= team_id is null on Apple binaries
        self.assertEqual(e.seq, 13)

    def test_fork_and_exit(self):
        f = self.ev["proc.fork"]
        self.assertEqual((f.pid, f.details["child_pid"], f.target), (1, 25991, "/sbin/launchd"))
        x = self.ev["proc.exit"]
        self.assertEqual((x.pid, x.ppid, x.name, x.signing_id, x.details["status"]), (25987, 86898, "sleep", "com.apple.sleep", 0))

    def test_open_close_write(self):
        o = self.ev["file.open"]
        self.assertEqual((o.target, o.details["fflag"], o.details["writing"]), ("/dev/console", 1, False))
        self.assertEqual((self.ev["file.close"].target, self.ev["file.close"].details["modified"]), ("/dev/null", False))
        self.assertEqual(self.ev["file.write"].target, "/private/var/log/com.apple.xpc.launchd/launchd.log")

    def test_create_rename_unlink_with_existing_file_destinations(self):
        self.assertEqual(self.ev["file.create"].target, "/Users/me/.agent/tmp/arg0-macos/agent-arg0uFWsj1")
        r = self.ev["file.rename"]
        self.assertEqual(r.target, "/Users/me/.local/share/shell/shell_historyqjt8SWcjji")
        self.assertEqual(r.target2, "/Users/me/.local/share/shell/shell_history")
        self.assertEqual(self.ev["file.unlink"].target, "/Users/me/.agent/tmp/arg0-macos/agent-arg0uFWsj1/.lock")

    def test_third_party_process_identity(self):
        c = self.ev["file.create"]
        self.assertEqual((c.name, c.signing_id, c.team_id, c.platform), ("agent", "agent", "TEAMID1234", False))

    def test_responsible_process_is_captured(self):
        self.assertEqual(self.ev["file.create"].responsible_pid, 71710)                    #= the app that started the helper
        self.assertEqual(self.ev["proc.exit"].responsible_pid, 86865)
        self.assertEqual(self.ev["proc.exec"].to_dict()["actor"]["responsible_pid"], 25991)

    def test_time_with_nanoseconds_renders_as_milliseconds(self):
        self.assertTrue(format_event(self.ev["proc.exec"]).startswith("01:17:31.785"))

    def test_watch_command_on_the_real_shaped_file(self):
        env = dict(os.environ, PYTHONPATH=PKG_ROOT)
        p = subprocess.run([sys.executable, "-m", "cresc", "watch", FIXTURE, "--app", "agent", "--json"], cwd=PKG_ROOT, env=env,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=60)
        self.assertEqual(p.returncode, 0, p.stderr)
        kinds = [json.loads(l)["kind"] for l in p.stdout.splitlines()]
        self.assertEqual(kinds, ["file.create", "file.unlink"])                           #= only agent's own events
        p = subprocess.run([sys.executable, "-m", "cresc", "watch", FIXTURE, "--dir", "/Users/me/.local/share/shell", "--json"],
                           cwd=PKG_ROOT, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=60)
        self.assertEqual([json.loads(l)["kind"] for l in p.stdout.splitlines()], ["file.rename"])


if __name__ == "__main__":
    unittest.main()
