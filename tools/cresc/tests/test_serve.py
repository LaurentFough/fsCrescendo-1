#= test_serve.py  version 0.1.0 (2026-11-08)
#= `cresc serve` driven the way a GUI drives it: a real child process, JSON lines in and out, pushed events.
#= macOS tools are fakes (CRESC_SANDBOX_EXEC / CRESC_LOG); watches read the synthetic eslogger fixtures.
import json
import os
import queue
import subprocess
import sys
import tempfile
import threading
import time
import unittest

from tests.test_profile_session import FAKE_LOG, FAKE_SANDBOX_EXEC, alive, write_exec

HERE = os.path.dirname(os.path.abspath(__file__))
PKG_ROOT = os.path.dirname(HERE)
SAMPLE = os.path.join(HERE, "fixtures", "eslogger-sample.jsonl")


class Client:
    def __init__(self, store, env):
        self.p = subprocess.Popen([sys.executable, "-m", "cresc", "serve", "--store", store], cwd=PKG_ROOT, env=env,
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        self.q = queue.Queue()
        self.events = []
        self.lines = []
        self.n = 0
        threading.Thread(target=self._pump, daemon=True).start()

    def _pump(self):
        for line in self.p.stdout:
            self.q.put(line)

    def _next(self, timeout=25):
        line = self.q.get(timeout=timeout)
        self.lines.append(line)
        return json.loads(line)                      #= every line the server prints must be one valid JSON object

    def send_raw(self, text):
        self.p.stdin.write(text)
        self.p.stdin.flush()

    def call(self, method, expect_ok=True, **params):
        self.n += 1
        rid = self.n
        self.send_raw(json.dumps({"id": rid, "method": method, "params": params}) + "\n")
        return self.read_response(rid, expect_ok)

    def read_response(self, rid, expect_ok=True):
        while True:
            obj = self._next()
            if "event" in obj:
                self.events.append(obj)
                continue
            if obj.get("id") == rid:
                if expect_ok:
                    assert obj["ok"], obj
                    return obj["result"]
                assert not obj["ok"], obj
                return obj["error"]

    def event(self, name, pred=None, timeout=25):
        end = time.time() + timeout
        while True:
            for i, e in enumerate(self.events):
                if e["event"] == name and (pred is None or pred(e["data"])):
                    return self.events.pop(i)["data"]
            if time.time() > end:
                raise AssertionError("no %s event; saw %s" % (name, [e["event"] for e in self.events]))
            try:
                obj = self._next(timeout=max(0.1, end - time.time()))
            except queue.Empty:
                continue
            if "event" in obj:
                self.events.append(obj)

    def close(self):
        try:
            self.p.stdin.close()
        except OSError:
            pass
        try:
            self.p.wait(timeout=20)
        except subprocess.TimeoutExpired:
            self.p.kill()
        return self.p.returncode


class ServeCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = os.path.realpath(self.tmp.name)
        self.store = os.path.join(self.root, "store")
        self.work = os.path.join(self.root, "work")
        self.sbx, self.log = os.path.join(self.root, "sbx"), os.path.join(self.root, "log")
        self.denials = os.path.join(self.root, "denials.ndjson")
        write_exec(self.sbx, FAKE_SANDBOX_EXEC)
        write_exec(self.log, FAKE_LOG)
        self.set_denials([("sh", "sysctl-read", "hw.ncpu"), ("sh", "mach-lookup", "com.apple.x")])
        self.env = dict(os.environ, PYTHONPATH=PKG_ROOT, CRESC_SANDBOX_EXEC=self.sbx, CRESC_LOG=self.log,
                        FAKE_DENIALS=self.denials, FAKE_ARGV_OUT=os.path.join(self.root, "argv.txt"))
        self.clients = []

    def tearDown(self):
        for c in self.clients:
            c.close()
        self.tmp.cleanup()

    def client(self):
        c = Client(self.store, self.env)
        self.clients.append(c)
        return c

    def set_denials(self, rows):
        with open(self.denials, "w") as fh:
            for proc, op, target in rows:
                fh.write(json.dumps({"eventMessage": "Sandbox: %s(4242) deny(1) %s %s" % (proc, op, target)}) + "\n")

    def run_params(self, script, **extra):
        p = dict(name="demo", target="sh", write_dirs=[self.work], args=["-c", script], settle=0.4, startup_wait=0.1,
                 pass_env=["FAKE_ARGV_OUT"])
        p.update(extra)
        return p


class ProtocolTests(ServeCase):
    def test_hello_and_errors(self):
        c = self.client()
        h = c.call("hello")
        self.assertEqual((h["protocol"], h["schemas"]["event"]), (1, "cresc.event/1"))
        for m in ("run.start", "run.stop", "profile.grant", "watch.start", "triage.lines", "shutdown"):
            self.assertIn(m, h["methods"])
        self.assertEqual(c.call("nope", expect_ok=False)["code"], "unknown_method")
        c.send_raw("this is not json\n")
        err = json.loads(c.q.get(timeout=10))
        self.assertEqual((err["id"], err["ok"], err["error"]["code"]), (None, False, "parse_error"))
        c.send_raw("[1,2]\n")
        self.assertEqual(json.loads(c.q.get(timeout=10))["error"]["code"], "invalid_request")
        self.assertEqual(c.call("profile.show", expect_ok=False, name=5)["code"], "invalid_params")
        self.assertEqual(c.call("profile.show", expect_ok=False)["code"], "invalid_params")
        c.n += 1
        c.send_raw(json.dumps({"id": c.n, "method": "hello", "params": [1]}) + "\n")
        self.assertEqual(c.read_response(c.n, expect_ok=False)["code"], "invalid_params")
        self.assertEqual(c.call("hello")["protocol"], 1)                       #= still alive after every error

    def test_oversized_request_is_rejected_and_the_server_survives(self):
        c = self.client()
        c.send_raw("x" * (1 << 20 + 0) + "yyyy\n")
        self.assertEqual(json.loads(c.q.get(timeout=20))["error"]["code"], "too_large")
        self.assertEqual(c.call("hello")["protocol"], 1)

    def test_output_is_ascii_json_lines(self):
        c = self.client()
        out = c.call("triage.lines", lines=["Sandbox: tëst  (1) deny(1) file-read-data /tmp/日本"])
        self.assertEqual(out["summary"]["candidate"], 1)
        for line in c.lines:
            self.assertTrue(line.isascii(), line)
            self.assertEqual(line.count("\n"), 1)

    def test_shutdown_and_eof_exit_cleanly(self):
        c = self.client()
        self.assertTrue(c.call("shutdown")["bye"])
        self.assertEqual(c.p.wait(timeout=20), 0)
        d = self.client()
        d.call("hello")
        self.assertEqual(d.close(), 0)                                           #= EOF on stdin = clean exit


class ProfileApiTests(ServeCase):
    def test_lifecycle(self):
        c = self.client()
        self.assertEqual(c.call("profile.new", name="demo")["version"], 1)
        self.assertEqual(c.call("profile.new", expect_ok=False, name="demo")["code"], "profile_error")
        self.assertEqual(c.call("profile.new", expect_ok=False, name="../x")["code"], "profile_error")
        self.assertEqual(c.call("profile.list")["profiles"], ["demo"])
        g = c.call("profile.grant", name="demo", manual=["sysctl-read hw.pagesize"])
        self.assertEqual((g["version"], g["grants"][0]["changed"]), (2, True))
        self.assertIn("hw.pagesize", c.call("profile.show", name="demo")["text"])
        self.assertNotIn("hw.pagesize", c.call("profile.show", name="demo", version=1)["text"])
        self.assertIn("+(allow sysctl-read", c.call("profile.diff", name="demo", a=1, b=2)["diff"])
        self.assertEqual([h["action"] for h in c.call("profile.history", name="demo")["history"]], ["create", "grant"])
        rid = g["grants"][0]["id"]
        self.assertEqual(c.call("profile.revoke", name="demo", id=rid)["version"], 3)

    def test_risky_grants_need_confirmation_and_say_which(self):
        c = self.client()
        c.call("profile.new", name="demo")
        e = c.call("profile.grant", expect_ok=False, name="demo", manual=["sysctl-read hw.ncpu", "file-write-create /Users/me/x"])
        self.assertEqual(e["code"], "confirmation_required")
        self.assertEqual([r["rule"]["text"] for r in e["data"]["rules"]], ['(allow file-write-create (literal "/Users/me/x"))'])
        self.assertNotIn("hw.ncpu", c.call("profile.show", name="demo")["text"])       #= all-or-nothing
        c.call("profile.grant", name="demo", manual=["file-write-create /Users/me/x"], confirm=True)
        self.assertEqual(c.call("profile.grant", expect_ok=False, name="demo", manual=["iokit-open X"])["code"], "invalid_params")
        self.assertEqual(c.call("profile.grant", expect_ok=False, name="demo")["code"], "invalid_params")

    def test_triage_lines_and_grant_from_pasted_denials(self):
        c = self.client()
        lines = ["Sandbox: p(1) deny(1) sysctl-read hw.ncpu", "Sandbox: p(1) deny(1) file-read-data /dev/dtracehelper", "noise"]
        t = c.call("triage.lines", lines=lines)
        self.assertEqual((t["summary"]["candidate"], t["summary"]["benign"], t["skipped_lines"]), (1, 1, 1))
        rid = t["items"][0]["rule"]["id"]
        c.call("profile.new", name="demo")
        g = c.call("profile.grant", name="demo", denial_lines=lines, ids=[rid])
        self.assertEqual(g["version"], 2)
        self.assertEqual(c.call("profile.grant", expect_ok=False, name="demo", denial_lines=lines, ids=["deadbeef00"])["code"], "not_found")


class RunApiTests(ServeCase):
    def test_start_events_finish_grant_restart_compare(self):
        c = self.client()
        c.call("profile.new", name="demo")
        s = c.call("run.start", **self.run_params("exit 3"))
        self.assertEqual((s["run"], s["profile_version"]), (1, 1))
        self.assertEqual(c.event("run.started")["run"], 1)
        fin = c.event("run.finished")
        self.assertEqual((fin["meta"]["exit"], fin["meta"]["stopped"], fin["triage"]["summary"]["candidate"]), (3, False, 2))
        self.assertEqual(len([e for e in c.events if e["event"] == "run.denial"]), 2)            #= live denials were pushed
        self.assertEqual(c.call("run.get", name="demo", run=1)["meta"]["exit"], 3)
        self.assertEqual([r["run"] for r in c.call("run.list", name="demo")["runs"]], [1])
        # review -> grant the low-risk ones -> restart under the new version
        g = c.call("profile.grant", name="demo", run="last", auto="low")
        self.assertEqual(g["version"], 2)
        self.set_denials([("sh", "mach-lookup", "com.apple.x")])
        s2 = c.call("run.start", **self.run_params("exit 0"))
        self.assertEqual((s2["run"], s2["profile_version"]), (2, 2))
        self.assertEqual(c.event("run.finished", lambda d: d["run"] == 2)["meta"]["exit"], 0)
        cmp = c.call("run.compare", name="demo", a=1, b=2)
        self.assertEqual([r["target"] for r in cmp["resolved"]], ["hw.ncpu"])

    def test_output_and_triage_of_a_stored_run(self):
        c = self.client()
        c.call("profile.new", name="demo")
        c.call("run.start", **self.run_params("echo out; echo err >&2; exit 1"))
        c.event("run.finished")
        o = c.call("run.output", name="demo", run="last")
        self.assertEqual((o["stdout"]["text"].strip(), o["stderr"]["text"].strip(), o["exit"]), ("out", "err", 1))
        self.assertEqual(c.call("triage.run", name="demo", run=1)["summary"]["candidate"], 2)
        self.assertEqual(c.call("run.get", expect_ok=False, name="demo", run=99)["code"], "not_found")

    def test_stop_kills_the_run(self):
        c = self.client()
        c.call("profile.new", name="demo")
        s = c.call("run.start", **self.run_params("sleep 60 & echo $!; wait"))
        c.event("run.started")
        time.sleep(0.6)
        self.assertTrue(c.call("run.stop", name="demo", run=s["run"])["stopping"])
        t0 = time.time()
        fin = c.event("run.finished", timeout=20)
        self.assertTrue(fin["meta"]["stopped"])
        self.assertLess(time.time() - t0, 15)
        child = int(open(fin["meta"]["stdout"]).read().split()[0])
        time.sleep(0.3)
        self.assertFalse(alive(child), "the whole process tree must be stopped")
        self.assertEqual(c.call("run.stop", expect_ok=False, name="demo", run=s["run"])["code"], "not_found")

    def test_bad_run_requests(self):
        c = self.client()
        c.call("profile.new", name="demo")
        for bad in (dict(write_dirs=["relative"]), dict(write_dirs=["/"]), dict(write_dirs=[]), dict(target="no-such-program-xyz"),
                    dict(timeout=-1), dict(args="not a list"), dict(inherit_env="yes")):
            e = c.call("run.start", expect_ok=False, **self.run_params("exit 0", **bad))
            self.assertIn(e["code"], ("session_error", "invalid_params"), bad)
        self.assertEqual(c.call("run.start", expect_ok=False, **self.run_params("exit 0", name="missing"))["code"], "profile_error")
        self.assertEqual(c.call("hello")["protocol"], 1)

    def test_closing_the_pipe_stops_an_active_run(self):
        c = self.client()
        c.call("profile.new", name="demo")
        c.call("run.start", **self.run_params("sleep 60"))
        c.event("run.started")
        time.sleep(0.5)
        t0 = time.time()
        self.assertEqual(c.close(), 0)
        self.assertLess(time.time() - t0, 18)                      #= the run was cancelled, not waited for 60 s


class WatchApiTests(ServeCase):
    def test_replay_a_file_with_scopes(self):
        c = self.client()
        w = c.call("watch.start", source={"file": SAMPLE}, scopes=[{"kind": "app", "value": "tool"}])
        ended = c.event("watch.ended", timeout=20)
        self.assertEqual(ended["watch_id"], w["watch_id"])
        self.assertEqual((ended["stats"]["read"], ended["stats"]["shown"], ended["stats"]["dropped"]), (18, 13, 3))
        evs = [e["data"]["event"] for e in c.events if e["event"] == "watch.event"]
        self.assertEqual(len(evs), 13)
        self.assertEqual({e["schema"] for e in evs}, {"cresc.event/1"})
        self.assertFalse(c.call("watch.stats", watch_id=w["watch_id"])["running"])

    def test_live_fifo_and_stop(self):
        c = self.client()
        fifo = os.path.join(self.root, "es.fifo")
        os.mkfifo(fifo)
        w = c.call("watch.start", source={"file": fifo}, kinds=["file.*"])
        lines = open(SAMPLE).read().splitlines()
        with open(fifo, "w") as fh:                                  #= the privileged helper would write here
            for line in lines[:6]:
                fh.write(line + "\n")
                fh.flush()
        got = [c.event("watch.event")["event"]["kind"] for _ in range(3)]       #= of the 5 events written, 3 are file.*
        self.assertEqual(got, ["file.open", "file.open", "file.write"])
        self.assertTrue(c.call("watch.stats", watch_id=w["watch_id"])["running"])
        c.call("watch.stop", watch_id=w["watch_id"])
        ended = c.event("watch.ended", timeout=20)
        self.assertGreaterEqual(ended["stats"]["read"], 5)

    def test_denials_join_the_watch(self):
        c = self.client()
        self.set_denials([("tool", "sysctl-read", "hw.ncpu")])
        c.call("watch.start", source={"file": SAMPLE}, scopes=[{"kind": "app", "value": "tool"}], denials=["tool"], settle=0.8)
        c.event("watch.ended", timeout=20)
        kinds = [e["data"]["event"]["kind"] for e in c.events if e["event"] == "watch.event"]
        self.assertIn("sandbox.deny", kinds)

    def test_bad_watch_requests(self):
        c = self.client()
        for params in (dict(), dict(source={"file": "relative.jsonl"}), dict(source={"file": "/no/such/file"}),
                       dict(source={"file": SAMPLE}, scopes=[{"kind": "dir", "value": "relative"}]),
                       dict(source={"file": SAMPLE}, scopes=[{"kind": "bogus", "value": "x"}]), dict(source={"file": SAMPLE}, scopes="x")):
            self.assertEqual(c.call("watch.start", expect_ok=False, **params)["code"], "invalid_params", params)
        self.assertEqual(c.call("watch.stop", expect_ok=False, watch_id="nope")["code"], "not_found")


if __name__ == "__main__":
    unittest.main()
