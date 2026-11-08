#= test_watch.py  version 0.1.0 (2026-11-08)
#= Event normalisation, scopes (app / dir / file / pid, child following, mute, pid reuse) and the watch command.
#= The fixture is SYNTHETIC (built from the documented Endpoint Security JSON layout); replace it with a real capture
#= (`sudo eslogger exec fork exit open close write create rename unlink > real.jsonl`) to validate against macOS.
import json
import os
import subprocess
import sys
import tempfile
import unittest

from cresc.events import parse_event
from cresc.scope import DEFAULT_MUTE, Filter, parse_scope, under
from cresc.watch import Stats, format_event, run_watch
from tests.test_profile_session import FAKE_LOG, write_exec

HERE = os.path.dirname(os.path.abspath(__file__))
PKG_ROOT = os.path.dirname(HERE)
FIXTURE = os.path.join(HERE, "fixtures", "eslogger-sample.jsonl")


def lines():
    with open(FIXTURE, encoding="utf-8") as fh:
        return fh.read().splitlines()


def watch(scopes=(), **kw):
    shown = []
    flt = Filter([parse_scope(k, v) for k, v in scopes], self_pid=-5, **kw)
    stats = run_watch(lines(), flt, shown.append)
    return shown, stats


def seqs(events):
    return [e.seq for e in events]


class ParseTests(unittest.TestCase):
    def setUp(self):
        self.by_seq = {e.seq: e for e in (parse_event(l) for l in lines()) if e}

    def test_exec(self):
        e = self.by_seq[2]
        self.assertEqual((e.kind, e.pid, e.ppid, e.process), ("proc.exec", 101, 100, "/bin/zsh"))
        self.assertEqual(e.target, "/Users/me/Downloads/tool")
        self.assertEqual(e.details["args"], ["/Users/me/Downloads/tool", "-machine"])
        self.assertEqual(e.details["cwd"], "/Users/me/out")

    def test_fork_exit(self):
        self.assertEqual(self.by_seq[13].details["child_pid"], 102)
        self.assertEqual((self.by_seq[16].kind, self.by_seq[16].details["status"]), ("proc.exit", 0))

    def test_open_flags(self):
        self.assertFalse(self.by_seq[3].details["writing"])
        self.assertTrue(self.by_seq[4].details["writing"])

    def test_close_create_rename_unlink(self):
        self.assertTrue(self.by_seq[6].details["modified"])
        self.assertEqual(self.by_seq[7].target, "/Users/me/out/new.txt")                 #= dir + filename
        self.assertEqual((self.by_seq[8].target, self.by_seq[8].target2),
                         ("/Users/me/out/new.txt", "/Users/me/out2/final.txt"))
        self.assertEqual(self.by_seq[9].target, "/Users/me/out/old.txt")

    def test_process_identity(self):
        e = self.by_seq[14]
        self.assertEqual(e.target, "/usr/sbin/ioreg")
        e = self.by_seq[15]
        self.assertEqual((e.name, e.signing_id, e.platform), ("ioreg", "com.apple.ioreg", True))

    def test_unknown_event_type_keeps_a_path(self):
        e = self.by_seq[21]
        self.assertEqual((e.kind, e.target), ("other.foo", "/Users/me/out/z"))

    def test_not_events(self):
        for bad in ("", "this line is not json", "{broken", "[1]", "{}", '{"event": {}}', '{"event": 3}'):
            self.assertIsNone(parse_event(bad), bad)

    def test_hostile_values_do_not_crash(self):
        weird = {"process": {"audit_token": {"pid": "x"}, "executable": {"path": 5}}, "time": 3, "global_seq_num": "n",
                 "event": {"open": {"file": 7, "fflag": "q"}}}
        ev = parse_event(json.dumps(weird))
        self.assertEqual((ev.kind, ev.pid, ev.target, ev.seq), ("file.open", -1, "", None))

    def test_serialises(self):
        d = parse_event(lines()[0]).to_dict()
        self.assertEqual(d["schema"], "cresc.event/1")
        json.dumps(d)


class ScopeTests(unittest.TestCase):
    def test_under_respects_path_boundaries(self):
        self.assertTrue(under("/a/out/x", "/a/out"))
        self.assertTrue(under("/a/out", "/a/out/"))
        self.assertFalse(under("/a/out2/x", "/a/out"))
        self.assertFalse(under("", "/a"))

    def test_no_scope_shows_everything_but_noise(self):
        shown, stats = watch()
        self.assertEqual((stats.read, stats.shown), (18, 17))
        self.assertNotIn(17, seqs(shown))                                    #= mds is muted by default
        self.assertEqual(len(watch(mute=[])[0]), 18)                         #= --no-mute

    def test_app_scope_follows_children_and_forgets_exited_pids(self):
        shown, _ = watch([("app", "tool")])
        self.assertEqual(seqs(shown), [2, 3, 4, 5, 6, 7, 8, 9, 13, 14, 15, 16, 19])
        self.assertNotIn(20, seqs(shown))               #= pid 101 was reused by vim after tool exited: not tool any more

    def test_app_scope_without_following_children(self):
        shown, _ = watch([("app", "tool")], follow=False)
        #= no descendants: pid 102 counts only while its own image is 'tool' (its exec event), not after it became ioreg
        self.assertEqual(seqs(shown), [2, 3, 4, 5, 6, 7, 8, 9, 13, 14, 19])

    def test_app_scope_by_path_and_signing_id(self):
        self.assertEqual(seqs(watch([("app", "/Users/me/Downloads")])[0]), seqs(watch([("app", "tool")])[0]))
        self.assertEqual(seqs(watch([("app", "com.apple.ioreg")], follow=False)[0]), [14, 15, 16])

    def test_dir_scope(self):
        shown, _ = watch([("dir", "/Users/me/out")])
        self.assertEqual(seqs(shown), [4, 5, 6, 7, 8, 9, 20, 21])           #= not 17: mds is muted
        self.assertEqual(seqs(watch([("dir", "/Users/me/out")], mute=[])[0]), [4, 5, 6, 7, 8, 9, 17, 20, 21])

    def test_dir_scope_matches_the_second_path_and_not_prefixes(self):
        self.assertEqual(seqs(watch([("dir", "/Users/me/out2")])[0]), [8])  #= rename destination
        self.assertEqual(watch([("dir", "/Users/me/ou")])[0], [])

    def test_file_scope(self):
        self.assertEqual(seqs(watch([("file", "/Users/me/out/result.txt")])[0]), [4, 5, 6])

    def test_pid_scope_retires_when_the_process_exits(self):
        shown, _ = watch([("pid", "101")])
        self.assertEqual(seqs(shown), [2, 3, 4, 5, 6, 7, 8, 9, 13, 14, 15, 16, 19])   #= seq 20 (a new pid 101) is not shown

    def test_scopes_combine_with_or(self):
        shown, _ = watch([("app", "Safari"), ("file", "/Users/me/out/result.txt")])
        self.assertEqual(seqs(shown), [4, 5, 6, 18])

    def test_kind_patterns(self):
        shown, _ = watch(kinds=["proc.exec", "file.c*"])
        self.assertEqual(sorted(set(e.kind for e in shown)), ["file.close", "file.create", "proc.exec"])

    def test_own_pid_is_muted(self):
        flt = Filter(self_pid=101)                       #= events of our own process must never be shown (feedback loop)
        shown = [e for e in map(parse_event, lines()) if e and flt.accept(e)]
        self.assertEqual(seqs(shown), [1, 14, 15, 16, 18, 21])     #= everything except pid 101's own events and mds

    def test_bad_scopes_are_rejected(self):
        for kind, value in (("dir", "relative/path"), ("file", "x"), ("pid", "abc"), ("app", ""), ("bogus", "x"), ("app", 5)):
            with self.assertRaises(ValueError, msg=(kind, value)):
                parse_scope(kind, value)
        self.assertEqual(parse_scope("dir", "/a/b/../c").value, "/a/c")

    def test_default_mute_list_has_the_spotlight_processes(self):
        for name in ("mds", "mdworker", "fseventsd", "eslogger"):
            self.assertIn(name, DEFAULT_MUTE)


class ResponsibleScopeTests(unittest.TestCase):
    """Helpers launched on behalf of an app (XPC services) are attributed to it by macOS (responsible_audit_token)."""

    def ev(self, pid, path, kind="file.open", responsible=-1, **kw):
        from cresc.events import Event
        return Event(kind=kind, pid=pid, process=path, responsible_pid=responsible, target=kw.get("target", ""), details=kw.get("details", {}))

    def run_scope(self, follow=True):
        flt = Filter([parse_scope("app", "Safari")], follow=follow, self_pid=-5)
        steps = [
            self.ev(400, "/Applications/Safari.app/Contents/MacOS/Safari", responsible=400),
            self.ev(410, "/System/Library/xpc/WebContent", responsible=400),        #= helper launched for Safari
            self.ev(410, "/System/Library/xpc/WebContent", responsible=400, kind="proc.exit"),
            self.ev(420, "/usr/bin/other", responsible=999),                         #= unrelated
            self.ev(430, "/usr/bin/orphan", responsible=410),                        #= responsible is the (exited) helper
        ]
        return [flt.accept(e) for e in steps]

    def test_helpers_are_followed_through_the_responsible_process(self):
        self.assertEqual(self.run_scope(), [True, True, True, False, False])

    def test_no_follow_does_not_use_the_responsible_process(self):
        self.assertEqual(self.run_scope(follow=False), [True, False, False, False, False])

    def test_unknown_responsible_pid_is_ignored(self):
        flt = Filter([parse_scope("app", "Safari")], self_pid=-5)
        flt.accept(self.ev(400, "/Applications/Safari.app/Contents/MacOS/Safari", responsible=400))
        self.assertFalse(flt.accept(self.ev(500, "/x/y", responsible=-1)))


class StatsTests(unittest.TestCase):
    def test_dropped_events_are_counted_from_sequence_gaps(self):
        _, stats = watch()
        self.assertEqual(stats.dropped, 3)               #= seq 10, 11, 12 are missing
        self.assertEqual(stats.skipped, 1)               #= the "not json" line; the blank lines are ignored
        self.assertEqual(stats.by_kind["file.open"], 6)

    def test_limit_stops_early(self):
        shown = []
        run_watch(lines(), Filter(self_pid=-5), shown.append, limit=3)
        self.assertEqual(len(shown), 3)

    def test_format_escapes_hostile_names(self):
        ev = parse_event(json.dumps({"time": "2026-11-08T12:00:00.100Z", "process": {"audit_token": {"pid": 9},
                                     "executable": {"path": "/tmp/\x1b]0;evil\x07x"}},
                                     "event": {"open": {"file": {"path": "/tmp/\x1b[2Jboom"}, "fflag": 1}}}))
        line = format_event(ev)
        self.assertNotIn("\x1b", line)
        self.assertNotIn("\x07", line)
        self.assertIn("\\x1b[2Jboom", line)
        self.assertTrue(line.startswith("12:00:00.100"))


class WatchCommand(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.env = dict(os.environ, PYTHONPATH=PKG_ROOT, CRESC_HOME=os.path.join(self.tmp.name, "store"))

    def tearDown(self):
        self.tmp.cleanup()

    def cresc(self, *args, stdin=None, env=None, expect=0):
        p = subprocess.run([sys.executable, "-m", "cresc", "watch"] + list(args), cwd=PKG_ROOT, env=env or self.env,
                           input=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=60)
        self.assertEqual(p.returncode, expect, "stdout=%s\nstderr=%s" % (p.stdout, p.stderr))
        return p

    def test_table_output_and_summary(self):
        p = self.cresc(FIXTURE, "--app", "tool")
        self.assertTrue(p.stdout.startswith("TIME"))
        self.assertIn("proc.exec", p.stdout)
        self.assertIn("-machine", p.stdout)                         #= exec arguments are shown
        self.assertIn("[write] /Users/me/out/result.txt", p.stdout)
        self.assertIn("/Users/me/out/new.txt -> /Users/me/out2/final.txt", p.stdout)
        self.assertNotIn("Safari", p.stdout)
        self.assertIn("18 event(s) read, 13 shown, 1 non-event line(s) skipped, 3 dropped", p.stderr)

    def test_json_output(self):
        p = self.cresc(FIXTURE, "--dir", "/Users/me/out", "--json")
        events = [json.loads(l) for l in p.stdout.splitlines()]
        self.assertEqual(len(events), 8)
        self.assertEqual({e["schema"] for e in events}, {"cresc.event/1"})
        self.assertEqual(events[0]["kind"], "file.open")

    def test_reads_stdin_like_a_pipe(self):
        p = self.cresc("-", "--kinds", "proc.*", "--limit", "2", stdin=open(FIXTURE).read())
        self.assertEqual(len([l for l in p.stdout.splitlines() if l.startswith("12:")]), 2)

    def test_errors(self):
        self.cresc("/no/such/file.jsonl", expect=66)
        self.cresc(FIXTURE, "--dir", "relative", expect=64)
        self.cresc(FIXTURE, "--pid", "abc", expect=64)

    def test_denials_are_merged_into_the_timeline(self):
        fake_log = os.path.join(self.tmp.name, "fake-log")
        denials = os.path.join(self.tmp.name, "d.ndjson")
        write_exec(fake_log, FAKE_LOG)
        with open(denials, "w") as fh:
            fh.write(json.dumps({"eventMessage": "Sandbox: tool(101) deny(1) sysctl-read hw.ncpu"}) + "\n")
        env = dict(self.env, CRESC_LOG=fake_log, FAKE_DENIALS=denials)
        p = self.cresc(FIXTURE, "--app", "tool", "--denials", "tool", "--settle", "0.8", env=env)
        self.assertIn("sandbox.deny", p.stdout)
        self.assertIn("sysctl-read hw.ncpu", p.stdout)
        j = self.cresc(FIXTURE, "--app", "tool", "--denials", "tool", "--settle", "0.8", "--json", env=env)
        kinds = [json.loads(l)["kind"] for l in j.stdout.splitlines()]
        self.assertIn("sandbox.deny", kinds)

    def test_missing_log_tool_for_denials_is_reported(self):
        env = dict(self.env, CRESC_LOG=os.path.join(self.tmp.name, "nope"))
        self.cresc(FIXTURE, "--denials", "tool", "--settle", "0.1", env=env, expect=65)


if __name__ == "__main__":
    unittest.main()
