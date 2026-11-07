#= test_profile_session.py  version 0.1.0 (2026-11-07)
#= Profile store (versions, grants, revoke, diff) and managed sessions (validation, run, timeout, kill, compare).
#= macOS tools are replaced by fakes: FSX_SANDBOX_EXEC runs the program unconfined, FSX_LOG prints canned denials.
import json
import os
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unittest

from fsx.denials import Group
from fsx.profile import Profile, ProfileError, validate_sbpl
from fsx.rules import Rule
from fsx.session import (MAX_WRITE_DIRS, SAFE_ENV, SessionError, build_argv, child_env, compare_groups, kill_tree,
                         latest_run_number,
                         list_runs, load_run, resolve_target, resolve_write_dirs, run_once, watch_predicate)

FAKE_SANDBOX_EXEC = """#!/usr/bin/env python3
# fake sandbox-exec: skips "-D k=v" and "-f file" then runs the command unconfined; records its argv
import os, sys
a = sys.argv[1:]
open(os.environ["FAKE_ARGV_OUT"], "w").write("\\n".join(sys.argv[1:]))
i = 0
while i < len(a) and a[i] in ("-D", "-f"):
    i += 2
os.execvp(a[i], a[i:])
"""

FAKE_LOG = """#!/usr/bin/env python3
# fake `log stream`: after a moment prints the canned ndjson denials, then waits until it is killed
import os, sys, time
time.sleep(0.2)
for line in open(os.environ["FAKE_DENIALS"]).read().splitlines():
    print(line, flush=True)
time.sleep(60)
"""


def write_exec(path, text):
    with open(path, "w") as fh:
        fh.write(text)
    os.chmod(path, os.stat(path).st_mode | stat.S_IXUSR)


def alive(pid):
    #= a zombie (state Z) is already dead and only waits to be reaped by its parent; some containers' PID 1 never reaps
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    state = subprocess.run(["ps", "-o", "stat=", "-p", str(pid)], stdout=subprocess.PIPE,
                           universal_newlines=True).stdout.strip()
    return bool(state) and not state.startswith("Z")


class ProfileTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = self.tmp.name

    def tearDown(self):
        self.tmp.cleanup()

    def test_baseline_is_valid_sbpl(self):
        p = Profile.create(self.store, "a")
        validate_sbpl(p.snapshot(1))
        self.assertIn("(deny default)", p.snapshot(1))
        self.assertIn('(param "WRITE_DIR_7")', p.snapshot(1))
        for i in range(8):                  #= every slot is used by the ancestors list, the write grant and the guard
            self.assertEqual(p.snapshot(1).count('(param "WRITE_DIR_%d")' % i), 3, "slot %d" % i)

    def test_create_load_list(self):
        Profile.create(self.store, "a")
        Profile.create(self.store, "b")
        self.assertEqual(Profile.list_names(self.store), ["a", "b"])
        self.assertEqual(Profile.load(self.store, "a").version, 1)
        with self.assertRaises(ProfileError):
            Profile.create(self.store, "a")
        with self.assertRaises(ProfileError):
            Profile.load(self.store, "missing")

    def test_names_are_validated(self):
        for bad in ("", "../x", "a/b", ".hidden", "x" * 65, "a b", "a;b"):
            with self.assertRaises(ProfileError, msg=bad):
                Profile.create(self.store, bad)

    def test_grant_versions_snapshots_and_idempotence(self):
        p = Profile.create(self.store, "a")
        r = Rule("mach-lookup", "global-name", "com.apple.system.opendirectoryd.libinfo")
        v, changed = p.grant(r, "medium", "needed for user lookup", "denial: tool mach-lookup x")
        self.assertEqual((v, changed), (2, True))
        self.assertEqual(p.grant(r, "medium"), (2, False))                  #= same rule again: nothing changes
        self.assertEqual(p.version, 2)
        self.assertNotIn("opendirectoryd", p.snapshot(1))                    #= v1 is immutable
        self.assertIn(r.render(), p.snapshot(2))
        self.assertIn("grant %s v2 risk=medium" % r.id, p.snapshot(2))
        self.assertEqual(Profile.load(self.store, "a").version, 2)           #= persisted
        validate_sbpl(p.snapshot(2))

    def test_grants_come_after_the_baseline_guards(self):
        #= measured semantics: the LAST matching filtered rule wins, so grants must follow the write guard
        p = Profile.create(self.store, "a")
        p.grant(Rule("file-write-create", "literal", "/Users/me/out.txt", confirm=True), "high")
        text = p.snapshot()
        self.assertGreater(text.index('(allow file-write-create (literal "/Users/me/out.txt"))'), text.index("(deny file-write*"))

    def test_revoke_and_diff_and_history(self):
        p = Profile.create(self.store, "a")
        r = Rule("sysctl-read", "sysctl-name", "hw.ncpu")
        p.grant(r, "low")
        self.assertEqual(p.revoke(r.id), 3)
        self.assertNotIn("hw.ncpu", p.snapshot(3))
        self.assertIn("+(allow sysctl-read", p.diff(1, 2))
        self.assertIn("-(allow sysctl-read", p.diff(2, 3))
        self.assertEqual([h["action"] for h in p.history()], ["create", "grant", "revoke"])
        with self.assertRaises(ProfileError):
            p.revoke("nope")
        with self.assertRaises(ProfileError):
            p.snapshot(99)

    def test_notes_cannot_break_the_profile(self):
        p = Profile.create(self.store, "a")
        p.grant(Rule("sysctl-read", "sysctl-name", "hw.ncpu"), "low", note="x\n(allow default)\n; y")
        text = p.snapshot()
        validate_sbpl(text)
        self.assertNotIn("\n(allow default)", text)           #= newlines in a note are flattened into the comment line

    def test_validate_sbpl(self):
        validate_sbpl('(a "(" ")" ; ( comment\n (b))')
        for bad in ("(a", "a)", '(a "unterminated)'):
            with self.assertRaises(ProfileError, msg=bad):
                validate_sbpl(bad)


class ValidationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = os.path.realpath(self.tmp.name)
        self.home = os.path.join(self.root, "home")
        os.makedirs(self.home)

    def tearDown(self):
        self.tmp.cleanup()

    def test_write_dirs_ok_and_created_private(self):
        d = os.path.join(self.home, "tmp", "_sandbox")
        os.makedirs(os.path.dirname(d))
        [out] = resolve_write_dirs([d + "/"], home=self.home)
        self.assertEqual(out, d)
        self.assertEqual(stat.S_IMODE(os.stat(d).st_mode), 0o700)

    def test_existing_dir_permissions_are_not_changed(self):
        d = os.path.join(self.root, "shared")
        os.makedirs(d, mode=0o755)
        os.chmod(d, 0o755)
        resolve_write_dirs([d], home=self.home)
        self.assertEqual(stat.S_IMODE(os.stat(d).st_mode), 0o755)

    def test_refusals(self):
        link = os.path.join(self.root, "link")
        os.symlink(self.home, link)
        cases = {"relative": ["rel/dir"], "empty": [""], "slash": ["/"], "home": [self.home],
                 "ancestor of home": [self.root], "symlink": [link], "none": [],
                 "too many": [os.path.join(self.root, "d%d" % i) for i in range(MAX_WRITE_DIRS + 1)]}
        for label, dirs in cases.items():
            with self.assertRaises(SessionError, msg=label):
                resolve_write_dirs(dirs, home=self.home)

    def test_target_resolution(self):
        self.assertTrue(os.path.isabs(resolve_target("sh")))
        with self.assertRaises(SessionError):
            resolve_target("definitely-not-a-command-xyz")
        with self.assertRaises(SessionError):
            resolve_target(self.root)

    def test_build_argv_fills_all_slots(self):
        argv = build_argv("sandbox-exec", "/p/v2.sb", "/bin/echo", ["/a", "/b"], ["hi", "there"])
        slots = [a for a in argv if a.startswith("WRITE_DIR_")]
        self.assertEqual(len(slots), 8)
        self.assertEqual(slots[0], "WRITE_DIR_0=/a")
        self.assertEqual(slots[1], "WRITE_DIR_1=/b")
        self.assertTrue(all(s.endswith("=/a") for s in slots[2:]))     #= unused slots repeat the first directory
        self.assertEqual(argv[-5:], ["-f", "/p/v2.sb", "/bin/echo", "hi", "there"][-5:])
        self.assertIn("TARGET=/bin/echo", argv)

    def test_watch_predicate_rejects_quotes(self):
        self.assertIn('eventMessage CONTAINS "tool"', watch_predicate(["tool"]))
        for bad in ('a"b', "a'b", "a\\b", "", "a\nb"):
            with self.assertRaises(SessionError, msg=repr(bad)):
                watch_predicate([bad])
        with self.assertRaises(SessionError):
            watch_predicate([])


class KillTreeTests(unittest.TestCase):
    def test_whole_process_group_is_stopped(self):
        proc = subprocess.Popen(["sh", "-c", "sleep 60 & echo $! ; wait"], stdout=subprocess.PIPE,
                                start_new_session=True, universal_newlines=True)
        child = int(proc.stdout.readline())
        self.assertTrue(alive(child))
        kill_tree(proc, grace=1.0)
        time.sleep(0.2)
        self.assertIsNotNone(proc.poll())
        self.assertFalse(alive(child), "the child process must be stopped with its parent")

    def test_term_ignoring_process_is_killed(self):
        proc = subprocess.Popen(["sh", "-c", "trap '' TERM; while :; do sleep 1; done"], start_new_session=True)
        time.sleep(0.3)
        kill_tree(proc, grace=0.5)
        self.assertIsNotNone(proc.poll())


class RunTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = os.path.realpath(self.tmp.name)
        self.store = os.path.join(root, "store")
        self.work = os.path.join(root, "work")
        self.home = os.path.join(root, "home")
        os.makedirs(self.home)
        self.sbx = os.path.join(root, "fake-sandbox-exec")
        self.log = os.path.join(root, "fake-log")
        self.denials = os.path.join(root, "denials.ndjson")
        self.argv_out = os.path.join(root, "argv.txt")
        write_exec(self.sbx, FAKE_SANDBOX_EXEC)
        write_exec(self.log, FAKE_LOG)
        self.write_denials([("sh", "sysctl-read", "kern.bootargs"), ("sh", "mach-lookup", "com.apple.x")])
        self.env = {"FSX_SANDBOX_EXEC": self.sbx, "FSX_LOG": self.log, "FAKE_DENIALS": self.denials,
                    "FAKE_ARGV_OUT": self.argv_out}
        self.saved = {k: os.environ.get(k) for k in self.env}
        os.environ.update(self.env)
        self.profile = Profile.create(self.store, "demo")

    def tearDown(self):
        for k, v in self.saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        self.tmp.cleanup()

    def write_denials(self, rows):
        with open(self.denials, "w") as fh:
            for proc, op, target in rows:
                fh.write(json.dumps({"timestamp": "2026-11-07 01:00:00.000000+0000",
                                     "eventMessage": "Sandbox: %s(4242) deny(1) %s %s" % (proc, op, target)}) + "\n")

    def run_sh(self, script, **kw):
        opts = dict(settle=0.4, startup_wait=0.1, grace=0.5, pass_env=["FAKE_ARGV_OUT"])    #= the fake sandbox-exec needs it
        opts.update(kw)
        return run_once(self.profile, "sh", [self.work], ["-c", script], **opts)

    def test_run_records_exit_output_and_denials(self):
        res = self.run_sh("echo out; echo err >&2; exit 3")
        m = res.meta
        self.assertEqual((m["exit"], m["run"], m["profile_version"], m["timed_out"]), (3, 1, 1, False))
        self.assertEqual(open(m["stdout"]).read().strip(), "out")
        self.assertEqual(open(m["stderr"]).read().strip(), "err")
        self.assertEqual(sorted((g.op, g.target) for g in res.groups),
                         [("mach-lookup", "com.apple.x"), ("sysctl-read", "kern.bootargs")])
        self.assertEqual(m["denials_total"], 2)
        self.assertTrue(os.path.isfile(os.path.join(res.directory, "result.json")))
        self.assertTrue(os.path.isdir(self.work))                      #= the write dir was created

    def test_sandbox_exec_receives_the_versioned_profile_and_slots(self):
        res = self.run_sh("exit 0")
        argv = open(self.argv_out).read().split("\n")
        self.assertIn(self.profile.snapshot_path(1), argv)
        self.assertEqual(len([a for a in argv if a.startswith("WRITE_DIR_")]), 8)
        self.assertEqual(res.meta["argv"][0], self.sbx)

    def test_program_gets_no_stdin(self):
        res = self.run_sh("cat; echo done")                            #= would hang forever on a terminal
        self.assertEqual(res.meta["exit"], 0)
        self.assertEqual(open(res.meta["stdout"]).read().strip(), "done")

    def test_timeout_stops_the_program_and_its_children(self):
        res = self.run_sh("sleep 60 & echo $!; wait", timeout=0.6)
        self.assertTrue(res.meta["timed_out"])
        child = int(open(res.meta["stdout"]).read().split()[0])
        time.sleep(0.2)
        self.assertFalse(alive(child))

    def test_restart_after_grant_uses_the_new_version_and_resolves(self):
        first = self.run_sh("exit 0")
        self.assertEqual(first.meta["profile_version"], 1)
        self.profile.grant(Rule("sysctl-read", "sysctl-name", "kern.bootargs"), "low")
        self.write_denials([("sh", "mach-lookup", "com.apple.x")])         #= the sysctl denial is gone after the grant
        second = self.run_sh("exit 0")
        self.assertEqual((second.meta["run"], second.meta["profile_version"]), (2, 2))
        diff = compare_groups(first.groups, second.groups)
        self.assertEqual([r["target"] for r in diff["resolved"]], ["kern.bootargs"])
        self.assertEqual([r["target"] for r in diff["persisting"]], ["com.apple.x"])
        self.assertEqual(diff["new"], [])
        self.assertEqual([r["run"] for r in list_runs(self.profile)], [1, 2])
        self.assertEqual(latest_run_number(self.profile), 2)
        self.assertEqual(len(load_run(self.profile, 1).groups), 2)

    def test_program_starts_in_the_first_write_dir_not_in_the_launchers_directory(self):
        res = self.run_sh("pwd")
        self.assertEqual(os.path.realpath(open(res.meta["stdout"]).read().strip()), os.path.realpath(self.work))
        self.assertEqual(res.meta["cwd"], os.path.realpath(self.work))
        self.assertNotEqual(os.path.realpath(os.getcwd()), os.path.realpath(self.work))

    def test_secrets_in_the_environment_are_withheld_by_default(self):
        os.environ["SECRET_TOKEN"] = "hunter2"
        try:
            hidden = self.run_sh('echo "[$SECRET_TOKEN][$HOME][${FSX_HOME:-unset}]"')
            out = open(hidden.meta["stdout"]).read().strip()
            self.assertTrue(out.startswith("[]["), out)               #= the token is not visible
            self.assertIn("SECRET_TOKEN", "".join(os.environ))         #= ...although it is set in our own environment
            self.assertNotIn("SECRET_TOKEN", hidden.meta["env_names"])
            self.assertIn("PATH", hidden.meta["env_names"])
            shown = self.run_sh('echo "[$SECRET_TOKEN]"', pass_env=["SECRET_TOKEN", "FAKE_ARGV_OUT"])
            self.assertEqual(open(shown.meta["stdout"]).read().strip(), "[hunter2]")
            self.assertIn("SECRET_TOKEN", shown.meta["env_names"])
            self.assertNotIn("hunter2", json.dumps(shown.meta))        #= the record keeps names, never values
            every = self.run_sh('echo "[$SECRET_TOKEN]"', inherit_env=True)
            self.assertEqual(open(every.meta["stdout"]).read().strip(), "[hunter2]")
            self.assertTrue(every.meta["env_inherited"])
        finally:
            os.environ.pop("SECRET_TOKEN", None)

    def test_child_env_rules(self):
        base = {"PATH": "/usr/bin", "HOME": "/h", "AWS_SECRET_ACCESS_KEY": "x", "FOO": "1"}
        self.assertEqual(child_env(base=base), {"PATH": "/usr/bin", "HOME": "/h"})
        self.assertEqual(child_env(["FOO"], base=base), {"PATH": "/usr/bin", "HOME": "/h", "FOO": "1"})
        self.assertEqual(child_env(inherit=True, base=base), base)
        for bad in ("A B", "1X", "A=B", "", "A;rm"):
            with self.assertRaises(SessionError, msg=bad):
                child_env([bad], base=base)
        self.assertIn("PATH", SAFE_ENV)
        self.assertNotIn("AWS_SECRET_ACCESS_KEY", SAFE_ENV)

    def test_missing_log_tool_is_reported(self):
        os.environ["FSX_LOG"] = os.path.join(self.tmp.name, "nope")
        with self.assertRaises(SessionError):
            self.run_sh("exit 0")

    def test_missing_program_is_reported(self):
        with self.assertRaises(SessionError):
            run_once(self.profile, "no-such-program-xyz", [self.work], settle=0.1, startup_wait=0.1)


if __name__ == "__main__":
    unittest.main()
