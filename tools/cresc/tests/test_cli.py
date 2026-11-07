#= test_cli.py  version 0.1.0 (2026-11-07)
#= End-to-end tests of the command line (subprocess), including the interactive grant-and-restart loop.
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
PKG_ROOT = os.path.dirname(HERE)
FIXTURE = os.path.join(HERE, "fixtures", "sandbox-denials.log")
PATH_FOR_NOISE = "/System/Cryptexes/App/usr/bin:$HOME/.cargo/bin:$HOME/.gem/bin:$HOME/bin:/opt/homebrew/opt/openssl/bin"

from tests.test_profile_session import FAKE_LOG, FAKE_SANDBOX_EXEC, write_exec


class CliCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = os.path.realpath(self.tmp.name)
        self.store = os.path.join(self.root, "store")
        self.env = dict(os.environ, PYTHONPATH=PKG_ROOT, CRESC_HOME=self.store)

    def tearDown(self):
        self.tmp.cleanup()

    def cresc(self, *args, stdin=None, env=None, expect=0):
        p = subprocess.run([sys.executable, "-m", "cresc"] + list(args), cwd=PKG_ROOT, env=env or self.env,
                           input=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=120)
        if expect is not None:
            self.assertEqual(p.returncode, expect, "args=%r\nstdout=%s\nstderr=%s" % (args, p.stdout, p.stderr))
        return p


class OfflineCommands(CliCase):
    def test_parse_json(self):
        d = json.loads(self.cresc("parse", "--json", FIXTURE).stdout)
        self.assertEqual(d["schema"], "cresc.denials/1")
        self.assertEqual(d["skipped_lines"], 1)
        boot = [g for g in d["groups"] if g["target"] == "kern.bootargs"][0]
        self.assertEqual(boot["count"], 3)

    def test_parse_from_stdin(self):
        out = self.cresc("parse", "-", stdin="Sandbox: a(1) deny(1) sysctl-read hw.ncpu\n").stdout
        self.assertIn("hw.ncpu", out)

    def test_triage_json_hides_noise_by_default(self):
        d = json.loads(self.cresc("triage", "--json", "--home", "/Users/me", "--path", PATH_FOR_NOISE, FIXTURE).stdout)
        self.assertEqual(d["schema"], "cresc.triage/1")
        targets = {i["target"] for i in d["items"]}
        self.assertNotIn("/dev/dtracehelper", targets)
        self.assertNotIn("$HOME/.cargo", targets)
        self.assertIn("com.apple.system.opendirectoryd.libinfo", targets)
        self.assertGreater(d["summary"]["benign"], 0)
        self.assertGreater(d["summary"]["path-search"], 0)
        ssh = [i for i in d["items"] if i["target"].endswith(".ssh/id_ed25519")][0]
        self.assertEqual((ssh["risk"], ssh["needs_confirm"]), ("high", True))
        self.assertTrue(d["prefix_suggestions"])

    def test_triage_table_and_all(self):
        out = self.cresc("triage", "--home", "/Users/me", "--path", PATH_FOR_NOISE, FIXTURE).stdout
        self.assertIn("harmless group(s) hidden", out)
        self.assertNotIn("dtracehelper", out)
        self.assertIn("dtracehelper", self.cresc("triage", "--all", "--home", "/Users/me", "--path", PATH_FOR_NOISE, FIXTURE).stdout)

    def test_missing_file_is_exit_66(self):
        self.cresc("parse", "/no/such/file.log", expect=66)

    def test_usage_errors(self):
        self.cresc("triage", "--run", "1", expect=2)                      #= --run without --profile
        self.cresc("profile", expect=2)


class ProfileCommands(CliCase):
    def triage_ids(self):
        d = json.loads(self.cresc("triage", "--json", "--home", "/Users/me", "--path", PATH_FOR_NOISE, FIXTURE).stdout)
        return {i["target"]: i["rule"]["id"] for i in d["items"] if i["rule"]}

    def test_profile_lifecycle(self):
        self.cresc("profile", "new", "demo")
        self.assertIn("demo", self.cresc("profile", "list").stdout)
        self.assertIn("(deny default)", self.cresc("profile", "show", "demo").stdout)
        self.cresc("profile", "new", "demo", expect=65)                         #= already exists

        out = self.cresc("profile", "grant", "demo", FIXTURE, "--auto", "low", "--home", "/Users/me",
                       "--path", PATH_FOR_NOISE).stdout
        self.assertIn("granted", out)
        text = self.cresc("profile", "show", "demo").stdout
        self.assertIn('(allow sysctl-read (sysctl-name "kern.bootargs"))', text)
        self.assertIn('(allow file-read-metadata (literal "/var"))', text)
        self.assertNotIn("opendirectoryd", text)                              #= medium risk: not part of --auto low
        self.assertNotIn(".ssh", text)
        v = json.loads(open(os.path.join(self.store, "profiles", "demo", "profile.json")).read())["version"]
        self.assertEqual(v, 1 + len([l for l in text.splitlines() if l.startswith(";= grant ")]))

        again = self.cresc("profile", "grant", "demo", FIXTURE, "--auto", "low", "--home", "/Users/me",
                         "--path", PATH_FOR_NOISE).stdout
        self.assertIn("already granted", again)
        self.assertIn("grant", self.cresc("profile", "history", "demo").stdout)

    def test_high_risk_needs_confirm_and_nothing_is_granted_without_it(self):
        self.cresc("profile", "new", "demo")
        ids = self.triage_ids()
        rid = ids["/Users/me/Library/Caches/x y/file \"name\".tmp"]
        p = self.cresc("profile", "grant", "demo", FIXTURE, "--id", rid, "--id", ids["hw.pagesize_compat"],
                     "--home", "/Users/me", "--path", PATH_FOR_NOISE, expect=65)
        self.assertIn("need --confirm", p.stderr)
        self.assertNotIn("pagesize", self.cresc("profile", "show", "demo").stdout)    #= all-or-nothing
        self.cresc("profile", "grant", "demo", FIXTURE, "--id", rid, "--confirm", "--home", "/Users/me",
                 "--path", PATH_FOR_NOISE)
        self.assertIn('x y/file \\"name\\".tmp', self.cresc("profile", "show", "demo").stdout)

    def test_unknown_rule_id_and_revoke_and_diff(self):
        self.cresc("profile", "new", "demo")
        self.cresc("profile", "grant", "demo", FIXTURE, "--id", "deadbeef00", expect=65)
        self.cresc("profile", "grant", "demo", FIXTURE, "--auto", "low", "--home", "/Users/me", "--path", PATH_FOR_NOISE)
        rid = self.triage_ids()["kern.bootargs"]
        self.assertIn("revoked", self.cresc("profile", "revoke", "demo", rid).stdout)
        self.assertNotIn("kern.bootargs", self.cresc("profile", "show", "demo").stdout)
        self.assertIn("v1.sb", self.cresc("profile", "diff", "demo", "1", "2").stdout)
        self.cresc("profile", "revoke", "demo", "nope", expect=65)

    def test_grant_needs_a_selection_and_options_work_after_the_subcommand(self):
        self.cresc("profile", "new", "demo", "--store", self.store)
        self.cresc("profile", "grant", "demo", FIXTURE, expect=64)


class ManualGrants(CliCase):
    def setUp(self):
        super().setUp()
        self.cresc("profile", "new", "demo")

    def test_manual_low_risk_rule(self):
        out = self.cresc("profile", "grant", "demo", "--manual", "sysctl-read hw.pagesize", stdin="").stdout
        self.assertIn('(allow sysctl-read (sysctl-name "hw.pagesize"))', out)
        self.assertIn("hw.pagesize", self.cresc("profile", "show", "demo").stdout)

    def test_manual_dangerous_rules_need_confirm_like_logged_ones(self):
        p = self.cresc("profile", "grant", "demo", "--manual", "file-write-create /Users/me/x", expect=65, stdin="")
        self.assertIn("need --confirm", p.stderr)
        self.assertNotIn("/Users/me/x", self.cresc("profile", "show", "demo").stdout)
        self.cresc("profile", "grant", "demo", "--manual", "file-write-create /Users/me/x", "--confirm", stdin="")
        self.assertIn('(literal "/Users/me/x")', self.cresc("profile", "show", "demo").stdout)

    def test_manual_rule_without_a_known_form_is_refused(self):
        p = self.cresc("profile", "grant", "demo", "--manual", "iokit-open IOSurfaceRootUserClient", expect=64, stdin="")
        self.assertIn("no rule form", p.stderr)
        self.cresc("profile", "grant", "demo", "--manual", "   ", expect=64, stdin="")

    def test_manual_rule_cannot_inject_profile_text(self):
        self.cresc("profile", "grant", "demo", "--manual", 'file-read-data /x") (allow default) ("', stdin="")
        text = self.cresc("profile", "show", "demo").stdout
        self.assertNotIn("\n(allow default)", text)
        self.assertIn('\\")', text)                            #= the quote was escaped, not interpreted


class RunWorkflow(CliCase):
    def setUp(self):
        super().setUp()
        self.work = os.path.join(self.root, "work")
        self.sbx, self.log = os.path.join(self.root, "sbx"), os.path.join(self.root, "log")
        self.denials = os.path.join(self.root, "denials.ndjson")
        write_exec(self.sbx, FAKE_SANDBOX_EXEC)
        write_exec(self.log, FAKE_LOG)
        self.set_denials([("sh", "sysctl-read", "hw.ncpu"), ("sh", "file-write-create", self.work + "/../outside.txt")])
        self.env.update(CRESC_SANDBOX_EXEC=self.sbx, CRESC_LOG=self.log, FAKE_DENIALS=self.denials,
                        FAKE_ARGV_OUT=os.path.join(self.root, "argv.txt"))
        self.cresc("profile", "new", "demo")

    def set_denials(self, rows):
        with open(self.denials, "w") as fh:
            for proc, op, target in rows:
                fh.write(json.dumps({"eventMessage": "Sandbox: %s(4242) deny(1) %s %s" % (proc, op, target)}) + "\n")

    def run_args(self):
        return ["--target", "sh", "--write-dir", self.work, "--settle", "0.4", "--startup-wait", "0.1",
                "--pass-env", "FAKE_ARGV_OUT"]

    def test_run_json_runs_compare(self):
        d = json.loads(self.cresc("run", "demo", *self.run_args(), "--json", "--", "-c", "exit 2").stdout)
        self.assertEqual((d["schema"], d["exit"], d["profile_version"], d["run"]), ("cresc.run/1", 2, 1, 1))
        self.assertEqual(d["triage"]["summary"]["candidate"], 2)
        self.cresc("profile", "grant", "demo", "--run", "last", "--auto", "low", "--home", self.root)
        self.set_denials([("sh", "file-write-create", self.work + "/../outside.txt")])
        d2 = json.loads(self.cresc("run", "demo", *self.run_args(), "--json", "--", "-c", "exit 0").stdout)
        self.assertEqual((d2["run"], d2["profile_version"], d2["exit"]), (2, 2, 0))
        cmp = json.loads(self.cresc("compare", "demo", "1", "2", "--json").stdout)
        self.assertEqual([r["target"] for r in cmp["resolved"]], ["hw.ncpu"])
        runs = json.loads(self.cresc("runs", "demo", "--json").stdout)["runs"]
        self.assertEqual([r["run"] for r in runs], [1, 2])
        self.assertIn("RUN", self.cresc("runs", "demo").stdout)
        self.assertIn("RESOLVED: 1", self.cresc("compare", "demo", "1", "2").stdout)

    def test_triage_reads_a_stored_run(self):
        self.cresc("run", "demo", *self.run_args(), "--", "-c", "exit 0")
        d = json.loads(self.cresc("triage", "--json", "--profile", "demo", "--run", "last", "--home", self.root).stdout)
        self.assertEqual(d["summary"]["candidate"], 2)

    def test_loop_grants_and_restarts_then_quits(self):
        #= run 1 shows 2 denials; "g low" grants the sysctl; the loop restarts (run 2) with profile v2; "q" quits
        p = self.cresc("loop", "demo", *self.run_args(), "--", "-c", "exit 0", stdin="g low\nq\n")
        self.assertIn("run 1 under demo v1", p.stdout)
        self.assertIn("granted 1 rule(s): profile is now v2", p.stdout)
        self.assertIn("run 2 under demo v2", p.stdout)
        self.assertIn('hw.ncpu', self.cresc("profile", "show", "demo").stdout)
        self.assertNotIn("file-write-create (literal", self.cresc("profile", "show", "demo").stdout)   #= high risk: not granted

    def test_loop_high_risk_requires_typing_yes(self):
        rid = json.loads(self.cresc("triage", "--json", "--home", self.root, "--path", "/usr/bin",
                                  stdin="Sandbox: sh(1) deny(1) file-write-create %s/../outside.txt\n" % self.work).stdout)
        rid = rid["items"][0]["rule"]["id"]
        p = self.cresc("loop", "demo", *self.run_args(), "--", "-c", "exit 0", stdin="g %s\nno\nq\n" % rid)
        self.assertIn("needs confirmation", p.stdout)
        self.assertNotIn("outside.txt", self.cresc("profile", "show", "demo").stdout)
        p = self.cresc("loop", "demo", *self.run_args(), "--", "-c", "exit 0", stdin="g %s\nYES\nq\n" % rid)
        self.assertIn("outside.txt", self.cresc("profile", "show", "demo").stdout)

    def test_loop_restart_and_eof(self):
        p = self.cresc("loop", "demo", *self.run_args(), "--", "-c", "exit 0", stdin="r\n")      #= restart, then EOF = quit
        self.assertIn("run 2 under demo v1", p.stdout)

    def test_loop_manual_rule_then_restart(self):
        p = self.cresc("loop", "demo", *self.run_args(), "--", "-c", "exit 0", stdin="a sysctl-read hw.pagesize\nq\n")
        self.assertIn("granted 1 rule(s): profile is now v2", p.stdout)
        self.assertIn("run 2 under demo v2", p.stdout)
        self.assertIn("hw.pagesize", self.cresc("profile", "show", "demo").stdout)
        bad = self.cresc("loop", "demo", *self.run_args(), "--", "-c", "exit 0", stdin="a iokit-open X\nq\n")
        self.assertIn("not granted", bad.stdout)

    def test_failure_without_denials_explains_what_to_do(self):
        self.set_denials([])
        p = self.cresc("run", "demo", *self.run_args(), "--", "-c", "exit 2")
        self.assertIn("no grantable denial was logged", p.stdout)
        ok = self.cresc("run", "demo", *self.run_args(), "--", "-c", "exit 0")
        self.assertNotIn("no grantable denial", ok.stdout)           #= a clean exit needs no hint

    def test_refuses_dangerous_write_dirs(self):
        p = self.cresc("run", "demo", "--target", "sh", "--write-dir", "/", expect=65)
        self.assertIn("refusing", p.stderr)
        self.cresc("run", "demo", "--target", "sh", "--write-dir", "relative", expect=65)


if __name__ == "__main__":
    unittest.main()
