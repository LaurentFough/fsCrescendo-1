#= test_export.py  version 0.1.0 (2026-11-08)
#= Evidence bundles: contents, redaction, manifest verification (tamper detection), unsafe archives, CLI and server.
import json
import os
import shutil
import tempfile
import unittest
import zipfile

from cresc.export import ExportError, build_bundle, verify_bundle
from cresc.profile import Profile
from cresc.session import run_once
from tests.test_profile_session import FAKE_LOG, FAKE_SANDBOX_EXEC, write_exec
from tests.test_serve import ServeCase


class BundleBase(unittest.TestCase):
    """A real run (fake sandbox-exec / log) so the bundle is built from genuine run directories."""

    def setUp(self):
        self.root = os.path.realpath(tempfile.mkdtemp(prefix="cresc-export-"))
        self.addCleanup(shutil.rmtree, self.root, True)
        self.home = os.path.join(self.root, "home")
        os.makedirs(self.home)
        self.store = os.path.join(self.root, "store")
        self.sandbox = os.path.join(self.root, "sbx")
        self.log = os.path.join(self.root, "lg")
        write_exec(self.sandbox, FAKE_SANDBOX_EXEC)
        write_exec(self.log, FAKE_LOG)
        denials = os.path.join(self.root, "denials.ndjson")
        with open(denials, "w") as fh:
            fh.write(json.dumps({"eventMessage": "Sandbox: sh(4242) deny(1) sysctl-read hw.ncpu"}) + "\n")
        env = {"CRESC_SANDBOX_EXEC": self.sandbox, "CRESC_LOG": self.log, "FAKE_DENIALS": denials,
               "FAKE_ARGV_OUT": os.path.join(self.root, "argv.txt")}
        saved = {k: os.environ.get(k) for k in env}
        os.environ.update(env)
        self.addCleanup(lambda: [os.environ.pop(k, None) if v is None else os.environ.__setitem__(k, v) for k, v in saved.items()])
        self.prof = Profile.create(self.store, "demo")
        self.write_dir = os.path.join(self.root, "w")
        os.makedirs(self.write_dir)
        self.script = "echo hello from %s; echo err >&2" % self.home
        self.res = self.run_it()

    def run_it(self):
        return run_once(self.prof, "sh", [self.write_dir], ["-c", self.script], sandbox_exec=self.sandbox, log_bin=self.log,
                        settle=0.2, startup_wait=0.1, pass_env=["FAKE_ARGV_OUT"])

    def build(self, name="b.zip", **kw):
        out = os.path.join(self.root, name)
        info = build_bundle(self.prof, self.res.number, out, [], self.home, **kw)
        return out, info


class BundleTests(BundleBase):
    def test_contents_and_verify(self):
        out, info = self.build()
        self.assertEqual(len(info["sha256"]), 64)
        top = info["top"]
        with zipfile.ZipFile(out) as zf:
            names = set(zf.namelist())
            for need in ("README.md", "manifest.json", "run/result.json", "run/stdout.txt", "run/stderr.txt",
                         "run/denials.jsonl", "analysis/triage.json", "analysis/denials.csv", "profile/meta.json",
                         "profile/profile-v1.sb"):
                self.assertIn(top + "/" + need, names, need)
            readme = zf.read(top + "/README.md").decode()
            self.assertTrue(readme.startswith("---\ntitle:"))               #= PKIM frontmatter
            meta = json.loads(zf.read(top + "/run/result.json"))
            self.assertEqual(meta["stdout"], "stdout.txt")                  #= no absolute disk paths
        result = verify_bundle(out)
        self.assertTrue(result["ok"], result["problems"])
        self.assertEqual(result["checked"], len(info["files"]) - 1)         #= everything but the manifest itself

    def test_home_is_redacted_unless_disabled(self):
        out, _ = self.build()
        with zipfile.ZipFile(out) as zf:
            blob = b"".join(zf.read(n) for n in zf.namelist())
            self.assertIn(b"hello from ~", zf.read(_find(zf, "run/stdout.txt")))      #= the program really printed it
        self.assertNotIn(self.home.encode(), blob)
        out2, _ = self.build("raw.zip", redact=False)
        with zipfile.ZipFile(out2) as zf:
            self.assertIn(self.home.encode(), zf.read(_find(zf, "run/stdout.txt")))

    def test_tampering_is_detected(self):
        out, info = self.build()
        bad = os.path.join(self.root, "bad.zip")
        with zipfile.ZipFile(out) as src, zipfile.ZipFile(bad, "w") as dst:
            for item in src.infolist():
                data = src.read(item.filename)
                if item.filename.endswith("run/stdout.txt"):
                    data = b"forged output\n"
                if item.filename.endswith("analysis/denials.csv"):
                    continue
                dst.writestr(item.filename, data)
            dst.writestr(info["top"] + "/extra.txt", b"x")
        result = verify_bundle(bad)
        self.assertFalse(result["ok"])
        text = " ".join(result["problems"])
        for expect in ("hash differs: run/stdout.txt", "missing: analysis/denials.csv", "not in manifest: extra.txt"):
            self.assertIn(expect, text)

    def test_unsafe_archives_are_refused(self):
        evil = os.path.join(self.root, "evil.zip")
        with zipfile.ZipFile(evil, "w") as zf:
            zf.writestr("top/../../escape.txt", b"x")
            zf.writestr("top/manifest.json", b"{}")
        self.assertFalse(verify_bundle(evil)["ok"])
        self.assertFalse(verify_bundle(os.path.join(self.root, "missing.zip"))["ok"])
        junk = os.path.join(self.root, "junk.zip")
        with open(junk, "w") as fh:
            fh.write("not a zip")
        self.assertFalse(verify_bundle(junk)["ok"])

    def test_output_path_rules(self):
        out, _ = self.build()
        with self.assertRaises(ExportError):
            build_bundle(self.prof, self.res.number, out, [], self.home)               #= exists, no force
        build_bundle(self.prof, self.res.number, out, [], self.home, force=True)
        for bad in ("relative.zip", os.path.join(self.root, "x.txt")):
            with self.assertRaises(ExportError):
                build_bundle(self.prof, self.res.number, bad, [], self.home)
        with self.assertRaises(ExportError):
            build_bundle(self.prof, 99, os.path.join(self.root, "n.zip"), [], self.home)
        self.assertFalse([f for f in os.listdir(self.root) if f.endswith(".part")])

    def test_events_and_compare(self):
        ev = os.path.join(self.root, "ev.jsonl")
        with open(ev, "w") as fh:
            fh.write('{"a": "%s"}\n{"b": 2}\n' % self.home)
        second = self.run_it()
        out = os.path.join(self.root, "two.zip")
        info = build_bundle(self.prof, second.number, out, [], self.home, events_file=ev)
        self.assertIn("events/events.jsonl", info["files"])
        self.assertIn("analysis/compare-previous.json", info["files"])
        with zipfile.ZipFile(out) as zf:
            events = zf.read(_find(zf, "events/events.jsonl")).decode()
        self.assertNotIn(self.home, events)
        self.assertTrue(verify_bundle(out)["ok"])


def _find(zf, suffix):
    return next(n for n in zf.namelist() if n.endswith(suffix))


class ExportCliTests(BundleBase):
    def run_cli(self, *argv):
        import contextlib
        import io
        from cresc.cli import main
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = main(list(argv))
        return code, buf.getvalue()

    def test_export_and_verify_commands(self):
        out = os.path.join(self.root, "cli.zip")
        code, text = self.run_cli("export", "demo", "--store", self.store, "-o", out, "--json")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(text)["schema"], "cresc.bundle/1")
        code, text = self.run_cli("verify-bundle", out, "--json")
        self.assertEqual((code, json.loads(text)["ok"]), (0, True))
        code, _ = self.run_cli("export", "demo", "--store", self.store, "-o", out)            #= exists
        self.assertEqual(code, 65)


class ExportServeTests(ServeCase):
    def test_export_over_the_protocol(self):
        c = self.client()
        c.call("profile.new", name="demo")
        self.assertEqual(c.call("run.export", expect_ok=False, name="demo")["code"], "not_found")
        self.assertEqual(c.call("run.export", expect_ok=False, name="demo", path="rel.zip")["code"], "invalid_params")
        self.assertEqual(c.call("bundle.verify", expect_ok=False, path="rel.zip")["code"], "invalid_params")


if __name__ == "__main__":
    unittest.main()
