#= test_capture.py  version 0.1.0 (2026-11-09)
#= The capture filter: markers, redaction, non-event lines, and the CLI wrapper.
import contextlib
import io
import json
import os
import tempfile
import unittest

from cresc.capture import filter_capture
from cresc.cli import main


def ev(name, payload):
    return json.dumps({"time": "2026-11-09T10:00:00.000000000Z", "process": {"audit_token": {"pid": 5}, "executable": {"path": "/Users/alice/bin/tool"}},
                       "event": {name: payload}}).replace("/", "\\/")        #= real eslogger escapes slashes


class CaptureTests(unittest.TestCase):
    def test_only_marked_events_are_kept_and_home_is_redacted(self):
        lines = [ev("create", {"path": "/Users/alice/crescendo-capture-X/a"}), ev("open", {"path": "/etc/hosts"}),
                 "not json", "", ev("unlink", {"path": "/Users/alice/crescendo-capture-X/a"}), "[1,2]", "{}", "{\"event\": {}}"]
        kept, counts = filter_capture(lines, ["crescendo-capture-X"], home="/Users/alice")
        self.assertEqual(counts, {"create": 1, "unlink": 1})
        self.assertEqual(len(kept), 2)
        joined = "".join(kept)
        self.assertNotIn("alice", joined)
        self.assertIn("/Users/me/crescendo-capture-X/a", joined)
        self.assertIn("/Users/me/bin/tool", joined)                          #= the actor path is redacted too
        for line in kept:
            json.loads(line)

    def test_no_markers_means_keep_all_events(self):
        kept, _ = filter_capture([ev("open", {"path": "/etc/hosts"})], [])
        self.assertEqual(len(kept), 1)

    def test_cli(self):
        with tempfile.TemporaryDirectory() as d:
            raw, out = os.path.join(d, "raw.jsonl"), os.path.join(d, "out.jsonl")
            with open(raw, "w") as fh:
                fh.write(ev("create", {"path": "/Users/alice/m/x"}) + "\n" + ev("open", {"path": "/etc/passwd"}) + "\n")
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                code = main(["capture-filter", raw, out, "--marker", "/Users/alice/m", "--redact-home", "/Users/alice"])
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(buf.getvalue())["kept"], 1)
            with open(out) as fh:
                self.assertNotIn("alice", fh.read())


if __name__ == "__main__":
    unittest.main()
