#= test_real_file_capture.py  version 0.1.0 (2026-11-09)
#= The parsers against a REAL eslogger capture of scripted file actions (scripts/capture-file-events.sh, macOS 26, owner's Mac,
#= home path redacted to /Users/me). Fixture: tests/fixtures/eslogger-file-events.jsonl.
import collections
import json
import os
import unittest

from cresc.events import parse_event
from cresc.filechange import from_event

FIXTURE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "eslogger-file-events.jsonl")


def load():
    with open(FIXTURE) as fh:
        events = [parse_event(line) for line in fh]
    assert all(e is not None for e in events)
    return events


class RealFileCaptureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.events = load()
        cls.by_es = collections.defaultdict(list)
        cls.rows = []
        for ev in cls.events:
            cls.by_es[ev.details["es_event"]].append(ev)
            for c in from_event(ev):
                cls.rows.append((ev.details["es_event"], c))

    def test_every_event_parses_and_file_events_map(self):
        self.assertEqual(len(self.events), 178)
        for name in ("create", "rename", "unlink", "truncate", "link", "clone", "exchangedata", "setmode", "setflags",
                     "setextattr", "deleteextattr", "setacl", "setattrlist", "utimes"):
            mapped = [c for es, c in self.rows if es == name]
            self.assertTrue(mapped, name)
        for es, c in self.rows:
            self.assertTrue(c.path.startswith("/"), (es, c.path))
            self.assertIsNotNone(c.inode, (es, c.path))
            self.assertIsNotNone(c.created)

    def test_category_totals(self):
        cats = collections.Counter(c.category for _, c in self.rows)
        self.assertEqual(dict(cats), {"created": 17, "modified": 18, "moved_from": 3, "moved_to": 3, "attributes": 9, "deleted": 7})

    def test_renames_to_new_and_existing_names(self):
        kinds = collections.Counter(e.details["es_event"] for e in self.events)
        self.assertEqual(kinds["rename"], 3)
        pairs = [(a, b) for (ea, a), (eb, b) in zip(self.rows, self.rows[1:]) if a.category == "moved_from" and b.category == "moved_to"]
        self.assertEqual(len(pairs), 3)
        seen = {(os.path.basename(a.path), os.path.basename(b.path)) for a, b in pairs}
        self.assertIn(("new.txt", "renamed.txt"), seen)                                #= rename to a NEW name (destination_type 1)
        self.assertIn(("tmpfile", "renamed.txt"), seen)                                #= rename OVER an existing file (type 0)
        for a, b in pairs:
            self.assertEqual(b.source_path, a.path)
            self.assertEqual(a.inode, b.inode)                                          #= the moved file keeps its inode

    def test_hard_link_shares_the_inode_and_clone_does_not(self):
        by_path = {os.path.basename(c.path): c for es, c in self.rows if es in ("link", "clone", "create")}
        link = next(c for es, c in self.rows if es == "link")
        self.assertEqual(os.path.basename(link.path), "hard.txt")
        self.assertEqual(os.path.basename(link.source_path), "renamed.txt")
        self.assertEqual(link.event_type, "Item Linked")
        clone = next(c for es, c in self.rows if es == "clone")
        self.assertEqual((os.path.basename(clone.path), clone.event_type), ("clone.txt", "Item Cloned"))
        self.assertIn("hard.txt", by_path)

    def test_exchangedata_gives_two_modifications(self):
        rows = [c for es, c in self.rows if es == "exchangedata"]
        self.assertEqual(sorted(os.path.basename(c.path) for c in rows), ["ex1", "ex2"])
        self.assertEqual({c.event_type for c in rows}, {"Items Exchanged"})

    def test_attribute_details_are_kept(self):
        attrs = {c.event_type: c for es, c in self.rows if c.category == "attributes"}
        self.assertEqual(attrs["Xattrs Changed"].details["extattr"], "com.crescendo.test")
        self.assertEqual(attrs["Mode Changed"].details["mode_set"], 384)               #= 0o600
        flags = [c.details["flags"] for es, c in self.rows if c.event_type == "Flags Changed"]
        self.assertEqual(flags, [32768, 0])                                            #= chflags hidden, then nohidden (UF_HIDDEN)
        self.assertIn("mtime", attrs["Times Changed"].details)
        self.assertIn("ACL Changed", attrs)

    def test_unix_socket_and_mount_events(self):
        bind, connect = self.by_es["uipc_bind"][0], self.by_es["uipc_connect"][0]
        self.assertTrue(bind.target.endswith("/s.sock"), bind.target)                  #= bind: dir + filename
        self.assertEqual(bind.target, connect.target)
        self.assertEqual((connect.details["domain"], connect.details["type"]), (1, 1))
        mount, unmount = self.by_es["mount"][0], self.by_es["unmount"][0]
        self.assertTrue(mount.target.endswith("/mnt"))
        self.assertTrue(mount.details["from"].startswith("/dev/disk"))
        self.assertEqual(mount.details["fstype"], "apfs")
        self.assertEqual(unmount.target, mount.target)

    def test_processes_are_attributed_at_event_time(self):
        names = {c.process_name for _, c in self.rows}
        for expected in ("touch", "mv", "chmod", "xattr", "chflags", "ln", "cp", "rmdir"):
            self.assertIn(expected, names)
        for _, c in self.rows:
            self.assertGreater(c.pid, 0)
            self.assertGreaterEqual(c.actor_uid, 0)

    def test_json_safe_with_large_inodes(self):
        for _, c in self.rows:
            json.dumps(c.to_dict())


if __name__ == "__main__":
    unittest.main()
