#= test_cleanup.py  version 0.1.0 (2026-11-09)
#= Cleanup modes (none / coalesce / prune) on hand-built scenarios, streaming settle behaviour, the real file capture,
#= `watch.start cleanup=...` through a real `cresc serve` process, and `cresc watch --files`.
import contextlib
import io
import json
import os
import subprocess
import sys
import unittest

from cresc.cleanup import Cleaner, MODES, clean
from cresc.events import parse_event
from cresc.filechange import FileChange, from_event
from tests.test_serve import PKG_ROOT, ServeCase

HERE = os.path.dirname(os.path.abspath(__file__))
REAL = os.path.join(HERE, "fixtures", "eslogger-file-events.jsonl")
_seq = [0]


def fc(category, path, text=None, pid=10, inode=1, source="", **details):
    _seq[0] += 1
    ts = "2026-11-09T10:00:%02d.%06dZ" % (_seq[0] // 1000000, _seq[0] % 1000000)
    return FileChange(category=category, event_type=text or category, ts=ts, seq=_seq[0], path=path, source_path=source,
                      inode=inode, device=1, pid=pid, process_path="/bin/w", details=details)


def rename(src, dst, replaced=False, pid=10, inode=1):
    return [fc("moved_from", src, "Item Renamed", pid=pid, inode=inode, destination=dst),
            fc("moved_to", dst, "Item Renamed", pid=pid, inode=inode, source=src, replaced=replaced)]


def summary(rows):
    return [(r.category, os.path.basename(r.path), r.count) for r in rows]


class RuleTests(unittest.TestCase):
    def test_none_is_a_passthrough(self):
        rows = [fc("created", "/d/a"), fc("modified", "/d/a"), fc("deleted", "/d/a")]
        self.assertEqual(clean(rows, "none"), rows)
        self.assertEqual(Cleaner("none").feed(rows[0]), [rows[0]])

    def test_unknown_mode(self):
        with self.assertRaises(ValueError):
            Cleaner("bogus")
        self.assertEqual(MODES, ("none", "coalesce", "prune"))

    def test_temp_file_disappears_in_prune_only(self):
        rows = [fc("created", "/d/tmp"), fc("modified", "/d/tmp"), fc("modified", "/d/tmp"), fc("deleted", "/d/tmp")]
        self.assertEqual(clean(rows, "prune"), [])
        self.assertEqual(summary(clean(rows, "coalesce")), [("created", "tmp", 1), ("modified", "tmp", 2), ("deleted", "tmp", 1)])

    def test_atomic_save_becomes_one_modified_row(self):
        rows = [fc("created", "/d/.t1", pid=7), fc("modified", "/d/.t1", pid=7), fc("modified", "/d/.t1", pid=7)] \
            + rename("/d/.t1", "/d/plist", replaced=True, pid=7)
        out = clean(rows, "prune")
        self.assertEqual(len(out), 1)
        r = out[0]
        self.assertEqual((r.category, r.event_type, r.path, r.source_path, r.pid), ("modified", "Content Replaced", "/d/plist", "/d/.t1", 7))
        self.assertEqual(r.count, 5)
        self.assertTrue(r.details["collapsed"])
        self.assertEqual(len(clean(rows, "coalesce")), 4)                    #= created, modified x2 coalesced into one, moved_from, moved_to

    def test_created_then_renamed_to_a_new_name_is_one_created_row(self):
        rows = [fc("created", "/d/new.txt"), fc("modified", "/d/new.txt")] + rename("/d/new.txt", "/d/final.txt")
        out = clean(rows, "prune")
        self.assertEqual(summary(out), [("created", "final.txt", 4)])
        self.assertEqual(out[0].event_type, "Item Created")

    def test_renaming_an_old_file_is_kept_as_a_move(self):
        out = clean(rename("/d/old", "/d/older"), "prune")
        self.assertEqual([r.category for r in out], ["moved_from", "moved_to"])

    def test_deleting_an_old_file_is_kept(self):
        rows = [fc("modified", "/d/old"), fc("deleted", "/d/old")]
        self.assertEqual([r.category for r in clean(rows, "prune")], ["modified", "deleted"])

    def test_repeated_modifications_coalesce(self):
        rows = [fc("modified", "/d/log", "Content Modified") for _ in range(5)]
        out = clean(rows, "coalesce")
        self.assertEqual(summary(out), [("modified", "log", 5)])
        self.assertEqual(out[0].details["first_ts"], rows[0].ts)
        self.assertEqual(out[0].ts, rows[-1].ts)                             #= the newest timestamp is kept
        self.assertEqual(len(clean([fc("modified", "/d/a", pid=1), fc("modified", "/d/a", pid=2)], "coalesce")), 2)   #= different writers stay apart

    def test_interleaved_modifications_and_attribute_changes_still_coalesce(self):
        rows = [fc("modified", "/d/img"), fc("attributes", "/d/img"), fc("modified", "/d/img"), fc("attributes", "/d/img"), fc("modified", "/d/img")]
        out = clean(rows, "coalesce")
        self.assertEqual(sorted((r.category, r.count) for r in out), [("attributes", 2), ("modified", 3)])
        #= a structural change (rename, delete) ends the segment
        rows = [fc("modified", "/d/x")] + rename("/d/x", "/d/y") + [fc("modified", "/d/y"), fc("modified", "/d/y")]
        self.assertEqual([(r.category, r.count) for r in clean(rows, "coalesce")],
                         [("modified", 1), ("moved_from", 1), ("moved_to", 1), ("modified", 2)])

    def test_different_files_do_not_mix(self):
        rows = [fc("created", "/d/a"), fc("created", "/d/b"), fc("deleted", "/d/a"), fc("modified", "/d/b")]
        self.assertEqual(summary(clean(rows, "prune")), [("created", "b", 1), ("modified", "b", 1)])

    def test_hard_link_created_and_removed_is_transient_but_the_original_stays(self):
        rows = [fc("created", "/d/orig", inode=5), fc("created", "/d/link", "Item Linked", inode=5, source="/d/orig"),
                fc("deleted", "/d/link", inode=5)]
        self.assertEqual(summary(clean(rows, "prune")), [("created", "orig", 1)])

    def test_two_saves_of_the_same_target_inside_the_window_become_one_row(self):
        rows = []
        for _ in range(2):
            rows += [fc("created", "/d/.t", pid=3), fc("modified", "/d/.t", pid=3)] + rename("/d/.t", "/d/doc", replaced=True, pid=3)
        out = clean(rows, "prune")
        self.assertEqual(summary(out), [("modified", "doc", 8)])                #= one lifetime of the path; first_ts..ts is the span
        self.assertEqual(out[0].details["first_ts"], rows[0].ts)
        #= saves separated by a quiet period (the window) stay separate rows
        c = Cleaner("prune", window=1.0)
        seen = []
        for t, group in ((0.0, rows[:4]), (10.0, rows[4:])):
            for row in group:
                seen += c.feed(row, now=t)
        seen += c.flush()
        self.assertEqual([(r.category, r.count) for r in seen], [("modified", 4), ("modified", 4)])

    def test_clone_and_create_of_one_file_are_one_creation(self):
        rows = [fc("created", "/d/c", "Item Cloned", pid=9, inode=1, source="/d/o"), fc("created", "/d/c", "Item Created", pid=9, inode=2)]
        out = clean(rows, "coalesce")
        self.assertEqual((len(out), out[0].event_type, out[0].count), (1, "Item Cloned", 2))
        self.assertEqual(clean(rows + [fc("deleted", "/d/c", inode=2)], "prune"), [])      #= and a deleted clone is transient

    def test_replaced_file_that_is_later_deleted_leaves_nothing(self):
        #= create X, rename it to Y (new name), save Y atomically (replaced), delete Y: Y never existed before and is gone
        rows = [fc("created", "/d/x")] + rename("/d/x", "/d/y") \
            + [fc("created", "/d/.t", pid=2), fc("modified", "/d/.t", pid=2)] + rename("/d/.t", "/d/y", replaced=True, pid=2) \
            + [fc("deleted", "/d/y")]
        self.assertEqual(clean(rows, "prune"), [])

    def test_output_is_ordered_by_time(self):
        rows = [fc("modified", "/d/a"), fc("modified", "/d/b"), fc("deleted", "/d/a"), fc("attributes", "/d/b")]
        out = clean(rows, "prune")
        self.assertEqual([r.ts for r in out], sorted(r.ts for r in out))


class StreamingTests(unittest.TestCase):
    def test_rows_leave_only_after_the_file_was_quiet(self):
        c = Cleaner("prune", window=2.0)
        self.assertEqual(c.feed(fc("created", "/d/a"), now=0.0), [])
        self.assertEqual(c.feed(fc("modified", "/d/a"), now=1.0), [])
        self.assertEqual(c.settle(now=2.5), [])                                 #= a was active at 1.0: quiet only from 3.0
        out = c.settle(now=3.1)
        self.assertEqual([r.category for r in out], ["created", "modified"])
        self.assertEqual(c.settle(now=99), [])

    def test_a_delete_closes_the_file_at_once(self):
        c = Cleaner("prune", window=60)
        c.feed(fc("modified", "/d/a"), now=0)
        out = c.feed(fc("deleted", "/d/a"), now=1)
        self.assertEqual([r.category for r in out], ["modified", "deleted"])

    def test_a_meta_row_flushes_everything_first(self):
        c = Cleaner("prune", window=60)
        c.feed(fc("modified", "/d/a"), now=0)
        meta = FileChange(category="meta", event_type="Recording stopped", ts="2026-11-09T11:00:00Z", path="x")
        out = c.feed(meta, now=1)
        self.assertEqual([r.category for r in out], ["modified", "meta"])

    def test_flush_releases_a_rename_that_never_finished(self):
        c = Cleaner("prune", window=60)
        c.feed(rename("/d/a", "/d/b")[0], now=0)
        self.assertEqual([r.category for r in c.flush()], ["moved_from"])

    def test_buffer_cap_forces_the_oldest_out(self):
        c = Cleaner("coalesce", window=999, max_open=3)
        out = []
        for i in range(6):
            out += c.feed(fc("modified", "/d/f%d" % i), now=float(i))
        self.assertGreaterEqual(len(out), 3)
        self.assertLessEqual(len(c._live), 3)


class RealCaptureTests(unittest.TestCase):
    def rows(self):
        with open(REAL) as fh:
            return [c for line in fh for c in from_event(parse_event(line))]

    def test_prune_shrinks_the_real_capture_and_keeps_the_final_state(self):
        raw = self.rows()
        pruned = clean(raw, "prune")
        coalesced = clean(raw, "coalesce")
        self.assertLess(len(pruned), len(coalesced))
        self.assertLessEqual(len(coalesced), len(raw))
        names = [os.path.basename(r.path) for r in pruned if r.category == "created"]
        self.assertIn("crescendo-ready-marker", names)                             #= left on disk until the scratch folder went away
        #= every file the script created and removed again (hard.txt, clone.txt, renamed.txt, sub2) is gone from the pruned view
        for transient in ("hard.txt", "clone.txt", "renamed.txt"):
            self.assertNotIn(transient, [os.path.basename(r.path) for r in pruned if r.category in ("created", "moved_to")], transient)
        self.assertTrue(all(r.category != "deleted" or r.count >= 1 for r in pruned))

    def test_none_keeps_everything(self):
        raw = self.rows()
        self.assertEqual(len(clean(raw, "none")), len(raw))


class ServeCleanupTests(ServeCase):
    def test_watch_start_cleanup_prune_emits_fewer_rows(self):
        def collect(cleanup):
            c = self.client()
            w = c.call("watch.start", source={"file": REAL}, view="files", no_mute=True, cleanup=cleanup, cleanup_window=0.2)
            c.event("watch.ended", timeout=30)
            rows = [e["data"]["change"] for e in c.events if e["event"] == "watch.change" and e["data"]["watch_id"] == w["watch_id"]]
            return rows
        plain, pruned = collect("none"), collect("prune")
        self.assertLess(len(pruned), len(plain))
        self.assertEqual(pruned[-1]["event_type"], "Recording stopped")           #= the stop marker is still the last row
        self.assertEqual(pruned[0]["event_type"], "Recording started")

    def test_bad_cleanup_is_refused(self):
        c = self.client()
        self.assertEqual(c.call("watch.start", expect_ok=False, source={"file": REAL}, view="files", cleanup="x")["code"], "invalid_params")
        self.assertEqual(c.call("watch.start", expect_ok=False, source={"file": REAL}, view="files", cleanup_window=999)["code"], "invalid_params")


class CliTests(unittest.TestCase):
    def run_watch(self, *extra):
        p = subprocess.run([sys.executable, "-m", "cresc", "watch", REAL, "--files", "--no-mute"] + list(extra),
                           cwd=PKG_ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=60)
        self.assertEqual(p.returncode, 0, p.stderr)
        return p.stdout.splitlines()

    def test_files_view_text_and_json(self):
        lines = self.run_watch()
        self.assertTrue(lines[0].startswith("DATE"))
        self.assertTrue(any(" CRE " in l for l in lines))
        self.assertTrue(any(" MVT " in l for l in lines))
        rows = [json.loads(l) for l in self.run_watch("--json")]
        self.assertTrue(all(r["schema"] == "cresc.filechange/1" for r in rows))

    def test_cleanup_prune_lists_fewer_lines(self):
        plain = self.run_watch("--json")
        pruned = self.run_watch("--json", "--cleanup", "prune", "--cleanup-window", "0.1")
        self.assertLess(len(pruned), len(plain))


if __name__ == "__main__":
    unittest.main()
