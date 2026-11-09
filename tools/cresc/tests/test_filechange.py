#= test_filechange.py  version 0.1.0 (2026-11-09)
#= File-change model: eslogger event -> created / deleted / modified / attributes / moved_from / moved_to / meta,
#= stat extraction, path normalisation, text lines, and `watch.start view=files` through a real `cresc serve` process.
#= Synthetic shapes; the real capture is covered by test_real_file_capture.py.
import json
import os
import tempfile
import unittest

from cresc.events import parse_event
from cresc.filechange import CATEGORIES, FILE_EVENTS, canonical_path, format_change, from_event, meta_change
from tests.test_serve import ServeCase

HERE = os.path.dirname(os.path.abspath(__file__))
REAL = os.path.join(HERE, "fixtures", "eslogger-real-shape.jsonl")


def stat(ino=11, mode=33188, uid=501, gid=20, size=5):
    return {"st_ino": ino, "st_dev": 16777234, "st_mode": mode, "st_uid": uid, "st_gid": gid, "st_size": size, "st_nlink": 1,
            "st_birthtimespec": "2026-11-09T10:00:00.000000000Z", "st_mtimespec": "2026-11-09T10:00:01.000000000Z",
            "st_ctimespec": "2026-11-09T10:00:02.000000000Z"}


def f(path, **kw):
    return {"path": path, "path_truncated": False, "stat": stat(**kw)}


def line(name, payload, pid=621, exe="/usr/sbin/cfprefsd", ts="2026-11-09T22:38:35.471000000Z"):
    return json.dumps({"schema_version": 1, "time": ts, "global_seq_num": 7, "event_type": 0,
                       "process": {"audit_token": {"pid": pid, "euid": 506, "egid": 20}, "ppid": 1, "executable": {"path": exe},
                                   "signing_id": "com.apple.cfprefsd", "team_id": None, "is_platform_binary": True},
                       "event": {name: payload}})


def changes(name, payload, **kw):
    ev = parse_event(line(name, payload, **kw))
    return from_event(ev)


class MappingTests(unittest.TestCase):
    def test_create_existing_and_new_name(self):
        c, = changes("create", {"destination_type": 0, "destination": {"existing_file": f("/Users/me/a.txt", ino=42)}})
        self.assertEqual((c.category, c.event_type, c.path, c.inode), ("created", "Item Created", "/Users/me/a.txt", 42))
        #= synthetic: a not yet existing file = directory + file name (+ requested mode); not seen in real notify events
        c, = changes("create", {"destination_type": 1, "destination": {"new_path": {"dir": f("/Users/me"), "filename": "b.txt", "mode": 33188}}})
        self.assertEqual((c.category, c.path, c.inode), ("created", "/Users/me/b.txt", None))
        self.assertEqual(c.details["mode_requested"], 33188)

    def test_rename_gives_a_pair(self):
        out = changes("rename", {"source": f("/Users/me/tmp1", ino=9), "destination_type": 0,
                                 "destination": {"existing_file": f("/Users/me/real", ino=3)}})
        self.assertEqual([c.category for c in out], ["moved_from", "moved_to"])
        self.assertEqual((out[0].path, out[0].details["destination"]), ("/Users/me/tmp1", "/Users/me/real"))
        self.assertEqual((out[1].path, out[1].source_path), ("/Users/me/real", "/Users/me/tmp1"))
        self.assertEqual(out[1].inode, 9)                                  #= the moved file's inode, as a monitor shows it
        #= assumed shape: rename to a new name
        out = changes("rename", {"source": f("/Users/me/x", ino=5), "destination_type": 1,
                                 "destination": {"new_path": {"dir": f("/Users/me/dir"), "filename": "y"}}})
        self.assertEqual(out[1].path, "/Users/me/dir/y")

    def test_unlink_and_close(self):
        c, = changes("unlink", {"target": f("/Users/me/gone", ino=77), "parent_dir": f("/Users/me")})
        self.assertEqual((c.category, c.event_type, c.inode), ("deleted", "Item Removed", 77))
        c, = changes("close", {"modified": True, "target": f("/Users/me/w")})
        self.assertEqual((c.category, c.event_type), ("modified", "Content Modified"))
        self.assertEqual(changes("close", {"modified": False, "target": f("/Users/me/r")}), [])     #= a read-only close is no change

    def test_attribute_events_keep_their_names(self):
        names = {"setmode": "Mode Changed", "setowner": "Owner Changed", "setextattr": "Xattrs Changed",
                 "deleteextattr": "Xattrs Changed", "utimes": "Times Changed", "setflags": "Flags Changed",
                 "setacl": "ACL Changed", "setattrlist": "Attributes Changed"}
        for es_name, text in names.items():
            c, = changes(es_name, {"target": f("/Users/me/t")})
            self.assertEqual((c.category, c.event_type), ("attributes", text), es_name)

    def test_truncate_link_clone_exchange(self):
        c, = changes("truncate", {"target": f("/Users/me/t")})
        self.assertEqual((c.category, c.event_type), ("modified", "Item Truncated"))
        c, = changes("link", {"source": f("/Users/me/s", ino=4), "target_dir": f("/Users/me/d"), "target_filename": "l"})
        self.assertEqual((c.category, c.path, c.source_path, c.event_type), ("created", "/Users/me/d/l", "/Users/me/s", "Item Linked"))
        c, = changes("clone", {"source": f("/Users/me/s"), "target_dir": f("/Users/me/d"), "target_name": "c"})     
        self.assertEqual((c.path, c.event_type), ("/Users/me/d/c", "Item Cloned"))
        a, b = changes("exchangedata", {"file1": f("/Users/me/one", ino=1), "file2": f("/Users/me/two", ino=2)}) 
        self.assertEqual((a.path, a.inode, b.path, b.inode), ("/Users/me/one", 1, "/Users/me/two", 2))

    def test_other_events_are_not_file_changes(self):
        self.assertEqual(changes("exec", {"target": {"executable": {"path": "/bin/ls"}}, "args": []}), [])
        self.assertEqual(changes("fork", {"child": {"executable": {"path": "/bin/ls"}}}), [])
        self.assertEqual(changes("open", {"file": f("/Users/me/r"), "fflag": 1}), [])
        self.assertEqual(changes("exit", {"stat": 0}), [])

    def test_file_and_process_fields(self):
        c, = changes("close", {"modified": True, "target": f("/Users/me/w", ino=99, mode=33152, uid=501, gid=20, size=123)})
        d = c.to_dict()
        self.assertEqual(d["schema"], "cresc.filechange/1")
        self.assertEqual((d["file"]["inode"], d["file"]["mode"], d["file"]["uid"], d["file"]["size"]), (99, 33152, 501, 123))
        self.assertEqual(d["file"]["created"], "2026-11-09T10:00:00.000000000Z")
        self.assertEqual((d["process"]["pid"], d["process"]["name"], d["process"]["uid"], d["process"]["gid"]), (621, "cfprefsd", 506, 20))
        self.assertEqual(d["process"]["signing_id"], "com.apple.cfprefsd")
        json.dumps(d)                                                       #= JSON-safe, including 64-bit inodes

    def test_big_inodes_survive(self):
        c, = changes("close", {"modified": True, "target": f("/x", ino=1152921500312612045)})
        self.assertEqual(c.inode, 1152921500312612045)

    def test_data_volume_prefix_is_stripped_by_default(self):
        p = "/System/Volumes/Data/Users/me/a"
        self.assertEqual(canonical_path(p), "/Users/me/a")
        self.assertEqual(canonical_path(p, strip_data_volume=False), p)
        self.assertEqual(canonical_path("/System/Volumes/Data"), "/")
        self.assertEqual(canonical_path("/System/Volumes/DataX/a"), "/System/Volumes/DataX/a")      #= not a prefix match on a name
        ev = parse_event(line("unlink", {"target": f(p), "parent_dir": f("/System/Volumes/Data/Users/me")}))
        self.assertEqual(from_event(ev)[0].path, "/Users/me/a")
        self.assertEqual(from_event(ev, strip_data_volume=False)[0].path, p)

    def test_text_line_and_meta(self):
        c, = changes("unlink", {"target": f("/Users/me/gone", ino=77), "parent_dir": f("/Users/me")})
        text = format_change(c)
        for part in ("2026-11-09 22:38:35.471", "DEL", "621", "cfprefsd", "77", "/Users/me/gone"):
            self.assertIn(part, text)
        moved = changes("rename", {"source": f("/a"), "destination_type": 0, "destination": {"existing_file": f("/b")}})[1]
        self.assertIn("/b  <-  /a", format_change(moved))
        m = meta_change("Recording started", "2026-11-09T22:00:00.000000000Z")
        self.assertEqual((m.category, m.event_type), ("meta", "Recording started"))
        self.assertIn("META", format_change(m))

    def test_vocabulary_is_closed(self):
        self.assertEqual(set(CATEGORIES), {"created", "deleted", "modified", "attributes", "moved_from", "moved_to", "meta"})
        self.assertIn("close", FILE_EVENTS)
        self.assertNotIn("open", FILE_EVENTS)                               #= reads are not file changes


class RealShapeTests(unittest.TestCase):
    def test_real_capture_maps_cleanly(self):
        seen = {}
        for raw in open(REAL):
            ev = parse_event(raw)
            if ev is None:
                continue
            for c in from_event(ev):
                seen.setdefault(c.category, []).append(c)
        self.assertIn("created", seen)
        self.assertIn("moved_from", seen)
        self.assertEqual(len(seen["moved_from"]), len(seen["moved_to"]))
        for c in sum(seen.values(), []):
            self.assertTrue(c.path.startswith("/"), c.path)
            self.assertIsNotNone(c.inode, c.category)                      #= every real file event carries a stat
            self.assertIsNotNone(c.created)


class FilesViewServeTests(ServeCase):
    def test_watch_start_files_view(self):
        c = self.client()
        w = c.call("watch.start", source={"file": REAL}, view="files", no_mute=True)
        ended = c.event("watch.ended", timeout=20)
        got = [e["data"]["change"] for e in c.events if e["event"] == "watch.change" and e["data"]["watch_id"] == w["watch_id"]]
        cats = [x["category"] for x in got]
        self.assertEqual(cats[0], "meta")
        self.assertEqual(cats[-1], "meta")
        self.assertEqual((got[0]["event_type"], got[-1]["event_type"]), ("Recording started", "Recording stopped"))
        self.assertIn("created", cats)
        self.assertFalse([e for e in c.events if e["event"] == "watch.event"])      #= files view pushes changes only
        self.assertGreater(ended["stats"]["read"], 0)

    def test_bad_view_is_refused(self):
        c = self.client()
        self.assertEqual(c.call("watch.start", expect_ok=False, source={"file": REAL}, view="tree")["code"], "invalid_params")


if __name__ == "__main__":
    unittest.main()
