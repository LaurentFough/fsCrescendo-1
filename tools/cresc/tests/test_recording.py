#= test_recording.py  version 0.1.0 (2026-11-09)
#= .crescrec recordings: format, verification (tamper evidence), export, the player (speed, pause, seek, gaps), and a live
#= record -> reopen -> replay round trip through a real `cresc serve` process with pre-roll.
import csv
import json
import os
import shutil
import tempfile
import threading
import time
import unittest

from cresc import recording as rec
from tests.test_serve import ServeCase

HERE = os.path.dirname(os.path.abspath(__file__))
REAL = os.path.join(HERE, "fixtures", "eslogger-file-events.jsonl")


def change(i, category="created", path=None):
    return {"schema": "cresc.filechange/1", "ts": "2026-11-09T10:00:%02d.000000000Z" % (i % 60), "category": category, "event_type": "Item Created",
            "path": path or "/Users/me/f%d" % i, "source_path": "", "count": 1, "file": {"inode": 100 + i}, "process": {"pid": 7, "name": "touch"},
            "details": {}}


class TmpCase(unittest.TestCase):
    def setUp(self):
        self.dir = os.path.realpath(tempfile.mkdtemp(prefix="cresc-rec-"))
        self.addCleanup(shutil.rmtree, self.dir, True)

    def make(self, times, name="a.crescrec", **kw):
        path = os.path.join(self.dir, name)
        r = rec.Recorder(path, rec.make_header(**kw))
        for i, t in enumerate(times):
            r.write("change", change(i), t=t)
        info = r.close()
        return path, info


class FormatTests(TmpCase):
    def test_roundtrip_and_header(self):
        path, info = self.make([0, 0.5, 1.0], notes="demo", cleanup="prune")
        self.assertEqual(info["records"], 3)
        self.assertFalse(os.path.exists(path + ".part"))
        h = rec.read_header(path)
        self.assertEqual((h["schema"], h["kind"], h["notes"], h["cleanup"]), ("cresc.recording/1", "live-capture", "demo", "prune"))
        self.assertIn("hostname", h["host"])
        self.assertNotIn("hostname", rec.make_header(include_host=False)["host"])
        got = list(rec.iter_records(path))
        self.assertEqual([r["t"] for r in got], [0, 0.5, 1.0])
        self.assertEqual(got[0]["data"]["path"], "/Users/me/f0")
        v = rec.verify_recording(path)
        self.assertTrue(v["ok"] and v["complete"], v["problems"])
        self.assertEqual(len(info["file_sha256"]), 64)

    def test_path_rules_and_overwrite(self):
        header = rec.make_header()
        for bad in ("relative.crescrec", os.path.join(self.dir, "x.txt")):
            with self.assertRaises(rec.RecordingError):
                rec.Recorder(bad, header)
        path, _ = self.make([0])
        with self.assertRaises(rec.RecordingError):
            rec.Recorder(path, header)
        rec.Recorder(path, header, force=True).close()
        with self.assertRaises(rec.RecordingError):
            rec.make_header(kind="bogus")

    def test_unknown_record_type_is_refused(self):
        r = rec.Recorder(os.path.join(self.dir, "u.crescrec"), rec.make_header())
        with self.assertRaises(rec.RecordingError):
            r.write("bogus", {})
        r.abort()
        self.assertEqual(os.listdir(self.dir), [])                              #= no .part left behind

    def test_tampering_and_damage_are_detected(self):
        path, _ = self.make([0, 1, 2])
        data = open(path, "rb").read()
        forged = os.path.join(self.dir, "forged.crescrec")
        open(forged, "wb").write(data.replace(b"/Users/me/f1", b"/Users/me/ZZ"))
        v = rec.verify_recording(forged)
        self.assertFalse(v["ok"])
        self.assertIn("hash differs", " ".join(v["problems"]))
        dropped = os.path.join(self.dir, "dropped.crescrec")
        lines = data.split(b"\n")
        open(dropped, "wb").write(b"\n".join(lines[:2] + lines[3:]))              #= one record removed
        self.assertIn("record count differs", " ".join(rec.verify_recording(dropped)["problems"]))
        nofooter = os.path.join(self.dir, "nofooter.crescrec")
        open(nofooter, "wb").write(b"\n".join(lines[:3]) + b"\n")
        v = rec.verify_recording(nofooter)
        self.assertFalse(v["complete"])                                           #= readable, but reported incomplete
        self.assertEqual(len(list(rec.iter_records(nofooter))), 2)
        junk = os.path.join(self.dir, "junk.crescrec")
        open(junk, "w").write("not json\n")
        self.assertFalse(rec.verify_recording(junk)["ok"])
        with self.assertRaises(rec.RecordingError):
            rec.read_header(junk)
        self.assertFalse(rec.verify_recording(os.path.join(self.dir, "missing.crescrec"))["ok"])

    def test_time_going_backwards_is_a_problem(self):
        path = os.path.join(self.dir, "b.crescrec")
        header = json.dumps(rec.make_header())
        rows = [json.dumps({"type": "change", "t": 5, "data": {}}), json.dumps({"type": "change", "t": 1, "data": {}})]
        open(path, "w").write("\n".join([header] + rows) + "\n")
        self.assertIn("time goes backwards", " ".join(rec.verify_recording(path)["problems"]))

    def test_summary(self):
        path = os.path.join(self.dir, "s.crescrec")
        r = rec.Recorder(path, rec.make_header())
        r.write("change", change(1, "created"), t=0)
        r.write("change", change(2, "deleted"), t=1)
        r.write("note", {"text": "hello"}, t=2)
        r.close()
        s = rec.summarise(path)
        self.assertEqual((s["records"], s["duration_s"]), (3, 2.0))
        self.assertEqual(s["by_type"], {"change": 2, "note": 1})
        self.assertEqual(s["by_category"], {"created": 1, "deleted": 1})

    def test_export_formats(self):
        path, _ = self.make([0, 1])
        out = lambda n: os.path.join(self.dir, n)
        self.assertEqual(rec.export_recording(path, out("a.jsonl"), "jsonl")["rows"], 2)
        self.assertEqual(rec.export_recording(path, out("a.txt"), "text")["rows"], 2)
        self.assertIn("CRE", open(out("a.txt")).read())
        self.assertEqual(rec.export_recording(path, out("a.csv"), "csv")["rows"], 2)
        rows = list(csv.reader(open(out("a.csv"))))
        self.assertEqual((rows[0][0], rows[1][7]), ("t", "/Users/me/f0"))
        rec.export_recording(path, out("a.json"), "json")
        self.assertEqual(len(json.load(open(out("a.json")))["records"]), 2)
        with self.assertRaises(rec.RecordingError):
            rec.export_recording(path, out("a.txt"), "text")                      #= exists
        with self.assertRaises(rec.RecordingError):
            rec.export_recording(path, out("b.x"), "xml")


class Collector:
    def __init__(self):
        self.batches = []
        self.ended = threading.Event()
        self.lock = threading.Lock()

    def __call__(self, batch, position, reset, ended):
        with self.lock:
            self.batches.append((list(batch), position, reset, ended))
        if ended:
            self.ended.set()

    def ts(self):
        with self.lock:
            return [r["t"] for b, _p, _r, _e in self.batches for r in b]


class PlayerTests(TmpCase):
    def test_plays_everything_in_order_and_signals_the_end(self):
        path, _ = self.make([0, 0.01, 0.02, 0.02, 0.05])
        c = Collector()
        p = rec.Player(path, c, speed=100)
        self.assertEqual((p.duration, len(p.records)), (0.05, 5))
        p.start()
        self.assertTrue(c.ended.wait(5))
        self.assertEqual(c.ts(), [0, 0.01, 0.02, 0.02, 0.05])
        self.assertTrue(p.finished)

    def test_long_gaps_are_compressed(self):
        path, _ = self.make([0, 100])
        c = Collector()
        t0 = time.time()
        rec.Player(path, c, speed=10, max_gap=1.0).start()
        self.assertTrue(c.ended.wait(5))
        self.assertLess(time.time() - t0, 3)                                      #= 100 s of silence became 0.1 s

    def test_speed_changes_the_pace(self):
        path, _ = self.make([0, 1.0])
        c = Collector()
        t0 = time.time()
        rec.Player(path, c, speed=20).start()
        self.assertTrue(c.ended.wait(5))
        self.assertLess(time.time() - t0, 1.0)                                    #= 1 s of recording at 20x

    def test_pause_resume_and_stop(self):
        path, _ = self.make([i * 0.2 for i in range(10)])
        c = Collector()
        p = rec.Player(path, c, speed=1.0)
        p.start()
        time.sleep(0.5)
        p.pause()
        time.sleep(0.3)
        n = len(c.ts())
        time.sleep(0.8)
        self.assertEqual(len(c.ts()), n)                                          #= nothing arrives while paused
        self.assertFalse(c.ended.is_set())
        p.resume()
        time.sleep(0.6)
        self.assertGreater(len(c.ts()), n)
        p.stop()
        before = len(c.ts())
        time.sleep(0.7)
        self.assertEqual(len(c.ts()), before)
        self.assertFalse(c.ended.is_set())                                        #= stopped, not finished

    def test_seek_rebuilds_state_then_continues(self):
        path, _ = self.make([0, 1, 2, 3, 4])
        c = Collector()
        p = rec.Player(path, c, speed=1000)
        p.pause()
        p.start()
        time.sleep(0.2)
        p.seek(2.5)
        time.sleep(0.3)
        with c.lock:
            resets = [(len(b), pos) for b, pos, reset, _e in c.batches if reset]
        self.assertEqual(resets, [(3, 2.0)])                                      #= records at t=0,1,2 pushed in one reset batch
        p.resume()
        self.assertTrue(c.ended.wait(5))
        self.assertEqual(c.ts()[-2:], [3, 4])
        p.seek(0)                                                                  #= seek after the end restarts from the beginning
        time.sleep(0.3)

    def test_start_at(self):
        path, _ = self.make([0, 1, 2, 3])
        c = Collector()
        p = rec.Player(path, c, speed=1000, start_t=1.5)
        p.start()
        self.assertTrue(c.ended.wait(5))
        with c.lock:
            first = c.batches[0]
        self.assertTrue(first[2])                                                  #= first batch is a reset holding t=0 and t=1
        self.assertEqual([r["t"] for r in first[0]], [0, 1])
        self.assertEqual(c.ts()[-2:], [2, 3])

    def test_empty_recording(self):
        path, _ = self.make([])
        c = Collector()
        rec.Player(path, c).start()
        self.assertTrue(c.ended.wait(3))


class ServeRecordingTests(ServeCase):
    def feed(self, fifo, lines):
        with open(fifo, "w") as fh:
            for line in lines:
                fh.write(line + "\n")
                fh.flush()

    def count_changes(self, c, watch_id):
        return len([e for e in c.events if e["event"] == "watch.change" and e["data"]["watch_id"] == watch_id])

    def test_live_record_reopen_and_replay(self):
        c = self.client()
        fifo = os.path.join(self.root, "es.fifo")
        os.mkfifo(fifo)
        out = os.path.join(self.root, "live.crescrec")
        lines = open(REAL).read().splitlines()
        w = c.call("watch.start", source={"file": fifo}, view="files", no_mute=True)
        self.feed(fifo, lines[:30])                                               #= happens BEFORE recording starts: pre-roll material
        c.event("watch.change", lambda d: d["change"]["category"] != "meta" and d["watch_id"] == w["watch_id"])
        time.sleep(0.5)
        started = c.call("recording.start", watch_id=w["watch_id"], path=out, pre_roll=60, notes="from a test")
        self.assertGreater(started["pre_roll_rows"], 0)
        self.feed(fifo, lines[30:60])
        time.sleep(0.8)
        stopped = c.call("recording.stop", recording_id=started["recording_id"])
        self.assertGreater(stopped["records"], started["pre_roll_rows"])
        self.assertEqual(len(stopped["file_sha256"]), 64)
        c.call("watch.stop", watch_id=w["watch_id"])
        c.event("watch.ended", timeout=20)
        self.assertEqual(c.call("recording.verify", path=out)["ok"], True)
        info = c.call("recording.open", path=out)
        self.assertEqual(info["header"]["notes"], "from a test")
        self.assertEqual(info["records"], stopped["records"])
        self.assertTrue(info["ok"] and info["complete"])
        #= replay it
        play = c.call("recording.play", path=out, speed=1000)
        self.assertEqual(play["records"], stopped["records"])
        got = 0
        while True:
            data = c.event("recording.records", lambda d: d["play_id"] == play["play_id"])
            got += len(data["records"])
            if data["ended"]:
                break
        self.assertEqual(got, stopped["records"])
        #= export
        exp = os.path.join(self.root, "live.csv")
        self.assertEqual(c.call("recording.export", path=out, out=exp, format="csv")["rows"], stopped["records"])

    def test_recording_is_finished_when_the_watch_ends(self):
        c = self.client()
        fifo = os.path.join(self.root, "es.fifo")
        os.mkfifo(fifo)
        out = os.path.join(self.root, "auto.crescrec")
        w = c.call("watch.start", source={"file": fifo}, view="files", no_mute=True)
        started = c.call("recording.start", watch_id=w["watch_id"], path=out)
        self.feed(fifo, open(REAL).read().splitlines()[:10])
        time.sleep(0.5)
        c.call("watch.stop", watch_id=w["watch_id"])
        done = c.event("recording.finished", timeout=20)
        self.assertEqual(done["recording_id"], started["recording_id"])
        self.assertTrue(rec.verify_recording(out)["ok"])
        self.assertEqual(c.call("recording.stop", expect_ok=False, recording_id=started["recording_id"])["code"], "not_found")

    def test_player_controls_and_errors(self):
        c = self.client()
        path = os.path.join(self.root, "p.crescrec")
        r = rec.Recorder(path, rec.make_header())
        for i in range(5):
            r.write("change", change(i), t=i * 0.3)
        r.close()
        play = c.call("recording.play", path=path, speed=1)
        c.call("recording.control", play_id=play["play_id"], action="pause")
        c.call("recording.control", play_id=play["play_id"], action="speed", value=1000)
        c.call("recording.control", play_id=play["play_id"], action="seek", value=0.5)
        c.call("recording.control", play_id=play["play_id"], action="resume")
        while not c.event("recording.records", lambda d: d["play_id"] == play["play_id"])["ended"]:
            pass
        c.call("recording.control", play_id=play["play_id"], action="stop")
        self.assertEqual(c.call("recording.control", expect_ok=False, play_id=play["play_id"], action="dance")["code"], "invalid_params")
        self.assertEqual(c.call("recording.control", expect_ok=False, play_id="nope", action="pause")["code"], "not_found")
        for bad in (dict(path="relative.crescrec"), dict(path=os.path.join(self.root, "missing.crescrec"))):
            self.assertIn(c.call("recording.open", expect_ok=False, **bad)["code"], ("invalid_params", "session_error"))
        self.assertEqual(c.call("recording.start", expect_ok=False, watch_id="nope", path=path)["code"], "not_found")


if __name__ == "__main__":
    unittest.main()
