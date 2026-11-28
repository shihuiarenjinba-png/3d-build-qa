"""Regression tests for append-only Prism physical QA session resume."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import struct
import tempfile
import unittest
import zlib

from prism_physical_capture_checkpoint import (
    ARTIFACT_ID, EXE_SHA, OBSERVATIONS, PCK_SHA, REQUEST, SOURCE, STATE_FILES,
    CaptureHold, finalize_capture, inspect_status, record_session,
)

def png_bytes(seed: int) -> bytes:
    row = b"\x00" + bytes((seed & 255, (seed + 53) & 255, (seed + 107) & 255)) * 1024
    raw = row * 768
    def chunk(kind: bytes, payload: bytes) -> bytes:
        return (struct.pack(">I", len(payload)) + kind + payload +
                struct.pack(">I", zlib.crc32(kind + payload) & 0xffffffff))
    return (
        b"\x89PNG\r\n\x1a\n" +
        chunk(b"IHDR", struct.pack(">IIBBBBB", 1024, 768, 8, 2, 0, 0, 0)) +
        chunk(b"IDAT", zlib.compress(raw, 9)) +
        chunk(b"IEND", b"")
    )

class CaptureCheckpointTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def make_session(self, key="ja-100", *, seed_base=1, operator="operator-one"):
        language, dpi_text = key.split("-")
        dpi = int(dpi_text)
        attempt_id = f"{seed_base:032x}"
        attempt_rel = f"physical-session-attempts/{key}/{attempt_id}"
        attempt = self.root / attempt_rel
        attempt.mkdir(parents=True)
        screenshots = {}
        hashes = {}
        for offset, (state, filename) in enumerate(STATE_FILES.items()):
            data = png_bytes(seed_base + offset + 1)
            (attempt / filename).write_bytes(data)
            import hashlib
            screenshots[state] = filename
            hashes[state] = hashlib.sha256(data).hexdigest()
        session = {
            "schema_version": 1,
            "session_key": key,
            "language": language,
            "dpi_percent": dpi,
            "actual_dpi": int(96 * dpi / 100),
            "resolution": [1024, 768],
            "attempt_id": attempt_id,
            "attempt_dir": attempt_rel,
            "source_sha": SOURCE,
            "request_id": REQUEST,
            "factory_artifact_id": ARTIFACT_ID,
            "factory_artifact_expires_at": None,
            "exe_sha256": EXE_SHA,
            "pck_sha256": PCK_SHA,
            "exe_path": r"C:\Prism\candidate.exe",
            "pck_path": r"C:\Prism\candidate.pck",
            "physical_device": True,
            "operator": operator,
            "windows_build": "Windows 11 build 26100",
            "code_integrity_status": "ALLOWED_BY_EXISTING_POLICY",
            "capture_started_at": "2026-11-28T00:00:00+00:00",
            "play_started_at": "2026-11-28T00:00:05+00:00",
            "play_finished_at": "2026-11-28T00:02:05+00:00",
            "capture_finished_at": "2026-11-28T00:02:10+00:00",
            "elapsed_play_seconds": 120.0,
            "first_goal_seconds": 20.0,
            "uncoached_first_launch": True,
            "start_pressed": True,
            "screenshots": screenshots,
            "screenshot_sha256": hashes,
        }
        session.update({field: True for field in OBSERVATIONS})
        candidate = attempt / "session.json"
        candidate.write_text(json.dumps(session, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        return candidate, session

    def record(self, key="ja-100", **kwargs):
        candidate, session = self.make_session(key, **kwargs)
        record_session(self.root, candidate)
        return candidate, session

    def test_valid_completed_session_is_recovered_and_resumed(self):
        self.make_session("ja-100")
        status = inspect_status(self.root)
        self.assertIn("ja-100", status["completed_sessions"])
        self.assertIn("ja-100", status["recovered_sessions"])
        self.assertTrue((self.root / "physical-checkpoints/ja-100.json").is_file())
        self.assertIn("ja-100", inspect_status(self.root)["completed_sessions"])

    def test_partial_attempt_remains_hold_and_is_not_promoted(self):
        attempt = self.root / "physical-session-attempts/ja-100" / ("a" * 32)
        attempt.mkdir(parents=True)
        (attempt / "guide.png").write_bytes(png_bytes(1))
        status = inspect_status(self.root)
        self.assertNotIn("ja-100", status["completed_sessions"])
        self.assertEqual(status["incomplete_attempts"][0]["session_key"], "ja-100")
        with self.assertRaisesRegex(CaptureHold, "missing completed sessions"):
            finalize_capture(self.root)

    def test_tampered_checkpoint_is_hold(self):
        self.record()
        path = self.root / "physical-checkpoints/ja-100.json"
        value = json.loads(path.read_text(encoding="utf-8"))
        value["session"]["screenshot_sha256"]["guide"] = "0" * 64
        path.write_text(json.dumps(value), encoding="utf-8")
        with self.assertRaises(CaptureHold):
            inspect_status(self.root)

    def test_changed_source_exe_or_pck_tuple_is_rejected(self):
        for field, value in (
            ("source_sha", "1" * 40),
            ("exe_sha256", "2" * 64),
            ("pck_sha256", "3" * 64),
            ("request_id", "wrong-request"),
            ("factory_artifact_id", ARTIFACT_ID + 1),
        ):
            with self.subTest(field=field):
                candidate, session = self.make_session("ja-100", seed_base=10)
                session[field] = value
                candidate.write_text(json.dumps(session), encoding="utf-8")
                with self.assertRaises(CaptureHold):
                    record_session(self.root, candidate)
                import shutil
                shutil.rmtree(self.root / "physical-session-attempts")
                if (self.root / "physical-checkpoints").exists():
                    shutil.rmtree(self.root / "physical-checkpoints")

    def test_duplicate_screenshot_hashes_are_rejected(self):
        candidate, session = self.make_session()
        attempt = candidate.parent
        (attempt / "active.png").write_bytes((attempt / "guide.png").read_bytes())
        import hashlib
        session["screenshot_sha256"]["active"] = hashlib.sha256((attempt / "active.png").read_bytes()).hexdigest()
        candidate.write_text(json.dumps(session), encoding="utf-8")
        with self.assertRaisesRegex(CaptureHold, "duplicate screenshot bytes"):
            record_session(self.root, candidate)

    def test_missing_screenshot_is_rejected(self):
        candidate, _ = self.make_session()
        (candidate.parent / "trap.png").unlink()
        with self.assertRaises(CaptureHold):
            record_session(self.root, candidate)

    def test_sub_90_second_or_falsified_stopwatch_is_rejected(self):
        candidate, session = self.make_session()
        session["play_finished_at"] = "2026-11-28T00:01:34+00:00"
        session["elapsed_play_seconds"] = 89.0
        candidate.write_text(json.dumps(session), encoding="utf-8")
        with self.assertRaisesRegex(CaptureHold, "90-1800"):
            record_session(self.root, candidate)

    def test_operator_and_physical_device_attestation_are_required(self):
        for field, value in (("operator", "x"), ("physical_device", False),
                             ("code_integrity_status", "BYPASSED")):
            with self.subTest(field=field):
                candidate, session = self.make_session("ja-100", seed_base=11)
                session[field] = value
                candidate.write_text(json.dumps(session), encoding="utf-8")
                with self.assertRaises(CaptureHold):
                    record_session(self.root, candidate)
                import shutil
                shutil.rmtree(self.root / "physical-session-attempts")
                if (self.root / "physical-checkpoints").exists():
                    shutil.rmtree(self.root / "physical-checkpoints")

    def test_checkpoint_is_never_overwritten(self):
        candidate, _ = self.record()
        checkpoint = self.root / "physical-checkpoints/ja-100.json"
        original = checkpoint.read_bytes()
        with self.assertRaisesRegex(CaptureHold, "refuse to overwrite"):
            record_session(self.root, candidate)
        self.assertEqual(checkpoint.read_bytes(), original)

    def test_screenshot_changed_after_checkpoint_is_rejected(self):
        candidate, _ = self.record()
        (candidate.parent / "guide.png").write_bytes(png_bytes(200))
        with self.assertRaises(CaptureHold):
            inspect_status(self.root)

    def test_all_six_sessions_finalize_to_existing_gate_schema(self):
        for index, key in enumerate(
            f"{lang}-{dpi}" for lang in ("ja", "en") for dpi in (100, 125, 150)
        ):
            self.record(key, seed_base=100 + index * 10)
        result = finalize_capture(self.root)
        self.assertEqual(result["sessions"], 6)
        self.assertEqual(result["screenshots"], 36)
        capture = json.loads((self.root / "physical-capture.json").read_text(encoding="utf-8"))
        self.assertEqual(len(capture["sessions"]), 6)
        self.assertFalse(capture["sale_ready"])
        self.assertFalse(capture["store_submission_allowed"])
        frame_files = list((self.root / "physical-frames").glob("*.png"))
        self.assertEqual(len(frame_files), 36)
        self.assertEqual(finalize_capture(self.root), result)

    def test_global_duplicate_screenshot_hashes_are_rejected(self):
        self.record("ja-100", seed_base=500)
        self.record("ja-125", seed_base=500)
        for index, key in enumerate(("ja-150", "en-100", "en-125", "en-150")):
            self.record(key, seed_base=600 + index * 10)
        with self.assertRaisesRegex(CaptureHold, "duplicate screenshot bytes across sessions"):
            finalize_capture(self.root)

    def test_existing_frame_bytes_are_never_overwritten(self):
        for index, key in enumerate(
            f"{lang}-{dpi}" for lang in ("ja", "en") for dpi in (100, 125, 150)
        ):
            self.record(key, seed_base=700 + index * 10)
        frame_dir = self.root / "physical-frames"
        frame_dir.mkdir()
        target = frame_dir / "ja-100-guide.png"
        target.write_bytes(b"preserve-me")
        with self.assertRaises(CaptureHold):
            finalize_capture(self.root)
        self.assertEqual(target.read_bytes(), b"preserve-me")

    def test_operator_must_remain_consistent_across_all_six_sessions(self):
        for index, key in enumerate(
            f"{lang}-{dpi}" for lang in ("ja", "en") for dpi in (100, 125, 150)
        ):
            self.record(key, seed_base=800 + index * 10,
                        operator=("different-operator" if key == "en-150" else "operator-one"))
        with self.assertRaisesRegex(CaptureHold, "attestation changed"):
            finalize_capture(self.root)

if __name__ == "__main__":
    unittest.main()
