"""Fail-closed physical acceptance: fixture can never prove human GUI or sale."""
import copy
from datetime import datetime, timedelta, timezone
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch
import zlib

from prism_first30s_physical_windows_gate import (
    ARTIFACT_ID, EXE_SHA, PCK_SHA, REQUEST, SOURCE,
    PhysicalGateHold, evaluate, SCREENSHOTS, OBSERVATIONS,
)


def chunk(kind, payload):
    return (struct.pack(">I", len(payload)) + kind + payload +
            struct.pack(">I", zlib.crc32(kind + payload) & 0xffffffff))


def png(n):
    header = struct.pack(">IIBBBBB", 1024, 768, 8, 2, 0, 0, 0)
    pixels = (b"\x00" + b"\x00" * (1024 * 3)) * 768
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", header) +
            chunk(b"tEXt", b"test-only-not-physical:" + str(n).encode()) +
            chunk(b"IDAT", zlib.compress(pixels)) + chunk(b"IEND", b""))


class PhysicalGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temp.name)
        (cls.root / "candidate.exe").write_bytes(b"fixture exe")
        (cls.root / "candidate.pck").write_bytes(b"fixture pck")
        start = datetime(2026, 11, 2, 19, 0, tzinfo=timezone(timedelta(hours=9)))
        sessions = []
        count = 0
        for lang in ("ja", "en"):
            for dpi in (125, 150):
                frames = {}
                for state in SCREENSHOTS:
                    name = f"{lang}-{dpi}-{state}.png"
                    (cls.root / name).write_bytes(png(count))
                    frames[state] = name
                    count += 1
                session = {
                    "language": lang, "dpi_percent": dpi,
                    "resolution": [1024, 768],
                    "capture_started_at": start.isoformat(),
                    "capture_finished_at": (start + timedelta(seconds=130)).isoformat(),
                    "elapsed_play_seconds": 90, "first_goal_seconds": 20,
                    "start_pressed": True, "uncoached_first_launch": True,
                    "screenshots": frames,
                }
                session.update({field: True for field in OBSERVATIONS})
                sessions.append(session)
        cls.capture = {
            "schema_version": 1,
            "capture_kind": "PHYSICAL_WINDOWS_OPERATOR_ATTESTATION",
            "source_sha": SOURCE, "request_id": REQUEST,
            "factory_artifact_id": ARTIFACT_ID,
            "exe_sha256": EXE_SHA, "pck_sha256": PCK_SHA,
            "exe_path": str(cls.root / "candidate.exe"),
            "pck_path": str(cls.root / "candidate.pck"),
            "physical_device": True, "operator": "test-only",
            "windows_build": "Windows 11 26200",
            "sessions": sessions,
        }

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def check(self, data, host=True):
        with patch("prism_first30s_physical_windows_gate.digest",
                   side_effect=lambda p: EXE_SHA if p.suffix == ".exe" else PCK_SHA):
            return evaluate(data, self.root, windows_host=host)

    def test_fixture_only_can_reach_review_not_sale(self):
        result = self.check(copy.deepcopy(self.capture))
        self.assertEqual(result["status"], "PHYSICAL_QA_EVIDENCE_REVIEW_REQUIRED")
        self.assertFalse(result["physical_gui_automatically_proven"])
        self.assertFalse(result["sale_ready"])
        self.assertFalse(result["store_submission_allowed"])
        self.assertEqual(result["physical_screenshot_sha256_count"], 24)

    def test_non_windows_always_hold(self):
        with self.assertRaisesRegex(PhysicalGateHold, "DEFERRED_LOCAL_GATE"):
            self.check(copy.deepcopy(self.capture), host=False)

    def test_wrong_lineage_or_missing_physical_attestation(self):
        for key, bad in (
            ("source_sha", "3c5a1e6837118a73609a0b9c9b7b54dfa4c14f0d"),
            ("request_id", "3d-prism-route-3d-3c5a1e683711"),
            ("pck_sha256", "7a7d5243452786dcb7eb265d1dbdd6309e596f9d370d73bf0d8f8023b5096060"),
            ("physical_device", False), ("operator", ""),
            ("factory_artifact_id", 13130487252),
        ):
            with self.subTest(key=key):
                item = copy.deepcopy(self.capture)
                item[key] = bad
                with self.assertRaises(PhysicalGateHold):
                    self.check(item)

    def test_old_pr18_lineage_cannot_pass_as_new_pr19(self):
        # EXE template may have the same SHA across revisions. The compiled
        # PCK, source, request and Artifact must independently match PR19.
        stale = copy.deepcopy(self.capture)
        stale.update({
            "source_sha": "3c5a1e6837118a73609a0b9c9b7b54dfa4c14f0d",
            "request_id": "3d-prism-route-3d-3c5a1e683711",
            "factory_artifact_id": 13130487252,
            "pck_sha256": "7a7d5243452786dcb7eb265d1dbdd6309e596f9d370d73bf0d8f8023b5096060",
        })
        with self.assertRaisesRegex(PhysicalGateHold, "PROVENANCE_HOLD"):
            self.check(stale)
        # A forged receipt that claims new lineage but points to old PCK
        # bytes must still fail the real on-disk digest check.
        with patch("prism_first30s_physical_windows_gate.digest",
                   side_effect=lambda p: EXE_SHA if p.suffix == ".exe" else
                   "7a7d5243452786dcb7eb265d1dbdd6309e596f9d370d73bf0d8f8023b5096060"):
            with self.assertRaisesRegex(PhysicalGateHold, "exact pck_path"):
                evaluate(copy.deepcopy(self.capture), self.root, windows_host=True)

    def test_first30s_and_human_90s_fail_closed(self):
        for key, bad in (
            ("goal_understood_in_30s", False),
            ("first_goal_seconds", 31),
            ("elapsed_play_seconds", 0),
            ("clock_frozen_until_start", False),
            ("failure_reason_understood", False),
            ("retry_completed", False),
            ("uncoached_first_launch", False),
        ):
            with self.subTest(key=key):
                item = copy.deepcopy(self.capture)
                item["sessions"][0][key] = bad
                with self.assertRaises(PhysicalGateHold):
                    self.check(item)

    def test_dpi_and_frame_reuse_fail_closed(self):
        item = copy.deepcopy(self.capture)
        item["sessions"][0]["dpi_percent"] = 100
        with self.assertRaises(PhysicalGateHold):
            self.check(item)
        item = copy.deepcopy(self.capture)
        item["sessions"][0]["screenshots"]["retry"] = item["sessions"][0]["screenshots"]["guide"]
        with self.assertRaisesRegex(PhysicalGateHold, "duplicate frames"):
            self.check(item)

    def test_missing_file_and_fake_exe_digest_fail_closed(self):
        item = copy.deepcopy(self.capture)
        item["sessions"][0]["screenshots"]["scan_warning"] = "missing.png"
        with self.assertRaises(PhysicalGateHold):
            self.check(item)
        with self.assertRaisesRegex(PhysicalGateHold, "exact exe_path"):
            evaluate(copy.deepcopy(self.capture), self.root, windows_host=True)


if __name__ == "__main__":
    unittest.main()
