"""Negative fixtures for PR22 physical evidence. Fixtures are NEVER human proof."""
import copy
from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import prism_pr22_physical_evidence_gate as gate


class PhysicalPR22Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temp.name)
        cls.capture = gate.blank_template()
        cls.capture.update({
            "physical_device": True, "windows_build": "Windows 11 build 26200",
            "operator": "test-operator", "code_integrity_status": "ALLOWED_BY_EXISTING_POLICY",
        })
        start = datetime(2026, 11, 3, 9, 0, tzinfo=timezone(timedelta(hours=9)))
        for i, s in enumerate(cls.capture["sessions"]):
            s.update({
                "tester_id": f"test-person-{i}",
                "capture_started_at": start.isoformat(),
                "capture_finished_at": (start + timedelta(seconds=200)).isoformat(),
                "first_goal_seconds": 20, "elapsed_play_seconds": 90,
            })
            s.update({field: True for field in gate.OBSERVATIONS})
            for state, filename in s["screenshots"].items():
                (cls.root / filename).write_bytes(b"fixture-not-a-real-png-" + filename.encode() * 200)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def check(self, capture, host=True):
        # Fake PNG checker exists only inside tests; real gate checks PNG CRC.
        with patch.object(gate, "check_png", side_effect=lambda p: gate.sha(p)):
            return gate.evaluate(capture, self.root, windows_host=host,
                                 now=datetime(2026, 11, 3, tzinfo=timezone.utc))

    def test_blank_template_is_hold_not_evidence(self):
        template = gate.blank_template()
        self.assertEqual(template["physical_qa"], gate.HOLD)
        self.assertEqual(template["human_fun"], gate.HOLD)
        self.assertFalse(template["sale_ready"])
        with self.assertRaises(gate.EvidenceHold):
            self.check(template)

    def test_complete_fixture_only_reaches_human_review(self):
        result = self.check(copy.deepcopy(self.capture))
        self.assertEqual(result["status"], "PHYSICAL_EVIDENCE_REVIEW_REQUIRED")
        self.assertEqual(result["distinct_1024x768_frames"], 42)
        self.assertFalse(result["physical_gui_automatically_proven"])
        self.assertFalse(result["human_enjoyment_automatically_proven"])
        self.assertFalse(result["sale_ready"])

    def test_cloud_and_fake_positive_rejected(self):
        with self.assertRaisesRegex(gate.EvidenceHold, "no actual Windows"):
            self.check(copy.deepcopy(self.capture), host=False)
        for field, value in (("physical_qa", "PASS"), ("human_fun", "PASS"),
                             ("sale_ready", True), ("store_submission_allowed", True)):
            c = copy.deepcopy(self.capture)
            c[field] = value
            with self.subTest(field=field), self.assertRaises(gate.EvidenceHold):
                self.check(c)

    def test_old_source_and_old_pck_rejected(self):
        for field, bad in (
            ("source_sha", "066d9f51d58cfecb994665d5c31adb1156c38942"),
            ("request_id", "3d-prism-route-3d-066d9f51d58c"),
            ("pck_sha256", "a27c198ff4bdaa961780b4e42d5fb429c328c5bad0b5cb816e399c06e3fd8cb9"),
            ("factory_artifact_id", 13155398069),
            ("software_qa_zip_sha256", "0" * 64),
        ):
            c = copy.deepcopy(self.capture)
            c[field] = bad
            with self.subTest(field=field), self.assertRaisesRegex(gate.EvidenceHold, "PROVENANCE_HOLD"):
                self.check(c)

    def test_missing_dpi_or_duplicate_tester_rejected(self):
        for field, bad in (("dpi_percent", 125), ("language", "en"),
                           ("tester_id", "test-person-1"), ("resolution", [1280, 720])):
            c = copy.deepcopy(self.capture)
            c["sessions"][0][field] = bad
            with self.subTest(field=field), self.assertRaises(gate.EvidenceHold):
                self.check(c)
        c = copy.deepcopy(self.capture)
        c["sessions"].pop()
        with self.assertRaises(gate.EvidenceHold):
            self.check(c)

    def test_human_30_90_failure_recovery_and_taskbar(self):
        for field, bad in (
            ("first_goal_seconds", 31), ("elapsed_play_seconds", 89),
            ("goal_understood", False), ("tower_order_1_2_3_understood", False),
            ("sentinel_scan_timing_understood", False),
            ("timeout_reason_understood", False), ("trap_reason_understood", False),
            ("sentinel_reason_understood", False),
            ("retry_completed", False), ("failure_recovery_understood", False),
            ("taskbar_visible", False), ("game_window_unclipped", False),
            ("uncoached_first_launch", False),
        ):
            c = copy.deepcopy(self.capture)
            c["sessions"][0][field] = bad
            with self.subTest(field=field), self.assertRaises(gate.EvidenceHold):
                self.check(c)

    def test_wrong_image_missing_image_or_duplicate_pixels(self):
        c = copy.deepcopy(self.capture)
        c["sessions"][0]["screenshots"]["timeout"] = "ja-100-trap.png"
        with self.assertRaises(gate.EvidenceHold):
            self.check(c)
        c = copy.deepcopy(self.capture)
        c["sessions"][0]["screenshots"]["retry"] = "ja-100-retry-missing.png"
        with self.assertRaises(gate.EvidenceHold):
            self.check(c)
        with patch.object(gate, "check_png", return_value="same-hash"):
            with self.assertRaisesRegex(gate.EvidenceHold, "duplicate frame"):
                gate.evaluate(copy.deepcopy(self.capture), self.root, windows_host=True,
                              now=datetime(2026, 11, 3, tzinfo=timezone.utc))

    def test_code_integrity_and_expiry(self):
        for status in ("BLOCKED", "BYPASSED", "NOT_CHECKED"):
            c = copy.deepcopy(self.capture)
            c["code_integrity_status"] = status
            with self.assertRaisesRegex(gate.EvidenceHold, "CODE_INTEGRITY_HOLD"):
                self.check(c)
        with self.assertRaisesRegex(gate.EvidenceHold, "expired"):
            gate.evaluate(copy.deepcopy(self.capture), self.root, windows_host=True,
                          now=datetime(2026, 11, 10, tzinfo=timezone.utc))


if __name__ == "__main__":
    unittest.main()
