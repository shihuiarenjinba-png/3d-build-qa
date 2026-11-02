"""Synthetic negative tests only; no fake physical Windows or product evidence."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from prism_pr21_physical_handoff import (
    ARTIFACT_ID, FILES, FRAMES, MEMBERS, REQUEST, SOURCE, ZIP_SHA,
    HandoffHold, capture_template, check_handoff, verify_template,
)


class HandoffTests(unittest.TestCase):
    def test_template_has_four_sessions_24_distinct_images_and_no_false_pass(self):
        t = capture_template()
        verify_template(t)
        self.assertFalse(t["physical_device"])
        self.assertIsNone(t["operator"])
        self.assertEqual(t["source_sha"], SOURCE)
        self.assertEqual(t["request_id"], REQUEST)
        self.assertEqual(t["factory_artifact_id"], ARTIFACT_ID)
        self.assertEqual([(s["language"], s["dpi_percent"]) for s in t["sessions"]],
                         [("ja", 125), ("ja", 150), ("en", 125), ("en", 150)])
        self.assertEqual(len({p for s in t["sessions"] for p in s["screenshots"].values()}), 24)
        for session in t["sessions"]:
            self.assertFalse(session["start_pressed"])
            self.assertFalse(session["uncoached_first_launch"])
            self.assertIsNone(session["elapsed_play_seconds"])
            self.assertIsNone(session["first_goal_seconds"])
            self.assertFalse(session["retry_completed"])

    def test_wrong_source_request_artifact_old_pck_or_fake_attestation_rejected(self):
        template = capture_template()
        for key, value in (
            ("source_sha", "f015db1762fb63696bcca304028871235142bf3d"),
            ("request_id", "3d-prism-route-3d-f015db1762fb"),
            ("factory_artifact_id", 13149467845),
            ("pck_sha256", "10acb61a586caa55b2da59ed0aae62f0952cfbaf7a69cac3cf219f3ae2a982c9"),
            ("physical_device", True),
        ):
            with self.subTest(key=key):
                bad = dict(template, **{key: value})
                with self.assertRaises(HandoffHold):
                    verify_template(bad)

    def test_missing_session_or_image_and_false_human_answer_rejected(self):
        for change in ("missing_session", "missing_image", "fake_human"):
            t = capture_template()
            if change == "missing_session":
                t["sessions"].pop()
            elif change == "missing_image":
                t["sessions"][0]["screenshots"].pop("guide")
            else:
                t["sessions"][0]["goal_understood_in_30s"] = True
            with self.subTest(change=change), self.assertRaises(HandoffHold):
                verify_template(t)

    def test_missing_factory_zip_rejected_before_claiming_handoff(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaisesRegex(HandoffHold, "original Factory ZIP missing"):
                check_handoff(Path(d))

    def test_missing_exe_rejected_even_if_archive_preflight_was_mocked(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "factory-original.zip").write_bytes(b"fixture-not-factory")
            with patch("prism_pr21_physical_handoff.verify_archive",
                       return_value={"source_sha": SOURCE, "request_id": REQUEST}):
                with self.assertRaisesRegex(HandoffHold, "missing/symlink handoff member: candidate.exe"):
                    check_handoff(root)

    def test_crc_and_old_factory_zip_are_delegated_to_exact_archive_gate(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "factory-original.zip").write_bytes(b"not-the-immutable-factory-zip")
            with self.assertRaises(ValueError):
                check_handoff(root)


if __name__ == "__main__":
    unittest.main()
