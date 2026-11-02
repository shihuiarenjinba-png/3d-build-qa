"""Negative fixtures: old lineage, fake physical PASS, false causes and PNG reuse."""
import copy
import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from prism_pr22_failure_reason_gate import (
    ARTIFACT_ID, EXPECTED_HINTS, FRAMES, MEMBERS, PR22Hold, REQUEST, RUN_ID,
    SOURCE, ZIP_SHA, ZIP_SIZE, verify_archive, verify_runtime,
)


def make_preflight():
    return {
        "status": "PR22_EXACT_FACTORY_BYTES_VERIFIED_RUNTIME_PENDING",
        "source_sha": SOURCE, "request_id": REQUEST,
        "factory_run_id": RUN_ID, "factory_artifact_id": ARTIFACT_ID,
        "zip_sha256": ZIP_SHA, "zip_size_bytes": ZIP_SIZE,
        "zip_crc_verified": True,
        "exe_sha256": MEMBERS["candidate.exe"][1],
        "pck_sha256": MEMBERS["candidate.pck"][1],
        "manifest_sha256": MEMBERS["export-evidence.json"][1],
        "physical_windows_gui": "HOLD", "sale_ready": False,
    }


def make_runtime():
    states = {}
    for name in FRAMES:
        cause, lang = name.split("_")
        states[name] = {
            "status": "playing" if cause == "retry" else "failed",
            "failure_reason": "" if cause == "retry" else cause,
            "language": lang,
            "hint_text": ("塔1→2→3へ再挑戦" if lang == "ja" else "Towers 1→2→3; retry")
                         if cause == "retry" else EXPECTED_HINTS[name],
            "remaining_seconds": 90 if cause == "retry" else 0,
            "next_target": 0,
        }
    return {
        "runtime_kind": "GODOT_4_3_PR22_EXPORTED_PCK_SOFTWARE_RENDER",
        "status": "PASS_PCK_CAUSE_SPECIFIC_STATES",
        "capture_kind": "GODOT_MESA_XVFB_TIME_ADVANCED_NOT_HUMAN",
        "source_sha": SOURCE, "request_id": REQUEST,
        "pck_sha256": MEMBERS["candidate.pck"][1],
        "states": states, "stale_trap_event_timeout_checked": True,
        "physical_windows_gui": "HOLD", "human_real_time_90s": "HOLD",
        "sale_ready": False, "store_submission_allowed": False,
    }


class TestPR22FailureReasonGate(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.preflight = make_preflight()
        self.runtime = make_runtime()
        for i, name in enumerate(FRAMES):
            (self.root / (name + ".png")).write_bytes(bytes([i + 1]) * 5000)

    def run_gate(self):
        with patch("prism_pr22_failure_reason_gate.check_png",
                   side_effect=lambda p: hashlib.sha256(p.read_bytes()).hexdigest()):
            return verify_runtime(self.preflight, self.runtime, self.root)

    def test_valid_fixture_is_software_only(self):
        result = self.run_gate()
        self.assertEqual(result["software_frame_sha256_count"], 8)
        self.assertEqual(result["physical_windows_gui"], "HOLD")
        self.assertFalse(result["sale_ready"])

    def test_old_pr21_source_rejected(self):
        self.preflight["source_sha"] = "066d9f51d58cfecb994665d5c31adb1156c38942"
        with self.assertRaisesRegex(PR22Hold, "lineage"):
            self.run_gate()

    def test_old_pr21_pck_rejected(self):
        self.runtime["pck_sha256"] = "a27c198ff4bdaa961780b4e42d5fb429c328c5bad0b5cb816e399c06e3fd8cb9"
        with self.assertRaisesRegex(PR22Hold, "lineage"):
            self.run_gate()

    def test_request_mismatch_rejected(self):
        self.runtime["request_id"] = "3d-prism-route-3d-066d9f51d58c"
        with self.assertRaisesRegex(PR22Hold, "lineage"):
            self.run_gate()

    def test_fake_physical_pass_rejected(self):
        self.runtime["physical_windows_gui"] = "PASS"
        with self.assertRaisesRegex(PR22Hold, "physical/human"):
            self.run_gate()

    def test_fake_human_pass_rejected(self):
        self.runtime["human_real_time_90s"] = "PASS"
        with self.assertRaisesRegex(PR22Hold, "physical/human"):
            self.run_gate()

    def test_wrong_failure_cause_rejected(self):
        self.runtime["states"]["timeout_ja"]["failure_reason"] = "trap"
        with self.assertRaisesRegex(PR22Hold, "state reason"):
            self.run_gate()

    def test_wrong_timeout_advice_rejected(self):
        self.runtime["states"]["timeout_ja"]["hint_text"] = EXPECTED_HINTS["trap_ja"]
        with self.assertRaisesRegex(PR22Hold, "cause-specific"):
            self.run_gate()

    def test_language_mix_rejected(self):
        self.runtime["states"]["sentinel_ja"]["hint_text"] = EXPECTED_HINTS["sentinel_en"]
        with self.assertRaisesRegex(PR22Hold, "cause-specific"):
            self.run_gate()

    def test_stale_trap_event_not_tested_rejected(self):
        self.runtime["stale_trap_event_timeout_checked"] = False
        with self.assertRaisesRegex(PR22Hold, "stale trap"):
            self.run_gate()

    def test_retry_without_full_clock_rejected(self):
        self.runtime["states"]["retry_en"]["remaining_seconds"] = 84
        with self.assertRaisesRegex(PR22Hold, "retry"):
            self.run_gate()

    def test_missing_image_rejected(self):
        (self.root / "trap_ja.png").unlink()
        with self.assertRaisesRegex(PR22Hold, "missing/empty"):
            self.run_gate()

    def test_copied_image_rejected(self):
        (self.root / "retry_ja.png").write_bytes((self.root / "timeout_ja.png").read_bytes())
        with self.assertRaisesRegex(PR22Hold, "duplicate"):
            self.run_gate()

    def test_png_crc_rejected(self):
        # With real PNG verifier, a large non-PNG blob is not accepted.
        with self.assertRaises((ValueError, PR22Hold)):
            verify_runtime(self.preflight, self.runtime, self.root)

    def test_old_zip_rejected(self):
        p = self.root / "old-pr21.zip"
        p.write_bytes(b"old-pr21")
        with self.assertRaisesRegex(PR22Hold, "ZIP size"):
            verify_archive(p)


if __name__ == "__main__":
    unittest.main()
