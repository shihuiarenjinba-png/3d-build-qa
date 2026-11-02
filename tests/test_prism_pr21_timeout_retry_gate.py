"""Negative fixtures for PR21 exported-PCK timeout / post-defeat retry images."""
import copy
import hashlib
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch
import zlib

from prism_consumer_artifact_runtime_gate import (
    SOURCE, REQUEST, ARTIFACT_ID, RUN_ID, ZIP_SHA, MEMBERS,
)
from prism_pr21_software_baseline_gate import FRAMES, SoftwareBaselineHold
from prism_pr21_timeout_retry_gate import (
    EXPECTED_STATES, TimeoutRetryHold, verify,
)


def png_chunk(kind: bytes, payload: bytes) -> bytes:
    return (struct.pack(">I", len(payload)) + kind + payload
            + struct.pack(">I", zlib.crc32(kind + payload) & 0xffffffff))


def make_png(seed: int, width: int = 1024, height: int = 768) -> bytes:
    # Valid RGB PNG, not a screenshot. Only for negative validator fixtures.
    line = b"\x00" + bytes((i + seed) % 256 for i in range(width * 3))
    raw = line * height
    header = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    return (b"\x89PNG\r\n\x1a\n" + png_chunk(b"IHDR", header)
            + png_chunk(b"IDAT", zlib.compress(raw, 6))
            + png_chunk(b"IEND", b""))


class TimeoutRetryGateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        for name, seed in (("timeout_ja", 1), ("retry_ja", 5)):
            data = make_png(seed)
            self.assertGreater(len(data), 4096)
            (self.root / (name + ".png")).write_bytes(data)
        expected = {
            "source_sha": SOURCE, "request_id": REQUEST,
            "factory_run_id": RUN_ID, "factory_artifact_id": ARTIFACT_ID,
            "zip_sha256": ZIP_SHA, "exe_sha256": MEMBERS["candidate.exe"][1],
            "pck_sha256": MEMBERS["candidate.pck"][1],
            "manifest_sha256": MEMBERS["export-evidence.json"][1],
        }
        self.preflight = {
            **expected,
            "receipt_type": "PRISM_CONSUMER_REAL_ARTIFACT_RUNTIME_PREFLIGHT",
            "status": "EXACT_FACTORY_BYTES_VERIFIED_RUNTIME_PENDING",
            "archive_bytes_verified_this_run": True,
            "godot_pck_executed_this_run": False,
        }
        self.runtime = {
            "source_sha": SOURCE, "request_id": REQUEST,
            "pck_sha256": MEMBERS["candidate.pck"][1],
            "runtime_kind": "GODOT_4_3_EXPORTED_PCK_LOADED_SOFTWARE_RENDER",
            "status": "PASS_PCK_LOADED_LOGIC_AND_RENDER",
            "physical_windows_gui": "DEFERRED_LOCAL_GATE",
            "sale_ready": False,
            "assertions": ["timeout", "restart", "english_japanese"],
            "timeout_retry_states": copy.deepcopy(EXPECTED_STATES),
        }
        self.baseline = {
            **expected,
            "status": "PCK_LOADED_SOFTWARE_RUNTIME_QA_PASS_NOT_HUMAN_GUI",
            "godot_pck_executed_this_run": True,
            "physical_windows_gui": "DEFERRED_LOCAL_GATE",
            "human_first_30s_readability": "HOLD",
            "human_90s_gameplay": "HOLD",
            "sale_ready": False, "store_submission_allowed": False,
            "software_rendered_screenshots": {
                name: {"sha256": hashlib.sha256(name.encode()).hexdigest()}
                for name in FRAMES
            },
        }

    def tearDown(self):
        self.tmp.cleanup()

    def run_gate(self):
        # The existing baseline gate has its own exhaustive PNG/receipt tests.
        # Here isolate new two-state logic while checking the two real PNG CRCs.
        with patch("prism_pr21_timeout_retry_gate.verify_software_baseline",
                   return_value={"software_screenshot_sha256_count": 7}):
            return verify(self.preflight, self.runtime, self.baseline, self.root)

    def test_two_new_states_with_nine_distinct_frames_pass_software_only(self):
        r = self.run_gate()
        self.assertEqual(r["all_software_frame_sha256_count"], 9)
        self.assertEqual(set(r["new_software_frames_verified"]),
                         {"timeout_ja", "retry_ja"})
        self.assertEqual(r["physical_windows_gui"], "HOLD")
        self.assertFalse(r["sale_ready"])
        self.assertFalse(r["store_submission_allowed"])

    def test_missing_timeout_image_holds(self):
        (self.root / "timeout_ja.png").unlink()
        with self.assertRaisesRegex(TimeoutRetryHold, "missing timeout_ja"):
            self.run_gate()

    def test_missing_retry_image_holds(self):
        (self.root / "retry_ja.png").unlink()
        with self.assertRaisesRegex(TimeoutRetryHold, "missing retry_ja"):
            self.run_gate()

    def test_duplicate_timeout_and_retry_image_holds(self):
        (self.root / "retry_ja.png").write_bytes(
            (self.root / "timeout_ja.png").read_bytes())
        with self.assertRaisesRegex(TimeoutRetryHold, "duplicate state"):
            self.run_gate()

    def test_reused_baseline_image_holds(self):
        self.baseline["software_rendered_screenshots"]["ja"]["sha256"] = (
            hashlib.sha256((self.root / "retry_ja.png").read_bytes()).hexdigest())
        with self.assertRaisesRegex(TimeoutRetryHold, "copied or duplicate"):
            self.run_gate()

    def test_corrupt_png_crc_holds(self):
        p = self.root / "timeout_ja.png"
        data = bytearray(p.read_bytes())
        data[50] ^= 0x40
        p.write_bytes(data)
        with self.assertRaisesRegex(ValueError, "PNG CRC mismatch"):
            self.run_gate()

    def test_wrong_resolution_holds(self):
        (self.root / "retry_ja.png").write_bytes(make_png(5, 960, 768))
        with self.assertRaisesRegex(ValueError, "1024x768"):
            self.run_gate()

    def test_old_pr20_pck_holds(self):
        self.preflight["pck_sha256"] = "10acb61a586caa55b2da59ed0aae62f0952cfbaf7a69cac3cf219f3ae2a982c9"
        with self.assertRaisesRegex(TimeoutRetryHold, "PROVENANCE_HOLD: pck_sha256"):
            self.run_gate()

    def test_old_source_or_request_holds(self):
        self.runtime["source_sha"] = "f015db1762fb63696bcca304028871235142bf3d"
        with self.assertRaisesRegex(TimeoutRetryHold, "RUNTIME_HOLD"):
            self.run_gate()
        self.runtime["source_sha"] = SOURCE
        self.baseline["request_id"] = "3d-prism-route-3d-f015db1762fb"
        with self.assertRaisesRegex(TimeoutRetryHold, "PROVENANCE_HOLD: request_id"):
            self.run_gate()

    def test_manifest_sha_mismatch_holds(self):
        self.baseline["manifest_sha256"] = "f" * 64
        with self.assertRaisesRegex(TimeoutRetryHold, "manifest_sha256"):
            self.run_gate()

    def test_timeout_reason_or_retry_state_drift_holds(self):
        self.runtime["timeout_retry_states"]["timeout_reason"] = "Victory"
        with self.assertRaisesRegex(TimeoutRetryHold, "STATE_HOLD"):
            self.run_gate()
        self.runtime["timeout_retry_states"] = copy.deepcopy(EXPECTED_STATES)
        self.runtime["timeout_retry_states"]["retry_next_target"] = 2
        with self.assertRaisesRegex(TimeoutRetryHold, "STATE_HOLD"):
            self.run_gate()

    def test_fabricated_human_pass_holds(self):
        self.baseline["human_90s_gameplay"] = "PASS"
        with self.assertRaisesRegex(TimeoutRetryHold, "BASELINE_HOLD"):
            self.run_gate()

    def test_original_seven_frame_gate_failure_propagates(self):
        with patch("prism_pr21_timeout_retry_gate.verify_software_baseline",
                   side_effect=SoftwareBaselineHold("missing original JA frame")):
            with self.assertRaisesRegex(SoftwareBaselineHold, "missing original"):
                verify(self.preflight, self.runtime, self.baseline, self.root)


if __name__ == "__main__":
    unittest.main()
