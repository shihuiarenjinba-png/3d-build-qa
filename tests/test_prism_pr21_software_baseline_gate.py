"""Synthetic PR21 negative fixtures, never proof of actual Godot/Windows."""
import copy
import hashlib
from pathlib import Path
import struct
import tempfile
import unittest
import zlib

from prism_pr21_software_baseline_gate import (
    SOURCE, REQUEST, FACTORY_RUN_ID, FACTORY_ARTIFACT_ID, ZIP_SHA,
    EXE_SHA, PCK_SHA, MANIFEST_SHA, FRAMES, ASSERTIONS,
    SoftwareBaselineHold, verify_software_baseline,
)


def chunk(kind, payload):
    return (struct.pack(">I", len(payload)) + kind + payload +
            struct.pack(">I", zlib.crc32(kind + payload) & 0xffffffff))


def fake_png(n):
    header = struct.pack(">IIBBBBB", 1024, 768, 8, 2, 0, 0, 0)
    pixels = (b"\x00" + b"\x00" * (1024 * 3)) * 768
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", header) +
            chunk(b"tEXt", b"fixture-only-not-rendered:" + str(n).encode()) +
            chunk(b"IDAT", zlib.compress(pixels)) + chunk(b"IEND", b""))


class SoftwareBaselineTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        frames = {}
        for i, name in enumerate(FRAMES):
            data = fake_png(i)
            (self.root / (name + ".png")).write_bytes(data)
            frames[name] = {"sha256": hashlib.sha256(data).hexdigest(),
                            "bytes": len(data), "width": 1024, "height": 768}
        self.receipt = {
            "schema_version": 1,
            "receipt_type": "PRISM_CONSUMER_REAL_ARTIFACT_RUNTIME_PREFLIGHT",
            "status": "PCK_LOADED_SOFTWARE_RUNTIME_QA_PASS_NOT_HUMAN_GUI",
            "source_sha": SOURCE, "factory_build_head": SOURCE,
            "request_id": REQUEST, "factory_run_id": FACTORY_RUN_ID,
            "factory_artifact_id": FACTORY_ARTIFACT_ID,
            "zip_sha256": ZIP_SHA, "exe_sha256": EXE_SHA,
            "pck_sha256": PCK_SHA, "manifest_sha256": MANIFEST_SHA,
            "archive_bytes_verified_this_run": True,
            "godot_pck_executed_this_run": True,
            "japanese_font_glyphs_available": True,
            "physical_windows_gui": "DEFERRED_LOCAL_GATE",
            "human_first_30s_readability": "HOLD",
            "human_90s_gameplay": "HOLD",
            "dpi_125_150": "HOLD", "identity_cas": "HOLD_36_OWNER",
            "sale_ready": False, "store_submission_allowed": False,
            "godot_4_3_runtime_assertions": sorted(ASSERTIONS),
            "board_colored_bounds": {"width": 504, "height": 442},
            "software_rendered_screenshots": frames,
        }

    def tearDown(self):
        self.tmp.cleanup()

    def test_synthetic_fixture_never_physical_or_sale(self):
        result = verify_software_baseline(self.receipt, self.root)
        self.assertEqual(result["software_screenshot_sha256_count"], 7)
        self.assertEqual(result["physical_windows_gui"], "HOLD")
        self.assertEqual(result["human_real_time_90s"], "HOLD")
        self.assertFalse(result["sale_ready"])

    def test_wrong_source_request_artifact_sha_or_false_claims_hold(self):
        for key, bad in (
            ("source_sha", "f015db1762fb63696bcca304028871235142bf3d"),
            ("factory_build_head", "f015db1762fb63696bcca304028871235142bf3d"),
            ("request_id", "3d-prism-route-3d-f015db1762fb"),
            ("factory_artifact_id", 13149467845),
            ("pck_sha256", "10acb61a586caa55b2da59ed0aae62f0952cfbaf7a69cac3cf219f3ae2a982c9"),
            ("zip_sha256", "0" * 64),
            ("exe_sha256", "0" * 64),
            ("manifest_sha256", "0" * 64),
            ("godot_pck_executed_this_run", False),
            ("japanese_font_glyphs_available", False),
            ("human_90s_gameplay", "PASS"),
            ("physical_windows_gui", "PASS"),
            ("sale_ready", True),
        ):
            with self.subTest(key=key):
                with self.assertRaises(SoftwareBaselineHold):
                    verify_software_baseline(dict(self.receipt, **{key: bad}), self.root)

    def test_missing_or_swapped_japanese_english_frame_hold(self):
        path = self.root / "guide_ja.png"
        data = path.read_bytes()
        path.unlink()
        with self.assertRaisesRegex(SoftwareBaselineHold, "missing frame"):
            verify_software_baseline(self.receipt, self.root)
        path.write_bytes((self.root / "guide_en.png").read_bytes())
        with self.assertRaisesRegex(SoftwareBaselineHold, "frame byte length|frame digest"):
            verify_software_baseline(self.receipt, self.root)
        path.write_bytes(data)

    def test_receipt_frame_hash_and_language_assertions_hold(self):
        bad = copy.deepcopy(self.receipt)
        bad["software_rendered_screenshots"]["guide_ja"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(SoftwareBaselineHold, "frame digest"):
            verify_software_baseline(bad, self.root)
        bad = copy.deepcopy(self.receipt)
        bad["godot_4_3_runtime_assertions"].remove("english_japanese")
        with self.assertRaisesRegex(SoftwareBaselineHold, "PCK assertions"):
            verify_software_baseline(bad, self.root)
        bad = copy.deepcopy(self.receipt)
        bad["software_rendered_screenshots"].pop("scan")
        with self.assertRaisesRegex(SoftwareBaselineHold, "seven frames"):
            verify_software_baseline(bad, self.root)


if __name__ == "__main__":
    unittest.main()
