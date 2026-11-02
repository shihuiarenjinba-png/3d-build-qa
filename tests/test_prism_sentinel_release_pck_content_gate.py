"""Synthetic PCK negative tests; CI never calls synthetic bytes real Factory bytes."""
import copy
import hashlib
import json
from pathlib import Path
import struct
import unittest

from prism_sentinel_release_pck_content_gate import (
    PckContentError, PCK_SHA, audit_bytes, parse_pck, validate_historical_inventory
)


def make_pck(resources, *, major=4, minor=3):
    """Construct minimal valid Godot v2 PCK, NOT a product artifact."""
    directory = bytearray()
    payload = bytearray()
    for path, content in resources:
        name = path.encode("utf-8")
        name += b"\0" * (-len(name) % 4)
        directory += struct.pack("<I", len(name)) + name
        offset = len(payload)
        payload += content
        payload += b"\0" * (-len(payload) % 16)
        directory += struct.pack("<QQ", offset, len(content))
        directory += hashlib.md5(content).digest()
        directory += struct.pack("<I", 0)
    base = (100 + len(directory) + 15) & ~15
    header = (b"GDPC" + struct.pack("<IIIIIQ", 2, major, minor, 0, 0, base)
              + b"\0" * 64 + struct.pack("<I", len(resources)))
    assert len(header) == 100
    return header + directory + b"\0" * (base - 100 - len(directory)) + payload


CLEAN = [("res://project.binary", b"compiled project"),
         ("res://scripts/main.gdc", b"compiled main")]


class TestReleasePckContentGate(unittest.TestCase):
    def test_synthetic_clean_is_never_product(self):
        data = make_pck(CLEAN)
        out = audit_bytes(data)
        self.assertEqual(out["status"], "FIXTURE_ONLY_NOT_PRODUCT")
        self.assertFalse(out["real_factory_bytes_checked_this_run"])
        self.assertFalse(out["sale_ready"])
        self.assertFalse(out["store_submission_allowed"])
        self.assertFalse(out["pinned_factory_pck_sha_size_match"])

    def test_old_identity_json_is_release_hold(self):
        out = audit_bytes(make_pck(CLEAN + [
            ("res://store/approved-identity.json", b'{"source_sha":"15fdcb52"}')]))
        self.assertEqual(out["status"], "RELEASE_PCK_CONTENT_HOLD")
        self.assertIn("OLD_IDENTITY_BUNDLED", [x["reason"] for x in out["findings"]])

    def test_factory_manifest_is_release_hold(self):
        out = audit_bytes(make_pck(CLEAN + [
            ("res://product-manifest.json", b'{"lane":"GAME_3D"}')]))
        self.assertEqual(out["status"], "RELEASE_PCK_CONTENT_HOLD")
        self.assertIn("FACTORY_INTERNAL_MANIFEST_BUNDLED",
                      [x["reason"] for x in out["findings"]])

    def test_development_script_compiled_and_remap_are_hold(self):
        for path in ("res://tests/test_smoke.gdc", "res://tests/test_smoke.gd.remap",
                     "res://test/smoke.gd", "res://handoffs/receipt.json"):
            with self.subTest(path=path):
                out = audit_bytes(make_pck(CLEAN + [(path, b"internal")]))
                self.assertEqual(out["status"], "RELEASE_PCK_CONTENT_HOLD")

    def test_all_three_release_contaminants_are_detected(self):
        resources = CLEAN + [
            ("res://store/approved-identity.json", b"old identity"),
            ("res://product-manifest.json", b"factory manifest"),
            ("res://tests/test_smoke.gdc", b"test code"),
        ]
        out = audit_bytes(make_pck(resources))
        self.assertEqual(len(out["findings"]), 3)
        self.assertEqual(out["status"], "RELEASE_PCK_CONTENT_HOLD")

    def test_wrong_pck_cannot_be_passed_as_real_factory(self):
        with self.assertRaisesRegex(PckContentError, "SHA/size mismatch"):
            audit_bytes(make_pck(CLEAN), real_factory_bytes=True)

    def test_malformed_and_tampered_payload_fail_closed(self):
        valid = make_pck(CLEAN)
        for data in (b"not a pck", valid[:-3],
                     valid[:8] + struct.pack("<I", 3) + valid[12:],
                     valid[:12] + struct.pack("<I", 2) + valid[16:]):
            with self.subTest(length=len(data)), self.assertRaises(PckContentError):
                parse_pck(data)
        tampered = bytearray(valid)
        tampered[-17] ^= 1
        with self.assertRaisesRegex(PckContentError, "MD5 mismatch"):
            parse_pck(bytes(tampered))

    def test_duplicate_and_traversal_paths_rejected(self):
        for resources in (
            CLEAN + [CLEAN[0]],
            CLEAN + [("res://../store/approved-identity.json", b"bypass")],
            CLEAN + [("res://store\\approved-identity.json", b"bypass")],
        ):
            with self.subTest(resources=resources[-1][0]), self.assertRaises(PckContentError):
                parse_pck(make_pck(resources))

    def test_historical_inventory_is_hold_not_live_bytes(self):
        path = (Path(__file__).resolve().parents[1] / "evidence" /
                "prism-sentinel-pck-resource-inventory-20261102.json")
        inv = json.loads(path.read_text(encoding="utf-8"))
        out = validate_historical_inventory(inv)
        self.assertEqual(out["status"], "RELEASE_PCK_CONTENT_HOLD")
        self.assertFalse(out["real_factory_bytes_checked_this_run"])
        self.assertEqual(out["evidence_boundary"],
                         "HISTORICAL_INVENTORY_ONLY_NOT_PCK_BYTES")

    def test_inventory_tamper_or_false_promotion_rejected(self):
        path = (Path(__file__).resolve().parents[1] / "evidence" /
                "prism-sentinel-pck-resource-inventory-20261102.json")
        inv = json.loads(path.read_text(encoding="utf-8"))
        for key, value in (
            ("pck_sha256", "0" * 64),
            ("contains_legacy_identity_json", False),
            ("contains_test_smoke_gdc", False),
            ("contains_product_manifest_json", False),
            ("source_sha", "15fdcb52e46e35e6de8e87c55af99719c21e09b9"),
            ("factory_pck_executed_in_ci", True),
            ("sale_ready", True),
        ):
            with self.subTest(key=key), self.assertRaises(PckContentError):
                altered = copy.deepcopy(inv)
                altered[key] = value
                validate_historical_inventory(altered)


if __name__ == "__main__":
    unittest.main()
