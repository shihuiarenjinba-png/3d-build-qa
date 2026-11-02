"""Offline positive/negative contract tests against pinned Provisioner-3D receipt."""
import copy
from pathlib import Path
import tempfile
import unittest

from prism_sentinel_provisioner_custody_gate import (
    CustodyError, validate_receipt, verify_archive, load_json,
    EXE, PCK, OLD_PCK, ARCHIVE
)

SNAPSHOT = (Path(__file__).resolve().parents[1] /
            "evidence/prism-sentinel-provisioner-byte-custody-snapshot.json")


class ProvisionerCustodyContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.r = load_json(SNAPSHOT)

    def test_real_receipt_correlates_but_remains_hold(self):
        out = validate_receipt(self.r)
        self.assertTrue(out["receipt_correlated"])
        self.assertEqual(out["status"], "HOLD_CHECK_ONLY_CUSTODY_CORRELATED")
        self.assertEqual(out["exe_sha256"], EXE)
        self.assertEqual(out["pck_sha256"], PCK)
        self.assertEqual(out["archive_sha256"], ARCHIVE)
        self.assertFalse(out["real_archive_bytes_verified_this_run"])
        self.assertEqual(out["official_identity_cas"], "HOLD")
        self.assertEqual(out["signed_product_msix"], "HOLD")
        self.assertEqual(out["product_e2e"], "HOLD")
        self.assertFalse(out["store_submission_allowed"])

    def reject(self, section, key, value):
        altered = copy.deepcopy(self.r)
        altered[section][key] = value
        with self.assertRaises(CustodyError):
            validate_receipt(altered)

    def test_reject_legacy_source_and_request(self):
        self.reject("source", "sha", "15fdcb52e46e35e6de8e87c55af99719c21e09b9")
        self.reject("source", "request_id", "3d-prism-route-3d-15fdcb52e46e")
        self.reject("source", "factory_build_head", "0" * 40)

    def test_reject_old_pck_and_wrong_exe(self):
        self.reject("members", "candidate.pck", {"bytes": 71568, "sha256": OLD_PCK})
        self.reject("members", "candidate.exe", {"bytes": 84214784, "sha256": "0" * 64})
        self.reject("manifest", "pck_sha256", OLD_PCK)
        self.reject("manifest", "exe_sha256", "0" * 64)

    def test_reject_wrong_artifact_provenance(self):
        self.reject("artifact", "artifact_id", 13091630401)
        self.reject("artifact", "archive_sha256", "0" * 64)
        self.reject("artifact", "run_head_sha", "15fdcb52e46e35e6de8e87c55af99719c21e09b9")
        self.reject("artifact", "archive_bytes", 31032520)

    def test_reject_legacy_identity_as_new_cas(self):
        self.reject("legacy_revision", "historical_identity_is_new_revision_cas", True)
        self.reject("legacy_revision", "promotable", True)
        self.reject("legacy_revision", "pck_matches_sentinel", True)

    def test_reject_unapproved_version_fixture_and_store(self):
        for key, value in (("package_version", "1.0.0.0"),
                           ("official_identity_cas", "PASS"),
                           ("signed_product_msix", "PASS"),
                           ("unsigned_qa_fixture_is_store_package", True),
                           ("store_submission_allowed", True),
                           ("windows_all_auto_intake", "PASS"),
                           ("product_e2e", "PASS")):
            with self.subTest(key=key):
                self.reject("downstream", key, value)

    def test_reject_manifest_or_route_drift(self):
        self.reject("manifest", "source_sha", "0" * 40)
        self.reject("route", "registration_type", "GDK_GAME")
        self.reject("route", "partner_center_selection", "GDK game")

    def test_reject_missing_checks_and_duplicate_json(self):
        self.reject("checks", "zip_crc", False)
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "duplicate.json"
            p.write_text('{"a":1,"a":2}', encoding="utf-8")
            with self.assertRaises(CustodyError):
                load_json(p)

    def test_bad_archive_never_passes_even_with_valid_receipt(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "wrong.zip"
            p.write_bytes(b"not a Factory ZIP")
            with self.assertRaises(CustodyError):
                verify_archive(p, self.r)


if __name__ == "__main__":
    unittest.main()
