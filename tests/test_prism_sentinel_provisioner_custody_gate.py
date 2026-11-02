"""Offline positive/negative contract tests against pinned Provisioner-3D receipt."""
import copy
from pathlib import Path
import tempfile
import unittest

import hashlib
import json
import os
import stat
import warnings
import zipfile
from unittest import mock
import prism_sentinel_provisioner_custody_gate as gate

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


    def test_historical_receipt_metadata_is_pinned_not_live_status(self):
        self.reject("artifact", "github_expired", True)
        self.reject("artifact", "expires_at", "2026-11-06T15:24:12Z")
        for key, value in (("verified_at_utc", "2099-01-01T00:00:00Z"),
                           ("verification_method", "GitHub metadata only")):
            altered = copy.deepcopy(self.r)
            altered[key] = value
            with self.subTest(key=key), self.assertRaises(CustodyError):
                validate_receipt(altered)
        altered = copy.deepcopy(self.r)
        altered["downstream"]["store_ready"] = True
        with self.assertRaises(CustodyError):
            validate_receipt(altered)
        out = validate_receipt(self.r)
        self.assertFalse(out["github_artifact_live_availability_checked_this_run"])
        self.assertFalse(out["real_archive_bytes_verified_this_run"])

    def _synthetic_zip_reader_case(self, mutation=None, error=None):
        """Exercise ZIP reader with tiny bytes, never substitute for real Factory bytes."""
        manifest = {"test_fixture": "synthetic_only"}
        baseline = [
            ("candidate.exe", b"synthetic-windows-exe"),
            ("candidate.pck", b"synthetic-sentinel-pck"),
            ("export-evidence.json", json.dumps(manifest).encode("utf-8")),
        ]
        expected = {name: (len(data), hashlib.sha256(data).hexdigest())
                    for name, data in baseline}
        entries = list(baseline)
        if mutation == "old_pck":
            entries[1] = ("candidate.pck", b"synthetic-sentinel-pcK")
        elif mutation == "manifest":
            entries[2] = ("export-evidence.json", json.dumps({"test_fixture": "synthetic_bad!"}).encode("utf-8"))
        elif mutation == "extra":
            entries.append(("unsigned-qa-fixture.msix", b"not a product"))
        elif mutation == "duplicate":
            entries.append(entries[1])
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "synthetic-not-factory.zip"
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                with zipfile.ZipFile(p, "w", compression=zipfile.ZIP_STORED) as z:
                    for name, data in entries:
                        if mutation == "symlink" and name == "candidate.pck":
                            info = zipfile.ZipInfo(name)
                            info.create_system = 3
                            info.external_attr = (stat.S_IFLNK | 0o777) << 16
                            z.writestr(info, data)
                        else:
                            z.writestr(name, data)
            r = {"artifact": {"archive_bytes": p.stat().st_size},
                 "manifest": manifest}
            archive_hash = hashlib.sha256(p.read_bytes()).hexdigest()
            hold = {"product_e2e": "HOLD", "store_submission_allowed": False}
            with (mock.patch.object(gate, "MEMBERS", expected),
                  mock.patch.object(gate, "ARCHIVE", archive_hash),
                  mock.patch.object(gate, "validate_receipt", return_value=hold.copy())):
                if error:
                    with self.assertRaisesRegex(CustodyError, error):
                        gate.verify_archive(p, r)
                else:
                    result = gate.verify_archive(p, r)
                    self.assertTrue(result["real_archive_bytes_verified_this_run"])
                    self.assertEqual(result["product_e2e"], "HOLD")
                    self.assertFalse(result["store_submission_allowed"])

    def test_synthetic_zip_reader_positive_is_still_hold(self):
        self._synthetic_zip_reader_case()

    def test_synthetic_zip_reader_rejects_rehashed_old_pck(self):
        # Rehashing the outer archive must not hide wrong inner PCK bytes.
        self._synthetic_zip_reader_case("old_pck", "member SHA mismatch")

    def test_synthetic_zip_reader_rejects_forged_manifest(self):
        self._synthetic_zip_reader_case("manifest", "member SHA mismatch")

    def test_synthetic_zip_reader_rejects_unsigned_fixture_extra_member(self):
        self._synthetic_zip_reader_case("extra", "archive member set")

    def test_synthetic_zip_reader_rejects_duplicate_member(self):
        self._synthetic_zip_reader_case("duplicate", "archive member set")

    def test_synthetic_zip_reader_rejects_symlink(self):
        self._synthetic_zip_reader_case("symlink", "unsafe ZIP entry")

    @unittest.skipUnless(os.environ.get("PRISM_SENTINEL_REAL_ZIP"),
                         "real Factory ZIP not supplied; CI checks pinned receipt only")
    def test_actual_factory_zip_if_supplied(self):
        out = verify_archive(Path(os.environ["PRISM_SENTINEL_REAL_ZIP"]), self.r)
        self.assertTrue(out["real_archive_bytes_verified_this_run"])
        self.assertEqual(out["product_e2e"], "HOLD")
        self.assertFalse(out["store_submission_allowed"])



if __name__ == "__main__":
    unittest.main()
