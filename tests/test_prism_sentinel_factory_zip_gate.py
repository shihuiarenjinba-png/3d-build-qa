"""Regression: live Factory receipt cannot authorize Store, Identity, or legacy PCK."""
import copy
import json
from pathlib import Path
import unittest

from prism_sentinel_factory_zip_gate import (
    EvidenceError, validate_receipt, verify_zip, ARCHIVE_SHA, FILES
)

RECEIPT = Path(__file__).resolve().parents[1] / "evidence/prism-sentinel-factory-live-recheck-20261102.json"


class TestSentinelFactoryLiveReceipt(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.receipt = json.loads(RECEIPT.read_text(encoding="utf-8"))

    def test_pinned_receipt_is_valid_but_not_store_authorization(self):
        self.assertTrue(validate_receipt(self.receipt))
        self.assertEqual(self.receipt["artifact"]["archive_sha256"], ARCHIVE_SHA)
        self.assertEqual(self.receipt["members"]["candidate.pck"]["sha256"], FILES["candidate.pck"][1])
        self.assertEqual(self.receipt["downstream"]["product_e2e"], "HOLD")

    def test_reject_source_drift(self):
        r = copy.deepcopy(self.receipt)
        r["source"]["sha"] = "15fdcb52e46e35e6de8e87c55af99719c21e09b9"
        with self.assertRaises(EvidenceError):
            validate_receipt(r)

    def test_reject_legacy_pck_relabel(self):
        r = copy.deepcopy(self.receipt)
        r["members"]["candidate.pck"]["sha256"] = r["legacy_provisioner_discrimination"]["legacy_pck_sha256"]
        with self.assertRaises(EvidenceError):
            validate_receipt(r)

    def test_reject_fixture_or_identity_promotion(self):
        for key, value in (("signed_product_msix", "PASS"),
                           ("official_identity_cas", "PASS"),
                           ("unsigned_qa_fixture_is_store_package", True),
                           ("historical_identity_rebound_to_sentinel", True),
                           ("store_submission_allowed", True)):
            with self.subTest(key=key):
                r = copy.deepcopy(self.receipt)
                r["downstream"][key] = value
                with self.assertRaises(EvidenceError):
                    validate_receipt(r)

    def test_reject_wrong_zip_even_with_valid_receipt(self):
        with self.assertRaises(EvidenceError):
            verify_zip(RECEIPT, self.receipt)


if __name__ == "__main__":
    unittest.main()
