"""Historical new consumer revision receipt guard; NOT a fresh ZIP download."""
import json
from pathlib import Path
import unittest

RECEIPT = Path(__file__).resolve().parents[1] / "evidence/prism-sentinel-consumer-new-revision-independent-byte-custody-20261102.json"


class ConsumerRevisionReceiptTests(unittest.TestCase):
    def test_new_revision_separate_from_immutable_sentinel(self):
        data = json.loads(RECEIPT.read_text(encoding="utf-8"))
        self.assertEqual(data["receipt_type"], "PRISM_SENTINEL_NEW_CONSUMER_REVISION_INDEPENDENT_BYTE_CUSTODY")
        self.assertEqual(data["source_sha"], "da6f7c129687922c58c43496da4667ecef903e17")
        self.assertEqual(data["request_id"], "3d-prism-route-3d-" + data["source_sha"][:12])
        self.assertEqual(data["factory_build_head"], data["source_sha"])
        self.assertNotEqual(data["source_sha"], data["old_sentinel_source_sha"])
        self.assertNotEqual(data["pck_sha256"], data["old_sentinel_pck_sha256"])
        self.assertEqual(data["pck_size_bytes"], 48320)
        self.assertEqual(data["pck_resource_count"], 10)
        self.assertTrue(data["all_resource_md5_match"])
        self.assertEqual(data["forbidden_resource_count"], 0)

    def test_clean_payload_does_not_authorize_product(self):
        data = json.loads(RECEIPT.read_text(encoding="utf-8"))
        self.assertEqual(data["new_revision_identity_cas"], "HOLD_36_OWNER")
        self.assertEqual(data["approved_package_version"], "HOLD")
        self.assertEqual(data["signed_product_msix"], "HOLD")
        self.assertEqual(data["windows_all_auto_intake"], "HOLD")
        self.assertEqual(data["physical_windows_gui"], "DEFERRED_LOCAL_GATE")
        self.assertFalse(data["sale_ready"])
        self.assertFalse(data["store_submission_allowed"])
        self.assertIn("historical snapshot", data["evidence_boundary"])
        self.assertTrue(data["old_sentinel_pck_must_not_be_relabelled"])


if __name__ == "__main__":
    unittest.main()
