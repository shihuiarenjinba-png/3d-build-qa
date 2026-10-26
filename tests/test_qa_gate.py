import unittest
from qa_gate import inspect


def receipt():
    return {"schema_version": "1.0", "source_factory": "3d-game-factory",
            "request_id": "case-01", "repository_full_name": "owner/demo",
            "source_sha": "a" * 40, "package_sha256": "b" * 64,
            "windows_run_id": "run-1", "runner_evidence_id": "evidence-1",
            "windows_launch": True,
            "tests": {"executed": 10, "failed": 0, "skipped": 0, "crashes": 0}}


class QATest(unittest.TestCase):
    def test_good_claims_still_unverified(self):
        x = inspect(receipt())
        self.assertEqual(x["status"], "EVIDENCE_REVIEW")
        self.assertFalse(x["qa_claims_verified"])
        self.assertTrue(x["human_qa_required"])

    def test_no_tests_hold(self):
        r = receipt()
        r["tests"]["executed"] = 0
        self.assertEqual(inspect(r)["status"], "HOLD")

    def test_failed_tests_hold(self):
        r = receipt()
        r["tests"]["failed"] = 1
        self.assertEqual(inspect(r)["status"], "HOLD")

    def test_launch_failure_hold(self):
        r = receipt()
        r["windows_launch"] = False
        self.assertEqual(inspect(r)["status"], "HOLD")

    def test_missing_evidence_blocks(self):
        r = receipt()
        del r["runner_evidence_id"]
        self.assertEqual(inspect(r)["status"], "BLOCKED")

    def test_unknown_factory_blocks(self):
        r = receipt()
        r["source_factory"] = "AI-Game-Factory"
        self.assertEqual(inspect(r)["status"], "BLOCKED")

    def test_bool_test_count_blocks(self):
        r = receipt()
        r["tests"]["executed"] = True
        self.assertEqual(inspect(r)["status"], "BLOCKED")


if __name__ == "__main__":
    unittest.main()
