import hashlib
import json
from pathlib import Path
import tempfile
import unittest
import zipfile

from msix_artifact_verify import verify_msix, main

MANIFEST = (b'<?xml version="1.0" encoding="utf-8"?>'
            b'<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10">'
            b'<Identity Name="Example.ThreeD" Publisher="CN=Verified" Version="1.0.0.0"/>'
            b'</Package>')
IDENTITY = {"reviewed": True, "source": "partner_center", "store_id": "9PTEST3D0001",
            "name": "Example.ThreeD", "publisher": "CN=Verified", "version": "1.0.0.0"}


def receipt(digest):
    return {
        "schema_version": "1.0", "source_factory": "3d-game-factory",
        "request_id": "three-d-001", "repository_full_name": "owner/game3d",
        "source_sha": "a" * 40, "package_sha256": digest,
        "windows_run_id": "1234", "runner_evidence_id": "1234",
        "windows_launch": True,
        "tests": {"executed": 10, "failed": 0, "skipped": 0, "crashes": 0},
    }


class ArtifactTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "demo.msix"
        self.make_package()

    def make_package(self, manifest=MANIFEST):
        with zipfile.ZipFile(self.path, "w") as archive:
            archive.writestr("AppxManifest.xml", manifest)
            archive.writestr("Assets/icon.png", b"not-a-real-image")
        self.sha = hashlib.sha256(self.path.read_bytes()).hexdigest()

    def test_matching_bytes_and_identity_still_need_external_review(self):
        result = verify_msix(receipt(self.sha), self.path, IDENTITY)
        self.assertEqual(result["status"], "EVIDENCE_REVIEW")
        self.assertTrue(result["artifact_bytes_verified"])
        self.assertTrue(result["manifest_identity_matched"])
        for key in ("official_identity_verified", "github_provenance_verified",
                    "windows_launch_verified", "signature_verified", "submission_authorized"):
            self.assertFalse(result[key])

    def test_no_official_identity_holds_even_when_bytes_match(self):
        result = verify_msix(receipt(self.sha), self.path)
        self.assertEqual(result["status"], "HOLD")
        self.assertTrue(result["artifact_bytes_verified"])

    def test_tampered_package_blocks(self):
        result = verify_msix(receipt("b" * 64), self.path, IDENTITY)
        self.assertEqual(result["status"], "BLOCKED")
        self.assertFalse(result["artifact_bytes_verified"])

    def test_wrong_manifest_identity_blocks(self):
        wrong = dict(IDENTITY, name="Different.Game")
        result = verify_msix(receipt(self.sha), self.path, wrong)
        self.assertEqual(result["status"], "BLOCKED")
        self.assertFalse(result["manifest_identity_matched"])

    def test_unreviewed_identity_blocks(self):
        result = verify_msix(receipt(self.sha), self.path, dict(IDENTITY, reviewed=False))
        self.assertEqual(result["status"], "BLOCKED")

    def test_malformed_manifest_blocks(self):
        self.make_package(b"<Package><Identity")
        result = verify_msix(receipt(self.sha), self.path, IDENTITY)
        self.assertEqual(result["status"], "BLOCKED")

    def test_missing_manifest_blocks(self):
        with zipfile.ZipFile(self.path, "w") as archive:
            archive.writestr("not-a-manifest.txt", "x")
        sha = hashlib.sha256(self.path.read_bytes()).hexdigest()
        self.assertEqual(verify_msix(receipt(sha), self.path, IDENTITY)["status"], "BLOCKED")

    def test_duplicate_manifest_blocks(self):
        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with zipfile.ZipFile(self.path, "w") as archive:
                archive.writestr("AppxManifest.xml", MANIFEST)
                archive.writestr("AppxManifest.xml", MANIFEST)
        sha = hashlib.sha256(self.path.read_bytes()).hexdigest()
        self.assertEqual(verify_msix(receipt(sha), self.path, IDENTITY)["status"], "BLOCKED")

    def test_not_msix_blocks(self):
        renamed = self.path.with_suffix(".zip")
        self.path.rename(renamed)
        self.assertEqual(verify_msix(receipt(self.sha), renamed, IDENTITY)["status"], "BLOCKED")

    def test_failed_windows_qa_stays_hold(self):
        r = receipt(self.sha)
        r["tests"]["failed"] = 1
        self.assertEqual(verify_msix(r, self.path, IDENTITY)["status"], "HOLD")

    def test_cli_exit_codes(self):
        receipt_path = Path(self.tmp.name) / "receipt.json"
        identity_path = Path(self.tmp.name) / "approved.json"
        receipt_path.write_text(json.dumps(receipt(self.sha)), encoding="utf-8")
        identity_path.write_text(json.dumps(IDENTITY), encoding="utf-8")
        args = ["--receipt", str(receipt_path), "--package", str(self.path)]
        self.assertEqual(main(args), 2)
        self.assertEqual(main(args + ["--approved-identity", str(identity_path)]), 0)


if __name__ == "__main__":
    unittest.main()
