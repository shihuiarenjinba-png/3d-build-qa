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
            b'<Applications><Application Id="Game" Executable="Game/game.exe" '
            b'EntryPoint="Windows.FullTrustApplication"/></Applications>'
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

    def make_package(self, manifest=MANIFEST, executable=b"MZmock-game", include_executable=True):
        with zipfile.ZipFile(self.path, "w") as archive:
            archive.writestr("AppxManifest.xml", manifest)
            archive.writestr("Assets/icon.png", b"not-a-real-image")
            if include_executable:
                archive.writestr("Game/game.exe", executable)
        self.sha = hashlib.sha256(self.path.read_bytes()).hexdigest()

    def test_matching_bytes_and_identity_still_need_external_review(self):
        result = verify_msix(receipt(self.sha), self.path, IDENTITY)
        self.assertEqual(result["status"], "EVIDENCE_REVIEW")
        self.assertTrue(result["artifact_bytes_verified"])
        self.assertTrue(result["manifest_identity_matched"])
        self.assertTrue(result["payload_executables_verified"])
        for key in ("official_identity_verified", "github_provenance_verified",
                    "windows_launch_verified", "signature_verified", "submission_authorized"):
            self.assertFalse(result[key])

    def test_missing_declared_executable_blocks(self):
        self.make_package(include_executable=False)
        result = verify_msix(receipt(self.sha), self.path, IDENTITY)
        self.assertEqual(result["status"], "BLOCKED")
        self.assertFalse(result["payload_executables_verified"])

    def test_empty_declared_executable_blocks(self):
        self.make_package(executable=b"")
        self.assertEqual(verify_msix(receipt(self.sha), self.path, IDENTITY)["status"], "BLOCKED")

    def test_non_executable_payload_blocks(self):
        self.make_package(executable=b"not-a-windows-executable")
        self.assertEqual(verify_msix(receipt(self.sha), self.path, IDENTITY)["status"], "BLOCKED")

    def test_traversal_executable_path_blocks(self):
        self.make_package(manifest=MANIFEST.replace(b"Game/game.exe", b"../Game/game.exe"))
        self.assertEqual(verify_msix(receipt(self.sha), self.path, IDENTITY)["status"], "BLOCKED")

    def test_windows_backslash_path_is_supported(self):
        self.make_package(manifest=MANIFEST.replace(b"Game/game.exe", b"Game\\game.exe"))
        self.assertEqual(verify_msix(receipt(self.sha), self.path, IDENTITY)["status"], "EVIDENCE_REVIEW")

    def test_case_colliding_executable_paths_block(self):
        with zipfile.ZipFile(self.path, "w") as archive:
            archive.writestr("AppxManifest.xml", MANIFEST)
            archive.writestr("Game/game.exe", b"MZfirst")
            archive.writestr("game/GAME.EXE", b"MZsecond")
        sha = hashlib.sha256(self.path.read_bytes()).hexdigest()
        self.assertEqual(verify_msix(receipt(sha), self.path, IDENTITY)["status"], "BLOCKED")

    def test_no_official_identity_holds_even_when_bytes_match(self):
        result = verify_msix(receipt(self.sha), self.path)
        self.assertEqual(result["status"], "HOLD")
        self.assertTrue(result["artifact_bytes_verified"])

    def test_tampered_package_blocks(self):
        result = verify_msix(receipt("b" * 64), self.path, IDENTITY)
        self.assertEqual(result["status"], "BLOCKED")
        self.assertFalse(result["artifact_bytes_verified"])

    def test_corrupt_unrelated_asset_crc_blocks(self):
        # A recomputed package SHA alone cannot prove ZIP member integrity.
        # A broken asset must fail even when manifest and EXE remain readable.
        raw = self.path.read_bytes()
        marker = b"not-a-real-image"
        self.assertEqual(raw.count(marker), 1)
        self.path.write_bytes(raw.replace(marker, b"X" + marker[1:], 1))
        digest = hashlib.sha256(self.path.read_bytes()).hexdigest()
        result = verify_msix(receipt(digest), self.path, IDENTITY)
        self.assertEqual(result["status"], "BLOCKED", result)
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

    def test_forged_manifest_namespaces_block(self):
        # Local-name-only XML matching used to accept these spoofed elements.
        # MSIX Package/Identity/Applications/Application must be in the
        # Windows foundation manifest namespace, not a lookalike namespace.
        cases = {
            "package": MANIFEST.replace(
                b'xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"',
                b'xmlns="urn:forged"'),
            "identity": MANIFEST.replace(
                b'<Identity ', b'<Identity xmlns="urn:forged" '),
            "applications": MANIFEST.replace(
                b'<Applications>', b'<Applications xmlns="urn:forged">'),
            "application": MANIFEST.replace(
                b'<Application ', b'<Application xmlns="urn:forged" '),
        }
        for field, manifest in cases.items():
            with self.subTest(field=field):
                self.assertNotEqual(manifest, MANIFEST)
                self.make_package(manifest=manifest)
                result = verify_msix(receipt(self.sha), self.path, IDENTITY)
                self.assertEqual(result["status"], "BLOCKED", result)
                self.assertFalse(result["artifact_bytes_verified"])

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


    def _assert_rejects_added_zip_entry(self, entry, data=b"unsafe"):
        with zipfile.ZipFile(self.path, "w") as archive:
            archive.writestr("AppxManifest.xml", MANIFEST)
            archive.writestr("Game/game.exe", b"MZgame")
            archive.writestr(entry, data)
        sha = hashlib.sha256(self.path.read_bytes()).hexdigest()
        result = verify_msix(receipt(sha), self.path, IDENTITY)
        self.assertEqual(result["status"], "BLOCKED", result)
        self.assertFalse(result["artifact_bytes_verified"])

    def test_unrelated_traversal_entry_blocks_entire_msix(self):
        self._assert_rejects_added_zip_entry("Assets/../evil.txt")

    def test_windows_reserved_device_name_blocks(self):
        self._assert_rejects_added_zip_entry("Assets/CON.txt")

    def test_windows_superscript_com_lpt_device_names_block(self):
        # Win32 reserves COM¹/²/³ and LPT¹/²/³ as device names,
        # including when an extension is present.
        for name in ("COM\u00b9.txt", "com\u00b3.bin", "LPT\u00b2.log"):
            with self.subTest(name=name):
                self._assert_rejects_added_zip_entry("Assets/" + name)

    def test_windows_alternate_data_stream_blocks(self):
        self._assert_rejects_added_zip_entry("Assets/image.png:stream")

    def test_backslash_archive_entry_blocks(self):
        self._assert_rejects_added_zip_entry("Assets\\other.png")

    def test_trailing_space_path_blocks(self):
        self._assert_rejects_added_zip_entry("Assets/bad .png ")

    def test_case_colliding_unrelated_assets_block(self):
        with zipfile.ZipFile(self.path, "w") as archive:
            archive.writestr("AppxManifest.xml", MANIFEST)
            archive.writestr("Game/game.exe", b"MZgame")
            archive.writestr("Assets/ICON.png", b"one")
            archive.writestr("assets/icon.PNG", b"two")
        sha = hashlib.sha256(self.path.read_bytes()).hexdigest()
        self.assertEqual(verify_msix(receipt(sha), self.path, IDENTITY)["status"], "BLOCKED")

    def test_file_directory_ancestor_collision_blocks(self):
        with zipfile.ZipFile(self.path, "w") as archive:
            archive.writestr("AppxManifest.xml", MANIFEST)
            archive.writestr("Game/game.exe", b"MZgame")
            archive.writestr("Assets", b"file")
            archive.writestr("Assets/icon.png", b"image")
        sha = hashlib.sha256(self.path.read_bytes()).hexdigest()
        self.assertEqual(verify_msix(receipt(sha), self.path, IDENTITY)["status"], "BLOCKED")

    def test_symlink_entry_blocks(self):
        import stat
        link = zipfile.ZipInfo("Assets/link")
        link.create_system = 3
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        with zipfile.ZipFile(self.path, "w") as archive:
            archive.writestr("AppxManifest.xml", MANIFEST)
            archive.writestr("Game/game.exe", b"MZgame")
            archive.writestr(link, "target")
        sha = hashlib.sha256(self.path.read_bytes()).hexdigest()
        self.assertEqual(verify_msix(receipt(sha), self.path, IDENTITY)["status"], "BLOCKED")

    def test_unix_special_file_entries_block(self):
        import stat
        for file_type in (stat.S_IFCHR, stat.S_IFBLK, stat.S_IFIFO, stat.S_IFSOCK):
            with self.subTest(file_type=file_type):
                entry = zipfile.ZipInfo("Assets/special")
                entry.create_system = 3
                entry.external_attr = (file_type | 0o600) << 16
                with zipfile.ZipFile(self.path, "w") as archive:
                    archive.writestr("AppxManifest.xml", MANIFEST)
                    archive.writestr("Game/game.exe", b"MZgame")
                    archive.writestr(entry, b"not-a-regular-file")
                sha = hashlib.sha256(self.path.read_bytes()).hexdigest()
                result = verify_msix(receipt(sha), self.path, IDENTITY)
                self.assertEqual(result["status"], "BLOCKED", result)

    def test_zip_file_type_disagrees_with_directory_marker(self):
        import stat
        for filename, file_type in (("Assets/looks-like-file", stat.S_IFDIR),
                                    ("Assets/looks-like-directory/", stat.S_IFREG)):
            with self.subTest(filename=filename):
                entry = zipfile.ZipInfo(filename)
                entry.create_system = 3
                entry.external_attr = (file_type | 0o700) << 16
                with zipfile.ZipFile(self.path, "w") as archive:
                    archive.writestr("AppxManifest.xml", MANIFEST)
                    archive.writestr("Game/game.exe", b"MZgame")
                    archive.writestr(entry, b"" if filename.endswith("/") else b"data")
                sha = hashlib.sha256(self.path.read_bytes()).hexdigest()
                result = verify_msix(receipt(sha), self.path, IDENTITY)
                self.assertEqual(result["status"], "BLOCKED", result)

    def test_zip_expansion_bomb_blocks(self):
        with zipfile.ZipFile(self.path, "w") as archive:
            archive.writestr("AppxManifest.xml", MANIFEST)
            archive.writestr("Game/game.exe", b"MZgame")
            archive.writestr("Assets/zeros.bin", b"\0" * (8 * 1024 * 1024),
                             compress_type=zipfile.ZIP_DEFLATED)
        sha = hashlib.sha256(self.path.read_bytes()).hexdigest()
        self.assertEqual(verify_msix(receipt(sha), self.path, IDENTITY)["status"], "BLOCKED")

    def test_normal_explicit_directory_entry_is_allowed(self):
        with zipfile.ZipFile(self.path, "w") as archive:
            archive.writestr("AppxManifest.xml", MANIFEST)
            archive.writestr("Game/", b"")
            archive.writestr("Game/game.exe", b"MZgame")
        sha = hashlib.sha256(self.path.read_bytes()).hexdigest()
        self.assertEqual(verify_msix(receipt(sha), self.path, IDENTITY)["status"], "EVIDENCE_REVIEW")


if __name__ == "__main__":
    unittest.main()
