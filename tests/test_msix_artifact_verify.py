import base64
import hashlib
import struct
import xml.etree.ElementTree as ET
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
BLOCKMAP_NS = "http://schemas.microsoft.com/appx/2010/blockmap"
CONTENT_TYPES = (b'<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
                 b'<Default Extension="exe" ContentType="application/octet-stream"/>'
                 b'<Default Extension="xml" ContentType="application/xml"/>'
                 b'<Default Extension="png" ContentType="image/png"/>'
                 b'<Default Extension="txt" ContentType="text/plain"/>'
                 b'<Default Extension="bin" ContentType="application/octet-stream"/>'
                 b'<Override PartName="/AppxManifest.xml" ContentType="application/vnd.ms-appx.manifest+xml"/>'
                 b'<Override PartName="/AppxBlockMap.xml" ContentType="application/vnd.ms-appx.blockmap+xml"/>'
                 b'</Types>')
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

    def make_package(self, manifest=MANIFEST, executable=b"MZmock-game", include_executable=True,
                     include_blockmap=True, blockmap_mutator=None, content_types=CONTENT_TYPES):
        with zipfile.ZipFile(self.path, "w") as archive:
            if content_types is not None:
                archive.writestr("[Content_Types].xml", content_types)
            archive.writestr("AppxManifest.xml", manifest)
            archive.writestr("Assets/icon.png", b"not-a-real-image")
            if include_executable:
                archive.writestr("Game/game.exe", executable)
        if include_blockmap:
            self.add_blockmap(blockmap_mutator)
        self.sha = hashlib.sha256(self.path.read_bytes()).hexdigest()


    def add_blockmap(self, mutate=None):
        """Create an offline-only block map with correct ZIP local header sizes."""
        root = ET.Element(f"{{{BLOCKMAP_NS}}}BlockMap", {
            "HashMethod": "http://www.w3.org/2001/04/xmlenc#sha256"})
        with zipfile.ZipFile(self.path) as archive, self.path.open("rb") as raw:
            for info in archive.infolist():
                if info.is_dir() or info.filename in ("AppxBlockMap.xml", "[Content_Types].xml"):
                    continue
                raw.seek(info.header_offset)
                header = raw.read(30)
                name_len, extra_len = struct.unpack_from("<HH", header, 26)
                node = ET.SubElement(root, f"{{{BLOCKMAP_NS}}}File", {
                    "Name": info.filename.replace("/", "\\"),
                    "Size": str(info.file_size),
                    "LfhSize": str(30 + name_len + extra_len)})
                with archive.open(info) as stream:
                    blocks = []
                    while True:
                        data = stream.read(65536)
                        if not data:
                            break
                        blocks.append(ET.SubElement(node, f"{{{BLOCKMAP_NS}}}Block", {
                            "Hash": base64.b64encode(hashlib.sha256(data).digest()).decode()}))
                    if info.compress_type == zipfile.ZIP_DEFLATED:
                        for i, block in enumerate(blocks):
                            block.set("Size", str(1 if i < len(blocks) - 1
                                                  else info.compress_size - (len(blocks) - 1)))
        if mutate:
            mutate(root)
        with zipfile.ZipFile(self.path, "a") as archive:
            archive.writestr("AppxBlockMap.xml", ET.tostring(root, encoding="utf-8"))


    def test_missing_blockmap_blocks(self):
        self.make_package(include_blockmap=False)
        result = verify_msix(receipt(self.sha), self.path, IDENTITY)
        self.assertEqual(result["status"], "BLOCKED", result)
        self.assertFalse(result["blockmap_verified"])

    def test_forged_blockmap_hash_blocks(self):
        def tamper(root):
            block = root.find(f"{{{BLOCKMAP_NS}}}File").find(f"{{{BLOCKMAP_NS}}}Block")
            block.set("Hash", base64.b64encode(b"\x00" * 32).decode())
        self.make_package(blockmap_mutator=tamper)
        result = verify_msix(receipt(self.sha), self.path, IDENTITY)
        self.assertEqual(result["status"], "BLOCKED", result)
        self.assertFalse(result["blockmap_verified"])

    def test_blockmap_omitted_asset_blocks(self):
        def tamper(root):
            for node in list(root):
                if node.get("Name") == "Assets\\icon.png":
                    root.remove(node)
        self.make_package(blockmap_mutator=tamper)
        self.assertEqual(verify_msix(receipt(self.sha), self.path, IDENTITY)["status"], "BLOCKED")

    def test_blockmap_wrong_namespace_blocks(self):
        def tamper(root):
            root.tag = "{urn:forged}BlockMap"
        self.make_package(blockmap_mutator=tamper)
        self.assertEqual(verify_msix(receipt(self.sha), self.path, IDENTITY)["status"], "BLOCKED")

    def test_blockmap_wrong_size_blocks(self):
        def tamper(root):
            root.find(f"{{{BLOCKMAP_NS}}}File").set("Size", "999999")
        self.make_package(blockmap_mutator=tamper)
        self.assertEqual(verify_msix(receipt(self.sha), self.path, IDENTITY)["status"], "BLOCKED")

    def test_blockmap_two_uncompressed_blocks_pass_synthetic(self):
        with zipfile.ZipFile(self.path, "w") as archive:
            archive.writestr("[Content_Types].xml", CONTENT_TYPES)
            archive.writestr("AppxManifest.xml", MANIFEST)
            archive.writestr("Game/game.exe", b"MZgame")
            archive.writestr("Assets/large.bin", b"A" * 65537)
        self.add_blockmap()
        sha = hashlib.sha256(self.path.read_bytes()).hexdigest()
        result = verify_msix(receipt(sha), self.path, IDENTITY)
        self.assertEqual(result["status"], "EVIDENCE_REVIEW", result)
        self.assertTrue(result["blockmap_verified"])

    def test_blockmap_compressed_file_pass_synthetic(self):
        with zipfile.ZipFile(self.path, "w") as archive:
            archive.writestr("[Content_Types].xml", CONTENT_TYPES)
            archive.writestr("AppxManifest.xml", MANIFEST)
            archive.writestr("Game/game.exe", b"MZgame")
            archive.writestr("Assets/compressed.txt", b"abc" * 200,
                             compress_type=zipfile.ZIP_DEFLATED)
        self.add_blockmap()
        sha = hashlib.sha256(self.path.read_bytes()).hexdigest()
        result = verify_msix(receipt(sha), self.path, IDENTITY)
        self.assertEqual(result["status"], "EVIDENCE_REVIEW", result)
        self.assertTrue(result["blockmap_verified"])


    def test_blockmap_noncanonical_name_aliases_block(self):
        # A BlockMap name must match the ZIP member's canonical Windows
        # spelling, not merely casefold/replace to the same lookup key.
        # These two aliases currently pass the older blockmap verifier.
        aliases = ("Assets/icon.png", "assets\\icon.png", "Assets\\\\icon.png")
        for alias in aliases:
            with self.subTest(alias=alias):
                def tamper(root):
                    for node in root:
                        if node.get("Name") == "Assets\\icon.png":
                            node.set("Name", alias)
                            return
                    self.fail("missing fixture asset")
                self.make_package(blockmap_mutator=tamper)
                result = verify_msix(receipt(self.sha), self.path, IDENTITY)
                self.assertEqual(result["status"], "BLOCKED", result)

    def test_blockmap_wrong_lfh_size_blocks(self):
        def tamper(root):
            root.find(f"{{{BLOCKMAP_NS}}}File").set("LfhSize", "30")
        self.make_package(blockmap_mutator=tamper)
        self.assertEqual(verify_msix(receipt(self.sha), self.path, IDENTITY)["status"], "BLOCKED")

    def test_blockmap_duplicate_file_blocks(self):
        def tamper(root):
            root.append(ET.fromstring(ET.tostring(root[0])))
        self.make_package(blockmap_mutator=tamper)
        self.assertEqual(verify_msix(receipt(self.sha), self.path, IDENTITY)["status"], "BLOCKED")

    def test_blockmap_unsupported_hash_method_blocks(self):
        def tamper(root):
            root.set("HashMethod", "urn:untrusted-hash")
        self.make_package(blockmap_mutator=tamper)
        self.assertEqual(verify_msix(receipt(self.sha), self.path, IDENTITY)["status"], "BLOCKED")

    def test_blockmap_wrong_compressed_size_blocks(self):
        with zipfile.ZipFile(self.path, "w") as archive:
            archive.writestr("[Content_Types].xml", CONTENT_TYPES)
            archive.writestr("AppxManifest.xml", MANIFEST)
            archive.writestr("Game/game.exe", b"MZgame")
            archive.writestr("Assets/compressed.txt", b"abc" * 200,
                             compress_type=zipfile.ZIP_DEFLATED)
        def tamper(root):
            for node in root:
                if node.get("Name") == "Assets\\compressed.txt":
                    node[0].set("Size", "1")
        self.add_blockmap(tamper)
        sha = hashlib.sha256(self.path.read_bytes()).hexdigest()
        self.assertEqual(verify_msix(receipt(sha), self.path, IDENTITY)["status"], "BLOCKED")

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
            archive.writestr("[Content_Types].xml", CONTENT_TYPES)
            archive.writestr("AppxManifest.xml", MANIFEST)
            archive.writestr("Game/game.exe", b"MZfirst")
            archive.writestr("game/GAME.EXE", b"MZsecond")
        self.add_blockmap()
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
        self.add_blockmap()
        sha = hashlib.sha256(self.path.read_bytes()).hexdigest()
        self.assertEqual(verify_msix(receipt(sha), self.path, IDENTITY)["status"], "BLOCKED")

    def test_duplicate_manifest_blocks(self):
        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with zipfile.ZipFile(self.path, "w") as archive:
                archive.writestr("[Content_Types].xml", CONTENT_TYPES)
                archive.writestr("AppxManifest.xml", MANIFEST)
                archive.writestr("[Content_Types].xml", CONTENT_TYPES)
                archive.writestr("AppxManifest.xml", MANIFEST)
        self.add_blockmap()
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
            archive.writestr("[Content_Types].xml", CONTENT_TYPES)
            archive.writestr("AppxManifest.xml", MANIFEST)
            archive.writestr("Game/game.exe", b"MZgame")
            archive.writestr(entry, data)
        self.add_blockmap()
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
            archive.writestr("[Content_Types].xml", CONTENT_TYPES)
            archive.writestr("AppxManifest.xml", MANIFEST)
            archive.writestr("Game/game.exe", b"MZgame")
            archive.writestr("Assets/ICON.png", b"one")
            archive.writestr("assets/icon.PNG", b"two")
        self.add_blockmap()
        sha = hashlib.sha256(self.path.read_bytes()).hexdigest()
        self.assertEqual(verify_msix(receipt(sha), self.path, IDENTITY)["status"], "BLOCKED")

    def test_file_directory_ancestor_collision_blocks(self):
        with zipfile.ZipFile(self.path, "w") as archive:
            archive.writestr("[Content_Types].xml", CONTENT_TYPES)
            archive.writestr("AppxManifest.xml", MANIFEST)
            archive.writestr("Game/game.exe", b"MZgame")
            archive.writestr("Assets", b"file")
            archive.writestr("Assets/icon.png", b"image")
        self.add_blockmap()
        sha = hashlib.sha256(self.path.read_bytes()).hexdigest()
        self.assertEqual(verify_msix(receipt(sha), self.path, IDENTITY)["status"], "BLOCKED")

    def test_symlink_entry_blocks(self):
        import stat
        link = zipfile.ZipInfo("Assets/link")
        link.create_system = 3
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        with zipfile.ZipFile(self.path, "w") as archive:
            archive.writestr("[Content_Types].xml", CONTENT_TYPES)
            archive.writestr("AppxManifest.xml", MANIFEST)
            archive.writestr("Game/game.exe", b"MZgame")
            archive.writestr(link, "target")
        self.add_blockmap()
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
                    archive.writestr("[Content_Types].xml", CONTENT_TYPES)
                    archive.writestr("AppxManifest.xml", MANIFEST)
                    archive.writestr("Game/game.exe", b"MZgame")
                    archive.writestr(entry, b"not-a-regular-file")
                self.add_blockmap()
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
                    archive.writestr("[Content_Types].xml", CONTENT_TYPES)
                    archive.writestr("AppxManifest.xml", MANIFEST)
                    archive.writestr("Game/game.exe", b"MZgame")
                    archive.writestr(entry, b"" if filename.endswith("/") else b"data")
                self.add_blockmap()
                sha = hashlib.sha256(self.path.read_bytes()).hexdigest()
                result = verify_msix(receipt(sha), self.path, IDENTITY)
                self.assertEqual(result["status"], "BLOCKED", result)

    def test_zip_expansion_bomb_blocks(self):
        with zipfile.ZipFile(self.path, "w") as archive:
            archive.writestr("[Content_Types].xml", CONTENT_TYPES)
            archive.writestr("AppxManifest.xml", MANIFEST)
            archive.writestr("Game/game.exe", b"MZgame")
            archive.writestr("Assets/zeros.bin", b"\0" * (8 * 1024 * 1024),
                             compress_type=zipfile.ZIP_DEFLATED)
        self.add_blockmap()
        sha = hashlib.sha256(self.path.read_bytes()).hexdigest()
        self.assertEqual(verify_msix(receipt(sha), self.path, IDENTITY)["status"], "BLOCKED")

    def _package_with_explicit_directory(self):
        with zipfile.ZipFile(self.path, "w") as archive:
            archive.writestr("[Content_Types].xml", CONTENT_TYPES)
            archive.writestr("AppxManifest.xml", MANIFEST)
            archive.writestr("Game/", b"")
            archive.writestr("Game/game.exe", b"MZgame")
        self.add_blockmap()
        with zipfile.ZipFile(self.path) as archive:
            return archive.getinfo("Game/").header_offset

    def test_local_header_directory_filename_mismatch_blocks(self):
        # The central directory still says Game/, but the local header
        # says Same/. zipfile does not read directory payloads by default.
        offset = self._package_with_explicit_directory()
        raw = bytearray(self.path.read_bytes())
        self.assertEqual(raw[offset + 30:offset + 35], b"Game/")
        raw[offset + 30:offset + 35] = b"Same/"
        self.path.write_bytes(raw)
        sha = hashlib.sha256(raw).hexdigest()
        result = verify_msix(receipt(sha), self.path, IDENTITY)
        self.assertEqual(result["status"], "BLOCKED", result)
        self.assertFalse(result["artifact_bytes_verified"])

    def test_local_header_directory_method_mismatch_blocks(self):
        # A forged local compression method must not bypass the ZIP guard
        # merely because this directory has no file bytes to CRC-check.
        offset = self._package_with_explicit_directory()
        raw = bytearray(self.path.read_bytes())
        struct.pack_into("<H", raw, offset + 8, zipfile.ZIP_DEFLATED)
        self.path.write_bytes(raw)
        sha = hashlib.sha256(raw).hexdigest()
        result = verify_msix(receipt(sha), self.path, IDENTITY)
        self.assertEqual(result["status"], "BLOCKED", result)
        self.assertFalse(result["artifact_bytes_verified"])

    def test_normal_explicit_directory_entry_is_allowed(self):
        with zipfile.ZipFile(self.path, "w") as archive:
            archive.writestr("[Content_Types].xml", CONTENT_TYPES)
            archive.writestr("AppxManifest.xml", MANIFEST)
            archive.writestr("Game/", b"")
            archive.writestr("Game/game.exe", b"MZgame")
        self.add_blockmap()
        sha = hashlib.sha256(self.path.read_bytes()).hexdigest()
        self.assertEqual(verify_msix(receipt(sha), self.path, IDENTITY)["status"], "EVIDENCE_REVIEW")


    def test_missing_content_types_blocks(self):
        self.make_package(content_types=None)
        result = verify_msix(receipt(self.sha), self.path, IDENTITY)
        self.assertEqual(result["status"], "BLOCKED", result)
        self.assertFalse(result["content_types_verified"])

    def test_forged_content_types_namespace_blocks(self):
        forged = CONTENT_TYPES.replace(
            b"http://schemas.openxmlformats.org/package/2006/content-types", b"urn:forged")
        self.make_package(content_types=forged)
        self.assertEqual(verify_msix(receipt(self.sha), self.path, IDENTITY)["status"], "BLOCKED")

    def test_missing_content_type_for_executable_blocks(self):
        forged = CONTENT_TYPES.replace(b'Extension="exe"', b'Extension="unused"')
        self.make_package(content_types=forged)
        self.assertEqual(verify_msix(receipt(self.sha), self.path, IDENTITY)["status"], "BLOCKED")

    def test_wrong_manifest_or_blockmap_content_type_blocks(self):
        cases = (
            CONTENT_TYPES.replace(b"application/vnd.ms-appx.manifest+xml", b"application/xml"),
            CONTENT_TYPES.replace(b"application/vnd.ms-appx.blockmap+xml", b"application/xml"),
        )
        for forged in cases:
            with self.subTest(forged=forged):
                self.make_package(content_types=forged)
                self.assertEqual(verify_msix(receipt(self.sha), self.path, IDENTITY)["status"], "BLOCKED")

    def test_duplicate_content_type_extension_blocks(self):
        forged = CONTENT_TYPES.replace(
            b"</Types>", b'<Default Extension="EXE" ContentType="application/xml"/></Types>')
        self.make_package(content_types=forged)
        self.assertEqual(verify_msix(receipt(self.sha), self.path, IDENTITY)["status"], "BLOCKED")

    def test_content_type_unknown_override_blocks(self):
        forged = CONTENT_TYPES.replace(b'PartName="/AppxManifest.xml"',
                                       b'PartName="/Missing.xml"')
        self.make_package(content_types=forged)
        self.assertEqual(verify_msix(receipt(self.sha), self.path, IDENTITY)["status"], "BLOCKED")

    def test_content_type_encoded_separator_blocks(self):
        forged = CONTENT_TYPES.replace(b'PartName="/AppxManifest.xml"',
                                       b'PartName="/%2FAppxManifest.xml"')
        self.make_package(content_types=forged)
        self.assertEqual(verify_msix(receipt(self.sha), self.path, IDENTITY)["status"], "BLOCKED")

    def test_content_type_safe_percent_encoded_part_passes(self):
        safe = CONTENT_TYPES.replace(b'PartName="/AppxManifest.xml"',
                                     b'PartName="/%41ppxManifest.xml"')
        self.make_package(content_types=safe)
        result = verify_msix(receipt(self.sha), self.path, IDENTITY)
        self.assertEqual(result["status"], "EVIDENCE_REVIEW", result)
        self.assertTrue(result["content_types_verified"])



if __name__ == "__main__":
    unittest.main()
