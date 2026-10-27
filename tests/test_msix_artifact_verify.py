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
                 b'<Default Extension="pck" ContentType="application/octet-stream"/>'
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
                     include_blockmap=True, blockmap_mutator=None, content_types=CONTENT_TYPES,
                     pck=None):
        with zipfile.ZipFile(self.path, "w") as archive:
            if content_types is not None:
                archive.writestr("[Content_Types].xml", content_types)
            archive.writestr("AppxManifest.xml", manifest)
            archive.writestr("Assets/icon.png", b"not-a-real-image")
            if include_executable:
                archive.writestr("Game/game.exe", executable)
            if pck is not None:
                archive.writestr("Game/game.pck", pck)
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


    def test_makeappx_default_xml_manifest_mime_passes_synthetic(self):
        # Real MakeAppx 10.0.26100 uses Default(xml)=manifest MIME and
        # Override(AppxBlockMap.xml)=blockmap MIME.
        types = CONTENT_TYPES.replace(
            b'<Default Extension="xml" ContentType="application/xml"/>',
            b'<Default Extension="xml" ContentType="application/vnd.ms-appx.manifest+xml"/>',
        ).replace(
            b'<Override PartName="/AppxManifest.xml" ContentType="application/vnd.ms-appx.manifest+xml"/>',
            b'',
        )
        self.make_package(content_types=types)
        self.assertEqual(verify_msix(receipt(self.sha), self.path, IDENTITY)["status"],
                         "EVIDENCE_REVIEW")

    def test_makeappx_default_xml_without_blockmap_override_blocks(self):
        types = CONTENT_TYPES.replace(
            b'<Default Extension="xml" ContentType="application/xml"/>',
            b'<Default Extension="xml" ContentType="application/vnd.ms-appx.manifest+xml"/>',
        ).replace(
            b'<Override PartName="/AppxManifest.xml" ContentType="application/vnd.ms-appx.manifest+xml"/>',
            b'',
        ).replace(
            b'<Override PartName="/AppxBlockMap.xml" ContentType="application/vnd.ms-appx.blockmap+xml"/>',
            b'',
        )
        self.make_package(content_types=types)
        self.assertEqual(verify_msix(receipt(self.sha), self.path, IDENTITY)["status"],
                         "BLOCKED")

    def test_makeappx_b4_ignorable_namespace_passes_synthetic(self):
        def add_b4(root):
            root.set("IgnorableNamespaces", "b4")
            root.set("xmlns:b4", "http://schemas.microsoft.com/appx/2021/blockmap")
        self.make_package(blockmap_mutator=add_b4)
        self.assertEqual(verify_msix(receipt(self.sha), self.path, IDENTITY)["status"],
                         "EVIDENCE_REVIEW")

    def test_makeappx_b4_spoofed_namespace_blocks(self):
        def spoof(root):
            root.set("IgnorableNamespaces", "b4")
            root.set("xmlns:b4", "urn:forged")
        self.make_package(blockmap_mutator=spoof)
        self.assertEqual(verify_msix(receipt(self.sha), self.path, IDENTITY)["status"],
                         "BLOCKED")

    def test_makeappx_b4_whole_file_hash_passes_synthetic(self):
        b4 = "http://schemas.microsoft.com/appx/2021/blockmap"
        def add_hash(root):
            root.set("IgnorableNamespaces", "b4")
            root.set("xmlns:b4", b4)
            file_node = next(n for n in root if n.get("Name") == "Assets\\icon.png")
            ET.SubElement(file_node, f"{{{b4}}}FileHash", {
                "Hash": base64.b64encode(hashlib.sha256(b"not-a-real-image").digest()).decode()
            })
        self.make_package(blockmap_mutator=add_hash)
        self.assertEqual(verify_msix(receipt(self.sha), self.path, IDENTITY)["status"],
                         "EVIDENCE_REVIEW")

    def test_makeappx_b4_forged_whole_file_hash_blocks(self):
        b4 = "http://schemas.microsoft.com/appx/2021/blockmap"
        def forge_hash(root):
            root.set("IgnorableNamespaces", "b4")
            root.set("xmlns:b4", b4)
            file_node = next(n for n in root if n.get("Name") == "Assets\\icon.png")
            ET.SubElement(file_node, f"{{{b4}}}FileHash", {
                "Hash": base64.b64encode(b"\x00" * 32).decode()
            })
        self.make_package(blockmap_mutator=forge_hash)
        self.assertEqual(verify_msix(receipt(self.sha), self.path, IDENTITY)["status"],
                         "BLOCKED")

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

    def test_blockmap_unexpected_metadata_attributes_block(self):
        # Unknown XML metadata is not part of the declared BlockMap schema.
        # A matching digest must not make schema-invalid metadata acceptable.
        cases = ("root", "file", "block")
        for target in cases:
            with self.subTest(target=target):
                def tamper(root):
                    if target == "root":
                        node = root
                    elif target == "file":
                        node = root.find(f"{{{BLOCKMAP_NS}}}File")
                    else:
                        node = root.find(f"{{{BLOCKMAP_NS}}}File").find(
                            f"{{{BLOCKMAP_NS}}}Block")
                    node.set("Unexpected", "injected")
                self.make_package(blockmap_mutator=tamper)
                result = verify_msix(receipt(self.sha), self.path, IDENTITY)
                self.assertEqual(result["status"], "BLOCKED", result)

    def test_blockmap_nonwhitespace_xml_text_blocks(self):
        for target in ("root", "file", "block"):
            with self.subTest(target=target):
                def tamper(root):
                    if target == "root":
                        node = root
                    elif target == "file":
                        node = root.find(f"{{{BLOCKMAP_NS}}}File")
                    else:
                        node = root.find(f"{{{BLOCKMAP_NS}}}File").find(
                            f"{{{BLOCKMAP_NS}}}Block")
                    node.text = "unexpected payload text"
                self.make_package(blockmap_mutator=tamper)
                result = verify_msix(receipt(self.sha), self.path, IDENTITY)
                self.assertEqual(result["status"], "BLOCKED", result)

    def test_blockmap_whitespace_formatting_stays_accepted_synthetic(self):
        # MakeAppx-style pretty-printed XML may contain indentation. Reject
        # unexpected text without rejecting harmless XML whitespace.
        def pretty(root):
            root.text = "\n  "
            for file_node in root:
                file_node.text = "\n    "
                file_node.tail = "\n  "
                for block in file_node:
                    block.text = "\n    "
                    block.tail = "\n    "
        self.make_package(blockmap_mutator=pretty)
        result = verify_msix(receipt(self.sha), self.path, IDENTITY)
        self.assertEqual(result["status"], "EVIDENCE_REVIEW", result)

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


    def test_independently_pinned_external_godot_exe_pck_hashes_match(self):
        exe = b"MZmock-game"
        pck = b"GDPCmock-resources"
        self.make_package(executable=exe, pck=pck)
        evidence = {
            "exe_path": "Game/game.exe", "exe_sha256": hashlib.sha256(exe).hexdigest(),
            "embed_pck": False, "pck_path": "Game/game.pck",
            "pck_sha256": hashlib.sha256(pck).hexdigest(),
        }
        result = verify_msix(receipt(self.sha), self.path, IDENTITY, evidence)
        self.assertEqual(result["status"], "EVIDENCE_REVIEW", result)
        self.assertTrue(result["godot_export_bytes_matched"])
        self.assertFalse(result["github_provenance_verified"])

    def test_missing_external_godot_pck_blocks_even_when_msix_hash_matches(self):
        exe = b"MZmock-game"
        evidence = {
            "exe_path": "Game/game.exe", "exe_sha256": hashlib.sha256(exe).hexdigest(),
            "embed_pck": False, "pck_path": "Game/game.pck",
            "pck_sha256": hashlib.sha256(b"GDPCmock-resources").hexdigest(),
        }
        result = verify_msix(receipt(self.sha), self.path, IDENTITY, evidence)
        self.assertEqual(result["status"], "BLOCKED", result)
        self.assertFalse(result["godot_export_bytes_matched"])

    def test_repacked_tampered_pck_rejected_against_independent_export_hash(self):
        exe = b"MZmock-game"
        original = b"GDPCoriginal"
        self.make_package(executable=exe, pck=b"GDPCtampered")
        evidence = {
            "exe_path": "Game/game.exe", "exe_sha256": hashlib.sha256(exe).hexdigest(),
            "embed_pck": False, "pck_path": "Game/game.pck",
            "pck_sha256": hashlib.sha256(original).hexdigest(),
        }
        result = verify_msix(receipt(self.sha), self.path, IDENTITY, evidence)
        self.assertEqual(result["status"], "BLOCKED", result)
        self.assertIn("payload SHA-256 mismatch", result["errors"][0])

    def test_embedded_godot_pck_exe_only_hash_match(self):
        exe = b"MZmock-game"
        evidence = {"exe_path": "Game/game.exe",
                    "exe_sha256": hashlib.sha256(exe).hexdigest(),
                    "embed_pck": True}
        result = verify_msix(receipt(self.sha), self.path, IDENTITY, evidence)
        self.assertEqual(result["status"], "EVIDENCE_REVIEW", result)
        self.assertTrue(result["godot_export_bytes_matched"])

    def test_godot_export_manifest_path_mismatch_blocks(self):
        exe = b"MZmock-game"
        evidence = {"exe_path": "Game/other.exe",
                    "exe_sha256": hashlib.sha256(exe).hexdigest(),
                    "embed_pck": True}
        self.assertEqual(
            verify_msix(receipt(self.sha), self.path, IDENTITY, evidence)["status"],
            "BLOCKED")

    def test_godot_export_evidence_is_optional_but_never_claimed_without_it(self):
        result = verify_msix(receipt(self.sha), self.path, IDENTITY)
        self.assertEqual(result["status"], "EVIDENCE_REVIEW")
        self.assertFalse(result["godot_export_bytes_matched"])

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

    def test_local_header_crc_and_size_disagreement_blocks(self):
        # zipfile normally trusts the central directory CRC and sizes; a
        # recomputed outer SHA does not authenticate contradictory LFH fields.
        for field, field_offset in (("crc", 14), ("compressed", 18), ("uncompressed", 22)):
            with self.subTest(field=field):
                self.make_package()
                with zipfile.ZipFile(self.path) as archive:
                    header_offset = archive.getinfo("Game/game.exe").header_offset
                raw = bytearray(self.path.read_bytes())
                offset = header_offset + field_offset
                original = struct.unpack_from("<I", raw, offset)[0]
                struct.pack_into("<I", raw, offset, (original + 1) & 0xFFFFFFFF)
                self.path.write_bytes(raw)
                digest = hashlib.sha256(raw).hexdigest()
                result = verify_msix(receipt(digest), self.path, IDENTITY)
                self.assertEqual(result["status"], "BLOCKED", result)
                self.assertFalse(result["artifact_bytes_verified"])


    def _make_zip64_local_size_package(self):
        # force_zip64 writes genuine ZIP64 size sentinels/extra fields even
        # for a tiny member. This is an offline fixture, not MakeAppx output.
        with zipfile.ZipFile(self.path, "w") as archive:
            archive.writestr("[Content_Types].xml", CONTENT_TYPES)
            archive.writestr("AppxManifest.xml", MANIFEST)
            archive.writestr("Assets/icon.png", b"not-a-real-image")
            with archive.open("Game/game.exe", "w", force_zip64=True) as stream:
                stream.write(b"MZmock-game")
        self.add_blockmap()
        with zipfile.ZipFile(self.path) as archive:
            offset = archive.getinfo("Game/game.exe").header_offset
        raw = bytearray(self.path.read_bytes())
        self.assertEqual(struct.unpack_from("<II", raw, offset + 18),
                         (0xFFFFFFFF, 0xFFFFFFFF))
        name_length, extra_length = struct.unpack_from("<HH", raw, offset + 26)
        extra_start = offset + 30 + name_length
        self.assertGreaterEqual(extra_length, 20)
        self.assertEqual(struct.unpack_from("<HH", raw, extra_start), (1, 16))
        return raw, extra_start

    def test_valid_zip64_local_sizes_allowed(self):
        self._make_zip64_local_size_package()
        digest = hashlib.sha256(self.path.read_bytes()).hexdigest()
        result = verify_msix(receipt(digest), self.path, IDENTITY)
        self.assertEqual(result["status"], "EVIDENCE_REVIEW", result)

    def test_forged_zip64_local_sizes_blocked(self):
        # Python zipfile trusts central-directory sizes and still reads the
        # member when the local ZIP64 extra sizes are forged.
        for variant in ("uncompressed", "compressed", "missing_extra"):
            with self.subTest(variant=variant):
                raw, extra_start = self._make_zip64_local_size_package()
                if variant == "missing_extra":
                    struct.pack_into("<H", raw, extra_start, 2)
                else:
                    field_offset = extra_start + (4 if variant == "uncompressed" else 12)
                    current = struct.unpack_from("<Q", raw, field_offset)[0]
                    struct.pack_into("<Q", raw, field_offset, current + 1)
                self.path.write_bytes(raw)
                with zipfile.ZipFile(self.path) as archive:
                    self.assertEqual(archive.read("Game/game.exe"), b"MZmock-game")
                digest = hashlib.sha256(raw).hexdigest()
                result = verify_msix(receipt(digest), self.path, IDENTITY)
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




    def _make_data_descriptor_package(self, force_zip64=False, signatureless=False):
        # Non-seekable output forces GPBF bit 3 and a real data descriptor.
        # This fixture is generated by Python zipfile, not by MakeAppx.
        import io

        class NonSeekable(io.BytesIO):
            def seek(self, *args, **kwargs):
                raise OSError("stream is not seekable")

        stream = NonSeekable()
        with zipfile.ZipFile(stream, "w") as archive:
            archive.writestr("[Content_Types].xml", CONTENT_TYPES)
            archive.writestr("AppxManifest.xml", MANIFEST)
            archive.writestr("Assets/icon.png", b"not-a-real-image")
            with archive.open("Game/game.exe", "w",
                              force_zip64=force_zip64) as output:
                output.write(b"MZmock-game")
        self.path.write_bytes(stream.getvalue())
        if signatureless:
            # Remove the optional signature from the last member's descriptor.
            # Only the EOCD central-directory offset needs adjustment.
            with zipfile.ZipFile(self.path) as archive:
                info = archive.getinfo("Game/game.exe")
                raw = bytearray(self.path.read_bytes())
                name_length, extra_length = struct.unpack_from("<HH", raw, info.header_offset + 26)
                dd_offset = info.header_offset + 30 + name_length + extra_length + info.compress_size
            self.assertEqual(raw[dd_offset:dd_offset + 4], bytes.fromhex("504b0708"))
            del raw[dd_offset:dd_offset + 4]
            eocd = raw.rfind(bytes.fromhex("504b0506"))
            self.assertGreaterEqual(eocd, 0)
            central_offset = struct.unpack_from("<I", raw, eocd + 16)[0]
            struct.pack_into("<I", raw, eocd + 16, central_offset - 4)
            self.path.write_bytes(raw)
        self.add_blockmap()
        with zipfile.ZipFile(self.path) as archive:
            info = archive.getinfo("Game/game.exe")
            self.assertTrue(info.flag_bits & 0x0008)
            self.assertEqual(archive.read(info), b"MZmock-game")
            offset = info.header_offset
            raw = self.path.read_bytes()
            name_length, extra_length = struct.unpack_from("<HH", raw, offset + 26)
            descriptor_offset = offset + 30 + name_length + extra_length + info.compress_size
            if signatureless:
                self.assertNotEqual(raw[descriptor_offset:descriptor_offset + 4], bytes.fromhex("504b0708"))
            else:
                self.assertEqual(raw[descriptor_offset:descriptor_offset + 4], bytes.fromhex("504b0708"))
        return descriptor_offset

    def test_data_descriptor_32_and_zip64_pass_synthetic(self):
        for force_zip64 in (False, True):
            with self.subTest(force_zip64=force_zip64):
                self._make_data_descriptor_package(force_zip64)
                digest = hashlib.sha256(self.path.read_bytes()).hexdigest()
                result = verify_msix(receipt(digest), self.path, IDENTITY)
                self.assertEqual(result["status"], "EVIDENCE_REVIEW", result)

    def test_signatureless_data_descriptor_32_and_zip64_pass_synthetic(self):
        # The descriptor signature is optional; exercise actual unsigned bytes.
        for force_zip64 in (False, True):
            with self.subTest(force_zip64=force_zip64):
                self._make_data_descriptor_package(force_zip64, signatureless=True)
                digest = hashlib.sha256(self.path.read_bytes()).hexdigest()
                result = verify_msix(receipt(digest), self.path, IDENTITY)
                self.assertEqual(result["status"], "EVIDENCE_REVIEW", result)

    def test_data_descriptor_local_header_forgery_blocks(self):
        # GPBF bit 3 requires zero CRC and zero/ZIP64-sentinel local sizes.
        # Python zipfile still reads the payload when those fields are forged.
        for force_zip64 in (False, True):
            for field, position in (("crc", 14), ("compressed", 18),
                                    ("uncompressed", 22)):
                with self.subTest(force_zip64=force_zip64, field=field):
                    self._make_data_descriptor_package(force_zip64)
                    raw = bytearray(self.path.read_bytes())
                    with zipfile.ZipFile(self.path) as archive:
                        info = archive.getinfo("Game/game.exe")
                    struct.pack_into("<I", raw, info.header_offset + position, 1)
                    self.path.write_bytes(raw)
                    with zipfile.ZipFile(self.path) as archive:
                        self.assertEqual(archive.read("Game/game.exe"), b"MZmock-game")
                    digest = hashlib.sha256(raw).hexdigest()
                    result = verify_msix(receipt(digest), self.path, IDENTITY)
                    self.assertEqual(result["status"], "BLOCKED", result)
                    self.assertFalse(result["artifact_bytes_verified"])

    def test_forged_data_descriptor_crc_and_sizes_block(self):
        # The member remains readable by zipfile: it trusts the central
        # directory and does not compare the descriptor's claimed metadata.
        for force_zip64 in (False, True):
            for field in ("crc", "compressed", "uncompressed"):
                with self.subTest(force_zip64=force_zip64, field=field):
                    offset = self._make_data_descriptor_package(force_zip64)
                    raw = bytearray(self.path.read_bytes())
                    size_width = 8 if force_zip64 else 4
                    field_offset = {"crc": 4, "compressed": 8,
                                    "uncompressed": 8 + size_width}[field]
                    position = offset + field_offset
                    current = int.from_bytes(raw[position:position + (4 if field == "crc" else size_width)], "little")
                    width = 4 if field == "crc" else size_width
                    raw[position:position + width] = ((current + 1) % (1 << (8 * width))).to_bytes(width, "little")
                    self.path.write_bytes(raw)
                    with zipfile.ZipFile(self.path) as archive:
                        self.assertEqual(archive.read("Game/game.exe"), b"MZmock-game")
                    digest = hashlib.sha256(raw).hexdigest()
                    result = verify_msix(receipt(digest), self.path, IDENTITY)
                    self.assertEqual(result["status"], "BLOCKED", result)
                    self.assertFalse(result["artifact_bytes_verified"])


if __name__ == "__main__":
    unittest.main()
