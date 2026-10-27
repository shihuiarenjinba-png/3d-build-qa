"""Windows SDK MakeAppx byte-compatibility smoke fixture, not a product."""
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import struct
import zipfile
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from msix_artifact_verify import verify_msix

MANIFEST = r"""<?xml version="1.0" encoding="utf-8"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"
 xmlns:uap="http://schemas.microsoft.com/appx/manifest/uap/windows10"
 xmlns:rescap="http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities"
 IgnorableNamespaces="uap rescap">
 <Identity Name="Example.ThreeD.Fixture" Publisher="CN=Offline QA Fixture"
  Version="1.0.0.0" ProcessorArchitecture="x64"/>
 <Properties><DisplayName>Offline 3D QA Fixture</DisplayName>
  <PublisherDisplayName>Offline QA Only</PublisherDisplayName>
  <Logo>Assets\Logo.png</Logo></Properties>
 <Dependencies><TargetDeviceFamily Name="Windows.Desktop"
  MinVersion="10.0.17763.0" MaxVersionTested="10.0.22621.0"/></Dependencies>
 <Resources><Resource Language="en-us"/></Resources>
 <Applications><Application Id="Game" Executable="Game\game.exe"
  EntryPoint="Windows.FullTrustApplication">
  <uap:VisualElements DisplayName="Offline 3D QA Fixture"
   Description="Non-product MakeAppx contract fixture"
   BackgroundColor="transparent" Square150x150Logo="Assets\Logo.png"
   Square44x44Logo="Assets\Logo.png"/>
 </Application></Applications>
 <Capabilities><rescap:Capability Name="runFullTrust"/></Capabilities>
</Package>
"""
PNG = base64.b64decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAusB9Y9P6GQAAAAASUVORK5CYII=")

def main():
    if os.name != "nt":
        raise RuntimeError("Requires actual Windows SDK MakeAppx")
    sdk = Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")) / "Windows Kits" / "10" / "bin"
    tools = sorted(sdk.glob("*/x64/makeappx.exe"), reverse=True)
    if not tools:
        raise RuntimeError("Windows SDK x64 MakeAppx.exe unavailable")
    out = Path(os.environ.get("RUNNER_TEMP", tempfile.gettempdir())) / "3d-makeappx-fixture"
    stage = out / "staging"
    (stage / "Game").mkdir(parents=True, exist_ok=True)
    (stage / "Assets").mkdir(parents=True, exist_ok=True)
    (stage / "AppxManifest.xml").write_text(MANIFEST, encoding="utf-8")
    (stage / "Assets" / "Logo.png").write_bytes(PNG)
    # >128 KiB deterministic, high-entropy payload exercises three real
    # MakeAppx 64-KiB BlockMap blocks without a compression-bomb fixture.
    (stage / "Assets" / "payload.bin").write_bytes(b"".join(
        hashlib.sha256(i.to_bytes(4, "little")).digest() for i in range(4100)))
    # MZ-shaped fixture only: no application launch, no Microsoft binary redistribution.
    # These are synthetic bytes, not a real Godot export. Pin their digests
    # independently of the MSIX container to exercise the payload contract.
    fake_exe = b"MZoffline-fixture-not-runnable"
    fake_pck = b"GDPCoffline-pck-fixture-not-a-playable-project"
    (stage / "Game" / "game.exe").write_bytes(fake_exe)
    (stage / "Game" / "game.pck").write_bytes(fake_pck)
    expected_export = {
        "exe_path": "Game/game.exe", "exe_sha256": hashlib.sha256(fake_exe).hexdigest(),
        "embed_pck": False, "pck_path": "Game/game.pck",
        "pck_sha256": hashlib.sha256(fake_pck).hexdigest(),
    }
    package = out / "offline-3d-fixture.msix"
    subprocess.run([str(tools[0]), "pack", "/d", str(stage), "/p", str(package), "/o"], check=True)
    digest = hashlib.sha256(package.read_bytes()).hexdigest()
    receipt = {
        "schema_version": "1.0", "source_factory": "3d-game-factory",
        "request_id": "offline-makeappx-fixture", "repository_full_name": "offline/fixture",
        "source_sha": "0" * 40, "package_sha256": digest,
        "windows_run_id": "fixture-only", "runner_evidence_id": "fixture-only",
        "windows_launch": False,
        "tests": {"executed": 0, "failed": 0, "skipped": 0, "crashes": 0},
    }
    # Bypass only the launch receipt gate to test actual MakeAppx bytes.
    # This must never be interpreted as product E2E or Partner Center evidence.
    with patch("msix_artifact_verify.inspect", return_value={"status": "EVIDENCE_REVIEW", "errors": []}):
        result = verify_msix(receipt, package, expected_godot_export=expected_export)
    # Corrupt an actual MakeAppx ZIP64 descriptor while keeping the central
    # directory/payload intact; recompute receipt SHA so the byte guard itself
    # (not just package digest) must reject it.
    with zipfile.ZipFile(package) as archive:
        member = archive.getinfo("Game/game.exe")
        with package.open("rb") as raw:
            raw.seek(member.header_offset + 26)
            name_len, extra_len = struct.unpack("<HH", raw.read(4))
            descriptor_at = member.header_offset + 30 + name_len + extra_len + member.compress_size
    forged = bytearray(package.read_bytes())
    assert forged[descriptor_at:descriptor_at + 4] == b"PK\x07\x08"
    forged[descriptor_at + 8] ^= 1  # 64-bit compressed-size low byte
    bad_package = out / "forged-descriptor.msix"
    bad_package.write_bytes(forged)
    bad_receipt = dict(receipt, package_sha256=hashlib.sha256(forged).hexdigest())
    with patch("msix_artifact_verify.inspect", return_value={"status": "EVIDENCE_REVIEW", "errors": []}):
        rejected = verify_msix(bad_receipt, bad_package)
    bad_package.unlink()
    assert rejected["status"] == "BLOCKED", rejected
    assert any("descriptor" in error.lower() for error in rejected["errors"]), rejected
    evidence = {
        "kind": "UNSIGNED_SYNTHETIC_MAKEAPPX_FIXTURE_NOT_PRODUCT",
        "makeappx_path": str(tools[0]), "package_sha256": digest,
        "package_bytes": package.stat().st_size, "verification": result,
        "forged_makeappx_descriptor_rejected": True,
        "synthetic_godot_exe_pck_hash_contract_checked": True,
        "official_identity": None, "windows_gpu_gui_tested": False,
        "store_submission_allowed": False,
    }
    (out / "fixture-evidence.json").write_text(json.dumps(evidence, indent=2), encoding="utf-8")
    print(json.dumps(evidence, indent=2))
    if result["status"] != "HOLD":
        with zipfile.ZipFile(package) as archive, package.open("rb") as raw:
            print("MAKEAPPX_CONTENT_TYPES", archive.read("[Content_Types].xml").decode())
            print("MAKEAPPX_BLOCKMAP", archive.read("AppxBlockMap.xml").decode())
            for info in archive.infolist():
                raw.seek(info.header_offset)
                header = raw.read(30)
                flags = struct.unpack_from("<H", header, 6)[0]
                crc, packed, unpacked = struct.unpack_from("<III", header, 14)
                name_len, extra_len = struct.unpack_from("<HH", header, 26)
                data_offset = info.header_offset + 30 + name_len + extra_len
                raw.seek(data_offset)
                compressed_head = raw.read(8).hex()
                raw.seek(data_offset + max(0, info.compress_size - 8))
                compressed_tail = raw.read(8).hex()
                offset = data_offset + info.compress_size
                raw.seek(offset)
                print("ZIP_DESCRIPTOR_DIAGNOSTIC", json.dumps({
                    "name": info.filename, "flags": flags, "local_crc": crc,
                    "local_compressed": packed, "local_uncompressed": unpacked,
                    "central_crc": info.CRC, "central_compressed": info.compress_size,
                    "central_uncompressed": info.file_size,
                    "compressed_head": compressed_head,
                    "compressed_tail": compressed_tail,
                    "descriptor_hex": raw.read(32).hex(),
                }))
    assert result["status"] == "HOLD", result
    for key in ("artifact_bytes_verified", "content_types_verified",
                "blockmap_verified", "payload_executables_verified",
                "godot_export_bytes_matched"):
        assert result[key] is True, (key, result)
    for key in ("official_identity_verified", "windows_launch_verified",
                "signature_verified", "submission_authorized"):
        assert result[key] is False, (key, result)

if __name__ == "__main__":
    main()
