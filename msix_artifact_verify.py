"""Fail-closed MSIX byte/manifest inspection for the 3D Windows QA handoff.

This does NOT verify GitHub run provenance, Microsoft Store registration,
Windows launch, graphics quality, signing trust or the truth of a receipt.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import xml.etree.ElementTree as ET
import zipfile

from qa_gate import inspect
from msix_zip_guard import validate_archive_paths

SHA256 = re.compile(r"^[a-fA-F0-9]{64}$")
MAX_PACKAGE_BYTES = 8 * 1024**3
MAX_MANIFEST_BYTES = 512 * 1024


def verify_msix(receipt: dict, package: Path, approved_identity: dict | None = None) -> dict:
    """Inspect actual bytes without extracting archive entries or trusting receipt claims."""
    result = {
        "status": "BLOCKED", "errors": [], "artifact_bytes_verified": False,
        "manifest_identity_matched": False, "payload_executables_verified": False,
        "official_identity_verified": False,
        "github_provenance_verified": False, "windows_launch_verified": False,
        "signature_verified": False, "submission_authorized": False,
    }
    shape = inspect(receipt)
    if shape["status"] != "EVIDENCE_REVIEW":
        result["status"] = shape["status"]
        result["errors"] = shape["errors"]
        return result
    if not isinstance(package, Path) or package.suffix.lower() != ".msix":
        result["errors"].append("expected a .msix file, not a bundle or upload archive")
        return result
    try:
        if not package.is_file() or package.is_symlink():
            raise ValueError("package is missing or is a symlink")
        size = package.stat().st_size
        if not 0 < size <= MAX_PACKAGE_BYTES:
            raise ValueError("package size out of allowed range")
        digest = hashlib.sha256()
        with package.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
        claimed = receipt.get("package_sha256")
        if not isinstance(claimed, str) or not SHA256.fullmatch(claimed):
            raise ValueError("invalid receipt package SHA-256")
        if digest.hexdigest() != claimed.lower():
            raise ValueError("package SHA-256 differs from receipt")
        with zipfile.ZipFile(package) as archive:
            validate_archive_paths(archive)
            names = archive.namelist()
            if names.count("AppxManifest.xml") != 1:
                raise ValueError("exactly one root AppxManifest.xml required")
            manifest_info = archive.getinfo("AppxManifest.xml")
            if not 0 < manifest_info.file_size <= MAX_MANIFEST_BYTES:
                raise ValueError("AppxManifest.xml size out of range")
            with archive.open(manifest_info) as stream:
                manifest = stream.read(MAX_MANIFEST_BYTES + 1)
            root = ET.fromstring(manifest)
            groups = [node for node in root if node.tag.split("}")[-1] == "Applications"]
            if len(groups) != 1:
                raise ValueError("exactly one Applications element required")
            applications = [node for node in groups[0] if node.tag.split("}")[-1] == "Application"]
            if not applications:
                raise ValueError("MSIX declares no application executable")
            for application in applications:
                executable = application.attrib.get("Executable", "")
                normalized = executable.replace("\\", "/")
                components = normalized.split("/")
                if (not normalized.lower().endswith(".exe") or
                        any(not part or part in (".", "..") or ":" in part
                            for part in components)):
                    raise ValueError("unsafe or invalid application executable path")
                matches = [info for info in archive.infolist()
                           if info.filename.casefold() == normalized.casefold()]
                if len(matches) != 1:
                    raise ValueError("declared application executable missing or duplicated")
                info = matches[0]
                if (info.is_dir() or info.file_size < 2 or
                        (info.external_attr >> 16) & 0o170000 == 0o120000):
                    raise ValueError("application executable empty or a symlink")
                with archive.open(info) as stream:
                    if stream.read(2) != b"MZ":
                        raise ValueError("application executable lacks MZ header")
            result["payload_executables_verified"] = True
        if root.tag.split("}")[-1] != "Package":
            raise ValueError("invalid MSIX package manifest root")
        identities = [node for node in root if node.tag.split("}")[-1] == "Identity"]
        if len(identities) != 1:
            raise ValueError("exactly one manifest Identity required")
        actual = identities[0].attrib
        for field in ("Name", "Publisher", "Version"):
            if not actual.get(field):
                raise ValueError("missing manifest Identity " + field)
        result["artifact_bytes_verified"] = True
        result["manifest_identity"] = {k.lower(): actual[k] for k in ("Name", "Publisher", "Version")}
        if approved_identity is None:
            result["status"] = "HOLD"
            result["errors"] = ["approved Partner Center identity not supplied"]
            return result
        if (not isinstance(approved_identity, dict)
                or approved_identity.get("reviewed") is not True
                or approved_identity.get("source") != "partner_center"):
            raise ValueError("unreviewed Partner Center identity record")
        for key in ("name", "publisher", "version", "store_id"):
            if not isinstance(approved_identity.get(key), str) or not approved_identity[key]:
                raise ValueError("approved identity missing " + key)
        if any(actual[field] != approved_identity[field.lower()]
               for field in ("Name", "Publisher", "Version")):
            raise ValueError("MSIX manifest identity differs from approved record")
        result["manifest_identity_matched"] = True
        result["status"] = "EVIDENCE_REVIEW"
        return result
    except (OSError, ValueError, zipfile.BadZipFile, ET.ParseError, RuntimeError) as exc:
        result["errors"] = [type(exc).__name__ + ": " + str(exc)[:180]]
        return result


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receipt", required=True, type=Path)
    parser.add_argument("--package", required=True, type=Path)
    parser.add_argument("--approved-identity", type=Path)
    args = parser.parse_args(argv)
    try:
        receipt = json.loads(args.receipt.read_text(encoding="utf-8"))
        identity = (json.loads(args.approved_identity.read_text(encoding="utf-8"))
                    if args.approved_identity else None)
        result = verify_msix(receipt, args.package, identity)
    except (OSError, ValueError) as exc:
        result = {"status": "BLOCKED", "errors": [type(exc).__name__],
                  "artifact_bytes_verified": False, "submission_authorized": False}
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["status"] == "EVIDENCE_REVIEW" else 2


if __name__ == "__main__":
    raise SystemExit(main())
