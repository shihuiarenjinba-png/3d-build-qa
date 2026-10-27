"""Bounded Open Packaging Conventions content-type checks for 3D MSIX QA.

This verifies internal declarations, not signatures, installability, or Store approval.
The ZIP path and CRC guards must run before this function.
"""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from urllib.parse import unquote
import zipfile

NS = "http://schemas.openxmlformats.org/package/2006/content-types"
MAX_CONTENT_TYPES_BYTES = 1024 * 1024
MANIFEST_TYPE = "application/vnd.ms-appx.manifest+xml"
BLOCKMAP_TYPE = "application/vnd.ms-appx.blockmap+xml"
EXTENSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]*$")
PERCENT = re.compile(r"%(?![0-9a-fA-F]{2})")
ENCODED_SEPARATOR = re.compile(r"%(?:2f|5c|00)", re.I)


def validate_content_types(archive: zipfile.ZipFile) -> None:
    """Reject missing, spoofed, ambiguous or incomplete OPC declarations."""
    entries = {info.filename.casefold(): info.filename for info in archive.infolist()
               if not info.is_dir()}
    info = next((item for item in archive.infolist()
                 if item.filename == "[Content_Types].xml"), None)
    if info is None or not 0 < info.file_size <= MAX_CONTENT_TYPES_BYTES:
        raise ValueError("root [Content_Types].xml missing or out of range")
    with archive.open(info) as stream:
        root = ET.fromstring(stream.read(MAX_CONTENT_TYPES_BYTES + 1))
    if root.tag != f"{{{NS}}}Types" or root.attrib:
        raise ValueError("invalid [Content_Types].xml root")
    defaults: dict[str, str] = {}
    overrides: dict[str, str] = {}
    for node in root:
        if list(node) or (node.text or "").strip():
            raise ValueError("nested content type declaration")
        if node.tag == f"{{{NS}}}Default":
            if set(node.attrib) != {"Extension", "ContentType"}:
                raise ValueError("invalid content type Default attributes")
            extension = node.get("Extension", "")
            if not EXTENSION.fullmatch(extension):
                raise ValueError("invalid content type extension")
            key = extension.casefold()
            if key in defaults:
                raise ValueError("duplicate content type extension")
            defaults[key] = node.get("ContentType", "")
            value = defaults[key]
        elif node.tag == f"{{{NS}}}Override":
            if set(node.attrib) != {"PartName", "ContentType"}:
                raise ValueError("invalid content type Override attributes")
            part = node.get("PartName", "")
            if not part.startswith("/") or part.startswith("//") or PERCENT.search(part) or ENCODED_SEPARATOR.search(part):
                raise ValueError("invalid content type part name")
            decoded = unquote(part[1:], encoding="utf-8", errors="strict")
            key = decoded.casefold()
            if key not in entries or key == "[content_types].xml":
                raise ValueError("content type override refers to unknown part")
            if key in overrides:
                raise ValueError("duplicate content type override")
            overrides[key] = node.get("ContentType", "")
            value = overrides[key]
        else:
            raise ValueError("unexpected content type declaration")
        if not value or value.strip() != value or any(ch.isspace() for ch in value) or "/" not in value:
            raise ValueError("invalid content type MIME value")
    for key, original in entries.items():
        if key == "[content_types].xml":
            continue
        extension = original.rsplit("/", 1)[-1].rsplit(".", 1)[-1].casefold()
        if key not in overrides and extension not in defaults:
            raise ValueError("package part lacks content type")
    if overrides.get("appxmanifest.xml") != MANIFEST_TYPE:
        raise ValueError("missing or incorrect AppxManifest content type")
    if overrides.get("appxblockmap.xml") != BLOCKMAP_TYPE:
        raise ValueError("missing or incorrect AppxBlockMap content type")
