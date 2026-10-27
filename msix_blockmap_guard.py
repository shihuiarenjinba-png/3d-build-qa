"""Bounded, fail-closed AppxBlockMap byte integrity checks for MSIX QA.

The hashes cover uncompressed 64-KiB file blocks, not the signature or
authenticated provenance. This does not validate Authenticode or installability.
See Microsoft's Block, File and BlockMap schema documentation.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import struct
import xml.etree.ElementTree as ET
import zipfile

BLOCK_SIZE = 65536
MAX_BLOCKMAP_BYTES = 32 * 1024 * 1024
NS = "http://schemas.microsoft.com/appx/2010/blockmap"
HASH_METHOD = "http://www.w3.org/2001/04/xmlenc#sha256"
# MSIX footprint/signing metadata is not described as ordinary content files.
EXCLUDED = {
    "appxblockmap.xml", "[content_types].xml", "appxsignature.p7x",
    "appxmetadata/codeintegrity.cat",
}


def _nonnegative_integer(value: str | None, label: str) -> int:
    if not isinstance(value, str) or not value.isascii() or not value.isdecimal():
        raise ValueError("invalid AppxBlockMap " + label)
    return int(value)


def _local_header_size(archive: zipfile.ZipFile, info: zipfile.ZipInfo) -> int:
    # ZIP LFH: fixed 30-byte header followed by name and extra field.
    archive.fp.seek(info.header_offset)
    header = archive.fp.read(30)
    if len(header) != 30 or header[:4] != b"PK\x03\x04":
        raise ValueError("invalid ZIP local file header")
    name_length, extra_length = struct.unpack_from("<HH", header, 26)
    return 30 + name_length + extra_length


def validate_blockmap(archive: zipfile.ZipFile) -> None:
    """Verify exact non-footprint file coverage and each uncompressed block hash.

    The surrounding ZIP guard must run first to reject unsafe paths and
    collisions; this function additionally rejects block-map omissions,
    duplicate entries, wrong sizes and mismatched SHA-256 blocks.
    """
    names = {info.filename.casefold(): info for info in archive.infolist()
             if not info.is_dir()}
    info = names.get("appxblockmap.xml")
    if info is None or info.filename != "AppxBlockMap.xml":
        raise ValueError("root AppxBlockMap.xml required")
    if not 0 < info.file_size <= MAX_BLOCKMAP_BYTES:
        raise ValueError("AppxBlockMap.xml size out of range")
    with archive.open(info) as stream:
        root = ET.fromstring(stream.read(MAX_BLOCKMAP_BYTES + 1))
    if root.tag != f"{{{NS}}}BlockMap" or root.get("HashMethod") != HASH_METHOD:
        raise ValueError("invalid AppxBlockMap namespace or hash method")
    if set(root.attrib) != {"HashMethod"} or (root.text or "").strip() or (root.tail or "").strip():
        raise ValueError("unexpected AppxBlockMap root metadata")
    expected = set(names) - EXCLUDED
    seen: set[str] = set()
    for file_node in root:
        if file_node.tag != f"{{{NS}}}File":
            raise ValueError("unexpected AppxBlockMap child")
        if (set(file_node.attrib) != {"Name", "Size", "LfhSize"} or
                (file_node.text or "").strip() or (file_node.tail or "").strip()):
            raise ValueError("unexpected AppxBlockMap File metadata")
        raw_name = file_node.get("Name")
        if not raw_name or raw_name.startswith(("/", "\\")):
            raise ValueError("invalid AppxBlockMap file name")
        name = raw_name.replace("\\", "/")
        key = name.casefold()
        if key not in expected or key in seen:
            raise ValueError("unknown or duplicate AppxBlockMap file")
        seen.add(key)
        entry = names[key]
        # BlockMap uses Windows backslashes; a normalized lookup alone would
        # accept forward slashes and case aliases not present in the ZIP.
        # Require the exact ZIP member spelling before trusting its hashes.
        if raw_name != entry.filename.replace("/", "\\"):
            raise ValueError("noncanonical AppxBlockMap file name")
        size = _nonnegative_integer(file_node.get("Size"), "file Size")
        if size != entry.file_size:
            raise ValueError("AppxBlockMap file Size mismatch")
        lfh_size = _nonnegative_integer(file_node.get("LfhSize"), "LfhSize")
        if lfh_size != _local_header_size(archive, entry):
            raise ValueError("AppxBlockMap local header size mismatch")
        blocks = list(file_node)
        count = (size + BLOCK_SIZE - 1) // BLOCK_SIZE
        if len(blocks) != count:
            raise ValueError("AppxBlockMap block count mismatch")
        compressed_total = 0
        with archive.open(entry) as stream:
            for index, block in enumerate(blocks):
                if block.tag != f"{{{NS}}}Block" or list(block):
                    raise ValueError("invalid AppxBlockMap Block element")
                expected_attrs = ({"Hash", "Size"} if entry.compress_type == zipfile.ZIP_DEFLATED
                                  else {"Hash"})
                if (set(block.attrib) != expected_attrs or
                        (block.text or "").strip() or (block.tail or "").strip()):
                    raise ValueError("unexpected AppxBlockMap Block metadata")
                length = min(BLOCK_SIZE, size - index * BLOCK_SIZE)
                data = stream.read(length)
                if len(data) != length:
                    raise ValueError("AppxBlockMap truncated payload block")
                encoded = block.get("Hash")
                try:
                    expected_hash = base64.b64decode(encoded, validate=True)
                except (TypeError, ValueError, binascii.Error):
                    raise ValueError("invalid AppxBlockMap block hash") from None
                if len(expected_hash) != 32 or hashlib.sha256(data).digest() != expected_hash:
                    raise ValueError("AppxBlockMap block SHA-256 mismatch")
                stored_size = block.get("Size")
                if entry.compress_type == zipfile.ZIP_DEFLATED:
                    n = _nonnegative_integer(stored_size, "compressed Block Size")
                    if n <= 0:
                        raise ValueError("invalid compressed AppxBlockMap Block Size")
                    compressed_total += n
                elif stored_size is not None:
                    raise ValueError("uncompressed AppxBlockMap Block has Size")
            if stream.read(1):
                raise ValueError("AppxBlockMap trailing payload data")
        if entry.compress_type == zipfile.ZIP_DEFLATED and compressed_total != entry.compress_size:
            raise ValueError("AppxBlockMap compressed Size total mismatch")
    if seen != expected:
        raise ValueError("AppxBlockMap omits package files")
