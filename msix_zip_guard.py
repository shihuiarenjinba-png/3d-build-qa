"""Conservative Windows path and ZIP resource guard for untrusted 3D MSIX bytes.

No extraction, Store trust or installability is asserted here. Reject ambiguous
Windows paths before reading even the manifest/executable payload.
"""
from __future__ import annotations

import re
import stat
import struct
import zipfile

MAX_ENTRIES = 20_000
MAX_ENTRY_BYTES = 8 * 1024**3
MAX_TOTAL_UNCOMPRESSED_BYTES = 12 * 1024**3
MAX_EXPANSION_RATIO = 1000
MAX_PATH_LENGTH = 240
RESERVED = {"con", "prn", "aux", "nul", "conin$", "conout$"}
RESERVED.update(f"{prefix}{number}" for prefix in ("com", "lpt") for number in range(1, 10))
# Win32 also treats superscript 1, 2 and 3 as COM/LPT device digits.
# See Microsoft naming conventions; casefold alone does not fold these.
RESERVED.update(f"{prefix}{number}" for prefix in ("com", "lpt")
                for number in ("\u00b9", "\u00b2", "\u00b3"))
INVALID = re.compile(r'[<>:"|?*\x00-\x1f]')


def validate_archive_paths(archive: zipfile.ZipFile) -> None:
    """Reject Windows-ambiguous paths, symlinks, collisions and ZIP bombs.

    This is a fail-closed preflight only; it does not validate AppxBlockMap,
    Authenticode, central-directory cryptography or actual installability.
    """
    infos = archive.infolist()
    if not infos or len(infos) > MAX_ENTRIES:
        raise ValueError("MSIX ZIP entry count out of range")
    seen: set[str] = set()
    files: set[str] = set()
    directories: set[str] = set()
    total = 0

    for info in infos:
        # zipfile.open verifies local names only for members it reads. Empty
        # directory entries are skipped by the CRC pass, so validate every
        # local header against the central directory before trusting paths.
        archive.fp.seek(info.header_offset)
        local = archive.fp.read(30)
        if len(local) != 30 or local[:4] != b"PK\x03\x04":
            raise ValueError("invalid ZIP local file header")
        local_flags, local_method = struct.unpack_from("<HH", local, 6)
        name_size, extra_size = struct.unpack_from("<HH", local, 26)
        if local_flags != info.flag_bits or local_method != info.compress_type:
            raise ValueError("ZIP local/central header metadata mismatch")
        # Without a data descriptor, the local header must agree with the
        # central directory. zipfile reads the central CRC/sizes and otherwise
        # accepts forged local values even when the member bytes are intact.
        # ZIP64 size sentinels are left to the ZIP64 extra field and the
        # downstream byte/blockmap checks; never compare them as 32-bit sizes.
        if not (local_flags & 0x0008):
            local_crc, local_compressed, local_uncompressed = struct.unpack_from("<III", local, 14)
            if local_crc != info.CRC:
                raise ValueError("ZIP local/central CRC mismatch")
            if (local_compressed != 0xFFFFFFFF and
                    local_compressed != info.compress_size):
                raise ValueError("ZIP local/central compressed size mismatch")
            if (local_uncompressed != 0xFFFFFFFF and
                    local_uncompressed != info.file_size):
                raise ValueError("ZIP local/central uncompressed size mismatch")
        raw_name = archive.fp.read(name_size)
        try:
            central_name = info.filename.encode(
                "utf-8" if local_flags & 0x800 else "cp437")
        except UnicodeEncodeError:
            raise ValueError("invalid ZIP central filename encoding") from None
        if raw_name != central_name:
            raise ValueError("ZIP local/central header filename mismatch")
        raw_extra = archive.fp.read(extra_size)
        if len(raw_extra) != extra_size:
            raise ValueError("truncated ZIP local header extra field")
        # A 0xffffffff local size is not a wildcard: the corresponding
        # 64-bit value in the local ZIP64 extra field must match the central
        # directory. Python zipfile reads the central sizes and otherwise
        # accepts forged local ZIP64 values with intact member bytes.
        if not (local_flags & 0x0008) and (
                local_compressed == 0xFFFFFFFF or local_uncompressed == 0xFFFFFFFF):
            cursor = 0
            zip64_sizes = None
            while cursor < len(raw_extra):
                if len(raw_extra) - cursor < 4:
                    raise ValueError("truncated ZIP local extra field header")
                field_id, field_length = struct.unpack_from("<HH", raw_extra, cursor)
                cursor += 4
                if field_length > len(raw_extra) - cursor:
                    raise ValueError("truncated ZIP local extra field body")
                if field_id == 0x0001:
                    if zip64_sizes is not None:
                        raise ValueError("duplicate ZIP64 local extra field")
                    zip64_sizes = raw_extra[cursor:cursor + field_length]
                cursor += field_length
            if zip64_sizes is None:
                raise ValueError("missing ZIP64 local size extra field")
            position = 0
            for sentinel, central_size, label in (
                    (local_uncompressed, info.file_size, "uncompressed"),
                    (local_compressed, info.compress_size, "compressed")):
                if sentinel != 0xFFFFFFFF:
                    continue
                if len(zip64_sizes) - position < 8:
                    raise ValueError("truncated ZIP64 local " + label + " size")
                local_size = struct.unpack_from("<Q", zip64_sizes, position)[0]
                if local_size != central_size:
                    raise ValueError("ZIP64 local/central " + label + " size mismatch")
                position += 8
        name = info.filename
        if not isinstance(name, str) or len(name) > MAX_PATH_LENGTH:
            raise ValueError("invalid MSIX ZIP entry path length")
        if name.startswith("/") or "\\" in name:
            raise ValueError("absolute or backslash ZIP entry path")
        is_dir = info.is_dir()
        parts = name[:-1].split("/") if is_dir else name.split("/")
        if not parts or any(
            not part or part in (".", "..") or part.endswith((".", " "))
            or INVALID.search(part) or part.split(".", 1)[0].casefold() in RESERVED
            for part in parts
        ):
            raise ValueError("unsafe Windows ZIP entry path")
        folded = "/".join(part.casefold() for part in parts)
        if folded in seen:
            raise ValueError("duplicate or case-colliding Windows ZIP entry")
        seen.add(folded)
        if is_dir:
            directories.add(folded)
        else:
            files.add(folded)

        mode = info.external_attr >> 16
        file_type = stat.S_IFMT(mode)
        # Windows packages must not smuggle Unix device nodes, FIFOs or
        # sockets. A missing Unix type is normal for DOS-origin ZIP entries.
        if file_type == stat.S_IFLNK:
            raise ValueError("symlink ZIP entry")
        if file_type not in (0, stat.S_IFREG, stat.S_IFDIR):
            raise ValueError("unsupported special-file ZIP entry")
        if file_type == stat.S_IFDIR and not is_dir:
            raise ValueError("directory type without trailing slash")
        if file_type == stat.S_IFREG and is_dir:
            raise ValueError("regular-file type on directory entry")
        if info.flag_bits & 1:
            raise ValueError("encrypted ZIP entry")
        if info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
            raise ValueError("unsupported ZIP compression method")
        if info.file_size < 0 or info.file_size > MAX_ENTRY_BYTES:
            raise ValueError("ZIP entry uncompressed size out of range")
        if info.file_size > 1024 * 1024 and info.file_size > MAX_EXPANSION_RATIO * max(1, info.compress_size):
            raise ValueError("ZIP entry expansion ratio out of range")
        total += info.file_size
        if total > MAX_TOTAL_UNCOMPRESSED_BYTES:
            raise ValueError("ZIP uncompressed total exceeds limit")

    for path in files | directories:
        components = path.split("/")
        if any("/".join(components[:i]) in files for i in range(1, len(components))):
            raise ValueError("file conflicts with ZIP directory ancestor")
