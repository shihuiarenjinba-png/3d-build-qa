"""Read-only Godot 4.3 PCK payload hygiene gate for immutable Prism Sentinel.

A historical inventory JSON is NOT proof that CI downloaded the real PCK.
Even a clean synthetic PCK never authorizes Store promotion.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import struct

SOURCE = "e432d94ed0db22878f61f1a8af140d7d7de2288f"
REQUEST = "3d-prism-route-3d-e432d94ed0db"
PCK_SHA = "3e92b7b6e336a0ab40419448b79f330cf00e0cba4d6bb9ec864ba70b89ecdb03"
PCK_BYTES = 71568
ARTIFACT = 12909162367
FORBIDDEN = {
    "res://store/approved-identity.json": "OLD_IDENTITY_BUNDLED",
    "res://product-manifest.json": "FACTORY_INTERNAL_MANIFEST_BUNDLED",
}
MAX_PCK = 512 * 1024 * 1024
MAX_ENTRIES = 20000
MAX_PATH = 4096


class PckContentError(ValueError):
    pass


def require(ok, message):
    if not ok:
        raise PckContentError(message)


def _u32(data, offset):
    require(offset + 4 <= len(data), "truncated PCK directory")
    return struct.unpack_from("<I", data, offset)[0]


def _u64(data, offset):
    require(offset + 8 <= len(data), "truncated PCK directory")
    return struct.unpack_from("<Q", data, offset)[0]


def parse_pck(data):
    """Parse Godot PCK v2 directory, verify all payload MD5 and bounds.

    No Godot execution occurs; a directory-only fixture cannot pass this parser.
    """
    require(isinstance(data, bytes) and 100 <= len(data) <= MAX_PCK, "invalid PCK size")
    require(data[:4] == b"GDPC", "invalid PCK magic")
    require(_u32(data, 4) == 2, "unsupported PCK format")
    require((_u32(data, 8), _u32(data, 12)) == (4, 3), "unexpected Godot version")
    require(_u32(data, 20) == 0, "unsupported PCK flags")
    base = _u64(data, 24)
    require(100 <= base <= len(data), "invalid PCK payload offset")
    count = _u32(data, 96)
    require(0 < count <= MAX_ENTRIES, "invalid PCK file count")
    pos, entries, seen, intervals = 100, [], set(), []
    for _ in range(count):
        n = _u32(data, pos)
        pos += 4
        require(0 < n <= MAX_PATH and pos + n + 36 <= base, "invalid PCK path length")
        raw = data[pos:pos+n]
        pos += n
        try:
            path = raw.rstrip(b"\0").decode("utf-8", errors="strict")
        except UnicodeError as exc:
            raise PckContentError("invalid UTF-8 PCK path") from exc
        require(path.startswith("res://") and
                "\\" not in path and
                not any(p in (".", "..") for p in path[6:].split("/")) and
                path not in seen, "unsafe or duplicate PCK path")
        seen.add(path)
        offset = _u64(data, pos)
        size = _u64(data, pos + 8)
        md5 = data[pos+16:pos+32]
        flags = _u32(data, pos+32)
        pos += 36
        require(flags == 0, "unsupported PCK entry flags")
        require(offset <= len(data) - base and size <= len(data) - base - offset,
                "PCK payload out of bounds")
        chunk = data[base+offset:base+offset+size]
        require(hashlib.md5(chunk).digest() == md5, "PCK resource MD5 mismatch")
        if size:
            intervals.append((offset, offset + size))
        entries.append({"path": path, "size": size, "md5": md5.hex()})
    require(pos <= base, "PCK directory overlaps payload")
    intervals.sort()
    require(all(intervals[i][1] <= intervals[i+1][0]
                for i in range(len(intervals)-1)), "overlapping PCK payloads")
    return entries


def prohibited_resource(path):
    low = path.lower()
    if low in FORBIDDEN:
        return FORBIDDEN[low]
    if low.startswith("res://tests/") or low.startswith("res://test/"):
        return "DEVELOPMENT_TEST_SCRIPT_BUNDLED"
    if low.startswith(("res://handoffs/", "res://.github/", "res://factory/")):
        return "INTERNAL_PIPELINE_RESOURCE_BUNDLED"
    if low.startswith("res://store/") and ("identity" in low or "approved" in low):
        return "STORE_IDENTITY_RESOURCE_BUNDLED"
    return None


def audit_bytes(data, *, real_factory_bytes=False):
    """No positive release verdict exists in this historical gate."""
    entries = parse_pck(data)
    findings = [{"path": item["path"], "reason": prohibited_resource(item["path"])}
                for item in entries if prohibited_resource(item["path"])]
    digest = hashlib.sha256(data).hexdigest()
    pinned = len(data) == PCK_BYTES and digest == PCK_SHA
    if real_factory_bytes:
        require(pinned, "Factory PCK SHA/size mismatch; no substitution allowed")
    return {
        "schema_version": 1, "source_sha": SOURCE, "request_id": REQUEST,
        "factory_artifact_id": ARTIFACT, "pck_sha256": digest,
        "pck_size_bytes": len(data), "pck_resource_count": len(entries),
        "all_resource_md5_match": True, "pinned_factory_pck_sha_size_match": pinned,
        "real_factory_bytes_checked_this_run": bool(real_factory_bytes),
        "findings": findings,
        "status": ("RELEASE_PCK_CONTENT_HOLD" if findings else
                   "HOLD_CONTENT_CLEAN_BUT_OTHER_GATES_UNVERIFIED"
                   if real_factory_bytes else "FIXTURE_ONLY_NOT_PRODUCT"),
        "identity_cas": "HOLD", "package_version": "HOLD",
        "signed_product_msix": "HOLD", "windows_gui": "DEFERRED_LOCAL_GATE",
        "sale_ready": False, "store_submission_allowed": False,
    }


def validate_historical_inventory(inv):
    """Pin the earlier independently verified inventory, never call it live bytes."""
    require(isinstance(inv, dict) and inv.get("schema_version") == 1 and
            inv.get("receipt_type") == "SENTINEL_PRESERVED_PCK_RESOURCE_INVENTORY" and
            inv.get("source_sha") == SOURCE and inv.get("request_id") == REQUEST and
            inv.get("factory_artifact_id") == ARTIFACT and
            inv.get("pck_sha256") == PCK_SHA and
            inv.get("pck_size_bytes") == PCK_BYTES and
            inv.get("pck_resource_count") == 14 and
            inv.get("all_14_resource_md5_match") is True and
            inv.get("contains_legacy_identity_json") is True and
            inv.get("contains_test_smoke_gdc") is True and
            inv.get("contains_product_manifest_json") is True and
            inv.get("embedded_identity_source_sha") ==
            "15fdcb52e46e35e6de8e87c55af99719c21e09b9" and
            inv.get("factory_pck_executed_in_ci") is False and
            inv.get("sale_ready") is False,
            "historical PCK inventory missing/changed: fail closed")
    return {"status": "RELEASE_PCK_CONTENT_HOLD",
            "evidence_boundary": "HISTORICAL_INVENTORY_ONLY_NOT_PCK_BYTES",
            "real_factory_bytes_checked_this_run": False,
            "forbidden_resources": sorted([
                "res://store/approved-identity.json",
                "res://product-manifest.json",
                "res://tests/test_smoke.gdc",
            ]),
            "sale_ready": False, "store_submission_allowed": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pck", type=Path)
    parser.add_argument("--historical-inventory", type=Path)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args(argv)
    try:
        require(args.pck is not None or args.historical_inventory is not None,
                "missing PCK/inventory input")
        if args.pck:
            require(args.pck.is_file() and not args.pck.is_symlink(), "unsafe PCK file")
            result = audit_bytes(args.pck.read_bytes(), real_factory_bytes=True)
        else:
            result = validate_historical_inventory(
                json.loads(args.historical_inventory.read_text(encoding="utf-8")))
    except (OSError, ValueError, TypeError, UnicodeError) as exc:
        result = {"status": "BLOCKED_PCK_UNVERIFIED", "reason": str(exc)[:200],
                  "sale_ready": False, "store_submission_allowed": False}
    payload = json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if args.out:
        args.out.write_text(payload, encoding="utf-8")
    print(payload, end="")
    return 2  # HOLD is intentional, never success-as-release


if __name__ == "__main__":
    raise SystemExit(main())
