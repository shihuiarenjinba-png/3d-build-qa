"""Read-only, fail-closed verification of the pinned real Sentinel Factory ZIP.

A valid Factory ZIP is not a Store package or an Identity CAS receipt.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import zipfile

SOURCE = "e432d94ed0db22878f61f1a8af140d7d7de2288f"
REQUEST = "3d-prism-route-3d-e432d94ed0db"
ARCHIVE_SHA = "dc60f397e002bddf63a8f64ec263dd241a3eb8c4f7fd6e6595d115a9f273ae9c"
FILES = {
    "candidate.exe": (84214784, "66b26ad96df7458ea917b632a73ac7c88bb058db24dbd11a457fd50435ab7b13"),
    "candidate.pck": (71568, "3e92b7b6e336a0ab40419448b79f330cf00e0cba4d6bb9ec864ba70b89ecdb03"),
    "export-evidence.json": (672, "c55db8c276919cc9792c02f2423ecc6e7b249ad83772e9e256de1fd412208103"),
}


class EvidenceError(ValueError):
    pass


def require(ok, reason):
    if not ok:
        raise EvidenceError(reason)


def unique_keys(pairs):
    obj = {}
    for k, v in pairs:
        require(k not in obj, "duplicate JSON key")
        obj[k] = v
    return obj


def validate_receipt(r):
    require(isinstance(r, dict), "receipt missing")
    require(r.get("schema_version") == "1.0" and
            r.get("receipt_type") == "GAME_3D_LIVE_FACTORY_ARCHIVE_RECHECK" and
            r.get("slug") == "prism-route-3d", "wrong receipt type/product")
    src, a, members, manifest, checks, downstream = (
        r.get(k) for k in ("source", "artifact", "members", "manifest",
                           "independent_checks", "downstream"))
    require(all(isinstance(x, dict) for x in
                (src, a, members, manifest, checks, downstream)), "missing receipt fields")
    require(src.get("sha") == SOURCE and src.get("request_id") == REQUEST and
            src.get("factory_build_head") == SOURCE and
            src.get("repository") == "shihuiarenjinba-png/3d-game-factory",
            "source/request drift")
    require(a.get("workflow_run_id") == 40901053437 and
            a.get("artifact_id") == 12909162367 and
            a.get("archive_size_bytes") == 30880705 and
            a.get("archive_sha256") == ARCHIVE_SHA and
            a.get("github_metadata_digest") == "sha256:" + ARCHIVE_SHA and
            a.get("github_workflow_head_sha") == SOURCE and
            a.get("github_metadata_expired") is False, "artifact metadata drift")
    require(set(members) == set(FILES), "unexpected ZIP members")
    for name, (size, digest) in FILES.items():
        require(members[name].get("size_bytes") == size and
                members[name].get("sha256") == digest, "member drift: " + name)
    require(manifest.get("source_sha") == SOURCE and
            manifest.get("factory_build_head") == SOURCE and
            manifest.get("request_id") == REQUEST and
            manifest.get("product_type") == "GAME_3D" and
            manifest.get("slug") == "prism-route-3d" and
            manifest.get("exe_path") == "candidate.exe" and
            manifest.get("pck_path") == "candidate.pck" and
            manifest.get("exe_sha256") == FILES["candidate.exe"][1] and
            manifest.get("pck_sha256") == FILES["candidate.pck"][1] and
            manifest.get("exe_size_bytes") == FILES["candidate.exe"][0] and
            manifest.get("pck_size_bytes") == FILES["candidate.pck"][0],
            "embedded manifest drift")
    require(r.get("registration_type") == "MSIX_OR_PWA_GAME" and
            r.get("partner_center_selection") == "MSIX or PWA game",
            "wrong registration route")
    require(all(checks.get(k) is True for k in
                ("archive_matches_github_digest", "workflow_head_matches_source",
                 "source_request_build_head_match_manifest", "exe_sha_and_size_match_manifest",
                 "pck_sha_and_size_match_manifest", "archive_members_exact", "crc_pass")),
            "incomplete byte checks")
    legacy = r.get("legacy_provisioner_discrimination", {})
    require(legacy.get("legacy_pck_sha256") ==
            "2cd8af6496cf288bc3e6aef317e472b480f21d2052cbd4ae0cd171e6285ab1ef" and
            legacy.get("legacy_pck_matches_sentinel") is False and
            legacy.get("legacy_promotable_to_sentinel") is False, "legacy artifact promoted")
    require(all(downstream.get(k) == "HOLD" for k in
                ("official_identity_cas", "package_version", "signed_product_msix",
                 "windows_all_auto_intake", "product_e2e")) and
            downstream.get("historical_identity_rebound_to_sentinel") is False and
            downstream.get("unsigned_qa_fixture_is_store_package") is False and
            downstream.get("store_submission_allowed") is False,
            "Store/Identity gate bypass")
    return True


def verify_zip(path, receipt):
    """Verify actual archive bytes, not merely the JSON receipt's claims."""
    validate_receipt(receipt)
    p = Path(path)
    require(p.is_file() and not p.is_symlink(), "missing/unsafe archive")
    require(p.stat().st_size == 30880705, "archive size drift")
    digest = hashlib.sha256()
    with p.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(block)
    require(digest.hexdigest() == ARCHIVE_SHA, "archive SHA256 drift")
    with zipfile.ZipFile(p) as z:
        infos = z.infolist()
        require(len(infos) == 3 and {i.filename for i in infos} == set(FILES),
                "unexpected or duplicate ZIP members")
        require(sum(i.file_size for i in infos) == 84287024,
                "uncompressed size drift")
        for i in infos:
            require(not i.is_dir() and not (i.flag_bits & 1) and
                    not stat.S_ISLNK(i.external_attr >> 16),
                    "unsafe ZIP member")
            expected_size, expected_sha = FILES[i.filename]
            require(i.file_size == expected_size, "member size drift: " + i.filename)
            with z.open(i) as stream:
                h = hashlib.sha256()
                for block in iter(lambda: stream.read(1024 * 1024), b""):
                    h.update(block)
            require(h.hexdigest() == expected_sha, "member SHA drift: " + i.filename)
        require(z.testzip() is None, "ZIP CRC failure")
        manifest = json.loads(z.read("export-evidence.json"), object_pairs_hook=unique_keys)
        require(manifest == receipt["manifest"], "archive manifest differs from receipt")
    return {"status": "HOLD_FACTORY_ZIP_BYTES_VERIFIED_NOT_STORE_PRODUCT",
            "factory_archive_verified": True, "official_identity_cas": "HOLD",
            "signed_product_msix": "HOLD", "windows_all_auto_intake": "HOLD",
            "product_e2e": "HOLD", "store_submission_allowed": False}


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--receipt", required=True, type=Path)
    parser.add_argument("--archive", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        require(args.receipt.is_file() and not args.receipt.is_symlink() and
                0 < args.receipt.stat().st_size < 65536, "unsafe receipt")
        receipt = json.loads(args.receipt.read_text(encoding="utf-8"),
                             object_pairs_hook=unique_keys)
        result = verify_zip(args.archive, receipt)
    except (OSError, ValueError, TypeError, zipfile.BadZipFile) as exc:
        result = {"status": "BLOCKED", "reason": str(exc)[:160],
                  "product_e2e": "HOLD", "store_submission_allowed": False}
    print(json.dumps(result, sort_keys=True))
    return 2  # HOLD is never a Store-ready success.


if __name__ == "__main__":
    raise SystemExit(main())
