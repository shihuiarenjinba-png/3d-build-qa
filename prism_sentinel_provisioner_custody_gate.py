"""Check-only consumer of a PINNED Provisioner-3D real-byte custody receipt.

This verifies historical Factory provenance, optionally the real ZIP bytes.
A successful check NEVER authenticates Partner Center Identity, signs an MSIX,
or promotes the unsigned MakeAppx QA fixture to a Store product.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import stat
import zipfile

SOURCE = "e432d94ed0db22878f61f1a8af140d7d7de2288f"
REQUEST = "3d-prism-route-3d-e432d94ed0db"
EXE = "66b26ad96df7458ea917b632a73ac7c88bb058db24dbd11a457fd50435ab7b13"
PCK = "3e92b7b6e336a0ab40419448b79f330cf00e0cba4d6bb9ec864ba70b89ecdb03"
OLD_PCK = "2cd8af6496cf288bc3e6aef317e472b480f21d2052cbd4ae0cd171e6285ab1ef"
ARCHIVE = "dc60f397e002bddf63a8f64ec263dd241a3eb8c4f7fd6e6595d115a9f273ae9c"
MANIFEST = "c55db8c276919cc9792c02f2423ecc6e7b249ad83772e9e256de1fd412208103"
MEMBERS = {"candidate.exe": (84214784, EXE),
           "candidate.pck": (71568, PCK),
           "export-evidence.json": (672, MANIFEST)}


class CustodyError(ValueError):
    pass


def need(value, reason):
    if not value:
        raise CustodyError(reason)


def unique_pairs(pairs):
    d = {}
    for k, v in pairs:
        need(k not in d, "duplicate JSON key")
        d[k] = v
    return d


def load_json(path):
    p = Path(path)
    need(p.is_file() and not p.is_symlink() and 0 < p.stat().st_size <= 65536,
         "missing, symlinked, or oversized JSON")
    return json.loads(p.read_text(encoding="utf-8"), object_pairs_hook=unique_pairs)


def validate_receipt(r):
    need(isinstance(r, dict) and r.get("schema_version") == "1.0" and
         r.get("receipt_type") == "GAME_3D_SENTINEL_INDEPENDENT_ARCHIVE_CUSTODY_20261102" and
         r.get("product") == "Prism Route 3D" and r.get("slug") == "prism-route-3d",
         "wrong receipt/product")
    source, a, members, m, checks, old, route, downstream = (
        r.get(k) for k in ("source", "artifact", "members", "manifest", "checks",
                           "legacy_revision", "route", "downstream"))
    need(all(isinstance(x, dict) for x in
             (source, a, members, m, checks, old, route, downstream)),
         "incomplete receipt")
    need(source.get("repository") == "shihuiarenjinba-png/3d-game-factory" and
         source.get("sha") == SOURCE and source.get("request_id") == REQUEST and
         source.get("factory_build_head") == SOURCE and
         source.get("branch") == "codex/prism-route-trap-tension-20261029",
         "source/request/build head mismatch")
    need(type(a.get("run_id")) is int and a["run_id"] == 40901053437 and
         type(a.get("artifact_id")) is int and a["artifact_id"] == 12909162367 and
         type(a.get("archive_bytes")) is int and a["archive_bytes"] == 30880705 and
         a.get("archive_sha256") == ARCHIVE and
         a.get("github_digest") == "sha256:" + ARCHIVE and
         a.get("run_head_sha") == SOURCE and
         a.get("artifact_name") == "godot-3d-factory-export-evidence",
         "Factory artifact provenance mismatch")
    need(set(members) == set(MEMBERS), "missing/extra member evidence")
    for name, (size, sha) in MEMBERS.items():
        item = members[name]
        need(isinstance(item, dict) and type(item.get("bytes")) is int and
             item["bytes"] == size and item.get("sha256") == sha,
             "EXE/PCK/manifest SHA or size mismatch: " + name)
    need(m.get("schema_version") == 1 and m.get("product_type") == "GAME_3D" and
         m.get("slug") == "prism-route-3d" and
         m.get("source_repository") == source["repository"] and
         m.get("source_branch") == source["branch"] and
         m.get("source_sha") == SOURCE and m.get("request_id") == REQUEST and
         m.get("factory_build_head") == SOURCE and
         m.get("exe_path") == "candidate.exe" and m.get("exe_sha256") == EXE and
         m.get("exe_size_bytes") == MEMBERS["candidate.exe"][0] and
         m.get("pck_path") == "candidate.pck" and m.get("pck_sha256") == PCK and
         m.get("pck_size_bytes") == MEMBERS["candidate.pck"][0],
         "embedded manifest drift")
    need(all(checks.get(k) is True for k in (
         "archive_sha_and_size", "archive_digest_matches_github_metadata",
         "zip_crc", "exact_three_members", "member_sha_and_size",
         "manifest_source_request_build_head", "manifest_exe_pck",
         "legacy_pck_mismatch_detected")), "incomplete independent byte checks")
    need(old.get("source_sha") == "15fdcb52e46e35e6de8e87c55af99719c21e09b9" and
         old.get("pck_sha256") == OLD_PCK and OLD_PCK != PCK and
         old.get("pck_matches_sentinel") is False and
         old.get("promotable") is False and
         old.get("historical_identity_commit") ==
         "11417b75636ee18816028ffd5221884c4c9a9836" and
         old.get("historical_identity_is_new_revision_cas") is False,
         "old PCK or historical Identity incorrectly rebound")
    need(route.get("registration_type") == "MSIX_OR_PWA_GAME" and
         route.get("partner_center_selection") == "MSIX or PWA game",
         "incorrect Partner Center registration")
    need(all(downstream.get(k) == "HOLD" for k in
             ("official_identity_cas", "package_version", "signed_product_msix",
              "windows_all_auto_intake", "product_e2e")) and
         downstream.get("unsigned_qa_fixture_is_store_package") is False and
         downstream.get("store_submission_allowed") is False and
         downstream.get("second_3d_product_allowed") is False and
         downstream.get("local_windows") == "DEFERRED_LOCAL_GATE",
         "unapproved Identity, version, fixture, or Store promotion")
    return {"status": "HOLD_CHECK_ONLY_CUSTODY_CORRELATED",
            "source_sha": SOURCE, "request_id": REQUEST,
            "exe_sha256": EXE, "pck_sha256": PCK,
            "archive_sha256": ARCHIVE, "receipt_correlated": True,
            "real_archive_bytes_verified_this_run": False,
            "official_identity_cas": "HOLD", "package_version": "HOLD",
            "signed_product_msix": "HOLD", "windows_all_auto_intake": "HOLD",
            "product_e2e": "HOLD", "store_submission_allowed": False}


def verify_archive(path, r):
    result = validate_receipt(r)
    p = Path(path)
    need(p.is_file() and not p.is_symlink() and p.stat().st_size == 30880705,
         "archive missing/unsafe/size mismatch")
    with p.open("rb") as stream:
        h = hashlib.sha256()
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    need(h.hexdigest() == ARCHIVE, "archive SHA256 mismatch")
    with zipfile.ZipFile(p) as z:
        infos = z.infolist()
        need(len(infos) == 3 and {x.filename for x in infos} == set(MEMBERS),
             "archive member set/duplicate mismatch")
        for info in infos:
            need(not info.is_dir() and not (info.flag_bits & 1) and
                 not stat.S_ISLNK(info.external_attr >> 16),
                 "unsafe ZIP entry")
            size, sha = MEMBERS[info.filename]
            need(info.file_size == size, "member size mismatch: " + info.filename)
            h = hashlib.sha256()
            with z.open(info) as stream:
                for block in iter(lambda: stream.read(1024 * 1024), b""):
                    h.update(block)
            need(h.hexdigest() == sha, "member SHA mismatch: " + info.filename)
        need(z.testzip() is None, "ZIP CRC mismatch")
        embedded = json.loads(z.read("export-evidence.json"),
                              object_pairs_hook=unique_pairs)
        need(embedded == r["manifest"], "embedded manifest differs from custody receipt")
    result["real_archive_bytes_verified_this_run"] = True
    result["status"] = "HOLD_REAL_FACTORY_BYTES_VERIFIED_NOT_STORE_MSIX"
    return result


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--archive", type=Path)
    args = parser.parse_args(argv)
    try:
        r = load_json(args.receipt)
        result = verify_archive(args.archive, r) if args.archive else validate_receipt(r)
    except (OSError, ValueError, TypeError, zipfile.BadZipFile) as exc:
        result = {"status": "BLOCKED", "reason": str(exc)[:200],
                  "product_e2e": "HOLD", "store_submission_allowed": False}
        print(json.dumps(result, sort_keys=True))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0  # check-only command succeeded; the product status remains HOLD


if __name__ == "__main__":
    raise SystemExit(main())
