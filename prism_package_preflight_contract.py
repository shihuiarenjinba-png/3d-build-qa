"""QA-only Prism PR25 package layout and exact-byte custody contract."""
import argparse
from datetime import datetime, timezone
import hashlib, json, re, stat, zipfile
from pathlib import Path

SOURCE_REPO = "shihuiarenjinba-png/3d-game-factory"
SOURCE_BRANCH = "codex/prism-tower1-hud-clearance-fix-20261103"
SOURCE = "b03ce7b16c3f75c04fe20fdda224c45849eeba0d"
REQUEST = "3d-prism-route-3d-b03ce7b16c3f"
RUN_ID, ARTIFACT_ID = 43794658086, 14797309778
ARTIFACT_NAME = "godot-3d-factory-export-evidence"
ZIP_SIZE = 37795977
ZIP_SHA = "e2573b9ab11afde6ab6ec7417c23438581620a08bb9dcff76d792a2b5592ccac"
MEMBERS = {
    "candidate.exe": (84214784, "66b26ad96df7458ea917b632a73ac7c88bb058db24dbd11a457fd50435ab7b13", b"MZ"),
    "candidate.pck": (6987584, "b7abc0f9caf2e505a1dcaf834b4cb897d8f00df4060c31708914e8bb4f3d5666", b"GDPC"),
    "export-evidence.json": (680, "442d2c9070e017adf1c0ceaa96ba607f470c0f147176671f8a844122aca4d5bd", b"{"),
}
REGISTRATION = "MSIX_OR_PWA_GAME"
SELECTION = "MSIX or PWA game"
PACKAGE_DIR = "VFS/ProgramFilesX64/PrismRoute3D"
ASSETS = (
    ("properties_logo", "Assets/StoreLogo.png"),
    ("square_150x150_logo", "Assets/Square150x150Logo.png"),
    ("square_44x44_logo", "Assets/Square44x44Logo.png"),
)
VERSION_RE = re.compile(r"^(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})$")

HANDOFF_REPOSITORY = "shihuiarenjinba-png/3d-build-qa"
HANDOFF_BRANCH = "codex/prism-pr25-exact-pck-qa-20261106"
HANDOFF_SOURCE = "9b90bfc9dfa6ded9699c3f22df45390be909dae8"
HANDOFF_RUN_ID, HANDOFF_ARTIFACT_ID = 45461731033, 14952074847
HANDOFF_NAME = "prism-pr25-exact-binary-physical-qa-handoff-not-store"
HANDOFF_SIZE = 129481721
HANDOFF_SHA = "35ae3ea873e0b122fe2cb138a170cd233cf89c7c81e8fed4262139d366a4c4c6"
HANDOFF_MEMBERS = {
    "candidate.exe", "candidate.pck", "README-PHYSICAL-QA.txt", "export-evidence.json",
    "factory-original.zip", "launch-verified.ps1", "handoff-receipt.json",
    "physical-capture-TEMPLATE.json", "prism_capture_physical_qa.ps1",
    "prism_consumer_artifact_runtime_gate.py", "prism_first30s_physical_windows_gate.py",
    "prism_pr25_physical_handoff.py", "prism_pr25_software_baseline_gate.py",
    "prism_sentinel_release_pck_content_gate.py", "qa11/pck-runtime-independent-receipt.json",
    "qa11/screenshots/guide_en.png", "qa11/screenshots/guide_ja.png",
    "qa11/screenshots/initial.png", "qa11/screenshots/ja.png",
    "qa11/screenshots/scan.png", "qa11/screenshots/trap.png", "qa11/screenshots/win.png",
}

class Hold(ValueError):
    pass

def need(ok, reason):
    if not ok:
        raise Hold(reason)

def unique_pairs(pairs):
    out = {}
    for k, v in pairs:
        need(k not in out, "duplicate JSON key")
        out[k] = v
    return out

def sha_file(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()

def sha_bytes(data):
    return hashlib.sha256(data).hexdigest()

def verify_metadata(m):
    expected = {"id": ARTIFACT_ID, "name": ARTIFACT_NAME,
                "size_in_bytes": ZIP_SIZE, "digest": "sha256:" + ZIP_SHA,
                "expired": False}
    need(type(m) is dict, "Factory metadata missing")
    for k, v in expected.items():
        need(type(m.get(k)) is type(v) and m.get(k) == v, "Factory metadata mismatch: " + k)
    run = m.get("workflow_run")
    need(type(run) is dict and run.get("id") == RUN_ID and
         run.get("head_sha") == SOURCE and run.get("head_branch") == SOURCE_BRANCH,
         "Factory run/source provenance mismatch")
    expiry_text = m.get("expires_at")
    need(isinstance(expiry_text, str) and expiry_text.endswith("Z"), "artifact expiry missing")
    try:
        expiry = datetime.fromisoformat(expiry_text.replace("Z", "+00:00"))
    except ValueError:
        raise Hold("invalid artifact expiry") from None
    need(datetime.now(timezone.utc) < expiry, "Factory artifact expired; do not rebuild or substitute")
    return {"artifact_id": ARTIFACT_ID, "run_id": RUN_ID, "source_sha": SOURCE,
            "expires_at": expiry_text, "metadata_verified": True}

def verify_archive(path):
    need(isinstance(path, Path) and path.is_file() and not path.is_symlink(),
         "Factory ZIP missing or unsafe")
    need(path.stat().st_size == ZIP_SIZE, "Factory ZIP byte length mismatch")
    digest = sha_file(path)
    need(digest == ZIP_SHA, "Factory ZIP SHA256 mismatch")
    try:
        with zipfile.ZipFile(path) as z:
            infos = z.infolist()
            names = [i.filename for i in infos]
            need(len(infos) == 3 and len(names) == len(set(names)) and set(names) == set(MEMBERS),
                 "Factory ZIP member set/duplicate mismatch")
            need(z.testzip() is None, "Factory ZIP CRC failure")
            data = {}
            for i in infos:
                need(not i.is_dir() and not (i.flag_bits & 1) and
                     not stat.S_ISLNK(i.external_attr >> 16), "unsafe ZIP member: " + i.filename)
                size, expected_sha, magic = MEMBERS[i.filename]
                b = z.read(i)
                need(i.file_size == size and b.startswith(magic) and sha_bytes(b) == expected_sha,
                     "Factory member bytes mismatch: " + i.filename)
                data[i.filename] = b
            manifest = json.loads(data["export-evidence.json"].decode("utf-8"),
                                  object_pairs_hook=unique_pairs)
    except (OSError, zipfile.BadZipFile, json.JSONDecodeError) as e:
        raise Hold("Factory ZIP parse/CRC failure: " + type(e).__name__) from None
    expected_manifest = {
        "schema_version": 1, "slug": "prism-route-3d", "product_type": "GAME_3D",
        "source_repository": SOURCE_REPO, "source_branch": SOURCE_BRANCH,
        "source_sha": SOURCE, "factory_build_head": SOURCE, "request_id": REQUEST,
        "exe_path": "candidate.exe", "exe_sha256": MEMBERS["candidate.exe"][1],
        "exe_size_bytes": MEMBERS["candidate.exe"][0],
        "pck_path": "candidate.pck", "pck_sha256": MEMBERS["candidate.pck"][1],
        "pck_size_bytes": MEMBERS["candidate.pck"][0],
    }
    for k, v in expected_manifest.items():
        need(type(manifest.get(k)) is type(v) and manifest.get(k) == v,
             "Factory export-evidence mismatch: " + k)
    return {
        "status": "EXACT_PR25_FACTORY_BYTES_VERIFIED",
        "source_sha": SOURCE, "request_id": REQUEST, "factory_run_id": RUN_ID,
        "factory_artifact_id": ARTIFACT_ID, "factory_zip_bytes": ZIP_SIZE,
        "factory_zip_sha256": digest,
        "exe_bytes": MEMBERS["candidate.exe"][0], "exe_sha256": MEMBERS["candidate.exe"][1],
        "pck_bytes": MEMBERS["candidate.pck"][0], "pck_sha256": MEMBERS["candidate.pck"][1],
        "manifest_sha256": MEMBERS["export-evidence.json"][1],
        "archive_bytes_verified_this_run": True, "product_msix_created": False,
        "sale_ready": False, "store_submission_allowed": False,
    }

def verify_handoff_metadata(m):
    expected = {"id": HANDOFF_ARTIFACT_ID, "name": HANDOFF_NAME,
                "size_in_bytes": HANDOFF_SIZE, "digest": "sha256:" + HANDOFF_SHA,
                "expired": False}
    need(type(m) is dict, "physical handoff metadata missing")
    for k, v in expected.items():
        need(type(m.get(k)) is type(v) and m.get(k) == v, "handoff metadata mismatch: " + k)
    run = m.get("workflow_run")
    need(type(run) is dict and run.get("id") == HANDOFF_RUN_ID and
         run.get("head_sha") == HANDOFF_SOURCE and run.get("head_branch") == HANDOFF_BRANCH,
         "physical handoff PR19 provenance mismatch")
    expiry_text = m.get("expires_at")
    need(isinstance(expiry_text, str) and expiry_text == "2026-12-01T18:39:16Z",
         "physical handoff expiry mismatch")
    expiry = datetime.fromisoformat(expiry_text.replace("Z", "+00:00"))
    need(datetime.now(timezone.utc) < expiry, "physical handoff artifact expired")
    return {"artifact_id": HANDOFF_ARTIFACT_ID, "run_id": HANDOFF_RUN_ID,
            "source_sha": HANDOFF_SOURCE, "expires_at": expiry_text, "metadata_verified": True}

def verify_handoff_archive(path):
    need(isinstance(path, Path) and path.is_file() and not path.is_symlink(),
         "physical handoff ZIP missing or unsafe")
    need(path.stat().st_size == HANDOFF_SIZE, "physical handoff ZIP byte length mismatch")
    need(sha_file(path) == HANDOFF_SHA, "physical handoff ZIP SHA256 mismatch")
    try:
        with zipfile.ZipFile(path) as z:
            infos = z.infolist()
            names = [i.filename for i in infos]
            need(len(names) == len(set(names)) and set(names) == HANDOFF_MEMBERS,
                 "physical handoff ZIP member set/duplicate mismatch")
            need(z.testzip() is None, "physical handoff ZIP CRC failure")
            for i in infos:
                need(not i.is_dir() and not (i.flag_bits & 1) and
                     not stat.S_ISLNK(i.external_attr >> 16),
                     "unsafe physical handoff member: " + i.filename)
            def member(name):
                return z.read(name)
            exe, pck = member("candidate.exe"), member("candidate.pck")
            factory_zip, manifest = member("factory-original.zip"), member("export-evidence.json")
            need(len(exe) == MEMBERS["candidate.exe"][0] and sha_bytes(exe) == MEMBERS["candidate.exe"][1],
                 "handoff EXE bytes mismatch")
            need(len(pck) == MEMBERS["candidate.pck"][0] and sha_bytes(pck) == MEMBERS["candidate.pck"][1],
                 "handoff PCK bytes mismatch")
            need(len(factory_zip) == ZIP_SIZE and sha_bytes(factory_zip) == ZIP_SHA,
                 "embedded original Factory ZIP mismatch")
            need(len(manifest) == MEMBERS["export-evidence.json"][0] and
                 sha_bytes(manifest) == MEMBERS["export-evidence.json"][1],
                 "handoff export-evidence bytes mismatch")
            receipt = json.loads(member("handoff-receipt.json").decode("utf-8"),
                                 object_pairs_hook=unique_pairs)
            need(receipt.get("status") == "EXACT_PR25_BINARY_HANDOFF_VERIFIED_NOT_PHYSICAL" and
                 receipt.get("source_sha") == SOURCE and receipt.get("request_id") == REQUEST and
                 receipt.get("factory_artifact_id") == ARTIFACT_ID and
                 receipt.get("factory_zip_sha256") == ZIP_SHA and
                 receipt.get("exe_sha256") == MEMBERS["candidate.exe"][1] and
                 receipt.get("pck_sha256") == MEMBERS["candidate.pck"][1] and
                 receipt.get("physical_screenshots_captured") == 0 and
                 receipt.get("physical_windows_gui") == "HOLD" and
                 receipt.get("sale_ready") is False and
                 receipt.get("store_submission_allowed") is False,
                 "physical handoff receipt claims or provenance mismatch")
            template = json.loads(member("physical-capture-TEMPLATE.json").decode("utf-8"),
                                  object_pairs_hook=unique_pairs)
            need(template.get("source_sha") == SOURCE and template.get("request_id") == REQUEST and
                 template.get("factory_artifact_id") == ARTIFACT_ID and
                 template.get("factory_artifact_expires_at") is None and
                 template.get("physical_device") is False and
                 template.get("code_integrity_status") == "NOT_CHECKED" and
                 len(template.get("sessions", [])) == 6,
                 "physical capture template is not an empty fail-closed template")
            screenshot_names = [name for session in template["sessions"]
                                for name in session["screenshots"].values()]
            need(len(screenshot_names) == 36 and len(set(screenshot_names)) == 36,
                 "physical template must contain 36 unique expected filenames")
            readme = member("README-PHYSICAL-QA.txt").decode("utf-8").lower()
            need("prism_capture_physical_qa.ps1" in readme and "not a signed msix" in readme,
                 "physical runner instructions missing safety boundary")
    except (OSError, zipfile.BadZipFile, json.JSONDecodeError) as e:
        raise Hold("physical handoff ZIP parse/CRC failure: " + type(e).__name__) from None
    return {"status": "EXACT_PR19_PHYSICAL_HANDOFF_CUSTODY_VERIFIED_NOT_PHYSICAL",
            "artifact_id": HANDOFF_ARTIFACT_ID, "run_id": HANDOFF_RUN_ID,
            "source_sha": HANDOFF_SOURCE, "zip_sha256": HANDOFF_SHA,
            "embedded_factory_zip_sha256": ZIP_SHA,
            "physical_screenshots_captured": 0, "physical_windows_gui": "HOLD",
            "sale_ready": False, "store_submission_allowed": False}

def version_gate(evidence):
    if evidence is None:
        return "HOLD_MISSING_AUTHORITATIVE_FOUR_PART_VERSION"
    if type(evidence) is not dict:
        return "HOLD_INVALID_VERSION_EVIDENCE"
    v = evidence.get("version")
    if (not isinstance(v, str) or not VERSION_RE.fullmatch(v) or
        any(int(p) > 65535 for p in v.split("."))):
        return "HOLD_MALFORMED_FOUR_PART_VERSION"
    # This QA-only contract has no authority to authenticate a Partner Center
    # or 36-owner receipt. Four-part or self-asserted JSON values remain HOLD.
    return "HOLD_UNAUTHENTICATED_VERSION_EVIDENCE"

def build_plan(p, registration=REGISTRATION, version_evidence=None):
    need(type(p) is dict and p.get("status") == "EXACT_PR25_FACTORY_BYTES_VERIFIED" and
         p.get("source_sha") == SOURCE and p.get("request_id") == REQUEST and
         p.get("factory_run_id") == RUN_ID and p.get("factory_artifact_id") == ARTIFACT_ID and
         p.get("factory_zip_bytes") == ZIP_SIZE and p.get("factory_zip_sha256") == ZIP_SHA and
         p.get("exe_bytes") == MEMBERS["candidate.exe"][0] and
         p.get("exe_sha256") == MEMBERS["candidate.exe"][1] and
         p.get("pck_bytes") == MEMBERS["candidate.pck"][0] and
         p.get("pck_sha256") == MEMBERS["candidate.pck"][1] and
         p.get("manifest_sha256") == MEMBERS["export-evidence.json"][1],
         "package plan requires exact current PR25 byte receipt")
    need(registration == REGISTRATION, "registration route mismatch; GDK is not accepted")
    exe = PACKAGE_DIR + "/candidate.exe"
    pck = PACKAGE_DIR + "/candidate.pck"
    assets = [{"logical_name": n, "package_path": path, "source_path": None,
               "status": "HOLD_OFFICIAL_ASSET_SOURCE_NOT_PRESENT"} for n, path in ASSETS]
    return {
        "schema_version": 1, "kind": "QA_FIXTURE_ONLY_NOT_PRODUCT",
        "status": "PACKAGE_PREFLIGHT_HOLD_NOT_PRODUCT_MSIX",
        "source_sha": SOURCE, "request_id": REQUEST, "factory_run_id": RUN_ID,
        "factory_artifact_id": ARTIFACT_ID, "factory_zip_sha256": ZIP_SHA,
        "payload_mapping": [
            {"source_member": "candidate.exe", "package_path": exe,
             "role": "Godot Windows executable", "sha256": MEMBERS["candidate.exe"][1]},
            {"source_member": "candidate.pck", "package_path": pck,
             "role": "Godot external PCK sidecar; same directory/stem as EXE",
             "sha256": MEMBERS["candidate.pck"][1]},
        ],
        "manifest_contract": {
            "manifest_path": "AppxManifest.xml", "application_executable": exe,
            "external_pck_sidecar": pck,
            "identity": "SYNTHETIC_ONLY_NOT_PRODUCT; official Identity remains 36-owner HOLD",
            "version": "SYNTHETIC_ONLY_NOT_PRODUCT; no authoritative four-part Version supplied",
            "required_assets": assets, "assets_status": "HOLD_OFFICIAL_ASSET_SOURCE_NOT_PRESENT",
        },
        "registration_type": REGISTRATION, "partner_center_selection": SELECTION,
        "authoritative_package_version_status": version_gate(version_evidence),
        "identity_cas_status": "HOLD_36_OWNER", "physical_windows_gui": "HOLD",
        "package_build_allowed": False, "makeappx_package_build_invoked": False,
        "product_msix_created": False, "store_submission_allowed": False, "sale_ready": False,
    }

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--metadata", type=Path, required=True)
    ap.add_argument("--archive", type=Path, required=True)
    ap.add_argument("--handoff-metadata", type=Path, required=True)
    ap.add_argument("--handoff-archive", type=Path, required=True)
    ap.add_argument("--receipt-out", type=Path, required=True)
    ap.add_argument("--plan-out", type=Path, required=True)
    ap.add_argument("--handoff-receipt-out", type=Path, required=True)
    a = ap.parse_args()
    try:
        meta = json.loads(a.metadata.read_text(encoding="utf-8"), object_pairs_hook=unique_pairs)
        meta_receipt = verify_metadata(meta)
        handoff_meta = json.loads(a.handoff_metadata.read_text(encoding="utf-8"), object_pairs_hook=unique_pairs)
        handoff_meta_receipt = verify_handoff_metadata(handoff_meta)
        handoff_receipt = verify_handoff_archive(a.handoff_archive)
        preflight = verify_archive(a.archive)
        plan = build_plan(preflight)
        canonical = json.dumps(plan, sort_keys=True, separators=(",", ":")).encode("utf-8")
        receipt = {
            "status": "EXACT_FACTORY_BYTES_CUSTODY_VERIFIED_PACKAGE_PREFLIGHT_HOLD",
            "metadata": meta_receipt, "physical_handoff_metadata": handoff_meta_receipt,
            "physical_handoff": handoff_receipt, "source_sha": SOURCE, "request_id": REQUEST,
            "factory_artifact_id": ARTIFACT_ID, "factory_zip_sha256": ZIP_SHA,
            "exe_sha256": MEMBERS["candidate.exe"][1], "pck_sha256": MEMBERS["candidate.pck"][1],
            "manifest_sha256": MEMBERS["export-evidence.json"][1],
            "package_layout_plan_sha256": hashlib.sha256(canonical).hexdigest(),
            "registration_type": REGISTRATION, "partner_center_selection": SELECTION,
            "authoritative_package_version_status": plan["authoritative_package_version_status"],
            "official_store_assets_status": plan["manifest_contract"]["assets_status"],
            "package_build_allowed": False, "makeappx_package_build_invoked": False,
            "product_msix_created": False, "identity_cas_status": "HOLD_36_OWNER",
            "physical_windows_gui": "HOLD", "sale_ready": False, "store_submission_allowed": False,
        }
        a.receipt_out.parent.mkdir(parents=True, exist_ok=True)
        a.plan_out.parent.mkdir(parents=True, exist_ok=True)
        a.receipt_out.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
        a.plan_out.write_text(json.dumps(plan, indent=2) + "\n", encoding="utf-8")
        a.handoff_receipt_out.parent.mkdir(parents=True, exist_ok=True)
        a.handoff_receipt_out.write_text(json.dumps(handoff_receipt, indent=2) + "\n", encoding="utf-8")
    except (OSError, ValueError, TypeError, KeyError, zipfile.BadZipFile) as e:
        print(json.dumps({"status": "PACKAGE_PREFLIGHT_HOLD", "reason": str(e)[:240],
                          "product_msix_created": False, "store_submission_allowed": False}))
        return 2
    print(json.dumps(receipt, indent=2))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
