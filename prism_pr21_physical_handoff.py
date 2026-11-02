"""Reproducible read-only PR21 EXE/PCK handoff; never physical or Store approval.

The original GitHub Actions Factory ZIP is retained so the recipient can recheck
ZIP CRC, exact immutable source/request, EXE/PCK/manifest bytes offline.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import sys
import zipfile

from prism_consumer_artifact_runtime_gate import (
    SOURCE, REQUEST, ARTIFACT_ID, RUN_ID, ZIP_SHA, MEMBERS, verify_archive,
)
from prism_pr21_software_baseline_gate import verify_software_baseline, unique_pairs

FILES = (
    "prism_consumer_artifact_runtime_gate.py",
    "prism_sentinel_release_pck_content_gate.py",
    "prism_pr21_software_baseline_gate.py",
    "prism_first30s_physical_windows_gate.py",
    "prism_pr21_physical_handoff.py",
)
FRAMES = ("guide_en", "guide_ja", "initial", "scan", "trap", "win", "ja")
OBSERVATIONS = (
    "goal_understood_in_30s", "tower_order_1_2_3_understood",
    "controls_understood", "sentinel_colors_understood", "traps_understood",
    "start_action_understood", "clock_frozen_until_start", "no_clipping",
    "no_debug_ui", "failure_reason_understood", "retry_completed",
)


class HandoffHold(ValueError):
    pass


def need(condition, reason):
    if not condition:
        raise HandoffHold(reason)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load(path):
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique_pairs)


def capture_template():
    sessions = []
    for lang in ("ja", "en"):
        for dpi in (125, 150):
            session = {
                "language": lang, "dpi_percent": dpi, "resolution": [1024, 768],
                "capture_started_at": None, "capture_finished_at": None,
                "elapsed_play_seconds": None, "first_goal_seconds": None,
                "uncoached_first_launch": False, "start_pressed": False,
                "screenshots": {
                    "guide": f"{lang}-{dpi}-guide.png",
                    "active": f"{lang}-{dpi}-active.png",
                    "scan_warning": f"{lang}-{dpi}-scan.png",
                    "trap": f"{lang}-{dpi}-trap.png",
                    "outcome": f"{lang}-{dpi}-outcome.png",
                    "retry": f"{lang}-{dpi}-retry.png",
                },
            }
            session.update({key: False for key in OBSERVATIONS})
            sessions.append(session)
    return {
        "schema_version": 1, "capture_kind": "PHYSICAL_WINDOWS_OPERATOR_ATTESTATION",
        "source_sha": SOURCE, "request_id": REQUEST,
        "factory_artifact_id": ARTIFACT_ID,
        "exe_sha256": MEMBERS["candidate.exe"][1],
        "pck_sha256": MEMBERS["candidate.pck"][1],
        "exe_path": None, "pck_path": None,
        "physical_device": False, "operator": None, "windows_build": None,
        "sessions": sessions,
    }


def verify_template(value):
    need(isinstance(value, dict), "capture template missing")
    expected = capture_template()
    need(value == expected, "capture template modified, incomplete, or falsely attested")
    need(len(value["sessions"]) == 4, "four uncoached sessions required")
    need(len({x for s in value["sessions"] for x in s["screenshots"].values()}) == 24,
         "24 unique physical screenshot filenames required")


def check_handoff(root):
    need(root.is_dir() and not root.is_symlink(), "missing or symlink handoff directory")
    archive = root / "factory-original.zip"
    need(archive.is_file() and not archive.is_symlink(), "original Factory ZIP missing")
    preflight = verify_archive(archive)  # ZIP size, SHA, CRC, members, PCK, source and request
    for name, (size, expected) in MEMBERS.items():
        p = root / name
        need(p.is_file() and not p.is_symlink(), "missing/symlink handoff member: " + name)
        need(p.stat().st_size == size and digest(p) == expected,
             "handoff EXE/PCK/manifest bytes drift: " + name)
    receipt = load(root / "qa11" / "pck-runtime-independent-receipt.json")
    baseline = verify_software_baseline(receipt, root / "qa11" / "screenshots")
    need(receipt["source_sha"] == preflight["source_sha"] and
         receipt["request_id"] == preflight["request_id"] and
         receipt["exe_sha256"] == preflight["exe_sha256"] and
         receipt["pck_sha256"] == preflight["pck_sha256"] and
         receipt["zip_sha256"] == ZIP_SHA, "software receipt not bound to original Factory bytes")
    verify_template(load(root / "physical-capture-TEMPLATE.json"))
    handoff = load(root / "handoff-receipt.json")
    need(handoff == {
        "schema_version": 1,
        "status": "EXACT_PR21_BINARY_HANDOFF_VERIFIED_NOT_PHYSICAL",
        "source_sha": SOURCE, "request_id": REQUEST,
        "factory_run_id": RUN_ID, "factory_artifact_id": ARTIFACT_ID,
        "factory_zip_sha256": ZIP_SHA,
        "exe_sha256": MEMBERS["candidate.exe"][1],
        "pck_sha256": MEMBERS["candidate.pck"][1],
        "manifest_sha256": MEMBERS["export-evidence.json"][1],
        "software_frames_verified": 7, "physical_screenshots_captured": 0,
        "physical_windows_gui": "HOLD", "human_30s": "HOLD", "human_90s": "HOLD",
        "identity_cas": "HOLD_36_OWNER", "sale_ready": False,
        "store_submission_allowed": False,
    }, "handoff receipt drift or false physical/Store claim")
    need(baseline["software_screenshot_sha256_count"] == 7, "seven software images required")
    return handoff


def build(archive, preflight_path, runtime_receipt, screenshot_dir, destination):
    need(not destination.exists(), "refuse to overwrite existing handoff directory")
    verified = verify_archive(archive)
    preflight = load(preflight_path)
    need(preflight == verified, "byte-preflight does not match original Factory ZIP")
    software = load(runtime_receipt)
    verify_software_baseline(software, screenshot_dir)
    need(software["source_sha"] == SOURCE and software["request_id"] == REQUEST and
         software["zip_sha256"] == ZIP_SHA, "old source/request/software receipt")
    destination.mkdir(parents=True)
    shutil.copyfile(archive, destination / "factory-original.zip")
    with zipfile.ZipFile(archive) as z:
        for name in MEMBERS:
            (destination / name).write_bytes(z.read(name))
    software_dest = destination / "qa11" / "screenshots"
    software_dest.mkdir(parents=True)
    shutil.copyfile(runtime_receipt, destination / "qa11" / "pck-runtime-independent-receipt.json")
    for name in FRAMES:
        shutil.copyfile(screenshot_dir / (name + ".png"), software_dest / (name + ".png"))
    for name in FILES:
        shutil.copyfile(Path(__file__).resolve().parent / name, destination / name)
    (destination / "physical-frames").mkdir()
    (destination / "physical-capture-TEMPLATE.json").write_text(
        json.dumps(capture_template(), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    handoff = {
        "schema_version": 1, "status": "EXACT_PR21_BINARY_HANDOFF_VERIFIED_NOT_PHYSICAL",
        "source_sha": SOURCE, "request_id": REQUEST,
        "factory_run_id": RUN_ID, "factory_artifact_id": ARTIFACT_ID,
        "factory_zip_sha256": ZIP_SHA,
        "exe_sha256": MEMBERS["candidate.exe"][1],
        "pck_sha256": MEMBERS["candidate.pck"][1],
        "manifest_sha256": MEMBERS["export-evidence.json"][1],
        "software_frames_verified": 7, "physical_screenshots_captured": 0,
        "physical_windows_gui": "HOLD", "human_30s": "HOLD", "human_90s": "HOLD",
        "identity_cas": "HOLD_36_OWNER", "sale_ready": False,
        "store_submission_allowed": False,
    }
    (destination / "handoff-receipt.json").write_text(
        json.dumps(handoff, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (destination / "README-PHYSICAL-QA.txt").write_text(INSTRUCTIONS, encoding="utf-8")
    (destination / "launch-verified.ps1").write_text(LAUNCHER, encoding="utf-8")
    return check_handoff(destination)


INSTRUCTIONS = """PRISM ROUTE 3D - PR21 EXACT-BINARY PHYSICAL WINDOWS QA (READ-ONLY)

Do not run an unsigned MSIX or bypass Code Integrity, SmartScreen or other security.
This bundle is not a signed MSIX, Store candidate or approval. Only execute if the
normal Windows policy allows candidate.exe. A block means DEFERRED_LOCAL_GATE.

1. Unzip the CI handoff Artifact to a local folder, retaining all filenames.
2. Install Python 3.10+ if available; in PowerShell from that folder:
   py -3 .\\prism_pr21_physical_handoff.py --verify .
   This rechecks original Factory ZIP SHA/CRC, exact EXE/PCK/manifest, source,
   request, seven independent Godot screenshots and the hold-only template.
3. Run .\\launch-verified.ps1 ONLY if normal Windows security allows the EXE.
   It rechecks hashes and starts candidate.exe with candidate.pck alongside.
4. For JA/125%, JA/150%, EN/125%, EN/150%, set Windows display 1024x768
   and corresponding scaling. Each is a fresh uncoached first-launch session.
   Record 30-second goal comprehension, Start-before-clock, tower 1->2->3,
   yellow warning/red scan, time/warp traps, outcome, retry, real 90 seconds.
   Record Windows build, actual tester and timezone-aware wall-clock timestamps.
   Do not manufacture answers, manipulate time or replace missing screenshots.
5. Copy physical-capture-TEMPLATE.json to physical-capture.json; fill real
   observations and paths. Save 6 DISTINCT 1024x768 PNGs per session in
   physical-frames/ using the exact 24 names in the template.
6. Run on the SAME physical Windows computer:
   py -3 .\\prism_first30s_physical_windows_gate.py --software-receipt .\\qa11\\pck-runtime-independent-receipt.json --software-screenshot-dir .\\qa11\\screenshots --capture .\\physical-capture.json --screenshot-dir .\\physical-frames --out .\\physical-review-receipt.json
   Missing evidence fails closed. Even a passing receipt is REVIEW_REQUIRED,
   never human fun PASS, SALE_READY or Store submission.

The 7 included PNGs are CLOUD SOFTWARE RENDER ONLY, not physical Windows.
Historical PR20 and old Identity commit 11417b7 do not authenticate this revision.
Only 36-owner may change central ledger/Identity CAS/Version/Partner Center.
"""

LAUNCHER = """# Read-only EXE/PCK launch; NEVER change Windows security policy.
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
py -3 .\\prism_pr21_physical_handoff.py --verify .
if ($LASTEXITCODE -ne 0) { throw 'HOLD: immutable binary handoff failed verification' }
$exe = (Resolve-Path .\\candidate.exe).Path
$pck = (Resolve-Path .\\candidate.pck).Path
if ((Get-FileHash $exe -Algorithm SHA256).Hash.ToLowerInvariant() -ne '66b26ad96df7458ea917b632a73ac7c88bb058db24dbd11a457fd50435ab7b13') { throw 'EXE SHA mismatch' }
if ((Get-FileHash $pck -Algorithm SHA256).Hash.ToLowerInvariant() -ne 'a27c198ff4bdaa961780b4e42d5fb429c328c5bad0b5cb816e399c06e3fd8cb9') { throw 'PCK SHA mismatch' }
Write-Host 'Exact PR21 bytes verified; starting only under existing Windows security policy.'
Start-Process -FilePath $exe -WorkingDirectory $PSScriptRoot -Wait
"""


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--verify", type=Path)
    modes.add_argument("--build", type=Path, help="new output directory")
    parser.add_argument("--archive", type=Path)
    parser.add_argument("--preflight", type=Path)
    parser.add_argument("--software-receipt", type=Path)
    parser.add_argument("--screenshots", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.verify is not None:
            result = check_handoff(args.verify)
        else:
            need(all(x is not None for x in (args.archive, args.preflight,
                                             args.software_receipt, args.screenshots)),
                 "build needs archive, preflight, software receipt and screenshots")
            result = build(args.archive, args.preflight, args.software_receipt,
                           args.screenshots, args.build)
    except (OSError, ValueError, KeyError, TypeError, zipfile.BadZipFile) as exc:
        print(json.dumps({"status": "HANDOFF_HOLD", "reason": str(exc)[:240],
                          "sale_ready": False, "store_submission_allowed": False}))
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
