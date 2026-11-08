"""Bind PR25's seven Godot software frames to its immutable product bytes.

This is a read-only QA bridge. It never establishes physical Windows,
human play, Identity CAS, Store eligibility, or SALE_READY.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from prism_first30s_physical_windows_gate import check_png

SOURCE = "e8c77192a06527b005168359433f2868ff86708e"
REQUEST = "3d-prism-route-3d-e8c77192a065"
FACTORY_RUN_ID = 42475405044
FACTORY_ARTIFACT_ID = 13614249496
QA_RUN_ID = 41472861586
QA_ARTIFACT_ID = 13156640316
ZIP_SHA = "dea496bfd9352b8aceeb4b0ff9e01aa4784307569d04fa08da2c2bbfd55448c1"
EXE_SHA = "66b26ad96df7458ea917b632a73ac7c88bb058db24dbd11a457fd50435ab7b13"
PCK_SHA = "c4f36ed505dc447a5977d9cd5e1ed68d78d089d8b502184647acf44370261630"
MANIFEST_SHA = "29fc410de25d6e95ec987e6e2a889660496efb67cfdfc21d693996695be799fe"
FRAMES = ("guide_en", "guide_ja", "initial", "scan", "trap", "win", "ja")
ASSERTIONS = {"bilingual_start_guide", "bilingual_hint_single_line_1024",
              "clock_frozen_until_start", "tower_order_1_2_3", "next_tower_hud",
              "sentinel_telegraph_and_hit", "time_and_warp_trap", "pause",
              "win", "timeout", "restart", "english_japanese",
              "board_visible_1024x768", "hud_contrast_and_type", "first_30s_goal"}


class SoftwareBaselineHold(ValueError):
    pass


def need(ok: bool, why: str) -> None:
    if not ok:
        raise SoftwareBaselineHold(why)


def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        need(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def verify_software_baseline(receipt: dict, screenshots: Path) -> dict:
    """Check one QA receipt and its seven actual PNG files, not provenance."""
    need(isinstance(receipt, dict), "invalid software receipt")
    expected = {
        "schema_version": 1,
        "receipt_type": "PRISM_CONSUMER_REAL_ARTIFACT_RUNTIME_PREFLIGHT",
        "status": "PCK_LOADED_SOFTWARE_RUNTIME_QA_PASS_NOT_HUMAN_GUI",
        "source_sha": SOURCE, "factory_build_head": SOURCE,
        "request_id": REQUEST, "factory_run_id": FACTORY_RUN_ID,
        "factory_artifact_id": FACTORY_ARTIFACT_ID,
        "zip_sha256": ZIP_SHA, "exe_sha256": EXE_SHA,
        "pck_sha256": PCK_SHA, "manifest_sha256": MANIFEST_SHA,
        "archive_bytes_verified_this_run": True,
        "godot_pck_executed_this_run": True,
        "japanese_font_glyphs_available": True,
        "physical_windows_gui": "DEFERRED_LOCAL_GATE",
        "human_first_30s_readability": "HOLD",
        "human_90s_gameplay": "HOLD",
        "dpi_125_150": "HOLD",
        "identity_cas": "HOLD_36_OWNER",
        "sale_ready": False, "store_submission_allowed": False,
    }
    for key, value in expected.items():
        need(type(receipt.get(key)) is type(value) and receipt.get(key) == value,
             "SOFTWARE_BASELINE_HOLD: " + key)
    need(set(receipt.get("godot_4_3_runtime_assertions", [])) == ASSERTIONS,
         "SOFTWARE_BASELINE_HOLD: missing or extra PCK assertions")
    bounds = receipt.get("board_colored_bounds")
    need(isinstance(bounds, dict) and type(bounds.get("width")) is int and
         type(bounds.get("height")) is int and bounds["width"] >= 420 and
         bounds["height"] >= 290, "SOFTWARE_BASELINE_HOLD: board geometry")
    frames = receipt.get("software_rendered_screenshots")
    need(isinstance(frames, dict) and set(frames) == set(FRAMES),
         "SOFTWARE_BASELINE_HOLD: seven frames required")
    hashes = set()
    for name in FRAMES:
        meta = frames[name]
        need(isinstance(meta, dict) and set(meta) == {"sha256", "bytes", "width", "height"} and
             type(meta["bytes"]) is int and meta["bytes"] > 1024 and
             type(meta["width"]) is int and meta["width"] == 1024 and
             type(meta["height"]) is int and meta["height"] == 768,
             "SOFTWARE_BASELINE_HOLD: frame metadata " + name)
        path = screenshots / (name + ".png")
        need(path.is_file() and not path.is_symlink(),
             "SOFTWARE_BASELINE_HOLD: missing frame " + name)
        need(path.stat().st_size == meta["bytes"],
             "SOFTWARE_BASELINE_HOLD: frame byte length " + name)
        digest = check_png(path)
        need(digest == meta["sha256"],
             "SOFTWARE_BASELINE_HOLD: frame digest / language-state mix " + name)
        need(digest not in hashes, "SOFTWARE_BASELINE_HOLD: duplicate frames")
        hashes.add(digest)
    return {
        "status": "PR25_SOFTWARE_BASELINE_BYTES_VERIFIED_NOT_PHYSICAL",
        "source_sha": SOURCE, "request_id": REQUEST,
        "factory_artifact_id": FACTORY_ARTIFACT_ID,
        "exe_sha256": EXE_SHA, "pck_sha256": PCK_SHA,
        "software_screenshot_sha256_count": len(hashes),
        "physical_windows_gui": "HOLD", "human_first_30s": "HOLD",
        "human_real_time_90s": "HOLD", "dpi_125_150": "HOLD",
        "identity_cas": "HOLD_36_OWNER", "sale_ready": False,
        "store_submission_allowed": False,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receipt", required=True, type=Path)
    parser.add_argument("--screenshot-dir", required=True, type=Path)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args(argv)
    try:
        receipt = json.loads(args.receipt.read_text(encoding="utf-8"),
                             object_pairs_hook=unique_pairs)
        result = verify_software_baseline(receipt, args.screenshot_dir)
        code = 0
    except (OSError, ValueError, TypeError, KeyError) as exc:
        result = {"status": "SOFTWARE_BASELINE_HOLD", "reason": str(exc)[:240],
                  "sale_ready": False, "store_submission_allowed": False}
        code = 2
    data = json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if args.out:
        args.out.write_text(data, encoding="utf-8")
    print(data, end="")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
