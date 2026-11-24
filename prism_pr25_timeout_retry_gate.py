"""Two additional defeat/retry screenshots from the SAME immutable PR25 PCK.

This is a software-rendered state transition receipt only. Existing seven-frame
baseline and the separate physical/human QA gate remain unchanged.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from prism_consumer_artifact_runtime_gate import (
    SOURCE, REQUEST, ARTIFACT_ID, RUN_ID, ZIP_SHA, MEMBERS, unique_pairs,
)
from prism_first30s_physical_windows_gate import check_png
from prism_pr25_software_baseline_gate import (
    FRAMES, verify_software_baseline,
)

NEW_FRAMES = ("timeout_ja", "retry_ja")
EXPECTED_STATES = {
    "capture_kind": "GODOT_4_3_SOFTWARE_RENDER_TIME_ADVANCED_NOT_HUMAN",
    "timeout_status": "failed",
    "timeout_language": "ja",
    "timeout_reason": "時間切れ",
    "timeout_remaining_seconds": 0,
    "retry_status": "playing",
    "retry_language": "ja",
    "retry_next_target": 0,
    "retry_remaining_seconds": 90,
    "frame_names": list(NEW_FRAMES),
}


class TimeoutRetryHold(ValueError):
    pass


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise TimeoutRetryHold(reason)


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique_pairs)


def verify(preflight: dict, runtime: dict, baseline: dict, screenshots: Path) -> dict:
    """Require byte-bound Godot runtime assertions plus nine distinct valid PNGs."""
    require(isinstance(preflight, dict) and isinstance(runtime, dict)
            and isinstance(baseline, dict), "missing provenance/receipt")
    expected = {
        "source_sha": SOURCE, "request_id": REQUEST,
        "factory_run_id": RUN_ID, "factory_artifact_id": ARTIFACT_ID,
        "zip_sha256": ZIP_SHA, "exe_sha256": MEMBERS["candidate.exe"][1],
        "pck_sha256": MEMBERS["candidate.pck"][1],
        "manifest_sha256": MEMBERS["export-evidence.json"][1],
    }
    for key, value in expected.items():
        require(preflight.get(key) == value and baseline.get(key) == value,
                "PROVENANCE_HOLD: " + key)
    require(preflight.get("receipt_type") == "PRISM_CONSUMER_REAL_ARTIFACT_RUNTIME_PREFLIGHT"
            and preflight.get("status") == "EXACT_FACTORY_BYTES_VERIFIED_RUNTIME_PENDING"
            and preflight.get("archive_bytes_verified_this_run") is True
            and preflight.get("godot_pck_executed_this_run") is False,
            "PROVENANCE_HOLD: original Factory ZIP was not independently verified")
    require(runtime.get("source_sha") == SOURCE and runtime.get("request_id") == REQUEST
            and runtime.get("pck_sha256") == MEMBERS["candidate.pck"][1]
            and runtime.get("runtime_kind") == "GODOT_4_3_EXPORTED_PCK_LOADED_SOFTWARE_RENDER"
            and runtime.get("status") == "PASS_PCK_LOADED_LOGIC_AND_RENDER"
            and runtime.get("physical_windows_gui") == "DEFERRED_LOCAL_GATE"
            and runtime.get("sale_ready") is False,
            "RUNTIME_HOLD: actual compiled PR25 PCK evidence missing")
    require(runtime.get("timeout_retry_states") == EXPECTED_STATES,
            "STATE_HOLD: timeout/retry not both observed in exported PCK")
    require({"timeout", "restart", "english_japanese"} <= set(runtime.get("assertions", [])),
            "STATE_HOLD: runtime assertions missing")
    require(baseline.get("status") == "PCK_LOADED_SOFTWARE_RUNTIME_QA_PASS_NOT_HUMAN_GUI"
            and baseline.get("godot_pck_executed_this_run") is True
            and baseline.get("physical_windows_gui") == "DEFERRED_LOCAL_GATE"
            and baseline.get("human_first_30s_readability") == "HOLD"
            and baseline.get("human_90s_gameplay") == "HOLD"
            and baseline.get("sale_ready") is False
            and baseline.get("store_submission_allowed") is False,
            "BASELINE_HOLD: false physical/human/Store claim")
    verified = verify_software_baseline(baseline, screenshots)
    require(verified["software_screenshot_sha256_count"] == 7,
            "BASELINE_HOLD: original seven frames lost")
    original = baseline.get("software_rendered_screenshots", {})
    require(set(original) == set(FRAMES), "BASELINE_HOLD: seven original names drift")
    hashes = {original[name]["sha256"] for name in FRAMES}
    require(len(hashes) == 7, "BASELINE_HOLD: original duplicate frames")
    frames = {}
    for name in NEW_FRAMES:
        path = screenshots / (name + ".png")
        require(path.is_file() and not path.is_symlink(), "SCREENSHOT_HOLD: missing " + name)
        require(path.stat().st_size > 4096, "SCREENSHOT_HOLD: too small " + name)
        digest = check_png(path)  # 1024x768, PNG chunk CRC, complete IEND
        require(digest not in hashes, "SCREENSHOT_HOLD: copied or duplicate state " + name)
        hashes.add(digest)
        frames[name] = {
            "sha256": digest, "bytes": path.stat().st_size,
            "width": 1024, "height": 768,
            "state": "failed" if name == "timeout_ja" else "playing_after_defeat",
            "language": "ja",
        }
    require(len(hashes) == 9, "SCREENSHOT_HOLD: nine distinct real PCK frames required")
    return {
        "schema_version": 1,
        "status": "PR25_EXACT_PCK_TIMEOUT_RETRY_TWO_STATES_VERIFIED_NOT_PHYSICAL",
        **expected,
        "capture_kind": EXPECTED_STATES["capture_kind"],
        "state_transitions": ["failed_timeout_ja", "playing_after_defeat_retry_ja"],
        "original_software_frames_verified": 7,
        "new_software_frames_verified": frames,
        "all_software_frame_sha256_count": 9,
        "physical_windows_gui": "HOLD",
        "human_first_30s": "HOLD",
        "human_real_time_90s": "HOLD",
        "identity_cas": "HOLD_36_OWNER",
        "sale_ready": False,
        "store_submission_allowed": False,
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--preflight", type=Path, required=True)
    ap.add_argument("--runtime", type=Path, required=True)
    ap.add_argument("--baseline-receipt", type=Path, required=True)
    ap.add_argument("--screenshot-dir", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args(argv)
    try:
        result = verify(load(args.preflight), load(args.runtime),
                        load(args.baseline_receipt), args.screenshot_dir)
        status = 0
    except (OSError, ValueError, KeyError, TypeError) as exc:
        result = {"status": "TIMEOUT_RETRY_HOLD", "reason": str(exc)[:240],
                  "sale_ready": False, "store_submission_allowed": False}
        status = 2
    args.out.write_text(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2)
                        + "\n", encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))
    return status


if __name__ == "__main__":
    raise SystemExit(main())
