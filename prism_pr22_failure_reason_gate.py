"""Fail-closed independent byte and software-rendered QA for Factory PR22.

This module never validates a physical Windows GUI, a human player, Identity,
package version, MSIX, Store eligibility, or SALE_READY. PR21 images are not PR22 evidence.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import stat
import zipfile
from pathlib import Path

from prism_first30s_physical_windows_gate import check_png
from prism_sentinel_release_pck_content_gate import parse_pck, prohibited_resource

SOURCE = "f4b458384243fdf379683ca793329614f61c9ead"
REQUEST = "3d-prism-route-3d-f4b458384243"
RUN_ID = 41528683539
ARTIFACT_ID = 13180284133
ZIP_SHA = "71ff9fca61ea310939f777a8c29cf93a57f25e19237ceb0fe1cacdbe3b977785"
ZIP_SIZE = 37794728
MEMBERS = {
    "candidate.exe": (84214784, "66b26ad96df7458ea917b632a73ac7c88bb058db24dbd11a457fd50435ab7b13"),
    "candidate.pck": (6983776, "d1363805e4f899b0a895b6c4153f3fc902d548529c0cc47579b965666fcd98ec"),
    "export-evidence.json": (669, "aea18d476ec7cc0a54c38a46fdbb78639d45ed3d0e55ec5814e46751cacdd2bb"),
}
OLD_PCKS = {
    "a27c198ff4bdaa961780b4e42d5fb429c328c5bad0b5cb816e399c06e3fd8cb9",
    "10acb61a586caa55b2da59ed0aae62f0952cfbaf7a69cac3cf219f3ae2a982c9",
}
EXPECTED_HINTS = {
    "timeout_en": "Time up. Reach towers 1→2→3 faster; retry.",
    "timeout_ja": "時間切れ。塔1→2→3の順に急いで再挑戦。",
    "trap_en": "Trap drained the clock. Avoid orange/purple tiles; retry.",
    "trap_ja": "罠で時間切れ。橙・紫のマスを避けて再挑戦。",
    "sentinel_en": "Sentinel scan ended the run. Avoid the warning lane; retry.",
    "sentinel_ja": "Sentinel照射で時間切れ。予告帯を避けて再挑戦。",
}
FRAMES = tuple(EXPECTED_HINTS) + ("retry_en", "retry_ja")
EXPECTED_REASONS = {"timeout": "timeout", "trap": "trap", "sentinel": "sentinel", "retry": ""}


class PR22Hold(ValueError):
    pass


def require(ok, reason):
    if not ok:
        raise PR22Hold(reason)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique_pairs)


def verify_archive(path: Path, extract_to: Path | None = None) -> dict:
    require(path.is_file() and not path.is_symlink(), "missing Factory ZIP")
    require(path.stat().st_size == ZIP_SIZE, "ZIP size mismatch / PR21 reuse")
    require(sha(path.read_bytes()) == ZIP_SHA, "ZIP SHA mismatch / historical revision")
    with zipfile.ZipFile(path) as z:
        infos = z.infolist()
        require(len(infos) == 3 and {x.filename for x in infos} == set(MEMBERS),
                "ZIP members missing, duplicate or extra")
        for x in infos:
            require(not x.is_dir() and not x.flag_bits & 1
                    and not stat.S_ISLNK(x.external_attr >> 16), "unsafe ZIP member")
            size, digest = MEMBERS[x.filename]
            require(x.file_size == size and sha(z.read(x)) == digest,
                    "independent EXE/PCK/manifest byte mismatch: " + x.filename)
        require(z.testzip() is None, "ZIP CRC failure")
        m = json.loads(z.read("export-evidence.json"), object_pairs_hook=unique_pairs)
        expected = {
            "schema_version": 1, "slug": "prism-route-3d", "product_type": "GAME_3D",
            "source_repository": "shihuiarenjinba-png/3d-game-factory",
            "source_branch": "codex/prism-failure-cause-20261103",
            "source_sha": SOURCE, "factory_build_head": SOURCE, "request_id": REQUEST,
        }
        for k, v in expected.items():
            require(m.get(k) == v, "manifest source/request mismatch: " + k)
        for kind in ("exe", "pck"):
            name = "candidate." + kind
            require(m.get(kind + "_path") == name
                    and m.get(kind + "_sha256") == MEMBERS[name][1]
                    and m.get(kind + "_size_bytes") == MEMBERS[name][0],
                    "manifest member mismatch: " + kind)
        pck = z.read("candidate.pck")
        require(sha(pck) not in OLD_PCKS, "old PR20/PR21 PCK forbidden")
        entries = parse_pck(pck)
        paths = {x["path"] for x in entries}
        required = {"res://project.binary", "res://scenes/main.tscn.remap",
                    "res://scripts/main.gdc", "res://scripts/game_logic.gdc"}
        require(len(entries) == 14 and required <= paths
                and not any(prohibited_resource(x["path"]) for x in entries),
                "compiled PCK resource inventory invalid")
        if extract_to is not None:
            require(not extract_to.exists() or not any(extract_to.iterdir()),
                    "refuse overwrite of existing extracted files")
            extract_to.mkdir(parents=True, exist_ok=True)
            for name in MEMBERS:
                (extract_to / name).write_bytes(z.read(name))
    return {
        "status": "PR22_EXACT_FACTORY_BYTES_VERIFIED_RUNTIME_PENDING",
        "source_sha": SOURCE, "request_id": REQUEST,
        "factory_run_id": RUN_ID, "factory_artifact_id": ARTIFACT_ID,
        "zip_sha256": ZIP_SHA, "zip_size_bytes": ZIP_SIZE,
        "exe_sha256": MEMBERS["candidate.exe"][1],
        "pck_sha256": MEMBERS["candidate.pck"][1],
        "manifest_sha256": MEMBERS["export-evidence.json"][1],
        "zip_crc_verified": True, "pck_resource_count": len(entries),
        "physical_windows_gui": "HOLD", "human_first_30s": "HOLD",
        "human_real_time_90s": "HOLD", "identity_cas": "HOLD_36_OWNER",
        "sale_ready": False, "store_submission_allowed": False,
    }


def verify_runtime(preflight: dict, runtime: dict, screenshots: Path) -> dict:
    require(preflight.get("status") == "PR22_EXACT_FACTORY_BYTES_VERIFIED_RUNTIME_PENDING",
            "missing verified Factory ZIP preflight")
    provenance = {"source_sha": SOURCE, "request_id": REQUEST,
                  "pck_sha256": MEMBERS["candidate.pck"][1]}
    for key, value in provenance.items():
        require(preflight.get(key) == value and runtime.get(key) == value,
                "PR22 lineage mismatch: " + key)
    require(preflight.get("zip_sha256") == ZIP_SHA
            and preflight.get("zip_crc_verified") is True
            and preflight.get("exe_sha256") == MEMBERS["candidate.exe"][1]
            and preflight.get("manifest_sha256") == MEMBERS["export-evidence.json"][1],
            "Factory archive evidence incomplete")
    require(runtime.get("runtime_kind") == "GODOT_4_3_PR22_EXPORTED_PCK_SOFTWARE_RENDER"
            and runtime.get("status") == "PASS_PCK_CAUSE_SPECIFIC_STATES"
            and runtime.get("capture_kind") == "GODOT_MESA_XVFB_TIME_ADVANCED_NOT_HUMAN"
            and runtime.get("physical_windows_gui") == "HOLD"
            and runtime.get("human_real_time_90s") == "HOLD"
            and runtime.get("sale_ready") is False
            and runtime.get("store_submission_allowed") is False,
            "runtime evidence cannot assert physical/human/Store PASS")
    states = runtime.get("states")
    require(isinstance(states, dict) and set(states) == set(FRAMES),
            "eight bilingual states required")
    require(runtime.get("stale_trap_event_timeout_checked") is True,
            "stale trap event must not relabel natural TIMEOUT")
    hashes = set()
    frames = {}
    for name in FRAMES:
        state = states[name]
        cause, language = name.split("_")
        require(isinstance(state, dict) and set(state) == {
            "status", "failure_reason", "language", "hint_text", "remaining_seconds", "next_target"
        }, "state receipt shape mismatch: " + name)
        require(state["status"] == ("playing" if cause == "retry" else "failed")
                and state["failure_reason"] == EXPECTED_REASONS[cause]
                and state["language"] == language and type(state["remaining_seconds"]) is int
                and type(state["next_target"]) is int,
                "state reason/language mismatch: " + name)
        if cause == "retry":
            require(state["remaining_seconds"] == 90 and state["next_target"] == 0
                    and ("1→2→3" in state["hint_text"]),
                    "retry does not reset timer/tower: " + name)
        else:
            require(state["remaining_seconds"] == 0 and state["next_target"] == 0
                    and state["hint_text"] == EXPECTED_HINTS[name],
                    "failure advice not cause-specific: " + name)
        p = screenshots / (name + ".png")
        require(p.is_file() and not p.is_symlink() and p.stat().st_size > 4096,
                "missing/empty software image: " + name)
        digest = check_png(p)  # validates PNG CRC, IEND, 1024x768
        require(digest not in hashes, "reused/duplicate image: " + name)
        hashes.add(digest)
        frames[name] = {"sha256": digest, "bytes": p.stat().st_size,
                        "width": 1024, "height": 768, "state": cause, "language": language}
    require(len(hashes) == 8, "eight distinct actual PR22 PCK images required")
    return {
        **preflight,
        "status": "PR22_REAL_PCK_BILINGUAL_FAILURE_STATES_VERIFIED_NOT_PHYSICAL",
        "runtime_kind": runtime["runtime_kind"], "capture_kind": runtime["capture_kind"],
        "software_rendered_screenshots": frames,
        "software_frame_sha256_count": 8,
        "state_transitions": states,
        "stale_trap_event_timeout_checked": True,
        "physical_windows_gui": "HOLD", "human_first_30s": "HOLD",
        "human_real_time_90s": "HOLD", "dpi_125_150": "HOLD",
        "identity_cas": "HOLD_36_OWNER", "sale_ready": False,
        "store_submission_allowed": False,
    }


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--archive", type=Path)
    ap.add_argument("--extract-to", type=Path)
    ap.add_argument("--preflight", type=Path)
    ap.add_argument("--runtime", type=Path)
    ap.add_argument("--screenshots", type=Path)
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args(argv)
    try:
        if args.archive is not None:
            result = verify_archive(args.archive, args.extract_to)
        else:
            require(all((args.preflight, args.runtime, args.screenshots)),
                    "missing runtime input")
            result = verify_runtime(load_json(args.preflight), load_json(args.runtime),
                                    args.screenshots)
        code = 0
    except (OSError, ValueError, TypeError, KeyError, zipfile.BadZipFile) as e:
        result = {"status": "PR22_QA_HOLD", "reason": str(e)[:240],
                  "sale_ready": False, "store_submission_allowed": False}
        code = 2
    args.out.write_text(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2)
                        + "\n", encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
