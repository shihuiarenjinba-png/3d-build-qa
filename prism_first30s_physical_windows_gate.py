"""Check-only physical Windows acceptance evidence for Prism Route 3D.

No fixture/cloud screenshot can grant SALE_READY. Even complete operator evidence
only yields REVIEW_REQUIRED: a human must verify genuine physical capture.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path
import platform
import struct
import zlib

SOURCE = "0878f48c79073596e30fed37a5703e0826389862"
REQUEST = "3d-prism-route-3d-0878f48c7907"
ARTIFACT_ID = 13142680551
EXE_SHA = "66b26ad96df7458ea917b632a73ac7c88bb058db24dbd11a457fd50435ab7b13"
PCK_SHA = "4036486c320c858b06a43ce632d063a6ab034f273b5f70e7861a5b663d1406fc"
SCREENSHOTS = ("guide", "active", "scan_warning", "trap", "outcome", "retry")
OBSERVATIONS = (
    "goal_understood_in_30s", "tower_order_1_2_3_understood",
    "controls_understood", "sentinel_colors_understood", "traps_understood",
    "start_action_understood", "clock_frozen_until_start",
    "no_clipping", "no_debug_ui", "failure_reason_understood",
    "retry_completed",
)


class PhysicalGateHold(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise PhysicalGateHold(message)


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def timestamp(value: str) -> dt.datetime:
    try:
        parsed = dt.datetime.fromisoformat(value)
    except (TypeError, ValueError):
        raise PhysicalGateHold("invalid capture timestamp") from None
    require(parsed.tzinfo is not None and parsed.utcoffset() is not None,
            "timezone required for capture timestamp")
    return parsed


def check_png(path: Path) -> str:
    require(path.is_file() and not path.is_symlink(), "missing or symlink screenshot")
    data = path.read_bytes()
    require(len(data) > 1024 and data[:8] == b"\x89PNG\r\n\x1a\n",
            "invalid screenshot PNG")
    pos, dimensions, idat, ended = 8, None, False, False
    while pos < len(data):
        require(pos + 12 <= len(data), "truncated PNG")
        size = struct.unpack_from(">I", data, pos)[0]
        require(size <= 30_000_000 and pos + 12 + size <= len(data), "unsafe PNG chunk")
        kind = data[pos + 4:pos + 8]
        payload = data[pos + 8:pos + 8 + size]
        crc = struct.unpack_from(">I", data, pos + 8 + size)[0]
        require((zlib.crc32(kind + payload) & 0xffffffff) == crc, "PNG CRC mismatch")
        if kind == b"IHDR":
            require(dimensions is None and size == 13, "bad PNG header")
            dimensions = struct.unpack_from(">II", payload)
        elif kind == b"IDAT":
            idat = True
        elif kind == b"IEND":
            require(size == 0 and pos + 12 == len(data), "PNG trailing bytes")
            ended = True
            break
        pos += 12 + size
    require(dimensions == (1024, 768) and idat and ended,
            "screenshot must be complete 1024x768 PNG")
    return hashlib.sha256(data).hexdigest()


def evaluate(capture: dict, screenshot_dir: Path, *, windows_host: bool) -> dict:
    """Validate evidence, never attest that screenshots came from a physical GPU."""
    require(windows_host, "DEFERRED_LOCAL_GATE: physical Windows execution not available")
    require(capture.get("schema_version") == 1 and
            capture.get("capture_kind") == "PHYSICAL_WINDOWS_OPERATOR_ATTESTATION",
            "invalid physical capture schema")
    require(capture.get("source_sha") == SOURCE and capture.get("request_id") == REQUEST and
            capture.get("factory_artifact_id") == ARTIFACT_ID and
            capture.get("exe_sha256") == EXE_SHA and capture.get("pck_sha256") == PCK_SHA,
            "PROVENANCE_HOLD: source/request/EXE/PCK mismatch")
    require(capture.get("physical_device") is True and
            isinstance(capture.get("operator"), str) and len(capture["operator"].strip()) >= 3 and
            isinstance(capture.get("windows_build"), str) and len(capture["windows_build"].strip()) >= 5,
            "operator and physical Windows machine attestation required")
    for key, expected in (("exe_path", EXE_SHA), ("pck_path", PCK_SHA)):
        raw = capture.get(key)
        require(isinstance(raw, str) and bool(raw), "missing " + key)
        path = Path(raw)
        require(path.is_file() and not path.is_symlink() and digest(path) == expected,
                "PROVENANCE_HOLD: exact " + key + " bytes missing")
    sessions = capture.get("sessions")
    require(isinstance(sessions, list) and len(sessions) == 4,
            "require JA and EN at both 125% and 150%")
    seen, hashes = set(), set()
    for session in sessions:
        require(isinstance(session, dict), "invalid session")
        lang, dpi = session.get("language"), session.get("dpi_percent")
        require(lang in ("ja", "en") and type(dpi) is int and dpi in (125, 150),
                "unexpected language or DPI")
        require((lang, dpi) not in seen, "duplicate language/DPI session")
        seen.add((lang, dpi))
        require(session.get("resolution") == [1024, 768], "physical resolution mismatch")
        start = timestamp(session.get("capture_started_at"))
        finish = timestamp(session.get("capture_finished_at"))
        require(90 <= (finish - start).total_seconds() <= 1800,
                "human session must span actual 90 seconds")
        require(type(session.get("elapsed_play_seconds")) in (int, float) and
                90 <= session["elapsed_play_seconds"] <= (finish - start).total_seconds(),
                "simulated 90-second clock cannot count as human play")
        require(type(session.get("first_goal_seconds")) in (int, float) and
                0 <= session["first_goal_seconds"] <= 30,
                "first goal must be understood within 30 seconds")
        for field in OBSERVATIONS:
            require(session.get(field) is True, "CONSUMER_QA_HOLD: " + field)
        require(session.get("start_pressed") is True and
                session.get("uncoached_first_launch") is True,
                "first launch must be uncoached and explicitly started")
        screenshots = session.get("screenshots")
        require(isinstance(screenshots, dict) and set(screenshots) == set(SCREENSHOTS),
                "missing required physical screenshot states")
        for state in SCREENSHOTS:
            name = screenshots[state]
            require(isinstance(name, str) and Path(name).name == name and
                    name.endswith(".png") and name not in (".png", "..png"),
                    "unsafe screenshot name")
            h = check_png(screenshot_dir / name)
            require(h not in hashes, "duplicate frames cannot prove distinct gameplay states")
            hashes.add(h)
    require(seen == {(lang, dpi) for lang in ("ja", "en") for dpi in (125, 150)},
            "missing language/DPI coverage")
    return {
        "schema_version": 1,
        "status": "PHYSICAL_QA_EVIDENCE_REVIEW_REQUIRED",
        "source_sha": SOURCE, "request_id": REQUEST, "factory_artifact_id": ARTIFACT_ID,
        "exe_sha256": EXE_SHA, "pck_sha256": PCK_SHA,
        "operator_attested_sessions": 4, "physical_screenshot_sha256_count": len(hashes),
        "human_review_required": True, "physical_gui_automatically_proven": False,
        "identity_cas": "HOLD_36_OWNER", "package_version": "HOLD",
        "signed_product_msix": "HOLD", "sale_ready": False,
        "store_submission_allowed": False,
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture", type=Path, required=True)
    parser.add_argument("--screenshot-dir", type=Path, required=True)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args(argv)
    try:
        capture = json.loads(args.capture.read_text(encoding="utf-8"))
        result = evaluate(capture, args.screenshot_dir,
                          windows_host=platform.system() == "Windows")
        code = 0
    except (OSError, ValueError, TypeError, KeyError) as error:
        result = {
            "status": "DEFERRED_LOCAL_GATE",
            "reason": str(error)[:240],
            "sale_ready": False, "store_submission_allowed": False,
            "human_review_required": True,
        }
        code = 2
    payload = json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if args.out:
        args.out.write_text(payload, encoding="utf-8")
    print(payload, end="")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
