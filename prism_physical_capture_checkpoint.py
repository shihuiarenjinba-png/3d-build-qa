"""Append-only, resumable checkpoints for genuine Prism physical Windows QA.

Completed sessions can be resumed only after their six PNG bytes, hashes,
language/DPI, wall-clock timing, operator attestation and exact PR25 tuple
are revalidated. Partial attempts are preserved and never promoted.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import struct
import zlib

from prism_consumer_artifact_runtime_gate import SOURCE, REQUEST, ARTIFACT_ID, MEMBERS

EXE_SHA = MEMBERS["candidate.exe"][1]
PCK_SHA = MEMBERS["candidate.pck"][1]
SESSION_KEYS = tuple(f"{lang}-{dpi}" for lang in ("ja", "en") for dpi in (100, 125, 150))
STATE_FILES = {
    "guide": "guide.png",
    "active": "active.png",
    "scan_warning": "scan.png",
    "trap": "trap.png",
    "outcome": "outcome.png",
    "retry": "retry.png",
}
OBSERVATIONS = (
    "goal_understood_in_30s",
    "tower_order_1_2_3_understood",
    "controls_understood",
    "sentinel_colors_understood",
    "traps_understood",
    "start_action_understood",
    "clock_frozen_until_start",
    "no_clipping",
    "no_debug_ui",
    "failure_reason_understood",
    "retry_completed",
)
ATTEMPT_ID_RE = re.compile(r"^[0-9a-f]{32}$")
SHA_RE = re.compile(r"^[0-9a-f]{64}$")


class CaptureHold(ValueError):
    pass


def need(condition: bool, reason: str) -> None:
    if not condition:
        raise CaptureHold(reason)


def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        need(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def load_json(path: Path) -> dict:
    need(path.is_file() and not path.is_symlink(), "missing or symlink JSON: " + str(path))
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique_pairs)


def json_bytes(value: dict) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")


def ensure_directory(path: Path) -> None:
    if path.exists() or path.is_symlink():
        need(path.is_dir() and not path.is_symlink(), "directory is not a real directory: " + str(path))
    else:
        path.mkdir()


def write_exclusive(path: Path, value: dict) -> None:
    ensure_directory(path.parent)
    data = json_bytes(value)
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        raise CaptureHold("refuse to overwrite existing bytes: " + str(path)) from None
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        try:
            path.unlink()
        except OSError:
            pass
        raise


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest(path: Path) -> str:
    need(path.is_file() and not path.is_symlink(), "missing or symlink file: " + str(path))
    hasher = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(block)
    return hasher.hexdigest()


def safe_relative(root: Path, raw: str) -> Path:
    need(isinstance(raw, str) and bool(raw) and "\\" not in raw, "unsafe relative path")
    relative = PurePosixPath(raw)
    need(not relative.is_absolute() and bool(relative.parts) and
         all(part not in ("", ".", "..") for part in relative.parts),
         "unsafe relative path")
    current = root
    for part in relative.parts:
        current = current / part
        need(not current.is_symlink(), "symlink path is not accepted: " + raw)
    return current


def check_png(path: Path) -> str:
    need(path.is_file() and not path.is_symlink(), "missing or symlink screenshot: " + str(path))
    data = path.read_bytes()
    need(1024 < len(data) <= 20_000_000 and data[:8] == b"\x89PNG\r\n\x1a\n",
         "invalid or oversized PNG: " + path.name)
    position = 8
    dimensions = None
    bit_depth = color_type = None
    compressed = bytearray()
    ended = False
    while position < len(data):
        need(position + 12 <= len(data), "truncated PNG")
        size = struct.unpack_from(">I", data, position)[0]
        need(size <= 20_000_000 and position + 12 + size <= len(data), "unsafe PNG chunk")
        kind = data[position + 4:position + 8]
        payload = data[position + 8:position + 8 + size]
        crc = struct.unpack_from(">I", data, position + 8 + size)[0]
        need((zlib.crc32(kind + payload) & 0xffffffff) == crc, "PNG CRC mismatch")
        if position == 8:
            need(kind == b"IHDR" and size == 13, "PNG IHDR must be first")
        if kind == b"IHDR":
            need(dimensions is None and size == 13, "invalid PNG IHDR")
            width, height, bit_depth, color_type, compression, filtering, interlace = struct.unpack(
                ">IIBBBBB", payload
            )
            dimensions = (width, height)
            need((compression, filtering, interlace) == (0, 0, 0), "unsupported PNG encoding")
        elif kind == b"IDAT":
            compressed.extend(payload)
        elif kind == b"IEND":
            need(size == 0 and position + 12 == len(data), "PNG IEND/trailing bytes mismatch")
            ended = True
            break
        position += 12 + size
    need(dimensions == (1024, 768) and bit_depth == 8 and color_type in (2, 6)
         and bool(compressed) and ended, "screenshot must be a complete 1024x768 RGB/RGBA PNG")
    try:
        raw = zlib.decompress(bytes(compressed))
    except zlib.error:
        raise CaptureHold("PNG image data cannot be decompressed") from None
    channels = 3 if color_type == 2 else 4
    need(len(raw) == 768 * (1 + 1024 * channels), "PNG pixel data length mismatch")
    return sha256_bytes(data)


def parse_timestamp(value: str) -> dt.datetime:
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, TypeError, ValueError):
        raise CaptureHold("invalid or missing timezone-aware timestamp") from None
    need(parsed.tzinfo is not None and parsed.utcoffset() is not None,
         "timezone required for every session timestamp")
    return parsed


def validate_tuple(value: dict) -> None:
    need(value.get("source_sha") == SOURCE and value.get("request_id") == REQUEST and
         value.get("factory_artifact_id") == ARTIFACT_ID and
         value.get("factory_artifact_expires_at") is None and
         value.get("exe_sha256") == EXE_SHA and value.get("pck_sha256") == PCK_SHA,
         "PROVENANCE_HOLD: source/request/Factory artifact/EXE/PCK tuple mismatch")


def validate_session(session: dict, root: Path) -> tuple[str, set[str]]:
    need(isinstance(session, dict) and session.get("schema_version") == 1,
         "invalid session checkpoint schema")
    validate_tuple(session)
    language = session.get("language")
    dpi = session.get("dpi_percent")
    need(language in ("ja", "en") and type(dpi) is int and dpi in (100, 125, 150),
         "unexpected language or DPI")
    key = f"{language}-{dpi}"
    need(session.get("session_key") == key, "session key/language/DPI mismatch")
    attempt_id = session.get("attempt_id")
    need(isinstance(attempt_id, str) and ATTEMPT_ID_RE.fullmatch(attempt_id),
         "invalid attempt identifier")
    expected_attempt = f"physical-session-attempts/{key}/{attempt_id}"
    need(session.get("attempt_dir") == expected_attempt, "attempt directory/source mismatch")
    attempt_dir = safe_relative(root, expected_attempt)
    need(attempt_dir.is_dir(), "session attempt directory missing")
    candidate_path = attempt_dir / "session.json"
    need(candidate_path.is_file() and not candidate_path.is_symlink(),
         "completed session candidate JSON missing")
    need(load_json(candidate_path) == session, "session candidate/checkpoint content mismatch")

    expected_dpi = int(96 * dpi / 100)
    need(session.get("actual_dpi") == expected_dpi, "actual game-window DPI mismatch")
    need(session.get("resolution") == [1024, 768], "physical resolution must be 1024x768")
    need(session.get("physical_device") is True, "physical Windows device attestation required")
    need(isinstance(session.get("operator"), str) and len(session["operator"].strip()) >= 3,
         "operator attestation missing")
    need(isinstance(session.get("windows_build"), str) and len(session["windows_build"].strip()) >= 5,
         "Windows build attestation missing")
    need(session.get("code_integrity_status") == "ALLOWED_BY_EXISTING_POLICY",
         "Code Integrity/SmartScreen normal-policy launch not attested")
    need(isinstance(session.get("exe_path"), str) and bool(session["exe_path"]) and
         isinstance(session.get("pck_path"), str) and bool(session["pck_path"]),
         "exact local EXE/PCK paths missing")

    capture_start = parse_timestamp(session.get("capture_started_at"))
    play_start = parse_timestamp(session.get("play_started_at"))
    play_finish = parse_timestamp(session.get("play_finished_at"))
    capture_finish = parse_timestamp(session.get("capture_finished_at"))
    capture_seconds = (capture_finish - capture_start).total_seconds()
    play_seconds = (play_finish - play_start).total_seconds()
    elapsed = session.get("elapsed_play_seconds")
    need(capture_start <= play_start <= play_finish <= capture_finish,
         "capture/play timestamps are not ordered")
    need(90 <= capture_seconds <= 1800 and 90 <= play_seconds <= 1800,
         "actual capture/play wall-clock duration must be 90-1800 seconds")
    need(type(elapsed) in (int, float) and math.isfinite(float(elapsed)) and
         90 <= float(elapsed) <= 1800 and abs(float(elapsed) - play_seconds) <= 2.0,
         "Stopwatch elapsed play time does not match the 90-second wall-clock interval")
    first_goal = session.get("first_goal_seconds")
    need(type(first_goal) in (int, float) and math.isfinite(float(first_goal)) and
         0 <= float(first_goal) <= 30, "first goal must be understood within 30 seconds")
    need(session.get("start_pressed") is True and
         session.get("uncoached_first_launch") is True,
         "uncoached first launch and actual Start press required")
    for field in OBSERVATIONS:
        need(session.get(field) is True, "CONSUMER_QA_HOLD: " + field)

    screenshots = session.get("screenshots")
    hashes = session.get("screenshot_sha256")
    need(isinstance(screenshots, dict) and set(screenshots) == set(STATE_FILES),
         "six required screenshot states missing")
    need(isinstance(hashes, dict) and set(hashes) == set(STATE_FILES),
         "six screenshot SHA256 values missing")
    expected_files = {"session.json", *STATE_FILES.values()}
    actual_files = set()
    for item in attempt_dir.iterdir():
        need(not item.is_symlink() and item.is_file(), "unexpected directory/symlink in session attempt")
        actual_files.add(item.name)
    need(actual_files == expected_files, "attempt must contain exactly session.json and six PNGs")
    seen_hashes = set()
    for state, filename in STATE_FILES.items():
        need(screenshots.get(state) == filename, "screenshot filename/state mismatch: " + state)
        expected_hash = hashes.get(state)
        need(isinstance(expected_hash, str) and SHA_RE.fullmatch(expected_hash),
             "invalid screenshot SHA256: " + state)
        actual_hash = check_png(attempt_dir / filename)
        need(actual_hash == expected_hash, "screenshot SHA256 mismatch: " + state)
        need(actual_hash not in seen_hashes, "duplicate screenshot bytes within a session")
        seen_hashes.add(actual_hash)
    return key, seen_hashes


def checkpoint_path(root: Path, key: str) -> Path:
    return root / "physical-checkpoints" / (key + ".json")


def checkpoint_payload(key: str, session: dict) -> dict:
    return {
        "schema_version": 1,
        "checkpoint_kind": "PRISM_PHYSICAL_WINDOWS_SESSION_CHECKPOINT",
        "session_key": key,
        "source_sha": SOURCE,
        "request_id": REQUEST,
        "factory_artifact_id": ARTIFACT_ID,
        "factory_artifact_expires_at": None,
        "exe_sha256": EXE_SHA,
        "pck_sha256": PCK_SHA,
        "session": session,
    }


def validate_checkpoint(path: Path, root: Path) -> tuple[str, dict, set[str]]:
    need(path.is_file() and not path.is_symlink(), "missing or symlink session checkpoint")
    value = load_json(path)
    need(value.get("schema_version") == 1 and
         value.get("checkpoint_kind") == "PRISM_PHYSICAL_WINDOWS_SESSION_CHECKPOINT",
         "invalid checkpoint schema")
    key = value.get("session_key")
    need(key in SESSION_KEYS and
         value.get("source_sha") == SOURCE and value.get("request_id") == REQUEST and
         value.get("factory_artifact_id") == ARTIFACT_ID and
         value.get("factory_artifact_expires_at") is None and
         value.get("exe_sha256") == EXE_SHA and value.get("pck_sha256") == PCK_SHA,
         "checkpoint provenance tuple mismatch")
    session = value.get("session")
    actual_key, hashes = validate_session(session, root)
    need(actual_key == key, "checkpoint session key mismatch")
    return key, session, hashes


def list_attempts(root: Path, key: str) -> list[Path]:
    parent = root / "physical-session-attempts" / key
    if not parent.exists() and not parent.is_symlink():
        return []
    need(parent.is_dir() and not parent.is_symlink(), "unsafe session attempts directory")
    result = []
    for item in parent.iterdir():
        need(item.is_dir() and not item.is_symlink() and ATTEMPT_ID_RE.fullmatch(item.name),
             "unexpected file/symlink/attempt name in session directory")
        result.append(item)
    return sorted(result, key=lambda p: p.name)


def write_checkpoint(root: Path, key: str, session: dict) -> None:
    validate_session(session, root)
    path = checkpoint_path(root, key)
    ensure_directory(path.parent)
    write_exclusive(path, checkpoint_payload(key, session))
    validate_checkpoint(path, root)


def inspect_status(root: Path) -> dict:
    completed = []
    recovered = []
    pending = []
    incomplete = []
    corrupt = []
    for key in SESSION_KEYS:
        path = checkpoint_path(root, key)
        if path.exists() or path.is_symlink():
            actual_key, _, _ = validate_checkpoint(path, root)
            need(actual_key == key, "checkpoint filename/key mismatch")
            completed.append(key)
            continue

        valid_candidates = []
        for attempt in list_attempts(root, key):
            candidate = attempt / "session.json"
            if candidate.is_symlink():
                corrupt.append({"session_key": key, "attempt_id": attempt.name,
                                "reason": "session.json is a symlink"})
                continue
            if not candidate.exists():
                incomplete.append({"session_key": key, "attempt_id": attempt.name,
                                   "reason": "interrupted before complete session.json"})
                continue
            try:
                session = load_json(candidate)
                actual_key, _ = validate_session(session, root)
                need(actual_key == key, "candidate session key mismatch")
                valid_candidates.append(session)
            except (OSError, ValueError, TypeError, KeyError) as error:
                corrupt.append({"session_key": key, "attempt_id": attempt.name,
                                "reason": str(error)[:180]})
        need(len(valid_candidates) <= 1,
             "multiple complete candidates for " + key + "; refuse ambiguous resume")
        if valid_candidates:
            write_checkpoint(root, key, valid_candidates[0])
            completed.append(key)
            recovered.append(key)
        else:
            pending.append(key)

    return {
        "status": "CHECKPOINT_STATUS_NOT_PHYSICAL_QA",
        "completed_sessions": completed,
        "recovered_sessions": recovered,
        "pending_sessions": pending,
        "incomplete_attempts": incomplete,
        "corrupt_attempts": corrupt,
        "physical_windows_qa": "HOLD_UNTIL_ALL_SIX_AND_HUMAN_REVIEW",
        "sale_ready": False,
        "store_submission_allowed": False,
    }


def record_session(root: Path, candidate_path: Path) -> dict:
    need(candidate_path.is_file() and not candidate_path.is_symlink(),
         "missing or symlink session candidate")
    resolved_root = root.resolve(strict=True)
    resolved_candidate = candidate_path.resolve(strict=True)
    need(resolved_candidate.is_relative_to(resolved_root),
         "session candidate must be inside the handoff directory")
    session = load_json(candidate_path)
    key, _ = validate_session(session, root)
    write_checkpoint(root, key, session)
    return {
        "status": "SESSION_CHECKPOINT_RECORDED_NOT_PHYSICAL_QA_PASS",
        "session_key": key,
        "checkpoint": str(checkpoint_path(root, key).relative_to(root)),
        "sale_ready": False,
        "store_submission_allowed": False,
    }


def finalize_capture(root: Path) -> dict:
    status = inspect_status(root)
    missing = status["pending_sessions"]
    need(not missing, "FINALIZE_HOLD: missing completed sessions: " + ", ".join(missing))
    sessions = {}
    global_hashes = set()
    for key in SESSION_KEYS:
        actual_key, session, hashes = validate_checkpoint(checkpoint_path(root, key), root)
        need(actual_key == key, "session checkpoint ordering mismatch")
        need(not (global_hashes & hashes), "duplicate screenshot bytes across sessions")
        global_hashes.update(hashes)
        sessions[key] = session
    need(len(global_hashes) == 36, "exactly 36 distinct physical screenshot hashes required")

    common_fields = ("operator", "windows_build", "exe_path", "pck_path",
                     "physical_device", "code_integrity_status")
    for field in common_fields:
        need(len({sessions[key][field] for key in SESSION_KEYS}) == 1,
             "session attestation changed across matrix: " + field)

    frame_dir = root / "physical-frames"
    ensure_directory(frame_dir)
    target_names = {
        f"{key}-{filename}"
        for key in SESSION_KEYS
        for filename in STATE_FILES.values()
    }
    for item in frame_dir.iterdir():
        need(item.is_file() and not item.is_symlink() and item.name in target_names,
             "unexpected existing physical-frames entry; preserve it and HOLD")

    final_sessions = []
    for key in SESSION_KEYS:
        session = sessions[key]
        attempt_dir = safe_relative(root, session["attempt_dir"])
        final_names = {}
        final_hashes = {}
        for state, filename in STATE_FILES.items():
            expected_hash = session["screenshot_sha256"][state]
            source = attempt_dir / filename
            target_name = f"{key}-{filename}"
            target = frame_dir / target_name
            if target.exists() or target.is_symlink():
                need(target.is_file() and not target.is_symlink() and digest(target) == expected_hash,
                     "refuse to overwrite mismatched existing screenshot: " + target_name)
            else:
                data = source.read_bytes()
                need(sha256_bytes(data) == expected_hash, "source screenshot changed before finalization")
                try:
                    descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                except FileExistsError:
                    raise CaptureHold("refuse to overwrite concurrently created screenshot: " + target_name) from None
                with os.fdopen(descriptor, "wb") as stream:
                    stream.write(data)
                    stream.flush()
                    os.fsync(stream.fileno())
            final_names[state] = target_name
            final_hashes[state] = expected_hash

        final_session = {
            "language": session["language"],
            "dpi_percent": session["dpi_percent"],
            "resolution": [1024, 768],
            "capture_started_at": session["capture_started_at"],
            "play_started_at": session["play_started_at"],
            "play_finished_at": session["play_finished_at"],
            "capture_finished_at": session["capture_finished_at"],
            "elapsed_play_seconds": session["elapsed_play_seconds"],
            "first_goal_seconds": session["first_goal_seconds"],
            "uncoached_first_launch": True,
            "start_pressed": True,
            "screenshots": final_names,
            "screenshot_sha256": final_hashes,
            "attempt_id": session["attempt_id"],
            "physical_device_attested": True,
            "actual_dpi": session["actual_dpi"],
        }
        for field in OBSERVATIONS:
            final_session[field] = True
        final_sessions.append(final_session)

    first = sessions[SESSION_KEYS[0]]
    capture = {
        "schema_version": 1,
        "capture_kind": "PHYSICAL_WINDOWS_OPERATOR_ATTESTATION",
        "source_sha": SOURCE,
        "request_id": REQUEST,
        "factory_artifact_id": ARTIFACT_ID,
        "factory_artifact_expires_at": None,
        "code_integrity_status": "ALLOWED_BY_EXISTING_POLICY",
        "exe_sha256": EXE_SHA,
        "pck_sha256": PCK_SHA,
        "exe_path": first["exe_path"],
        "pck_path": first["pck_path"],
        "physical_device": True,
        "operator": first["operator"],
        "windows_build": first["windows_build"],
        "sessions": final_sessions,
        "checkpoint_resume": {
            "status": "ALL_SIX_SESSION_CHECKPOINTS_REVALIDATED",
            "session_count": 6,
            "distinct_screenshot_sha256_count": 36,
        },
        "sale_ready": False,
        "store_submission_allowed": False,
    }
    capture_path = root / "physical-capture.json"
    if capture_path.exists() or capture_path.is_symlink():
        need(capture_path.is_file() and not capture_path.is_symlink(),
             "physical-capture.json is not a regular file")
        need(load_json(capture_path) == capture,
             "existing physical-capture.json differs; never overwrite it")
    else:
        write_exclusive(capture_path, capture)

    return {
        "status": "ALL_SIX_CHECKPOINTS_FINALIZED_AWAITING_EXISTING_FAIL_CLOSED_REVIEW_GATE",
        "sessions": 6,
        "screenshots": 36,
        "physical_capture": "physical-capture.json",
        "physical_screenshot_directory": "physical-frames",
        "human_review_required": True,
        "sale_ready": False,
        "store_submission_allowed": False,
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("status", help="validate/recover completed session checkpoints")
    record = sub.add_parser("record", help="validate and record one completed session")
    record.add_argument("--session-json", type=Path, required=True)
    sub.add_parser("finalize", help="assemble the six validated sessions for the existing gate")
    args = parser.parse_args(argv)
    try:
        root = args.root
        need(root.is_dir() and not root.is_symlink(), "handoff root must be a real directory")
        root = root.resolve(strict=True)
        if args.command == "status":
            result = inspect_status(root)
        elif args.command == "record":
            result = record_session(root, args.session_json)
        else:
            result = finalize_capture(root)
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        return 0
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError) as error:
        print(json.dumps({
            "status": "PHYSICAL_CAPTURE_CHECKPOINT_HOLD",
            "reason": str(error)[:240],
            "sale_ready": False,
            "store_submission_allowed": False,
        }, ensure_ascii=False, indent=2, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
