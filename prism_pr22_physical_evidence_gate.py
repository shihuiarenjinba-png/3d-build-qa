"""PR22 physical Windows human evidence: read-only, fail-closed, never SALE_READY.

Cloud CI can verify a software baseline and issue an EMPTY template only.
Only actual Windows execution plus six uncoached human sessions may reach
PHYSICAL_EVIDENCE_REVIEW_REQUIRED; screenshots/attestations cannot prove GPU or fun.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import platform
from pathlib import Path
import zipfile

from prism_first30s_physical_windows_gate import check_png
from prism_pr22_failure_reason_gate import (
    SOURCE, REQUEST, ARTIFACT_ID, ZIP_SHA, MEMBERS, verify_archive,
)

QA_ZIP_SHA = "df4999581b280f0663e4f72a0ba80379849163a42efe54cf311ec138be7c0caf"
QA_ARTIFACT_ID = 13185037028
EXPIRES_AT = "2026-11-09T22:27:53+00:00"
LANGUAGES = ("ja", "en")
DPIS = (100, 125, 150)
STATES = ("guide", "active", "scan_warning", "timeout", "trap", "sentinel", "retry")
OBSERVATIONS = (
    "uncoached_first_launch", "goal_understood", "tower_order_1_2_3_understood",
    "start_action_understood", "controls_understood", "sentinel_scan_timing_understood",
    "trap_penalty_understood", "clock_frozen_before_start",
    "timeout_reason_understood", "trap_reason_understood",
    "sentinel_reason_understood", "retry_completed", "failure_recovery_understood",
    "taskbar_visible", "game_window_unclipped", "no_debug_ui",
)
HOLD = "PHYSICAL_HOLD"


class EvidenceHold(ValueError):
    pass


def require(ok, message):
    if not ok:
        raise EvidenceHold(message)


def sha(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def load(path):
    def pairs(items):
        d = {}
        for k, v in items:
            require(k not in d, "duplicate JSON key: " + k)
            d[k] = v
        return d
    return json.loads(Path(path).read_text(encoding="utf-8"), object_pairs_hook=pairs)


def timestamp(value):
    require(isinstance(value, str), "missing timezone-aware timestamp")
    try:
        t = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise EvidenceHold("invalid timestamp") from None
    require(t.tzinfo is not None and t.utcoffset() is not None, "timestamp must include timezone")
    return t


def verify_software_zip(path):
    path = Path(path)
    require(path.is_file() and not path.is_symlink(), "missing exact PR22 software ZIP")
    require(sha(path) == QA_ZIP_SHA, "PR22 software artifact ZIP digest mismatch")
    with zipfile.ZipFile(path) as z:
        names = z.namelist()
        require(len(names) == len(set(names)) and
                "independent-pr22-receipt.json" in names,
                "software ZIP missing/duplicate receipt")
        require(all(z.getinfo(n).file_size < 5_000_000 for n in names),
                "oversized software ZIP member")
        require(z.testzip() is None, "software ZIP CRC mismatch")
        receipt = json.loads(z.read("independent-pr22-receipt.json"))
        require(receipt.get("source_sha") == SOURCE and
                receipt.get("request_id") == REQUEST and
                receipt.get("pck_sha256") == MEMBERS["candidate.pck"][1] and
                receipt.get("factory_artifact_id") == ARTIFACT_ID,
                "software receipt provenance mismatch")
        require(receipt.get("software_frame_sha256_count") == 8 and
                receipt.get("physical_windows_gui") == "HOLD" and
                receipt.get("sale_ready") is False,
                "software receipt cannot claim physical PASS")
        frames = receipt.get("software_rendered_screenshots")
        require(isinstance(frames, dict) and
                set(frames) == {f"{cause}_{lang}" for cause in
                               ("timeout", "trap", "sentinel", "retry")
                               for lang in LANGUAGES},
                "software receipt eight-state coverage mismatch")
        for name, info in frames.items():
            filename = "screenshots/" + name + ".png"
            require(filename in names and
                    hashlib.sha256(z.read(filename)).hexdigest() == info["sha256"] and
                    len(z.read(filename)) == info["bytes"],
                    "software PNG hash/size mismatch: " + name)
    return receipt


def blank_template():
    return {
        "schema_version": 1,
        "capture_kind": "PR22_PHYSICAL_WINDOWS_HUMAN_OPERATOR",
        "source_sha": SOURCE, "request_id": REQUEST,
        "factory_artifact_id": ARTIFACT_ID,
        "software_qa_artifact_id": QA_ARTIFACT_ID,
        "factory_zip_sha256": ZIP_SHA, "software_qa_zip_sha256": QA_ZIP_SHA,
        "exe_sha256": MEMBERS["candidate.exe"][1],
        "pck_sha256": MEMBERS["candidate.pck"][1],
        "physical_device": None, "windows_build": None,
        "code_integrity_status": None, "operator": None,
        "sessions": [
            {"language": lang, "dpi_percent": dpi, "tester_id": None,
             "resolution": [1024, 768], "capture_started_at": None,
             "capture_finished_at": None, "first_goal_seconds": None,
             "elapsed_play_seconds": None,
             **{field: None for field in OBSERVATIONS},
             "screenshots": {state: f"{lang}-{dpi}-{state}.png" for state in STATES}}
            for lang in LANGUAGES for dpi in DPIS
        ],
        "physical_qa": HOLD, "human_fun": HOLD, "sale_ready": False,
        "store_submission_allowed": False,
    }


def evaluate(capture, frames_dir, *, windows_host, now=None):
    require(windows_host, "PHYSICAL_HOLD: no actual Windows host")
    require(capture.get("schema_version") == 1 and
            capture.get("capture_kind") == "PR22_PHYSICAL_WINDOWS_HUMAN_OPERATOR",
            "invalid capture schema")
    for key, expected in (
        ("source_sha", SOURCE), ("request_id", REQUEST),
        ("factory_artifact_id", ARTIFACT_ID),
        ("software_qa_artifact_id", QA_ARTIFACT_ID),
        ("factory_zip_sha256", ZIP_SHA), ("software_qa_zip_sha256", QA_ZIP_SHA),
        ("exe_sha256", MEMBERS["candidate.exe"][1]),
        ("pck_sha256", MEMBERS["candidate.pck"][1]),
    ):
        require(type(capture.get(key)) is type(expected) and capture[key] == expected,
                "PROVENANCE_HOLD: " + key)
    require(capture.get("sale_ready") is False and
            capture.get("store_submission_allowed") is False and
            capture.get("physical_qa") == HOLD and
            capture.get("human_fun") == HOLD,
            "false physical/human/Store PASS")
    current = now or dt.datetime.now(dt.timezone.utc)
    require(current < timestamp(EXPIRES_AT), "expired PR22 QA evidence; renew exact-source custody")
    require(capture.get("physical_device") is True and
            isinstance(capture.get("windows_build"), str) and
            len(capture["windows_build"].strip()) >= 5 and
            isinstance(capture.get("operator"), str) and
            len(capture["operator"].strip()) >= 3,
            "actual Windows/operator attestation missing")
    require(capture.get("code_integrity_status") == "ALLOWED_BY_EXISTING_POLICY",
            "CODE_INTEGRITY_HOLD: do not bypass policy")
    sessions = capture.get("sessions")
    require(isinstance(sessions, list) and len(sessions) == 6,
            "six JA/EN x 100/125/150 DPI sessions required")
    seen, testers, hashes = set(), set(), set()
    for s in sessions:
        require(isinstance(s, dict), "invalid session")
        lang, dpi = s.get("language"), s.get("dpi_percent")
        require(lang in LANGUAGES and type(dpi) is int and dpi in DPIS and
                (lang, dpi) not in seen, "duplicate/unknown locale-DPI session")
        seen.add((lang, dpi))
        tester = s.get("tester_id")
        require(isinstance(tester, str) and len(tester.strip()) >= 3 and
                tester not in testers, "uncoached first launch needs a distinct tester")
        testers.add(tester)
        require(s.get("resolution") == [1024, 768], "full-screen 1024x768 required")
        start, end = timestamp(s.get("capture_started_at")), timestamp(s.get("capture_finished_at"))
        elapsed = (end - start).total_seconds()
        require(90 <= elapsed <= 3600, "real 90-second session wall clock missing")
        first, play = s.get("first_goal_seconds"), s.get("elapsed_play_seconds")
        require(type(first) in (int, float) and 0 <= first <= 30 and
                type(play) in (int, float) and 90 <= play <= elapsed,
                "uncoached 30s / real 90s evidence missing")
        for field in OBSERVATIONS:
            require(s.get(field) is True, "CONSUMER_HOLD: " + field)
        shots = s.get("screenshots")
        require(isinstance(shots, dict) and set(shots) == set(STATES),
                "missing timeout/trap/Sentinel/retry frame")
        for state in STATES:
            filename = shots[state]
            require(filename == f"{lang}-{dpi}-{state}.png",
                    "unsafe/mislabeled screenshot name")
            frame = Path(frames_dir) / filename
            require(frame.is_file() and not frame.is_symlink() and frame.stat().st_size > 4096,
                    "missing physical frame: " + filename)
            digest = check_png(frame)
            require(digest not in hashes, "duplicate frame cannot prove unique state")
            hashes.add(digest)
    require(seen == {(l, d) for l in LANGUAGES for d in DPIS}, "incomplete locale/DPI matrix")
    return {
        "status": "PHYSICAL_EVIDENCE_REVIEW_REQUIRED",
        "source_sha": SOURCE, "request_id": REQUEST,
        "sessions": 6, "uncoached_testers": len(testers),
        "distinct_1024x768_frames": len(hashes),
        "physical_gui_automatically_proven": False,
        "human_enjoyment_automatically_proven": False,
        "human_review_required": True,
        "identity_cas": "HOLD_36_OWNER", "package_version": "HOLD",
        "sale_ready": False, "store_submission_allowed": False,
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--template", type=Path)
    ap.add_argument("--factory-zip", type=Path)
    ap.add_argument("--software-zip", type=Path)
    ap.add_argument("--capture", type=Path)
    ap.add_argument("--frames", type=Path)
    ap.add_argument("--exe", type=Path)
    ap.add_argument("--pck", type=Path)
    ap.add_argument("--out", type=Path)
    a = ap.parse_args(argv)
    if a.template:
        a.template.parent.mkdir(parents=True, exist_ok=True)
        a.template.write_text(json.dumps(blank_template(), indent=2, ensure_ascii=False) + "\n",
                              encoding="utf-8")
        print("PHYSICAL_HOLD: blank template only; no human or physical evidence")
        return 0
    try:
        require(all((a.factory_zip, a.software_zip, a.capture, a.frames, a.exe, a.pck)),
                "missing physical input")
        verify_archive(a.factory_zip, None)
        verify_software_zip(a.software_zip)
        for path, member in ((a.exe, "candidate.exe"), (a.pck, "candidate.pck")):
            require(path.is_file() and not path.is_symlink() and
                    path.stat().st_size == MEMBERS[member][0] and
                    sha(path) == MEMBERS[member][1],
                    "exact physical candidate binary missing: " + member)
        result = evaluate(load(a.capture), a.frames, windows_host=platform.system() == "Windows")
        code = 0
    except (ValueError, OSError, KeyError, TypeError, zipfile.BadZipFile) as e:
        result = {"status": HOLD, "reason": str(e)[:300],
                  "physical_gui_automatically_proven": False,
                  "human_review_required": True, "sale_ready": False,
                  "store_submission_allowed": False}
        code = 2
    if a.out:
        a.out.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n",
                         encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
