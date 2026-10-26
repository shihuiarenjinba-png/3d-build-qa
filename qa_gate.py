"""Validate a 3D Windows QA receipt shape; does not claim tests actually ran."""
import argparse
import json
import re
from pathlib import Path

ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
SHA = re.compile(r"^[0-9a-fA-F]{64}$")
SOURCE = re.compile(r"^[0-9a-fA-F]{40}$")
REPO = re.compile(r"^[A-Za-z0-9-]+/[A-Za-z0-9_.-]+$")


def _match(regex, value):
    return isinstance(value, str) and regex.fullmatch(value) is not None


def inspect(receipt):
    errors = []
    if not isinstance(receipt, dict):
        return {"status": "BLOCKED", "errors": ["receipt must be JSON object"]}
    if receipt.get("schema_version") != "1.0":
        errors.append("schema_version must be 1.0")
    if receipt.get("source_factory") != "3d-game-factory":
        errors.append("source_factory mismatch")
    for key in ("request_id", "windows_run_id"):
        if not _match(ID, receipt.get(key)):
            errors.append(f"invalid {key}")
    if not _match(REPO, receipt.get("repository_full_name")):
        errors.append("invalid repository_full_name")
    if not _match(SOURCE, receipt.get("source_sha")):
        errors.append("invalid source_sha")
    if not _match(SHA, receipt.get("package_sha256")):
        errors.append("invalid package_sha256")
    tests = receipt.get("tests")
    if not isinstance(tests, dict):
        errors.append("tests missing")
    else:
        for k in ("executed", "failed", "skipped", "crashes"):
            if type(tests.get(k)) is not int or tests[k] < 0:
                errors.append(f"invalid tests.{k}")
    if receipt.get("windows_launch") not in (True, False):
        errors.append("windows_launch must be boolean")
    if not _match(ID, receipt.get("runner_evidence_id")):
        errors.append("runner_evidence_id required")
    if errors:
        return {"status": "BLOCKED", "errors": errors, "qa_claims_verified": False}
    if (tests["executed"] <= 0 or tests["failed"] or tests["skipped"]
            or tests["crashes"] or receipt["windows_launch"] is not True):
        return {"status": "HOLD", "errors": ["unmet Windows QA requirements"],
                "qa_claims_verified": False}
    return {"status": "EVIDENCE_REVIEW", "errors": [],
            "qa_claims_verified": False, "human_qa_required": True,
            "submission_authorized": False}


def main(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument("receipt", type=Path)
    a = p.parse_args(argv)
    try:
        result = inspect(json.loads(a.receipt.read_text(encoding="utf-8")))
    except (OSError, ValueError) as exc:
        result = {"status": "BLOCKED", "errors": [type(exc).__name__],
                  "qa_claims_verified": False}
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["status"] == "EVIDENCE_REVIEW" else 2


if __name__ == "__main__":
    raise SystemExit(main())
