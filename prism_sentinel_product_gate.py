"""Fail-closed differential correlation of real Prism Sentinel artifact roles.

Historical downloaded-byte anchors are not live GitHub authentication.
This module never verifies official Partner Center CAS or Store readiness.
"""
from __future__ import annotations

SENTINEL = "e432d94ed0db22878f61f1a8af140d7d7de2288f"
REQUEST = "3d-prism-route-3d-e432d94ed0db"
LEGACY = "15fdcb52e46e35e6de8e87c55af99719c21e09b9"
LEGACY_REQUEST = "3d-prism-route-3d-15fdcb52e46e"
EXE = "66b26ad96df7458ea917b632a73ac7c88bb058db24dbd11a457fd50435ab7b13"
PCK = "3e92b7b6e336a0ab40419448b79f330cf00e0cba4d6bb9ec864ba70b89ecdb03"
LEGACY_PCK = "2cd8af6496cf288bc3e6aef317e472b480f21d2052cbd4ae0cd171e6285ab1ef"
# Role -> (run_id, artifact_id, downloaded ZIP SHA256, ZIP size).
ANCHORS = {
    "factory": (40901053437, 12909162367, "dc60f397e002bddf63a8f64ec263dd241a3eb8c4f7fd6e6595d115a9f273ae9c", 30880705),
    "sentinel_pre": (41020501779, 12961277866, "516f9dad3375ee8b4d6bc86b98b0542c3a140206de23b9badfe296c0f5a73b8c", 2482),
    "sentinel_unsigned_qa": (41020501832, 12961735943, "d678c0ff7c014f86a3d4ccb6517a9eafa65b409016dc57a650ed3d017c2f3be2", 31032520),
    "new_legacy_pre": (41269051480, 13068198139, "73cdd592eb2be8de96d5c0d7d34ed045bc03907f122934d916f6dfc9de07567d", 4640),
    "new_legacy_unsigned_qa": (41269051453, 13068860574, "02cdb9d1d0ded8cf3fb3845fa82d79b2a6c2b606889d13a57537f054fcf73be0", 31022039),
}


class ProductEvidenceError(ValueError):
    pass


def require(condition, reason):
    if not condition:
        raise ProductEvidenceError(reason)


def inspect_product_evidence(audit, *, qa=None, identity=None):
    """Correlate independent historical audit claims; always HOLD for product."""
    require(isinstance(audit, dict), "missing audit")
    require(audit.get("schema_version") == "1.0" and
            audit.get("receipt_type") == "GAME_3D_INDEPENDENT_REAL_ARTIFACT_SOURCE_DISCRIMINATION" and
            audit.get("product") == "Prism Route 3D" and
            audit.get("slug") == "prism-route-3d", "wrong product audit")
    for key, expected in (("pinned_source_sha", SENTINEL),
                          ("pinned_request_id", REQUEST),
                          ("factory_build_head", SENTINEL)):
        require(audit.get(key) == expected, "source/request/factory drift: " + key)
    roles = audit.get("artifact_checks")
    require(isinstance(roles, dict) and set(roles) == set(ANCHORS), "incomplete artifact roles")
    for role, expected in ANCHORS.items():
        item = roles[role]
        require(isinstance(item, dict) and
                type(item.get("run_id")) is int and
                type(item.get("artifact_id")) is int and
                type(item.get("archive_bytes")) is int and
                (item["run_id"], item["artifact_id"], item.get("archive_sha256"),
                 item["archive_bytes"]) == expected, "artifact role drift: " + role)
    factory, pre, unsigned, legacy_pre, legacy_msix = (roles[k] for k in ANCHORS)
    require(factory.get("exe_sha256") == EXE and factory.get("exe_bytes") == 84214784 and
            factory.get("pck_sha256") == PCK and factory.get("pck_bytes") == 71568,
            "Factory EXE/PCK mismatch")
    require(pre.get("source_request_match") is True and pre.get("status") == "HOLD" and
            pre.get("official_identity_status") == "UNVERIFIED", "PRE identity not held")
    require(unsigned.get("evidence_source_sha") == SENTINEL and
            unsigned.get("evidence_request_id") == REQUEST and
            unsigned.get("exe_sha256") == EXE and unsigned.get("pck_sha256") == PCK and
            unsigned.get("exe_matches_sentinel_factory") is True and
            unsigned.get("pck_matches_sentinel_factory") is True and
            unsigned.get("fixture_identity") is True and
            unsigned.get("appx_signature_present") is False,
            "Sentinel QA fixture payload drift")
    require(legacy_pre.get("source_sha") == LEGACY and
            legacy_pre.get("request_id") == LEGACY_REQUEST and
            legacy_msix.get("evidence_source_sha") == LEGACY and
            legacy_msix.get("evidence_request_id") == LEGACY_REQUEST and
            legacy_msix.get("exe_sha256") == EXE and
            legacy_msix.get("pck_sha256") == LEGACY_PCK and
            legacy_msix.get("pck_matches_sentinel_factory") is False and
            legacy_msix.get("fixture_identity") is True and
            legacy_msix.get("appx_signature_present") is False,
            "legacy-vs-Sentinel differential mismatch")
    d = audit.get("decision")
    require(isinstance(d, dict) and
            d.get("registration_type") == "MSIX_OR_PWA_GAME" and
            d.get("partner_center_selection") == "MSIX or PWA game" and
            d.get("new_20261101_workflow_outputs") == "LEGACY_SOURCE_NOT_SENTINEL" and
            d.get("new_legacy_msix_promotable_to_sentinel") is False and
            all(d.get(k) == "HOLD" for k in
                ("official_identity_cas", "signed_msix", "windows_all_auto_intake", "product_e2e")) and
            d.get("store_submission_allowed") is False and
            d.get("second_3d_product_allowed") is False,
            "unsafe downstream decision")
    identity_state = "HOLD_OFFICIAL_IDENTITY_MISSING"
    if identity is not None:
        require(isinstance(identity, dict), "invalid identity")
        for key in ("source_sha", "verified_source_sha", "expected_head_sha"):
            if key in identity:
                require(identity[key] == SENTINEL, "historical Identity source: " + key)
        if "request_id" in identity:
            require(identity["request_id"] == REQUEST, "historical Identity request")
        identity_state = ("HOLD_NEW_REVISION_CAS_AUTHENTICATION_REQUIRED"
                          if identity.get("source") == "partner_center" and
                          identity.get("reviewed") is True and
                          identity.get("source_sha") == SENTINEL and
                          identity.get("request_id") == REQUEST
                          else "HOLD_NEW_REVISION_CAS_NOT_BOUND")
    if qa is not None:
        require(isinstance(qa, dict), "invalid QA result")
        require(qa.get("submission_authorized") is False and
                qa.get("official_identity_verified") is False and
                qa.get("signature_verified") is False,
                "QA claims unverified authorization")
        require(qa.get("status") == "BLOCKED" and
                isinstance(qa.get("errors"), list) and
                any("fixture-only" in str(error) for error in qa["errors"]),
                "pinned fixture must be BLOCKED, never product MSIX")
        require(not (qa.get("revision_binding_verified") is True and
                     identity_state != "HOLD_NEW_REVISION_CAS_AUTHENTICATION_REQUIRED"),
                "QA revision binding conflicts with CAS")
    return {
        "status": "HOLD_SENTINEL_HISTORICAL_BYTES_NOT_STORE_PRODUCT",
        "slug": "prism-route-3d", "source_sha": SENTINEL, "request_id": REQUEST,
        "factory_build_head": SENTINEL,
        "exe_sha256": EXE, "pck_sha256": PCK,
        "unsigned_fixture_msix_sha256": unsigned.get("msix_sha256"),
        "newer_workflow_source_sha": LEGACY,
        "newer_workflow_promotable_to_sentinel": False,
        "registration_type": "MSIX_OR_PWA_GAME",
        "identity_state": identity_state,
        "historical_byte_audit_correlated": True,
        "live_github_authenticated_by_this_gate": False,
        "official_identity_authenticated_by_this_gate": False,
        "real_product_msix_verified": False,
        "windows_all_auto_intake_verified": False,
        "local_windows_gate": "DEFERRED_LOCAL_GATE",
        "product_e2e": "HOLD", "store_submission_allowed": False,
    }


def _unique_json_keys(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def main(argv=None):
    """Read-only CLI: exit 2 even for a valid historical HOLD receipt."""
    import argparse
    import json
    from pathlib import Path

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--audit", required=True, type=Path)
    parser.add_argument("--qa", type=Path)
    parser.add_argument("--identity", type=Path)
    args = parser.parse_args(argv)

    def load(path):
        require(path.is_file() and not path.is_symlink() and
                0 < path.stat().st_size <= 65536, "unsafe or missing JSON")
        return json.loads(path.read_text(encoding="utf-8"),
                          object_pairs_hook=_unique_json_keys)

    try:
        result = inspect_product_evidence(
            load(args.audit), qa=load(args.qa) if args.qa else None,
            identity=load(args.identity) if args.identity else None)
    except (OSError, ValueError, UnicodeError, TypeError) as exc:
        result = {"status": "BLOCKED", "reason": str(exc)[:160],
                  "product_e2e": "HOLD", "store_submission_allowed": False}
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
