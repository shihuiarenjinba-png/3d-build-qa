"""Fail-closed Prism Sentinel historical source/fixture regression."""
import copy
import unittest

from prism_sentinel_product_gate import (
    ANCHORS, EXE, PCK, LEGACY, LEGACY_REQUEST, LEGACY_PCK,
    SENTINEL, REQUEST, ProductEvidenceError, inspect_product_evidence,
)


def audit():
    roles = {k: dict(run_id=v[0], artifact_id=v[1],
                     archive_sha256=v[2], archive_bytes=v[3])
             for k, v in ANCHORS.items()}
    roles["factory"].update(exe_sha256=EXE, exe_bytes=84214784,
                            pck_sha256=PCK, pck_bytes=71568)
    roles["sentinel_pre"].update(source_request_match=True, status="HOLD",
                                  official_identity_status="UNVERIFIED")
    roles["sentinel_unsigned_qa"].update(
        evidence_source_sha=SENTINEL, evidence_request_id=REQUEST,
        exe_sha256=EXE, pck_sha256=PCK, exe_matches_sentinel_factory=True,
        pck_matches_sentinel_factory=True, fixture_identity=True,
        appx_signature_present=False,
        msix_sha256="45de4b28bb2dc966a96f7f1507e70d0e1d40f26b2079eee8de2b2fa6eacef8d1")
    roles["new_legacy_pre"].update(source_sha=LEGACY, request_id=LEGACY_REQUEST)
    roles["new_legacy_unsigned_qa"].update(
        evidence_source_sha=LEGACY, evidence_request_id=LEGACY_REQUEST,
        exe_sha256=EXE, pck_sha256=LEGACY_PCK,
        pck_matches_sentinel_factory=False, fixture_identity=True,
        appx_signature_present=False)
    return {
        "schema_version": "1.0",
        "receipt_type": "GAME_3D_INDEPENDENT_REAL_ARTIFACT_SOURCE_DISCRIMINATION",
        "product": "Prism Route 3D", "slug": "prism-route-3d",
        "pinned_source_sha": SENTINEL, "pinned_request_id": REQUEST,
        "factory_build_head": SENTINEL, "artifact_checks": roles,
        "decision": {
            "registration_type": "MSIX_OR_PWA_GAME",
            "partner_center_selection": "MSIX or PWA game",
            "new_20261101_workflow_outputs": "LEGACY_SOURCE_NOT_SENTINEL",
            "new_legacy_msix_promotable_to_sentinel": False,
            "official_identity_cas": "HOLD", "signed_msix": "HOLD",
            "windows_all_auto_intake": "HOLD", "product_e2e": "HOLD",
            "store_submission_allowed": False, "second_3d_product_allowed": False,
        },
    }


FIXTURE_QA = {
    "status": "BLOCKED",
    "errors": ["ValueError: fixture-only MSIX identity is not a product package"],
    "submission_authorized": False,
    "official_identity_verified": False,
    "signature_verified": False,
    "revision_binding_verified": False,
}


class TestPrismSentinelProductGate(unittest.TestCase):
    def test_exact_real_sentinel_historical_evidence_still_hold(self):
        result = inspect_product_evidence(audit(), qa=FIXTURE_QA)
        self.assertTrue(result["historical_byte_audit_correlated"])
        self.assertEqual(result["product_e2e"], "HOLD")
        self.assertFalse(result["real_product_msix_verified"])
        self.assertFalse(result["store_submission_allowed"])
        self.assertEqual(result["identity_state"], "HOLD_OFFICIAL_IDENTITY_MISSING")

    def test_legacy_identity_rejected(self):
        identity = {"source": "partner_center", "reviewed": True,
                    "source_sha": LEGACY, "request_id": LEGACY_REQUEST}
        with self.assertRaisesRegex(ProductEvidenceError, "historical Identity"):
            inspect_product_evidence(audit(), identity=identity)

    def test_self_declared_new_identity_not_official_cas(self):
        identity = {"source": "partner_center", "reviewed": True,
                    "source_sha": SENTINEL, "request_id": REQUEST}
        result = inspect_product_evidence(audit(), identity=identity)
        self.assertEqual(result["identity_state"], "HOLD_NEW_REVISION_CAS_AUTHENTICATION_REQUIRED")
        self.assertFalse(result["official_identity_authenticated_by_this_gate"])

    def test_fixture_must_be_blocked_not_evidence_review(self):
        with self.assertRaisesRegex(ProductEvidenceError, "fixture must be BLOCKED"):
            inspect_product_evidence(audit(), qa=dict(FIXTURE_QA,
                status="EVIDENCE_REVIEW", errors=[], artifact_bytes_verified=True))

    def test_qa_forged_promotion_rejected(self):
        for key in ("submission_authorized", "signature_verified", "official_identity_verified"):
            with self.subTest(key=key), self.assertRaises(ProductEvidenceError):
                inspect_product_evidence(audit(), qa=dict(FIXTURE_QA, **{key: True}))

    def test_revision_binding_without_official_cas_rejected(self):
        with self.assertRaisesRegex(ProductEvidenceError, "revision binding"):
            inspect_product_evidence(audit(), qa=dict(FIXTURE_QA, revision_binding_verified=True))

    def test_artifact_role_substitution_rejected(self):
        for key in ("run_id", "artifact_id", "archive_sha256", "archive_bytes"):
            with self.subTest(key=key):
                changed = copy.deepcopy(audit())
                changed["artifact_checks"]["sentinel_unsigned_qa"][key] = (
                    "0" * 64 if key == "archive_sha256" else 1)
                with self.assertRaisesRegex(ProductEvidenceError, "artifact role drift"):
                    inspect_product_evidence(changed)

    def test_identical_exe_does_not_prove_pck(self):
        changed = copy.deepcopy(audit())
        changed["artifact_checks"]["sentinel_unsigned_qa"]["pck_sha256"] = LEGACY_PCK
        with self.assertRaisesRegex(ProductEvidenceError, "fixture payload drift"):
            inspect_product_evidence(changed)

    def test_factory_build_head_mismatch_rejected(self):
        changed = copy.deepcopy(audit())
        changed["factory_build_head"] = LEGACY
        with self.assertRaisesRegex(ProductEvidenceError, "factory drift"):
            inspect_product_evidence(changed)

    def test_route_and_store_promotion_rejected(self):
        for key, value in (("registration_type", "GDK_GAME"),
                           ("signed_msix", "PASS"),
                           ("windows_all_auto_intake", "PASS"),
                           ("store_submission_allowed", True),
                           ("second_3d_product_allowed", True)):
            with self.subTest(key=key):
                changed = copy.deepcopy(audit())
                changed["decision"][key] = value
                with self.assertRaisesRegex(ProductEvidenceError, "unsafe downstream"):
                    inspect_product_evidence(changed)


if __name__ == "__main__":
    unittest.main()
