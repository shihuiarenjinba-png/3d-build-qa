import unittest
from datetime import datetime, timezone
from prism_package_preflight_contract import (
    ARTIFACT_ID, RUN_ID, ZIP_SHA, MEMBERS, PACKAGE_DIR, REQUEST, SOURCE,
    HANDOFF_ARTIFACT_ID, HANDOFF_RUN_ID, HANDOFF_SOURCE, HANDOFF_SHA,
    HANDOFF_NAME, HANDOFF_BRANCH, HANDOFF_SIZE, HANDOFF_REPOSITORY,
    Hold, build_plan, version_gate, verify_handoff_metadata,
)

def preflight():
    return {
        "status": "EXACT_PR25_FACTORY_BYTES_VERIFIED",
        "source_sha": SOURCE, "request_id": REQUEST, "factory_run_id": RUN_ID,
        "factory_artifact_id": ARTIFACT_ID, "factory_zip_bytes": 37795977,
        "factory_zip_sha256": ZIP_SHA, "exe_bytes": MEMBERS["candidate.exe"][0],
        "exe_sha256": MEMBERS["candidate.exe"][1], "pck_bytes": MEMBERS["candidate.pck"][0],
        "pck_sha256": MEMBERS["candidate.pck"][1],
        "manifest_sha256": MEMBERS["export-evidence.json"][1],
    }

class PackagePreflightTests(unittest.TestCase):
    def test_exact_exe_pck_sidecar_mapping(self):
        p = build_plan(preflight())
        self.assertEqual(p["payload_mapping"][0]["package_path"], PACKAGE_DIR + "/candidate.exe")
        self.assertEqual(p["payload_mapping"][1]["package_path"], PACKAGE_DIR + "/candidate.pck")
        self.assertEqual(p["manifest_contract"]["application_executable"], p["payload_mapping"][0]["package_path"])
        self.assertEqual(p["manifest_contract"]["external_pck_sidecar"], p["payload_mapping"][1]["package_path"])

    def test_official_assets_are_missing_not_fabricated(self):
        a = build_plan(preflight())["manifest_contract"]
        self.assertEqual(a["assets_status"], "HOLD_OFFICIAL_ASSET_SOURCE_NOT_PRESENT")
        self.assertTrue(all(x["source_path"] is None for x in a["required_assets"]))
        self.assertEqual(len(a["required_assets"]), 3)

    def test_registration_is_exact_msix_or_pwa_game(self):
        p = build_plan(preflight())
        self.assertEqual(p["registration_type"], "MSIX_OR_PWA_GAME")
        self.assertEqual(p["partner_center_selection"], "MSIX or PWA game")

    def test_gdk_route_is_rejected(self):
        with self.assertRaisesRegex(Hold, "registration route mismatch"):
            build_plan(preflight(), registration="GDK_GAME")

    def test_missing_authoritative_four_part_version_holds(self):
        self.assertEqual(version_gate(None), "HOLD_MISSING_AUTHORITATIVE_FOUR_PART_VERSION")
        self.assertEqual(build_plan(preflight())["authoritative_package_version_status"],
                         "HOLD_MISSING_AUTHORITATIVE_FOUR_PART_VERSION")

    def test_malformed_or_out_of_range_version_holds(self):
        for e in ({"version": "1.2.3"}, {"version": "1.2.beta.4"},
                  {"version": 1.2}, {"version": "65536.0.0.0"}):
            with self.subTest(e=e):
                self.assertEqual(version_gate(e), "HOLD_MALFORMED_FOUR_PART_VERSION")

    def test_synthetic_four_part_version_is_not_authoritative(self):
        self.assertEqual(version_gate({"version": "1.0.0.0", "fixture_only": True}),
                         "HOLD_UNAUTHENTICATED_VERSION_EVIDENCE")

    def test_self_asserted_approval_cannot_promote_version(self):
        e = {"version": "2.4.6.8", "authority": "partner_center",
             "authenticated": True, "source_sha": SOURCE, "request_id": REQUEST}
        self.assertEqual(version_gate(e), "HOLD_UNAUTHENTICATED_VERSION_EVIDENCE")

    def test_stale_source_or_artifact_cannot_create_plan(self):
        for key, value in (("source_sha", "1" * 40), ("request_id", "legacy"),
                           ("factory_artifact_id", 13180284133), ("factory_zip_sha256", "2" * 64),
                           ("exe_sha256", "3" * 64), ("pck_sha256", "4" * 64),
                           ("manifest_sha256", "5" * 64)):
            bad = preflight()
            bad[key] = value
            with self.subTest(key=key):
                with self.assertRaises(Hold):
                    build_plan(bad)

    def test_physical_handoff_metadata_is_bound_to_pr19_source_and_retention(self):
        metadata = {
            "id": HANDOFF_ARTIFACT_ID, "name": HANDOFF_NAME,
            "size_in_bytes": HANDOFF_SIZE, "digest": "sha256:" + HANDOFF_SHA,
            "expired": False, "expires_at": "2026-12-01T18:39:16Z",
            "workflow_run": {
                "id": HANDOFF_RUN_ID, "head_sha": HANDOFF_SOURCE,
                "head_branch": HANDOFF_BRANCH,
            },
        }
        result = verify_handoff_metadata(
            metadata, now=datetime(2026, 11, 28, tzinfo=timezone.utc)
        )
        self.assertTrue(result["metadata_verified"])
        self.assertEqual(result["artifact_id"], 14952074847)
        self.assertEqual(result["source_sha"], HANDOFF_SOURCE)
        self.assertEqual(HANDOFF_REPOSITORY, "shihuiarenjinba-png/3d-build-qa")

    def test_wrong_or_expired_physical_handoff_metadata_fails_closed(self):
        base = {
            "id": HANDOFF_ARTIFACT_ID, "name": HANDOFF_NAME,
            "size_in_bytes": HANDOFF_SIZE, "digest": "sha256:" + HANDOFF_SHA,
            "expired": False, "expires_at": "2026-12-01T18:39:16Z",
            "workflow_run": {
                "id": HANDOFF_RUN_ID, "head_sha": HANDOFF_SOURCE,
                "head_branch": HANDOFF_BRANCH,
            },
        }
        bad = dict(base)
        bad["id"] = 13180284133
        with self.assertRaises(Hold):
            verify_handoff_metadata(bad, now=datetime(2026, 11, 28, tzinfo=timezone.utc))
        with self.assertRaises(Hold):
            verify_handoff_metadata(base, now=datetime(2026, 12, 2, tzinfo=timezone.utc))

    def test_fixture_never_builds_or_submits_product(self):
        p = build_plan(preflight())
        self.assertEqual(p["kind"], "QA_FIXTURE_ONLY_NOT_PRODUCT")
        for key in ("package_build_allowed", "makeappx_package_build_invoked",
                    "product_msix_created", "store_submission_allowed", "sale_ready"):
            self.assertFalse(p[key])
        self.assertEqual(p["identity_cas_status"], "HOLD_36_OWNER")
        self.assertEqual(p["physical_windows_gui"], "HOLD")

if __name__ == "__main__":
    unittest.main()
