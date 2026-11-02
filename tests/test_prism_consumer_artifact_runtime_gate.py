"""Negative tests cannot claim real artifact or Godot execution."""
from pathlib import Path
import tempfile
import unittest

from prism_consumer_artifact_runtime_gate import (
    ArtifactRuntimeError, MEMBERS, REQUEST, SOURCE, ZIP_SHA,
    finalize_runtime, verify_archive,
)

class TestPrismConsumerArtifactRuntimeGate(unittest.TestCase):
    def preflight(self):
        return {
            'receipt_type': 'PRISM_CONSUMER_REAL_ARTIFACT_RUNTIME_PREFLIGHT',
            'archive_bytes_verified_this_run': True,
            'source_sha': SOURCE, 'request_id': REQUEST,
            'pck_sha256': MEMBERS['candidate.pck'][1],
            'sale_ready': False, 'store_submission_allowed': False,
        }

    def runtime(self):
        return {
            'schema_version': 1,
            'runtime_kind': 'GODOT_4_3_EXPORTED_PCK_LOADED_SOFTWARE_RENDER',
            'status': 'PASS_PCK_LOADED_LOGIC_AND_RENDER',
            'source_sha': SOURCE, 'request_id': REQUEST,
            'pck_sha256': MEMBERS['candidate.pck'][1],
            'physical_windows_gui': 'DEFERRED_LOCAL_GATE',
            'sale_ready': False,
            'assertions': [
                'first_30s_goal','tower_order_1_2_3','next_tower_hud',
                'sentinel_telegraph_and_hit','time_and_warp_trap','pause',
                'win','timeout','restart','english_japanese',
            ],
        }

    def test_archive_fails_closed_for_fixture_bytes(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)/'fixture.zip'
            p.write_bytes(b'PK\x03\x04')
            with self.assertRaisesRegex(ArtifactRuntimeError, 'ZIP size drift'):
                verify_archive(p)

    def test_no_runtime_promotion_from_unverified_receipt(self):
        with tempfile.TemporaryDirectory() as d:
            for key, value in (
                ('archive_bytes_verified_this_run', False),
                ('source_sha', 'e432d94ed0db22878f61f1a8af140d7d7de2288f'),
                ('request_id', '3d-prism-route-3d-e432d94ed0db'),
                ('pck_sha256', '3e92b7b6e336a0ab40419448b79f330cf00e0cba4d6bb9ec864ba70b89ecdb03'),
                ('sale_ready', True),
            ):
                with self.subTest(key=key), self.assertRaises(ArtifactRuntimeError):
                    finalize_runtime(dict(self.preflight(), **{key:value}), self.runtime(), Path(d))

    def test_runtime_claims_cannot_upgrade_store(self):
        with tempfile.TemporaryDirectory() as d:
            for key, value in (
                ('pck_sha256', '3e92b7b6e336a0ab40419448b79f330cf00e0cba4d6bb9ec864ba70b89ecdb03'),
                ('source_sha', 'e432d94ed0db22878f61f1a8af140d7d7de2288f'),
                ('assertions', ['win']),
                ('sale_ready', True),
                ('physical_windows_gui', 'PASS'),
                ('approved_package_version', '1.0.0.0'),
                ('signed_product_msix', 'PASS'),
            ):
                with self.subTest(key=key), self.assertRaises(ArtifactRuntimeError):
                    finalize_runtime(self.preflight(), dict(self.runtime(), **{key:value}), Path(d))

    def test_screenshot_bytes_are_required(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaisesRegex(ArtifactRuntimeError, 'missing runtime screenshot'):
                finalize_runtime(self.preflight(), self.runtime(), Path(d))

    def test_fixed_new_revision_not_old(self):
        self.assertEqual(REQUEST, '3d-prism-route-3d-' + SOURCE[:12])
        self.assertNotEqual(MEMBERS['candidate.pck'][1], '3e92b7b6e336a0ab40419448b79f330cf00e0cba4d6bb9ec864ba70b89ecdb03')
        self.assertEqual(ZIP_SHA, '8e7610217874136197f7cf9157bcc239444c1ae74097b51a3b461c3d0d0c6390')

if __name__ == '__main__':
    unittest.main()
