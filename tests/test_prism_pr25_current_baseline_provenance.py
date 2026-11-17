"""PR25 provenance regression; PR21 historical fixtures stay immutable."""
import tempfile
import unittest
from pathlib import Path

import prism_consumer_artifact_runtime_gate as canonical
import prism_pr25_software_baseline_gate as current
from prism_pr25_software_baseline_gate import SoftwareBaselineHold


class CurrentBaselineProvenanceTests(unittest.TestCase):
    def test_current_baseline_uses_canonical_verified_bytes(self):
        self.assertEqual(current.SOURCE, canonical.SOURCE)
        self.assertEqual(current.REQUEST, canonical.REQUEST)
        self.assertEqual(current.FACTORY_RUN_ID, canonical.RUN_ID)
        self.assertEqual(current.FACTORY_ARTIFACT_ID, canonical.ARTIFACT_ID)
        self.assertEqual(current.ZIP_SHA, canonical.ZIP_SHA)
        self.assertEqual(current.EXE_SHA, canonical.MEMBERS['candidate.exe'][1])
        self.assertEqual(current.PCK_SHA, canonical.MEMBERS['candidate.pck'][1])
        self.assertEqual(current.MANIFEST_SHA, canonical.MEMBERS['export-evidence.json'][1])

    def test_old_source_and_artifact_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            receipt = {'schema_version': 1, 'source_sha': '4c22875c5ed79d393516c6a7a95361b9e9ed1950',
                       'factory_artifact_id': 13642354096}
            with self.assertRaisesRegex(SoftwareBaselineHold, 'SOFTWARE_BASELINE_HOLD'):
                current.verify_software_baseline(receipt, Path(tmp))


if __name__ == '__main__':
    unittest.main()
