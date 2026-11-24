"""Static contract tests for the guided Windows physical-capture helper."""
from pathlib import Path
import re
import unittest

from prism_pr25_physical_handoff import FILES, INSTRUCTIONS

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "prism_capture_physical_qa.ps1"


class CaptureRunnerContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = SCRIPT.read_text(encoding="utf-8")

    def test_runner_is_in_the_offline_handoff_and_readme(self):
        self.assertIn("prism_capture_physical_qa.ps1", FILES)
        self.assertIn("prism_capture_physical_qa.ps1", INSTRUCTIONS)

    def test_all_six_language_dpi_sessions_and_six_states_are_explicit(self):
        self.assertIn("foreach ($Language in @('ja', 'en'))", self.source)
        self.assertIn("foreach ($DpiPercent in @(100, 125, 150))", self.source)
        for state in ("guide", "active", "scan_warning", "trap", "outcome", "retry"):
            self.assertRegex(self.source, rf"key\s*=\s*'{state}'")
        self.assertIn("$Frames[$Frame.key] = $FileName", self.source)
        self.assertIn("$GuideFrame.key", self.source)

    def test_physical_capture_and_dpi_are_checked_not_inferred(self):
        for required in (
            "GetDpiForWindow", "SetThreadDpiAwarenessContext", "Screen]::PrimaryScreen.Bounds",
            "CopyFromScreen", "PHYSICAL_WINDOWS_OPERATOR_ATTESTATION", "physical-capture.json",
            "ALLOWED_BY_EXISTING_POLICY", "Wait-ForActualNinetySeconds", "Get-FileHash",
            "UTF8Encoding]::new($false)",
        ):
            self.assertIn(required, self.source)

    def test_guide_is_captured_before_start_and_frames_are_not_overwritten(self):
        self.assertLess(self.source.index("$GuideFrame = $FramePlan[0]"),
                        self.source.index("ゲーム内でStartを押す"))
        self.assertIn("physical-capture.json already exists", self.source)
        self.assertIn("physical-frames already contains files", self.source)

    def test_no_windows_security_bypass_commands(self):
        banned = (
            r"(?im)^\s*Set-ExecutionPolicy\b",
            r"(?im)^\s*Add-MpPreference\b",
            r"(?im)^\s*Set-MpPreference\b",
            r"(?im)^\s*bcdedit\b",
            r"(?im)^\s*reg\s+add\b",
            r"(?im)^\s*Set-ItemProperty\b.*(?:CodeIntegrity|SmartScreen)",
        )
        for pattern in banned:
            self.assertIsNone(re.search(pattern, self.source), pattern)
        self.assertIn("do not bypass security", self.source)


if __name__ == "__main__":
    unittest.main()
