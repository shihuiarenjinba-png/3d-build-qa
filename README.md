# 3d-build-qa

Offline 3D Windows QA **receipt contract**, not a complete Unreal/GPU build runner.

```bash
python -m unittest discover -s tests -v
python qa_gate.py path/to/windows-receipt.json
```

Outputs BLOCKED/HOLD/EVIDENCE_REVIEW only. Even EVIDENCE_REVIEW is not independently verified evidence and never authorizes Store submission. See [requirements](docs/REQUIREMENTS.md).
