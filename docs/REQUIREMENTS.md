# 3D build QA acceptance boundary

This package checks **only the structure and internal consistency of a claimed Windows-run receipt**. It does not run Unreal Engine, install an application, inspect a screenshot, verify a real runner or validate SHA-256 against bytes. Positive output is EVIDENCE_REVIEW, not PASS. Report HOLD for failed/skipped/zero tests, crashes, or launch failure. Forged evidence can pass the shape check: actual GitHub run provenance, artifact bytes, Windows runtime, GPU performance and visual comparison must be independently verified before downstream handoff.

Future integration: Windows GPU-capable self-hosted or cloud-hosted runner; pinned engine version, deterministic asset license inventory, build artifact hash verification, meaningful end-to-end input control tests, graphics presets (integrated GPU/high-end), performance and first-run UI assessment. Never assume local user PC is the production runner. Bridge and Windows-all-auto require separate authenticated evidence verification. No package submission.


## MSIX byte-integrity gate (2026-10-26)

Run after obtaining a real MSIX from the exact GitHub Actions Artifact, not a test fixture:

    python msix_artifact_verify.py --receipt windows-receipt.json --package candidate.msix --approved-identity approved-identity.json

The command streams SHA-256 over actual package bytes, checks that the claimed hash matches, reads the root AppxManifest.xml from the MSIX ZIP container without extraction, and compares its Name, Publisher and Version to the reviewed Partner Center record. It rejects missing/duplicate manifests, malformed XML, altered bytes and unsupported archive types. Without a reviewed identity record, even a matching package is HOLD. The CLI exits 0 only for EVIDENCE_REVIEW, and 2 for HOLD/BLOCKED.

**EVIDENCE_REVIEW is not a QA pass.** The provided identity JSON is an untrusted claim until independently checked against an authenticated Partner Center session; this tool does not authenticate that session. A syntactically valid ZIP with AppxManifest.xml is not necessarily an installable MSIX. The tool does not validate package signatures, full Appx schema, Godot runtime, Windows/GPU behavior, GitHub Artifact origin, screenshots, WACK, Store ID or Microsoft certification. The separate authorized pipeline must perform those checks before any Store handoff. No OpenAI API key, Ollama, package upload, repository creation or Store submission is performed.
