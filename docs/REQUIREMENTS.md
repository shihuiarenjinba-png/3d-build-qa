# 3D build QA acceptance boundary

This package checks **only the structure and internal consistency of a claimed Windows-run receipt**. It does not run Unreal Engine, install an application, inspect a screenshot, verify a real runner or validate SHA-256 against bytes. Positive output is EVIDENCE_REVIEW, not PASS. Report HOLD for failed/skipped/zero tests, crashes, or launch failure. Forged evidence can pass the shape check: actual GitHub run provenance, artifact bytes, Windows runtime, GPU performance and visual comparison must be independently verified before downstream handoff.

Future integration: Windows GPU-capable self-hosted or cloud-hosted runner; pinned engine version, deterministic asset license inventory, build artifact hash verification, meaningful end-to-end input control tests, graphics presets (integrated GPU/high-end), performance and first-run UI assessment. Never assume local user PC is the production runner. Bridge and Windows-all-auto require separate authenticated evidence verification. No package submission.


## MSIX byte-integrity gate (2026-10-26)

Run after obtaining a real MSIX from the exact GitHub Actions Artifact, not a test fixture:

    python msix_artifact_verify.py --receipt windows-receipt.json --package candidate.msix --approved-identity approved-identity.json

The command streams SHA-256 over actual package bytes, checks that the claimed hash matches, reads the root AppxManifest.xml from the MSIX ZIP container without extraction, and compares its Name, Publisher and Version to the reviewed Partner Center record. It rejects missing/duplicate manifests, malformed XML, altered bytes and unsupported archive types. Without a reviewed identity record, even a matching package is HOLD. The CLI exits 0 only for EVIDENCE_REVIEW, and 2 for HOLD/BLOCKED.

**EVIDENCE_REVIEW is not a QA pass.** The provided identity JSON is an untrusted claim until independently checked against an authenticated Partner Center session; this tool does not authenticate that session. A syntactically valid ZIP with AppxManifest.xml is not necessarily an installable MSIX. The tool does not validate package signatures, full Appx schema, Godot runtime, Windows/GPU behavior, GitHub Artifact origin, screenshots, WACK, Store ID or Microsoft certification. The separate authorized pipeline must perform those checks before any Store handoff. No OpenAI API key, Ollama, package upload, repository creation or Store submission is performed.

## Windows ZIP entry safety preflight (2026-10-27)

Before reading the manifest, the verifier now checks every archive entry for
Windows-safe relative paths, case-insensitive collisions (including non-executable
assets), DOS device names, alternate data streams, trailing spaces/dots,
file/directory ancestor conflicts, symlinks, Unix device/FIFO/socket entries, mismatched file/directory type markers, encryption, unsupported compression
and bounded uncompressed size/expansion ratio. A failure is **BLOCKED**, not
EVIDENCE_REVIEW. These tests use synthetic ZIP fixtures only, not a produced
3D MSIX. They do not authenticate official Partner Center Identity, validate
AppxBlockMap/signatures, install the package, or prove GPU/gameplay QA.


## AppxBlockMap structural and SHA-256 gate (2026-10-27)

The byte verifier now **requires** a root `AppxBlockMap.xml` and checks its
canonical Microsoft block-map XML namespace, SHA-256 HashMethod, complete
non-footprint file coverage, unique File entries, uncompressed file Size,
actual ZIP local-file-header (LfhSize), the exact 64-KiB block count and
each block's SHA-256 against decompressed package bytes. For DEFLATE entries
the declared positive compressed Block Sizes must sum to the ZIP member's
compressed size. Invalid, missing, mismatched or spoofed block maps are
**BLOCKED**. Parsing and reads are bounded; this follows the Windows path
and ZIP CRC/decompression guards.

The regression fixtures include omitted files, missing/forged block maps,
wrong hashes, wrong XML namespace, duplicate files, altered LFH/size/hash
metadata, multi-block uncompressed content and single-block DEFLATE.
The fixtures are **not** MakeAppx-produced, signed, installable or commercial
MSIX packages. This check does **not** authenticate the block-map signature,
Partner Center, GitHub provenance, WACK, Windows installation or GPU/gameplay.
Even a successful check remains EVIDENCE_REVIEW, not product PASS.

Specification: https://learn.microsoft.com/en-us/uwp/schemas/blockmapschema/element-block
and https://learn.microsoft.com/en-us/uwp/schemas/blockmapschema/element-file
