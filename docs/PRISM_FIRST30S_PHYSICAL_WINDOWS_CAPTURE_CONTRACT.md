# Prism Route 3D — check-only physical Windows capture contract

**Status: DEFERRED_LOCAL_GATE.** Cloud Godot screenshots are not physical Windows evidence. This contract applies **only** to the new first-30s consumer lineage; older Sentinel/consumer PCK and Identity return commit `11417b7...` cannot be relabelled.

- Factory Draft PR #20 source: `f015db1762fb63696bcca304028871235142bf3d`
- Request: `3d-prism-route-3d-f015db1762fb`
- Factory Artifact: `13149467845` / run `41463172094`
- EXE SHA256: `66b26ad96df7458ea917b632a73ac7c88bb058db24dbd11a457fd50435ab7b13`
- PCK SHA256: `10acb61a586caa55b2da59ed0aae62f0952cfbaf7a69cac3cf219f3ae2a982c9`
- PR19 is also historical for this new HUD revision: source `0878f48c79073596e30fed37a5703e0826389862`, Artifact `13142680551`, PCK SHA `4036486c320c858b06a43ce632d063a6ab034f273b5f70e7861a5b663d1406fc` must be rejected. The new PR20 source/request/PCK are a separate lineage.
- PR18 is stale for this contract: source `3c5a1e6837118a73609a0b9c9b7b54dfa4c14f0d`, Artifact `13130487252`, PCK SHA `7a7d5243452786dcb7eb265d1dbdd6309e596f9d370d73bf0d8f8023b5096060` must be rejected. The Windows EXE template SHA may remain identical between revisions; never use EXE equality alone as lineage proof.
- Partner Center route: `MSIX_OR_PWA_GAME` / `MSIX or PWA game`. Identity CAS, approved Version and signed Store MSIX remain 36-owner HOLD.

## Procedure (physical Windows only)

1. **Do not install unsigned MSIX or bypass Code Integrity.** Run only when Windows permits the exact verified EXE/PCK under the normal security policy. If launch is blocked, record `DEFERRED_LOCAL_GATE`; do not substitute cloud screenshots.
2. On the actual 1024×768 Windows display, run four **separate uncoached first-launch sessions**: JA/125%, JA/150%, EN/125%, EN/150%. Record operator, OS build, timestamps with timezone, and actual binary paths. Hash both files before capture. Repeated sessions must reset first-launch onboarding state without tampering with product behavior.
3. For each session, before coaching, measure seconds until the tester explains the 1→2→3 goal, WASD/arrows, yellow warning/red scan, orange −15s and purple −8s+warp, and Start. All must be independently understood within 30 seconds. Check timer remains frozen before Start.
4. After Start, **actually play for at least 90 seconds of wall-clock time**. Observe tower order, scan warning/hit, trap penalty, loss reason, pause, end and retry. Time manipulation or scripted headless progression does not count. If a player cannot explain a loss or refuses to retry, hold consumer quality.
5. At each language/DPI, capture six distinct real screenshots: `guide`, `active`, `scan_warning`, `trap`, `outcome`, `retry`. Each must be a 1024×768 PNG with no HUD clipping, debug labels or developer paths. Keep screenshot names unique across all sessions. Record any visual quality concern even when the gate parses.
6. Run the check-only command on that **same physical Windows machine**:

```powershell
py -3 prism_first30s_physical_windows_gate.py --capture physical-capture.json --screenshot-dir .\physical-frames --out physical-review-receipt.json
```

The evaluator verifies exact source/request/Artifact/EXE/PCK values, hashes the two files from disk, checks all four language/DPI sessions, timestamps, comprehension/90s/retry flags and screenshot PNG CRC/dimensions/uniqueness. Missing or contradictory evidence yields nonzero exit code and `DEFERRED_LOCAL_GATE`.

## Capture JSON shape (values shown are placeholders, not evidence)

```json
{
  "schema_version": 1,
  "capture_kind": "PHYSICAL_WINDOWS_OPERATOR_ATTESTATION",
  "source_sha": "f015db1762fb63696bcca304028871235142bf3d",
  "request_id": "3d-prism-route-3d-f015db1762fb",
  "factory_artifact_id": 13149467845,
  "exe_sha256": "66b26ad96df7458ea917b632a73ac7c88bb058db24dbd11a457fd50435ab7b13",
  "pck_sha256": "10acb61a586caa55b2da59ed0aae62f0952cfbaf7a69cac3cf219f3ae2a982c9",
  "exe_path": "C:/qa/prism/candidate.exe",
  "pck_path": "C:/qa/prism/candidate.pck",
  "physical_device": true,
  "operator": "ACTUAL_TESTER",
  "windows_build": "ACTUAL_WINDOWS_BUILD",
  "sessions": [
    {
      "language": "ja",
      "dpi_percent": 125,
      "resolution": [1024, 768],
      "capture_started_at": "2026-11-02T19:00:00+09:00",
      "capture_finished_at": "2026-11-02T19:03:00+09:00",
      "elapsed_play_seconds": 90,
      "first_goal_seconds": 20,
      "uncoached_first_launch": true,
      "start_pressed": true,
      "goal_understood_in_30s": true,
      "tower_order_1_2_3_understood": true,
      "controls_understood": true,
      "sentinel_colors_understood": true,
      "traps_understood": true,
      "start_action_understood": true,
      "clock_frozen_until_start": true,
      "no_clipping": true,
      "no_debug_ui": true,
      "failure_reason_understood": true,
      "retry_completed": true,
      "screenshots": {
        "guide": "ja-125-guide.png",
        "active": "ja-125-active.png",
        "scan_warning": "ja-125-scan.png",
        "trap": "ja-125-trap.png",
        "outcome": "ja-125-outcome.png",
        "retry": "ja-125-retry.png"
      }
    }
  ]
}
```

The sample has **only one of four required sessions**, and therefore MUST fail. Replace all placeholders with observed facts and add JA/150%, EN/125%, EN/150%. Never mark a failed observation `true` just to satisfy the parser.

## Evidence boundary

Even when all machine-readable checks pass, the **only positive status** is `PHYSICAL_QA_EVIDENCE_REVIEW_REQUIRED`, **not** physical QA PASS or SALE_READY. Operator-supplied screenshots and declarations are not cryptographic proof that a physical GPU rendered the exact binary. A human reviewer must verify genuine Windows provenance, readability, 30-second understanding, enjoyment, distinctiveness and willingness to retry. Only the 36 owner may progress Identity CAS/Version/Store routing. This QA lane never modifies central ledger, submits to Store, merges PRs or creates a second 3D product.
