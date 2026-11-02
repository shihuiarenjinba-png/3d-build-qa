# Prism Route 3D — physical Windows first-30s consumer QA (HOLD)

This is a **manual gate**, not a cloud/fixture PASS. Do not upload these cloud frames as Store screenshots.

## Preconditions
- Run only the exact signed/approved product lineage after the 36-owner official Identity CAS and Package Version gate. Until then use a clearly marked QA build only; do not install unsigned MSIX or weaken Windows Code Integrity.
- Capture source SHA, request ID, Factory artifact ID, EXE/PCK SHA256, OS build, monitor resolution, Windows scaling, screenshot timestamps and operator identity. If the installed/running binary cannot be tied to those bytes, mark `PROVENANCE_HOLD`.
- Physical Windows display at **1024×768**, repeat at **125% and 150% DPI**. Check JP and EN, with normal window focus and focus loss.

## Human observation (do not prompt the tester)
1. On first launch, before pressing Start, ask what the goal is and which tower comes first. Within 30 seconds the tester should independently identify **1→2→3**, movement controls, yellow Sentinel warning vs red active scan, orange −15s and purple −8s+warp, and the Start action. Record correct/incorrect for each; no coaching.
2. Verify the first-run guide is opaque and readable, its button visually obvious, and the 90-second clock remains at 90 until Start. Check no clipping/overlap at each DPI.
3. Start and play 90 seconds with keyboard and mouse. Verify tower numbers/next target, warning lead time, hit reason, time/warp penalties, pause/focus-loss behavior, timeout, win and immediate restart. Record time-to-first-move, first mistake, reason understood, and whether the player wants to retry.
4. Capture the **real Windows** first guide (EN/JA), first active board, yellow warning, red scan, orange/purple trap, win/fail, and restart. Do not present software-rendered frames as physical screenshots.
5. Inspect consumer value: route choice must feel distinct from a Pac-Man-like chase; no developer paths, debug text, old Identity, or technical labels should appear. If the tester cannot explain a loss or finds no reason to retry, `CONSUMER_QA_HOLD`.

## Promotion rules
- Software Godot 4.3 PCK runtime, seven screenshots, SHA and source checks are **CLOUD_PASS only**.
- Physical Windows 1024×768 / 125% / 150%, first-30s comprehension and human 90-second play remain **DEFERRED_LOCAL_GATE** until witnessed evidence exists.
- No Identity CAS, Package Version, signed MSIX, Store submission, central ledger edit, main/release write, merge, or second 3D product by this QA lane.
