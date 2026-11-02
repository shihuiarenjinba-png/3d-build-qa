# Prism Route 3D PR22 — physical Windows read-only evidence handoff

**Current status: PHYSICAL_HOLD.** This bundle is QA-only, not an MSIX, not a Store submission, and not a physical/human PASS. Software Godot Mesa/Xvfb images cannot be reused as physical images.

Immutable source `f4b458384243fdf379683ca793329614f61c9ead`, request `3d-prism-route-3d-f4b458384243`; Factory Artifact **13180284133** (EXE `66b26ad9...`, PCK `d1363805...`), software QA15 Artifact **13185037028** (eight JA/EN timeout/trap/Sentinel/retry images). Both archives are independently SHA/CRC checked in CI. The latter expires **2026-11-09 22:27:53 UTC**; after expiry the gate remains HOLD pending renewed custody. The old PR21 PCK, screenshots, and Identity commit `11417b7` cannot authenticate PR22.

## On a physical Windows PC

1. Extract the CI handoff artifact locally. Do not run unsigned MSIX, disable Defender/Code Integrity, elevate to bypass a block, or modify game files. Verify `factory-pr22.zip` and `software-qa15.zip` with the included Python gate before testing; use the extracted **candidate.exe** and **candidate.pck** together, in the same directory. If normal Windows security blocks launch, record **PHYSICAL_HOLD** and stop.
2. Use an actual 1024×768 primary desktop with the **Windows taskbar visible**. Test JA/EN at Windows display scaling **100%, 125%, 150%** (six sessions), ideally **six different first-time testers** to preserve uncoached first launch. Windows 1024×768 with visible taskbar may clip a 1024×768 game window: do **not** hide/crop the taskbar or claim visibility if clipped. This is a real potential UX failure.
3. For each tester, time the first 30 seconds without coaching. Ask them to describe the goal, tower order **1→2→3**, Start, controls, Sentinel scan timing/warning lane, and orange/purple trap penalties. Check the clock stays stopped before Start. Then have them actually play for **at least 90 wall-clock seconds**, encounter TIMEOUT, TRAP, Sentinel, and retry/failure recovery. A scripted clock advance or cloud simulation does not count. If one person cannot produce all three loss states naturally, the session remains HOLD rather than fabricating evidence.
4. With the game and taskbar on screen, capture seven distinct full-desktop PNGs per session using the included recorder. Example (repeat for all seven states, both languages and three scales):

```powershell
powershell -NoProfile -File .\Capture-PrismPR22PhysicalFrame.ps1 -Language ja -DpiPercent 125 -State guide -OutputDirectory .\physical-frames
powershell -NoProfile -File .\Capture-PrismPR22PhysicalFrame.ps1 -Language ja -DpiPercent 125 -State timeout -OutputDirectory .\physical-frames
```

The recorder refuses the wrong resolution/system DPI and overwrites. It records timestamps and SHA256 but never labels a screenshot as genuine human gameplay. A reviewer must inspect language, actual loss cause, taskbar, window clipping, and whether the user understood the game. **42 distinct PNGs** (2×3×7) are required.
5. Edit `physical-capture.EMPTY.json` into `physical-capture.json` using actual observations, six distinct pseudonymous tester IDs, actual timestamps (timezone required), Windows build, operator, and `code_integrity_status: "ALLOWED_BY_EXISTING_POLICY"` only if observed. Leave `physical_qa` and `human_fun` as `PHYSICAL_HOLD`, and `sale_ready` as false. Never change missing/failed answers to true to satisfy the gate.
6. Run the check-only aggregator **on the same physical Windows PC** (after extracting Factory candidate files):

```powershell
py -3 .\prism_pr22_physical_evidence_gate.py --factory-zip .\factory-pr22.zip --software-zip .\software-qa15.zip --exe .\candidate\candidate.exe --pck .\candidate\candidate.pck --capture .\physical-capture.json --frames .\physical-frames --out .\physical-review.json
```

The only successful machine status is `PHYSICAL_EVIDENCE_REVIEW_REQUIRED`; **never** physical PASS, human fun PASS, SALE_READY, Identity CAS, package version, or Store submission. Failed checks return exit code 2 and `PHYSICAL_HOLD`. This is still self-reported evidence requiring an independent human reviewer.

## Negative cases covered in CI

Old PR21 source/PCK/Artifact, wrong locale or missing 100/125/150 DPI, duplicate testers or screenshots, absent timeout/trap/Sentinel/retry frames, missing taskbar/unclipped observation, failed first 30 seconds, less than 90 real seconds, Code Integrity bypass, expired artifact, and false physical/human PASS are rejected. Windows hosted CI runs **fixtures only**; hosted runners are not a substitute for a consumer's physical PC.

Scope boundaries: no Factory code edits, no central ledger/Windows-all-auto edits, no second game, no Partner Center/Store, no Identity CAS, no main/release or merge.
