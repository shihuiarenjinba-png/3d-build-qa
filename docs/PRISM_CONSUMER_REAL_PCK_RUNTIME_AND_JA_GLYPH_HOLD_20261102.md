# Prism Route 3D — exported consumer PCK software-runtime QA (2026-11-02)

## Verified artifact and evidence boundary

- Product: Prism Route 3D; MSIX_OR_PWA_GAME / "MSIX or PWA game".
- New consumer source: da6f7c129687922c58c43496da4667ecef903e17; request 3d-prism-route-3d-da6f7c129687.
- Factory run 41394020607, Artifact 13118228531, actual ZIP SHA256 8e7610217874136197f7cf9157bcc239444c1ae74097b51a3b461c3d0d0c6390.
- Exported PCK: 48,320 bytes, SHA256 6e04300b176f923c9dda5777c5115af4e7670dad1d2c677fb271ba9e395fef57, 10 resources, 0 forbidden internal resources.
- QA: [real-PCK run 41400284402](https://github.com/shihuiarenjinba-png/3d-build-qa/actions/runs/41400284402) with five software-rendered 1024×768 PNGs and SHA-bound receipt in artifact 13121142145; [general QA run 41400284301](https://github.com/shihuiarenjinba-png/3d-build-qa/actions/runs/41400284301). Both SUCCESS.
- Unlike historical source-only or receipt-only checks, this run downloaded and SHA-verified the real new Factory ZIP, loaded the exported PCK through Godot 4.3 --main-pack, exercised deterministic first-30s/90s state transitions, and captured Mesa llvmpipe/Xvfb frames. It did NOT execute the Windows EXE or physical Windows GPU/DPI. 90 seconds were advanced programmatically, not played by a human for 90 wall-clock seconds.

## Consumer defect: Japanese UI is unreadable

- The actual ja.png from the exported PCK contains many square replacement glyphs in the Japanese HUD, instructions, and buttons. This is a visible consumer blocker, not a hypothetical concern.
- Runtime Font.has_char checks for representative Japanese glyphs returned false in this Linux software-render environment. Receipt: japanese_visual_quality=HOLD_MISSING_JAPANESE_GLYPHS_IN_SOFTWARE_RENDER.
- English first frame is readable and numbered towers 1→2→3 are visible, but the 5×5 platform occupies a relatively small central region amid a large unused grey background. Scan/trap colors appear, but human legibility and commercial appeal remain unverified.
- Do not claim this exact glyph failure is proven on physical Windows. It is proven for this shipped PCK in the CI renderer; EN/JA is mandatory, so SALE_READY remains HOLD.

## Required separate Factory Draft revision

1. Add an explicitly licensed, distributable Japanese-capable font with license text, and verify the font is actually bundled in the new consumer PCK. Do not rely on CI runner system fonts; do not add unlicensed font binaries.
2. Apply the font to all Japanese HUD, hints, and buttons; preserve EN/JA choice across restarts. Add glyph coverage assertions and actual Japanese screenshots.
3. Improve board screen occupancy, next-tower salience, and scan-warning clarity without Pac-Man-style chasing enemies.
4. Re-export with a new source SHA/request ID, rehash EXE/PCK/manifest, and re-run the exported-PCK-bound QA. Never relabel immutable Sentinel e432d94... or consumer da6f7c... artifacts.
5. Physical Windows 1024×768 at 125%/150% DPI, real 90-second human input, first-30s comprehension, Store-quality screenshots and purchase-worthiness remain independent HOLD gates.

## Downstream boundary

Historical Identity return commit 11417b75636ee18816028ffd5221884c4c9a9836 is NOT a CAS for this consumer revision. Only the 36-minute Windows owner may officially rebind Store Identity, approve Package Version, create signed product MSIX or update central ledger. This QA work performs no Partner Center, Store, merge, main/release or second-product action. SALE_READY=false.
