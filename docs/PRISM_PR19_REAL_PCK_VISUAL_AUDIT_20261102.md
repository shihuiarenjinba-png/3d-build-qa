# Prism Route 3D — PR19 actual-PCK visual audit (software-only)

**Evidence boundary:** This is a cloud Godot 4.3 software-rendered observation of the exact PR19 PCK, **not** a physical Windows / 125–150% DPI / human usability pass, not a Store image, and not permission to promote the product.

## Exact consumer lineage and independent receipt

- Factory Draft PR #19 source `0878f48c79073596e30fed37a5703e0826389862`
- Request `3d-prism-route-3d-0878f48c7907`
- Factory run [#41444879105](https://github.com/shihuiarenjinba-png/3d-game-factory/actions/runs/41444879105); artifact `13142680551`
- Artifact ZIP SHA256 `447c18e789acc1b1ca12c08bdce8b3cda030baf0c7abc70a452bde7e0c748800`
- EXE SHA256 `66b26ad96df7458ea917b632a73ac7c88bb058db24dbd11a457fd50435ab7b13`
- PCK SHA256 `4036486c320c858b06a43ce632d063a6ab034f273b5f70e7861a5b663d1406fc`, 6,979,328 bytes
- Manifest SHA256 `5d06d46fc2a3a19325e77edc311f4dcb58d456c0dc9df5e872242b8c6098f11e`
- QA run [#41454758338](https://github.com/shihuiarenjinba-png/3d-build-qa/actions/runs/41454758338); software evidence artifact `13145583388`
- QA receipt status `PCK_LOADED_SOFTWARE_RUNTIME_QA_PASS_NOT_HUMAN_GUI`, source/request/ZIP/EXE/PCK/manifest SHA matched, 14 PCK resources, prohibited resources absent.

## Actual 1024×768 software frames, pinned SHA256

| Frame | SHA256 |
| --- | --- |
| guide_en | `5830b03efb117cbe9b2a96559347127c61a73b9eafcaa25ae17c000dc5bbd0d0` |
| guide_ja | `290542eccf9f63bb33b941ee799cc2ab4eeb64c466ea488ff2b1e589b2179f49` |
| initial | `1cfeb2fd4ed6104a86a0600cbfc2f3cb964c1f962fb41dae36e7fc73239d311d` |
| ja | `13a667b59d151b27993df4a58b57f05a71d9fdea4b6352a8cffdbeae220e1480` |
| scan | `2a4b3fc37acc924a87a7ce64ea03aa8ad52e2c4c99b0576696675e8c3a6c43ea` |
| trap | `a37d111ff0dfb13c106cf9fda1ab455942b4e07f5c34d1ab67f9b62bf5f8a705` |
| win | `cd1e5fe07c7beef06f88e07a68e55757a0e6f088f620f4d66c62e7f5f06c66a9` |

Runtime assertions cover EN/JA four-line guide, timer frozen before Start, numbered towers 1→2→3, yellow/red Sentinel, time/warp traps, win/timeout/retry, simulated 90s state progression and 1024×768 board bounds (504×442px). Japanese glyphs are present, with no previously observed tofu boxes in the reviewed guide. These assertions are not proof of 90 seconds of human play.

## Single prioritized consumer defect: gameplay HUD readability

The real `guide_ja` frame shows **thin gray text on gray/dark panels** in the top status/scan and bottom hint HUD, with small button labels. The onboarding modal itself is legible and its Start button is visible; do not conflate this with a HUD pass. The defect may be worse at Windows 125%/150% scaling. A separate **Draft Factory PR #20** proposes brighter HUD text, darker opaque panels and larger text/buttons with positive/negative headless contrast fixtures. PR20 has its **own source SHA and request**, and its new real PCK must be exported and independently reverified; **PR19 screenshots may not be relabelled** as PR20 evidence.

## Hold boundary

Physical Windows 1024×768 at 125%/150%, uncoached JA/EN first 30 seconds, real-time human 90-second play, enjoyment, loss comprehension, replay motivation, Store screenshot quality and uniqueness remain `DEFERRED_LOCAL_GATE` / `CONSUMER_QA_HOLD`. PR18 source `3c5a1e6837118a73609a0b9c9b7b54dfa4c14f0d`, artifact `13130487252` and old Identity return `11417b7...` are historical only. No current-lineage CAS/Version/signed MSIX, central ledger write, Partner Center, Store, main/release, merge or second 3D product.
