# Prism Route 3D Sentinel — RELEASE_PCK_CONTENT_HOLD (2026-11-02)

## What was actually inspected
Preserved Factory Artifact #12909162367 ZIP `dc60f397e002bddf63a8f64ec263dd241a3eb8c4f7fd6e6595d115a9f273ae9c` contains `candidate.pck` SHA256 `3e92b7b6e336a0ab40419448b79f330cf00e0cba4d6bb9ec864ba70b89ecdb03`, 71,568 bytes. Local read-only Godot PCK v2 directory parsing verified all 14 resources' MD5 and found **four** release-prohibited resources:

| Exact exported resource | Why blocked | Proposed source/export exclusion |
| --- | --- | --- |
| `res://store/approved-identity.json` | Historical Identity refers to **15fdcb52**, not pinned Sentinel e432d94; consumer should never receive internal Partner Center evidence | `store/approved-identity.json` |
| `res://product-manifest.json` | Factory/internal metadata should be a build-sidecar, not consumer game payload | `product-manifest.json` |
| `res://tests/test_smoke.gd.remap` | Development test export remap | `tests/**` |
| `res://tests/test_smoke.gdc` | Compiled development test script | `tests/**` |

The **existing pinned PCK must stay HOLD**. No amount of fixture PASS or source headless PASS upgrades these bytes.

## Gate added to 3d-build-qa

- `prism_sentinel_release_pck_content_gate.py` reads actual PCK bytes when supplied, parses the Godot 4.3 v2 resource directory, checks all resource MD5s, path safety, duplicate entries, bounds, resource overlap and SHA256/size against the pinned Factory PCK. Forbidden paths produce `RELEASE_PCK_CONTENT_HOLD`. A wrong PCK cannot impersonate the Factory PCK.
- `tests/test_prism_sentinel_release_pck_content_gate.py` generates tiny **synthetic** PCKs to exercise clean-but-not-product, old Identity, Factory manifest, development script, corrupted payload, duplicate/traversal path and wrong-SHA negatives. No synthetic fixture can become SALE_READY.
- CI Ubuntu consumes `evidence/prism-sentinel-pck-resource-inventory-20261102.json` as **historical inventory only**, expecting HOLD and exit code 2. CI Windows runs the negative fixture tests. Neither job downloads the actual Factory ZIP; do not describe this CI as a new live PCK verification.
- Independent local real-byte receipt: `evidence/prism-sentinel-real-pck-content-hold-20261102.json`.

## Proposed change for the next explicitly authorized gameplay/export revision

In the **new revision only**, update the Godot project's `products/prism-route-3d/export_presets.cfg` Windows export preset's `exclude_filter` to omit the exact files above. Example candidate glob list (must be verified against Godot 4.3 export behavior): `store/approved-identity.json,product-manifest.json,tests/*,tests/**/*`. Prefer an explicit export allowlist or staged consumer-only project if the exclusion globs do not remove both test .gdc and .remap. Do **not** remove `scripts/game_logic.gd`, `scripts/main.gd`, `scripts/save_store.gd`, `scenes/main.tscn` or the runtime resources.

Keep `product-manifest.json` and the official Identity receipt as **CI/Factory/Provisioner sidecars outside the consumer PCK**, not as runtime assets. Keep QA test scripts in source control and headless CI, not in release exports. Add a release export inspection step that rejects `res://store/`, `res://tests/`, and `res://product-manifest.json` before packaging. Check that Godot export still starts and the 90-second state transitions still pass.

Required fresh provenance after any export change: new `source_sha` and `request_id`, new Factory build head, real Windows EXE/PCK SHA and sizes, manifest and signed-package checks, new independent receipt, new approved Version, and 36-owner check-only official Store Identity rebind/CAS. **Never** relabel e432d94 source or reuse old PCK with a new manifest.

## Consumer gate remains independent

Headless Godot 4.3 source tests are not exported PCK execution or physical Windows GUI. Tower order numbers/sequence, Sentinel scan cone preview, traps, failure reasons, restart, 90-second play, Japanese/English, and 1024×768 at 125% and 150% DPI require visual/input evidence before SALE_READY. The absence of obvious tower numbers is the current consumer-facing readability blocker; revise UI only in a new authorized source revision. No Partner Center action, second 3D game, central ledger change, Store submission or merge is authorized here.
