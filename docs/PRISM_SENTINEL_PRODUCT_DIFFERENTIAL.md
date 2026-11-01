# Prism Route 3D — Sentinel product differential (HOLD-only)

This contract consumes the independently downloaded Provisioner artifact-source discrimination receipt. It checks pinned Factory source/request/build HEAD, EXE and **PCK** digests, PRE role, the unsigned QA fixture role, and the newer **legacy** workflow role. It cannot substitute for live GitHub API/ZIP verification.

Run from this QA checkout with the Provisioner checkout available:

```bash
python prism_sentinel_product_gate.py \
  --audit ../Repository-Provisioner-3D/handoffs/prism-route-3d-artifact-source-discrimination-20261101-1325.json
```

Optional `--qa` must be the result of checking the **pinned unsigned fixture** using `msix_artifact_verify.py`. The only accepted fixture verdict is `BLOCKED` with a `fixture-only` reason. Optional `--identity` must never silently reuse the old `15fdcb52...` Identity as approval for `e432d94...`.

The CLI deliberately exits **2** even when the historical correlation is valid. Its output status is `HOLD_SENTINEL_HISTORICAL_BYTES_NOT_STORE_PRODUCT`; it is **not** an automated Store-ready check.

## Evidence and missing gates

- Sentinel source: `e432d94ed0db22878f61f1a8af140d7d7de2288f`
- Request: `3d-prism-route-3d-e432d94ed0db`
- Factory: run `40901053437`, artifact `12909162367`
- Sentinel PRE: run `41020501779`, artifact `12961277866`
- Sentinel unsigned MakeAppx QA: run `41020501832`, artifact `12961735943`
- Factory EXE SHA256: `66b26ad96df7458ea917b632a73ac7c88bb058db24dbd11a457fd50435ab7b13`
- Sentinel PCK SHA256: `3e92b7b6e336a0ab40419448b79f330cf00e0cba4d6bb9ec864ba70b89ecdb03`
- Original PCK SHA256: `2cd8af6496cf288bc3e6aef317e472b480f21d2052cbd4ae0cd171e6285ab1ef`

A matching EXE is **not** proof of a matching PCK. The newer 2026-11-01 Provisioner workflow outputs belong to the original source, not the Sentinel revision.

The unsigned MSIX carries a fixture Identity and is **not** a product package. Registration route remains `MSIX_OR_PWA_GAME` / `MSIX or PWA game`, not GDK. Official new-source Partner Center Identity capture and CAS, approved version, actual signed product MSIX, Windows-all-auto intake and Windows GUI/GPU QA remain unverified. Windows local gates are deferred. The central ledger belongs to the Windows/E2E owner. No second product or Store submission is authorized.
