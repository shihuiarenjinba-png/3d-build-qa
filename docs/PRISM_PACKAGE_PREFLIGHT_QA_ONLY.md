# Prism package preflight — QA fixture only, not product MSIX

This stacked draft uses the exact 3d-build-qa PR19 HEAD:
9b90bfc9dfa6ded9699c3f22df45390be909dae8. Factory source is unchanged.

Factory source b03ce7b16c3f75c04fe20fdda224c45849eeba0d, request
3d-prism-route-3d-b03ce7b16c3f, run 43794658086, artifact 14797309778.
Factory ZIP SHA256:
e2573b9ab11afde6ab6ec7417c23438581620a08bb9dcff76d792a2b5592ccac
EXE SHA256:
66b26ad96df7458ea917b632a73ac7c88bb058db24dbd11a457fd50435ab7b13
PCK SHA256:
b7abc0f9caf2e505a1dcaf834b4cb897d8f00df4060c31708914e8bb4f3d5666

The Ubuntu job re-downloads and verifies live artifact metadata, expiry, ZIP
CRC/member set, exact EXE/PCK/manifest sizes and hashes. It preserves the
original Factory ZIP byte-for-byte in a QA-owned 30-day artifact.

Deterministic proposed layout:
- candidate.exe -> VFS/ProgramFilesX64/PrismRoute3D/candidate.exe
- candidate.pck -> VFS/ProgramFilesX64/PrismRoute3D/candidate.pck
The AppxManifest Application Executable points at the EXE path; the external
PCK remains beside it. Three standard manifest image destinations are listed,
but official Store assets are absent from the Factory export and remain HOLD.

The Windows job only locates x64 MakeAppx, records version/hash/Authenticode
signer and runs the no-argument usage probe. It does not run makeappx pack,
create a package, install an SDK or alter the product payload.

Registration MSIX_OR_PWA_GAME maps to Partner Center "MSIX or PWA game";
GDK is rejected. Identity remains HOLD_36_OWNER. Missing, malformed,
synthetic and self-asserted Package Version values remain HOLD. No real
Identity, Version, Store write, product MSIX or sale approval is created.
Physical Windows QA remains 0/6 sessions and 0/36 screenshots until genuine
local evidence is collected and reviewed.


## Physical capture handoff preservation

The same Ubuntu custody job also verifies and preserves the exact PR19 physical
capture handoff, so the operator runner does not disappear when its original
short-retention artifact expires:

- Original artifact: 14952074847, run 45461731033, PR19 HEAD
  9b90bfc9dfa6ded9699c3f22df45390be909dae8
- Original ZIP SHA256:
  35ae3ea873e0b122fe2cb138a170cd233cf89c7c81e8fed4262139d366a4c4c6
- The verifier checks the complete member set, ZIP CRC, embedded original
  Factory ZIP SHA, EXE/PCK/manifest bytes, handoff receipt and empty 6-session /
  36-filename physical capture template.
- The handoff receipt must still declare physical screenshots 0, physical GUI
  HOLD, sale_ready false and Store submission false.
- Both the original Factory ZIP and the original physical handoff ZIP are
  retained together in the QA-owned artifact for 30 days. This preserves
  capture tooling and evidence, not physical QA itself.
