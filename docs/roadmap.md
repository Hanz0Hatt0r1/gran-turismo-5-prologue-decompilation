# Roadmap

## Phase 0 — Foundation

- [x] Repository scaffold
- [x] Research methodology
- [x] Contribution rules
- [x] Initial symbol/function data contract
- [x] Build-agnostic PS3 PPU ELF indexer
- [x] Initial GT5 BCUS-98114 reference-build profile
- [x] Establish an initial build/region inventory for GT5 and GT5 Prologue.
- [ ] Complete remaining region/revision inventory as additional verified builds become available.
- [x] Separate the GT5 Asia disc title ID `BCAS-20151` from packaging code `BCAS-20164`.
- [x] Finalize semantic naming conventions

## Phase 1 — Executable Intelligence

The executable-intelligence layer is the current engineering priority.

- [x] Parse PS3 ELF64/PPC64 program and section metadata.
- [x] Recover OPD descriptors and PPU entry points.
- [x] Discover additional function starts from direct calls and PPC64 stack prologues.
- [x] Generate normalized function fingerprints.
- [x] Recover RTTI/vtable and TOC/string evidence.
- [x] Extract PS3 import libraries, NIDs, and stub metadata.
- [x] Import existing Ghidra C exports and attach discovered-function identities.
- [x] Provide headless Ghidra orchestration.
- [x] Add synthetic regression coverage for the core indexer.
- [x] Promote the first reviewed GT5 BCUS-98114 build/function/entry evidence.
- [x] Audit function-boundary heuristics against confirmed GT5 entry/OPD data.
- [x] Add canonical BCUS-98158 GT5 Prologue build profile.
- [x] Resolve the GT5P bootstrap into reviewed function notes.
- [x] Record the NPEA-00050 `0x00010360` startup function and audit its portable P-code export.
- [x] Record a targeted decompilation of the NPEA-00050 startup continuation at `0x00010730` without promoting an unsupported semantic name ([review](../analysis/evidence/gt5p-npea00050-startup-continuation-10730-review-20261017.md)).
- [x] Reconcile Ghidra and static-indexer boundaries for `0x00010360` with branch-aware range traversal and a synthetic regression test.

## Phase 2 — Cross-build common-code map

- [ ] Compare GT5 retail against GT5 updates.
- [ ] Compare GT5 retail against GT5 Prologue.
  - [x] Add the locally supplied UK-marked NPEA-00050 Prologue ELF as a separately hash-pinned comparison build; keep it distinct from the canonical US BCUS-98158 profile.
  - [x] Accept the BCUS-98114 to NPEA-00050 ELFv1 entry-role relationship with scope limited to startup role; the first direct-call targets and normalized entry prefixes differ.
  - [ ] Review the 107 remaining of 127 generated normalized fingerprint candidates; the generated comparison ranks all as speculative, with twelve NPEA-00050 cross-reference records pending at probable confidence.
  - [x] Add an ELF-backed verifier that regenerates this comparison and checks the committed candidate CSV against both build profiles.
  - [x] Compare startup coordinators at `0x00010338` and `0x00010360`; record probable/pending role-level evidence while keeping the differing full functions out of the generated match table ([review](../analysis/evidence/gt5p-npea00050-gt5-startup-coordinator-review-20261017.md)).
    - [x] Inspect `0x00bb6ce0` to `0x00013a70`; the wrapper bodies match after branch normalization, but downstream helpers remain unverified, so both rows stay speculative ([review note](evidence/gt5p-npea00050-function-candidate-review-20261017.md)).
    - [x] Inspect `0x00cf2e10` to `0x0004b188`; both have the same 188-byte normalized body and imported `_cellGcmSetFlipCommand` call; the game-function role remains unresolved, so the row stays speculative ([review note](evidence/gt5p-npea00050-function-candidate-review-20261017.md)).
    - [x] Inspect `0x00cf2ecc` to `0x0004b270`, `0x00d01688` to `0x00050ac0`, and `0x00d01774` to `0x00050bb8`; each pair has an exact normalized body and matching imported API identity (`_cellGcmInitBody`, `sys_lwmutex_unlock`, or `sys_lwmutex_destroy`), while the game-function roles remain speculative ([review note](evidence/gt5p-npea00050-function-candidate-review-20261017.md)).
    - [x] Review `0x00d1cd64` to `0x00056270`; identical normalized bodies call the same `sys_lwmutex_lock` import and three exact caller pairs reach them at matching offsets, recorded as a probable/pending helper relation ([cross-reference](crossref/gt5-bcus98114-vs-gt5p-npea00050-lwmutex-lock-helper.yaml)).
    - [x] Review `0x00d1a534` to `0x000539c0`; the 320-byte normalized bodies and a matched caller pair support a probable/pending function-body relationship, without semantic or source identity ([review](../analysis/evidence/gt5p-npea00050-helper-00d1a534-review-20261017.md)).
    - [x] Review `0x00d18dd0` to `0x00052228`; the 172-byte normalized bodies match, but one callee pair is absent and another is only a prefix candidate, so the row remains speculative ([review](../analysis/evidence/gt5p-npea00050-function-candidate-review-20261017.md)).
    - [x] Review `0x00d1cda0` to `0x000562e8` and `0x00d1ce8c` to `0x000564d0`; both exact bodies call the same raw import NID, while caller and local-callee pairs remain unresolved, so both generated rows stay speculative ([review](../analysis/evidence/gt5p-npea00050-function-candidate-review-20261017.md)).
    - [x] Review `0x00d19ca0` to `0x00053118`; the common 256-byte normalized prefix and matched caller edges support a probable/pending call-graph role, while the full function bodies remain different ([cross-reference](../analysis/crossref/gt5-bcus98114-vs-gt5p-npea00050-prefix-00d19ca0.yaml)).
    - [x] Review `0x00d1a96c` to `0x00053e00`; the exact 576-byte body and four aligned callee edges support a probable/pending function-body relationship, with no semantic identity promoted ([cross-reference](../analysis/crossref/gt5-bcus98114-vs-gt5p-npea00050-function-00d1a96c.yaml)).
    - [x] Review `0x00bb6dbc` to `0x00013b50`; the exact 80-byte body, one matching callee, and two exact caller pairs support a probable/pending body relationship ([cross-reference](../analysis/crossref/gt5-bcus98114-vs-gt5p-npea00050-function-00bb6dbc.yaml)).
    - [x] Review `0x00bb6e0c` to `0x00013ba0`; the exact 76-byte body and aligned exact callee support a probable/pending relationship while incoming caller identities remain unresolved ([cross-reference](../analysis/crossref/gt5-bcus98114-vs-gt5p-npea00050-function-00bb6e0c.yaml)).
    - [x] Review `0x00bb6d74` to `0x00013b08`; the exact 72-byte body and two aligned exact caller pairs support a probable/pending body relationship, while its callee remains unresolved ([cross-reference](../analysis/crossref/gt5-bcus98114-vs-gt5p-npea00050-function-00bb6d74.yaml)).
    - [x] Review `0x00bb6c90` to `0x00013a20`; the exact 80-byte body and two aligned exact caller pairs support a probable/pending body relationship, while its downstream helper remains unresolved ([cross-reference](../analysis/crossref/gt5-bcus98114-vs-gt5p-npea00050-function-00bb6c90.yaml)).
    - [x] Review `0x00d1bf50` to `0x00055438`; the exact 376-byte body calls the reviewed lock-helper pair at `+0x60`, supporting a probable/pending relationship ([cross-reference](../analysis/crossref/gt5-bcus98114-vs-gt5p-npea00050-function-00d1bf50.yaml)).
    - [x] Review `0x00d1c130` to `0x00055618`; the exact 136-byte body calls the reviewed lock-helper pair at `+0x4c`, supporting a probable/pending relationship ([cross-reference](../analysis/crossref/gt5-bcus98114-vs-gt5p-npea00050-function-00d1c130.yaml)).
    - [x] Review `0x00d1ecc4` to `0x00056b40`; the exact 184-byte body calls the reviewed lock-helper pair at `+0x74`, supporting a probable/pending relationship ([cross-reference](../analysis/crossref/gt5-bcus98114-vs-gt5p-npea00050-function-00d1ecc4.yaml)).
  - [x] Audit the currently available local input identity; its raw ELF hash
    matches BCUS-98114, while its entry descriptor and TOC differ from the
    BCUS-98158 profile. The former SELF-vs-ELF hash comparison was invalid and
    is documented in [the identity audit](evidence/gt5p-local-input-identity-audit-20261017.md).
  - [ ] Re-run the comparison after a BCUS-98158 input verifies against its
    checked-in build profile.
  - [x] Accept structural ELFv1 entry identity as a reviewed role-level match.
  - [ ] Confirm CRT/common-code matches from normalized fingerprints using local indexes for both builds.
- [ ] Classify matches as normalized-full, normalized-prefix, or manually verified.
- [ ] Transfer only research metadata (names, subsystem membership, evidence), never code.
- [x] Accept the reviewed ELFv1 entry cross-build identity.
- [ ] Identify shared subsystem families and build-specific forks.
- [x] Add explicit review status to every promoted cross-build match.

## Phase 3 — Core subsystem map

- [x] Seed GT5 BCUS-98114 subsystem triage from retained source-file evidence.
- [x] Connect retained GT5 source-file strings to executable TOC-load xrefs.
- [x] Classify source xrefs by OPD function containment.
- [x] Map OPD-contained source xrefs to concrete function ranges.
- [x] Record OPD-contained source xrefs as a derived function snapshot.

Map:
- startup / main loop;
- memory and job systems;
- input;
- UI;
- rendering;
- audio;
- vehicle simulation / physics;
- race/session logic;
- save/profile data;
- networking;
- resource loading.

## Phase 4 — Function reconstruction

For each subsystem:
1. identify function groups;
2. document call graphs and data structures;
3. assign evidence-backed names;
4. reconstruct behavior under `src/`;
5. add tests where behavior can be isolated;
6. cross-check behavior against related builds where useful.

## Phase 5 — Formats and supporting tooling

- Document relevant metadata/file formats from independent analysis.
- Improve RTTI/vtable and import/export recovery.
- Add call-graph and string-xref extraction.
- [x] Add reviewed symbol/address catalog validation and search.
- [x] Add ELF-backed verification of reviewed build/function metadata.
- [x] Automate full cross-build verification from local indexes for both builds.
- [x] Allow targeted Ghidra decompilation by indexed function VA.
- Add confidence-scored fuzzy cross-build matching only where deterministic matching is insufficient.

## Phase 6 — Integration

- Connect reconstructed subsystems.
- Add regression tests.
- Track unknown functions and behavior gaps.
- Document compatibility assumptions per game/build.
