# Roadmap

## Phase 0 — Foundation

- [x] Repository scaffold
- [x] Research methodology
- [x] Contribution rules
- [x] Initial symbol/function data contract
- [x] Build-agnostic PS3 PPU ELF indexer
- [x] Initial GT5 BCUS-98114 reference-build profile
- [ ] Complete build/region inventory for GT5 and GT5 Prologue
- [ ] Finalize semantic naming conventions

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
- [ ] Add canonical BCUS-98158 GT5 Prologue build profile.
- [ ] Resolve the GT5P bootstrap into reviewed function notes.

## Phase 2 — Cross-build common-code map

- [ ] Compare GT5 retail against GT5 updates.
- [ ] Compare GT5 retail against GT5 Prologue.
- [ ] Classify matches as normalized-full, normalized-prefix, or manually verified.
- [ ] Transfer only research metadata (names, subsystem membership, evidence), never code.
- [ ] Identify shared subsystem families and build-specific forks.
- [ ] Add explicit review status to every promoted cross-build match.

## Phase 3 — Core subsystem map

- [x] Seed GT5 BCUS-98114 subsystem triage from retained source-file evidence.

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
- Automate symbol/address mapping and research reports.
- Add confidence-scored fuzzy cross-build matching only where deterministic matching is insufficient.

## Phase 6 — Integration

- Connect reconstructed subsystems.
- Add regression tests.
- Track unknown functions and behavior gaps.
- Document compatibility assumptions per game/build.
