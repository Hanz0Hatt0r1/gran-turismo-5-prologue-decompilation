# Roadmap

## Phase 0 — Foundation

- [x] Repository scaffold
- [x] Research methodology
- [x] Contribution rules
- [x] Initial symbol/function database format
- [x] Build-agnostic PS3 PPU ELF indexer
- [x] Initial GT5 BCUS-98114 reference-build profile
- [ ] Complete build/region inventory for GT5 and GT5 Prologue
- [ ] Finalize semantic naming conventions

## Phase 1 — Executable and module inventory

- Index retail GT5 reference builds and updates.
- Index known GT5 Prologue builds/updates using the same schema.
- Catalog executable modules and high-level responsibilities.
- Resolve PS3 import NIDs and record import/export relationships.
- Establish stable function identities with normalized PowerPC fingerprints.
- Apply metadata to Ghidra without overwriting manually verified names.

## Phase 2 — Cross-build common-code map

- Compare GT5 retail against GT5 updates.
- Compare GT5 retail against GT5 Prologue.
- Classify matches as exact normalized-body, normalized-prefix, or manually verified.
- Transfer only research metadata (names, subsystem membership, evidence), never code.
- Identify shared subsystem families and build-specific forks.

## Phase 3 — Core subsystem map

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

## Phase 5 — Formats and tooling

- Document relevant metadata/file formats from independent analysis.
- Improve RTTI/vtable and import/export recovery.
- Add call-graph and string-xref extraction.
- Automate symbol/address mapping and analysis reports.
- Add confidence-scored fuzzy cross-build matching.

## Phase 6 — Integration

- Connect reconstructed subsystems.
- Add regression tests.
- Track unknown functions and behavior gaps.
- Document compatibility assumptions per game/build.