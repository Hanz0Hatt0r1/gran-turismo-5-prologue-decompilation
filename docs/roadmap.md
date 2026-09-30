# Roadmap

## Phase 0 — Foundation

- [x] Repository scaffold
- [x] Research methodology
- [x] Contribution rules
- [ ] Build/region inventory
- [ ] Naming conventions
- [ ] Initial symbol/function database format

## Phase 1 — Executable and module inventory

- Identify known GT5 Prologue builds/updates.
- Catalog executable modules and high-level responsibilities.
- Record entry points and import/export relationships.
- Establish stable function identifiers.

## Phase 2 — Core subsystem map

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

## Phase 3 — Function reconstruction

For each subsystem:

1. identify function groups;
2. document call graphs and data structures;
3. assign evidence-backed names;
4. reconstruct behavior under `src/`;
5. add tests where behavior can be isolated.

## Phase 4 — Formats and tooling

- Document relevant metadata/file formats from independent analysis.
- Build original parsers and validators.
- Automate symbol/address mapping and analysis reports.

## Phase 5 — Integration

- Connect reconstructed subsystems.
- Add regression tests.
- Track unknown functions and behavior gaps.
- Document compatibility assumptions.
