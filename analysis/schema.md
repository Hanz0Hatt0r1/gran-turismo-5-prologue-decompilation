# Analysis data schema

The repository separates **source-of-truth research metadata** from generated local analysis output.

The schema is build-aware: an address is never meaningful without its build and module.

## Design rules

1. Every record identifies the exact build and module.
2. Absolute addresses are evidence, not stable cross-build identities.
3. Stable function identity comes from normalized fingerprints plus contextual evidence.
4. Semantic names require explicit evidence and confidence.
5. Generated indexes may be reproduced locally and must not contain proprietary input.
6. Cross-build matches transfer research metadata only; they do not establish semantic equivalence by themselves.

## Build record

Build records live under `analysis/builds/`.

Required fields: `schema`, `game`, `title_id`, `role`, `executable_sha256`, `format`, `entry_descriptor_va`, `entry_code_va`, and `toc_va` when known.

Example:

    {
      "schema": 1,
      "game": "Gran Turismo 5 Prologue",
      "title_id": "BCUS-98158",
      "role": "target-build",
      "executable_sha256": "<local-input-sha256>",
      "format": "ELF64-big-endian-PowerPC64"
    }

Never store the executable itself.

## Function record

Function-level records are keyed by build/module/address and carry a stable fingerprint where available.

Example:

    schema: 1
    id: gt5p.bcus98158.eboot.00106e0
    build: BCUS-98158
    module: EBOOT.BIN
    address:
      va: 0x106E0
    name:
      current: sub_106E0
      candidates:
        - game_bootstrap
    confidence: probable
    status: analyzed
    fingerprints:
      normalized_full: "<sha256>"
      normalized_prefix: "<sha256>"
    evidence:
      - type: callgraph
        detail: "reached from CRT/bootstrap chain"
      - type: import
        detail: "uses cellGameDataCheckCreate2"
    callers: []
    callees: []
    subsystems:
      - startup

The exact generated CSV format is defined by `tools/gtdecomp.py`; this document defines the semantic contract.

## Evidence record

Supported evidence types include: `entry_chain`, `opd`, `direct_call`, `stack_prologue`, `import`, `string`, `rtti`, `vtable`, `callgraph`, `runtime`, `cross_build`, and `neighboring_function`.

Evidence does not automatically imply a semantic name.

## Confidence

- **confirmed** — observed directly and reproduced consistently.
- **probable** — strongly supported by multiple independent signals.
- **speculative** — working hypothesis requiring further validation.

## Cross-build match

Keep both sides of every match:

    reference:
      build: BCUS-98114
      module: EBOOT.BIN
      va: 0x00123456
    target:
      build: BCUS-98158
      module: EBOOT.BIN
      va: 0x00134567
    method: normalized-full
    confidence: probable
    review_status: pending

Initial methods: `normalized-full`, `normalized-prefix`, `manual`.

A cross-build match must never silently overwrite a manually verified target name.

## Generated versus reviewed data

Generated output belongs in local output directories unless intentionally promoted to a reviewed research artifact.

For every promoted artifact, preserve source build, executable SHA-256, module, generating tool/version, generation command, evidence/confidence, and reviewer notes where applicable.