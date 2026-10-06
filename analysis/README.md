# Analysis

Store reproducible reverse-engineering notes here. The analysis tree is the project's reviewed research layer; generated local indexes remain outside the repository unless explicitly promoted after review.

## Organization

- `builds/` — known versions, regions, updates, and identifying metadata.
- `modules/` — per-module notes and responsibilities.
- `functions/` — reviewed function-level findings and naming.
- `subsystems/` — rendering, physics, UI, audio, race logic, and other systems.
- `formats/` — independently documented formats.
- `symbols/` — reviewed symbol/function maps without proprietary binary data.
- `evidence/` — provenance and reasoning for important conclusions.

The semantic data contract is documented in [Analysis data schema](schema.md).

## Function research lifecycle

`discovered -> indexed -> evidence reviewed -> named/classified -> reconstructed -> tested`

The M1 executable-intelligence pipeline produces machine-generated candidates, fingerprints, imports, strings, RTTI/vtable candidates, and cross-build matches. These are evidence inputs, not automatically accepted semantic truth.

## Required context

Every reviewed note should identify:
- exact build/title ID and update when known;
- module;
- address or offset;
- observation/reproduction method;
- evidence;
- confidence;
- related functions/structures;
- follow-up questions.

Confidence levels are **confirmed**, **probable**, and **speculative**.

## Provenance

Promoted research artifacts should preserve the source executable SHA-256, tool/version, generation command, and review status.

Avoid large copied decompiler output, proprietary executable bytes, or copyrighted game content.