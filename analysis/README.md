# Analysis

Store reproducible reverse-engineering notes here.

Suggested organization:

- `builds/` — known versions, regions, updates, and identifying metadata.
- `modules/` — per-module notes.
- `functions/` — function-level analysis and naming.
- `subsystems/` — rendering, physics, UI, audio, race logic, and other systems.
- `formats/` — independently documented formats.
- `symbols/` — symbol/function maps without proprietary binary data.

Each note should include target build/region/update, module, addresses or offsets, observation method, evidence, confidence level, related functions, and follow-up questions.

Confidence levels: **confirmed**, **probable**, **speculative**.

Avoid large copied decompiler output or copyrighted game content.

## Current executable work

- [BCUS-98158 EBOOT](eboot/README.md) — executable fingerprint, ELF/OPD map, imports, and startup decompilation.
