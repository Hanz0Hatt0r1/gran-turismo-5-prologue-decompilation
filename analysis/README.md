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

## Current analyses

- [BCUS-98158 EBOOT bootstrap](builds/bcus-98158-eboot.md) — SELF/ELF identity, bootstrap control flow, PFS2 validation, launch handoff, and build metadata.
- [BCUS-98158 imports](builds/imports.csv) — all 74 imported functions resolved and NID-verified.
- [Initial function map](builds/functions.csv) — working names with confidence levels.
- [Partial `boot_main` reconstruction](decomp/boot_main.cpp) — clean-room pseudocode for the `0x106E0` bootstrap routine.
