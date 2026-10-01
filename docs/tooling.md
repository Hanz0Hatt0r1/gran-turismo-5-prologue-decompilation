# Decompilation tooling

The project treats each executable build as an independent evidence source.
The first supported reference build is retail **Gran Turismo 5 BCUS-98114**;
Gran Turismo 5 Prologue builds will be indexed using the same schema.

## Pipeline

```text
user-provided decrypted ELF
        |
        v
ELF / program / section parser
        |
        +--> PPU function descriptors (.opd)
        +--> normalized function fingerprints
        +--> RTTI / typeinfo candidates
        +--> vtable candidates
        +--> retained source-file strings / TOC references
        +--> function source/vtable evidence
        +--> PS3 import libraries / NIDs
        |
        v
per-build metadata index
        |
        +--> Ghidra annotations / function materialization
        +--> headless pseudocode export (local only)
        +--> subsystem/function catalog
        +--> cross-build matching
        |
        v
independently reconstructed source + tests
```

## Stable identity

Absolute addresses are never treated as stable identifiers across builds.
Each function receives relocation-tolerant fingerprints derived from normalized
PowerPC instructions. Cross-build matches are evidence and must still be
reviewed before a semantic name is considered confirmed.

## GT5 as the first reference build

Retail GT5 is useful as the first supported build because its executable keeps
a large amount of RTTI, class names, source-file names, and subsystem strings.
Those clues can seed the common code database. Once a genuine GT5 Prologue ELF
is indexed, the matcher can identify unchanged or lightly relocated functions
and transfer *research metadata* (not proprietary code) between the builds.

## Repository boundary

Only original tooling and derived research metadata belong in Git. Do not
commit decrypted executables, SELF/PRX files, game data, keys, firmware,
proprietary SDK material, or extracted copyrighted assets.

## Headless decompilation

`gtdecomp.py decompile` accepts a local Ghidra install and orchestrates a fresh
analysis project. The Ghidra scripts first materialize OPD entry points and
apply derived evidence, then export one pseudocode file per indexed function.
The output manifest keeps the normalized fingerprint beside each Ghidra name so
that later builds can reuse research labels through the cross-build matcher.

Decompiler output is evidence, not reconstructed source. Reviewed behavior is
rewritten independently under `src/` and tested separately.