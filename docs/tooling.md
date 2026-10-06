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
        +--> direct-call / stack-prologue function discovery
        +--> normalized function fingerprints
        +--> RTTI / typeinfo candidates
        +--> vtable candidates
        +--> retained source-file strings / TOC references
        +--> function source/vtable evidence
        +--> PS3 import libraries / NIDs / optional external symbol names
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
Each high-confidence discovered function receives relocation-tolerant fingerprints derived from normalized
PowerPC instructions. OPD descriptors, direct `bl` targets, and standard PPC64
stack-frame prologues are tracked as separate evidence rather than assuming the
OPD is a complete function list. Cross-build matches are evidence and must still be
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

`tools/audit_boundaries.py` performs a non-destructive boundary audit against
a user-provided ELF. It reports OPD/BLR relationships, nested prologue/call
evidence, and direct branches from before the first linear BLR into the
post-BLR region. These continuation suspects are review evidence only; the
auditor never promotes or renames a function automatically.

Decompiler output is evidence, not reconstructed source. Reviewed behavior is
rewritten independently under `src/` and tested separately.

## Import symbol names

Import NIDs are extracted directly from each executable and remain the stable
identity recorded by the project. `gtdecomp.py index` and `decompile` accept an
optional `--nid-db` path for local NID-to-symbol resolution. Supported inputs
are simple whitespace text, CSV, and JSON. The resolved name is convenience
evidence only; the raw module name and NID are always retained. External symbol
databases are deliberately not vendored, so their licensing and provenance
remain separate from this repository.

## Manjaro / Arch execution host

Ghidra itself is expected to run on the researcher's machine. The repository
contains a wrapper at `tools/manjaro/run_gt5_headless.sh` that detects
`analyzeHeadless`, runs the static indexer, applies annotations, and exports
pseudocode. The default `hinted` scope intentionally decompiles only functions
with source/vtable evidence; use `GTDECOMP_SCOPE=all` only after the first pass
has been reviewed.

A small `report-for-chat.tar.zst` is produced when `zstd` is installed. It
contains manifests and logs but not the ELF or the full pseudocode corpus.