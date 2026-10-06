# Contributing

## Scope

Contributions should advance reproducible reverse engineering, documentation, original tooling, or independently reconstructed source code.

## Do not commit

- game disc images or package files;
- firmware, BIOS, platform keys, licenses, or secrets;
- decrypted game executables or modules;
- extracted copyrighted assets;
- proprietary SDK files or headers;
- bulk raw decompiler output.

## Analysis workflow

1. Identify the exact build/module under study.
2. Record addresses/offsets and the method used to reach the conclusion.
3. Run or reproduce the smallest useful M1 indexer query before making semantic claims.
4. Name functions conservatively.
5. Separate confirmed behavior from hypotheses.
6. For cross-build matches, retain both build addresses and the matching method.
7. Link related issues and notes.
8. Keep commits narrowly scoped.
9. Add synthetic tests for tooling behavior where practical.

## Research data

Use the schema in `analysis/schema.md`.

A reviewed function should not exist only as a Ghidra name or pseudocode file. Promote its evidence, confidence, and relationships into repository-readable research metadata.

Generated local indexes may be large; do not commit them merely because they were generated.

## Pull requests

A useful PR should state:
- subsystem/build/module;
- what changed;
- how it was verified;
- unresolved questions;
- whether names/structures remain speculative;
- whether generated output was used only as local evidence;
- clean-room/licensing considerations.

Prefer small, reviewable PRs over large decompiler dumps.