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
3. Name functions conservatively.
4. Separate confirmed behavior from hypotheses.
5. Link related issues and notes.
6. Keep commits narrowly scoped.

## Pull requests

A useful PR should state what subsystem/build it covers, what changed, how it was verified, unresolved questions, and whether any names or structures remain speculative.
