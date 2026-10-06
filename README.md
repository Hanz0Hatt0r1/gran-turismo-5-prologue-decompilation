# Gran Turismo 5 / Prologue Decompilation Research

Open research and clean-room reverse-engineering project for understanding and
independently reconstructing the behavior and architecture of **Gran Turismo 5**
and **Gran Turismo 5 Prologue** on PlayStation 3.

Retail GT5 is used as the first reference build because it retains substantial
RTTI, class/source-file names, and subsystem metadata. The same tooling and
metadata schema are designed to index GT5 Prologue and later compare builds
without assuming stable absolute addresses.

## Goals

- Document executable structure, modules, subsystems, data flow, and runtime behavior.
- Build reproducible analysis notes with traceable evidence and explicit build context.
- Reconstruct functions and subsystems as independently authored source code.
- Develop original tooling for ELF analysis, symbol tracking, address mapping,
  RTTI/vtable discovery, cross-build function matching, and consistency checks.
- Reuse evidence across related GT5/GT5 Prologue builds when independently
  verified by cross-build matching.
- Keep proprietary game data, firmware, keys, disc images, extracted assets,
  and decrypted binaries out of Git.

## Repository layout

- `analysis/` — reverse-engineering findings, per-build metadata, symbols, hypotheses, and evidence.
- `docs/` — setup, methodology, architecture, tooling, and roadmap.
- `src/` — independently reconstructed source code.
- `tests/` — tests for reconstructed behavior and project tooling.
- `tools/` — original helper scripts and research utilities.
- `.github/` — issue and pull-request templates.

## Development principles

1. **No proprietary game content in Git.**
2. **Document evidence, not copied content.**
3. **Always include build/region context for addresses.**
4. **Mark conclusions as confirmed, probable, or speculative.**
5. **Treat cross-build matches as evidence, not automatic semantic proof.**
6. **Prefer small, reviewable changes.**

## Start here

- [Development setup](docs/setup.md)
- [Research methodology](docs/methodology.md)
- [Decompilation tooling](docs/tooling.md)
- [Roadmap](docs/roadmap.md)
- [Architecture map](docs/architecture.md)
- [Contributing](CONTRIBUTING.md)
- [Parallel development prompts](docs/parallel-development-prompts.md)

## Current reference build

The first reproducible index targets retail **Gran Turismo 5 BCUS-98114**.
Run the local indexer against a user-provided decrypted executable:

```bash
python3 tools/gtdecomp.py index /path/to/EBOOT.ELF -o output/gt5-bcus98114
```

The baseline build metadata lives at
[`analysis/builds/gt5-bcus98114.json`](analysis/builds/gt5-bcus98114.json).
The executable itself is intentionally not present in this repository.

## Scope

This repository is for original research, interoperability, documentation, and
independently authored code. Do not commit game ISOs/PKGs, firmware, keys,
decrypted modules, extracted copyrighted assets, proprietary SDK components,
or other restricted material.