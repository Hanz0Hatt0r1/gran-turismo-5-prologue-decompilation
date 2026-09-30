# Gran Turismo 5 Prologue Decompilation

Open research and clean-room reverse-engineering project for understanding and independently reconstructing the behavior and architecture of **Gran Turismo 5 Prologue**.

## Goals

- Document executable structure, modules, subsystems, data flow, and runtime behavior.
- Build reproducible analysis notes with traceable evidence.
- Reconstruct functions and subsystems as independently authored source code.
- Develop original tooling for symbol tracking, address mapping, report generation, and consistency checks.
- Keep proprietary game data, firmware, keys, disc images, extracted assets, and decrypted binaries out of Git.

## Repository layout

- `analysis/` — reverse-engineering findings, function notes, symbols, hypotheses, and evidence.
- `docs/` — setup, methodology, architecture, and roadmap.
- `src/` — independently reconstructed source code.
- `tests/` — tests for reconstructed behavior and project tooling.
- `tools/` — original helper scripts and research utilities.
- `.github/` — issue and pull-request templates.

## Development principles

1. **No proprietary game content in Git.**
2. **Document evidence, not copied content.**
3. **Always include build/region context for addresses.**
4. **Mark conclusions as confirmed, probable, or speculative.**
5. **Prefer small, reviewable changes.**

## Start here

- [Development setup](docs/setup.md)
- [Research methodology](docs/methodology.md)
- [Roadmap](docs/roadmap.md)
- [Architecture map](docs/architecture.md)
- [Contributing](CONTRIBUTING.md)

## Status

Early-stage scaffold. Initial work focuses on build identification, executable/module inventory, symbol/function cataloging, subsystem mapping, and a reproducible research workflow.

## Scope

This repository is for original research, interoperability, documentation, and independently authored code. Do not commit game ISOs/PKGs, firmware, keys, decrypted modules, extracted copyrighted assets, proprietary SDK components, or other restricted material.
