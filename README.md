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

## Acknowledgements and upstream research tooling

This project benefits from open-source tooling and reverse-engineering work by the wider Gran Turismo community. Pinned local checkouts of compatible upstream projects can be fetched with:

```bash
bash tools/fetch_upstream_tools.sh
```

See [third_party/README.md](third_party/README.md) for pinned revisions, licensing notes, and clean-room handling rules.

Special thanks to:

- [Nenkai/GTToolsSharp](https://github.com/Nenkai/GTToolsSharp) — GT5/GT5 Prologue volume, PDIPFS, compression, crypto, and file-layout research.
- [Nenkai/GTAdhocToolchain](https://github.com/Nenkai/GTAdhocToolchain) — Adhoc bytecode and script/resource tooling.
- [Nenkai/PDTools](https://github.com/Nenkai/PDTools) — Gran Turismo format, compression, crypto, and utility research.
- [Nenkai/GTSpecDB](https://github.com/Nenkai/GTSpecDB) — GT4–GT5 SpecDB parsing and database research.
- [Nenkai/TXS3Converter](https://github.com/Nenkai/TXS3Converter) — GT5/GT6 TXS3 texture research and conversion.
- [Nenkai/GT-File-Specifications-Documentation](https://github.com/Nenkai/GT-File-Specifications-Documentation) — reverse-engineered Gran Turismo file-format specifications.
- [Silentwarior112/GTGPB](https://github.com/Silentwarior112/GTGPB) — independent GPB research and tooling; currently treated as reference-only because the repository does not declare a license.
- [Nenkai/Gran-Turismo-Modding-Guides](https://github.com/Nenkai/Gran-Turismo-Modding-Guides) — valuable PS3-era Gran Turismo research documentation; treated as reference-only where licensing is not declared.
- [vgmstream/vgmstream](https://github.com/vgmstream/vgmstream) — game-audio format research and playback tooling; used as an external/reference tool subject to its component licenses.

All trademarks, game assets, and proprietary code remain property of their respective owners. Upstream open-source code remains subject to the licenses and notices of its original projects.
