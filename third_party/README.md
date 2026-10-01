# Third-party research tooling

This directory is reserved for locally fetched upstream projects used to understand Gran Turismo file formats and tooling.

Run:

```bash
bash tools/fetch_upstream_tools.sh
```

The script checks out pinned revisions under `third_party/upstream/`. That directory is ignored by Git so upstream source is not silently mixed into the clean-room reconstruction.

## Pinned MIT-licensed projects

| Project | Pinned revision | Why it is useful |
| --- | --- | --- |
| [GTToolsSharp](https://github.com/Nenkai/GTToolsSharp) | `a59e6f17e8bf455bdaab84b88b3d02de3a593fc1` | GT5/GT5P volume and PDIPFS research, compression/crypto/file-layout behavior |
| [GTAdhocToolchain](https://github.com/Nenkai/GTAdhocToolchain) | `3fecc2ed58e5d46135b2f94d2ce5d3fa8fb7dba0` | Adhoc bytecode, GPB-related tooling, script/resource investigation |
| [PDTools](https://github.com/Nenkai/PDTools) | `ffe0bb26377ac9ff62f40951c1c0b16c5d9a380f` | Reusable format knowledge, compression, crypto, binary structures and utilities |
| [GTSpecDB](https://github.com/Nenkai/GTSpecDB) | `691e49fa6b85773bd4e8bc47e361c0a1cd6716a0` | GT4-GT5 SpecDB parsing and database structure research |
| [TXS3Converter](https://github.com/Nenkai/TXS3Converter) | `d007f92b5fc761f2598932dd1aef46d2d19a7103` | GT5/GT6 TXS3 texture format research and conversion |
| [GT File Specifications](https://github.com/Nenkai/GT-File-Specifications-Documentation) | `05e52347890541758222d173dbb62d2b40581b19` | Reverse-engineered file specifications and binary format documentation |
| [ps3recomp](https://github.com/sp00nznet/ps3recomp) | `a679051ef304555291de2eb3ec8a3dbf64a761a8` | PPU ELF loading, PS3 8-byte OPD parsing, firmware import extraction, function manifests, and static PPU-to-C++ lifting |

All projects in this table advertise the MIT license at the pinned repository state. Preserve their license files and attribution when reusing source.

For a legitimately decrypted `EBOOT.ELF`, ps3recomp is the preferred first-stage analysis pipeline because its loader emits function, image, import, and loader manifests directly from PS3 PPU metadata.

## Reference-only projects

These are useful for research, but their repository-level licensing is missing or not simple enough to treat as drop-in source for this project:

- [GTGPB](https://github.com/Silentwarior112/GTGPB) — useful independent GPB implementation; no repository license was declared when reviewed on 2026-10-01. Read for interoperability research, but do not copy its code into this repository without permission or a clarified license.
- [Gran Turismo Modding Guides](https://github.com/Nenkai/Gran-Turismo-Modding-Guides) — useful documentation, but no repository license was declared when reviewed on 2026-10-01.
- [vgmstream](https://github.com/vgmstream/vgmstream) — useful for game audio investigation, but it contains mixed/format-specific licensing rather than a simple project-wide MIT declaration. Treat it as an external tool unless the exact files and licenses are reviewed.

## Clean-room boundary

Upstream tools may be used to inspect formats, compare behavior, and build interoperability notes. Proprietary Gran Turismo assets and binaries must not be committed. Any code added to `src/` should have a clear provenance: independently reconstructed, or explicitly imported from a compatible open-source license with attribution.
