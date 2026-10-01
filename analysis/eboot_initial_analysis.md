# EBOOT.BIN initial analysis

## Sample identity

- File: `EBOOT.BIN`
- Size: **422,808 bytes** (`0x67398`)
- SHA-256: `f58e36b3cb371e357ae0f3a019fb339c653682bc7ff6423abf3c2c7db50eef2a`
- Container magic: `SCE\0`
- Embedded ELF header offset: `0x90`

The binary supplied for analysis is a PlayStation 3 SCE/SELF executable container. The embedded executable metadata identifies a **64-bit big-endian PowerPC ELF**.

## Embedded ELF metadata

| Field | Value |
| --- | --- |
| ELF class | ELF64 |
| Endianness | Big endian |
| OS/ABI byte | `0x66` |
| Type | `ET_EXEC` |
| Machine | `EM_PPC64` (`0x15`) |
| Entry point | `0x00000000000717D8` |
| Program headers | 8 |
| Section headers | 30 |
| Section-header table offset | `0x66298` |
| Section-name table index | 29 |

Program-header metadata exposes a principal executable mapping beginning at virtual address `0x10000` with an ELF file size of `0x5A338`, plus a writable mapping around `0x70000`.

## Encryption state

The main body of the supplied SELF is still encrypted. Entropy measurements across the central payload are approximately **7.997 bits/byte**, while attempting to interpret the SELF bytes as a directly extracted ELF produces invalid section headers. Therefore PPC64 disassembly/decompilation of the payload must wait for a legitimately decrypted SELF/ELF representation.

Do not treat disassembly of the encrypted bytes as game code.

## Visible import/module evidence

A plaintext import-name region near file offset `0x6621D` exposes references to:

- `libsysutil_np_stub`
- `libnetctl_stub`
- `libnet_stub`
- `libfs_stub`
- `libsysutil_stub`
- `libgcm_cmd`
- `libgcm_sys_stub`
- `libsysmodule_stub`
- `libstdc++`
- `libc`
- `liblv2_stub`
- `crt1`

These names are useful early subsystem evidence: filesystem access, networking/NP, system utility integration, RSX/GCM graphics, module loading, C/C++ runtime, and LV2 interaction are represented in the executable's import metadata.

## Next decompilation step

Obtain a decrypted executable image corresponding exactly to the SHA-256 sample above, then:

1. verify the decrypted ELF header and segment mappings;
2. hash and record the decrypted artifact locally (do not commit proprietary binaries);
3. disassemble from entry point `0x717D8`;
4. recover OPD/function-descriptor and TOC usage where applicable;
5. resolve import stubs/NIDs;
6. establish the first function map and call graph;
7. begin clean-room reconstruction under `src/`, keeping address/evidence notes under `analysis/`.

This document records only metadata and observations; the proprietary executable itself is not committed.
