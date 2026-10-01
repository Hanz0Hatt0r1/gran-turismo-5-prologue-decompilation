# EBOOT.BIN initial analysis

## Sample identity

- File: `EBOOT.BIN`
- Size: **422,808 bytes** (`0x67398`)
- SHA-256: `f58e36b3cb371e357ae0f3a019fb339c653682bc7ff6423abf3c2c7db50eef2a`
- Container: PlayStation 3 SCE/SELF
- Embedded executable: ELF64, big-endian, `EM_PPC64`
- SELF type: `APP`
- Application version field: `0x0001000000000000`
- Auth ID: `0x1010000001000003`
- Vendor ID: `0x01000002`
- Key revision: `0x0001`

## Executable layout

The embedded ELF has 8 program headers and 30 section headers. Its ELF entry value is `0x717D8`. On PS3 PPU executables, the entry value is an OPD address rather than a direct machine-code address; the supplied file's entry falls inside the reconstructed `.opd` range.

Primary mappings:

| Mapping | ELF offset | Virtual address | File size | Memory size |
| --- | ---: | ---: | ---: | ---: |
| executable `PT_LOAD` | `0x00000` | `0x10000` | `0x5A338` | `0x5A338` |
| writable `PT_LOAD` | `0x60000` | `0x70000` | `0x58A0` | `0x84A20` |
| `PT_PS3_PARAMS` | `0x5A2F0` | `0x6A2F0` | `0x20` | `0x20` |
| `PT_PS3_PRX` | `0x5A310` | `0x6A310` | `0x28` | `0x28` |

The writable mapping extends to `0xF4A20`; most of the tail is zero-filled BSS.

## Reconstructed section map

The original `.shstrtab` contents are encrypted, but this sample preserves section headers in plaintext. Their `sh_name` offsets, types, flags, addresses, and sizes match the standard PS3 PPU section-string layout exactly, allowing the names below to be reconstructed with high confidence.

| Section | VA | Size |
| --- | ---: | ---: |
| `.init` | `0x10200` | `0x2C` |
| `.text` | `0x10230` | `0x4A398` |
| `.fini` | `0x5A5C8` | `0x24` |
| `.sceStub.text` | `0x5A5EC` | `0x940` |
| `.eh_frame` | `0x5AF2C` | `0xAE50` |
| `.gcc_except_table` | `0x65D80` | `0x1348` |
| `.rodata.sceResident` | `0x670C8` | `0x7C` |
| `.rodata.sceFNID` | `0x67144` | `0x128` |
| `.lib.ent.top` | `0x6726C` | `0x4` |
| `.lib.ent.btm` | `0x67270` | `0x4` |
| `.lib.stub.top` | `0x67274` | `0x4` |
| `.lib.stub` | `0x67278` | `0x160` |
| `.lib.stub.btm` | `0x673D8` | `0x4` |
| `.rodata` | `0x67400` | `0x2EF0` |
| `.sys_proc_param` | `0x6A2F0` | `0x20` |
| `.sys_proc_prx_param` | `0x6A310` | `0x28` |
| `.ctors` | `0x70000` | `0x70` |
| `.dtors` | `0x70070` | `0x70` |
| `.jcr` | `0x700E0` | `0x4` |
| `.data.rel.ro` | `0x700E8` | `0xFBC` |
| `.data.sceFStub` | `0x710A4` | `0x128` |
| `.toc1` | `0x711D0` | `0x5F4` |
| `.opd` | `0x717C8` | `0x3948` |
| `.got` | `0x75110` | `0x420` |
| `.tbss` | `0x75530` | `0x28` |
| `.data` | `0x75558` | `0x348` |
| `.bss` | `0x758C0` | `0x7F160` |
| `.sceversion` | ELF offset `0x658A0` | `0x8C5` |
| `.shstrtab` | ELF offset `0x66165` | `0x12D` |

## Function/import estimates

PS3 PPU OPD descriptors are compact 8-byte `{u32 code, u32 toc}` records. The `.opd` section is `0x3948` bytes, so it contains space for **1,833 descriptor slots**. The exact valid function count requires the decrypted OPD contents because unused or duplicate descriptors must be filtered.

The import geometry is much tighter:

- `.rodata.sceFNID`: `0x128 / 4 = 74` NID slots.
- `.data.sceFStub`: `0x128 / 4 = 74` imported function-pointer slots.
- `.sceStub.text`: `0x940 / 74 = 0x20` bytes per import trampoline.
- `.lib.stub`: `0x160 / 0x2C = 8` import-library records.

Therefore this executable has **74 firmware imports across 8 import libraries**. The plaintext SCE-version records contain exactly eight distinct `*_stub` library families, making these the likely import modules:

- `libsysutil_np_stub`
- `libnetctl_stub`
- `libnet_stub`
- `libfs_stub`
- `libsysutil_stub`
- `libgcm_sys_stub`
- `libsysmodule_stub`
- `liblv2_stub`

The same version block also references `libgcm_cmd`, `libstdc++`, `libc`, `crt0`, and `crt1`, which are useful toolchain/link provenance but are not necessarily firmware import modules.

## SDK and firmware evidence

The plaintext SCE-version block contains **123 version records**, all tagged `p215001`. This strongly indicates a single PS3 SDK/toolchain generation across the linked objects; for now the repository records the literal tag rather than assigning an undocumented semantic version.

The SELF control-info digest block stores firmware version value **21700**, conventionally displayed by SCE tooling as **2.17**.


## RAP/NPDRM license check

A user-supplied RAP file named `EP9001-NPEA00050_00-0000000000000000.rap` was checked only for identity/compatibility metadata.

- RAP size: **16 bytes**
- RAP SHA-256: `5845af81fd7b0e20f23896ea9af7102857765a57e96942523c94b6811a9c1b3b`
- Filename content ID: `EP9001-NPEA00050_00-0000000000000000`

The analyzed `EBOOT.BIN` is **not an NPDRM SELF**:

- application-info SELF type = `4` (`APP`);
- control-info region is `0x70` bytes at file offset `0x3C0`;
- control records present are type `1` (flags, size `0x30`) and type `2` (digest, size `0x40`);
- there is **no type `3` NPDRM control record** and therefore no embedded NPDRM Content ID to match against the RAP.

Consequently, a RAP license is not the decryption input for this particular SELF container. The RAP filename does correspond to the PSN title ID family for Gran Turismo 5 Prologue, but it cannot unlock or validate this APP-type EBOOT by itself.

## Encryption state

Both non-empty `PT_LOAD` payloads are marked encrypted in the SELF section-info table.

Measured entropy:

- executable payload: approximately **7.99950 bits/byte**
- writable payload: approximately **7.99230 bits/byte**

The metadata and section tables are sufficient to map the executable, but the code, OPD contents, FNIDs, import structures, strings, and initialized data remain encrypted. Disassembling those encrypted payload bytes would produce false PPC instructions.

## Next executable stage

For the matching decrypted ELF:

1. verify the SHA/provenance pair against this SELF;
2. resolve the entry OPD `0x717D8` to its code address and initial TOC;
3. walk `.opd` in 8-byte records and retain descriptors whose code address lands in executable ranges;
4. parse the eight `.lib.stub` records and all 74 FNIDs;
5. resolve NIDs to PS3 API names;
6. generate the first authoritative function table and call graph;
7. start clean-room reconstruction from CRT/startup and initialization paths.

The proprietary executable itself is not committed.
