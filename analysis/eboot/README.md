# EBOOT analysis — BCUS-98158

Status: **initial executable mapping complete; function-by-function reconstruction started**.

This analysis is for the user-supplied `EBOOT.BIN`. No game executable, decrypted binary, disc keys, SELF keys, or proprietary assets are stored in this repository.

## Input fingerprint

- File: `EBOOT.BIN`
- Size: `422,808` bytes
- SHA-256: `f58e36b3cb371e357ae0f3a019fb339c653682bc7ff6423abf3c2c7db50eef2a`
- Container: retail PS3 `SCE\0` SELF
- SELF version: `2`
- Key revision: `0x0001`
- SELF type: `APP`
- Authentication ID: `0x1010000001000003`
- Vendor ID: `0x01000002`
- Application version field: `0x0001000000000000`

The SELF was decrypted locally for analysis with external PS3 key material. Key material is deliberately not recorded here.

## Build identity

Strings in the decrypted executable identify this build as the US Gran Turismo 5 Prologue executable:

- `BCUS-98158`
- `BCUS98158`
- `gt5p`
- `boot.gt5p.us.ps3.product-bd-key.release.build`
- `/dev_bdvd/PS3_GAME/USRDIR`
- `/dev_bdvd/PS3_GAME/USRDIR/GT.VOL`
- `https://gt5prologue.ps3.online.us.gran-turismo.com`
- `NPUA80075_00`
- `UP9000-NPUA80075_00`

This fingerprint must be used when recording addresses. Addresses from other GT5 Prologue regions/revisions must not be merged without validation.

## Embedded ELF

The decrypted payload is a stripped, big-endian 64-bit PowerPC/Cell LV2 ELF.

- ELF class: 64-bit
- Endianness: big-endian
- Machine: PowerPC64 (`e_machine = 0x15`)
- OS ABI: Cell LV2
- ELF entry field: `0x717D8`
- PPU TOC: `0x7D110`

The ELF entry is an **OPD descriptor**, not executable code:

```text
OPD 0x717D8
  code = 0x10230
  toc  = 0x7D110
```

So the first executable entry routine is `sub_10230`.

## Load map

| Segment | File offset | Virtual address | File size | Memory size | Flags |
| --- | ---: | ---: | ---: | ---: | --- |
| PT_LOAD 0 | `0x00000` | `0x10000` | `0x5A338` | `0x5A338` | R-X |
| PT_LOAD 1 | `0x60000` | `0x70000` | `0x58A0` | `0x84A20` | RW- |
| TLS | `0x65530` | `0x75530` | — | `0x28` | — |
| process param | `0x5A2F0` | `0x6A2F0` | `0x20` | `0x20` | — |
| PRX param | `0x5A310` | `0x6A310` | `0x28` | `0x28` | — |

The original section-name string table is not available in the reconstructed ELF. Any local section names used by analysis tooling are synthetic convenience labels and must not be treated as original compiler/linker names.

## Function discovery

The OPD region is at virtual address `0x717C8`, file offset `0x617C8`, size `0x3948`.

Current scan:

- 1,833 valid OPD descriptors
- 1,824 unique function entry addresses
- common TOC: `0x7D110`

First descriptors:

| OPD | Function | TOC |
| ---: | ---: | ---: |
| `0x717C8` | `0x10200` | `0x7D110` |
| `0x717D0` | `0x5A5C8` | `0x7D110` |
| `0x717D8` | `0x10230` | `0x7D110` |
| `0x717E0` | `0x10258` | `0x7D110` |
| `0x717E8` | `0x10268` | `0x7D110` |
| `0x717F0` | `0x10278` | `0x7D110` |
| `0x717F8` | `0x102A0` | `0x7D110` |
| `0x71800` | `0x102F8` | `0x7D110` |
| `0x71808` | `0x10328` | `0x7D110` |
| `0x71810` | `0x10368` | `0x7D110` |
| `0x71818` | `0x104F8` | `0x7D110` |
| `0x71820` | `0x10598` | `0x7D110` |
| `0x71828` | `0x10610` | `0x7D110` |
| `0x71830` | `0x10640` | `0x7D110` |
| `0x71838` | `0x106A0` | `0x7D110` |
| `0x71840` | `0x106E0` | `0x7D110` |

## Import table

The PRX parameter block reports:

```text
libentstart  = 0x67270
libentend    = 0x67270
libstubstart = 0x67278
libstubend   = 0x673D8
```

There are no PRX exports in this executable and eight imported libraries with 74 imported functions. See [imports.md](imports.md).

## Startup reconstruction

The entry/CRT chain has been mapped through the first game-level initializer:

```text
ELF entry OPD 0x717D8
    |
    v
sub_10230        PPU entry stub / establishes TOC
    |
    v
sub_10368        CRT/runtime bootstrap
    |
    v
sub_106E0        probable game bootstrap
```

See [startup.md](startup.md) for the current decompilation notes.

## Confidence convention

- **Confirmed** — directly established from instructions/data structures/import NIDs.
- **Probable** — behavior is strongly implied by call graph and platform ABI.
- **Speculative** — working name/hypothesis that still requires cross-reference evidence.

The immediate next phase is to split `sub_106E0` into subsystems, recover string/global cross-references, and name its callees.
