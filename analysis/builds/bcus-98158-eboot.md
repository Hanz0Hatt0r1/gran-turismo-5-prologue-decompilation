# BCUS-98158 EBOOT bootstrap analysis

Status: **in progress**

This note records reproducible findings from the user-supplied `EBOOT.BIN`. No game binary or extracted asset is committed to this repository.

## Sample identity

| Field | Value |
| --- | --- |
| Input | `EBOOT.BIN` |
| Size | 422,808 bytes (`0x67398`) |
| SHA-256 | `f58e36b3cb371e357ae0f3a019fb339c653682bc7ff6423abf3c2c7db50eef2a` |
| SHA-1 | `0f1fc6d3433876c3656d03996817b0420d87b6b9` |
| MD5 | `6af822f00c1c9afd8458f2595e7eedb9` |
| Product string | `BCUS-98158` |
| PDI version | `215.001` |
| Compile timestamp | `2008/03/22 17:01:51` |
| SVN revision strings | current/update `28055`, commit `28040` |

The embedded metadata also contains `gt5p`, `us`, `ps3`, `product-bd-key`, `release`, and `build`, consistent with a U.S. product build.

## SELF / ELF layout

The input is a PlayStation 3 SCE SELF containing a 64-bit, big-endian PowerPC ELF for Cell LV2.

SELF header:

- SCE version: 2
- key revision: 1
- SELF application type: APP
- header length: `0x980`
- data length: `0x66A18`
- embedded ELF header offset: `0x90`
- embedded program-header offset: `0xD0`
- embedded section-header offset: `0x66C18`

Embedded ELF:

- machine: PowerPC64
- endian: big
- ELF entry: `0x717D8`
- executable LOAD: VA `0x10000`, size `0x5A338`
- writable LOAD: VA `0x70000`, file size `0x58A0`, memory size `0x84A20`
- stripped/static executable

The ELF entry points to an OPD descriptor rather than directly to code:

- OPD: `0x717D8`
- code address: `0x10230`
- TOC: `0x7D110`

## Bootstrap entry chain

Current naming:

| Address | Working name | Confidence | Evidence |
| --- | --- | --- | --- |
| `0x10230` | `crt_entry` | confirmed | target of ELF entry OPD |
| `0x10368` | `crt_runtime_start` | probable | CRT setup path; invokes `0x106E0`, then process termination |
| `0x10610` | `handle_broken_game_data` | probable | calls `cellGameDataExitBroken` and local cleanup |
| `0x10640` | `paths_match_after_normalization` | tentative | normalizes second argument then compares; returns boolean |
| `0x106A0` | `path_exists` | probable | wrapper returns true only when lower-level path query returns zero |
| `0x106E0` | `boot_main` | high | receives argc/argv-like startup inputs and owns complete launch decision flow |
| `0x29070` | `check_game_data_paths` | probable | asynchronous game-data wrapper producing two path buffers and an error code |
| `0x379A0` | `game_data_check_callback` | high | directly calls `cellGameDataCheckCreate2` |
| `0x4B448` | `memcpy` | confirmed | byte-copy implementation |
| `0x4E0E0` | bounded string/memory copy | probable | copies output paths with caller-supplied capacity |

## Confirmed boot resources

The bootstrap references these paths and names:

```text
/dev_bdvd/PS3_GAME/USRDIR
/dev_bdvd/PS3_GAME/USRDIR/GT.VOL
EMAIN.SELF
EPATCH.SELF
UPDATING
/PDIPFS/
```

It also carries explicit launch/install state strings:

```text
boot_from=gamedata
boot_from=bdvd
install_condition=need_patch_update
install_condition=need_nothing
```

This establishes the role of this EBOOT as a launcher/bootstrap around disc content, installed game data, patch data, and the next executable SELF.

## Game-data flow

`boot_main` calls the wrapper at `0x29070`. Its callback path reaches `0x379A0`, where the imported `cellGameDataCheckCreate2` is invoked.

The wrapper copies two path-like output strings into caller buffers. In `boot_main`, both buffers have capacity 1055 bytes and live in a shared boot-state structure.

If the check fails with `0x8002B606` (`CELL_GAMEDATA_ERROR_BROKEN`), the bootstrap invokes `cellGameDataExitBroken`, performs local cleanup, enters failure state, and ultimately returns `-1`.

## Filesystem module initialization

Once the asynchronous/startup state permits launch, `boot_main` executes:

```text
cellSysmoduleInitialize();
cellSysmoduleLoadModule(0x000e);
```

Module `0x000e` is the filesystem sysmodule. This happens immediately before the final executable/path selection logic.

## PFS / GT.VOL validation

The bootstrap reads a 160-byte header-like structure and tests its first 32-bit value against:

```text
0x5B745162
```

GTToolsSharp identifies `5B 74 51 62` as the PFS2 header magic used by GT5/GT5 Prologue and GT6.

After the magic check, the code performs additional structure/size comparisons before accepting the candidate volume. The exact field names are still being reconstructed.

## Launch handoff

The final direct system import is:

```text
sys_game_process_exitspawn2(selected_path, argv_or_launch_args, NULL, NULL, NULL, 1001, 64);
```

The exact semantic names of every argument are not yet asserted, but the call is clearly the process handoff from the bootstrap to the selected next executable.

Observed executable candidates are `EMAIN.SELF` and `EPATCH.SELF`.

## Import table

The ELF contains 8 import-library descriptors and 74 function imports. All 74 NID/name pairs in [`imports.csv`](imports.csv) were cross-checked by recomputing the PS3 NID from the resolved function name.

Libraries:

| Library | Imports |
| --- | ---: |
| `sceNp` | 3 |
| `cellNetCtl` | 4 |
| `sys_net` | 3 |
| `sys_fs` | 22 |
| `cellSysutil` | 11 |
| `cellGcmSys` | 10 |
| `cellSysmodule` | 3 |
| `sysPrxForUser` | 18 |

## Build/configuration strings

Selected embedded configuration:

```text
PDIVersion=215.001
DiscProductNumber=BCUS-98158
NPCommunicationID=NPWR00222_00
NPTitleID=NPUA80075_00
ServiceID=UP9000-NPUA80075_00
GrimURL=https://gt5prologue.ps3.online.us.gran-turismo.com
VersionApplication=boot
VersionBranch=gt5p
VersionRegion=us
VersionTarget=ps3
VersionEnvironment=product-bd-key
VersionBuild=release
CompileDateTime=2008/03/22 17:01:51
CompileSVNRevision=28055
CompileSVNRevisionCurrent=28055
CompileSVNRevisionUpdate=28055
CompileSVNRevisionCommit=28040
```

## Next targets

The next useful decompilation targets are:

1. the local implementation behind `0x14570`, which materializes/validates the 160-byte PFS header;
2. the path and launch-state helpers around `0x323B0`, `0x32218`, `0x34960`, and `0x13F00`;
3. the game-data callback object around `0x379A0`;
4. the final argument construction immediately before `sys_game_process_exitspawn2`;
5. RTTI-backed PFS classes (`PDIPatchFileSystem`, `FileDevicePFSBase`) for mapping C++ methods to addresses.

Confidence labels are intentionally conservative: **confirmed** means directly established from binary structure/known import identity; **probable/high** means strongly supported by control flow; **tentative** remains subject to later renaming.
