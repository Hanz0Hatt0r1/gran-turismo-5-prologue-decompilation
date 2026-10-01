# EBOOT import map

This table was parsed from the PRX import descriptors in the decrypted BCUS-98158 executable. Symbol names were resolved from public PS3 NID databases and cross-checked where possible against open-source PS3 implementations. Stub addresses are addresses inside this EBOOT.

Total: **8 libraries / 74 imported functions**.

## `sceNp`

| NID | Stub | Resolved symbol |
| --- | ---: | --- |
| `0x4885AA18` | `0x5A5EC` | `sceNpTerm` |
| `0xBD28FDBF` | `0x5A60C` | `sceNpInit` |
| `0xE6C8F3F9` | `0x5A62C` | `sceNpDrmProcessExitSpawn2` |

## `cellNetCtl`

| NID | Stub | Resolved symbol |
| --- | ---: | --- |
| `0x04459230` | `0x5A64C` | `cellNetCtlNetStartDialogLoadAsync` |
| `0x0F1F13D3` | `0x5A66C` | `cellNetCtlNetStartDialogUnloadAsync` |
| `0x105EE2CB` | `0x5A68C` | `cellNetCtlTerm` |
| `0xBD5A59FC` | `0x5A6AC` | `cellNetCtlInit` |

## `sys_net`

| NID | Stub | Resolved symbol |
| --- | ---: | --- |
| `0x139A9E9B` | `0x5A6CC` | `sys_net_initialize_network_ex` |
| `0xB68D5625` | `0x5A6EC` | `sys_net_finalize_network` |
| `0xFDB8F926` | `0x5A70C` | `sys_net_free_thread_context` |

## `sys_fs`

| NID | Stub | Resolved symbol |
| --- | ---: | --- |
| `0x0E2939E5` | `0x5A72C` | `cellFsFtruncate` |
| `0x1A108AB7` | `0x5A74C` | `cellFsGetBlockSize` |
| `0x2796FDF3` | `0x5A76C` | `cellFsRmdir` |
| `0x2CB51F0D` | `0x5A78C` | `cellFsClose` |
| `0x3F61245C` | `0x5A7AC` | `cellFsOpendir` |
| `0x4D5FF8E2` | `0x5A7CC` | `cellFsRead` |
| `0x5C74903D` | `0x5A7EC` | `cellFsReaddir` |
| `0x718BF5F8` | `0x5A80C` | `cellFsOpen` |
| `0x7DE6DCED` | `0x5A82C` | `cellFsStat` |
| `0x7F4677A8` | `0x5A84C` | `cellFsUnlink` |
| `0x967A162B` | `0x5A86C` | `cellFsFsync` |
| `0x99406D0B` | `0x5A88C` | `cellFsChmod` |
| `0xA397D042` | `0x5A8AC` | `cellFsLseek` |
| `0xAA3B4BCD` | `0x5A8CC` | `cellFsGetFreeSize` |
| `0xBA901FE6` | `0x5A8EC` | `cellFsMkdir` |
| `0xBEF554A4` | `0x5A90C` | `cellFsUtime` |
| `0xC9DC3AC5` | `0x5A92C` | `cellFsTruncate` |
| `0xCB588DBA` | `0x5A94C` | `cellFsFGetBlockSize` |
| `0xECDCF2AB` | `0x5A96C` | `cellFsWrite` |
| `0xEFD3FA34` | `0x5A98C` | `cellFsFstat` |
| `0xF12EECC8` | `0x5A9AC` | `cellFsRename` |
| `0xFF42DCC3` | `0x5A9CC` | `cellFsClosedir` |

## `cellSysutil`

| NID | Stub | Resolved symbol |
| --- | ---: | --- |
| `0x02FF3C1B` | `0x5A9EC` | `cellSysutilUnregisterCallback` |
| `0x0BAE8772` | `0x5AA0C` | `cellVideoOutConfigure` |
| `0x189A74DA` | `0x5AA2C` | `cellSysutilCheckCallback` |
| `0x887572D5` | `0x5AA4C` | `cellVideoOutGetState` |
| `0x9949BF82` | `0x5AA6C` | `cellGameDataExitBroken` |
| `0x9D98AFA0` | `0x5AA8C` | `cellSysutilRegisterCallback` |
| `0xB72BC4E6` | `0x5AAAC` | `cellDiscGameGetBootDiscInfo` |
| `0xC9645C41` | `0x5AACC` | `cellGameDataCheckCreate2` |
| `0xDFDD302E` | `0x5AAEC` | `cellDiscGameRegisterDiscChangeCallback` |
| `0xE558748D` | `0x5AB0C` | `cellVideoOutGetResolution` |
| `0xEDC34E1A` | `0x5AB2C` | `cellDiscGameUnregisterDiscChangeCallback` |

## `cellGcmSys`

| NID | Stub | Resolved symbol |
| --- | ---: | --- |
| `0x15BAE46B` | `0x5AB4C` | `_cellGcmInitBody` |
| `0x21397818` | `0x5AB6C` | `_cellGcmSetFlipCommand` |
| `0x21AC3697` | `0x5AB8C` | `cellGcmAddressToOffset` |
| `0x3A33C1FD` | `0x5ABAC` | `_cellGcmFunc15` |
| `0x4AE8D215` | `0x5ABCC` | `cellGcmSetFlipMode` |
| `0x72A577CE` | `0x5ABEC` | `cellGcmGetFlipStatus` |
| `0xA53D12AE` | `0x5AC0C` | `cellGcmSetDisplayBuffer` |
| `0xA547ADDE` | `0x5AC2C` | `cellGcmGetControlRegister` |
| `0xB2E761D4` | `0x5AC4C` | `cellGcmResetFlipStatus` |
| `0xE315A0B2` | `0x5AC6C` | `cellGcmGetConfiguration` |

## `cellSysmodule`

| NID | Stub | Resolved symbol |
| --- | ---: | --- |
| `0x112A5EE9` | `0x5AC8C` | `cellSysmoduleUnloadModule` |
| `0x32267A31` | `0x5ACAC` | `cellSysmoduleLoadModule` |
| `0x63FF6FF9` | `0x5ACCC` | `cellSysmoduleInitialize` |

## `sysPrxForUser`

| NID | Stub | Resolved symbol |
| --- | ---: | --- |
| `0x1573DC3F` | `0x5ACEC` | `sys_lwmutex_lock` |
| `0x1BC200F4` | `0x5AD0C` | `sys_lwmutex_unlock` |
| `0x24A1EA07` | `0x5AD2C` | `sys_ppu_thread_create` |
| `0x2C847572` | `0x5AD4C` | `_sys_process_atexitspawn` |
| `0x2F85C0EF` | `0x5AD6C` | `sys_lwmutex_create` |
| `0x350D454E` | `0x5AD8C` | `sys_ppu_thread_get_id` |
| `0x409AD939` | `0x5ADAC` | `sys_mmapper_free_memory` |
| `0x4643BA6E` | `0x5ADCC` | `sys_mmapper_unmap_memory` |
| `0x67F9FEDB` | `0x5ADEC` | `sys_game_process_exitspawn2` |
| `0x744680A2` | `0x5AE0C` | `sys_initialize_tls` |
| `0x8461E528` | `0x5AE2C` | `sys_time_get_system_time` |
| `0xA2C7BA64` | `0x5AE4C` | `sys_prx_exitspawn_with_level` |
| `0xAEB78725` | `0x5AE6C` | `sys_lwmutex_trylock` |
| `0xAFF080A4` | `0x5AE8C` | `sys_ppu_thread_exit` |
| `0xB257540B` | `0x5AEAC` | `sys_mmapper_allocate_memory` |
| `0xC3476D0C` | `0x5AECC` | `sys_lwmutex_destroy` |
| `0xDC578057` | `0x5AEEC` | `sys_mmapper_map_memory` |
| `0xE6F2C1E7` | `0x5AF0C` | `sys_process_exit` |

## Notes

The import stub pattern is the standard PPU descriptor dispatch sequence: each stub loads a function descriptor through the import pointer table, saves the caller TOC at stack offset `0x28`, loads the target code/TOC pair, and branches through CTR.

This mapping immediately makes calls in the executable substantially more readable. For example:

- `0x103BC -> 0x5AE0C` = `sys_initialize_tls`
- `0x1047C -> 0x5AE2C` = `sys_time_get_system_time`
- `0x104A4 -> 0x5AD4C` = `_sys_process_atexitspawn`
- `0x108CC -> 0x5ACCC` = `cellSysmoduleInitialize`
- `0x108D8 -> 0x5ACAC` = `cellSysmoduleLoadModule(0x000E)`

For this PS3 sysmodule table, `0x000E` is `CELL_SYSMODULE_FS`, which fits the game-data/filesystem initialization path surrounding this call.
