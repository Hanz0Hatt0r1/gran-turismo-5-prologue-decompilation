# Startup decompilation

Build: BCUS-98158  
Executable SHA-256: `f58e36b3cb371e357ae0f3a019fb339c653682bc7ff6423abf3c2c7db50eef2a`

This document records reconstructed behavior, not a raw decompiler dump. Names beginning with `sub_` are address-based placeholders until stronger semantic evidence exists.

## `sub_10230` — PPU entry stub

**Confidence: confirmed.**

The ELF entry field is OPD `0x717D8`, whose descriptor is:

```text
code = 0x10230
toc  = 0x7D110
```

The routine explicitly recovers the TOC from the descriptor, creates the initial stack frame, clears the initial back-chain slot, and calls `sub_10368`.

Representative instructions:

```asm
10230  li      r2, 0
10234  oris    r2, r2, 7
10238  ori     r2, r2, 0x17d8
1023c  lwz     r2, 4(r2)          ; r2 = 0x7D110
10240  stdu    r1, -0x70(r1)
10244  li      r14, 0
10248  std     r14, 0(r1)
1024c  bl      0x10368
```

Working reconstruction:

```c
/* ABI-oriented pseudocode. Exact startup prototype still unknown. */
static void ppu_entry_stub(void)
{
    r2 = *(uint32_t *)(0x717D8 + 4);   /* TOC = 0x7D110 */
    make_initial_stack_frame(0x70);
    *(uint64_t *)r1 = 0;
    sub_10368(/* firmware startup registers */);
}
```

## `sub_10258` / `sub_10268` — startup state accessors

**Confidence: probable.**

Both load the same TOC-relative global pointer:

```text
r9 = *(u32 *)(r2 - 0x8000)
```

- `sub_10258` returns signed word `global[0]`.
- `sub_10268` returns word `global[1]`.

`sub_10368` later writes its first two normalized startup values into those two words, so these are likely accessors for process `argc` / `argv`-related CRT state.

## `sub_10278` — exit-spawn helper

**Confidence: confirmed call target; parameter semantics pending.**

```asm
10278  li      r3, 0
...
10288  bl      0x5AE4C
```

Import `0x5AE4C` resolves to `sys_prx_exitspawn_with_level`.

Pseudocode:

```c
static void sub_10278(void)
{
    sys_prx_exitspawn_with_level(/* r3 = */ 0);
}
```

The exact prototype is intentionally not imposed yet.

## `sub_102A0` — runtime finalization chain

**Confidence: probable.**

This function invokes the ELF `.fini` routine and five internal finalizers:

```text
0x5A5C8  .fini
0x4B128  unknown finalizer
0x501D8  unknown finalizer
0x4EAB0  unknown finalizer
0x50508  unknown finalizer
0x22908  unknown finalizer
```

Current reconstruction:

```c
static void sub_102A0(void)
{
    fini_5A5C8();
    sub_4B128();
    sub_501D8();
    sub_4EAB0();
    sub_50508();
    sub_22908();
}
```

The `.fini` routine itself calls `sub_104F8`.

## `sub_102F8` — pre-finalization wrapper

**Confidence: confirmed control flow.**

```c
static void sub_102F8(void)
{
    sub_4AC28();
    sub_102A0(); /* tail branch in the original */
}
```

## `sub_10328` — process termination path

**Confidence: high.**

The input status is preserved, the exit-spawn helper and finalization chain are run, then the saved status is passed to `sys_process_exit`.

```c
static void sub_10328(int32_t status)
{
    sub_10278();
    sub_102A0();
    sys_process_exit(status);
}
```

Import `0x5AF0C` is NID `0xE6F2C1E7 = sys_process_exit`.

## `sub_10368` — CRT/runtime bootstrap

**Confidence: high for role, incomplete for exact prototype.**

This is the main runtime startup routine reached directly from `sub_10230`.

Observed sequence:

1. Saves startup register arguments.
2. Calls `sys_initialize_tls` through import stub `0x5AE0C`.
3. Normalizes/copies two startup pointer arrays into 32-bit PPU address form.
4. Stores startup values into a TOC-relative CRT state object.
5. Calls internal runtime initializers:
   - `sub_225B8`
   - `sub_506D0`
   - `sub_4E928`
   - `sub_50170`
6. Calls `sys_time_get_system_time` and stores the result globally.
7. Calls the ELF initialization routine at `0x10200`.
8. Calls `sub_4AF60`.
9. Registers an exit-spawn handler through `_sys_process_atexitspawn`.
10. Converts the startup values to the expected 32-bit ABI widths.
11. Calls `sub_106E0`.
12. Passes the result to `sub_4AD40` and returns.

High-level reconstruction:

```c
static int64_t sub_10368(/* PS3 crt startup state */)
{
    sys_initialize_tls(...);

    normalize_startup_vectors(...);
    save_crt_process_state(...);

    sub_225B8();
    sub_506D0(...);
    sub_4E928();
    sub_50170();

    g_start_time = sys_time_get_system_time();

    init_10200();
    sub_4AF60(...);
    _sys_process_atexitspawn(...);

    int result = sub_106E0(/* normalized argc/argv/env-like values */);
    sub_4AD40(result);
    return result;
}
```

Do not yet rename `sub_10368` to `main`: it contains clear CRT/runtime setup and calls the next layer.

## `sub_106E0` — probable game bootstrap

**Confidence: probable.**

This is the first large routine after CRT startup and is the current primary decompilation target.

Notable facts already confirmed from its first basic blocks:

- allocates a `0x990`-byte stack frame;
- preserves the incoming process/startup arguments;
- calls `sub_11BD0`, `sub_34AE0`, `sub_11768`, `sub_124A0`, and `sub_116E0` early;
- builds several local buffers of size `0x104` (260) bytes;
- calls a helper at `sub_29070` with two `1055` constants;
- explicitly checks error `0x8002B606`, which resolves to `CELL_GAMEDATA_ERROR_BROKEN`;
- calls `cellSysmoduleInitialize()`;
- immediately calls `cellSysmoduleLoadModule(0x000E)`;
- `0x000E` resolves to `CELL_SYSMODULE_FS`;
- enters several state-dependent branches and later creates/starts additional execution work through `sub_27EB0`.

The relevant import calls are:

```asm
107f0  lis     r0, 0x8002
107f8  ori     r0, r0, 0xB606       ; CELL_GAMEDATA_ERROR_BROKEN
...
108cc  bl      0x5ACCC              ; cellSysmoduleInitialize
108d4  li      r3, 14               ; 0x000E = CELL_SYSMODULE_FS
108d8  bl      0x5ACAC              ; cellSysmoduleLoadModule
```

A conservative structural reconstruction is:

```c
static int sub_106E0(int argc_like, void *argv_like, void *env_like)
{
    /* large game startup context and temporary buffers */

    sub_11BD0();
    sub_34AE0(...);
    sub_11768(...);
    startup_state = sub_124A0();
    sub_116E0();

    /*
     * Prepare/check game-data paths and state.
     * One path explicitly handles CELL_GAMEDATA_ERROR_BROKEN.
     */

    if (/* filesystem/game-data startup path is needed */) {
        cellSysmoduleInitialize();
        cellSysmoduleLoadModule(CELL_SYSMODULE_FS);
        /* continue file/game-data setup */
    }

    /* additional startup state machine, services and worker creation */

    return /* startup result */;
}
```

### Why this is likely the game boundary

The caller `sub_10368` is dominated by CRT duties: TLS setup, static initialization, process-time setup, atexit registration and final result handling. `sub_106E0` immediately transitions into game-data paths, filesystem module loading, large local application state, and a substantial internal call graph.

For now the repository should keep the address-derived name `sub_106E0` until its callers/callees and string references establish a stronger original semantic name.

## Next targets

Priority order for the next pass:

1. resolve TOC globals referenced by `sub_106E0`;
2. identify `sub_29070` and the game-data callback path;
3. identify `sub_323B0` / `sub_32218` used for the 260-byte path/string objects;
4. trace all references to:
   - `/dev_bdvd/PS3_GAME/USRDIR`
   - `/dev_bdvd/PS3_GAME/USRDIR/GT.VOL`
   - `boot_from=gamedata`
   - `BCUS-98158`;
5. split `sub_106E0` into named startup subsystems before moving reconstructed code into `src/`.
