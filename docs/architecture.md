# Architecture map

This document is an evidence-driven map, not a prediction of the original source tree. Each non-unknown statement should link to a build/module/function note and carry a confidence level.

## Startup and lifecycle

**Status: probable / partially mapped**

Current evidence from the BCUS-98158 bootstrap work:

```text
ELF entry
  -> CRT/runtime bootstrap
  -> game-level bootstrap at 0x106E0
  -> cellGameDataCheckCreate2
  -> broken-game-data handling
  -> cellSysmodule initialization
  -> CELL_SYSMODULE_FS
  -> EMAIN.SELF / EPATCH.SELF / PDIPFS bootstrap path
```

The exact TOC-backed globals, complete initialization graph, and main application loop remain unresolved.

## Rendering

**Status: unknown**

Start from indexed functions, imports, strings, RTTI/vtables, and call-graph clusters.

## Vehicle simulation / physics
**Status: unknown**

Do not create reconstructed source until function groups and relevant data structures have evidence.

## Race/session logic
**Status: unknown**

## UI
**Status: unknown**

## Audio
**Status: unknown**

## Save/profile
**Status: unknown**

## Networking
**Status: unknown**

## Resource loading

**Status: probable / early evidence**

The bootstrap path establishes filesystem/game-data initialization, but resource-loader ownership and higher-level resource formats are not yet mapped.

## Architecture entry format

For each subsystem record: entry points; build/module/address; key data structures; major callers/callees; evidence; confidence; related analysis notes; unresolved questions.

Never promote a subsystem from unknown solely because a function name or decompiler guess looks plausible.