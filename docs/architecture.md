# Architecture map

This document is an evidence-driven map, not a prediction of the original source tree. Each non-unknown statement should link to a build/module/function note and carry a confidence level.

## Build model

The architecture map is multi-build. GT5 BCUS-98114 is currently the reference build; GT5 Prologue BCUS-98158 is the target build. A subsystem statement must identify which build supplies the evidence. Shared behavior is established through reviewed cross-build matches rather than by assuming source-level identity.

## Startup and lifecycle

**GT5 BCUS-98114: probable / early evidence**

```text
ELFv1 entry descriptor 0x017f8150
  -> code entry 0x00010230
  -> startup function 0x00010338
  -> early initialization calls / trampolines
```

The GT5 entry descriptor and entry code are confirmed. The semantic identity of 0x00010338 and the complete initialization graph remain unresolved. Earlier GT5 Prologue bootstrap notes are retained as target-build evidence and must not be presented as GT5 evidence.

**GT5 Prologue BCUS-98158: probable / partially mapped**

The Prologue bootstrap remains a separate target-build investigation. Its reviewed path includes game-data checks, filesystem/sysmodule initialization, and early EMAIN/EPATCH/PDIPFS handling, but the complete startup graph and main loop remain unresolved.

## Rendering

**Status: unknown**

Start from indexed functions, imports, strings, RTTI/vtables, and call-graph clusters.

## Vehicle simulation / physics
**Status: unknown**

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

The Prologue bootstrap establishes filesystem/game-data initialization, but resource-loader ownership and higher-level resource formats are not yet mapped. GT5 will be used as a reference where cross-build evidence supports the relationship.

## Architecture entry format

For each subsystem record: entry points; build/module/address; key data structures; major callers/callees; evidence; confidence; related analysis notes; unresolved questions.

Never promote a subsystem from unknown solely because a function name or decompiler guess looks plausible.
