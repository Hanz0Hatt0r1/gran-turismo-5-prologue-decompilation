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

## Source-file evidence seed

**GT5 BCUS-98114: probable / evidence-only**

The retained source-file names provide a useful subsystem triage layer before any function is semantically named. The current inventory contains 362 unique source-file strings. Keyword grouping yields UI (25), resource/I/O (16), networking (13), race (9), rendering (8), course (7), vehicle (6), audio (6), jobs/threads (5), game (4), and input/replay/save-profile (3 each). These counts are not function counts and do not establish ownership; they only identify themes for later xref and call-graph review.

The next addressable layer is now in place: scanning the GT5 TOC for PPU `lwz`/`ld` loads that resolve to retained source strings finds 340 executable xrefs covering 44 of the 362 source-file strings. Of those instruction sites, 99 fall inside ranges derived from confirmed OPD function starts; 241 remain outside OPD-backed ranges and are therefore left for static/local-function review. These xrefs identify concrete code-reference sites but still do not establish complete function ownership or semantic subsystem membership.

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
