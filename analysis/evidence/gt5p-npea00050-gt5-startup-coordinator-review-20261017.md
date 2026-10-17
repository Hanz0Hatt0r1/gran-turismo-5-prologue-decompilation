# GT5 retail to NPEA-00050 startup coordinator review

## Inputs and function ranges

This review compares the hash-pinned GT5 BCUS-98114 ELF
(`bbbc31048dd608f8e959d9a84205b9fd7001b480b707af08c9d1f8c0816672bc`) with
the separately pinned UK-marked NPEA-00050 ELF
(`f68bd95b7b4896e74911e68619705172039339aa688c918d6ed7022d36107fbc`). It
does not use the canonical BCUS-98158 Prologue profile.

The existing reviewed function records give GT5 `0x00010338` a 444-byte range
(`0x00010338-0x000104f4`) and NPEA-00050 `0x00010360` a 488-byte range
(`0x00010360-0x00010548`). Their normalized full fingerprints differ:
`5bd7ac80989be48f2e2e6a1a089a3d660736226b` and
`7a4dea8a68bec79ba51167628e960d940207b3ac`. The 256-byte normalized-prefix
fingerprints also differ, and the generated candidate CSV does not pair them.

## Shared startup evidence

The first 25 normalized instruction words (100 bytes) match exactly and have
SHA-1 `e6c01d78a3be289a05a0e4299adedcb30774035a`. This comparison uses
`normalize_ppc_instruction` from `tools/gtdecomp.py`; it is a manually selected
100-byte excerpt, not the matcher's 256-byte prefix method.

Both entry routines at `0x00010230` call the respective functions. Each target
establishes a 160-byte PPC64 frame and preserves the same nonvolatile register
set. Within the independently recorded function ranges, each makes calls to
`sysPrxForUser` imports with the same five NIDs in the same order:

| NID | GT5 function offset | NPEA-00050 function offset |
| --- | ---: | ---: |
| `0x744680a2` | `+0x54` | `+0x54` |
| `0x8461e528` | `+0x10c` | `+0x114` |
| `0x42b23552` | `+0x154` | `+0x160` |
| `0x2c847572` | `+0x160` | `+0x16c` |
| `0x96328741` | `+0x16c` | `+0x178` |

Both also directly call `0x00010200`, at offsets `+0x11c` and `+0x124`
respectively. Later calls and control-flow blocks differ; no downstream callee
mapping is inferred from this comparison.

## Review result

The shared entry position, frame setup, exact 100-byte normalized excerpt,
ordered import-NID context, and call to `0x00010200` support a probable
relationship at the early runtime/startup coordinator role. Different full
and 256-byte fingerprints and function sizes prevent claiming whole-function
identity. This is recorded separately as `manual`, `probable`, and `pending`;
the generated 127-row table remains unchanged and speculative. No function
name, source identity, application-loader identity, or code is transferred.

The [cross-reference record](../crossref/gt5-bcus98114-vs-gt5p-npea00050-startup-coordinator.yaml)
scopes the relationship to this observed startup evidence. The local
cross-build verifier confirms both addresses are executable and keeps this
manual record separate from generated fingerprint matches.
