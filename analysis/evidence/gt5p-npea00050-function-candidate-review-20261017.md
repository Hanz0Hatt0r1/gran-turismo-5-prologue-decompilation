# GT5 retail to NPEA-00050 candidate review

## Inputs and generated match

The comparison uses the hash-pinned GT5 BCUS-98114 ELF
(`bbbc31048dd608f8e959d9a84205b9fd7001b480b707af08c9d1f8c0816672bc`) and
UK-marked NPEA-00050 ELF
(`f68bd95b7b4896e74911e68619705172039339aa688c918d6ed7022d36107fbc`). The
generated candidate is recorded in
[`function-match-candidates.csv`](../crossref/gt5-bcus98114-vs-gt5p-npea00050-function-match-candidates.csv).

## Candidate `0x00bb6ce0` to `0x00013a70`

The table classifies this as a 72-byte `normalized-full` match with callgraph
ratio 1.0 and score 70 (`speculative`). Direct instruction comparison confirms
all 18 normalized PPC64 instruction words are equal. Both functions establish a
160-byte stack frame, save and restore LR and r29, prepare the same arguments
and local fields, perform one direct call, restore state, and return.

The call is at GT5 `0x00bb6d0c` and NPEA-00050 `0x00013a9c`; its targets
are respectively `0x00bb6c90` and `0x00013a20`. That helper pair is also an
80-byte `normalized-full` candidate with equal normalized instruction words.
Its direct call targets, however, are `0x00bb6a90` and `0x00013808`, and there
is no independently established mapping for those targets.

## Candidate `0x00cf2e10` to `0x0004b188`

The table classifies this as a 188-byte `normalized-full` match. Independently
recomputing the normalized SHA-1 from both pinned ELFs yields
`7daef03605f0e0386e5d7f5f5d94fc221b714cc2` for each body. Both functions make
a direct call at offset `0x4c`; the call targets resolve to `cellGcmSys` NID
`0x21397818` in their respective import tables. The local indexes leave the
name blank, while the external NID cross-check below identifies the imported
API as `_cellGcmSetFlipCommand`. That labels only the platform call, not either
game function.

## Additional exact imported-API candidates

Each pair below has an independently recomputed equal normalized-full SHA-1,
a direct call at the same function-relative offset, and the same import
library/NID in both builds. The local index leaves the name blank; the external
NID cross-check below supplies the API label.

| GT5 to NPEA-00050 | Bytes | Normalized SHA-1 | Imported API (library / NID) | Call offset |
| --- | ---: | --- | --- | ---: |
| `0x00cf2ecc` to `0x0004b270` | 64 | `62782eaa8ed0ffa9945e517a52c8206607837916` | `_cellGcmInitBody` (`cellGcmSys` / `0x15bae46b`) | `0x24` |
| `0x00d01688` to `0x00050ac0` | 68 | `06b1782da59fca38f53acc0a08991b02496474e2` | `sys_lwmutex_unlock` (`sysPrxForUser` / `0x1bc200f4`) | `0x2c` |
| `0x00d01774` to `0x00050bb8` | 44 | `17c8fc516cd9736e78a44f3d438f1db36207ef0a` | `sys_lwmutex_destroy` (`sysPrxForUser` / `0xc3476d0c`) | `0x14` |

The [PS3 Developer Wiki NID table](https://www.psdevwiki.com/ps3/Ps3.xml) lists
these names under the matching import libraries. An [RPCS3 loader trace](https://gist.github.com/Tripticon84/59be9941b1df565474c1a2de4167a762)
independently reports the same library/NID/name tuples. These sources identify
platform imports; they do not name the GT5/Prologue functions that call them.

## Review result

The first pair has matching wrapper bodies but unresolved downstream helpers.
The other five rows have identical normalized bodies and matched imported API
identities. Neither review establishes source identity or a supported semantic
name for any game function. Keep all six reviewed pairs at `candidate` /
`speculative`; do not transfer platform API names to game functions or add
accepted cross-references. Six match rows have been inspected; 121 of the 127
generated rows remain unreviewed.

The instruction comparison is reproducible from the pinned local ELF inputs by comparing each 32-bit word after `normalize_ppc_instruction` in `tools/gtdecomp.py`. The direct branch displacement is normalized away, while the caller and callee addresses above remain separately recorded. No executable bytes or decompiler output are committed.
