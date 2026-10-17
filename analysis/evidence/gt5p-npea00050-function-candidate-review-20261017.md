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

## Candidate `0x00d1cd64` to `0x00056270`

Both 60-byte bodies independently recompute to normalized SHA-1
`15c114e437488a6cba2537234a19075a1061d6d0`. Each makes one direct call at
function offset `0x10` to `sysPrxForUser` NID `0x1573dc3f`, identified as
`sys_lwmutex_lock` by the NID table and loader trace above.

Three separately normalized-full caller pairs call this helper at matching
relative offsets: `0x00d1bf50` to `0x00055438` at `+0x60`, `0x00d1c130` to
`0x00055618` at `+0x4c`, and `0x00d1ecc4` to `0x00056b40` at `+0x74`. This
supports the same lock-helper role in both builds. The generated row remains
`candidate` / `speculative` at score 70 because its automatic context does not
include these incoming caller edges. A separate manual cross-reference records
the relationship as `probable` / `pending`, scoped to this helper body and
import call; it does not assign a game-function name or accept the match.

## Candidate `0x00d18dd0` to `0x00052228`

Both indexed bodies are 172 bytes (43 instructions) and have normalized SHA-1
`559c1f8ca33e7a6952795e99a39a8bf7797d6d03`. The generated row reports
`normalized-full`, strong callgraph evidence, neutral import and vtable context,
and score 70 (`speculative`). Neither function has an indexed incoming caller,
source-file hint, or string reference.

Each body has two direct calls at matching offsets. At `+0x3c` (callsites
`0x00d18e0c` and `0x00052264`), GT5 calls `0x00c0e9c0` and NPEA calls
`0x000509e8`; that target pair is absent from the generated candidate table.
At `+0x54` (callsites `0x00d18e24` and `0x0005227c`), the targets are
`0x00d189c0` and `0x00051e10`, a separate `normalized-prefix` candidate with
sizes 1040 and 1048 bytes and no secondary context. The callgraph score
therefore does not establish matching identities for all outgoing targets.

The matching body is recorded as reviewed, but the candidate remains
`candidate` / `speculative`; no cross-reference or semantic identity is
promoted.

## Review result

The first pair has matching wrapper bodies but unresolved downstream helpers.
The other five speculative rows have identical normalized bodies and matched
imported API identities. Six match rows remain `candidate` / `speculative`; the
lock-helper row has a separate `probable` / `pending` cross-reference. Do not
transfer platform API names to game functions or add accepted cross-references.
At the time of this review, seven match rows had been inspected and 120 of the
127 generated rows remained unreviewed. A later review of
`0x00d1a534` to `0x000539c0` is recorded in the [helper-body review
note](gt5p-npea00050-helper-00d1a534-review-20261017.md), and the review of
`0x00d18dd0` to `0x00052228` above, bringing the current totals to nine
inspected rows and 118 unreviewed rows. The reviewed generated rows remain
candidate/speculative; all three cross-reference records remain pending.

The instruction comparison is reproducible from the pinned local ELF inputs by comparing each 32-bit word after `normalize_ppc_instruction` in `tools/gtdecomp.py`. The direct branch displacement is normalized away, while the caller and callee addresses above remain separately recorded. No executable bytes or decompiler output are committed.
