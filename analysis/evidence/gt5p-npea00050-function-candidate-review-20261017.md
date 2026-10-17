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

## Candidate `0x00bb6dbc` to `0x00013b50`

Both 80-byte (20-instruction) bodies have normalized SHA-1
`03737ecf00ab0a013646ab319fb3254e80901624`. The generated row is
`normalized-full` with strong callgraph evidence, neutral import/vtable
context, and score 70 (`speculative`). Neither function has a source-file hint
or string reference.

At `+0x34` (callsites `0x00bb6df0` / `0x00013b84`), both call the exact
normalized-full candidate `0x00bb6d74` / `0x00013b08` (72 bytes, SHA-1
`c46391a1b562c0af723f469ede93c114e1af4e69`). Two exact normalized-full caller
pairs also reach the reviewed functions at matching offsets: `0x00bb7560` /
`0x00014740` at `+0x28` and `0x00bb7a50` / `0x00014c70` at `+0x2c`. A third
GT5 caller at `0x00c677e8` has no generated cross-build caller pair and is not
used as evidence.

The exact body, callee, and two caller pairs support a probable body-level
relationship. The generated row remains `candidate` / `speculative`; the
separate [cross-reference record](../crossref/gt5-bcus98114-vs-gt5p-npea00050-function-00bb6dbc.yaml)
is probable/pending and does not assign a semantic or source name.

## Candidate `0x00bb6e0c` to `0x00013ba0`

Both 76-byte (19-instruction) bodies have normalized SHA-1
`600c57d1fc55f8a69229d66d8172ad871c105a65`. The generated row is
`normalized-full` with strong callgraph evidence, neutral import/vtable
context, and score 70 (`speculative`). Neither function has an indexed
source-file hint or string reference.

At `+0x30` (callsites `0x00bb6e3c` / `0x00013bd0`), both call
`0x00bb6d74` / `0x00013b08`, an exact normalized 72-byte body pair with
SHA-1 `c46391a1b562c0af723f469ede93c114e1af4e69`. Each build has two
indexed callers, but their caller bodies do not form cross-build pairs: GT5
callers `0x00bb7214` and `0x00bb7404` are 80 bytes, while NPEA callers
`0x000143e8` and `0x000145d8` are 88 bytes, with differing normalized hashes.

The exact body and aligned call to the exact callee pair support a probable
body-level relationship. The caller identities remain unresolved, and the
generated row stays `candidate` / `speculative`; the separate
[cross-reference record](../crossref/gt5-bcus98114-vs-gt5p-npea00050-function-00bb6e0c.yaml)
is probable/pending without a semantic or source name.

## Candidate `0x00bb6d74` to `0x00013b08`

Both 72-byte (18-instruction) bodies have normalized SHA-1
`c46391a1b562c0af723f469ede93c114e1af4e69`. The generated row is
`normalized-full` with neutral callgraph/import/vtable context and score 60
(`speculative`). Neither function has an indexed source-file hint or string
reference.

At `+0x2c` (callsites `0x00bb6da0` / `0x00013b34`), both call
`0x00bb6a90` / `0x00013808`, but the target bodies differ in size (424 / 420
bytes) and normalized SHA-1 (`29b350cc77ea0017c9ef33d6e8aa358fdcf5bcaf` /
`e76632b2b434d5fab333ddc39e51dc2f7f523c48`); this callee pair has no generated
match.

Two exact normalized-full caller pairs reach this function at matching
offsets: `0x00bb6dbc` / `0x00013b50` (80 bytes, SHA-1
`03737ecf00ab0a013646ab319fb3254e80901624`) calls at `+0x34`, and
`0x00bb6e0c` / `0x00013ba0` (76 bytes, SHA-1
`600c57d1fc55f8a69229d66d8172ad871c105a65`) calls at `+0x30`. Each build has
two more indexed callers, but these do not form cross-build pairs: GT5
`0x00bb71bc` / `0x00bb73ac` are 80 bytes, while NPEA
`0x00014390` / `0x00014580` are 88 bytes, with differing normalized hashes.

The exact body and two aligned exact caller pairs support a probable
body-level relationship. The unresolved outgoing callee and other incoming
callers limit the scope. The generated row stays `candidate` / `speculative`;
the separate [cross-reference record](../crossref/gt5-bcus98114-vs-gt5p-npea00050-function-00bb6d74.yaml)
is probable/pending without a semantic or source name.

## Candidate `0x00bb6c90` to `0x00013a20`

Both 80-byte (20-instruction) bodies have normalized SHA-1
`c1b73e9b69e84eec39902de2c886f24d05ebfd32`. The generated row is
`normalized-full` with neutral callgraph/import/vtable context and score 60
(`speculative`). Neither function has an indexed source-file hint or string
reference.

Two exact normalized-full caller pairs reach this function at matching
offsets: `0x00bb6ce0` / `0x00013a70` (72 bytes, SHA-1
`f9e2e1e0437a8d64223ec132b9a5d6c7d70fe39f`) calls at `+0x2c`, and
`0x00bb751c` / `0x000146f8` (68 bytes, SHA-1
`459efb7afb2916eb0af226468eae5ad8240b7bc6`) calls at `+0x28`.

At `+0x34` (callsites `0x00bb6cc4` / `0x00013a54`), both bodies call
`0x00bb6a90` / `0x00013808`; these downstream bodies differ in size (424 /
420 bytes) and normalized SHA-1
(`29b350cc77ea0017c9ef33d6e8aa358fdcf5bcaf` /
`e76632b2b434d5fab333ddc39e51dc2f7f523c48`), and have no generated match.

The exact body and two aligned caller pairs support a probable body-level
relationship, while the downstream helper remains unresolved. The generated
row stays `candidate` / `speculative`; the separate
[cross-reference record](../crossref/gt5-bcus98114-vs-gt5p-npea00050-function-00bb6c90.yaml)
is probable/pending without a semantic or source name.

## Exact-body callers of the reviewed lock helper

Three generated rows have exact normalized bodies and each directly calls the
previously reviewed lock-helper pair `0x00d1cd64` / `0x00056270` at a matching
offset. The generated rows all score 70 (`speculative`) with strong callgraph
context; each separate record below is probable/pending and scopes the relation
to the body and lock-helper edge.

| GT5 to NPEA-00050 | Bytes | Normalized SHA-1 | Lock-helper call offset |
| --- | ---: | --- | ---: |
| `0x00d1bf50` to `0x00055438` | 376 | `9a75f7c081f8a6536b89916b64a736be955c0b61` | `+0x60` |
| `0x00d1c130` to `0x00055618` | 136 | `82b04e32aabc12ae97c89e3fde9816e4ed1290f4` | `+0x4c` |
| `0x00d1ecc4` to `0x00056b40` | 184 | `b5b3ea9f319f710da13e5ed5c45249d8b24342a5` | `+0x74` |

Other local calls from these bodies do not have generated target pairs. None
has an indexed source-file hint or string reference, so the records do not
assign semantic names or broader subsystem roles. See the separate
[376-byte record](../crossref/gt5-bcus98114-vs-gt5p-npea00050-function-00d1bf50.yaml),
[136-byte record](../crossref/gt5-bcus98114-vs-gt5p-npea00050-function-00d1c130.yaml),
and [184-byte record](../crossref/gt5-bcus98114-vs-gt5p-npea00050-function-00d1ecc4.yaml).

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

## Candidate `0x00d19ca0` to `0x00053118`

The generated row is a 256-byte `normalized-prefix` match with score 60 and
speculative confidence. The shared prefix SHA-1 is
`94864a1f8b683fe3132445ff143d1ec714510a10`; the full bodies differ in size
(756 / 760 bytes) and SHA-1
(`0849b1efef20442864cfe3bc9fb789c65493ab88` /
`219f6dc11bb77599f17923f9163976412c4aef0b`). Neither function has a
source-file hint or string reference.

Two exact normalized-full caller pairs reach the functions at matching
offsets: `0x00d1a96c` / `0x00053e00` at `+0x1e4` and `0x00d1a534` /
`0x000539c0` at `+0x10c`. A third normalized-prefix caller pair,
`0x00d1abac` / `0x00054040`, reaches them at `+0x110`; its own full sizes
differ. Other indexed callers do not form generated cross-build pairs.

The functions each have five outgoing calls. Only one target pair,
`0x00d189c0` / `0x00051e10`, has a generated match, and that match is also
prefix-only; the remaining callees are unresolved. The three incoming caller
pairs support a probable shared call-graph role for the common prefix, but do
not establish full function or source identity. The generated row stays
candidate/speculative; a separate [cross-reference record](../crossref/gt5-bcus98114-vs-gt5p-npea00050-prefix-00d19ca0.yaml)
is probable/pending and not accepted.

## Candidate `0x00d1a96c` to `0x00053e00`

Both bodies are 576 bytes (144 instructions) with normalized SHA-1
`3223b3b107559c76900a3f7ddc500af3d30d29dd`. The generated row is
`normalized-full` with strong callgraph evidence, neutral import/vtable
context, and score 70 (`speculative`). Neither function has a source-file hint
or string reference.

Four calls have paired targets at matching relative offsets. At `+0xf0`, the
functions call the exact normalized-full candidate `0x00d1a534` /
`0x000539c0` (320 bytes, SHA-1
`50fe7748517a22753cb4f97aaceb4228fc892146`). At `+0x210`, they call exact
normalized-full candidate `0x00d1a830` / `0x00053cc0` (68 bytes, SHA-1
`0177f87399f83ae41ea3b8e0bb9ed3eef0012bea`). The other paired targets,
`0x00d19ca0` / `0x00053118` at `+0x1e4` and `0x00d19f94` / `0x00053410` at
`+0x22c`, are normalized-prefix candidates with different full sizes/hashes.
All four callee rows remain candidates or pending records, not accepted
identities.

The two other calls at `+0x200` and `+0x21c` target `0x00cf9050` /
`0x0004bc50` and `0x00d01898` / `0x00050da8`; neither target pair is in the
generated table. Each function has one indexed incoming caller, but
`0x00d200a4` and `0x00057ec0` do not form a generated caller pair. The exact
body and four aligned call edges support a probable body-level relationship;
they do not establish a semantic name or source identity. The generated row
stays `candidate` / `speculative`; the separate [cross-reference
record](../crossref/gt5-bcus98114-vs-gt5p-npea00050-function-00d1a96c.yaml)
is probable/pending and not accepted.

## Candidate `0x00d1cda0` to `0x000562e8`

Both bodies are 56 bytes (14 instructions) with normalized SHA-1
`851bc1bccd846f8c7b8b034d4a876b6d142af6b4`. The generated row is
`normalized-full` with supporting import context, neutral callgraph/vtable
context, and score 70 (`speculative`). Neither function has a source-file hint
or string reference.

At `+0x10` (callsites `0x00d1cdb0` and `0x000562f8`), both call the same raw
import tuple: `sysPrxForUser`, NID `0x2f85c0ef`; local indexes have no resolved
name. At `+0x30`, they call `0x00d01898` and `0x00050da8`, which have no
generated candidate pairing. Each function has two indexed callers, but no
cross-build caller pair: GT5 callers `0x00d1b370` and `0x00d1eca0` call at
`+0xc`, while NPEA callers `0x00054810` and `0x00056b10` call at `+0x14`.

The body and import context do not establish the function's higher-level role.
The generated row remains `candidate` / `speculative`; no cross-reference or
semantic name is promoted.

## Candidate `0x00d1ce8c` to `0x000564d0`

Both bodies are 72 bytes (18 instructions) with normalized SHA-1
`d82893edf401acdf85a611ae050e8ef380198a2b`. The generated row is
`normalized-full` with supporting import context, neutral callgraph/vtable
context, and score 70 (`speculative`). Neither function has a source-file hint
or string reference.

At `+0x20` (callsites `0x00d1ceac` and `0x000564f0`), both call
`sysPrxForUser`, NID `0x2f85c0ef`; the local indexes leave the import name
unresolved. At `+0x40` (callsites `0x00d1cecc` and `0x00056510`), they call
`0x00d01898` and `0x00050da8`, which have no generated candidate pairing.
Each function has one indexed caller immediately after its body; callers
`0x00d1ced4` and `0x00056518` are not a generated cross-build candidate pair.

The exact body and raw import tuple are useful cross-build evidence, but the
callee and caller identities remain unresolved. The generated row stays
`candidate` / `speculative`, with no cross-reference or semantic name promoted.

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
`0x00d18dd0` to `0x00052228` plus the two import-context pairs above, bringing
the current totals to twenty inspected rows and 107 unreviewed rows. The
reviewed generated rows remain candidate/speculative; all twelve NPEA probable
cross-reference records remain pending.

The instruction comparison is reproducible from the pinned local ELF inputs by comparing each 32-bit word after `normalize_ppc_instruction` in `tools/gtdecomp.py`. The direct branch displacement is normalized away, while the caller and callee addresses above remain separately recorded. No executable bytes or decompiler output are committed.
