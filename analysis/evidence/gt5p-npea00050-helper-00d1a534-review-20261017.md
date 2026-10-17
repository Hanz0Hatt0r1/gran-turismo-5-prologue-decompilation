# GT5 to NPEA-00050 function-body review: `0x00d1a534` / `0x000539c0`

## Inputs and generated candidate

The comparison uses GT5 BCUS-98114 ELF SHA-256
`bbbc31048dd608f8e959d9a84205b9fd7001b480b707af08c9d1f8c0816672bc` and
UK-marked NPEA-00050 ELF SHA-256
`f68bd95b7b4896e74911e68619705172039339aa688c918d6ed7022d36107fbc`.
NPEA-00050 remains separate from canonical BCUS-98158.

The generated candidate row classifies `0x00d1a534` to `0x000539c0` as a
320-byte `normalized-full` match with score 70 and speculative confidence. The
regenerated function indexes record the same normalized full SHA-1 for both
bodies: `50fe7748517a22753cb4f97aaceb4228fc892146` (80 instructions).

## Caller and callee context

GT5 `0x00d1a96c` and NPEA `0x00053e00` are a separate 576-byte
`normalized-full` pair with SHA-1
`3223b3b107559c76900a3f7ddc500af3d30d29dd`. Each directly calls the reviewed
function at caller offset `+0xf0` (`0x00d1aa5c` and `0x00053ef0`).

The reviewed functions also call `0x00d19ca0` / `0x00053118` at offset
`+0x10c`. Those callees share normalized-prefix SHA-1
`94864a1f8b683fe3132445ff143d1ec714510a10`, while their full sizes differ
(756 and 760 bytes), so their full identity remains unresolved. A second call
aligns at offset `+0x120`, but the targets `0x00cf9050` and `0x0004bc50` have
no generated candidate pairing.

Each function has another indexed caller, `0x00d20138` at `+0x64` and
`0x00057f48` at `+0x54`. These callers do not have a generated cross-build
pair, so this evidence is not used to claim a shared caller relationship.

## Review result

The exact 320-byte normalized body and the matching normalized-full caller at
the same relative call offset support a probable function-body relationship.
The generated row remains candidate/speculative because its automated score
does not include incoming-call context. The separate
[cross-reference record](../crossref/gt5-bcus98114-vs-gt5p-npea00050-helper-00d1a534.yaml)
records this relationship as probable/pending. No semantic name, subsystem
label, source identity, or code is transferred, and the relationship is not
accepted.
