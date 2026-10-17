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

## Review result

The outer wrappers have a mechanically matching structure, but the current
evidence does not establish what the downstream helpers do or whether their
behavior is equivalent. Keep both rows at `candidate` / `speculative`; do not
transfer semantic names or add an accepted cross-reference. This review covers
one of 131 generated rows and does not complete the candidate-review roadmap
item.

The instruction comparison is reproducible from the pinned local ELF inputs by comparing each 32-bit word after `normalize_ppc_instruction` in `tools/gtdecomp.py`. The direct branch displacement is normalized away, while the caller and callee addresses above remain separately recorded. No executable bytes or decompiler output are committed.
