# NPEA-00050 Prologue ELF identity and first GT5 comparison

## Input identity

The user-supplied `EBOOT.elf` is a 420,752-byte ELF64 big-endian PowerPC64
executable. Its SHA-256 is
`f68bd95b7b4896e74911e68619705172039339aa688c918d6ed7022d36107fbc`.
The ELF contains `NPTitleID=EP9001-NPEA00050_00`, the build string
`boot.gt5p.uk.ps3.product-edi-key.release.build`, and the GT5 Prologue UK online
endpoint. The local indexer independently reports title ID `NPEA-00050`.

`gtdecomp.py index` resolved `e_entry` descriptor `0x00071838` to code
`0x00010230` and TOC `0x0007d230`. Its reproducible index contains 1,857 OPD
descriptors, 1,848 unique function addresses, 1,925 discovered function
addresses, 2,693 candidates, 63 RTTI objects, 458 vtable slots, 8 import
libraries, 77 imports, and 2,936 direct call edges. The CFG-aware index also records 11 TOC string
references; the earlier linear range scan found 7. `gtverify.py verify` passed
the raw ELF SHA, entry descriptor, entry code, and TOC checks against
[`gt5p-npea00050.json`](../builds/gt5p-npea00050.json).

This is a separately pinned UK-marked raw ELF comparison build. It is not the
canonical US BCUS-98158 profile, and its SHA does not identify an enclosing SELF
or package. The two Prologue profiles use entry code VA `0x00010230`, but their
entry descriptors and TOCs differ.

## GT5 retail comparison

The GT5 BCUS-98114 local ELF was re-indexed with the current `gtdecomp.py`; its
SHA still matches the reviewed profile. The CFG-aware index reports 54,445 discovered function addresses and 67,205
function candidates, plus 19,316 TOC string references, 5,301 functions with
hints, and 182,866 direct call edges (182,642 local). The range walker follows
reachable conditional-branch blocks and stops at returns or the next strong
candidate boundary. These counts replace the earlier linear-scan metrics in
the checked-in baseline profile.

The earlier linear-range comparison emitted 131 rows. After CFG-aware function
ranges, the current comparison emits 127 rows: 117 normalized-full and 10
normalized-prefix candidates. All remain `candidate` and `speculative`; 22 have
supporting callgraph context and 7 have supporting import context. None was
ranked probable. At the time of this initial audit, seven generated rows had
been reviewed; six remained speculative. A separate pending cross-reference
records the 60-byte `0x00d1cd64` to `0x00056270` lock-helper relationship as
probable. A second pending cross-reference records the role-level startup
relationship between `0x00010338` and `0x00010360`; the full fingerprints differ, so the
pair is not added to the generated table. At that point the CSV contained 127
candidate/speculative rows, with 120 not yet reviewed. The later review of
`0x00d1a534` to `0x000539c0` is documented in the [helper-body review
note](gt5p-npea00050-helper-00d1a534-review-20261017.md).
Subsequent reviews of `0x00d18dd0` to `0x00052228`, `0x00d1cda0` to
`0x000562e8`, and `0x00d1ce8c` to `0x000564d0` are documented in the
[candidate review note](gt5p-npea00050-function-candidate-review-20261017.md);
their generated rows remain speculative. The review of `0x00d19ca0` to
`0x00053118` adds a separate probable/pending role-level cross-reference with
full function identity unresolved. The review of `0x00d1a96c` to `0x00053e00`
adds a probable/pending exact-body relationship. The review of `0x00bb6dbc` to
`0x00013b50` adds another probable/pending exact-body relationship. The
subsequent review of `0x00bb6e0c` to `0x00013ba0` adds an exact-body
relationship with one exact callee pair; incoming caller identities remain
unresolved, and 112 candidates are unreviewed.
The review of `0x00bb6d74` to `0x00013b08` adds a probable/pending exact-body
relationship supported by two aligned exact caller pairs; 111 candidates are
unreviewed.
The full CSV is
[`gt5-bcus98114-vs-gt5p-npea00050-function-match-candidates.csv`](../crossref/gt5-bcus98114-vs-gt5p-npea00050-function-match-candidates.csv).
No candidate was emitted for entry code `0x00010230`.

The separate accepted cross-reference records only the ELFv1 startup role.
Retail descriptor `0x017f8150` resolves to code `0x00010230` with TOC
`0x01846af0`; the NPEA-00050 descriptor resolves to that code address with TOC
`0x0007d230`. The normalized four-instruction entry prefixes differ, and the
first direct-call targets differ (`0x00010338` and `0x00010360`). The relation
does not assert matching function bodies, source identity, or subsystem
equivalence.

## Ghidra and portable P-code

Ghidra 12.1.2_DEV imported the ELF as
`PowerPC:BE:64:A2ALT:default` and completed analysis. Automatic analysis found
66 functions. I added the ELFv1 entry target `0x00010230` to the separate local
Ghidra project for inspection; Ghidra warned that its decompilation encounters
a P-code error at `0x00010254`. I excluded that row from the promoted corpus.

The shared `PortablePcodeCorpusExporter` from `revenginstr` commit
`8b1e5bd0ef001ae56a281a742f6826e77dfb1599` exported the remaining 66
functions. The `REVENGINSTR.PcodeAudit/1` report passed the portable contract
with 66/66 `ok`, zero truncated rows, and zero leakage findings. The retained
JSONL is [`gt5p-npea00050-portable-pcode.jsonl`](gt5p-npea00050-portable-pcode.jsonl),
SHA-256 `778c13898f2a130889ef51cbcf6a2067719d68ee5ffcaa1a33b6964618c0d66b`.

The raw ELF, Ghidra database, generated string table, and product/license fields
remain local. No executable bytes or extracted assets are included here.
