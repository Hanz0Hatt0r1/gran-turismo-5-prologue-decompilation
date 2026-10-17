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
ranked probable. The full CSV is
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
