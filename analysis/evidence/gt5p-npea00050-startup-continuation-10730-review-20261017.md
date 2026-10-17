# NPEA-00050 startup continuation at `0x00010730`

## Input and scope

This review uses the UK-marked NPEA-00050 raw ELF with SHA-256
`f68bd95b7b4896e74911e68619705172039339aa688c918d6ed7022d36107fbc`. It is a
separate comparison build, not the canonical US BCUS-98158 profile.

Ghidra 12.1.2 headless analysis and a targeted PyGhidra export completed for
`0x00010730` with status `ok`. The pseudocode and Ghidra project remain local;
neither is stored in this repository.

## Function evidence

The static index records `0x00010730` as a 1,660-byte, 415-instruction
function. Its normalized full-function SHA-1 is
`6206bab0ea05665a981395fb85767e6f2e194d52`, and its normalized prefix SHA-1 is
`763b15a095aa30a30836ecf94ff85c204ec8bd2b`. Ghidra retains the neutral name
`FUN_00010730`.

The local direct-call index has one incoming edge to this function: the NPEA
startup coordinator at `0x00010360` calls it at `0x000104ec`. The reviewed
coordinator record scopes its relationship to GT5 `0x00010338` to a probable,
pending startup role; it does not establish identity for this downstream
function. Inside `0x00010730`, the index records 63 direct-call sites to 33
local targets. Targeted decompilations of nearby helpers `0x00010660`,
`0x00010690`, and `0x000106f0` also completed, but their address-only bodies do
not supply an independent semantic signal.

The decompilation shows multiple conditional paths, repeated helper calls, an
error path, and a later loop. These observations do not identify a subsystem
or a stable semantic name. The build index has no retained source-file strings,
and the generated cross-build candidate table contains no pair for
`0x00010730`.

## Review result

Keep `0x00010730` unnamed beyond Ghidra's address-based label. Do not transfer a
GT5 name or claim a cross-build function match. Follow-up work can trace the
remaining callees and compare the startup continuation once stronger
independent evidence is available.
