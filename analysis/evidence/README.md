# Evidence

Evidence notes explain why a function, structure, relationship, or subsystem classification is believed to be true.

## Current local-input audit

- [NPEA-00050 UK-marked Prologue ELF identity and first GT5 comparison](gt5p-npea00050-identity-audit-20261017.md) — exact input hash, local index, reviewed entry-role scope, and unreviewed fingerprint candidates.
- [GT5 to NPEA-00050 function-candidate review](gt5p-npea00050-function-candidate-review-20261017.md) — one wrapper pair inspected; helper behavior remains unverified and no match is promoted.
- [NPEA-00050 startup function](../functions/gt5p-npea00050-startup-10360.yaml) — Ghidra-reviewed `0x00010360` body and audited one-function portable P-code corpus.
- [GT5 to NPEA-00050 startup coordinator review](gt5p-npea00050-gt5-startup-coordinator-review-20261017.md) — manual role-level comparison; full function identity remains pending.
- [NPEA-00050 startup continuation](gt5p-npea00050-startup-continuation-10730-review-20261017.md) — targeted Ghidra export for `0x00010730`; reachable from the reviewed coordinator, with no semantic name or cross-build identity promoted.
- [GT5 to NPEA-00050 helper-body review](gt5p-npea00050-helper-00d1a534-review-20261017.md) — exact normalized body plus matched caller context; probable/pending function-body relationship without a semantic name.

## Minimum record

    schema: 1
    build: BCUS-98158
    module: EBOOT.BIN
    subject: gt5p.bcus98158.eboot.00106e0
    observation: "Function initializes filesystem sysmodule after game-data validation."
    evidence:
      - type: callgraph
        detail: "reachable from the runtime bootstrap"
      - type: import
        detail: "calls cellSysmoduleLoadModule"
    confidence: probable
    next_check: "Resolve TOC-backed globals and confirm all bootstrap callers."

## Evidence discipline

- distinguish observation from interpretation;
- cite the exact address/range where applicable;
- record build and module;
- prefer two independent signals for semantic conclusions;
- do not paste large decompiler listings;
- never include proprietary executable bytes or extracted copyrighted assets.
