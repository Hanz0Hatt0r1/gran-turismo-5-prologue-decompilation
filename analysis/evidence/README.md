# Evidence

Evidence notes explain why a function, structure, relationship, or subsystem classification is believed to be true.

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
