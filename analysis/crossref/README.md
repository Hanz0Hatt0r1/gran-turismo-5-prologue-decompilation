# Cross-build research

Cross-build analysis is a first-class layer. Builds remain independent; only reviewed relationships are shared.

## Initial build pair

- **GT5 BCUS-98114** — reference build.
- **GT5 Prologue BCUS-98158** — target build.

The purpose of the pair is to use structurally stable code, imports, RTTI/vtables, strings, and call-graph context from the reference build to accelerate analysis of the Prologue executable without treating the builds as identical.

## Match lifecycle

`generated -> candidate -> evidence reviewed -> accepted`

Accepted matches must preserve the reference and target build/module/address, matching method, confidence, independent evidence, and review status. Addresses are never copied between builds and semantic names are never transferred automatically.

## Allowed matching methods

- `normalized-full`
- `normalized-prefix`
- `manual`
- `callgraph`
- `rtti-vtable`
- `import-context`

See [the analysis schema](../schema.md) for the canonical cross-build record.

## Evidence ranking

Generated matches are ranked only after a fingerprint match exists. The report combines the fingerprint method with callgraph, import/NID, and RTTI/vtable context.

- `evidence_score`: deterministic 0–100 ranking score.
- `evidence_confidence`: `probable` for scores at or above 75, otherwise `speculative`.
- `evidence_reasons`: compact trace of which evidence layers contributed.
- `review_status`: generated rows remain `candidate`.

A high ranking is not an acceptance decision. `confirmed` remains reserved for independently reviewed evidence, and secondary context never creates a cross-build match on its own.

## Schema validation

Cross-build records are schema-validated in CI. Both reference and target build/module/address identities, the comparison method, confidence, and explicit review status are required. Validation is structural and does not accept matches automatically. Accepted cross-build records additionally require confirmed confidence and an explicit identity scope.
