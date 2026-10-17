# Cross-build research

Cross-build analysis is a first-class layer. Builds remain independent; only reviewed relationships are shared.

## Initial build pair

- **GT5 BCUS-98114** — reference build.
- **GT5 Prologue BCUS-98158** — target build.

The purpose of the pair is to use structurally stable code, imports, RTTI/vtables, strings, and call-graph context from the reference build to accelerate analysis of the Prologue executable without treating the builds as identical.

## Additional local Prologue input

The user-supplied UK-marked `NPEA-00050` raw ELF is tracked as a separate
comparison build. Its identity audit and fingerprint candidates are recorded in
[`analysis/evidence/gt5p-npea00050-identity-audit-20261017.md`](../evidence/gt5p-npea00050-identity-audit-20261017.md).
It does not replace the canonical US BCUS-98158 target. The accepted GT5 to
NPEA relation covers only the ELFv1 entry role. Separate probable/pending
cross-reference records cover one startup-coordinator role, six function-body
relationships, and one shared-prefix call-graph role; none asserts semantic or source-level
function identity. The generated function matches remain candidate/speculative,
with 111 of 127 still unreviewed. The reviewed pairs are documented in [the candidate-review
note](../evidence/gt5p-npea00050-function-candidate-review-20261017.md) and [the
startup comparison](../evidence/gt5p-npea00050-gt5-startup-coordinator-review-20261017.md),
as well as the [helper-body review](../evidence/gt5p-npea00050-helper-00d1a534-review-20261017.md).
The new [prefix-role cross-reference](gt5-bcus98114-vs-gt5p-npea00050-prefix-00d19ca0.yaml)
remains probable/pending, with complete function identity unresolved.
The exact-body [cross-reference for `0x00d1a96c`](gt5-bcus98114-vs-gt5p-npea00050-function-00d1a96c.yaml)
is also probable/pending and transfers no semantic label.
The startup-cluster [cross-reference for `0x00bb6dbc`](gt5-bcus98114-vs-gt5p-npea00050-function-00bb6dbc.yaml)
is probable/pending, scoped to its exact function body and call relationships.
The adjacent startup-cluster [cross-reference for `0x00bb6e0c`](gt5-bcus98114-vs-gt5p-npea00050-function-00bb6e0c.yaml)
is probable/pending, scoped to its exact function body and aligned callee edge.
The central [cross-reference for `0x00bb6d74`](gt5-bcus98114-vs-gt5p-npea00050-function-00bb6d74.yaml)
is probable/pending, scoped to its exact function body and two aligned caller pairs.

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
