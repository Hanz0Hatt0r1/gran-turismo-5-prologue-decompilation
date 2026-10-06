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
