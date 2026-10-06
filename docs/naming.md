# Semantic naming conventions

Names in the research catalog distinguish structural identity from semantic interpretation.

## Function records

Function IDs are build/module/address scoped:

    <build>.<module>.<va>

For example:

    gt5.bcus98114.eboot.00010230
    gt5p.bcus98158.eboot.00010368

`name.current` is the single working label used by tools and notes. It must be
supported by the record's evidence and confidence. `name.candidates` contains
alternative hypotheses that are not yet selected.

Avoid decompiler-generated names such as FUN_XXXXXXXX as semantic names.

When semantics remain unresolved, prefer an explicit role plus address, for example:

    crt_runtime_bootstrap_10368
    game_bootstrap_106e0
    startup_application_loader_10970

Such names are still hypotheses unless their confidence/status says otherwise.

## Platform imports

Platform API names are separate from game-function names. Record the raw import
library and NID even when an external NID database resolves a human-readable name.

The imported API name must never be copied onto the game function that calls it.

## Build-qualified references

Every address must be interpreted together with its build and module. Cross-build
records keep reference and target identities separately and do not rename the target
until the relationship itself is reviewed.

## Cross-build promotion

A cross-build relationship starts as candidate or pending. An accepted
relationship requires an explicit relationship.identity_scope and
confidence: confirmed.

An accepted role-level relationship does not imply source-level identity or permit
code transfer. The accepted scope must say what is actually being equated.

## Confidence versus status

Use confidence for evidentiary strength:

- confirmed: directly observed and independently reproducible.
- probable: multiple independent signals support the interpretation.
- speculative: a working hypothesis.

Use status for lifecycle state:

- analyzed: examined and recorded.
- review-required: needs additional review before promotion.
- reviewed: evidence reviewed and retained.
- accepted: reserved for accepted cross-build relationships or equivalent reviewed promotion state.

Confidence and status are intentionally orthogonal.