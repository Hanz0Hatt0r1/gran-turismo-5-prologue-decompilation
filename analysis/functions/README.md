# Function research

This directory contains reviewed function-level findings. It is not a dump of decompiler output.

## Function lifecycle

discovered -> indexed -> evidence reviewed -> named/classified -> reconstructed -> tested

The M1 indexer produces machine-generated candidates and normalized fingerprints. Those outputs become research artifacts only after review.

## Required function note fields

A reviewed note should identify build and module, virtual address, current and candidate names, confidence, evidence, callers/callees, relevant globals/structures, cross-build matches, and unresolved questions.

Prefer one note per function family when individual functions are tightly coupled.

## Naming

Start conservatively with `sub_<address>`. Promote to semantic names only when evidence supports the change. Keep previous names/aliases when useful for traceability.
