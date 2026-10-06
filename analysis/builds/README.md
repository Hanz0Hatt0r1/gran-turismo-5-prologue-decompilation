# Build registry

Each file in this directory describes one known executable build using derived metadata only.

## Naming

Use `<game>-<title-id>.json`. For updates or multiple executable variants, extend the name with a short version/update identifier.

## Minimum metadata

Every build record should contain game, title ID, role, executable SHA-256, executable format, known entry point/TOC metadata, and provenance notes.

## Current reference

`gt5-bcus98114.json` is the first reference profile produced by the M1 executable-intelligence pipeline.

## GT5 Prologue target

The next canonical target is **BCUS-98158**. Its local executable is intentionally outside Git; only fingerprints and reviewed derived metadata belong here.

## Review rule

Do not create a build record from an unverified binary. Record enough identifying metadata to determine whether two local inputs are the same build.
