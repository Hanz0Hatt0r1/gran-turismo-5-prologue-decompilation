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

`gt5p-npea00050.json` records a separate UK-marked raw ELF whose embedded
`NPTitleID` is `EP9001-NPEA00050_00`. Its exact ELF SHA and entry metadata are
locally verifiable; it remains a comparison build and does not replace the
canonical US BCUS-98158 target.

## Review rule

Do not create a build record from an unverified binary. Record enough identifying metadata to determine whether two local inputs are the same build.
