# GT5 Prologue local input identity audit

**Result:** the local input at `local-research/bcus-98158/EBOOT.ELF` is the
indexed GT5 BCUS-98114 ELF, not the BCUS-98158 EBOOT recorded by this project.
It was not used as GT5 Prologue or cross-build evidence.

## Verification

The read-only `gtdecomp.py index` run reported SHA-256
`bbbc31048dd608f8e959d9a84205b9fd7001b480b707af08c9d1f8c0816672bc`, entry
descriptor `0x017f8150`, entry code `0x00010230`, and TOC `0x01846af0`. Its
descriptor, discovered-function, candidate, vtable, import, TOC-reference,
and function-hint counts match the checked-in GT5 BCUS-98114 baseline profile.

`gtverify.py verify` independently confirmed all four checks against
`analysis/builds/gt5-bcus98114.json`. Verification against
`analysis/builds/gt5p-bcus98158.json` failed on the SHA-256, entry descriptor,
and TOC. The code-entry value happens to match and does not override those
identity conflicts.

The checked-in BCUS-98158 profile identifies a different EBOOT.BIN SELF
container: SHA-256 `f58e36b3cb371e357ae0f3a019fb339c653682bc7ff6423abf3c2c7db50eef2a`,
entry descriptor `0x000717d8`, and TOC `0x0007d110`. No binary bytes or index
outputs are included in this report.

## Reproduction

With a legally obtained local executable at the ignored path used for this
audit:

```sh
python3 tools/gtdecomp.py index \
  local-research/bcus-98158/EBOOT.ELF -o /path/on/tmpfs/gt5p-input-audit

python3 tools/gtverify.py verify \
  --elf local-research/bcus-98158/EBOOT.ELF \
  --build-record analysis/builds/gt5-bcus98114.json

python3 tools/gtverify.py verify \
  --elf local-research/bcus-98158/EBOOT.ELF \
  --build-record analysis/builds/gt5p-bcus98158.json
```

Use a temporary filesystem for generated indexes when the host's persistent
disk quota is limited. Keep the local binary and generated indexes out of Git.
Obtain/identify a BCUS-98158 input that verifies against the checked-in target
profile before resuming GT5-to-GT5 Prologue fingerprint comparison.
