# GT5 Prologue local input identity audit

**Result:** the local input at `local-research/bcus-98158/EBOOT.ELF` has the
same SHA-256 and index counts as the GT5 BCUS-98114 ELF profile. Its entry
descriptor and TOC also differ from the BCUS-98158 profile, so it was not used
as GT5 Prologue or cross-build evidence.

## Verification

The read-only `gtdecomp.py index` run reported SHA-256
`bbbc31048dd608f8e959d9a84205b9fd7001b480b707af08c9d1f8c0816672bc`, entry
descriptor `0x017f8150`, entry code `0x00010230`, and TOC `0x01846af0`. Its
descriptor, discovered-function, candidate, vtable, import, TOC-reference,
and function-hint counts match the checked-in GT5 BCUS-98114 baseline profile.

`gtverify.py verify` independently confirmed all four checks against
`analysis/builds/gt5-bcus98114.json`. The earlier GT5 Prologue verification
also reported a SHA-256 mismatch, but that check compared different scopes:
the supplied file is a raw ELF while the BCUS-98158 profile hash identifies
the outer SELF container. That mismatch is not evidence. The ELF entry
descriptor and TOC do differ from the BCUS-98158 profile; the code-entry
value happens to match and does not override those identity conflicts.

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
  --container /path/to/candidate/BCUS-98158/EBOOT.BIN \
  --build-record analysis/builds/gt5p-bcus98158.json
```

The container digest and ELF entry metadata are checked independently; this
does not prove that the ELF was extracted from the supplied container. No
BCUS-98158 container was verified in this audit.

Use a temporary filesystem for generated indexes when the host's persistent
disk quota is limited. Keep the local binary and generated indexes out of Git.
Obtain/identify a BCUS-98158 input that verifies against the checked-in target
profile before resuming GT5-to-GT5 Prologue fingerprint comparison.
