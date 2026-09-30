# Research methodology

## Evidence levels

- **Confirmed** — observed directly and reproduced consistently.
- **Probable** — strongly supported by call relationships, data flow, constants, or runtime behavior.
- **Speculative** — a working hypothesis that guides further investigation.

## Function naming

Use conservative names and improve them as evidence accumulates.

```text
sub_00123456
candidate_vehicle_state_update
vehicle_state_update
```

## Addresses and builds

Addresses are only meaningful with build context. Include build/region/update whenever recording absolute addresses.

| Address/offset | Proposed name | Confidence | Evidence |
| --- | --- | --- | --- |
| ... | ... | ... | ... |

## Verification

Where practical, validate conclusions with at least two independent signals:

- callers/callees;
- referenced strings/constants;
- data structures;
- runtime observations;
- neighboring functions;
- cross-build comparison.

Decompiler output is evidence, not finished source. Convert findings into independently written notes and reconstructed code.
