# Decrypted EBOOT analysis pipeline

The supplied retail `EBOOT.BIN` is a real encrypted PS3 SELF (Certified File attribute/key revision `0x0001`), not an unencrypted debug fSELF. Its main executable segment cannot be disassembled until it is decrypted.

## Confirmed SELF metadata

- Certified File version: `2`
- Key revision / attribute: `0x0001`
- Category: `SELF` (`1`)
- Extended-header size / metadata offset: `0x410`
- Encapsulated data offset: `0x980`
- Encapsulated data size: `0x66A18`
- Program authority/auth ID: `0x1010000001000003` (retail game/update class)
- Vendor ID: `0x01000002`
- Program type: `4` (application)
- Program version: `0x0001000000000000`
- ELF SHA-1 recorded by the SELF supplemental digest header: `d51bd5405398037bad96bc19821d1834a1ca8367`

The segment-extended table begins at `0x290`. Its first entry maps encrypted/compressed SELF data at `0x980` to the principal ELF LOAD segment; this is why simply cutting the SELF header off does not reconstruct executable code.

## Getting the analysis input

Use a decrypted ELF produced from your own game/console environment. Two common legitimate routes are:

1. let RPCS3 load your legally dumped title and use its decrypted executable output/cache;
2. use a SELF decryption tool with keys obtained from your own PS3/firmware environment.

Do not commit the decrypted executable or keys to this repository.

## Automated analysis

With a decrypted ELF:

```bash
bash tools/analyze_decrypted_eboot.sh /path/to/EBOOT.ELF
```

The script verifies ELF magic, records a SHA-256 identity, dumps ELF headers/segments/sections, and—when `ps3recomp` is available—runs its PPU loader to recover OPD-based function boundaries, TOC information and firmware imports.

Generated analysis belongs under `analysis/generated/` and should be reviewed before committing. Proprietary executable bytes must remain local.

## Planned decompilation stages

After the ELF is available, the first pass is deterministic:

1. identify PT_LOAD mappings and the `.opd` range;
2. recover address-taken PPU functions from OPD descriptors;
3. resolve import stubs and NIDs;
4. establish module TOC and entry descriptor;
5. augment function discovery with direct branch targets/prologue analysis;
6. rank functions by call-graph centrality and imported subsystem use;
7. document functions in `analysis/functions/`;
8. reconstruct behavior as independently authored source under `src/`.

The initial target is startup/CRT and subsystem initialization, then filesystem/resource loading, GCM/RSX setup, and game-specific orchestration.
