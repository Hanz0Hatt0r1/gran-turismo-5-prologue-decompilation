# Tools

## `gtdecomp.py`

`gtdecomp.py` is the build-agnostic PS3 PPU analysis pipeline used by this
project. It consumes **user-provided decrypted ELF files locally** and writes
only derived metadata. Game executables, keys, firmware, SDK files, and assets
must not be committed.

### Index a build

```bash
python3 tools/gtdecomp.py index /path/to/EBOOT.ELF -o output/gt5-bcus98114
```

The index contains:

- `manifest.json` — build identity, hashes, entry descriptor, TOC and counts;
- `opd.csv` — recovered PPU function descriptors;
- `functions.csv` — normalized PowerPC function fingerprints;
- `rtti.csv` — Itanium-style C++ RTTI candidates;
- `vtables.csv` — virtual-table candidates linked to function descriptors;
- `source_files.csv` — source-file strings retained in the executable;
- `string_refs.csv` — recovered PPU TOC loads that point at retained strings;
- `function_hints.csv` — per-function source/vtable evidence;
- `imports.csv` — PS3 import libraries, NIDs, import slots, and stub addresses.

The current parser targets PS3 `ELF64`, big-endian, `PowerPC64` executables and
Sony's compact 8-byte PPU function descriptors.

### Compare two builds

```bash
python3 tools/gtdecomp.py compare \
  /path/to/reference/EBOOT.ELF \
  /path/to/target/EBOOT.ELF \
  -o output/gt5-vs-gt5p
```

The matcher normalizes direct branch displacements and common TOC-relative
loads/stores before hashing. Unique whole-function matches are preferred;
unique normalized-prefix matches are used as a lower-confidence fallback.
This is intended to transfer research labels between GT5 retail, GT5 Prologue,
and updates without assuming that absolute addresses are stable.

### Decompile a build with Ghidra

With a local Ghidra installation, one command performs the metadata index,
headless analysis, annotations, and local pseudocode export:

```bash
python3 tools/gtdecomp.py decompile /path/to/EBOOT.ELF \
  --ghidra /path/to/ghidra_12.1.2_PUBLIC \
  -o output/gt5-bcus98114-decompile
```

The decompiler output is written below `output/.../decompiled/functions/` with
a `decompilation_manifest.csv` that records the stable normalized function ID,
Ghidra name, source/vtable evidence, status, and output path. The generated
pseudocode is local reverse-engineering material and is intentionally ignored
by Git.

### Tests

```bash
python3 -m unittest tests/test_gtdecomp.py
```

Tests use synthetic ELF data only.


### Apply the index in Ghidra

Open the same ELF in Ghidra, add `tools/ghidra/` to the Script Manager search
path, and run `apply_gtdecomp_index.py`. Select the index directory generated
by `gtdecomp.py`. The script materializes OPD-discovered functions, adds fingerprint/source/vtable
evidence, and annotates imports/RTTI/vtables. `export_decompilation.py` exports
the local Ghidra pseudocode and manifest. Both scripts accept command-line
arguments when invoked through `analyzeHeadless` and fall back to file choosers
in the GUI.