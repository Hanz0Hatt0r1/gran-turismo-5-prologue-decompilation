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
- `functions.csv` — OPD-backed normalized PowerPC function fingerprints;
- `function_candidates.csv` — function-start evidence from OPD, calls, prologues, and return boundaries;
- `discovered_functions.csv` — high-confidence discovered functions with normalized fingerprints;
- `rtti.csv` — Itanium-style C++ RTTI candidates;
- `vtables.csv` — virtual-table candidates linked to function descriptors;
- `source_files.csv` — source-file strings retained in the executable;
- `string_refs.csv` — recovered PPU TOC loads that point at retained strings;
- `function_hints.csv` — per-function source/vtable evidence;
- `imports.csv` — PS3 import libraries, NIDs, optional resolved names, import slots, and stub addresses.

The current parser targets PS3 `ELF64`, big-endian, `PowerPC64` executables and
Sony's compact 8-byte PPU function descriptors.

### Optional PS3 NID names

The exact NID remains the canonical import identity. Human-readable API names
can be supplied from a local external database without vendoring that database:

```bash
python3 tools/gtdecomp.py index /path/to/EBOOT.ELF \
  --nid-db /path/to/nids.txt \
  -o output/gt5-bcus98114
```

Accepted database formats are whitespace text (`0x12345678 symbol`), CSV with
`nid`/`name` columns, and simple JSON mappings/lists. When a name resolves, the
Ghidra annotator uses it for import labels such as `imp_cellFsOpen`; otherwise
it falls back to the library + raw NID. Third-party NID databases are not
stored in this repository.

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

### Reviewed symbol/address catalog

`gtcatalog.py` is the dependency-free validation and query layer for
repository-readable research metadata. It checks required identity fields,
validates build hashes/addresses, detects duplicate function addresses within
a build/module, searches declared or referenced addresses and names, and emits
compact catalog summaries.

```bash
python3 tools/gtcatalog.py validate analysis
python3 tools/gtcatalog.py search analysis --address 0x10230
python3 tools/gtcatalog.py search analysis --name eboot_entry
python3 tools/gtcatalog.py summary analysis
```

The YAML support intentionally covers the project's simple mapping records rather
than attempting to be a general YAML parser. JSON records are parsed structurally.
The validator operates only on metadata already present under `analysis/`; it
never reads or stores executable contents.

### Import an existing Ghidra C export

Older Ghidra projects can be folded into the same database without rerunning
analysis:

```bash
python3 tools/gtdecomp.py import-ghidra-c /path/to/EBOOT.ELF.c \
  --index output/gt5-bcus98114 \
  -o output/gt5-c-seed
```

The command splits `FUN_XXXXXXXX` / `thunk_FUN_XXXXXXXX` blocks, assigns the
normalized function ID when the address is in the discovered-function set, and
writes `ghidra_c_manifest.csv`. Generated pseudocode remains local output.

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
python3 -m unittest discover -s tests -v
```

Tests use synthetic data only and do not require a game executable.

### Apply the index in Ghidra

Open the same ELF in Ghidra, add `tools/ghidra/` to the Script Manager search
path, and run `apply_gtdecomp_index.py`. Select the index directory generated
by `gtdecomp.py`. The script materializes OPD-discovered functions, adds fingerprint/source/vtable
evidence, and annotates imports/RTTI/vtables. `export_decompilation.py` exports
the local Ghidra pseudocode and manifest. Both scripts accept command-line
arguments when invoked through `analyzeHeadless` and fall back to file choosers
in the GUI.

## Manjaro helper

For a one-command local Ghidra run on Manjaro/Arch:

```bash
export GHIDRA_HOME="$HOME/ghidra_12.1.2_PUBLIC"
tools/manjaro/run_gt5_headless.sh /path/to/EBOOT.ELF
```

See [`manjaro/README.md`](manjaro/README.md) for smoke-test and full-export modes.
