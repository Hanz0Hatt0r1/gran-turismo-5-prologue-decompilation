# Development setup

Keep all local game material outside the repository.

## Recommended layout

```text
workspace/
├─ gran-turismo-5-prologue-decompilation/
└─ local-research/
   ├─ dumps/
   ├─ extracted/
   ├─ tool-projects/
   └─ private-notes/
```

## Typical tools

- Python 3;
- a PS3-capable ELF/disassembler/decompiler;
- Ghidra for local annotation/decompilation;
- hex/binary inspection tools;
- debugger or emulator-based observation environment where lawful;
- Git.

## M1 executable-intelligence workflow

The repository accepts a **user-provided decrypted ELF locally**. Do not add the executable, keys, firmware, SDK files, or generated proprietary asset data to Git.

Index one build:

```bash
python3 tools/gtdecomp.py index /path/to/EBOOT.ELF -o output/gt5p-build
```

Compare two local builds:

```bash
python3 tools/gtdecomp.py compare /path/to/reference.ELF /path/to/target.ELF -o output/compare
```

If a matching Ghidra installation is available:

```bash
python3 tools/gtdecomp.py decompile /path/to/EBOOT.ELF \
  --ghidra /path/to/ghidra \
  -o output/decompile
```

The default headless workflow is evidence-first: review the index before exporting broad pseudocode. See [Decompilation tooling](tooling.md) and the Manjaro/Arch wrapper under `tools/manjaro/`.

## Clone

```bash
git clone https://github.com/Hanz0Hatt0r1/gran-turismo-5-prologue-decompilation.git
cd gran-turismo-5-prologue-decompilation
```

## First contribution

1. Select or create a focused issue.
2. Identify the exact build/module.
3. Run the smallest reproducible analysis that can answer the question.
4. Promote only reviewed derived metadata into `analysis/`.
5. Include evidence and confidence.
6. Add/update tests when changing tooling.
7. Open a pull request linking the issue.