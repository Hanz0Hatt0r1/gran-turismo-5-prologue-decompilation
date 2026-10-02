# Manjaro / Arch headless workflow

The preferred local workflow is to let Ghidra run on the user's machine and keep all proprietary executables and decompiler output local.

## Requirements

- Python 3
- Ghidra with `support/analyzeHeadless`
- a Java version supported by that Ghidra release
- optional: `zstd` for a small report bundle

On Manjaro, the common packages are:

```bash
sudo pacman -S python jdk21-openjdk zstd
```

If Ghidra is already working in the GUI, do not change Java just for this project.

## First GT5 pass

```bash
git checkout feature/gt5-multibuild-pipeline
export GHIDRA_HOME="$HOME/ghidra_12.1.2_PUBLIC"
tools/manjaro/run_gt5_headless.sh /path/to/GT5/EBOOT.ELF
```

The default scope is `hinted`, which decompiles only functions for which the static index has source-file and/or vtable evidence. This is a much better first pass than sending every discovered function through the decompiler.

For a smoke test:

```bash
GTDECOMP_LIMIT=25 tools/manjaro/run_gt5_headless.sh /path/to/EBOOT.ELF ./output/smoke
```

For a complete export later:

```bash
GTDECOMP_SCOPE=all tools/manjaro/run_gt5_headless.sh /path/to/EBOOT.ELF ./output/gt5-all
```

After a run, send back `report-for-chat.tar.zst` first. If individual pseudocode bodies are needed, package selected files from `decompiled/functions/` separately.