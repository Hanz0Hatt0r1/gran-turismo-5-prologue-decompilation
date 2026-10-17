#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "usage: $0 /path/to/decrypted/EBOOT.ELF [output-dir]" >&2
  exit 2
fi

ELF="$(realpath "$1")"
OUT="${2:-analysis/generated/eboot}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ ! -f "$ELF" ]]; then
  echo "error: ELF not found: $ELF" >&2
  exit 1
fi

if [[ "$(dd if="$ELF" bs=1 count=4 status=none | od -An -tx1 | tr -d ' \n')" != "7f454c46" ]]; then
  echo "error: input is not a plain ELF. Retail EBOOT.BIN must be decrypted first." >&2
  exit 1
fi

mkdir -p "$ROOT/$OUT"
sha256sum "$ELF" | tee "$ROOT/$OUT/EBOOT.ELF.sha256"
readelf -h -l -S "$ELF" > "$ROOT/$OUT/readelf.txt"

PS3RECOMP="${PS3RECOMP_DIR:-$ROOT/third_party/upstream/ps3recomp}"
if [[ -f "$PS3RECOMP/tools/ppu_loader.py" ]]; then
  python3 "$PS3RECOMP/tools/ppu_loader.py" "$ELF" -o "$ROOT/$OUT/loader"
  if [[ -f "$PS3RECOMP/tools/gen_imports.py" ]]; then
    python3 "$PS3RECOMP/tools/gen_imports.py" "$ELF" -o "$ROOT/$OUT/imports_named.json" || true
  fi
else
  cat >&2 <<EOF
ps3recomp not found at:
  $PS3RECOMP

Clone it there or set PS3RECOMP_DIR. The readelf baseline was still generated.
EOF
fi

echo "analysis written to $ROOT/$OUT"
