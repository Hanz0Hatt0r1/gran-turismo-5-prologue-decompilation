#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  tools/manjaro/run_gt5_headless.sh /path/to/EBOOT.ELF [output-dir]

Environment variables:
  GHIDRA_HOME       Ghidra install directory, or path to analyzeHeadless
  GTDECOMP_SCOPE    hinted (default) or all
  GTDECOMP_LIMIT    max functions to decompile, 0 = unlimited (default)
  GTDECOMP_TIMEOUT  timeout per function in seconds (default: 60)
  GTDECOMP_NID_DB   optional text/JSON PS3 NID database

Examples:
  GHIDRA_HOME=$HOME/ghidra_12.1.2_PUBLIC \
    tools/manjaro/run_gt5_headless.sh ~/games/GT5/EBOOT.ELF

  GTDECOMP_SCOPE=all GTDECOMP_LIMIT=100 \
    tools/manjaro/run_gt5_headless.sh ./EBOOT.ELF ./out/gt5-test
EOF
}

if [[ ${1:-} == "-h" || ${1:-} == "--help" || $# -lt 1 ]]; then
  usage
  [[ $# -ge 1 ]] && exit 0 || exit 2
fi

ELF=$(realpath "$1")
if [[ ! -f "$ELF" ]]; then
  echo "error: ELF not found: $ELF" >&2
  exit 2
fi

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd -- "$SCRIPT_DIR/../.." && pwd)
OUT=${2:-"$REPO_ROOT/output/gt5-$(date +%Y%m%d-%H%M%S)"}
mkdir -p "$OUT"
OUT=$(realpath "$OUT")

if ! command -v python3 >/dev/null 2>&1; then
  echo "error: python3 is required (Manjaro: sudo pacman -S python)" >&2
  exit 2
fi
if ! command -v java >/dev/null 2>&1; then
  echo "error: Java is required by Ghidra. For Ghidra 12.x on Manjaro, install a supported JDK, e.g. jdk21-openjdk." >&2
  exit 2
fi

find_headless() {
  local c
  if [[ -n ${GHIDRA_HOME:-} ]]; then
    for c in "$GHIDRA_HOME" "$GHIDRA_HOME/support/analyzeHeadless"; do
      [[ -x "$c" ]] && { printf '%s\n' "$c"; return 0; }
    done
  fi
  if command -v analyzeHeadless >/dev/null 2>&1; then
    command -v analyzeHeadless
    return 0
  fi
  shopt -s nullglob
  for c in \
    /opt/ghidra/support/analyzeHeadless \
    /opt/ghidra*/support/analyzeHeadless \
    /usr/share/ghidra/support/analyzeHeadless \
    "$HOME"/ghidra*/support/analyzeHeadless \
    "$HOME"/opt/ghidra*/support/analyzeHeadless; do
    [[ -x "$c" ]] && { printf '%s\n' "$c"; return 0; }
  done
  return 1
}

ANALYZE_HEADLESS=$(find_headless || true)
if [[ -z "$ANALYZE_HEADLESS" ]]; then
  cat >&2 <<'EOF'
error: analyzeHeadless was not found.
Set GHIDRA_HOME to your Ghidra directory, for example:
  export GHIDRA_HOME="$HOME/ghidra_12.1.2_PUBLIC"
EOF
  exit 2
fi

SCOPE=${GTDECOMP_SCOPE:-hinted}
LIMIT=${GTDECOMP_LIMIT:-0}
TIMEOUT=${GTDECOMP_TIMEOUT:-60}
NID_ARGS=()
if [[ -n ${GTDECOMP_NID_DB:-} ]]; then
  NID_ARGS=(--nid-db "$(realpath "$GTDECOMP_NID_DB")")
fi

cat <<EOF
GT decompilation headless run
  ELF:              $ELF
  output:           $OUT
  analyzeHeadless:  $ANALYZE_HEADLESS
  scope:            $SCOPE
  limit:            $LIMIT
  timeout/function: ${TIMEOUT}s
EOF

set -o pipefail
python3 "$REPO_ROOT/tools/gtdecomp.py" decompile "$ELF" \
  --ghidra "$ANALYZE_HEADLESS" \
  --out "$OUT" \
  --timeout "$TIMEOUT" \
  --scope "$SCOPE" \
  --limit "$LIMIT" \
  "${NID_ARGS[@]}" 2>&1 | tee "$OUT/run.log"

REPORT="$OUT/report-for-chat.tar.zst"
if command -v zstd >/dev/null 2>&1; then
  tar --zstd -cf "$REPORT" -C "$OUT" \
    index/manifest.json \
    index/function_hints.csv \
    index/imports.csv \
    decompiled/decompilation_manifest.csv \
    decompile-summary.json \
    run.log 2>/dev/null || true
fi

cat <<EOF

Finished.
Useful files:
  $OUT/decompile-summary.json
  $OUT/decompiled/decompilation_manifest.csv
  $OUT/run.log
EOF
if [[ -f "$REPORT" ]]; then
  echo "  $REPORT  <- upload this back to ChatGPT first"
fi