#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEST_DIR="${GT5P_UPSTREAM_DIR:-$ROOT_DIR/third_party/upstream}"

mkdir -p "$DEST_DIR"

fetch_repo() {
    local name="$1"
    local url="$2"
    local sha="$3"
    local dir="$DEST_DIR/$name"

    printf '\n==> %s\n' "$name"

    if [[ ! -d "$dir/.git" ]]; then
        git clone --filter=blob:none --no-checkout "$url" "$dir"
    fi

    git -C "$dir" remote set-url origin "$url"
    git -C "$dir" fetch --depth 1 origin "$sha"
    git -C "$dir" checkout --detach "$sha"

    printf 'Pinned %s at %s\n' "$name" "$sha"
}

# MIT-licensed upstream projects useful for GT5/GT5 Prologue research.
fetch_repo "GTToolsSharp"   "https://github.com/Nenkai/GTToolsSharp.git"   "a59e6f17e8bf455bdaab84b88b3d02de3a593fc1"

fetch_repo "GTAdhocToolchain"   "https://github.com/Nenkai/GTAdhocToolchain.git"   "3fecc2ed58e5d46135b2f94d2ce5d3fa8fb7dba0"

fetch_repo "PDTools"   "https://github.com/Nenkai/PDTools.git"   "ffe0bb26377ac9ff62f40951c1c0b16c5d9a380f"

fetch_repo "GTSpecDB"   "https://github.com/Nenkai/GTSpecDB.git"   "691e49fa6b85773bd4e8bc47e361c0a1cd6716a0"

fetch_repo "TXS3Converter"   "https://github.com/Nenkai/TXS3Converter.git"   "d007f92b5fc761f2598932dd1aef46d2d19a7103"

fetch_repo "GT-File-Specifications-Documentation"   "https://github.com/Nenkai/GT-File-Specifications-Documentation.git"   "05e52347890541758222d173dbb62d2b40581b19"

fetch_repo "ps3recomp"   "https://github.com/sp00nznet/ps3recomp.git"   "a679051ef304555291de2eb3ec8a3dbf64a761a8"

cat <<EOF

Upstream research tooling is available under:
  $DEST_DIR

These checkouts are intentionally ignored by this repository.
Keep each upstream LICENSE/notice intact. Do not copy code from
reference-only projects with missing or unclear licenses into src/.
EOF
