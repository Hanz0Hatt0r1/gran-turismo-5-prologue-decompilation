#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'EOF'
Usage:
  tools/decrypt_self.sh [options] <EBOOT.BIN> [output.elf]

Options:
  --scetool PATH     Path to scetool executable (default: scetool from PATH)
  --keys-dir DIR     Local scetool key-data root. Exported as PS3=DIR.
                     DIR should contain scetool's data/keys setup.
  --force            Overwrite an existing output file.
  -h, --help         Show this help.

Examples:
  tools/decrypt_self.sh EBOOT.BIN EBOOT.ELF

  tools/decrypt_self.sh \
    --scetool "$HOME/tools/scetool/scetool" \
    --keys-dir "$HOME/.local/share/ps3keys" \
    EBOOT.BIN decrypted/EBOOT.ELF

The script does not contain or download console keys. It only invokes a local
scetool installation using key material already present on your machine.
EOF
}

SCETOOL="${SCETOOL:-scetool}"
KEYS_DIR=""
FORCE=0

while (($#)); do
    case "$1" in
        --scetool)
            [[ $# -ge 2 ]] || { echo "error: --scetool needs a path" >&2; exit 2; }
            SCETOOL="$2"
            shift 2
            ;;
        --keys-dir)
            [[ $# -ge 2 ]] || { echo "error: --keys-dir needs a directory" >&2; exit 2; }
            KEYS_DIR="$2"
            shift 2
            ;;
        --force)
            FORCE=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        --)
            shift
            break
            ;;
        -*)
            echo "error: unknown option: $1" >&2
            usage >&2
            exit 2
            ;;
        *)
            break
            ;;
    esac
done

[[ $# -ge 1 && $# -le 2 ]] || { usage >&2; exit 2; }

INPUT="$1"
OUTPUT="${2:-${INPUT%.*}.elf}"

[[ -f "$INPUT" ]] || { echo "error: input not found: $INPUT" >&2; exit 1; }

if [[ -e "$OUTPUT" && "$FORCE" -ne 1 ]]; then
    echo "error: output exists: $OUTPUT (use --force to replace)" >&2
    exit 1
fi

if [[ "$SCETOOL" == */* ]]; then
    [[ -x "$SCETOOL" ]] || { echo "error: scetool is not executable: $SCETOOL" >&2; exit 1; }
else
    command -v "$SCETOOL" >/dev/null 2>&1 || {
        echo "error: scetool was not found in PATH" >&2
        exit 1
    }
fi

if [[ -n "$KEYS_DIR" ]]; then
    [[ -d "$KEYS_DIR" ]] || { echo "error: key-data directory not found: $KEYS_DIR" >&2; exit 1; }
    export PS3="$KEYS_DIR"
fi

magic="$(od -An -tx1 -N4 "$INPUT" | tr -d ' \n')"
if [[ "$magic" != "53434500" ]]; then
    echo "error: $INPUT is not an SCE/SELF file (magic=$magic)" >&2
    exit 1
fi

mkdir -p "$(dirname "$OUTPUT")"

tmp="$(mktemp "$(dirname "$OUTPUT")/.decrypt-self.XXXXXX")"
trap 'rm -f "$tmp"' EXIT

echo "Input:"
sha256sum "$INPUT"

echo
echo "Decrypting SELF with scetool..."
"$SCETOOL" -d "$INPUT" "$tmp"

out_magic="$(od -An -tx1 -N4 "$tmp" | tr -d ' \n')"
if [[ "$out_magic" != "7f454c46" ]]; then
    echo "error: scetool returned a file that is not an ELF (magic=$out_magic)" >&2
    exit 1
fi

python3 - "$tmp" <<'PY'
import struct
import sys

path = sys.argv[1]
with open(path, "rb") as f:
    h = f.read(64)

if len(h) < 64 or h[:4] != b"\x7fELF":
    raise SystemExit("error: truncated/invalid ELF")

elf_class = h[4]
elf_data = h[5]
if elf_class != 2:
    raise SystemExit(f"error: expected ELF64, got EI_CLASS={elf_class}")
if elf_data != 2:
    raise SystemExit(f"error: expected big-endian ELF, got EI_DATA={elf_data}")

fields = struct.unpack(">16sHHIQQQIHHHHHH", h)
e_type = fields[1]
e_machine = fields[2]
entry = fields[4]
phnum = fields[10]
shnum = fields[12]

if e_machine != 0x15:
    raise SystemExit(f"error: expected EM_PPC64 (0x15), got 0x{e_machine:X}")

print("Validated decrypted ELF:")
print("  class:       ELF64")
print("  endian:      big")
print(f"  type:        0x{e_type:X}")
print(f"  machine:     EM_PPC64 (0x{e_machine:X})")
print(f"  entry:       0x{entry:X}")
print(f"  phnum:       {phnum}")
print(f"  shnum:       {shnum}")
PY

mv -f "$tmp" "$OUTPUT"
trap - EXIT

echo
echo "Output:"
sha256sum "$OUTPUT"
echo "Wrote: $OUTPUT"

if command -v file >/dev/null 2>&1; then
    file "$OUTPUT"
fi
