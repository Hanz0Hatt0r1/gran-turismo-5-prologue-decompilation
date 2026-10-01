#!/usr/bin/env python3
"""Inspect safe structural metadata from a PS3 SCE/SELF or decrypted PPC64 ELF."""

from __future__ import annotations

import argparse
import hashlib
import math
import struct
from pathlib import Path


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts if c)


def parse_elf(data: bytes, offset: int) -> None:
    hdr = data[offset : offset + 64]
    if len(hdr) < 64 or hdr[:4] != b"\x7fELF":
        raise ValueError("ELF header not found at requested offset")

    endian = ">" if hdr[5] == 2 else "<"
    fields = struct.unpack(endian + "16sHHIQQQIHHHHHH", hdr)
    (
        _ident,
        e_type,
        e_machine,
        _version,
        entry,
        phoff,
        shoff,
        _flags,
        ehsize,
        phentsize,
        phnum,
        shentsize,
        shnum,
        shstrndx,
    ) = fields

    print(f"ELF offset:      0x{offset:X}")
    print(f"ELF class:       {hdr[4]}")
    print(f"ELF data:        {'big-endian' if hdr[5] == 2 else 'little-endian'}")
    print(f"ELF type:        0x{e_type:X}")
    print(f"ELF machine:     0x{e_machine:X}")
    print(f"Entry point:     0x{entry:X}")
    print(f"Program headers: {phnum} @ 0x{phoff:X}, entsize 0x{phentsize:X}")
    print(f"Section headers: {shnum} @ 0x{shoff:X}, entsize 0x{shentsize:X}")
    print(f"SH string index: {shstrndx}")
    print(f"ELF hdr size:    0x{ehsize:X}")

    table = offset + phoff
    for i in range(phnum):
        start = table + i * phentsize
        raw = data[start : start + 56]
        if len(raw) < 56:
            break
        p = struct.unpack(endian + "IIQQQQQQ", raw)
        print(
            f"PH[{i}]: type=0x{p[0]:X} flags=0x{p[1]:X} "
            f"off=0x{p[2]:X} vaddr=0x{p[3]:X} filesz=0x{p[5]:X} "
            f"memsz=0x{p[6]:X} align=0x{p[7]:X}"
        )


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("file", type=Path)
    args = ap.parse_args()

    data = args.file.read_bytes()
    print(f"File:            {args.file}")
    print(f"Size:            {len(data)} (0x{len(data):X})")
    print(f"SHA-256:         {hashlib.sha256(data).hexdigest()}")
    print(f"Magic:           {data[:4]!r}")

    elf_off = data.find(b"\x7fELF")
    if elf_off >= 0:
        parse_elf(data, elf_off)
    else:
        print("Embedded ELF:    not found")

    block = 0x10000
    print("Entropy:")
    for off in range(0, len(data), block):
        chunk = data[off : off + block]
        print(f"  0x{off:06X}-0x{off + len(chunk):06X}: {entropy(chunk):.4f} bits/byte")


if __name__ == "__main__":
    main()
