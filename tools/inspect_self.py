#!/usr/bin/env python3
"""Inspect structural metadata from a PS3 SCE/SELF executable.

The tool does not decrypt SELF payloads.  For the known GT5 Prologue sample it
also labels the section-name offsets whose string-table layout has been
reconstructed from the section metadata and standard PS3 PPU section layout.
"""

from __future__ import annotations

import argparse
import hashlib
import math
import re
import struct
from collections import Counter
from pathlib import Path

KNOWN_GT5P_SHA256 = "f58e36b3cb371e357ae0f3a019fb339c653682bc7ff6423abf3c2c7db50eef2a"

PT_NAMES = {
    1: "PT_LOAD",
    7: "PT_TLS",
    0x60000001: "PT_PS3_PARAMS",
    0x60000002: "PT_PS3_PRX",
}

SELF_TYPES = {
    1: "LV0",
    2: "LV1",
    3: "LV2",
    4: "APP",
    5: "ISO",
    6: "LDR",
    7: "UNKNOWN_7",
    8: "NPDRM",
}

# This mapping is deliberately fingerprint-gated to the supplied EBOOT sample.
# The original .shstrtab bytes are encrypted, but every sh_name offset matches
# the standard PS3 PPU section string layout and the corresponding section
# types/flags/sizes.
GT5P_SECTION_NAMES = {
    0x01: ".shstrtab",
    0x0B: ".init",
    0x11: ".fini",
    0x17: ".sceStub.text",
    0x1F: ".text",
    0x25: ".eh_frame",
    0x2F: ".gcc_except_table",
    0x41: ".rodata.sceResident",
    0x55: ".rodata.sceFNID",
    0x65: ".lib.ent.top",
    0x72: ".lib.ent.btm",
    0x7F: ".lib.stub.top",
    0x8D: ".lib.stub",
    0x97: ".lib.stub.btm",
    0xA5: ".rodata",
    0xAD: ".sys_proc_param",
    0xBD: ".sys_proc_prx_param",
    0xD1: ".ctors",
    0xD8: ".dtors",
    0xDF: ".jcr",
    0xE4: ".data.rel.ro",
    0xF1: ".data.sceFStub",
    0x100: ".toc1",
    0x106: ".opd",
    0x10B: ".got",
    0x110: ".tbss",
    0x116: ".data",
    0x11C: ".bss",
    0x121: ".sceversion",
}


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((count / n) * math.log2(count / n) for count in counts.values())


def parse_self(path: Path) -> None:
    data = path.read_bytes()
    digest = hashlib.sha256(data).hexdigest()

    print(f"File:              {path}")
    print(f"Size:              {len(data)} (0x{len(data):X})")
    print(f"SHA-256:           {digest}")

    if data[:4] != b"SCE\0":
        raise SystemExit("Input is not an SCE/SELF container")

    (
        _magic,
        version,
        key_revision,
        header_type,
        metadata_offset,
        header_len,
        data_len,
    ) = struct.unpack_from(">IIHHIQQ", data, 0)

    print("\n[SCE]")
    print(f"Version:           {version}")
    print(f"Key revision:      0x{key_revision:04X}")
    print(f"Header type:       {header_type}")
    print(f"Metadata offset:   0x{metadata_offset:X}")
    print(f"Header length:     0x{header_len:X}")
    print(f"Data length:       0x{data_len:X}")

    selfh = struct.unpack_from(">10Q", data, 0x20)
    (
        self_header_type,
        app_info_offset,
        elf_offset,
        phdr_offset,
        shdr_offset,
        section_info_offset,
        sce_version_offset,
        control_info_offset,
        control_info_size,
        _padding,
    ) = selfh

    print("\n[SELF]")
    print(f"Header type:       0x{self_header_type:X}")
    print(f"App info:          0x{app_info_offset:X}")
    print(f"ELF header:        0x{elf_offset:X}")
    print(f"Program headers:   0x{phdr_offset:X}")
    print(f"Section headers:   0x{shdr_offset:X}")
    print(f"Section info:      0x{section_info_offset:X}")
    print(f"SCE version:       0x{sce_version_offset:X}")
    print(f"Control info:      0x{control_info_offset:X} (+0x{control_info_size:X})")

    auth_id, vendor_id, self_type, app_version, _ = struct.unpack_from(
        ">QIIQQ", data, app_info_offset
    )
    print("\n[Application]")
    print(f"Auth ID:           0x{auth_id:016X}")
    print(f"Vendor ID:         0x{vendor_id:08X}")
    print(f"SELF type:         {self_type} ({SELF_TYPES.get(self_type, '?')})")
    print(f"App version:       0x{app_version:016X}")

    ident = data[elf_offset : elf_offset + 16]
    if ident[:4] != b"\x7fELF":
        raise SystemExit("Embedded ELF header is missing")
    endian = ">" if ident[5] == 2 else "<"
    eh = struct.unpack_from(endian + "16sHHIQQQIHHHHHH", data, elf_offset)
    (
        _ident,
        e_type,
        e_machine,
        _e_version,
        e_entry,
        _e_phoff,
        _e_shoff,
        _e_flags,
        _e_ehsize,
        e_phentsize,
        e_phnum,
        e_shentsize,
        e_shnum,
        e_shstrndx,
    ) = eh

    print("\n[Embedded ELF]")
    print(f"Class:             ELF{ident[4] * 32}")
    print(f"Endianness:        {'big' if ident[5] == 2 else 'little'}")
    print(f"OS/ABI:            0x{ident[7]:02X}")
    print(f"Type:              0x{e_type:X}")
    print(f"Machine:           0x{e_machine:X}")
    print(f"Entry:             0x{e_entry:X}")
    print(f"Program headers:   {e_phnum}")
    print(f"Section headers:   {e_shnum}")
    print(f"SH string index:   {e_shstrndx}")

    phdrs = []
    print("\n[Program headers]")
    for i in range(e_phnum):
        off = phdr_offset + i * e_phentsize
        ph = struct.unpack_from(endian + "IIQQQQQQ", data, off)
        phdrs.append(ph)
        print(
            f"{i:02d} {PT_NAMES.get(ph[0], hex(ph[0])):<13} "
            f"flags=0x{ph[1]:X} elf_off=0x{ph[2]:X} vaddr=0x{ph[3]:X} "
            f"filesz=0x{ph[5]:X} memsz=0x{ph[6]:X}"
        )

    print("\n[SELF section-info]")
    section_infos = []
    for i in range(e_phnum):
        off = section_info_offset + i * 32
        si = struct.unpack_from(">QQIIII", data, off)
        section_infos.append(si)
        print(
            f"{i:02d} self_off=0x{si[0]:X} size=0x{si[1]:X} "
            f"compressed={si[2]} encrypted={si[5]}"
        )

    print("\n[SCE version records]")
    sv_header = struct.unpack_from(">IIII", data, sce_version_offset)
    print(
        f"header_type={sv_header[0]} present={sv_header[1]} "
        f"size=0x{sv_header[2]:X}"
    )
    if sv_header[1] and sv_header[2] >= 0x30:
        p = sce_version_offset + 16
        _u1, _u2, _u3, _u4, _u5, version_data_offset, version_data_size = (
            struct.unpack_from(">HHIIIQQ", data, p)
        )
        print(
            f"data_off=0x{version_data_offset:X} "
            f"data_size=0x{version_data_size:X}"
        )
        version_blob = data[
            version_data_offset : version_data_offset + version_data_size
        ]
        tags = re.findall(rb"([A-Za-z0-9_+.-]+):p([0-9]+)", version_blob)
        if tags:
            libraries = Counter(name.decode("ascii") for name, _ in tags)
            versions = Counter(ver.decode("ascii") for _, ver in tags)
            print("records:")
            for name, count in sorted(libraries.items()):
                print(f"  {name:<24} {count}")
            print("toolchain tags:")
            for ver, count in sorted(versions.items()):
                print(f"  p{ver}: {count}")

    print("\n[Control info]")
    off = control_info_offset
    end = off + control_info_size
    while off < end:
        ci_type, ci_size, ci_next = struct.unpack_from(">IIQ", data, off)
        print(
            f"off=0x{off:X} type={ci_type} size=0x{ci_size:X} next={ci_next}"
        )
        if ci_type == 2 and ci_size == 0x40:
            fw_version = struct.unpack_from(">Q", data, off + 16 + 40)[0]
            print(f"  firmware_version_raw=0x{fw_version:X} ({fw_version})")
        off += ci_size

    known_names = GT5P_SECTION_NAMES if digest == KNOWN_GT5P_SHA256 else {}
    sections = []
    print("\n[ELF section headers]")
    for i in range(e_shnum):
        off = shdr_offset + i * e_shentsize
        sh = struct.unpack_from(endian + "IIQQQQIIQQ", data, off)
        name = known_names.get(sh[0], "?")
        sections.append((name, sh))
        print(
            f"{i:02d} {name:<20} type=0x{sh[1]:X} flags=0x{sh[2]:X} "
            f"addr=0x{sh[3]:X} elf_off=0x{sh[4]:X} size=0x{sh[5]:X}"
        )

    by_name = {name: sh for name, sh in sections if name != "?"}
    if by_name:
        print("\n[Derived counts for known sample]")
        if ".opd" in by_name:
            print(
                "PS3 OPD descriptor slots: "
                f"{by_name['.opd'][5] // 8} (.opd size / 8)"
            )
        if ".rodata.sceFNID" in by_name:
            print(
                "Firmware FNID slots:      "
                f"{by_name['.rodata.sceFNID'][5] // 4}"
            )
        if ".sceStub.text" in by_name and ".rodata.sceFNID" in by_name:
            nids = by_name[".rodata.sceFNID"][5] // 4
            if nids:
                print(
                    "Import trampoline size: "
                    f"0x{by_name['.sceStub.text'][5] // nids:X} bytes"
                )
        if ".lib.stub" in by_name:
            print(
                "Import library records:   "
                f"{by_name['.lib.stub'][5] // 0x2C} (.lib.stub / 0x2C)"
            )

    print("\n[Payload entropy]")
    for i, (ph, si) in enumerate(zip(phdrs, section_infos)):
        if ph[0] == 1 and si[1]:
            blob = data[si[0] : si[0] + si[1]]
            print(f"PT_LOAD[{i}]: {entropy(blob):.5f} bits/byte")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("file", type=Path)
    args = parser.parse_args()
    parse_self(args.file)


if __name__ == "__main__":
    main()
