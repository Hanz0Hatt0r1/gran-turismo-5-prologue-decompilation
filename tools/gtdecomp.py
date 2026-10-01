#!/usr/bin/env python3
"""Gran Turismo PS3 executable analysis and cross-build matching utility.

The tool operates on user-provided decrypted PS3 PPU ELF files. It does not
contain game binaries, keys, SDK material, or proprietary assets.

Supported first-class input today:
  * ELF64, big-endian, PowerPC64 executables used by PS3 PPU titles.
  * Sony's compact 8-byte PPU function descriptor table (.opd-like layout).

Subcommands:
  index   Build a reproducible metadata database for one executable.
  compare Match functions between two builds using relocation-tolerant PPC
          fingerprints.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import struct
import subprocess
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional, Sequence, Tuple


ELFCLASS64 = 2
ELFDATA2MSB = 2
EM_PPC64 = 21
PT_LOAD = 1
SHF_ALLOC = 0x2
SHF_EXECINSTR = 0x4


def _u16(data: bytes, off: int) -> int:
    return struct.unpack_from(">H", data, off)[0]


def _u32(data: bytes, off: int) -> int:
    return struct.unpack_from(">I", data, off)[0]


def _s32(data: bytes, off: int) -> int:
    return struct.unpack_from(">i", data, off)[0]


def _u64(data: bytes, off: int) -> int:
    return struct.unpack_from(">Q", data, off)[0]


@dataclass(frozen=True)
class ProgramHeader:
    type: int
    flags: int
    offset: int
    vaddr: int
    filesz: int
    memsz: int


@dataclass(frozen=True)
class SectionHeader:
    index: int
    name: str
    type: int
    flags: int
    addr: int
    offset: int
    size: int
    entsize: int


@dataclass(frozen=True)
class FunctionDescriptor:
    descriptor_va: int
    code_va: int
    toc_va: int


@dataclass(frozen=True)
class Fingerprint:
    code_va: int
    size: int
    insns: int
    sha_full: str
    sha_prefix: str


@dataclass(frozen=True)
class RTTIObject:
    typeinfo_va: int
    typeinfo_vptr: int
    name_va: int
    encoded: str
    demangled: str


class PS3ELF:
    def __init__(self, path: Path | str):
        self.path = Path(path)
        self.data = self.path.read_bytes()
        self.sha256 = hashlib.sha256(self.data).hexdigest()
        self._parse_header()
        self._parse_program_headers()
        self._parse_section_headers()

    def _parse_header(self) -> None:
        d = self.data
        if len(d) < 64 or d[:4] != b"\x7fELF":
            raise ValueError("input is not an ELF file")
        if d[4] != ELFCLASS64 or d[5] != ELFDATA2MSB:
            raise ValueError("expected ELF64 big-endian input")
        self.machine = _u16(d, 18)
        if self.machine != EM_PPC64:
            raise ValueError(f"expected PowerPC64 ELF (machine {EM_PPC64}), got {self.machine}")
        self.entry = _u64(d, 24)
        self.phoff = _u64(d, 32)
        self.shoff = _u64(d, 40)
        self.ehsize = _u16(d, 52)
        self.phentsize = _u16(d, 54)
        self.phnum = _u16(d, 56)
        self.shentsize = _u16(d, 58)
        self.shnum = _u16(d, 60)
        self.shstrndx = _u16(d, 62)

    def _parse_program_headers(self) -> None:
        self.program_headers: List[ProgramHeader] = []
        for i in range(self.phnum):
            o = self.phoff + i * self.phentsize
            if o + 56 > len(self.data):
                raise ValueError("truncated program header table")
            self.program_headers.append(
                ProgramHeader(
                    type=_u32(self.data, o),
                    flags=_u32(self.data, o + 4),
                    offset=_u64(self.data, o + 8),
                    vaddr=_u64(self.data, o + 16),
                    filesz=_u64(self.data, o + 32),
                    memsz=_u64(self.data, o + 40),
                )
            )

    def _parse_section_headers(self) -> None:
        raw: List[Tuple[int, int, int, int, int, int, int]] = []
        for i in range(self.shnum):
            o = self.shoff + i * self.shentsize
            if o + 64 > len(self.data):
                raise ValueError("truncated section header table")
            raw.append(
                (
                    _u32(self.data, o),
                    _u32(self.data, o + 4),
                    _u64(self.data, o + 8),
                    _u64(self.data, o + 16),
                    _u64(self.data, o + 24),
                    _u64(self.data, o + 32),
                    _u64(self.data, o + 56),
                )
            )
        names = b""
        if 0 <= self.shstrndx < len(raw):
            _, _, _, _, off, size, _ = raw[self.shstrndx]
            if off + size <= len(self.data):
                names = self.data[off : off + size]
        self.section_headers: List[SectionHeader] = []
        for i, (name_off, typ, flags, addr, off, size, entsize) in enumerate(raw):
            name = ""
            if names and name_off < len(names):
                end = names.find(b"\0", name_off)
                if end < 0:
                    end = len(names)
                name = names[name_off:end].decode("ascii", "replace")
            self.section_headers.append(SectionHeader(i, name, typ, flags, addr, off, size, entsize))

    def va_to_offset(self, va: int) -> Optional[int]:
        for p in self.program_headers:
            if p.type == PT_LOAD and p.vaddr <= va < p.vaddr + p.filesz:
                return p.offset + (va - p.vaddr)
        return None

    def contains_va(self, va: int) -> bool:
        return self.va_to_offset(va) is not None

    def in_executable_segment(self, va: int) -> bool:
        return any(
            p.type == PT_LOAD
            and (p.flags & 1)
            and p.vaddr <= va < p.vaddr + p.filesz
            for p in self.program_headers
        )

    def section_for_va(self, va: int) -> Optional[SectionHeader]:
        for s in self.section_headers:
            if s.addr <= va < s.addr + s.size:
                return s
        return None

    def read_u32_va(self, va: int) -> Optional[int]:
        off = self.va_to_offset(va)
        if off is None or off + 4 > len(self.data):
            return None
        return _u32(self.data, off)

    def cstring_va(self, va: int, max_len: int = 4096) -> Optional[str]:
        off = self.va_to_offset(va)
        if off is None:
            return None
        end = self.data.find(b"\0", off, min(len(self.data), off + max_len))
        if end < 0:
            return None
        try:
            return self.data[off:end].decode("utf-8")
        except UnicodeDecodeError:
            return None

    def iter_ascii_strings(self, min_len: int = 4, alloc_only: bool = True) -> Iterator[Tuple[int, str]]:
        ranges: List[Tuple[int, int, int]] = []
        if alloc_only:
            for s in self.section_headers:
                if (s.flags & SHF_ALLOC) and s.size and s.offset + s.size <= len(self.data):
                    ranges.append((s.offset, s.offset + s.size, s.addr - s.offset))
        else:
            ranges.append((0, len(self.data), 0))
        seen = set()
        for start, end, delta in ranges:
            i = start
            while i < end:
                b = self.data[i]
                if 0x20 <= b <= 0x7E:
                    j = i + 1
                    while j < end and 0x20 <= self.data[j] <= 0x7E:
                        j += 1
                    if j - i >= min_len:
                        va = i + delta
                        key = (va, self.data[i:j])
                        if key not in seen:
                            seen.add(key)
                            yield va, self.data[i:j].decode("ascii", "replace")
                    i = j + 1 if j < end and self.data[j] == 0 else j
                else:
                    i += 1


def find_opd(elf: PS3ELF) -> Tuple[int, List[FunctionDescriptor]]:
    """Recover Sony PPU 8-byte function descriptors from the entry section.

    PS3 executables commonly store descriptors as two big-endian u32 values:
    code address and TOC address. The ELF entry points at a descriptor rather
    than directly at the first instruction.
    """
    entry_off = elf.va_to_offset(elf.entry)
    if entry_off is None or entry_off + 8 > len(elf.data):
        raise ValueError("ELF entry does not map to file data")
    entry_code = _u32(elf.data, entry_off)
    toc = _u32(elf.data, entry_off + 4)
    if not elf.in_executable_segment(entry_code):
        raise ValueError("entry descriptor does not point to executable code")
    sec = elf.section_for_va(elf.entry)
    if sec is None:
        raise ValueError("could not locate section containing the entry descriptor")
    descriptors: List[FunctionDescriptor] = []
    start = (sec.addr + 7) & ~7
    end = sec.addr + sec.size
    for va in range(start, end - 7, 8):
        off = elf.va_to_offset(va)
        if off is None or off + 8 > len(elf.data):
            continue
        code = _u32(elf.data, off)
        cur_toc = _u32(elf.data, off + 4)
        if cur_toc == toc and elf.in_executable_segment(code):
            descriptors.append(FunctionDescriptor(va, code, cur_toc))
    return toc, descriptors



@dataclass(frozen=True)
class ImportFunction:
    library: str
    nid: int
    stub_code_va: int
    import_slot_va: int


def find_proc_prx_param(elf: PS3ELF) -> Optional[Dict[str, int]]:
    """Read the process PRX parameter block from PT_LOOS+2 (0x60000002)."""
    for p in elf.program_headers:
        if p.type != 0x60000002 or p.filesz < 40:
            continue
        off = elf.va_to_offset(p.vaddr)
        if off is None or off + 40 > len(elf.data):
            # Non-PT_LOAD metadata segments can still point directly at file data.
            off = p.offset if p.offset + 40 <= len(elf.data) else None
        if off is None:
            continue
        vals = struct.unpack_from(">8I2HI", elf.data, off)
        if vals[1] != 0x1B434CEC:
            continue
        return {
            "size": vals[0],
            "magic": vals[1],
            "version": vals[2],
            "unk0": vals[3],
            "libent_start": vals[4],
            "libent_end": vals[5],
            "libstub_start": vals[6],
            "libstub_end": vals[7],
            "ver": vals[8],
            "unk1": vals[9],
            "unk2": vals[10],
        }
    return None


def find_imports(elf: PS3ELF) -> Tuple[List[ImportFunction], List[str]]:
    """Parse PS3 PPU PRX import module records from the executable."""
    proc = find_proc_prx_param(elf)
    if proc is None:
        return [], []
    addr = proc["libstub_start"]
    end = proc["libstub_end"]
    imports: List[ImportFunction] = []
    libraries: List[str] = []
    seen_libs = set()
    while addr < end:
        off = elf.va_to_offset(addr)
        if off is None or off + 0x2C > len(elf.data):
            break
        size = elf.data[off]
        version = _u16(elf.data, off + 2)
        attributes = _u16(elf.data, off + 4)
        num_func = _u16(elf.data, off + 6)
        num_var = _u16(elf.data, off + 8)
        num_tlsvar = _u16(elf.data, off + 10)
        name_va = _u32(elf.data, off + 16)
        nids_va = _u32(elf.data, off + 20)
        addrs_va = _u32(elf.data, off + 24)
        library = elf.cstring_va(name_va, 256) or "unknown"
        if library not in seen_libs:
            seen_libs.add(library)
            libraries.append(library)
        # Sanity limits prevent malformed metadata from turning into huge loops.
        if num_func > 0x4000 or num_var > 0x4000 or num_tlsvar > 0x4000:
            break
        nids_off = elf.va_to_offset(nids_va)
        addrs_off = elf.va_to_offset(addrs_va)
        if nids_off is not None and addrs_off is not None:
            for i in range(num_func):
                no = nids_off + 4 * i
                ao = addrs_off + 4 * i
                if no + 4 > len(elf.data) or ao + 4 > len(elf.data):
                    break
                imports.append(
                    ImportFunction(
                        library=library,
                        nid=_u32(elf.data, no),
                        stub_code_va=_u32(elf.data, ao),
                        import_slot_va=addrs_va + 4 * i,
                    )
                )
        step = size if size else 0x2C
        if step < 0x10:
            break
        addr += step
    return imports, libraries

def normalize_ppc_instruction(ins: int) -> int:
    """Erase relocation-sensitive fields while retaining instruction shape."""
    op = (ins >> 26) & 0x3F
    if op == 18:  # b / bl
        return ins & 0xFC000003
    if op == 16:  # bc / bcl
        return ins & 0xFFFF0003
    ra = (ins >> 16) & 0x1F
    if ra == 2 and op in {
        14, 15, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41,
        42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55,
    }:
        return ins & 0xFFFF0000
    if ra == 2 and op in {58, 62}:  # ld/std DS form
        return ins & 0xFFFF0003
    return ins


def build_fingerprints(elf: PS3ELF, descriptors: Sequence[FunctionDescriptor], max_size: int = 0x4000) -> List[Fingerprint]:
    funcs = sorted(set(d.code_va for d in descriptors))
    rows: List[Fingerprint] = []
    for i, va in enumerate(funcs):
        seg = next(
            (
                p for p in elf.program_headers
                if p.type == PT_LOAD and (p.flags & 1) and p.vaddr <= va < p.vaddr + p.filesz
            ),
            None,
        )
        if seg is None:
            continue
        seg_end = seg.vaddr + seg.filesz
        next_va = funcs[i + 1] if i + 1 < len(funcs) else seg_end
        if not (va < next_va <= seg_end):
            next_va = seg_end
        end = min(next_va, va + max_size, seg_end)
        size = end - va
        size -= size % 4
        off = elf.va_to_offset(va)
        if off is None or size <= 0:
            continue
        words = [normalize_ppc_instruction(_u32(elf.data, off + x)) for x in range(0, size, 4)]
        raw = b"".join(struct.pack(">I", w) for w in words)
        prefix = raw[: min(len(raw), 256)]
        rows.append(
            Fingerprint(
                code_va=va,
                size=size,
                insns=len(words),
                sha_full=hashlib.sha1(raw).hexdigest(),
                sha_prefix=hashlib.sha1(prefix).hexdigest(),
            )
        )
    return rows


_SOURCE_RE = re.compile(r"(?i)(?:^|[/\\])([^/\\\x00]{1,120}\.(?:c|cc|cpp|cxx))$")
_TITLE_ID_RE = re.compile(r"\b(?:BC|BL|NP)[A-Z]{2}-?\d{5}\b")
_CONTENT_ID_RE = re.compile(r"\b[A-Z]{2}\d{4}-[A-Z0-9]{9}_\d{2}-[A-Z0-9]{16}\b")


def find_source_files(strings: Iterable[Tuple[int, str]]) -> List[Tuple[int, str]]:
    rows = []
    seen = set()
    for va, s in strings:
        if _SOURCE_RE.search(s) and s not in seen:
            seen.add(s)
            rows.append((va, s))
    return rows


def find_build_identity(strings: Iterable[Tuple[int, str]]) -> Dict[str, List[str]]:
    title_ids = set()
    content_ids = set()
    build_strings = set()
    for _, s in strings:
        title_ids.update(_TITLE_ID_RE.findall(s))
        content_ids.update(_CONTENT_ID_RE.findall(s))
        ls = s.lower()
        if "gran turismo" in ls or "gt.gt5" in ls or "gt5p" in ls:
            if len(s) <= 240:
                build_strings.add(s)
    return {
        "title_ids": sorted(title_ids),
        "content_ids": sorted(content_ids),
        "build_strings": sorted(build_strings)[:100],
    }


def _looks_like_itanium_type_name(s: str) -> bool:
    if not (1 <= len(s) <= 512):
        return False
    if re.fullmatch(r"[A-Za-z0-9_.]+", s) is None:
        return False
    if s.startswith("N") and s.endswith("E") and any(c.isdigit() for c in s):
        return True
    if s[0].isdigit() and any(c.isalpha() for c in s):
        return True
    return False


def _demangle_type(encoded: str) -> str:
    try:
        p = subprocess.run(
            ["c++filt", "-t", encoded],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=1,
            check=False,
        )
        out = p.stdout.strip()
        if out and out != encoded:
            return out
    except (OSError, subprocess.SubprocessError):
        pass
    return encoded


def find_rtti_objects(elf: PS3ELF, strings: Sequence[Tuple[int, str]]) -> List[RTTIObject]:
    # c++filt is part of common binutils installations and understands the
    # compiler's Itanium-style type encoding, including GT's anonymous-
    # namespace names that retain source-file fragments. If it is unavailable,
    # nested N...E encodings still remain usable as conservative candidates.
    name_by_va: Dict[int, Tuple[str, str]] = {}
    for va, s in strings:
        if not _looks_like_itanium_type_name(s):
            continue
        demangled = _demangle_type(s)
        if demangled != s or (s.startswith("N") and s.endswith("E")):
            name_by_va[va] = (s, demangled)
    if not name_by_va:
        return []
    rows: List[RTTIObject] = []
    seen = set()
    for sec in elf.section_headers:
        if not (sec.flags & SHF_ALLOC) or (sec.flags & SHF_EXECINSTR):
            continue
        if sec.offset + sec.size > len(elf.data):
            continue
        start = (sec.offset + 3) & ~3
        end = sec.offset + sec.size - 7
        for off in range(start, end, 4):
            vptr = _u32(elf.data, off)
            name_va = _u32(elf.data, off + 4)
            named = name_by_va.get(name_va)
            if named is None:
                continue
            encoded, demangled = named
            if not elf.contains_va(vptr):
                continue
            va = sec.addr + (off - sec.offset)
            key = (va, name_va)
            if key in seen:
                continue
            seen.add(key)
            rows.append(RTTIObject(va, vptr, name_va, encoded, demangled))
    return rows


def find_vtables(
    elf: PS3ELF,
    rtti: Sequence[RTTIObject],
    descriptors: Sequence[FunctionDescriptor],
    max_slots: int = 128,
) -> List[Dict[str, object]]:
    typeinfo = {r.typeinfo_va: r for r in rtti}
    opd_to_code = {d.descriptor_va: d.code_va for d in descriptors}
    rows: List[Dict[str, object]] = []
    if not typeinfo or not opd_to_code:
        return rows
    for sec in elf.section_headers:
        if not (sec.flags & SHF_ALLOC) or (sec.flags & SHF_EXECINSTR):
            continue
        if sec.offset + sec.size > len(elf.data):
            continue
        start = (sec.offset + 3) & ~3
        end = sec.offset + sec.size - 12
        for off in range(start, end, 4):
            offset_to_top = _s32(elf.data, off)
            ti_va = _u32(elf.data, off + 4)
            ti = typeinfo.get(ti_va)
            if ti is None or abs(offset_to_top) > 0x1000000:
                continue
            first_desc = _u32(elf.data, off + 8)
            if first_desc not in opd_to_code:
                continue
            vtable_va = sec.addr + (off - sec.offset)
            slot_off = off + 8
            for slot in range(max_slots):
                if slot_off + 4 > sec.offset + sec.size:
                    break
                desc = _u32(elf.data, slot_off)
                code = opd_to_code.get(desc)
                if code is None:
                    break
                rows.append(
                    {
                        "demangled": ti.demangled,
                        "encoded": ti.encoded,
                        "vtable_start": vtable_va,
                        "address_point": vtable_va + 8,
                        "offset_to_top": offset_to_top,
                        "typeinfo_va": ti_va,
                        "slot": slot,
                        "slot_va": vtable_va + 8 + slot * 4,
                        "function_descriptor": desc,
                        "code_va": code,
                    }
                )
                slot_off += 4
    return rows


def _fmt_hex(v: int) -> str:
    return f"0x{v:08x}"


def _write_csv(path: Path, fieldnames: Sequence[str], rows: Iterable[Dict[str, object]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for row in rows:
            w.writerow(row)


def index_elf(path: Path, out: Path) -> Dict[str, object]:
    out.mkdir(parents=True, exist_ok=True)
    elf = PS3ELF(path)
    toc, descriptors = find_opd(elf)
    fingerprints = build_fingerprints(elf, descriptors)
    strings = list(elf.iter_ascii_strings(min_len=4, alloc_only=True))
    source_files = find_source_files(strings)
    identity = find_build_identity(strings)
    rtti = find_rtti_objects(elf, strings)
    vtables = find_vtables(elf, rtti, descriptors)
    imports, import_libraries = find_imports(elf)

    manifest = {
        "schema": 1,
        "input_name": path.name,
        "sha256": elf.sha256,
        "format": "ELF64-big-endian-PowerPC64",
        "entry_descriptor_va": _fmt_hex(elf.entry),
        "entry_code_va": _fmt_hex(elf.read_u32_va(elf.entry) or 0),
        "toc_va": _fmt_hex(toc),
        "program_headers": elf.phnum,
        "section_headers": elf.shnum,
        "function_descriptors": len(descriptors),
        "unique_function_addresses": len(set(d.code_va for d in descriptors)),
        "rtti_objects": len(rtti),
        "vtable_slots": len(vtables),
        "vtable_candidates": len(set(int(r["vtable_start"]) for r in vtables)),
        "source_file_strings": len(source_files),
        "import_libraries": len(import_libraries),
        "import_functions": len(imports),
        **identity,
    }
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    _write_csv(
        out / "opd.csv",
        ["descriptor_va", "code_va", "toc_va"],
        (
            {"descriptor_va": _fmt_hex(d.descriptor_va), "code_va": _fmt_hex(d.code_va), "toc_va": _fmt_hex(d.toc_va)}
            for d in descriptors
        ),
    )
    _write_csv(
        out / "functions.csv",
        ["code_va", "size", "insns", "sha_full", "sha_prefix"],
        (
            {
                "code_va": _fmt_hex(r.code_va),
                "size": r.size,
                "insns": r.insns,
                "sha_full": r.sha_full,
                "sha_prefix": r.sha_prefix,
            }
            for r in fingerprints
        ),
    )
    _write_csv(
        out / "rtti.csv",
        ["typeinfo_va", "typeinfo_vptr", "name_va", "encoded", "demangled"],
        (
            {
                "typeinfo_va": _fmt_hex(r.typeinfo_va),
                "typeinfo_vptr": _fmt_hex(r.typeinfo_vptr),
                "name_va": _fmt_hex(r.name_va),
                "encoded": r.encoded,
                "demangled": r.demangled,
            }
            for r in rtti
        ),
    )
    _write_csv(
        out / "vtables.csv",
        ["demangled", "encoded", "vtable_start", "address_point", "offset_to_top", "typeinfo_va", "slot", "slot_va", "function_descriptor", "code_va"],
        (
            {
                "demangled": r["demangled"],
                "encoded": r["encoded"],
                "vtable_start": _fmt_hex(int(r["vtable_start"])),
                "address_point": _fmt_hex(int(r["address_point"])),
                "offset_to_top": r["offset_to_top"],
                "typeinfo_va": _fmt_hex(int(r["typeinfo_va"])),
                "slot": r["slot"],
                "slot_va": _fmt_hex(int(r["slot_va"])),
                "function_descriptor": _fmt_hex(int(r["function_descriptor"])),
                "code_va": _fmt_hex(int(r["code_va"])),
            }
            for r in vtables
        ),
    )
    with (out / "source_files.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["va", "source_file"])
        for va, name in source_files:
            w.writerow([_fmt_hex(va), name])
    _write_csv(
        out / "imports.csv",
        ["library", "nid", "stub_code_va", "import_slot_va"],
        (
            {
                "library": r.library,
                "nid": _fmt_hex(r.nid),
                "stub_code_va": _fmt_hex(r.stub_code_va),
                "import_slot_va": _fmt_hex(r.import_slot_va),
            }
            for r in imports
        ),
    )
    return manifest


def _fp_index(rows: Sequence[Fingerprint], attr: str) -> Dict[str, List[Fingerprint]]:
    out: Dict[str, List[Fingerprint]] = {}
    for row in rows:
        out.setdefault(getattr(row, attr), []).append(row)
    return out


def compare_elfs(reference: Path, target: Path, out: Path) -> Dict[str, object]:
    out.mkdir(parents=True, exist_ok=True)
    a = PS3ELF(reference)
    b = PS3ELF(target)
    atoc, aopd = find_opd(a)
    btoc, bopd = find_opd(b)
    afp = build_fingerprints(a, aopd)
    bfp = build_fingerprints(b, bopd)
    af = _fp_index(afp, "sha_full")
    bf = _fp_index(bfp, "sha_full")
    ap = _fp_index(afp, "sha_prefix")
    bp = _fp_index(bfp, "sha_prefix")
    matches: List[Tuple[Fingerprint, Fingerprint, str]] = []
    used_b = set()
    matched_a = set()

    for h, aa in af.items():
        bb = bf.get(h, [])
        if len(aa) == 1 and len(bb) == 1:
            x, y = aa[0], bb[0]
            matches.append((x, y, "normalized-full"))
            used_b.add(y.code_va)
            matched_a.add(x.code_va)
    for h, aa0 in ap.items():
        aa = [r for r in aa0 if r.code_va not in matched_a]
        bb = [r for r in bp.get(h, []) if r.code_va not in used_b]
        if len(aa) == 1 and len(bb) == 1 and min(aa[0].insns, bb[0].insns) >= 8:
            x, y = aa[0], bb[0]
            matches.append((x, y, "normalized-prefix"))
            used_b.add(y.code_va)
            matched_a.add(x.code_va)

    with (out / "function_matches.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["reference_code_va", "target_code_va", "method", "reference_size", "target_size"])
        for x, y, method in sorted(matches, key=lambda t: t[0].code_va):
            w.writerow([_fmt_hex(x.code_va), _fmt_hex(y.code_va), method, x.size, y.size])

    summary = {
        "schema": 1,
        "reference_sha256": a.sha256,
        "target_sha256": b.sha256,
        "reference_toc": _fmt_hex(atoc),
        "target_toc": _fmt_hex(btoc),
        "reference_functions": len(afp),
        "target_functions": len(bfp),
        "matches": len(matches),
        "full_matches": sum(method == "normalized-full" for _, _, method in matches),
        "prefix_matches": sum(method == "normalized-prefix" for _, _, method in matches),
    }
    (out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    return summary


def main(argv: Optional[Sequence[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Index and compare Gran Turismo PS3 PPU executables")
    sub = ap.add_subparsers(dest="command", required=True)
    p_index = sub.add_parser("index", help="build a metadata database for one ELF")
    p_index.add_argument("elf", type=Path)
    p_index.add_argument("-o", "--out", type=Path, default=Path("analysis-out"))
    p_compare = sub.add_parser("compare", help="match functions between two ELF builds")
    p_compare.add_argument("reference", type=Path)
    p_compare.add_argument("target", type=Path)
    p_compare.add_argument("-o", "--out", type=Path, default=Path("compare-out"))
    args = ap.parse_args(argv)

    if args.command == "index":
        result = index_elf(args.elf, args.out)
    else:
        result = compare_elfs(args.reference, args.target, args.out)
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())