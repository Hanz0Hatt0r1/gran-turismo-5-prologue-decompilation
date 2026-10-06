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





def load_nid_database(path: Path | str) -> Dict[int, str]:
    """Load an optional external PS3 NID -> symbol-name database.

    Supported inputs are whitespace text (``0x12345678 symbol``), CSV with
    ``nid``/``name`` columns, and simple JSON mappings/lists. The project does
    not vendor third-party symbol databases; callers may provide one locally.
    """
    path = Path(path)
    raw = path.read_text(encoding="utf-8", errors="replace")
    out: Dict[int, str] = {}

    def add(nid_value, name_value) -> None:
        if nid_value is None or name_value is None:
            return
        try:
            if isinstance(nid_value, int):
                nid = nid_value
            else:
                text = str(nid_value).strip()
                nid = int(text, 0) if text.lower().startswith("0x") else int(text, 16)
        except (TypeError, ValueError):
            return
        name = str(name_value).strip()
        if 0 <= nid <= 0xFFFFFFFF and name:
            out.setdefault(nid, name)

    if path.suffix.lower() == ".json":
        obj = json.loads(raw)
        if isinstance(obj, dict):
            for key, value in obj.items():
                if isinstance(value, str):
                    add(key, value)
                elif isinstance(value, dict):
                    add(value.get("nid", key), value.get("name") or value.get("symbol"))
        elif isinstance(obj, list):
            for value in obj:
                if isinstance(value, dict):
                    add(value.get("nid"), value.get("name") or value.get("symbol"))
        return out

    if path.suffix.lower() == ".csv":
        rows = list(csv.reader(raw.splitlines()))
        if rows:
            header = [x.strip().lower() for x in rows[0]]
            if "nid" in header and ("name" in header or "symbol" in header):
                ni = header.index("nid")
                si = header.index("name") if "name" in header else header.index("symbol")
                for row in rows[1:]:
                    if max(ni, si) < len(row):
                        add(row[ni], row[si])
                return out
            for row in rows:
                if len(row) >= 2:
                    add(row[0], row[1])
            if out:
                return out

    line_re = re.compile(r"^\s*(?:0x)?([0-9A-Fa-f]{8})[\s,;:]+(.+?)\s*$")
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("//"):
            continue
        m = line_re.match(line)
        if m:
            add(m.group(1), m.group(2))
    return out


@dataclass(frozen=True)
class ImportFunction:
    library: str
    nid: int
    stub_code_va: int
    import_slot_va: int

@dataclass(frozen=True)
class FunctionCandidate:
    code_va: int
    score: int
    evidence: Tuple[str, ...]


@dataclass(frozen=True)
class CallEdge:
    caller_va: int
    callsite_va: int
    target_va: int
    kind: str


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


def function_ranges_from_starts(elf: PS3ELF, starts: Iterable[int], max_size: int = 0x4000) -> List[Tuple[int, int]]:
    """Return conservative ranges from sorted candidate function entry points."""
    funcs = sorted(set(va for va in starts if elf.in_executable_segment(va)))
    rows: List[Tuple[int, int]] = []
    for i, va in enumerate(funcs):
        seg = next((p for p in elf.program_headers if p.type == PT_LOAD and (p.flags & 1) and p.vaddr <= va < p.vaddr + p.filesz), None)
        if seg is None:
            continue
        seg_end = seg.vaddr + seg.filesz
        next_va = funcs[i + 1] if i + 1 < len(funcs) else seg_end
        if not (va < next_va <= seg_end):
            next_va = seg_end
        end = min(next_va, va + max_size, seg_end)
        end -= (end - va) % 4
        if end > va:
            rows.append((va, end))
    return rows


def function_ranges(elf: PS3ELF, descriptors: Sequence[FunctionDescriptor], max_size: int = 0x4000) -> List[Tuple[int, int]]:
    return function_ranges_from_starts(elf, (d.code_va for d in descriptors), max_size=max_size)


def _ppc_branch_target(ins: int, va: int) -> Optional[int]:
    if ((ins >> 26) & 0x3F) != 18:
        return None
    disp = ins & 0x03FFFFFC
    if disp & 0x02000000:
        disp -= 0x04000000
    return disp if ((ins >> 1) & 1) else va + disp


def _is_stack_prologue(ins: int) -> bool:
    # stdu r1, negative_frame(r1) on PPC64.
    if ((ins >> 26) & 0x3F) != 62 or ((ins >> 21) & 0x1F) != 1 or ((ins >> 16) & 0x1F) != 1 or (ins & 3) != 1:
        return False
    ds = (ins >> 2) & 0x3FFF
    if ds & 0x2000:
        ds -= 0x4000
    disp = ds * 4
    return -0x8000 <= disp < 0


def discover_function_candidates(elf: PS3ELF, descriptors: Sequence[FunctionDescriptor]) -> List[FunctionCandidate]:
    """Discover PPU function starts with explicit evidence and confidence scores.

    OPD entries and direct call targets are high-confidence. A standard PPC64
    stack-frame prologue is strong structural evidence. The instruction after a
    return is retained as lower-confidence evidence for leaf-function discovery,
    but is not used by default for cross-build fingerprinting.
    """
    evidence: Dict[int, set] = {}

    def add(va: int, kind: str) -> None:
        if va % 4 == 0 and elf.in_executable_segment(va):
            evidence.setdefault(va, set()).add(kind)

    for d in descriptors:
        add(d.code_va, "opd")
    entry_code = elf.read_u32_va(elf.entry)
    if entry_code is not None:
        add(entry_code, "entry")

    for ph in elf.program_headers:
        if ph.type != PT_LOAD or not (ph.flags & 1) or ph.filesz < 4:
            continue
        end_off = min(len(elf.data), ph.offset + ph.filesz)
        for off in range(ph.offset, end_off - 3, 4):
            va = ph.vaddr + (off - ph.offset)
            ins = _u32(elf.data, off)
            if ((ins >> 26) & 0x3F) == 18 and (ins & 1):  # bl / bla
                target = _ppc_branch_target(ins, va)
                if target is not None:
                    add(target, "direct-call")
            if _is_stack_prologue(ins):
                add(va, "stack-prologue")
            if ins == 0x4E800020:  # blr
                nxt = va + 4
                for _ in range(8):
                    no = elf.va_to_offset(nxt)
                    if no is None or no + 4 > len(elf.data):
                        break
                    ni = _u32(elf.data, no)
                    if ni in (0, 0x60000000):
                        nxt += 4
                        continue
                    add(nxt, "after-blr")
                    break

    weights = {"entry": 5, "opd": 4, "direct-call": 4, "stack-prologue": 3, "after-blr": 2}
    rows = []
    for va, kinds in evidence.items():
        ordered = tuple(sorted(kinds))
        rows.append(FunctionCandidate(va, sum(weights[k] for k in ordered), ordered))
    return sorted(rows, key=lambda r: r.code_va)


def extract_call_edges(\n    elf: PS3ELF,\n    function_starts: Sequence[int],\n    max_size: int = 0x4000,\n) -> List[CallEdge]:\n    """Extract direct PPU call edges from conservative function ranges.\n\n    Only direct bl/bla-class branches are emitted. This deliberately excludes\n    indirect calls through registers/OPD descriptors, so the result is a\n    high-confidence partial call graph rather than a guessed complete one.\n    """\n    ranges = function_ranges_from_starts(elf, function_starts, max_size=max_size)\n    rows: List[CallEdge] = []\n    for start, end in ranges:\n        off = elf.va_to_offset(start)\n        if off is None:\n            continue\n        for rel in range(0, end - start, 4):\n            va = start + rel\n            ins = _u32(elf.data, off + rel)\n            if ((ins >> 26) & 0x3F) != 18 or not (ins & 1):\n                continue\n            target = _ppc_branch_target(ins, va)\n            if target is None:\n                continue\n            rows.append(CallEdge(start, va, target, "direct"))\n    return rows\n\n\ndef build_fingerprints_from_starts(elf: PS3ELF, starts: Iterable[int], max_size: int = 0x4000) -> List[Fingerprint]:
    rows: List[Fingerprint] = []
    for va, end in function_ranges_from_starts(elf, starts, max_size=max_size):
        size = end - va
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


def find_toc_string_refs(
    elf: PS3ELF, toc: int, function_starts: Sequence[int], strings: Sequence[Tuple[int, str]]
) -> List[Dict[str, object]]:
    """Recover common 32-bit TOC loads whose slot points at an ASCII string.

    GT5 uses 32-bit effective addresses even in the 64-bit PPU ABI. A common
    compiler pattern is ``lwz rX, disp(r2)`` where the TOC slot contains the
    address of a literal. Floating-point loads are included because a handful of
    constants are emitted next to printable metadata and are useful as evidence.
    """
    text_by_va = dict(strings)
    string_vas = set(text_by_va)
    out: List[Dict[str, object]] = []
    for start, end in function_ranges_from_starts(elf, function_starts):
        off = elf.va_to_offset(start)
        if off is None:
            continue
        for rel in range(0, end - start, 4):
            ins = _u32(elf.data, off + rel)
            op = (ins >> 26) & 0x3F
            ra = (ins >> 16) & 0x1F
            if ra != 2 or op not in {32, 48}:  # lwz / lfs
                continue
            disp = ins & 0xFFFF
            if disp & 0x8000:
                disp -= 0x10000
            slot_va = toc + disp
            slot_off = elf.va_to_offset(slot_va)
            if slot_off is None or slot_off + 4 > len(elf.data):
                continue
            target_va = _u32(elf.data, slot_off)
            if target_va not in string_vas:
                continue
            out.append(
                {
                    "code_va": start,
                    "reference_va": start + rel,
                    "toc_slot_va": slot_va,
                    "string_va": target_va,
                    "string": text_by_va[target_va],
                    "kind": "lwz-toc" if op == 32 else "lfs-toc",
                }
            )
    return out


def build_function_hints(
    vtables: Sequence[Dict[str, object]],
    string_refs: Sequence[Dict[str, object]],
    source_files: Sequence[Tuple[int, str]],
) -> List[Dict[str, object]]:
    """Aggregate conservative class/source evidence per function."""
    source_by_va = dict(source_files)
    sources: Dict[int, set] = {}
    classes: Dict[int, set] = {}
    evidence: Dict[int, int] = {}
    for r in string_refs:
        sva = int(r["string_va"])
        if sva not in source_by_va:
            continue
        fva = int(r["code_va"])
        sources.setdefault(fva, set()).add(source_by_va[sva])
        evidence[fva] = evidence.get(fva, 0) + 1
    for r in vtables:
        fva = int(r["code_va"])
        classes.setdefault(fva, set()).add(str(r["demangled"]))
        evidence[fva] = evidence.get(fva, 0) + 1
    rows = []
    for fva in sorted(set(sources) | set(classes)):
        rows.append(
            {
                "code_va": fva,
                "source_files": " | ".join(sorted(sources.get(fva, set()))),
                "vtable_types": " | ".join(sorted(classes.get(fva, set()))),
                "evidence_count": evidence.get(fva, 0),
            }
        )
    return rows


def build_fingerprints(elf: PS3ELF, descriptors: Sequence[FunctionDescriptor], max_size: int = 0x4000) -> List[Fingerprint]:
    return build_fingerprints_from_starts(elf, (d.code_va for d in descriptors), max_size=max_size)


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


def index_elf(path: Path, out: Path, nid_db: Optional[Path] = None) -> Dict[str, object]:
    out.mkdir(parents=True, exist_ok=True)
    elf = PS3ELF(path)
    toc, descriptors = find_opd(elf)
    candidates = discover_function_candidates(elf, descriptors)
    strict_starts = [r.code_va for r in candidates if r.score >= 3]
    fingerprints = build_fingerprints(elf, descriptors)
    discovered_fingerprints = build_fingerprints_from_starts(elf, strict_starts)
    strings = list(elf.iter_ascii_strings(min_len=4, alloc_only=True))
    source_files = find_source_files(strings)
    identity = find_build_identity(strings)
    rtti = find_rtti_objects(elf, strings)
    vtables = find_vtables(elf, rtti, descriptors)
    string_refs = find_toc_string_refs(elf, toc, strict_starts, strings)
    function_hints = build_function_hints(vtables, string_refs, source_files)
    call_edges = extract_call_edges(elf, strict_starts)
    imports, import_libraries = find_imports(elf)
    nid_names = load_nid_database(nid_db) if nid_db is not None else {}
    resolved_import_names = sum(1 for r in imports if r.nid in nid_names)

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
        "discovered_function_addresses": len(strict_starts),
        "function_candidates": len(candidates),
        "rtti_objects": len(rtti),
        "vtable_slots": len(vtables),
        "vtable_candidates": len(set(int(r["vtable_start"]) for r in vtables)),
        "source_file_strings": len(source_files),
        "toc_string_references": len(string_refs),
        "functions_with_hints": len(function_hints),
        "import_libraries": len(import_libraries),
        "import_functions": len(imports),
        "resolved_import_names": resolved_import_names,
        "direct_call_edges": len(call_edges),
        "direct_local_call_edges": sum(elf.in_executable_segment(r.target_va) for r in call_edges),
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
        out / "function_candidates.csv",
        ["code_va", "score", "evidence"],
        (
            {"code_va": _fmt_hex(r.code_va), "score": r.score, "evidence": " | ".join(r.evidence)}
            for r in candidates
        ),
    )
    candidate_by_va = {r.code_va: r for r in candidates}
    _write_csv(
        out / "discovered_functions.csv",
        ["code_va", "score", "evidence", "size", "insns", "sha_full", "sha_prefix"],
        (
            {
                "code_va": _fmt_hex(r.code_va),
                "score": candidate_by_va[r.code_va].score,
                "evidence": " | ".join(candidate_by_va[r.code_va].evidence),
                "size": r.size,
                "insns": r.insns,
                "sha_full": r.sha_full,
                "sha_prefix": r.sha_prefix,
            }
            for r in discovered_fingerprints
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
        out / "string_refs.csv",
        ["code_va", "reference_va", "toc_slot_va", "string_va", "kind", "string"],
        (
            {
                "code_va": _fmt_hex(int(r["code_va"])),
                "reference_va": _fmt_hex(int(r["reference_va"])),
                "toc_slot_va": _fmt_hex(int(r["toc_slot_va"])),
                "string_va": _fmt_hex(int(r["string_va"])),
                "kind": r["kind"],
                "string": r["string"],
            }
            for r in string_refs
        ),
    )
    _write_csv(
        out / "function_hints.csv",
        ["code_va", "source_files", "vtable_types", "evidence_count"],
        (
            {
                "code_va": _fmt_hex(int(r["code_va"])),
                "source_files": r["source_files"],
                "vtable_types": r["vtable_types"],
                "evidence_count": r["evidence_count"],
            }
            for r in function_hints
        ),
    )
    _write_csv(
        out / "calls.csv",
        ["caller_code_va", "callsite_va", "target_va", "kind", "target_local"],
        (
            {
                "caller_code_va": _fmt_hex(r.caller_va),
                "callsite_va": _fmt_hex(r.callsite_va),
                "target_va": _fmt_hex(r.target_va),
                "kind": r.kind,
                "target_local": int(elf.in_executable_segment(r.target_va)),
            }
            for r in call_edges
        ),
    )
    _write_csv(
        out / "imports.csv",
        ["library", "nid", "name", "stub_code_va", "import_slot_va"],
        (
            {
                "library": r.library,
                "nid": _fmt_hex(r.nid),
                "name": nid_names.get(r.nid, ""),
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
    ac = discover_function_candidates(a, aopd)
    bc = discover_function_candidates(b, bopd)
    afp = build_fingerprints_from_starts(a, (r.code_va for r in ac if r.score >= 3))
    bfp = build_fingerprints_from_starts(b, (r.code_va for r in bc if r.score >= 3))
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


_GHIDRA_C_FUNC_RE = re.compile(
    r"(?m)^[^\n]*\b((?:thunk_)?FUN_([0-9A-Fa-f]{8}))\s*\([^\n]*\)\s*\n?\s*\{"
)


def _balanced_c_block_end(text: str, brace: int) -> int:
    """Return one-past the matching C brace while ignoring comments/strings."""
    depth = 0
    i = brace
    state = "code"
    while i < len(text):
        ch = text[i]
        nxt = text[i + 1] if i + 1 < len(text) else ""
        if state == "line-comment":
            if ch == "\n":
                state = "code"
        elif state == "block-comment":
            if ch == "*" and nxt == "/":
                state = "code"
                i += 1
        elif state == "string":
            if ch == "\\":
                i += 1
            elif ch == '"':
                state = "code"
        elif state == "char":
            if ch == "\\":
                i += 1
            elif ch == "'":
                state = "code"
        else:
            if ch == "/" and nxt == "/":
                state = "line-comment"
                i += 1
            elif ch == "/" and nxt == "*":
                state = "block-comment"
                i += 1
            elif ch == '"':
                state = "string"
            elif ch == "'":
                state = "char"
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    return i + 1
        i += 1
    return len(text)


def _csv_by_code_va(path: Path) -> Dict[int, Dict[str, str]]:
    if not path.exists():
        return {}
    with path.open("r", newline="", encoding="utf-8") as f:
        return {int(r["code_va"], 16): r for r in csv.DictReader(f)}


def import_ghidra_c(c_path: Path, index_dir: Path, out: Path) -> Dict[str, object]:
    """Split a Ghidra C export and attach gtdecomp identities/evidence."""
    out.mkdir(parents=True, exist_ok=True)
    functions_dir = out / "functions"
    functions_dir.mkdir(parents=True, exist_ok=True)
    text = c_path.read_text(encoding="utf-8", errors="replace")
    fp_path = index_dir / "discovered_functions.csv"
    if not fp_path.exists():
        fp_path = index_dir / "functions.csv"
    fps = _csv_by_code_va(fp_path)
    hints = _csv_by_code_va(index_dir / "function_hints.csv")
    rows: List[Dict[str, object]] = []
    raw_count = 0
    thunk_count = 0
    matched = 0
    for match in _GHIDRA_C_FUNC_RE.finditer(text):
        name = match.group(1)
        code_va = int(match.group(2), 16)
        brace = text.find("{", match.start(), match.end())
        if brace < 0:
            continue
        end = _balanced_c_block_end(text, brace)
        block = text[match.start():end].rstrip() + "\n"
        kind = "thunk" if name.startswith("thunk_") else "function"
        if kind == "thunk":
            thunk_count += 1
        else:
            raw_count += 1
        fp = fps.get(code_va, {})
        hint = hints.get(code_va, {})
        if fp:
            matched += 1
        rel = Path("functions") / (name + ".c")
        (out / rel).write_text(block, encoding="utf-8")
        rows.append(
            {
                "name": name,
                "kind": kind,
                "code_va": _fmt_hex(code_va),
                "function_id": fp.get("sha_full", ""),
                "normalized_size": fp.get("size", ""),
                "source_files": hint.get("source_files", ""),
                "vtable_types": hint.get("vtable_types", ""),
                "output_file": rel.as_posix(),
            }
        )
    _write_csv(
        out / "ghidra_c_manifest.csv",
        ["name", "kind", "code_va", "function_id", "normalized_size", "source_files", "vtable_types", "output_file"],
        rows,
    )
    summary = {
        "schema": 1,
        "input_name": c_path.name,
        "functions": raw_count,
        "thunks": thunk_count,
        "total_blocks": len(rows),
        "matched_index_functions": matched,
    }
    (out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    return summary


def resolve_analyze_headless(ghidra: Path) -> Path:
    """Resolve a Ghidra installation directory or analyzeHeadless executable."""
    ghidra = ghidra.expanduser().resolve()
    candidates = [ghidra]
    if ghidra.is_dir():
        candidates = [
            ghidra / "support" / "analyzeHeadless",
            ghidra / "support" / "analyzeHeadless.bat",
            ghidra / "analyzeHeadless",
        ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    raise FileNotFoundError(f"could not find analyzeHeadless under {ghidra}")


def decompile_elf(path: Path, out: Path, ghidra: Path, timeout: int = 90, nid_db: Optional[Path] = None, scope: str = "hinted", limit: int = 0) -> Dict[str, object]:
    """Index an ELF and run Ghidra headlessly to export local pseudocode."""
    if scope not in {"hinted", "all"}:
        raise ValueError("scope must be hinted or all")
    if limit < 0:
        raise ValueError("limit must be >= 0")
    analyze_headless = resolve_analyze_headless(ghidra)
    out = out.resolve()
    index_dir = out / "index"
    decompiled_dir = out / "decompiled"
    project_dir = out / "ghidra-project"
    index_manifest = index_elf(path, index_dir, nid_db=nid_db)
    decompiled_dir.mkdir(parents=True, exist_ok=True)
    project_dir.mkdir(parents=True, exist_ok=True)
    script_dir = Path(__file__).resolve().parent / "ghidra"
    project_name = "gtdecomp_" + str(index_manifest["sha256"])[:12]
    cmd = [
        str(analyze_headless),
        str(project_dir),
        project_name,
        "-import",
        str(path.resolve()),
        "-overwrite",
        "-scriptPath",
        str(script_dir),
        "-postScript",
        "apply_gtdecomp_index.py",
        str(index_dir),
        "-postScript",
        "export_decompilation.py",
        str(index_dir),
        str(decompiled_dir),
        str(timeout),
        scope,
        str(limit),
    ]
    subprocess.run(cmd, check=True)
    manifest_path = decompiled_dir / "decompilation_manifest.csv"
    exported = 0
    failed = 0
    if manifest_path.exists():
        with manifest_path.open("r", newline="", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                if row.get("status") == "ok":
                    exported += 1
                elif row.get("status") == "failed":
                    failed += 1
    result = {
        "schema": 1,
        "input_sha256": index_manifest["sha256"],
        "index_dir": str(index_dir),
        "decompiled_dir": str(decompiled_dir),
        "ghidra_project_dir": str(project_dir),
        "exported_functions": exported,
        "failed_functions": failed,
        "scope": scope,
        "limit": limit,
    }
    (out / "decompile-summary.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


def main(argv: Optional[Sequence[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Index and compare Gran Turismo PS3 PPU executables")
    sub = ap.add_subparsers(dest="command", required=True)
    p_index = sub.add_parser("index", help="build a metadata database for one ELF")
    p_index.add_argument("elf", type=Path)
    p_index.add_argument("-o", "--out", type=Path, default=Path("analysis-out"))
    p_index.add_argument("--nid-db", type=Path, help="optional external PS3 NID name database")
    p_compare = sub.add_parser("compare", help="match functions between two ELF builds")
    p_compare.add_argument("reference", type=Path)
    p_compare.add_argument("target", type=Path)
    p_compare.add_argument("-o", "--out", type=Path, default=Path("compare-out"))
    p_import_c = sub.add_parser("import-ghidra-c", help="split an existing Ghidra C export and attach index metadata")
    p_import_c.add_argument("c_export", type=Path)
    p_import_c.add_argument("--index", type=Path, required=True, help="index directory produced by the index command")
    p_import_c.add_argument("-o", "--out", type=Path, default=Path("ghidra-c-out"))
    p_decompile = sub.add_parser("decompile", help="index an ELF and export Ghidra pseudocode headlessly")
    p_decompile.add_argument("elf", type=Path)
    p_decompile.add_argument("--ghidra", type=Path, required=True, help="Ghidra installation or analyzeHeadless path")
    p_decompile.add_argument("-o", "--out", type=Path, default=Path("decompile-out"))
    p_decompile.add_argument("--timeout", type=int, default=90, help="per-function Ghidra decompiler timeout in seconds")
    p_decompile.add_argument("--nid-db", type=Path, help="optional external PS3 NID name database")
    p_decompile.add_argument("--scope", choices=("hinted", "all"), default="hinted", help="functions to export; hinted is the practical first pass")
    p_decompile.add_argument("--limit", type=int, default=0, help="maximum functions to export (0 = no limit)")
    args = ap.parse_args(argv)

    if args.command == "index":
        result = index_elf(args.elf, args.out, nid_db=args.nid_db)
    elif args.command == "compare":
        result = compare_elfs(args.reference, args.target, args.out)
    elif args.command == "import-ghidra-c":
        result = import_ghidra_c(args.c_export, args.index, args.out)
    else:
        result = decompile_elf(args.elf, args.out, args.ghidra, timeout=args.timeout, nid_db=args.nid_db, scope=args.scope, limit=args.limit)
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
