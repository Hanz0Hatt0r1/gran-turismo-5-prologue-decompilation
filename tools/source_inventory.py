#!/usr/bin/env python3
"""Extract source-file-name evidence from a PS3 PPU ELF.

Only retained source-file strings and their virtual addresses are exported.
The optional category is a conservative filename-keyword hint for research
triage; it is not a semantic assignment to a function or subsystem.
"""
from __future__ import annotations
import argparse
import bisect
import json
import re
from pathlib import Path
from typing import Dict, List, Tuple
from gtdecomp import PS3ELF

SOURCE_RE = re.compile(r"(?i)(?:^|[/\\])[^/\\\x00]{1,160}\.(?:c|cc|cpp|cxx)$")
RULES: Tuple[Tuple[str, Tuple[str, ...]], ...] = (
    ("networking", ("network", "online", "lobby", "matching", "np_")),
    ("audio", ("sound", "music", "audio")),
    ("replay", ("replay", "gps")),
    ("vehicle", ("car", "vehicle", "driver")),
    ("race", ("race", "eventrace", "umpire")),
    ("course", ("course", "track", "pathway", "circuit")),
    ("rendering", ("render", "shader", "scene", "paint", "texture", "mesh", "graphic", "camera")),
    ("input", ("input", "controller", "pad", "joystick")),
    ("save_profile", ("save", "profile", "storage")),
    ("ui", ("menu", "face", "dialog", "view", "option")),
    ("jobs_threads", ("job", "thread", "task")),
    ("resource_io", ("file", "stream", "resource", "archive", "reader", "writer", "pfs")),
    ("game", ("game",)),
)

def classify_source_name(name: str) -> str:
    lowered = name.lower()
    for category, needles in RULES:
        if any(needle in lowered for needle in needles):
            return category
    return "unclassified"

def toc_load_slot(ins: int, toc_va: int) -> Optional[Tuple[int, int]]:
    """Resolve a PPU lwz/ld using r2 as a TOC base into (slot_va, width)."""
    op = (ins >> 26) & 0x3F
    if op not in (32, 58):  # lwz / ld
        return None
    if ((ins >> 16) & 0x1F) != 2:  # rA must be r2 (TOC)
        return None
    disp = ins & 0xFFFF
    if disp & 0x8000:
        disp -= 0x10000
    return toc_va + disp, 8 if op == 58 else 4


def _read_u64_va(elf: PS3ELF, va: int) -> Optional[int]:
    off = elf.va_to_offset(va)
    if off is None or off + 8 > len(elf.data):
        return None
    return int.from_bytes(elf.data[off : off + 8], "big")


def extract_toc_source_xrefs(
    elf: PS3ELF,
    toc_va: int,
    source_files: List[Dict[str, object]],
) -> List[Dict[str, object]]:
    """Find executable TOC loads whose resolved slot points at a source string."""
    source_by_va = {int(str(row["va"]), 16): row for row in source_files}
    grouped: Dict[int, Dict[str, object]] = {}
    for section in elf.section_headers:
        if not (section.flags & 0x4) or section.size < 4:
            continue
        for rel in range(0, section.size - 3, 4):
            ins_va = section.addr + rel
            ins = elf.read_u32_va(ins_va)
            if ins is None:
                continue
            resolved = toc_load_slot(ins, toc_va)
            if resolved is None:
                continue
            slot_va, width = resolved
            value = elf.read_u32_va(slot_va)
            candidates = []
            if value is not None:
                candidates.append(value)
            if width == 8:
                wide = _read_u64_va(elf, slot_va)
                if wide is not None:
                    candidates.append(wide)
            for source_va in dict.fromkeys(candidates):
                source = source_by_va.get(source_va)
                if source is None:
                    continue
                row = grouped.setdefault(
                    source_va,
                    {
                        "source_va": source["va"],
                        "name": source["name"],
                        "category": source["category"],
                        "toc_slot_va": f"0x{slot_va:08x}",
                        "instruction_vas": [],
                        "confidence": "probable",
                        "evidence": "toc-load-slot",
                    },
                )
                row["instruction_vas"].append(f"0x{ins_va:08x}")
    for row in grouped.values():
        row["instruction_vas"] = sorted(
            set(row["instruction_vas"]),
            key=lambda value: int(value, 16),
        )
        row["xref_count"] = len(row["instruction_vas"])
    return sorted(
        grouped.values(),
        key=lambda row: (str(row["category"]), str(row["name"]), int(str(row["source_va"]), 16)),
    )

def map_toc_xrefs_to_opd_functions(
    toc_xrefs: List[Dict[str, object]],
    function_ranges: List[Tuple[int, int]],
) -> List[Dict[str, object]]:
    """Map contained source-string xrefs onto their OPD-derived function ranges."""
    starts = [start for start, _ in function_ranges]
    grouped: Dict[int, Dict[str, object]] = {}
    for row in toc_xrefs:
        for value in row["instruction_vas"]:
            va = int(str(value), 16)
            i = bisect.bisect_right(starts, va) - 1
            if i < 0 or not (function_ranges[i][0] <= va < function_ranges[i][1]):
                continue
            start, end = function_ranges[i]
            entry = grouped.setdefault(
                start,
                {
                    "function_start_va": f"0x{start:08x}",
                    "function_end_va": f"0x{end:08x}",
                    "xref_count": 0,
                    "source_names": set(),
                    "source_categories": set(),
                    "confidence": "probable",
                    "evidence": "TOC source-string xref contained in OPD-derived function range",
                },
            )
            entry["xref_count"] += 1
            entry["source_names"].add(str(row["name"]))
            entry["source_categories"].add(str(row["category"]))
    rows = list(grouped.values())
    for row in rows:
        row["source_names"] = sorted(row["source_names"])
        row["source_categories"] = sorted(row["source_categories"])
    return sorted(rows, key=lambda row: int(str(row["function_start_va"]), 16))

def summarize_opd_containment(
    toc_xrefs: List[Dict[str, object]],
    function_ranges: List[Tuple[int, int]],
) -> Dict[str, int]:
    """Summarize which TOC-xref instructions fall inside OPD-derived ranges."""
    starts = [start for start, _ in function_ranges]
    contained = 0
    unique_functions = set()
    total = 0
    for row in toc_xrefs:
        for value in row["instruction_vas"]:
            total += 1
            va = int(str(value), 16)
            i = bisect.bisect_right(starts, va) - 1
            if i >= 0 and function_ranges[i][0] <= va < function_ranges[i][1]:
                contained += 1
                unique_functions.add(function_ranges[i][0])
    return {
        "xref_instruction_count": total,
        "contained_xref_instruction_count": contained,
        "uncontained_xref_instruction_count": total - contained,
        "unique_functions_touched": len(unique_functions),
    }

def extract_source_files(elf: PS3ELF) -> List[Dict[str, object]]:
    rows: List[Dict[str, object]] = []
    seen = set()
    for va, value in elf.iter_ascii_strings(min_len=4, alloc_only=True):
        if not SOURCE_RE.search(value):
            continue
        key = (va, value)
        if key in seen:
            continue
        seen.add(key)
        rows.append({"va": f"0x{va:08x}", "name": value, "category": classify_source_name(value)})
    return sorted(rows, key=lambda row: (str(row["category"]), str(row["name"]), str(row["va"])))

def build_report(elf: PS3ELF) -> Dict[str, object]:
    files = extract_source_files(elf)
    counts: Dict[str, int] = {}
    for row in files:
        cat = str(row["category"])
        counts[cat] = counts.get(cat, 0) + 1
    toc_va, descriptors = find_opd(elf)
    toc_xrefs = extract_toc_source_xrefs(elf, toc_va, files)
    opd_ranges = function_ranges_from_starts(elf, (d.code_va for d in descriptors))
    opd_containment = summarize_opd_containment(toc_xrefs, opd_ranges)
    opd_function_map = map_toc_xrefs_to_opd_functions(toc_xrefs, opd_ranges)
    return {
        "schema": 1,
        "tool": "source_inventory.py",
        "module": elf.path.name,
        "input_sha256": elf.sha256,
        "format": "ELF64-big-endian-PowerPC64",
        "toc_va": f"0x{toc_va:08x}",
        "method": {
            "source_string_pattern": SOURCE_RE.pattern,
            "scope": "printable ASCII strings in allocated ELF data",
            "classification": "conservative filename-keyword grouping for research triage",
            "semantic_status": "evidence-only; category does not assign function ownership",
            "toc_xref_pattern": "PPU lwz/ld using r2, resolving a TOC slot to a retained source-string VA",
        },
        "source_file_count": len(files),
        "counts": dict(sorted(counts.items())),
        "toc_xref_count": sum(int(row["xref_count"]) for row in toc_xrefs),
        "toc_referenced_source_file_count": len(toc_xrefs),
        "toc_referenced_category_counts": dict(sorted(
            Counter(str(row["category"]) for row in toc_xrefs).items()
        )),
        "opd_range_mapping": {
            **opd_containment,
            "function_range_count": len(opd_ranges),
            "range_method": "OPD-derived starts with first linear blr end marker",
        },
        "opd_function_source_map_count": len(opd_function_map),
        "opd_function_source_map": opd_function_map,
        "files": files,
        "toc_xrefs": toc_xrefs,
    }

def main() -> int:
    parser = argparse.ArgumentParser(description="Extract source-file-name evidence from a PS3 PPU ELF")
    parser.add_argument("elf", type=Path)
    parser.add_argument("-o", "--out", type=Path, default=Path("source-inventory.json"))
    args = parser.parse_args()
    report = build_report(PS3ELF(args.elf))
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({k: v for k, v in report.items() if k != "files"}, indent=2))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
