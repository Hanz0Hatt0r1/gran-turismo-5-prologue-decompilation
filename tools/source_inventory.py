#!/usr/bin/env python3
"""Extract source-file-name evidence from a PS3 PPU ELF.

Only retained source-file strings and their virtual addresses are exported.
The optional category is a conservative filename-keyword hint for research
triage; it is not a semantic assignment to a function or subsystem.
"""
from __future__ import annotations
import argparse
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
    return {
        "schema": 1,
        "tool": "source_inventory.py",
        "module": elf.path.name,
        "input_sha256": elf.sha256,
        "format": "ELF64-big-endian-PowerPC64",
        "method": {
            "source_string_pattern": SOURCE_RE.pattern,
            "scope": "printable ASCII strings in allocated ELF data",
            "classification": "conservative filename-keyword grouping for research triage",
            "semantic_status": "evidence-only; category does not assign function ownership",
        },
        "source_file_count": len(files),
        "counts": dict(sorted(counts.items())),
        "files": files,
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
