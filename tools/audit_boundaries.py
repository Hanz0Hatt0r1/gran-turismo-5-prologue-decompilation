#!/usr/bin/env python3
"""Audit conservative PS3 PPU function-boundary heuristics.

A continuation suspect is deliberately narrow: only an unlinked direct branch
(LK=0) from before the first linear BLR into the post-BLR region is reported.
Linked branches (calls) are tracked separately.
"""
from __future__ import annotations

import argparse
import bisect
import csv
import json
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

from gtdecomp import PS3ELF, _is_stack_prologue, _ppc_branch_target, _u32, find_opd


def _conditional_branch_target(ins: int, va: int) -> Optional[int]:
    if ((ins >> 26) & 0x3F) != 16:
        return None
    disp = ins & 0x0000FFFC
    if disp & 0x00008000:
        disp -= 0x00010000
    return disp if ((ins >> 1) & 1) else va + disp


def direct_control_target(ins: int, va: int) -> Optional[int]:
    op = (ins >> 26) & 0x3F
    if op == 16:
        return _conditional_branch_target(ins, va)
    if op == 18:
        return _ppc_branch_target(ins, va)
    return None


def collect_control_flow(
    elf: PS3ELF,
) -> Tuple[List[Tuple[int, int, int, bool]], List[int], List[int]]:
    branches: List[Tuple[int, int, int, bool]] = []
    blrs: List[int] = []
    prologues: List[int] = []

    for ph in elf.program_headers:
        if ph.type != 1 or not (ph.flags & 1) or ph.filesz < 4:
            continue
        end = min(len(elf.data), ph.offset + ph.filesz)
        for off in range(ph.offset, end - 3, 4):
            va = ph.vaddr + (off - ph.offset)
            ins = _u32(elf.data, off)
            if ins == 0x4E800020:
                blrs.append(va)
            target = direct_control_target(ins, va)
            if target is not None and elf.in_executable_segment(target):
                branches.append((va, target, (ins >> 26) & 0x3F, bool(ins & 1)))
            if _is_stack_prologue(ins):
                prologues.append(va)

    branches.sort(key=lambda row: row[0])
    blrs.sort()
    prologues.sort()
    return branches, blrs, prologues


def first_linear_blr(
    blrs: Sequence[int], start: int, limit: Optional[int], max_size: int = 0x4000
) -> Optional[int]:
    hi = limit if limit is not None else start + max_size
    hi = min(hi, start + max_size)
    i = bisect.bisect_left(blrs, start)
    j = bisect.bisect_left(blrs, hi)
    return blrs[i] if i < j else None


def post_blr_targets(
    branches: Sequence[Tuple[int, int, int, bool]],
    start: int,
    blr: int,
    upper: int,
    sources: Optional[Sequence[int]] = None,
) -> List[Tuple[int, int, int, bool]]:
    source_index = sources if sources is not None else [row[0] for row in branches]
    i = bisect.bisect_left(source_index, start)
    j = bisect.bisect_left(source_index, blr)
    return [row for row in branches[i:j] if not row[3] and blr < row[1] < upper]


def audit(elf: PS3ELF) -> Dict[str, object]:
    _, descriptors = find_opd(elf)
    starts = sorted(set(d.code_va for d in descriptors))
    next_start = {
        va: starts[i + 1] if i + 1 < len(starts) else None
        for i, va in enumerate(starts)
    }

    branches, blrs, prologues = collect_control_flow(elf)
    sources = [row[0] for row in branches]

    nested_calls = 0
    nested_prologues = 0
    opd_overlaps = 0
    linked_post_blr_calls = 0
    suspects: List[Dict[str, object]] = []

    for start in starts:
        limit = next_start[start]
        blr = first_linear_blr(blrs, start, limit)
        upper = min(limit if limit is not None else start + 0x4000, start + 0x4000)

        if blr is None:
            p0 = bisect.bisect_right(prologues, start)
            p1 = bisect.bisect_left(prologues, upper)
            nested_prologues += max(0, p1 - p0)
            continue

        i = bisect.bisect_left(sources, start)
        j = bisect.bisect_left(sources, blr)
        prior = branches[i:j]

        linked_post_blr_calls += sum(
            1 for _, target, _, linked in prior if linked and blr < target < upper
        )

        for src, target, op, linked in post_blr_targets(
            branches, start, blr, upper, sources
        ):
            suspects.append(
                {
                    "function_va": f"0x{start:x}",
                    "first_blr_va": f"0x{blr:x}",
                    "next_opd_va": f"0x{limit:x}" if limit is not None else "",
                    "branch_source_va": f"0x{src:x}",
                    "branch_target_va": f"0x{target:x}",
                    "opcode": f"0x{op:x}",
                    "link": "1" if linked else "0",
                    "reason": "pre-blr unlinked direct branch reaches post-blr code",
                }
            )

        nested_calls += sum(
            1 for _, target, _, linked in prior if linked and start <= target < blr
        )
        p0 = bisect.bisect_right(prologues, start)
        p1 = bisect.bisect_left(prologues, blr)
        nested_prologues += max(0, p1 - p0)
        if limit is not None and limit < blr:
            opd_overlaps += 1

    return {
        "schema": 1,
        "tool": "audit_boundaries.py",
        "input_sha256": elf.sha256,
        "format": "ELF64-big-endian-PowerPC64",
        "entry_descriptor_va": f"0x{elf.entry:x}",
        "opd_descriptors": len(descriptors),
        "unique_opd_code": len(starts),
        "direct_control_transfers_to_exec": len(branches),
        "blr_count": len(blrs),
        "stack_prologue_count": len(prologues),
        "post_blr_continuation_functions": len({r["function_va"] for r in suspects}),
        "post_blr_continuation_edges": len(suspects),
        "post_blr_conditional_edges": sum(r["opcode"] == "0x10" for r in suspects),
        "post_blr_unconditional_edges": sum(r["opcode"] == "0x12" for r in suspects),
        "post_blr_linked_calls_excluded": linked_post_blr_calls,
        "nested_direct_call_targets_before_blr": nested_calls,
        "nested_stack_prologues_before_blr": nested_prologues,
        "opd_overlaps_before_first_blr": opd_overlaps,
        "examples": suspects[:20],
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Audit GT5/GT5P PPU function boundaries")
    ap.add_argument("elf", type=Path)
    ap.add_argument("-o", "--out", type=Path, default=Path("boundary-audit-out"))
    args = ap.parse_args()
    result = audit(PS3ELF(args.elf))
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "summary.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    with (args.out / "post_blr_suspects.csv").open("w", newline="", encoding="utf-8") as f:
        fields = [
            "function_va", "first_blr_va", "next_opd_va",
            "branch_source_va", "branch_target_va", "opcode", "link", "reason"
        ]
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(result["examples"])
    print(json.dumps({k: v for k, v in result.items() if k != "examples"}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
