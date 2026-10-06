#!/usr/bin/env python3
"""Audit conservative PS3 PPU function-boundary heuristics.

This tool consumes a user-provided decrypted PS3 PPU ELF and emits only
derived boundary evidence. It does not copy executable bytes to the output.

The audit is intentionally non-destructive: it reports places where the
current first-linear-Return (blr) rule deserves review, rather than changing
the function discovery algorithm automatically.
"""

from __future__ import annotations

import argparse
import bisect
import csv
import json
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from gtdecomp import PS3ELF, _is_stack_prologue, _ppc_branch_target, _u32, find_opd


def _conditional_branch_target(ins: int, va: int) -> Optional[int]:
    """Decode a PPC64 conditional direct branch (bc/bcl family)."""
    if ((ins >> 26) & 0x3F) != 16:
        return None
    disp = ins & 0x0000FFFC
    if disp & 0x00008000:
        disp -= 0x00010000
    return disp if ((ins >> 1) & 1) else va + disp


def direct_control_target(ins: int, va: int) -> Optional[int]:
    """Return the target of a direct b/bc-class control transfer."""
    op = (ins >> 26) & 0x3F
    if op == 16:
        return _conditional_branch_target(ins, va)
    if op == 18:
        return _ppc_branch_target(ins, va)
    return None


def collect_control_flow(elf: PS3ELF) -> Tuple[List[Tuple[int, int, int, bool]], List[int], List[int]]:
    """Collect direct control transfers, linear returns, and stack prologues."""
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


def first_linear_blr(blrs: Sequence[int], start: int, limit: Optional[int], max_size: int = 0x4000) -> Optional[int]:
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
    """Find direct branches from before the first blr into the post-blr region."""
    source_index = sources if sources is not None else [row[0] for row in branches]
    i = bisect.bisect_left(source_index, start)
    j = bisect.bisect_left(source_index, blr)
    return [row for row in branches[i:j] if blr < row[1] < upper]


def audit(elf: PS3ELF) -> Dict[str, object]:
    toc, descriptors = find_opd(elf)
    del toc
    opd_starts = sorted(set(d.code_va for d in descriptors))
    next_start = {
        va: opd_starts[i + 1] if i + 1 < len(opd_starts) else None
        for i, va in enumerate(opd_starts)
    }

    branches, blrs, prologues = collect_control_flow(elf)
    branch_sources = [row[0] for row in branches]

    nested_calls = 0
    nested_prologues = 0
    opd_overlaps = 0
    continuation_suspects: List[Dict[str, object]] = []

    for start in opd_starts:
        limit = next_start[start]
        blr = first_linear_blr(blrs, start, limit)
        upper = min(limit if limit is not None else start + 0x4000, start + 0x4000)

        if blr is not None:
            post = post_blr_targets(branches, start, blr, upper, branch_sources)
            for src, target, op, linked in post:
                continuation_suspects.append(
                    {
                        "function_va": f"0x{start:x}",
                        "first_blr_va": f"0x{blr:x}",
                        "next_opd_va": f"0x{limit:x}" if limit is not None else "",
                        "branch_source_va": f"0x{src:x}",
                        "branch_target_va": f"0x{target:x}",
                        "opcode": f"0x{op:x}",
                        "link": "1" if linked else "0",
                        "reason": "pre-blr direct control transfer reaches post-blr code",
                    }
                )

            i = bisect.bisect_left(branch_sources, start)
            j = bisect.bisect_left(branch_sources, blr)
            nested_calls += sum(
                1
                for src, target, op, linked in branches[i:j]
                if linked and start <= target < blr
            )

            p0 = bisect.bisect_right(prologues, start)
            p1 = bisect.bisect_left(prologues, blr)
            nested_prologues += max(0, p1 - p0)
            if limit is not None and limit < blr:
                opd_overlaps += 1
        else:
            p0 = bisect.bisect_right(prologues, start)
            p1 = bisect.bisect_left(prologues, upper)
            nested_prologues += max(0, p1 - p0)

    continuation_functions = len({row["function_va"] for row in continuation_suspects})
    conditional_edges = sum(row["opcode"] == "0x10" for row in continuation_suspects)
    unconditional_edges = sum(row["opcode"] == "0x12" for row in continuation_suspects)

    return {
        "schema": 1,
        "tool": "audit_boundaries.py",
        "input_sha256": elf.sha256,
        "format": "ELF64-big-endian-PowerPC64",
        "entry_descriptor_va": f"0x{elf.entry:x}",
        "opd_descriptors": len(descriptors),
        "unique_opd_code": len(opd_starts),
        "direct_control_transfers_to_exec": len(branches),
        "blr_count": len(blrs),
        "stack_prologue_count": len(prologues),
        "post_blr_continuation_functions": continuation_functions,
        "post_blr_continuation_edges": len(continuation_suspects),
        "post_blr_conditional_edges": conditional_edges,
        "post_blr_unconditional_edges": unconditional_edges,
        "nested_direct_call_targets_before_blr": nested_calls,
        "nested_stack_prologues_before_blr": nested_prologues,
        "opd_overlaps_before_first_blr": opd_overlaps,
        "examples": continuation_suspects[:20],
        "suspects": continuation_suspects,
        "note": (
            "A continuation suspect is evidence that the first linear blr may be an "
            "early return rather than a global function terminator. The tool does not "
            "alter function boundaries automatically."
        ),
    }


def write_outputs(result: Dict[str, object], out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    (out / "summary.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    rows = list(result["suspects"])
    with (out / "post_blr_suspects.csv").open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "function_va",
                "first_blr_va",
                "next_opd_va",
                "branch_source_va",
                "branch_target_va",
                "opcode",
                "link",
                "reason",
            ],
        )
        writer.writeheader()
        writer.writerows(rows)


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Audit GT5/GT5P PPU function boundaries")
    parser.add_argument("elf", type=Path)
    parser.add_argument("-o", "--out", type=Path, default=Path("boundary-audit-out"))
    args = parser.parse_args(argv)

    result = audit(PS3ELF(args.elf))
    write_outputs(result, args.out)
    print(json.dumps({k: v for k, v in result.items() if k not in {"examples", "suspects"}}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
