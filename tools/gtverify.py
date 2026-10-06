#!/usr/bin/env python3
"""Verify reviewed GT5/GT5 Prologue metadata against a user-provided ELF."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

import gtcatalog
import gtdecomp


RANGE_RE = re.compile(r"^\s*(0x[0-9a-fA-F]+)\s*-\s*(0x[0-9a-fA-F]+)\s*$")


def _field(record: gtcatalog.CatalogRecord, key: str) -> Optional[Any]:
    return record.fields.get(key)


def _hex(value: Any) -> Optional[int]:
    normalized = gtcatalog.normalize_address(value)
    return int(normalized, 16) if normalized else None


def _parse_range(value: Any) -> Optional[Tuple[int, int]]:
    if value is None:
        return None
    match = RANGE_RE.fullmatch(str(value))
    if not match:
        return None
    start = int(match.group(1), 16)
    end = int(match.group(2), 16)
    return (start, end) if start < end and (end - start) % 4 == 0 else None


def _fingerprint_for_range(elf: gtdecomp.PS3ELF, start: int, end: int) -> Dict[str, Any]:
    off = elf.va_to_offset(start)
    if off is None or end <= start:
        raise ValueError(f"range 0x{start:x}-0x{end:x} is not file-backed")
    raw_words = []
    for rel in range(0, end - start, 4):
        raw_words.append(gtdecomp.normalize_ppc_instruction(gtdecomp._u32(elf.data, off + rel)))
    raw = b"".join(gtdecomp.struct.pack(">I", word) for word in raw_words)
    return {
        "size": end - start,
        "insns": len(raw_words),
        "sha_full": gtdecomp.hashlib.sha1(raw).hexdigest(),
        "sha_prefix": gtdecomp.hashlib.sha1(raw[: min(len(raw), 256)]).hexdigest(),
    }


def verify_build_record(elf: gtdecomp.PS3ELF, record: gtcatalog.CatalogRecord) -> Dict[str, Any]:
    checks: List[Dict[str, Any]] = []
    expected_sha = str(_field(record, "executable_sha256") or "").lower()
    checks.append({"check": "sha256", "expected": expected_sha, "actual": elf.sha256, "ok": expected_sha == elf.sha256})

    entry_expected = _hex(_field(record, "entry_descriptor_va"))
    checks.append({"check": "entry_descriptor_va", "expected": _hex(_field(record, "entry_descriptor_va")), "actual": elf.entry, "ok": entry_expected == elf.entry})

    code_expected = _hex(_field(record, "entry_code_va"))
    toc_expected = _hex(_field(record, "toc_va"))
    entry_off = elf.va_to_offset(elf.entry)
    actual_code = gtdecomp._u32(elf.data, entry_off) if entry_off is not None else None
    actual_toc = gtdecomp._u32(elf.data, entry_off + 4) if entry_off is not None else None
    checks.append({"check": "entry_code_va", "expected": code_expected, "actual": actual_code, "ok": code_expected == actual_code})
    checks.append({"check": "toc_va", "expected": toc_expected, "actual": actual_toc, "ok": toc_expected == actual_toc})

    return {
        "path": record.path,
        "kind": record.kind,
        "valid": all(item["ok"] for item in checks),
        "checks": checks,
    }


def verify_function_record(elf: gtdecomp.PS3ELF, record: gtcatalog.CatalogRecord) -> Dict[str, Any]:
    start = _hex(_field(record, "address.va"))
    checks: List[Dict[str, Any]] = []
    if start is None:
        return {"path": record.path, "kind": record.kind, "valid": False,
                "checks": [{"check": "address.va", "ok": False, "error": "invalid function address"}]}

    declared_range = _parse_range(_field(record, "provenance.disassembly.range"))
    if declared_range is None:
        ranges = gtdecomp.function_ranges_from_starts(elf, [start])
        declared_range = ranges[0] if ranges and ranges[0][0] == start else None

    if declared_range is None:
        return {"path": record.path, "kind": record.kind, "valid": False,
                "checks": [{"check": "range", "ok": False, "error": "no verifiable function range"}]}

    range_start, range_end = declared_range
    fp = _fingerprint_for_range(elf, range_start, range_end)
    checks.append({"check": "range_start", "expected": start, "actual": range_start, "ok": start == range_start})
    stored_full = _field(record, "fingerprints.normalized_full")
    checks.append({"check": "normalized_full", "expected": stored_full, "actual": fp["sha_full"], "ok": stored_full == fp["sha_full"]})
    stored_prefix = _field(record, "fingerprints.normalized_prefix")
    if stored_prefix is None:
        stored_prefix = _field(record, "fingerprints.normalized_prefix_256")
    if stored_prefix is not None:
        checks.append({"check": "normalized_prefix", "expected": stored_prefix, "actual": fp["sha_prefix"], "ok": stored_prefix == fp["sha_prefix"]})

    return {
        "path": record.path,
        "kind": record.kind,
        "valid": all(item["ok"] for item in checks),
        "range": {"start": range_start, "end": range_end, "size": fp["size"], "insns": fp["insns"]},
        "checks": checks,
    }


def verify(elf_path: Path, build_record: Optional[Path], function_records: Sequence[Path]) -> Dict[str, Any]:
    elf = gtdecomp.PS3ELF(elf_path)
    results: List[Dict[str, Any]] = []

    if build_record:
        record = gtcatalog.load_record(build_record, build_record.parent)
        results.append(verify_build_record(elf, record))

    for path in function_records:
        record = gtcatalog.load_record(path, path.parent)
        results.append(verify_function_record(elf, record))

    return {
        "valid": bool(results) and all(item["valid"] for item in results),
        "elf": {"path": str(elf_path), "sha256": elf.sha256, "entry": elf.entry},
        "records": results,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    cmd = sub.add_parser("verify")
    cmd.add_argument("--elf", required=True, type=Path)
    cmd.add_argument("--build-record", type=Path)
    cmd.add_argument("--function-record", action="append", default=[], type=Path)
    cmd.add_argument("--function-dir", action="append", default=[], type=Path)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parser().parse_args(argv)
    function_records = list(args.function_record)
    for directory in args.function_dir:
        function_records.extend(
            sorted(
                path for path in directory.rglob("*")
                if path.is_file() and path.suffix.lower() in {".yaml", ".yml", ".json"}
            )
        )
    try:
        result = verify(args.elf, args.build_record, function_records)
    except (OSError, ValueError, KeyError) as exc:
        print(json.dumps({"valid": False, "error": str(exc)}, indent=2, sort_keys=True))
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
