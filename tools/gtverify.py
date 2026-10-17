#!/usr/bin/env python3
"""Verify reviewed GT5/GT5 Prologue metadata against a user-provided ELF."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

import gtcatalog
import gtdecomp
import source_inventory


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


def verify_source_xref_function_map(elf: gtdecomp.PS3ELF, map_path: Path) -> Dict[str, Any]:
    """Verify a derived source-xref function map against the same ELF."""
    snapshot = json.loads(map_path.read_text(encoding="utf-8"))
    report = source_inventory.build_report(elf)
    checks: List[Dict[str, Any]] = []

    checks.append({"check": "sha256", "expected": snapshot.get("input_sha256"), "actual": elf.sha256, "ok": snapshot.get("input_sha256") == elf.sha256})
    for field in ("source_file_count", "toc_xref_instruction_count", "opd_contained_xref_count", "uncontained_xref_count", "opd_function_range_count"):
        expected = snapshot.get(field)
        actual = report.get(field) if field != "opd_contained_xref_count" else report.get("opd_range_mapping", {}).get("contained_xref_instruction_count")
        if field == "toc_xref_instruction_count":
            actual = report.get("opd_range_mapping", {}).get("xref_instruction_count")
        elif field == "uncontained_xref_count":
            actual = report.get("opd_range_mapping", {}).get("uncontained_xref_instruction_count")
        elif field == "opd_function_range_count":
            actual = report.get("opd_range_mapping", {}).get("function_range_count")
        elif field == "source_file_count":
            actual = report.get("source_file_count")
        checks.append({"check": field, "expected": expected, "actual": actual, "ok": expected == actual})

    stored = snapshot.get("functions", [])
    actual_full = report.get("opd_function_source_map", [])
    actual = [
        {
            "function_start_va": row.get("function_start_va"),
            "function_end_va": row.get("function_end_va"),
            "xref_count": row.get("xref_count"),
            "source_names": row.get("source_names", []),
            "source_categories": row.get("source_categories", []),
        }
        for row in actual_full
    ]
    checks.append({"check": "function_map", "expected_count": len(stored), "actual_count": len(actual), "ok": stored == actual})
    return {
        "path": str(map_path),
        "kind": "source-xref-function-map",
        "valid": all(item["ok"] for item in checks),
        "checks": checks,
    }

def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_build_record(
    elf: gtdecomp.PS3ELF,
    record: gtcatalog.CatalogRecord,
    container_path: Optional[Path] = None,
) -> Dict[str, Any]:
    checks: List[Dict[str, Any]] = []
    expected_sha = str(_field(record, "executable_sha256") or "").lower()
    sha_scope = str(_field(record, "executable_sha256_scope") or "elf").lower()
    if sha_scope == "elf":
        checks.append({"check": "sha256", "scope": "elf", "expected": expected_sha, "actual": elf.sha256, "ok": expected_sha == elf.sha256})
    elif sha_scope == "container":
        if container_path is None:
            checks.append({
                "check": "container_sha256",
                "expected": expected_sha,
                "actual": None,
                "status": "not_checked",
                "reason": "this build record hashes the outer executable container; pass --container",
                "ok": False,
            })
        else:
            actual_sha = _sha256_file(container_path)
            checks.append({
                "check": "container_sha256",
                "path": str(container_path),
                "expected": expected_sha,
                "actual": actual_sha,
                "ok": expected_sha == actual_sha,
            })
    else:
        checks.append({
            "check": "executable_sha256_scope",
            "expected": "elf or container",
            "actual": sha_scope,
            "ok": False,
        })

    entry_expected = _hex(_field(record, "entry_descriptor_va"))
    checks.append({"check": "entry_descriptor_va", "expected": _hex(_field(record, "entry_descriptor_va")), "actual": elf.entry, "ok": entry_expected == elf.entry})

    code_expected = _hex(_field(record, "entry_code_va"))
    toc_expected = _hex(_field(record, "toc_va"))
    entry_off = elf.va_to_offset(elf.entry)
    actual_code = gtdecomp._u32(elf.data, entry_off) if entry_off is not None else None
    actual_toc = gtdecomp._u32(elf.data, entry_off + 4) if entry_off is not None else None
    checks.append({"check": "entry_code_va", "expected": code_expected, "actual": actual_code, "ok": code_expected == actual_code})
    checks.append({"check": "toc_va", "expected": toc_expected, "actual": actual_toc, "ok": toc_expected == actual_toc})

    result = {
        "path": record.path,
        "kind": record.kind,
        "valid": all(item["ok"] for item in checks),
        "checks": checks,
    }
    if sha_scope == "container":
        result["notes"] = [
            "The container digest and ELF metadata are checked independently; this does not prove the ELF was extracted from the supplied container."
        ]
    return result


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


def verify(
    elf_path: Path,
    build_record: Optional[Path],
    function_records: Sequence[Path],
    source_xref_map: Optional[Path] = None,
    container_path: Optional[Path] = None,
) -> Dict[str, Any]:
    if container_path is not None and build_record is None:
        raise ValueError("--container requires --build-record")
    elf = gtdecomp.PS3ELF(elf_path)
    results: List[Dict[str, Any]] = []

    if build_record:
        record = gtcatalog.load_record(build_record, build_record.parent)
        results.append(verify_build_record(elf, record, container_path))

    for path in function_records:
        record = gtcatalog.load_record(path, path.parent)
        results.append(verify_function_record(elf, record))

    if source_xref_map:
        results.append(verify_source_xref_function_map(elf, source_xref_map))

    return {
        "valid": bool(results) and all(item["valid"] for item in results),
        "elf": {"path": str(elf_path), "sha256": elf.sha256, "entry": elf.entry},
        "records": results,
    }


def _read_csv(path: Path) -> Tuple[List[str], List[Dict[str, str]]]:
    with path.open("r", newline="", encoding="utf-8") as source:
        reader = csv.DictReader(source)
        return list(reader.fieldnames or []), list(reader)


def _build_identity(record: gtcatalog.CatalogRecord) -> Tuple[str, str]:
    build = str(_field(record, "title_id") or _field(record, "build") or "")
    module = str(_field(record, "module") or "")
    return build, module


def verify_crossref_records(
    crossref_dir: Path,
    reference: gtdecomp.PS3ELF,
    target: gtdecomp.PS3ELF,
    reference_build: gtcatalog.CatalogRecord,
    target_build: gtcatalog.CatalogRecord,
    generated_rows: Sequence[Dict[str, str]],
) -> Dict[str, Any]:
    """Check relevant cross-build records against both ELFs and the regenerated match set."""
    reference_id, reference_module = _build_identity(reference_build)
    target_id, target_module = _build_identity(target_build)
    generated = {
        (row.get("reference_code_va", "").lower(), row.get("target_code_va", "").lower(), row.get("method", ""))
        for row in generated_rows
    }
    checks: List[Dict[str, Any]] = []

    for record in gtcatalog.iter_records(crossref_dir):
        if record.kind != "crossref":
            continue
        ref_id = str(_field(record, "reference.build") or "")
        record_target_id = str(_field(record, "target.build") or "")
        if ref_id == reference_id and record_target_id == target_id:
            ref_elf, tgt_elf = reference, target
            expected_ref_module, expected_target_module = reference_module, target_module
            ref_address = _hex(_field(record, "reference.va"))
            target_address = _hex(_field(record, "target.va"))
        elif ref_id == target_id and record_target_id == reference_id:
            ref_elf, tgt_elf = target, reference
            expected_ref_module, expected_target_module = target_module, reference_module
            ref_address = _hex(_field(record, "reference.va"))
            target_address = _hex(_field(record, "target.va"))
        else:
            continue

        record_reference_module = str(_field(record, "reference.module") or "")
        record_target_module = str(_field(record, "target.module") or "")
        method = str(_field(record, "method") or "")
        ok = (
            ref_address is not None
            and target_address is not None
            and record_reference_module.casefold() == expected_ref_module.casefold()
            and record_target_module.casefold() == expected_target_module.casefold()
            and ref_elf.in_executable_segment(ref_address)
            and tgt_elf.in_executable_segment(target_address)
        )
        if ok and method in {"normalized-full", "normalized-prefix"}:
            pair = (f"0x{ref_address:08x}", f"0x{target_address:08x}", method)
            ok = pair in generated
            if not ok:
                reverse_pair = (pair[1], pair[0], method)
                ok = reverse_pair in generated
        checks.append({
            "path": record.path,
            "method": method,
            "reference_va": ref_address,
            "target_va": target_address,
            "valid": bool(ok),
        })

    return {
        "valid": all(item["valid"] for item in checks),
        "checked": len(checks),
        "records": checks,
    }


def verify_cross_build(
    reference_elf_path: Path,
    reference_build_path: Path,
    target_elf_path: Path,
    target_build_path: Path,
    candidate_csv: Path,
) -> Dict[str, Any]:
    """Rebuild a cross-build match report and compare it with committed evidence."""
    reference = gtdecomp.PS3ELF(reference_elf_path)
    target = gtdecomp.PS3ELF(target_elf_path)
    reference_build = gtcatalog.load_record(reference_build_path, reference_build_path.parent)
    target_build = gtcatalog.load_record(target_build_path, target_build_path.parent)
    reference_check = verify_build_record(reference, reference_build)
    target_check = verify_build_record(target, target_build)
    catalog_records = [reference_build, target_build, *gtcatalog.iter_records(candidate_csv.parent)]
    catalog_check = gtcatalog.validate_records(catalog_records)

    with tempfile.TemporaryDirectory(prefix="gt5-cross-build-verify-") as temporary:
        comparison = gtdecomp.compare_elfs(reference_elf_path, target_elf_path, Path(temporary))
        generated_csv = Path(temporary) / "function_matches.csv"
        expected_fields, expected_rows = _read_csv(candidate_csv)
        generated_fields, generated_rows = _read_csv(generated_csv)
        csv_matches = expected_fields == generated_fields and expected_rows == generated_rows
        differences: List[Dict[str, Any]] = []
        if expected_fields != generated_fields:
            differences.append({
                "kind": "header",
                "expected": expected_fields,
                "actual": generated_fields,
            })
        for index, (expected, actual) in enumerate(zip(expected_rows, generated_rows)):
            if expected != actual:
                differences.append({"kind": "row", "index": index, "expected": expected, "actual": actual})
                if len(differences) >= 5:
                    break
        if len(expected_rows) != len(generated_rows):
            differences.append({
                "kind": "row_count",
                "expected": len(expected_rows),
                "actual": len(generated_rows),
            })

        crossrefs = verify_crossref_records(
            candidate_csv.parent,
            reference,
            target,
            reference_build,
            target_build,
            generated_rows,
        )

    return {
        "valid": (
            reference_check["valid"]
            and target_check["valid"]
            and catalog_check["valid"]
            and csv_matches
            and crossrefs["valid"]
        ),
        "catalog": catalog_check,
        "reference": {
            "elf": str(reference_elf_path),
            "sha256": reference.sha256,
            "build_record": reference_check,
        },
        "target": {
            "elf": str(target_elf_path),
            "sha256": target.sha256,
            "build_record": target_check,
        },
        "comparison": comparison,
        "candidate_csv": {
            "path": str(candidate_csv),
            "valid": csv_matches,
            "committed_rows": len(expected_rows),
            "regenerated_rows": len(generated_rows),
            "differences": differences,
        },
        "crossrefs": crossrefs,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    cmd = sub.add_parser("verify")
    cmd.add_argument("--elf", required=True, type=Path)
    cmd.add_argument("--build-record", type=Path)
    cmd.add_argument("--container", type=Path, help="outer executable container when the build record hashes a container")
    cmd.add_argument("--function-record", action="append", default=[], type=Path)
    cmd.add_argument("--function-dir", action="append", default=[], type=Path)
    cmd.add_argument("--source-xref-function-map", type=Path)
    cross = sub.add_parser("cross-build", help="verify both ELF profiles and regenerate their committed match CSV")
    cross.add_argument("--reference-elf", required=True, type=Path)
    cross.add_argument("--reference-build-record", required=True, type=Path)
    cross.add_argument("--target-elf", required=True, type=Path)
    cross.add_argument("--target-build-record", required=True, type=Path)
    cross.add_argument("--candidate-csv", required=True, type=Path)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "cross-build":
        try:
            result = verify_cross_build(
                args.reference_elf,
                args.reference_build_record,
                args.target_elf,
                args.target_build_record,
                args.candidate_csv,
            )
        except (OSError, ValueError, KeyError) as exc:
            print(json.dumps({"valid": False, "error": str(exc)}, indent=2, sort_keys=True))
            return 2
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result["valid"] else 1

    function_records = list(args.function_record)
    for directory in args.function_dir:
        function_records.extend(
            sorted(
                path for path in directory.rglob("*")
                if path.is_file() and path.suffix.lower() in {".yaml", ".yml", ".json"}
            )
        )
    try:
        result = verify(args.elf, args.build_record, function_records, args.source_xref_function_map, args.container)
    except (OSError, ValueError, KeyError) as exc:
        print(json.dumps({"valid": False, "error": str(exc)}, indent=2, sort_keys=True))
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
