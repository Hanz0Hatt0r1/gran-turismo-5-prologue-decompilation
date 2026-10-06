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


INDEX_REQUIRED_MANIFEST = ("schema", "sha256", "format", "entry_descriptor_va", "entry_code_va", "toc_va", "discovered_function_addresses")
VALID_MATCH_METHODS = {"normalized-full", "normalized-prefix", "manual", "callgraph", "rtti-vtable", "import-context"}
VALID_REVIEW_STATUSES = {"candidate", "pending", "accepted", "rejected"}
VALID_MATCH_CONFIDENCES = {"confirmed", "probable", "speculative"}

def _read_index_functions(index_dir: Path) -> Tuple[set, List[str]]:
    path = index_dir / "discovered_functions.csv"
    if not path.is_file():
        return set(), [f"missing discovered_functions.csv: {index_dir}"]
    rows = list(csv.DictReader(path.read_text(encoding="utf-8").splitlines()))
    addresses = set()
    errors: List[str] = []
    digest_re = re.compile(r"^[0-9a-fA-F]{40}$")
    for row in rows:
        address = gtcatalog.normalize_address(row.get("code_va"))
        if address is None:
            errors.append(f"invalid code_va: {row.get('code_va')}")
            continue
        if address in addresses:
            errors.append(f"duplicate discovered function address: {address}")
        addresses.add(address)
        try:
            size = int(row.get("size", ""), 10)
            insns = int(row.get("insns", ""), 10)
        except ValueError:
            errors.append(f"invalid size/insns at {address}")
            continue
        if size <= 0 or size % 4 or insns != size // 4:
            errors.append(f"invalid size/insns relationship at {address}")
        for field in ("sha_full", "sha_prefix"):
            if not digest_re.fullmatch(row.get(field, "")):
                errors.append(f"invalid {field} at {address}")
    return addresses, errors

def verify_index_dir(index_dir: Path, build_record: Optional[Path] = None) -> Dict[str, Any]:
    manifest_path = index_dir / "manifest.json"
    if not manifest_path.is_file():
        return {"path": str(index_dir), "valid": False, "checks": [{"check": "manifest", "ok": False, "error": "missing manifest.json"}]}
    manifest = _load_json(manifest_path)
    checks: List[Dict[str, Any]] = []
    errors: List[str] = []
    for field in INDEX_REQUIRED_MANIFEST:
        checks.append({"check": f"manifest.{field}", "ok": field in manifest and manifest[field] not in (None, ""), "value": manifest.get(field)})
    digest = str(manifest.get("sha256", ""))
    checks.append({"check": "manifest.sha256_format", "ok": bool(re.fullmatch(r"[0-9a-fA-F]{64}", digest))})
    for field in ("entry_descriptor_va", "entry_code_va", "toc_va"):
        checks.append({"check": f"manifest.{field}.format", "ok": _hex(manifest.get(field)) is not None})
    addresses, function_errors = _read_index_functions(index_dir)
    errors.extend(function_errors)
    expected_count = manifest.get("discovered_function_addresses")
    checks.append({"check": "discovered_function_count", "expected": expected_count, "actual": len(addresses), "ok": expected_count == len(addresses)})
    if build_record:
        record = gtcatalog.load_record(build_record, build_record.parent)
        expected_sha = str(_field(record, "executable_sha256") or "").lower()
        checks.append({"check": "build_record.sha256", "expected": expected_sha, "actual": digest.lower(), "ok": expected_sha == digest.lower()})
        for field in ("entry_descriptor_va", "entry_code_va", "toc_va"):
            expected = gtcatalog.normalize_address(_field(record, field))
            actual = gtcatalog.normalize_address(manifest.get(field))
            checks.append({"check": f"build_record.{field}", "expected": expected, "actual": actual, "ok": expected == actual})
    return {"path": str(index_dir), "kind": "index", "valid": not errors and all(x["ok"] for x in checks), "manifest": manifest, "checks": checks, "errors": errors, "function_addresses": len(addresses)}

def verify_compare_indexes(reference_index: Path, target_index: Path, match_csv: Optional[Path] = None, summary_path: Optional[Path] = None, reference_build_record: Optional[Path] = None, target_build_record: Optional[Path] = None) -> Dict[str, Any]:
    reference = verify_index_dir(reference_index, reference_build_record)
    target = verify_index_dir(target_index, target_build_record)
    checks: List[Dict[str, Any]] = []
    rows: List[Dict[str, str]] = []
    if match_csv:
        if not match_csv.is_file():
            checks.append({"check": "function_matches.csv", "ok": False, "error": "missing file"})
        else:
            rows = list(csv.DictReader(match_csv.read_text(encoding="utf-8").splitlines()))
            ref_addrs, ref_errors = _read_index_functions(reference_index)
            tgt_addrs, tgt_errors = _read_index_functions(target_index)
            row_errors = list(ref_errors) + list(tgt_errors)
            for row in rows:
                ref = gtcatalog.normalize_address(row.get("reference_code_va"))
                tgt = gtcatalog.normalize_address(row.get("target_code_va"))
                if ref not in ref_addrs: row_errors.append(f"reference address not in index: {row.get('reference_code_va')}")
                if tgt not in tgt_addrs: row_errors.append(f"target address not in index: {row.get('target_code_va')}")
                if row.get("method") not in VALID_MATCH_METHODS: row_errors.append(f"unsupported method: {row.get('method')}")
                if row.get("review_status") not in VALID_REVIEW_STATUSES: row_errors.append(f"unsupported review_status: {row.get('review_status')}")
                if row.get("evidence_confidence") not in VALID_MATCH_CONFIDENCES: row_errors.append(f"unsupported evidence_confidence: {row.get('evidence_confidence')}")
                try:
                    score = int(row.get("evidence_score", ""), 10)
                    if score < 0 or score > 100: raise ValueError
                except ValueError:
                    row_errors.append(f"invalid evidence_score: {row.get('evidence_score')}")
            checks.append({"check": "function_matches.csv", "row_count": len(rows), "ok": not row_errors, "errors": row_errors})
    if summary_path:
        if not summary_path.is_file():
            checks.append({"check": "summary.json", "ok": False, "error": "missing file"})
        else:
            summary = _load_json(summary_path)
            checks.append({"check": "summary.reference_sha256", "expected": reference.get("manifest", {}).get("sha256"), "actual": summary.get("reference_sha256"), "ok": summary.get("reference_sha256") == reference.get("manifest", {}).get("sha256")})
            checks.append({"check": "summary.target_sha256", "expected": target.get("manifest", {}).get("sha256"), "actual": summary.get("target_sha256"), "ok": summary.get("target_sha256") == target.get("manifest", {}).get("sha256")})
            if match_csv: checks.append({"check": "summary.matches", "expected": summary.get("matches"), "actual": len(rows), "ok": summary.get("matches") == len(rows)})
    return {"valid": reference["valid"] and target["valid"] and all(x["ok"] for x in checks), "reference": reference, "target": target, "checks": checks}
def _load_json(path: Path) -> Dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict): raise ValueError(f"expected JSON object: {path}")
    return value

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


def verify(elf_path: Path, build_record: Optional[Path], function_records: Sequence[Path], source_xref_map: Optional[Path] = None) -> Dict[str, Any]:
    elf = gtdecomp.PS3ELF(elf_path)
    results: List[Dict[str, Any]] = []

    if build_record:
        record = gtcatalog.load_record(build_record, build_record.parent)
        results.append(verify_build_record(elf, record))

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


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    cmd = sub.add_parser("verify")
    cmd.add_argument("--elf", required=True, type=Path)
    cmd.add_argument("--build-record", type=Path)
    cmd.add_argument("--function-record", action="append", default=[], type=Path)
    cmd.add_argument("--function-dir", action="append", default=[], type=Path)
    cmd.add_argument("--source-xref-function-map", type=Path)
    compare = sub.add_parser("verify-compare")
    compare.add_argument("--reference-index", required=True, type=Path)
    compare.add_argument("--target-index", required=True, type=Path)
    compare.add_argument("--match-csv", type=Path)
    compare.add_argument("--summary", type=Path)
    compare.add_argument("--reference-build-record", type=Path)
    compare.add_argument("--target-build-record", type=Path)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "verify-compare":
        result = verify_compare_indexes(
            args.reference_index, args.target_index, args.match_csv, args.summary,
            args.reference_build_record, args.target_build_record,
        )
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
        result = verify(args.elf, args.build_record, function_records, args.source_xref_function_map)
    except (OSError, ValueError, KeyError) as exc:
        print(json.dumps({"valid": False, "error": str(exc)}, indent=2, sort_keys=True))
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
