#!/usr/bin/env python3
"""Validate and query the reviewed GT5/GT5 Prologue research catalog.

The catalog utility is intentionally dependency-free. JSON records are parsed
structurally; the project's simple YAML records are parsed for scalar mapping
fields while raw text remains available for search. It is not a general YAML
parser.
"""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]+$")
SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
SUPPORTED_SUFFIXES = {".json", ".yaml", ".yml"}
HEX_TOKEN_RE = re.compile(r"0x[0-9a-fA-F]+")

REQUIRED = {
    "build": (
        "schema",
        "game",
        "title_id",
        "role",
        "executable_sha256",
        "format",
        "entry_descriptor_va",
        "entry_code_va",
    ),
    "function": (
        "schema",
        "id",
        "build",
        "module",
        "address.va",
        "confidence",
        "status",
    ),
    "evidence": (
        "schema",
        "build",
        "module",
        "confidence",
        "status",
    ),
}


@dataclass(frozen=True)
class CatalogRecord:
    path: str
    kind: str
    fields: Dict[str, Any]
    text: str

    @property
    def build(self) -> Optional[str]:
        return _as_text(self.fields.get("build"))

    @property
    def module(self) -> Optional[str]:
        return _as_text(self.fields.get("module"))

    @property
    def address(self) -> Optional[str]:
        value = self.fields.get("address.va")
        return normalize_address(value) if value is not None else None

    @property
    def addresses(self) -> Tuple[str, ...]:
        values: List[str] = []
        if self.kind == "function" and self.address:
            values.append(self.address)
        if self.kind == "build":
            for key in ("entry_descriptor_va", "entry_code_va", "toc_va"):
                value = normalize_address(self.fields.get(key))
                if value:
                    values.append(value)
        return tuple(dict.fromkeys(values))

    @property
    def display_name(self) -> Optional[str]:
        return (
            _as_text(self.fields.get("name.current"))
            or _as_text(self.fields.get("id"))
            or _as_text(self.fields.get("title_id"))
        )


def _as_text(value: Any) -> Optional[str]:
    if value is None:
        return None
    return str(value).strip()


def normalize_address(value: Any) -> Optional[str]:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return f"0x{value:x}"
    text = str(value).strip()
    if not text:
        return None
    if text.lower().startswith("0x"):
        try:
            return f"0x{int(text, 16):x}"
        except ValueError:
            return None
    if text.isdigit():
        return f"0x{int(text, 10):x}"
    return None


def _yaml_scalar(text: str) -> Any:
    value = text.strip()
    if not value:
        return None
    if value.startswith((""", "'")) and value[-1:] == value[0]:
        return value[1:-1]
    if value in {"null", "Null", "NULL", "~"}:
        return None
    if value in {"true", "True", "TRUE"}:
        return True
    if value in {"false", "False", "FALSE"}:
        return False
    if ADDRESS_RE.fullmatch(value):
        return value.lower()
    if re.fullmatch(r"-?\d+", value):
        try:
            return int(value, 10)
        except ValueError:
            pass
    return value


def _yaml_scalar_fields(text: str) -> Dict[str, Any]:
    """Extract scalar mapping fields from the project's simple YAML subset."""
    fields: Dict[str, Any] = {}
    stack: List[Tuple[int, str]] = []

    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        stripped = raw.strip()
        if stripped.startswith("-") or ":" not in stripped:
            continue

        key, raw_value = stripped.split(":", 1)
        key = key.strip()
        raw_value = raw_value.strip()
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", key):
            continue

        while stack and indent <= stack[-1][0]:
            stack.pop()

        path = [item[1] for item in stack] + [key]
        if raw_value:
            fields[".".join(path)] = _yaml_scalar(raw_value)
        else:
            stack.append((indent, key))

    return fields


def _flatten_json(value: Any, prefix: str = "") -> Dict[str, Any]:
    fields: Dict[str, Any] = {}
    if isinstance(value, dict):
        for key, child in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            if isinstance(child, dict):
                fields.update(_flatten_json(child, path))
            elif not isinstance(child, list):
                fields[path] = child
    return fields


def record_kind(path: Path) -> str:
    parts = {part.lower() for part in path.parts}
    if "builds" in parts:
        return "build"
    if "functions" in parts:
        return "function"
    if "evidence" in parts:
        return "evidence"
    return "other"


def load_record(path: Path, root: Path) -> CatalogRecord:
    text = path.read_text(encoding="utf-8")
    kind = record_kind(path)
    if path.suffix.lower() == ".json":
        fields = _flatten_json(json.loads(text))
    else:
        fields = _yaml_scalar_fields(text)

    relative_root = root if root.is_dir() else root.parent
    relative = str(path.relative_to(relative_root))
    return CatalogRecord(relative, kind, fields, text)


def iter_records(root: Path) -> Iterable[CatalogRecord]:
    root = root.resolve()
    paths = (
        [root]
        if root.is_file()
        else sorted(p for p in root.rglob("*") if p.is_file())
    )
    for path in paths:
        if path.suffix.lower() not in SUPPORTED_SUFFIXES:
            continue
        if path.name.startswith("."):
            continue
        try:
            yield load_record(path, root)
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            relative_root = root if root.is_dir() else root.parent
            relative = str(path.relative_to(relative_root))
            yield CatalogRecord(
                relative,
                "other",
                {"_parse_error": str(exc)},
                "",
            )


def validate_records(records: Sequence[CatalogRecord]) -> Dict[str, Any]:
    errors: List[Dict[str, str]] = []
    groups: Dict[Tuple[str, str, str], List[str]] = defaultdict(list)
    counts = Counter(record.kind for record in records)

    for record in records:
        if "_parse_error" in record.fields:
            errors.append({
                "path": record.path,
                "message": record.fields["_parse_error"],
            })
            continue

        for field in REQUIRED.get(record.kind, ()):
            if field not in record.fields or record.fields[field] in (None, ""):
                errors.append({
                    "path": record.path,
                    "message": f"missing required field: {field}",
                })

        if record.kind == "build":
            digest = _as_text(record.fields.get("executable_sha256"))
            if digest and not SHA256_RE.fullmatch(digest):
                errors.append({
                    "path": record.path,
                    "message": "executable_sha256 is not 64 hex characters",
                })
            for field in ("entry_descriptor_va", "entry_code_va", "toc_va"):
                if field in record.fields and normalize_address(record.fields[field]) is None:
                    errors.append({
                        "path": record.path,
                        "message": f"invalid address: {field}",
                    })

        if record.kind == "function":
            address = record.address
            if address is None:
                errors.append({
                    "path": record.path,
                    "message": "invalid function address",
                })
            else:
                identity = (record.build or "", record.module or "", address)
                groups[identity].append(record.path)

    duplicates = [
        {
            "build": key[0],
            "module": key[1],
            "address": key[2],
            "paths": paths,
        }
        for key, paths in sorted(groups.items())
        if len(paths) > 1
    ]

    return {
        "valid": not errors and not duplicates,
        "record_count": len(records),
        "counts_by_kind": dict(sorted(counts.items())),
        "errors": errors,
        "duplicate_function_addresses": duplicates,
    }


def search_records(
    records: Sequence[CatalogRecord],
    name: Optional[str],
    address: Optional[str],
) -> List[Dict[str, Any]]:
    normalized_address = normalize_address(address) if address else None
    needle = name.casefold() if name else None
    rows: List[Dict[str, Any]] = []

    for record in records:
        matched_by: List[str] = []

        if normalized_address is not None:
            if normalized_address in record.addresses:
                matched_by.append("declared-address")
            elif normalized_address in {
                normalize_address(token)
                for token in HEX_TOKEN_RE.findall(record.text)
            }:
                matched_by.append("address-reference")

        if needle is not None and needle in record.text.casefold():
            matched_by.append("name-text")

        if normalized_address is None and needle is None:
            matched_by.append("all-records")

        if matched_by:
            rows.append({
                "path": record.path,
                "kind": record.kind,
                "build": record.build,
                "module": record.module,
                "address": record.address,
                "name": record.display_name,
                "confidence": _as_text(record.fields.get("confidence")),
                "status": _as_text(record.fields.get("status")),
                "matched_by": sorted(set(matched_by)),
            })

    return rows


def summarize(records: Sequence[CatalogRecord]) -> Dict[str, Any]:
    function_keys = {
        (record.build, record.module, record.address)
        for record in records
        if record.kind == "function" and record.address
    }
    return {
        "record_count": len(records),
        "by_kind": dict(sorted(Counter(record.kind for record in records).items())),
        "by_build": dict(sorted(Counter(
            record.build or "<unknown>" for record in records
        ).items())),
        "by_confidence": dict(sorted(Counter(
            _as_text(record.fields.get("confidence")) or "<unknown>"
            for record in records
        ).items())),
        "by_status": dict(sorted(Counter(
            _as_text(record.fields.get("status")) or "<unknown>"
            for record in records
        ).items())),
        "function_addresses": len(function_keys),
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    for command in ("validate", "summary"):
        child = sub.add_parser(command)
        child.add_argument("root", type=Path)

    search = sub.add_parser("search")
    search.add_argument("root", type=Path)
    group = search.add_mutually_exclusive_group(required=True)
    group.add_argument("--name")
    group.add_argument("--address")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parser().parse_args(argv)
    records = list(iter_records(args.root))

    if args.command == "validate":
        result = validate_records(records)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result["valid"] else 1

    if args.command == "summary":
        print(json.dumps(summarize(records), indent=2, sort_keys=True))
        return 0

    rows = search_records(records, args.name, args.address)
    print(json.dumps(rows, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
