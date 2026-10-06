import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import gtcatalog


class CatalogTests(unittest.TestCase):
    def _fixture(self, duplicate: bool = False):
        root = Path(tempfile.mkdtemp())
        builds = root / "analysis" / "builds"
        functions = root / "analysis" / "functions"
        evidence = root / "analysis" / "evidence"
        builds.mkdir(parents=True)
        functions.mkdir(parents=True)
        evidence.mkdir(parents=True)

        (builds / "gt5.json").write_text(json.dumps({
            "schema": 1,
            "game": "Gran Turismo 5",
            "title_id": "BCUS-98114",
            "role": "reference-build",
            "executable_sha256": "a" * 64,
            "format": "ELF64-big-endian-PowerPC64",
            "entry_descriptor_va": "0x017f8150",
            "entry_code_va": "0x00010230",
            "toc_va": "0x01846af0",
        }), encoding="utf-8")

        function = """schema: 1
id: gt5.bcus98114.eboot.00010230
build: BCUS-98114
module: EBOOT.BIN
address:
  va: 0x00010230
name:
  current: eboot_entry
  candidates:
    - runtime_entry
confidence: confirmed
status: analyzed
"""
        (functions / "entry.yaml").write_text(function, encoding="utf-8")

        if duplicate:
            (functions / "entry-duplicate.yaml").write_text(
                function.replace("eboot_entry", "duplicate_entry"),
                encoding="utf-8",
            )

        (evidence / "startup.yaml").write_text(
            """schema: 1
build: BCUS-98114
module: EBOOT.BIN
confidence: probable
status: reviewed
observations:
  - "0x00010230 -> 0x00010338"
""",
            encoding="utf-8",
        )
        return root

    def test_normalize_address(self):
        self.assertEqual(gtcatalog.normalize_address("0x00010230"), "0x10230")
        self.assertEqual(gtcatalog.normalize_address(0x10230), "0x10230")
        self.assertIsNone(gtcatalog.normalize_address("not-an-address"))

    def test_validation_accepts_clean_fixture(self):
        root = self._fixture()
        result = gtcatalog.validate_records(list(gtcatalog.iter_records(root)))
        self.assertTrue(result["valid"])
        self.assertEqual(result["record_count"], 3)
        self.assertEqual(result["duplicate_function_addresses"], [])

    def test_validation_rejects_duplicate_function_address(self):
        root = self._fixture(duplicate=True)
        result = gtcatalog.validate_records(list(gtcatalog.iter_records(root)))
        self.assertFalse(result["valid"])
        self.assertEqual(len(result["duplicate_function_addresses"]), 1)
        self.assertEqual(result["duplicate_function_addresses"][0]["address"], "0x10230")

    def test_search_finds_nested_function_name_and_address_references(self):
        root = self._fixture()
        records = list(gtcatalog.iter_records(root))
        by_name = gtcatalog.search_records(records, "eboot_entry", None)
        self.assertEqual([row["name"] for row in by_name], ["eboot_entry"])

        by_address = gtcatalog.search_records(records, None, "0x10230")
        paths = {row["path"] for row in by_address}
        self.assertIn("analysis/builds/gt5.json", paths)
        self.assertIn("analysis/functions/entry.yaml", paths)
        self.assertIn("analysis/evidence/startup.yaml", paths)

    def test_validation_accepts_confirmed_scoped_crossref(self):
        root = self._fixture()
        crossrefs = root / "analysis" / "crossref"
        crossrefs.mkdir(parents=True)
        (crossrefs / "accepted.yaml").write_text(
            """schema: 1
id: gt5-vs-gt5p-entry
reference:
  build: BCUS-98114
  module: EBOOT.BIN
  va: 0x00010230
target:
  build: BCUS-98158
  module: EBOOT.BIN
  va: 0x00010230
method: manual
confidence: confirmed
review_status: accepted
relationship:
  identity_scope: "ELFv1 PPU entry routine / ABI startup role"
""", encoding="utf-8")
        result = gtcatalog.validate_records(list(gtcatalog.iter_records(root)))
        self.assertTrue(result["valid"])

    def test_validation_rejects_accepted_crossref_without_scope_or_confirmation(self):
        root = self._fixture()
        crossrefs = root / "analysis" / "crossref"
        crossrefs.mkdir(parents=True)
        (crossrefs / "bad-accepted.yaml").write_text(
            """schema: 1
id: invalid-accepted
reference:
  build: BCUS-98114
  module: EBOOT.BIN
  va: 0x00010230
target:
  build: BCUS-98158
  module: EBOOT.BIN
  va: 0x00010230
method: manual
confidence: probable
review_status: accepted
""", encoding="utf-8")
        result = gtcatalog.validate_records(list(gtcatalog.iter_records(root)))
        self.assertFalse(result["valid"])
        messages = [error["message"] for error in result["errors"]]
        self.assertIn("accepted crossref requires confidence: confirmed", messages)
        self.assertIn("accepted crossref requires relationship.identity_scope", messages)

    def test_validation_accepts_crossref_record(self):
        root = self._fixture()
        crossrefs = root / "analysis" / "crossref"
        crossrefs.mkdir(parents=True)
        (crossrefs / "crt.yaml").write_text(
            """schema: 1
id: gt5-vs-gt5p-crt
reference:
  build: BCUS-98114
  module: EBOOT.BIN
  va: 0x00010338
target:
  build: BCUS-98158
  module: EBOOT.BIN
  va: 0x00010368
method: manual
confidence: probable
review_status: pending
""", encoding="utf-8")
        result = gtcatalog.validate_records(list(gtcatalog.iter_records(root)))
        self.assertTrue(result["valid"])

    def test_validation_rejects_invalid_crossref_metadata(self):
        root = self._fixture()
        crossrefs = root / "analysis" / "crossref"
        crossrefs.mkdir(parents=True)
        (crossrefs / "bad.yaml").write_text(
            """schema: 1
id: invalid-match
reference:
  build: BCUS-98114
  module: EBOOT.BIN
  va: nope
target:
  build: BCUS-98158
  module: EBOOT.BIN
  va: 0x00010368
method: nonsense
confidence: probable
review_status: mystery
""", encoding="utf-8")
        result = gtcatalog.validate_records(list(gtcatalog.iter_records(root)))
        self.assertFalse(result["valid"])
        messages = [error["message"] for error in result["errors"]]
        self.assertIn("invalid address: reference.va", messages)
        self.assertIn("unsupported cross-build method: nonsense", messages)
        self.assertIn("unsupported review_status: mystery", messages)
    def test_summary_reports_kind_build_and_function_counts(self):
        root = self._fixture()
        result = gtcatalog.summarize(list(gtcatalog.iter_records(root)))
        self.assertEqual(result["record_count"], 3)
        self.assertEqual(result["by_kind"], {"build": 1, "evidence": 1, "function": 1})
        self.assertEqual(result["by_build"]["BCUS-98114"], 3)
        self.assertEqual(result["function_addresses"], 1)


if __name__ == "__main__":
    unittest.main()
