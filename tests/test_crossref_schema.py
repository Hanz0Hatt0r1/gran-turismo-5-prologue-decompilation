import tempfile
import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import gtcatalog


class CrossrefSchemaTests(unittest.TestCase):
    def test_accepts_complete_crossref(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            p = root / "analysis" / "crossref"
            p.mkdir(parents=True)
            (p / "crt.yaml").write_text(
                """schema: 1
id: gt5-vs-gt5p-crt
reference:
  build: BCUS-98114
  module: EBOOT.BIN
  va: 0x10338
target:
  build: BCUS-98158
  module: EBOOT.BIN
  va: 0x10368
method: manual
confidence: probable
review_status: pending
""",
                encoding="utf-8",
            )
            result = gtcatalog.validate_records(list(gtcatalog.iter_records(root)))
            self.assertTrue(result["valid"])

    def test_rejects_bad_crossref_fields(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            p = root / "analysis" / "crossref"
            p.mkdir(parents=True)
            (p / "bad.yaml").write_text(
                """schema: 1
id: bad
reference:
  build: BCUS-98114
  module: EBOOT.BIN
  va: nope
target:
  build: BCUS-98158
  module: EBOOT.BIN
  va: 0x10368
method: nonsense
confidence: probable
review_status: mystery
""",
                encoding="utf-8",
            )
            result = gtcatalog.validate_records(list(gtcatalog.iter_records(root)))
            self.assertFalse(result["valid"])
            messages = {e["message"] for e in result["errors"]}
            self.assertIn("invalid address: reference.va", messages)
            self.assertIn("unsupported cross-build method: nonsense", messages)
            self.assertIn("unsupported review_status: mystery", messages)


if __name__ == "__main__":
    unittest.main()
