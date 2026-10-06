import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from gtdecomp import vtable_context_by_function, vtable_context_match_ratio


class VtableContextTests(unittest.TestCase):
    def test_context_prefers_stable_encoded_rtti_identity(self):
        rows = [
            {"code_va": 0x1000, "encoded": "N3Foo3BarE", "demangled": "Foo::Bar"},
            {"code_va": 0x1000, "encoded": "N3Foo3BarE", "demangled": "Foo::Bar"},
        ]
        self.assertEqual(vtable_context_by_function(rows)[0x1000], {"N3Foo3BarE"})

    def test_ratio_is_neutral_without_type_context(self):
        self.assertIsNone(vtable_context_match_ratio(0x1000, 0x1100, {}, {}))

    def test_ratio_compares_stable_type_identity(self):
        ref = {0x1000: {"N3Foo3BarE", "N3Foo3BazE"}}
        tgt = {0x1100: {"N3Foo3BarE", "N3Foo3QuxE"}}
        self.assertEqual(vtable_context_match_ratio(0x1000, 0x1100, ref, tgt), 1 / 3)


if __name__ == "__main__":
    unittest.main()
