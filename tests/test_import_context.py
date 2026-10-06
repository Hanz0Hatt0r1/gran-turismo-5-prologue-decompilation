import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from gtdecomp import CallEdge, ImportFunction, import_context_by_function, import_context_match_ratio


class ImportContextTests(unittest.TestCase):
    def test_context_uses_library_and_nid_not_stub_address(self):
        edges = [
            CallEdge(0x1000, 0x1004, 0x2000, "direct"),
            CallEdge(0x1000, 0x1008, 0x3000, "direct"),
        ]
        imports = [
            ImportFunction("cellA", 0x11111111, 0x2000, 0x5000),
            ImportFunction("cellB", 0x22222222, 0x3000, 0x5004),
        ]
        context = import_context_by_function(edges, imports)
        self.assertEqual(
            context[0x1000],
            {("cellA", 0x11111111), ("cellB", 0x22222222)},
        )

    def test_ratio_is_neutral_without_import_calls(self):
        self.assertIsNone(import_context_match_ratio(0x1000, 0x1100, {}, {}))

    def test_ratio_uses_stable_import_identity(self):
        ref = {0x1000: {("cellA", 0x11111111), ("cellB", 0x22222222)}}
        tgt = {0x1100: {("cellA", 0x11111111), ("cellC", 0x33333333)}}
        self.assertEqual(import_context_match_ratio(0x1000, 0x1100, ref, tgt), 1 / 3)


if __name__ == "__main__":
    unittest.main()
