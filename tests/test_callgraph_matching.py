import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from gtdecomp import CallEdge, callgraph_match_ratio


class CallgraphMatchTests(unittest.TestCase):
    def test_ratio_uses_only_already_matched_callees(self):
        reference = [
            CallEdge(0x1000, 0x1004, 0x2000, "direct"),
            CallEdge(0x1000, 0x1008, 0x3000, "direct"),
        ]
        target = [
            CallEdge(0x1100, 0x1104, 0x2200, "direct"),
            CallEdge(0x1100, 0x1108, 0x4400, "direct"),
        ]
        mapping = {0x1000: 0x1100, 0x2000: 0x2200, 0x3000: 0x3300}
        ratio = callgraph_match_ratio(0x1000, 0x1100, reference, target, mapping)
        self.assertEqual(ratio, 0.5)

    def test_no_recognized_edges_are_neutral(self):
        reference = [CallEdge(0x1000, 0x1004, 0x2000, "direct")]
        target = [CallEdge(0x1100, 0x1104, 0x2200, "direct")]
        ratio = callgraph_match_ratio(0x1000, 0x1100, reference, target, {})
        self.assertIsNone(ratio)


if __name__ == "__main__":
    unittest.main()
