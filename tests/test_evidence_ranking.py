import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from gtdecomp import match_evidence_rank


class EvidenceRankingTests(unittest.TestCase):
    def test_full_match_with_two_strong_secondary_signals_is_probable(self):
        score, confidence, reasons = match_evidence_rank(
            "normalized-full", 0.9, 0.8, None
        )
        self.assertEqual(score, 80)
        self.assertEqual(confidence, "probable")
        self.assertIn("normalized-full", reasons)
        self.assertIn("callgraph:strong", reasons)
        self.assertIn("import-context:strong", reasons)

    def test_prefix_match_without_secondary_support_stays_speculative(self):
        score, confidence, reasons = match_evidence_rank(
            "normalized-prefix", None, None, None
        )
        self.assertEqual(score, 50)
        self.assertEqual(confidence, "speculative")
        self.assertEqual(reasons, "normalized-prefix")

    def test_weak_secondary_evidence_does_not_inflate_rank(self):
        score, confidence, reasons = match_evidence_rank(
            "normalized-full", 0.2, 0.1, 0.3
        )
        self.assertEqual(score, 60)
        self.assertEqual(confidence, "speculative")
        self.assertIn("callgraph:weak", reasons)


if __name__ == "__main__":
    unittest.main()
