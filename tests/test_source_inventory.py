import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from source_inventory import SOURCE_RE, classify_source_name, summarize_opd_containment, toc_load_slot


class SourceInventoryTests(unittest.TestCase):
    def test_source_pattern_accepts_cpp_and_c(self):
        self.assertIsNotNone(SOURCE_RE.search("MRenderContext.cpp"))
        self.assertIsNotNone(SOURCE_RE.search("../../job/src/joblist.cpp"))
        self.assertIsNotNone(SOURCE_RE.search("sgxfilestr.c"))

    def test_source_pattern_rejects_non_source_strings(self):
        self.assertIsNone(SOURCE_RE.search("MRenderContext.cpp.bak"))
        self.assertIsNone(SOURCE_RE.search("not_a_source_file.txt"))

    def test_opd_containment_counts_instruction_sites_and_functions(self):
        ranges = [(0x1000, 0x1020), (0x2000, 0x2040)]
        rows = [
            {"instruction_vas": ["0x1008", "0x2000", "0x3000"]},
        ]
        self.assertEqual(
            summarize_opd_containment(rows, ranges),
            {
                "xref_instruction_count": 3,
                "contained_xref_instruction_count": 2,
                "uncontained_xref_instruction_count": 1,
                "unique_functions_touched": 2,
            },
        )

    def test_toc_load_slot_resolves_signed_displacement(self):
        # lwz r3, -0x20(r2).
        ins = (32 << 26) | (3 << 21) | (2 << 16) | 0xFFE0
        self.assertEqual(toc_load_slot(ins, 0x10000), (0xFFE0, 4))

    def test_toc_load_slot_resolves_ld_width(self):
        # ld r4, 0x40(r2).
        ins = (58 << 26) | (4 << 21) | (2 << 16) | 0x0040
        self.assertEqual(toc_load_slot(ins, 0x10000), (0x10040, 8))

    def test_toc_load_slot_rejects_non_toc_base(self):
        ins = (32 << 26) | (3 << 21) | (1 << 16) | 0x0010
        self.assertIsNone(toc_load_slot(ins, 0x10000))
    def test_keyword_classification_is_conservative(self):
        self.assertEqual(classify_source_name("MRenderContextPS3.cpp"), "rendering")
        self.assertEqual(classify_source_name("MOnlineSession.cpp"), "networking")
        self.assertEqual(classify_source_name("MUserProfile2.cpp"), "save_profile")
        self.assertEqual(classify_source_name("MCarObject.cpp"), "vehicle")
        self.assertEqual(classify_source_name("CompletelyOpaqueThing.cpp"), "unclassified")


if __name__ == "__main__":
    unittest.main()
