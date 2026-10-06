import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from source_inventory import SOURCE_RE, classify_source_name


class SourceInventoryTests(unittest.TestCase):
    def test_source_pattern_accepts_cpp_and_c(self):
        self.assertIsNotNone(SOURCE_RE.search("MRenderContext.cpp"))
        self.assertIsNotNone(SOURCE_RE.search("../../job/src/joblist.cpp"))
        self.assertIsNotNone(SOURCE_RE.search("sgxfilestr.c"))

    def test_source_pattern_rejects_non_source_strings(self):
        self.assertIsNone(SOURCE_RE.search("MRenderContext.cpp.bak"))
        self.assertIsNone(SOURCE_RE.search("not_a_source_file.txt"))

    def test_keyword_classification_is_conservative(self):
        self.assertEqual(classify_source_name("MRenderContextPS3.cpp"), "rendering")
        self.assertEqual(classify_source_name("MOnlineSession.cpp"), "networking")
        self.assertEqual(classify_source_name("MUserProfile2.cpp"), "save_profile")
        self.assertEqual(classify_source_name("MCarObject.cpp"), "vehicle")
        self.assertEqual(classify_source_name("CompletelyOpaqueThing.cpp"), "unclassified")


if __name__ == "__main__":
    unittest.main()
