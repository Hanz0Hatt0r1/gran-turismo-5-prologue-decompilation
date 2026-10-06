import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class RegionInventoryTests(unittest.TestCase):
    def test_verified_build_profiles_remain_separate_from_public_release_ids(self):
        text = (ROOT / "analysis" / "builds" / "region-inventory.yaml").read_text(encoding="utf-8")
        self.assertIn("title_id: BCUS-98114", text)
        self.assertIn("title_id: BCUS-98158", text)
        self.assertIn("US: reviewed-executable", text)
        self.assertIn("BCES-00569", text)
        self.assertIn("BCJS-30050", text)
        self.assertIn("BCAS-20027", text)
        self.assertIn("NPUA-80075", text)
        self.assertIn("cataloged-public-release", text)

    def test_unknown_regions_remain_explicit(self):
        text = (ROOT / "analysis" / "builds" / "region-inventory.yaml").read_text(encoding="utf-8")
        self.assertIn("Other: unknown", text)
        self.assertIn("No executable, SELF, firmware, keys, SDK material, or game assets", text)


if __name__ == "__main__":
    unittest.main()
