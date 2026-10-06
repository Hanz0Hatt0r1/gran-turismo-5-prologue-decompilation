import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from audit_boundaries import _conditional_branch_target, direct_control_target, post_blr_targets


class BoundaryAuditTests(unittest.TestCase):
    def test_relative_conditional_branch_target(self):
        self.assertEqual(_conditional_branch_target(0x41820008, 0x1000), 0x1008)

    def test_relative_unconditional_branch_target(self):
        self.assertEqual(direct_control_target(0x48000008, 0x1000), 0x1008)

    def test_post_blr_target_is_flagged(self):
        branches = [
            (0x1004, 0x1010, 18, False),
            (0x1014, 0x1020, 18, False),
        ]
        self.assertEqual(post_blr_targets(branches, 0x1000, 0x1008, 0x1020), branches[:1])

    def test_post_blr_excludes_target_at_next_boundary(self):
        branches = [(0x1004, 0x1020, 18, False)]
        self.assertEqual(post_blr_targets(branches, 0x1000, 0x1008, 0x1020), [])


if __name__ == "__main__":
    unittest.main()
