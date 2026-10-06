import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from gtdecomp import _prune_nested_direct_call_evidence


class FakeElf:
    def __init__(self):
        self.data = bytearray(0x40)
        # 0x1000: function start; 0x1008: local label; 0x1010: blr.
        self._words = {
            0x1000: 0xF821FF91,  # stdu r1, -112(r1)
            0x1004: 0x60000000,
            0x1008: 0x60000000,
            0x100C: 0x60000000,
            0x1010: 0x4E800020,  # blr
            0x1014: 0x60000000,
        }

    def va_to_offset(self, va):
        if 0x1000 <= va < 0x1040:
            return va - 0x1000
        return None


class NestedDirectCallBoundaryTests(unittest.TestCase):
    def test_local_label_is_not_promoted_to_function(self):
        elf = FakeElf()
        evidence = {
            0x1000: {"opd"},
            0x1008: {"direct-call"},
            0x1014: {"direct-call"},
        }
        # Install fake words into the offsets used by _u32.
        for va, word in elf._words.items():
            off = elf.va_to_offset(va)
            elf.data[off:off + 4] = word.to_bytes(4, "big")

        _prune_nested_direct_call_evidence(elf, evidence)

        self.assertNotIn(0x1008, evidence)
        self.assertIn(0x1014, evidence)


if __name__ == "__main__":
    unittest.main()
