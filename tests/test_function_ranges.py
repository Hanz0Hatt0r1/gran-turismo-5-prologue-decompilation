import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from gtdecomp import function_ranges_from_starts


class FakeElf:
    def __init__(self):
        self.data = bytearray(0x40)
        self._words = {
            0x1000: 0x60000000,
            0x1004: 0x60000000,
            0x1008: 0x4E800020,
            0x100C: 0x60000000,
            0x1010: 0x60000000,
        }
        for va, word in self._words.items():
            off = va - 0x1000
            self.data[off:off + 4] = word.to_bytes(4, "big")

    def in_executable_segment(self, va):
        return 0x1000 <= va < 0x1040

    def va_to_offset(self, va):
        return va - 0x1000 if self.in_executable_segment(va) else None

    @property
    def program_headers(self):
        return [type("PH", (), {"type": 1, "flags": 1, "vaddr": 0x1000, "filesz": 0x40})()]


class BlrFunctionRangeTests(unittest.TestCase):
    def test_first_blr_terminates_range_before_later_candidate(self):
        ranges = function_ranges_from_starts(FakeElf(), [0x1000, 0x1030])
        self.assertEqual(ranges[0], (0x1000, 0x100C))

    def test_nonreturning_range_keeps_candidate_boundary(self):
        elf = FakeElf()
        elf.data[0:0x30] = b"\x60\x00\x00\x00" * 12
        ranges = function_ranges_from_starts(elf, [0x1000, 0x1030])
        self.assertEqual(ranges[0], (0x1000, 0x1030))


if __name__ == "__main__":
    unittest.main()
