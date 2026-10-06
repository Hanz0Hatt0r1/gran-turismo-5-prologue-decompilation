import struct
import unittest

from tools.gtdecomp import PS3ELF, ProgramHeader, extract_call_edges, _ppc_branch_target


class FakeELF:
    def __init__(self, start=0x1000, end=0x1100):
        self.data = bytearray(end - start)
        self.program_headers = [
            ProgramHeader(
                type=1,
                flags=5,
                offset=0,
                vaddr=start,
                filesz=end - start,
                memsz=end - start,
            )
        ]
        self.start = start
        self.end = end

    def va_to_offset(self, va):
        if self.start <= va < self.end:
            return va - self.start
        return None

    def in_executable_segment(self, va):
        return self.start <= va < self.end


def put_insn(elf, va, ins):
    off = elf.va_to_offset(va)
    elf.data[off:off + 4] = struct.pack(">I", ins)


def encode_bl(src, target):
    disp = target - src
    assert disp % 4 == 0
    assert -(1 << 25) <= disp < (1 << 25)
    return (18 << 26) | (disp & 0x03FFFFFC) | 1


class CallGraphTests(unittest.TestCase):
    def test_branch_target_for_relative_bl(self):
        ins = encode_bl(0x1000, 0x1040)
        self.assertEqual(_ppc_branch_target(ins, 0x1000), 0x1040)

    def test_extracts_direct_call_with_callsite_and_caller(self):
        elf = FakeELF()
        put_insn(elf, 0x1000, encode_bl(0x1000, 0x1040))
        put_insn(elf, 0x1004, 0x4E800020)

        edges = extract_call_edges(elf, [0x1000, 0x1020])
        self.assertEqual(len(edges), 1)
        self.assertEqual(edges[0].caller_va, 0x1000)
        self.assertEqual(edges[0].callsite_va, 0x1000)
        self.assertEqual(edges[0].target_va, 0x1040)
        self.assertEqual(edges[0].kind, "direct")


if __name__ == "__main__":
    unittest.main()
