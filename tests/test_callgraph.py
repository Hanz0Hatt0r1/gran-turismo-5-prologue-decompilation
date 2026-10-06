import struct
import unittest

from tools.gtdecomp import FunctionDescriptor, PS3ELF, ProgramHeader, discover_function_candidates, extract_call_edges, _ppc_branch_target


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

    def read_u32_va(self, va):
        off = self.va_to_offset(va)
        if off is None:
            return None
        return struct.unpack_from(">I", self.data, off)[0]


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

    def test_nested_stack_prologue_is_not_a_new_function(self):
        elf = FakeELF()
        # 0x1000 is a strong direct-call target; 0x1004 looks like a PPC64
        # stack prologue but is still inside that function.
        put_insn(elf, 0x1000, encode_bl(0x1000, 0x1040))
        put_insn(elf, 0x1004, 0xF821FF81)  # stdu r1, -128(r1)
        put_insn(elf, 0x1008, 0x4E800020)  # blr terminates the tiny function
        put_insn(elf, 0x1040, 0xF821FF81)  # real target starts with prologue

        candidates = discover_function_candidates(
            elf,
            [FunctionDescriptor(0x2000, 0x1000, 0)],
        )
        by_va = {row.code_va: row for row in candidates}
        self.assertNotIn(0x1004, by_va)
        self.assertIn(0x1040, by_va)
        self.assertIn("direct-call", by_va[0x1040].evidence)

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
