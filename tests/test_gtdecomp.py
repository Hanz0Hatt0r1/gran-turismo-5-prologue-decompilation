import importlib.util
import struct
import tempfile
import unittest
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("gtdecomp", ROOT / "tools" / "gtdecomp.py")
gtdecomp = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = gtdecomp
spec.loader.exec_module(gtdecomp)


class GTDecompTests(unittest.TestCase):
    def test_normalize_direct_branch_erases_target(self):
        a = 0x48001235
        b = 0x4BFFF235
        self.assertEqual(gtdecomp.normalize_ppc_instruction(a), gtdecomp.normalize_ppc_instruction(b))
        self.assertEqual(gtdecomp.normalize_ppc_instruction(a) & 1, 1)

    def test_normalize_toc_relative_load_erases_displacement(self):
        # lwz r3, disp(r2): opcode 32, RT=3, RA=2.
        a = (32 << 26) | (3 << 21) | (2 << 16) | 0x1234
        b = (32 << 26) | (3 << 21) | (2 << 16) | 0xABCD
        self.assertEqual(gtdecomp.normalize_ppc_instruction(a), gtdecomp.normalize_ppc_instruction(b))

    def test_identity_detection(self):
        rows = [
            (0x1000, "BCUS-98114"),
            (0x1010, "Gran Turismo 5"),
            (0x1020, "gt.gt5.us.ps3.product-bd-strong.release.build"),
        ]
        ident = gtdecomp.find_build_identity(rows)
        self.assertIn("BCUS-98114", ident["title_ids"])
        self.assertIn("Gran Turismo 5", ident["build_strings"])

    def test_resolve_analyze_headless_from_install_dir(self):
        with tempfile.TemporaryDirectory() as td:
            support = Path(td) / "support"
            support.mkdir()
            tool = support / "analyzeHeadless"
            tool.write_text("#!/bin/sh\n")
            self.assertEqual(gtdecomp.resolve_analyze_headless(Path(td)), tool.resolve())

    def test_parse_minimal_ppc64_elf_and_opd(self):
        # Build a tiny synthetic PS3-like ELF with one executable segment and
        # one writable descriptor section. It contains no proprietary data.
        data = bytearray(0x500)
        data[0:16] = b"\x7fELF\x02\x02\x01\x66" + b"\0" * 8
        struct.pack_into(">HHIQQQIHHHHHH", data, 16,
                         2, 21, 1, 0x3000, 64, 0x400, 0,
                         64, 56, 2, 64, 3, 2)
        # Executable PT_LOAD: VA 0x1000 -> file 0x200.
        struct.pack_into(">IIQQQQQQ", data, 64,
                         1, 5, 0x200, 0x1000, 0x1000, 0x100, 0x100, 0x10)
        # Writable PT_LOAD: VA 0x3000 -> file 0x300.
        struct.pack_into(">IIQQQQQQ", data, 120,
                         1, 6, 0x300, 0x3000, 0x3000, 0x40, 0x40, 8)
        # Two function descriptors, same TOC.
        struct.pack_into(">II", data, 0x300, 0x1000, 0x3800)
        struct.pack_into(">II", data, 0x308, 0x1010, 0x3800)
        # Section headers at 0x400; shstrtab is section 2.
        names = b"\0.text\0.opd\0.shstrtab\0"
        data[0x380:0x380 + len(names)] = names
        # null section
        # .opd covers entry. Name offset 7.
        struct.pack_into(">IIQQQQIIQQ", data, 0x440,
                         7, 1, 0x3, 0x3000, 0x300, 0x40, 0, 0, 8, 0)
        # shstrtab, name offset 12.
        struct.pack_into(">IIQQQQIIQQ", data, 0x480,
                         12, 3, 0, 0, 0x380, len(names), 0, 0, 1, 0)
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "tiny.elf"
            p.write_bytes(data)
            elf = gtdecomp.PS3ELF(p)
            toc, opd = gtdecomp.find_opd(elf)
            self.assertEqual(toc, 0x3800)
            self.assertEqual([(x.descriptor_va, x.code_va) for x in opd[:2]],
                             [(0x3000, 0x1000), (0x3008, 0x1010)])


if __name__ == "__main__":
    unittest.main()