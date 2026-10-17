import importlib.util
import struct
import tempfile
import unittest
import sys
from unittest import mock
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

    def test_import_ghidra_c_attaches_discovered_function_id(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            index = root / "index"
            index.mkdir()
            (index / "discovered_functions.csv").write_text(
                "code_va,score,evidence,size,insns,sha_full,sha_prefix\n"
                "0x00001000,4,direct-call,8,2,abc123,def456\n"
            )
            (index / "function_hints.csv").write_text(
                "code_va,source_files,vtable_types,evidence_count\n"
                "0x00001000,Foo.cpp,Foo,2\n"
            )
            c_export = root / "export.c"
            c_export.write_text("int FUN_00001000(void)\n{\n  return 1;\n}\n")
            out = root / "out"
            summary = gtdecomp.import_ghidra_c(c_export, index, out)
            self.assertEqual(summary["total_blocks"], 1)
            self.assertEqual(summary["matched_index_functions"], 1)
            manifest = (out / "ghidra_c_manifest.csv").read_text()
            self.assertIn("abc123", manifest)
            self.assertIn("Foo.cpp", manifest)

    def test_resolve_analyze_headless_from_install_dir(self):
        with tempfile.TemporaryDirectory() as td:
            support = Path(td) / "support"
            support.mkdir()
            tool = support / "analyzeHeadless"
            tool.write_text("#!/bin/sh\n")
            self.assertEqual(gtdecomp.resolve_analyze_headless(Path(td)), tool.resolve())

    def test_resolve_prefers_pyghidra_launcher_when_available(self):
        with tempfile.TemporaryDirectory() as td:
            support = Path(td) / "support"
            support.mkdir()
            headless = support / "analyzeHeadless"
            headless.write_text("#!/bin/sh\n")
            pyghidra = support / "pyghidraRun"
            pyghidra.write_text("#!/bin/sh\n")
            self.assertEqual(gtdecomp.resolve_analyze_headless(Path(td)), pyghidra.resolve())

    def test_decompile_rejects_missing_export_manifest(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            out = root / "out"
            decompiled = out / "decompiled"
            decompiled.mkdir(parents=True)
            stale_manifest = decompiled / "decompilation_manifest.csv"
            stale_manifest.write_text("code_va,status\n0x00001000,ok\n")
            stale_summary = out / "decompile-summary.json"
            stale_summary.write_text("{}\n")
            with mock.patch.object(gtdecomp, "index_elf", return_value={"sha256": "a" * 64}):
                with mock.patch.object(gtdecomp, "resolve_analyze_headless", return_value=Path("/ghidra/analyzeHeadless")):
                    with mock.patch.object(gtdecomp.subprocess, "run"):
                        with self.assertRaisesRegex(RuntimeError, "did not produce decompilation_manifest.csv"):
                            gtdecomp.decompile_elf(root / "input.elf", out, root / "ghidra")
            self.assertFalse(stale_manifest.exists())
            self.assertFalse(stale_summary.exists())

    def test_decompile_uses_pyghidra_headless_class_and_project_arguments(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            out = root / "out"

            def write_manifest(command, check):
                manifest = out / "decompiled" / "decompilation_manifest.csv"
                manifest.write_text("code_va,status\n0x00001000,ok\n")

            with mock.patch.object(gtdecomp, "index_elf", return_value={"sha256": "a" * 64}):
                with mock.patch.object(gtdecomp, "resolve_analyze_headless", return_value=Path("/ghidra/support/pyghidraRun")):
                    with mock.patch.object(gtdecomp.subprocess, "run", side_effect=write_manifest) as run:
                        result = gtdecomp.decompile_elf(
                            root / "input.elf",
                            out,
                            root / "ghidra",
                            limit=1,
                            function_vas=[0x1000, 0x2000],
                        )

            command = run.call_args.args[0]
            self.assertEqual(command[:2], [
                "/ghidra/support/pyghidraRun",
                "-H",
            ])
            self.assertEqual(command[2], str(out / "ghidra-project"))
            self.assertEqual(command[3], "gtdecomp_aaaaaaaaaaaa")
            self.assertEqual(command[18], "1")
            self.assertEqual(result["selected_functions"], 1)

    def test_decompile_rejects_manifest_missing_requested_function(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            out = root / "out"

            def write_empty_manifest(command, check):
                manifest = out / "decompiled" / "decompilation_manifest.csv"
                manifest.write_text("code_va,status\n")

            with mock.patch.object(gtdecomp, "index_elf", return_value={"sha256": "a" * 64}):
                with mock.patch.object(gtdecomp, "resolve_analyze_headless", return_value=Path("/ghidra/support/pyghidraRun")):
                    with mock.patch.object(gtdecomp.subprocess, "run", side_effect=write_empty_manifest):
                        with self.assertRaisesRegex(RuntimeError, "does not match requested function selection"):
                            gtdecomp.decompile_elf(
                                root / "input.elf", out, root / "ghidra", function_vas=[0x10730]
                            )

    def test_decompile_parser_accepts_repeated_function_vas(self):
        with mock.patch.object(gtdecomp, "decompile_elf", return_value={}) as decompile:
            with mock.patch("builtins.print"):
                result = gtdecomp.main([
                    "decompile", "EBOOT.elf", "--ghidra", "/opt/ghidra",
                    "--function-va", "0x00010730", "--function-va", "0x00010360",
                ])
        self.assertEqual(result, 0)
        self.assertEqual(decompile.call_args.kwargs["function_vas"], [0x10730, 0x10360])

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
        struct.pack_into(">II", data, 0x308, 0x1080, 0x3800)
        # bl 0x1050 from 0x1000, followed by blr, plus a standalone stdu
        # prologue at 0x1030. The blr closes the first function before 0x1030.
        struct.pack_into(">I", data, 0x200, 0x48000051)
        struct.pack_into(">I", data, 0x204, 0x4E800020)
        struct.pack_into(">I", data, 0x230, 0xF821FF91)
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
                             [(0x3000, 0x1000), (0x3008, 0x1080)])
            candidates = {x.code_va: x for x in gtdecomp.discover_function_candidates(elf, opd)}
            self.assertIn("direct-call", candidates[0x1050].evidence)
            self.assertIn("stack-prologue", candidates[0x1030].evidence)


if __name__ == "__main__":
    unittest.main()
