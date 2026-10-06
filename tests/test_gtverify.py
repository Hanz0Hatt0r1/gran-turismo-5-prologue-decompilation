import json
import struct
import tempfile
import unittest
from unittest import mock
from pathlib import Path

import gtcatalog
import gtverify
import source_inventory


class VerifyTests(unittest.TestCase):
    @staticmethod
    def make_elf(root: Path) -> Path:
        data = bytearray(0x500)
        data[0:16] = b"\x7fELF\x02\x02\x01\x66" + b"\0" * 8
        struct.pack_into(
            ">HHIQQQIHHHHHH",
            data, 16,
            2, 21, 1, 0x3000, 64, 0x400, 0,
            64, 56, 2, 64, 3, 2,
        )
        struct.pack_into(
            ">IIQQQQQQ",
            data, 64,
            1, 5, 0x200, 0x1000, 0x1000, 0x100, 0x100, 0x10,
        )
        struct.pack_into(
            ">IIQQQQQQ",
            data, 120,
            1, 6, 0x300, 0x3000, 0x3000, 0x40, 0x40, 8,
        )
        struct.pack_into(">II", data, 0x300, 0x1000, 0x3800)
        struct.pack_into(">I", data, 0x200, 0x48000051)
        struct.pack_into(">I", data, 0x204, 0x4E800020)
        path = root / "tiny.elf"
        path.write_bytes(data)
        return path

    def test_verify_function_record(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            elf_path = self.make_elf(root)
            record_path = root / "function.yaml"
            record_path.write_text(
                """schema: 1
id: synthetic.0x1000
build: SYNTH
module: EBOOT.ELF
address:
  va: 0x00001000
confidence: confirmed
status: reviewed
provenance:
  disassembly:
    range: "0x00001000-0x00001008"
fingerprints:
  normalized_full: 155622b99a30b638551336f6bc68330c23e16eb3
""",
                encoding="utf-8",
            )
            record = gtcatalog.load_record(record_path, root)
            result = gtverify.verify_function_record(
                gtverify.gtdecomp.PS3ELF(elf_path), record
            )
            self.assertTrue(result["valid"])
            self.assertEqual(result["range"]["size"], 8)

    def test_verify_build_record(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            elf_path = self.make_elf(root)
            elf = gtverify.gtdecomp.PS3ELF(elf_path)
            record_path = root / "build.json"
            record_path.write_text(
                '{"schema":1,"game":"Synthetic","title_id":"SYNTH","role":"test",'
                '"executable_sha256":"' + elf.sha256 + '",'
                '"format":"ELF64-big-endian-PowerPC64",'
                '"entry_descriptor_va":"0x00003000",'
                '"entry_code_va":"0x00001000",'
                '"toc_va":"0x00003800"}',
                encoding="utf-8",
            )
            record = gtcatalog.load_record(record_path, root)
            result = gtverify.verify_build_record(elf, record)
            self.assertTrue(result["valid"])

    def test_verify_source_xref_function_map(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            elf_path = self.make_elf(root)
            snapshot = root / "source-map.json"
            report = {
                "source_file_count": 1,
                "opd_range_mapping": {
                    "xref_instruction_count": 1,
                    "contained_xref_instruction_count": 1,
                    "uncontained_xref_instruction_count": 0,
                    "function_range_count": 1,
                },
                "opd_function_source_map": [{
                    "function_start_va": "0x00001000",
                    "function_end_va": "0x00001008",
                    "xref_count": 1,
                    "source_names": ["Synthetic.cpp"],
                    "source_categories": ["unclassified"],
                }],
            }
            snapshot.write_text(json.dumps({
                "schema": 1,
                "input_sha256": gtverify.gtdecomp.PS3ELF(elf_path).sha256,
                "source_file_count": 1,
                "toc_xref_instruction_count": 1,
                "opd_contained_xref_count": 1,
                "uncontained_xref_count": 0,
                "opd_function_range_count": 1,
                "functions": report["opd_function_source_map"],
            }), encoding="utf-8")
            with mock.patch.object(source_inventory, "build_report", return_value=report):
                result = gtverify.verify_source_xref_function_map(
                    gtverify.gtdecomp.PS3ELF(elf_path), snapshot
                )
            self.assertTrue(result["valid"])

    def test_verify_rejects_source_xref_function_map_mismatch(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            elf_path = self.make_elf(root)
            snapshot = root / "source-map.json"
            snapshot.write_text(json.dumps({
                "schema": 1,
                "input_sha256": gtverify.gtdecomp.PS3ELF(elf_path).sha256,
                "source_file_count": 99,
                "toc_xref_instruction_count": 0,
                "opd_contained_xref_count": 0,
                "uncontained_xref_count": 0,
                "opd_function_range_count": 1,
                "functions": [],
            }), encoding="utf-8")
            report = {
                "source_file_count": 1,
                "opd_range_mapping": {
                    "xref_instruction_count": 1,
                    "contained_xref_instruction_count": 1,
                    "uncontained_xref_instruction_count": 0,
                    "function_range_count": 1,
                },
                "opd_function_source_map": [],
            }
            with unittest.mock.patch.object(source_inventory, "build_report", return_value=report):
                result = gtverify.verify_source_xref_function_map(
                    gtverify.gtdecomp.PS3ELF(elf_path), snapshot
                )
            self.assertFalse(result["valid"])
    def test_verify_rejects_wrong_fingerprint(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            elf_path = self.make_elf(root)
            record_path = root / "function.yaml"
            record_path.write_text(
                """schema: 1
id: synthetic.0x1000
build: SYNTH
module: EBOOT.ELF
address:
  va: 0x00001000
confidence: confirmed
status: reviewed
provenance:
  disassembly:
    range: "0x00001000-0x00001008"
fingerprints:
  normalized_full: 0000000000000000000000000000000000000000
""",
                encoding="utf-8",
            )
            record = gtcatalog.load_record(record_path, root)
            result = gtverify.verify_function_record(
                gtverify.gtdecomp.PS3ELF(elf_path), record
            )
            self.assertFalse(result["valid"])


if __name__ == "__main__":
    unittest.main()
