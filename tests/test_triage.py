"""Observe known byte specimens without executing them."""

import hashlib
from pathlib import Path
import struct
import tempfile
import unittest

from custodia.triage import inspect


class TriageTests(unittest.TestCase):
    def observe(self, raw, **options):
        with tempfile.TemporaryDirectory() as temporary:
            sample = Path(temporary) / "sample.bin"
            sample.write_bytes(raw)
            result = inspect(sample, **options)
            self.assertEqual(sample.read_bytes(), raw)
        self.assertEqual(result["bytes"], len(raw))
        self.assertEqual(result["sha256"], hashlib.sha256(raw).hexdigest())
        self.assertFalse(result["target_executed"])
        self.assertEqual(result["classification"], "not_performed")
        return result

    def test_empty_and_uniform_byte_entropy(self):
        empty = self.observe(b"")
        self.assertEqual(empty["entropy_bits_per_byte"], 0)
        self.assertEqual(empty["format"], "unknown")
        self.assertEqual(empty["ascii_strings"], [])
        uniform = self.observe(bytes(range(256)) * 3)
        self.assertEqual(uniform["entropy_bits_per_byte"], 8)
        repeated = self.observe(b"\xff" * 1000)
        self.assertEqual(repeated["entropy_bits_per_byte"], 0)

    def test_little_endian_elf64_header(self):
        identity = b"\x7fELF\x02\x01\x01" + b"\0" * 9
        sample = struct.pack("<16sHHIQQQIHHHHHH", identity, 2, 62, 1, 0x401000, 0, 0, 0, 64, 56, 0, 64, 0, 0)
        result = self.observe(sample)
        self.assertEqual(result["format"], "ELF")
        self.assertEqual(result["architecture"], "x86-64")
        self.assertEqual(result["bits"], 64)
        self.assertEqual(result["byte_order"], "little")
        self.assertEqual(result["entry_point"], "0x401000")
        self.assertEqual(result["header_status"], "observed")
        self.assertEqual(result["observation_scope"], "byte_statistics_and_bounded_headers")

    def test_big_endian_elf32_header(self):
        identity = b"\x7fELF\x01\x02\x01" + b"\0" * 9
        sample = struct.pack(">16sHHIIIIIHHHHHH", identity, 2, 40, 1, 0x8000, 0, 0, 0, 52, 32, 0, 40, 0, 0)
        result = self.observe(sample)
        self.assertEqual(result["architecture"], "ARM")
        self.assertEqual(result["bits"], 32)
        self.assertEqual(result["byte_order"], "big")
        self.assertEqual(result["entry_point"], "0x8000")

    def test_elf_short_header_and_invalid_identification_stay_incomplete(self):
        samples = [b"\x7fELF", b"\x7fELF\x02\x01" + b"\0" * 46,
                   b"\x7fELF\x03\x01" + b"\0" * 58, b"\x7fELF\x02\x03" + b"\0" * 58]
        for sample in samples:
            with self.subTest(sample=sample[:6]):
                result = self.observe(sample)
                self.assertEqual(result["format"], "ELF")
                self.assertEqual(result["header_status"], "malformed_or_truncated")
                self.assertEqual(result["architecture"], "unknown")
                self.assertNotIn("entry_point", result)

    def test_pe_machine_and_section_count(self):
        sample = bytearray(152)
        sample[:2] = b"MZ"
        struct.pack_into("<I", sample, 60, 128)
        sample[128:132] = b"PE\0\0"
        struct.pack_into("<HH", sample, 132, 0x8664, 3)
        result = self.observe(bytes(sample))
        self.assertEqual(result["format"], "PE")
        self.assertEqual(result["architecture"], "x86-64")
        self.assertEqual(result["declared_sections"], 3)
        self.assertEqual(result["header_status"], "observed")

    def test_pe_signature_outside_header_window_is_not_claimed_parsed(self):
        sample = bytearray(70000)
        sample[:2] = b"MZ"
        struct.pack_into("<I", sample, 60, 66000)
        sample[66000:66004] = b"PE\0\0"
        struct.pack_into("<HH", sample, 66004, 0x8664, 3)
        for raw in (b"MZ", bytes(sample)):
            with self.subTest(size=len(raw)):
                result = self.observe(raw)
                self.assertEqual(result["format"], "PE-candidate")
                self.assertEqual(result["header_status"], "not_fully_parsed")
                self.assertNotIn("declared_sections", result)

    def test_magic_only_formats_and_wasm_version_are_qualified(self):
        for raw, kind in ((b"PK\x03\x04", "ZIP-candidate"), (b"\xcf\xfa\xed\xfe", "Mach-O-candidate")):
            with self.subTest(kind=kind):
                result = self.observe(raw)
                self.assertEqual(result["format"], kind)
                self.assertEqual(result["header_status"], "magic_only")
        wasm = self.observe(b"\0asm\x01\0\0\0")
        self.assertEqual(wasm["format"], "WebAssembly")
        self.assertEqual(wasm["declared_version"], 1)
        short = self.observe(b"\0asm")
        self.assertEqual(short["header_status"], "truncated")
        self.assertIsNone(short["declared_version"])

    def test_ascii_run_crosses_read_boundary_without_losing_offset(self):
        raw = b"\0" * 65533 + b"ABCDEFGH" + b"\0"
        result = self.observe(raw)
        self.assertEqual(result["ascii_strings"], [{"offset": 65533, "value": "ABCDEFGH", "truncated": False}])
        self.assertEqual(result["ascii_runs_at_least_6"], 1)

    def test_long_string_and_list_clipping_are_explicit(self):
        result = self.observe(b"A" * 10000 + b"\0second-value\0third-value\0", max_strings=2, string_limit=10)
        self.assertEqual(len(result["ascii_strings"]), 2)
        self.assertEqual(result["ascii_strings"][0], {"offset": 0, "value": "A" * 10, "truncated": True})
        self.assertEqual(result["ascii_strings"][1]["offset"], 10001)
        self.assertTrue(result["string_list_truncated"])
        self.assertEqual(result["ascii_runs_at_least_6"], 3)

    def test_trailing_string_is_retained_and_short_runs_are_ignored(self):
        result = self.observe(b"short\0visible-last")
        self.assertEqual(result["ascii_strings"], [{"offset": 6, "value": "visible-last", "truncated": False}])
        self.assertEqual(result["ascii_runs_at_least_6"], 1)

    def test_control_bytes_do_not_enter_ascii_observations(self):
        result = self.observe(b"before\x1bafter!\x07ending")
        self.assertEqual([entry["value"] for entry in result["ascii_strings"]], ["before", "after!", "ending"])
        self.assertNotIn("\x1b", str(result["ascii_strings"]))
        self.assertNotIn("\x07", str(result["ascii_strings"]))


if __name__ == "__main__":
    unittest.main()
