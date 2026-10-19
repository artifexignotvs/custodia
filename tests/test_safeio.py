from __future__ import annotations

from dataclasses import replace
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from custodia import safeio
from custodia.policy import Policy, from_document


class SafeIOTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_json_duplicate_nonfinite_and_deep_nesting_rejected(self) -> None:
        for raw in (b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":Infinity}', b'{"x":1e9999}', b'{"x":-1e9999}', b'\xff',
                    b"[" * 2000 + b"0" + b"]" * 2000):
            with self.subTest(raw=raw[:30]):
                with self.assertRaises(safeio.Invalid):
                    safeio.parse(raw)

    def test_file_and_json_limits(self) -> None:
        path = self.root / "input"
        path.write_bytes(b"12345")
        self.assertEqual(safeio.read(path, 5), b"12345")
        for operation in (lambda: safeio.read(path, 4), lambda: safeio.hash_file(path, 4),
                          lambda: safeio.parse(b"[123]", 4)):
            with self.assertRaises(safeio.Invalid):
                operation()

    def test_json_depth_guard_ignores_escaped_string_delimiters(self) -> None:
        value = {"text": "[" * 2000 + '\\"' + "}" * 2000}
        self.assertEqual(safeio.parse(safeio.canonical(value)), value)

    def test_symlink_directory_and_fifo_never_opened_as_evidence(self) -> None:
        source = self.root / "source"
        source.write_bytes(b"content")
        link = self.root / "link"
        link.symlink_to(source)
        fifo = self.root / "fifo"
        os.mkfifo(fifo)
        for path in (link, fifo, self.root):
            with self.subTest(kind=path.name):
                with self.assertRaises(safeio.Invalid):
                    safeio.read(path)

    def test_write_new_does_not_overwrite_file_or_symlink(self) -> None:
        target = self.root / "target"
        target.write_bytes(b"preserve")
        for path in (target, self.root / "link"):
            if path != target:
                path.symlink_to(target)
            with self.assertRaises(safeio.Invalid):
                safeio.write_new(path, b"replacement")
        self.assertEqual(target.read_bytes(), b"preserve")
        self.assertFalse(list(self.root.glob(".custodia-*")))

    def test_snapshot_hash_bound_and_no_overwrite(self) -> None:
        source, target = self.root / "source", self.root / "input.bin"
        source.write_bytes(b"synthetic")
        identity = safeio.snapshot(source, target)
        self.assertEqual(identity["sha256"], safeio.digest(b"synthetic"))
        self.assertEqual(identity["bytes"], 9)
        with self.assertRaises(safeio.Invalid):
            safeio.snapshot(source, target)
        self.assertEqual(target.read_bytes(), b"synthetic")
        with patch.object(safeio, "INPUT_LIMIT", 4):
            with self.assertRaises(safeio.Invalid):
                safeio.snapshot(source, self.root / "too-large")
        self.assertFalse((self.root / "too-large").exists())
        self.assertFalse(list(self.root.glob(".custodia-*")))

    def test_new_directory_is_private_and_exclusive(self) -> None:
        directory = self.root / "output"
        safeio.new_directory(directory)
        self.assertEqual(directory.stat().st_mode & 0o777, 0o700)
        with self.assertRaises(safeio.Invalid):
            safeio.new_directory(directory)

    def test_policy_rejects_bool_floats_unknown_fields_and_capacity_conflict(self) -> None:
        for value in (True, 128.0, "128", None):
            with self.subTest(value=value):
                with self.assertRaises(safeio.Invalid):
                    replace(Policy(), pids=value)
        with self.assertRaises(safeio.Invalid):
            replace(Policy(), scratch_mib=2048)
        document = Policy().document
        document["unexpected"] = 1
        with self.assertRaises(safeio.Invalid):
            from_document(document)
        self.assertEqual(from_document(Policy().document), Policy())


if __name__ == "__main__":
    unittest.main()
