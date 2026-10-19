"""Portable installed-package acceptance; no live isolation claim is made here."""
from __future__ import annotations

from importlib import metadata, resources
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

import custodia
from custodia.identity import engine_identity
from custodia.policy import Policy, from_document
from custodia.receipt import publish, verify
from custodia.safeio import Invalid, canonical, digest, parse, write_new
from custodia.triage import inspect


class InstalledAcceptance(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="custodia-acceptance-")
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)

    def command(self, *arguments, entrypoint=False):
        environment = {"PATH": os.defpath, "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
                       "HOME": str(self.directory), "PYTHONSAFEPATH": "1"}
        prefix = ([str(Path(sys.executable).with_name("custodia"))] if entrypoint
                  else [sys.executable, "-B", "-I", "-m", "custodia"])
        result = subprocess.run([*prefix, *map(str, arguments)], env=environment,
                                cwd=self.directory, capture_output=True, timeout=15)
        self.assertNotIn(b"Traceback", result.stderr)
        self.assertNotIn(b"\x1b", result.stdout + result.stderr)
        return result

    def make_failed_session(self, name, payload=b"controlled byte fixture"):
        # Receptum fictum defectum declarat, non executionem probatam.
        directory = self.directory / name
        directory.mkdir()
        write_new(directory / "input.bin", payload)
        policy = Policy()
        identity = engine_identity()
        receipt = {
            "schema": "custodia.receipt.v1", "version": custodia.__version__,
            "engine_sha256": identity, "started_utc": "2026-01-01T00:00:00+00:00",
            "finished_utc": "2026-01-01T00:00:01+00:00", "status": "failed", "provider": "triage",
            "input": {"artifact": "input.bin", "sha256": digest(payload), "bytes": len(payload)},
            "policy": policy.document, "policy_sha256": policy.sha256,
            "tools": {"engine_sha256": identity}, "stages": [], "artifacts": [],
            "parent_receipt_sha256": None, "authenticity": "not_established",
            "scope": "recorded_execution_and_artifact_consistency",
        }
        publish(directory, receipt)
        return directory

    def test_imports_come_from_this_isolated_installation(self):
        self.assertEqual(sys.flags.isolated, 1)
        self.assertNotEqual(sys.prefix, sys.base_prefix)
        package = Path(custodia.__file__).resolve()
        self.assertTrue(package.is_relative_to(Path(sys.prefix).resolve()))
        self.assertFalse(Path.cwd().resolve().is_relative_to(package.parent))
        self.assertEqual(metadata.version("custodia"), custodia.__version__)
        self.assertRegex(engine_identity(), re.compile(r"\A[0-9a-f]{64}\Z"))

    def test_original_java_exporter_is_packaged(self):
        source = resources.files("custodia.providers").joinpath("scripts", "CustodiaReport.java").read_text(encoding="utf-8")
        self.assertIn("class CustodiaReport", source)
        self.assertIn("custodia.ghidra-report.v1", source)
        self.assertIn("extends HeadlessScript", source)

    def test_console_entrypoint_and_module_version(self):
        for entrypoint in (False, True):
            result = self.command("--version", entrypoint=entrypoint)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.decode().strip(), "custodia " + custodia.__version__)
            self.assertEqual(result.stderr, b"")

    def test_help_and_policy_work_without_host_isolation(self):
        help_result = self.command("--help")
        self.assertEqual(help_result.returncode, 0, help_result.stderr)
        for name in (b"doctor", b"run", b"verify", b"retry", b"compare"):
            self.assertIn(name, help_result.stdout)
        policy_result = self.command("policy")
        self.assertEqual(policy_result.returncode, 0, policy_result.stderr)
        self.assertEqual(from_document(json.loads(policy_result.stdout)), Policy())

    def test_static_fixture_observations_preserve_bytes(self):
        sample = self.directory / "sample.bin"
        content = b"\0asm\x01\0\0\0controlled fixture\0"
        sample.write_bytes(content)
        result = inspect(sample)
        self.assertEqual(sample.read_bytes(), content)
        self.assertEqual(result["sha256"], digest(content))
        self.assertEqual(result["bytes"], len(content))
        self.assertEqual(result["format"], "WebAssembly")
        self.assertEqual(result["declared_version"], 1)
        self.assertIs(result["target_executed"], False)
        self.assertEqual(result["classification"], "not_performed")

    def test_saved_receipt_readers_establish_consistency_only(self):
        directory = self.make_failed_session("case")
        result = self.command("verify", directory, "--json")
        self.assertEqual(result.returncode, 0, result.stderr)
        value = json.loads(result.stdout)
        self.assertTrue(value["valid"])
        self.assertEqual(value["receipt"]["status"], "failed")
        self.assertEqual(value["authenticity"], "not_established")
        self.assertFalse(value["execution_repeated"])
        inspected = self.command("inspect", directory)
        self.assertEqual(inspected.returncode, 0, inspected.stderr)
        self.assertIn(b"FAILED", inspected.stdout)

    def test_comparison_and_tamper_detection(self):
        first = self.make_failed_session("first")
        second = self.make_failed_session("second", b"different controlled bytes")
        result = self.command("compare", first, second, "--json")
        self.assertEqual(result.returncode, 0, result.stderr)
        comparison = json.loads(result.stdout)
        self.assertFalse(comparison["same_input"])
        self.assertTrue(comparison["same_policy"])
        self.assertEqual(comparison["vulnerability_verdict"], "not_performed")
        (first / "input.bin").write_bytes(b"modified")
        with self.assertRaises(Invalid):
            verify(first)
        self.assertEqual(self.command("verify", first).returncode, 2)

    def test_malformed_policy_and_structured_data_are_refused(self):
        bad_policy = self.directory / "policy.json"
        bad_policy.write_bytes(b'{"schema":"custodia.policy.v1"}')
        output = self.directory / "must-not-exist"
        result = self.command("run", "missing.bin", "--out", output, "--policy", bad_policy)
        self.assertEqual(result.returncode, 2)
        self.assertFalse(output.exists())
        for raw in (b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":1e9999}'):
            with self.assertRaises(Invalid):
                parse(raw)
        self.assertEqual(parse(canonical({"safe": True})), {"safe": True})


if __name__ == "__main__":
    unittest.main(verbosity=2)
