from __future__ import annotations

from dataclasses import replace
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

from custodia import backend, selftest


def successful_outcome(identifier: str) -> backend.Outcome:
    facts = {key: True for key in selftest.FACT_KEYS[identifier]}
    if identifier == "pids":
        facts["children_started"] = 9
    status = {"memory": "memory_limit", "timeout": "timeout", "output": "output_limit"}.get(
        identifier, "completed"
    )
    payload = json.dumps({"probe": identifier, "ok": True, "facts": facts}).encode()
    return backend.Outcome(status, 0, payload, b"", 0.01, {"verified": True}, True)


class SelftestTests(unittest.TestCase):
    def test_unavailable_stops_before_resource_probes(self) -> None:
        with patch.object(backend, "run", return_value=backend.Outcome("unavailable", None)) as run:
            result = selftest.run_selftest()
        self.assertEqual(run.call_count, 1)
        self.assertFalse(result["passed"])
        self.assertTrue(result["unsupported"])
        self.assertEqual(result["status"], "unavailable")
        self.assertEqual([check["id"] for check in result["checks"]], list(selftest.CHECK_IDS))
        self.assertTrue(all(check["status"] == "unavailable" for check in result["checks"]))

    def test_missing_handshake_stops_before_resource_probes(self) -> None:
        initial = replace(successful_outcome("isolation"), enforcement={"verified": False})
        with patch.object(backend, "run", return_value=initial) as run:
            result = selftest.run_selftest()
        self.assertEqual(run.call_count, 1)
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["checks"][0]["details"]["reason"], "enforcement_not_verified")

    def test_cleanup_failure_never_passes(self) -> None:
        for identifier in selftest.CHECK_IDS:
            with self.subTest(identifier=identifier):
                outcome = replace(successful_outcome(identifier), cleanup_verified=False)
                check = selftest._evaluate(identifier, outcome, selftest._limits(identifier))
                self.assertEqual(check["status"], "fail")
                self.assertEqual(check["details"]["reason"], "process_cleanup_not_verified")

    def test_report_accepts_only_fixed_safe_facts(self) -> None:
        value = json.loads(successful_outcome("host_canary").stdout)
        value["facts"]["secret_path"] = "/private/host/canary"
        outcome = replace(successful_outcome("host_canary"), stdout=json.dumps(value).encode())
        check = selftest._evaluate("host_canary", outcome, selftest._limits("host_canary"))
        self.assertEqual(check["status"], "pass")
        self.assertNotIn("/private/host", json.dumps(check))
        value["facts"]["host_file_hidden"] = "/private/host/canary"
        outcome = replace(outcome, stdout=json.dumps(value).encode())
        check = selftest._evaluate("host_canary", outcome, selftest._limits("host_canary"))
        self.assertEqual(check["status"], "fail")
        self.assertNotIn("/private/host", json.dumps(check))

    def test_invalid_or_confused_probe_results_fail(self) -> None:
        for payload in (b"not-json", b"[]", b'{"probe":"wrong"}', b'\xff',
                        b'{"probe":"host_canary","ok":true,"facts":{}}'):
            with self.subTest(payload=payload):
                outcome = replace(successful_outcome("host_canary"), stdout=payload)
                result = selftest._evaluate("host_canary", outcome, selftest._limits("host_canary"))
                self.assertEqual(result["status"], "fail")

    def test_memory_probe_requires_oom_not_a_generic_failure(self) -> None:
        for status in ("completed", "timeout", "failed", "output_limit"):
            with self.subTest(status=status):
                outcome = replace(successful_outcome("memory"), status=status)
                result = selftest._evaluate("memory", outcome, selftest._limits("memory"))
                self.assertEqual(result["status"], "fail")

    def test_detached_probe_requires_both_timeout_and_start_evidence(self) -> None:
        outcome = replace(successful_outcome("timeout"), stdout=b"")
        self.assertEqual(selftest._evaluate("timeout", outcome, selftest._limits("timeout"))["status"], "fail")
        outcome = replace(successful_outcome("timeout"), status="completed")
        self.assertEqual(selftest._evaluate("timeout", outcome, selftest._limits("timeout"))["status"], "fail")

    def test_output_cap_covers_both_streams(self) -> None:
        limits = selftest._limits("output")
        outcome = replace(successful_outcome("output"), stdout=b"x" * 32768, stderr=b"y" * 32769)
        self.assertEqual(selftest._evaluate("output", outcome, limits)["status"], "fail")
        outcome = replace(outcome, stderr=b"y" * 32768)
        self.assertEqual(selftest._evaluate("output", outcome, limits)["status"], "pass")

    def test_host_environment_restored_on_backend_error(self) -> None:
        with patch.dict(os.environ, {"CUSTODIA_SELFTEST_HOST_SECRET": "existing-value"}):
            with patch.object(backend, "run", side_effect=RuntimeError("backend error")):
                with self.assertRaises(RuntimeError):
                    selftest.run_selftest()
            self.assertEqual(os.environ["CUSTODIA_SELFTEST_HOST_SECRET"], "existing-value")

    def test_synthetic_permissions_cannot_fake_boundary(self) -> None:
        def inspect(argv: list[str], *, mounts: dict[str, Path], limits: backend.Limits) -> backend.Outcome:
            source = mounts["/input/sample.bin"]
            self.assertEqual(source.stat().st_mode & 0o777, 0o666)
            self.assertEqual(source.parent.stat().st_mode & 0o777, 0o755)
            self.assertEqual((source.parent / "host-only-canary").stat().st_mode & 0o777, 0o644)
            self.assertIn("CUSTODIA_SELFTEST_HOST_SECRET", os.environ)
            return backend.Outcome("unavailable", None)

        with patch.object(backend, "run", side_effect=inspect):
            selftest.run_selftest()

    def test_host_file_mutation_is_independently_detected(self) -> None:
        def run(argv: list[str], *, mounts: dict[str, Path], limits: backend.Limits) -> backend.Outcome:
            identifier = argv[5]
            if identifier == "input_readonly":
                mounts["/input/sample.bin"].write_bytes(b"changed")
            return successful_outcome(identifier)

        with patch.object(backend, "run", side_effect=run):
            result = selftest.run_selftest()
        check = next(item for item in result["checks"] if item["id"] == "input_readonly")
        self.assertFalse(result["passed"])
        self.assertFalse(check["details"]["host_input_hash_unchanged"])
        self.assertEqual(check["status"], "fail")

    def test_host_execution_guard_refuses_resource_probe(self) -> None:
        script = Path(selftest.__file__).with_name("probes.py")
        clean = {key: value for key, value in os.environ.items() if key != "CUSTODIA_ISOLATED"}
        completed = subprocess.run(
            [sys.executable, "-I", str(script), "--sandbox-probe", "memory"],
            capture_output=True, timeout=5, env=clean,
        )
        self.assertEqual(completed.returncode, 78)
        self.assertEqual(completed.stdout, b"")


@unittest.skipUnless(os.environ.get("CUSTODIA_INTEGRATION") == "1", "real isolation checks are opt-in")
class RealSelftestTests(unittest.TestCase):
    def test_real_boundary(self) -> None:
        result = selftest.run_selftest()
        self.assertTrue(result["passed"], json.dumps(result, indent=2))
        self.assertFalse(result["unsupported"])
        self.assertEqual(len(result["checks"]), len(selftest.CHECK_IDS))
        self.assertNotIn(str(Path.home()), json.dumps(result))


if __name__ == "__main__":
    unittest.main()
