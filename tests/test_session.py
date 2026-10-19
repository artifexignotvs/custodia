from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from custodia import backend, session
from custodia.policy import Policy
from custodia.receipt import verify
from custodia.safeio import Invalid, canonical, digest
from custodia.triage import inspect


class SessionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.directory = Path(self.temporary.name)
        self.source = self.directory / "source.bin"
        self.source.write_bytes(b"synthetic evidence\n")
        self.calls: list[str] = []
        self.policy = Policy()
        self.patches = [patch.object(session, "doctor", return_value={"available": True}),
                        patch.object(session, "engine_identity", return_value="1" * 64),
                        patch.object(session, "run", side_effect=self.successful_run)]
        for item in self.patches:
            item.start()

    def tearDown(self) -> None:
        for item in reversed(self.patches):
            item.stop()
        self.temporary.cleanup()

    def successful_run(self, argv: list[str], mounts: dict, limits: backend.Limits) -> backend.Outcome:
        self.calls.append(argv[3])
        result = inspect(mounts["/input/sample.bin"]) if argv[3] == "triage" else {
            "schema": "custodia.ghidra-report.v1", "status": "completed",
            "analysis_timed_out": False, "decompilation_failed": False,
            "functions": {"items": [{"name": "main"}]},
        }
        envelope = {"schema": "custodia.worker.v1", "status": "completed", "result": result,
                    "diagnostics": {}}
        enforcement = {"verified": True, "backend": "bubblewrap+systemd-user-cgroup-v2",
                       "memory_max_bytes": limits.memory_mib * 1024**2, "memory_swap_max_bytes": 0,
                       "pids_max": limits.pids, "scratch_max_bytes": limits.scratch_mib * 1024**2,
                       "cpu_quota_us": limits.cpu_percent * 1000, "cpu_period_us": 100000,
                       "wall_seconds": limits.wall_seconds, "network": "isolated", "capabilities": "none",
                       "termination": "control-group", "readonly_input": True, "isolated_home": True}
        return backend.Outcome("completed", 0, canonical(envelope), b"", 0.01, enforcement, True)

    def execute(self, name: str, **kwargs) -> dict:
        return session.run_session(self.source, self.directory / name, self.policy, **kwargs)

    def test_complete_snapshot_verifies_and_does_not_change_source(self) -> None:
        before = self.source.read_bytes()
        result = self.execute("first")
        self.assertEqual(result["status"], "completed")
        self.assertTrue(verify(self.directory / "first")["valid"])
        self.assertEqual(self.source.read_bytes(), before)
        self.assertNotIn(str(self.source), canonical(result).decode())

    def test_existing_output_never_overwritten(self) -> None:
        output = self.directory / "existing"
        output.mkdir()
        marker = output / "marker"
        marker.write_bytes(b"preserve")
        with self.assertRaises(Invalid):
            self.execute("existing")
        self.assertEqual(marker.read_bytes(), b"preserve")
        self.assertEqual(self.calls, [])

    def test_unavailable_boundary_creates_no_session(self) -> None:
        with patch.object(session, "doctor", return_value={"available": False}):
            with self.assertRaises(Invalid):
                self.execute("unavailable")
        self.assertFalse((self.directory / "unavailable").exists())
        self.assertEqual(self.calls, [])

    def test_retry_reuses_only_exact_verified_identity(self) -> None:
        first = self.execute("first")
        result = self.execute("retry", retry=self.directory / "first")
        self.assertEqual(self.calls, ["triage"])
        self.assertEqual(result["stages"][0]["status"], "reused")
        self.assertEqual(first["input"], result["input"])
        self.assertEqual(result["parent_receipt_sha256"], verify(self.directory / "first")["receipt_sha256"])
        self.assertTrue(verify(self.directory / "retry")["valid"])

    def test_input_change_disables_reuse(self) -> None:
        self.execute("first")
        self.source.write_bytes(b"changed synthetic evidence")
        result = self.execute("retry", retry=self.directory / "first")
        self.assertEqual(self.calls, ["triage", "triage"])
        self.assertEqual(result["stages"][0]["status"], "completed")

    def test_policy_change_disables_reuse(self) -> None:
        self.execute("first")
        self.policy = replace(self.policy, wall_seconds=240)
        result = self.execute("retry", retry=self.directory / "first")
        self.assertEqual(self.calls, ["triage", "triage"])
        self.assertEqual(result["stages"][0]["status"], "completed")

    def test_engine_change_disables_reuse(self) -> None:
        self.execute("first")
        with patch.object(session, "engine_identity", return_value="2" * 64):
            result = self.execute("retry", retry=self.directory / "first")
        self.assertEqual(self.calls, ["triage", "triage"])
        self.assertEqual(result["stages"][0]["status"], "completed")

    def test_corrupted_parent_rejected_before_output_creation(self) -> None:
        self.execute("first")
        (self.directory / "first" / "triage.json").write_bytes(b"changed")
        with self.assertRaises(Invalid):
            self.execute("retry", retry=self.directory / "first")
        self.assertFalse((self.directory / "retry").exists())

    def test_retry_detects_parent_artifact_changed_after_verification(self) -> None:
        self.execute("first")
        parent = self.directory / "first"
        def verify_then_mutate(directory):
            result = verify(directory)
            (directory / "triage.json").write_bytes(b'{"modified":true}')
            return result
        with patch.object(session, "verify", side_effect=verify_then_mutate):
            with self.assertRaises(Invalid):
                self.execute("retry", retry=parent)

    def test_provider_change_is_rejected(self) -> None:
        self.execute("first")
        ghidra = {"name": "ghidra", "version": "12.1.4", "tree_sha256": "2" * 64,
                  "file_count": 1, "size_bytes": 1, "tested_version": True}
        java = {"name": "java", "version": "21.0.8", "tree_sha256": "3" * 64,
                "file_count": 1, "size_bytes": 1}
        with patch("custodia.providers.ghidra.tool_identity", return_value=ghidra), \
             patch.object(session, "java_identity", return_value=java):
            with self.assertRaises(Invalid):
                self.execute("retry", retry=self.directory / "first",
                             ghidra_home=self.directory / "ghidra", java_home=self.directory / "jdk")
        self.assertFalse((self.directory / "retry").exists())

    def test_tool_distribution_change_disables_reuse(self) -> None:
        ghidra = {"name": "ghidra", "version": "12.1.4", "tree_sha256": "2" * 64,
                  "file_count": 1, "size_bytes": 1, "tested_version": True}
        java = {"name": "java", "version": "21.0.8", "tree_sha256": "3" * 64,
                "file_count": 1, "size_bytes": 1}
        options = {"ghidra_home": self.directory / "ghidra", "java_home": self.directory / "jdk"}
        with patch("custodia.providers.ghidra.tool_identity", return_value=ghidra), \
             patch.object(session, "java_identity", return_value=java):
            self.execute("first", **options)
        changed = {**ghidra, "tree_sha256": "4" * 64}
        with patch("custodia.providers.ghidra.tool_identity", return_value=changed), \
             patch.object(session, "java_identity", return_value=java):
            result = self.execute("retry", retry=self.directory / "first", **options)
        self.assertEqual(self.calls, ["triage", "ghidra", "triage", "ghidra"])
        self.assertEqual(result["status"], "completed")
        self.assertTrue(verify(self.directory / "retry")["valid"])

    def test_same_tool_retry_repeats_analysis_but_preserves_triage(self) -> None:
        ghidra = {"name": "ghidra", "version": "12.1.4", "tree_sha256": "2" * 64,
                  "file_count": 1, "size_bytes": 1, "tested_version": True}
        java = {"name": "java", "version": "21.0.8", "tree_sha256": "3" * 64,
                "file_count": 1, "size_bytes": 1}
        options = {"ghidra_home": self.directory / "ghidra", "java_home": self.directory / "jdk"}
        with patch("custodia.providers.ghidra.tool_identity", return_value=ghidra), \
             patch.object(session, "java_identity", return_value=java):
            self.execute("first", **options)
            result = self.execute("retry", retry=self.directory / "first", **options)
        self.assertEqual(self.calls, ["triage", "ghidra", "ghidra"])
        self.assertEqual(result["stages"][0]["status"], "reused")
        self.assertEqual(result["stages"][1]["status"], "completed")
        self.assertTrue(verify(self.directory / "retry")["valid"])

    def test_tool_mutation_during_analysis_prevents_completion(self) -> None:
        ghidra = {"name": "ghidra", "version": "12.1.4", "tree_sha256": "2" * 64,
                  "file_count": 1, "size_bytes": 1, "tested_version": True}
        java = {"name": "java", "version": "21.0.8", "tree_sha256": "3" * 64,
                "file_count": 1, "size_bytes": 1}
        with patch("custodia.providers.ghidra.tool_identity",
                   side_effect=[ghidra, {**ghidra, "tree_sha256": "4" * 64}]), \
             patch.object(session, "java_identity", return_value=java):
            result = self.execute("changed", ghidra_home=self.directory / "ghidra",
                                  java_home=self.directory / "jdk")
        self.assertEqual(result["status"], "protocol_error")

    def test_worker_completion_cannot_hide_partial_or_invalid_analysis(self) -> None:
        report = {"schema": "custodia.ghidra-report.v1", "status": "completed",
                  "analysis_timed_out": False, "decompilation_failed": False,
                  "functions": {"items": []}}
        identity = {"sha256": "0" * 64, "bytes": 0}
        for field, value in (("status", "partial"), ("analysis_timed_out", True),
                             ("decompilation_failed", True), ("functions", [])):
            with self.subTest(field=field):
                envelope = {"schema": "custodia.worker.v1", "status": "completed",
                            "result": {**report, field: value}, "diagnostics": {}}
                with self.assertRaises(Invalid):
                    session._worker_result(canonical(envelope), "analysis", identity)

    def test_incomplete_prior_stage_is_executed_again(self) -> None:
        failure = backend.Outcome("timeout", None, b"", b"", 0.1, {"verified": True}, True)
        with patch.object(session, "run", return_value=failure):
            first = self.execute("first")
        self.assertEqual(first["status"], "timeout")
        self.assertTrue(verify(self.directory / "first")["valid"])
        result = self.execute("retry", retry=self.directory / "first")
        self.assertEqual(self.calls, ["triage"])
        self.assertEqual(result["stages"][0]["status"], "completed")

    def test_claimed_completion_requires_cleanup_returncode_and_controls(self) -> None:
        for name, changes in (("cleanup", {"cleanup_verified": False}),
                              ("exit", {"returncode": 2}),
                              ("controls", {"enforcement": {"verified": False}})):
            with self.subTest(name=name):
                def altered(argv, mounts, limits, changes=changes):
                    return replace(self.successful_run(argv, mounts, limits), **changes)
                with patch.object(session, "run", side_effect=altered):
                    result = self.execute(name)
                self.assertNotEqual(result["status"], "completed")

    def test_mismatched_triage_hash_rejected(self) -> None:
        envelope = {"schema": "custodia.worker.v1", "status": "completed",
                    "result": {"schema": "custodia.triage.v1", "sha256": "0" * 64, "bytes": 0},
                    "diagnostics": {}}
        result = backend.Outcome("completed", 0, canonical(envelope), b"", 0.1, {"verified": True}, True)
        with patch.object(session, "run", return_value=result):
            receipt = self.execute("mismatch")
        self.assertEqual(receipt["status"], "protocol_error")

    def test_timeout_never_promotes_partial_stdout_to_completion(self) -> None:
        def timed_out(argv, mounts, limits):
            return replace(self.successful_run(argv, mounts, limits), status="timeout")
        with patch.object(session, "run", side_effect=timed_out):
            result = self.execute("timeout")
        self.assertEqual(result["status"], "timeout")
        self.assertIsNone(result["stages"][0]["artifact"])

    def test_interruption_keeps_verifiable_snapshot(self) -> None:
        with patch.object(session, "run", side_effect=KeyboardInterrupt):
            result = self.execute("interrupted")
        self.assertEqual(result["status"], "interrupted")
        self.assertTrue(verify(self.directory / "interrupted")["valid"])

    def test_engine_rescan_error_cannot_publish_completed_receipt(self) -> None:
        with patch.object(session, "engine_identity", side_effect=["1" * 64, Invalid("Engine rescan failed.")]):
            with self.assertRaises(Invalid):
                self.execute("engine-rescan-error")
        result = verify(self.directory / "engine-rescan-error")
        self.assertTrue(result["valid"])
        self.assertEqual(result["receipt"]["status"], "protocol_error")
        self.assertEqual(result["receipt"]["stages"][0]["status"], "completed")

    def test_tool_rescan_errors_cannot_publish_completed_receipt(self) -> None:
        ghidra = {"name": "ghidra", "version": "12.1.4", "tree_sha256": "2" * 64,
                  "file_count": 1, "size_bytes": 1, "tested_version": True}
        java = {"name": "java", "version": "21.0.8", "tree_sha256": "3" * 64,
                "file_count": 1, "size_bytes": 1}
        for failing_tool in ("ghidra", "java"):
            with self.subTest(tool=failing_tool):
                ghidra_results = [ghidra, Invalid("Tool rescan failed.") if failing_tool == "ghidra" else ghidra]
                java_results = [java, Invalid("Runtime rescan failed.") if failing_tool == "java" else java]
                output = failing_tool + "-rescan-error"
                with patch("custodia.providers.ghidra.tool_identity", side_effect=ghidra_results), \
                     patch.object(session, "java_identity", side_effect=java_results):
                    with self.assertRaises(Invalid):
                        self.execute(output, ghidra_home=self.directory / "ghidra",
                                     java_home=self.directory / "jdk")
                result = verify(self.directory / output)
                self.assertTrue(result["valid"])
                self.assertEqual(result["receipt"]["status"], "protocol_error")
                self.assertEqual([stage["status"] for stage in result["receipt"]["stages"]],
                                 ["completed", "completed"])


if __name__ == "__main__":
    unittest.main()
