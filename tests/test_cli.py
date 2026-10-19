"""Exercise the real command parser and saved-session reader in subprocesses."""

from dataclasses import replace
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from custodia import __version__
from custodia.policy import Policy
from custodia.receipt import publish
from custodia.safeio import canonical, digest, write_new
from custodia.triage import inspect as inspect_bytes


class CliTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="custodia-cli-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = Path(__file__).resolve().parents[1] / "src"

    def command(self, *arguments):
        environment = {"PATH": os.defpath, "PYTHONPATH": str(self.source), "PYTHONNOUSERSITE": "1",
                       "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "HOME": str(self.root)}
        result = subprocess.run([sys.executable, "-m", "custodia.cli", *map(str, arguments)],
                                env=environment, cwd=self.root, capture_output=True, timeout=20)
        self.assertNotIn(b"\x1b", result.stdout + result.stderr)
        self.assertNotIn(b"Traceback", result.stderr)
        return result

    def make_session(self, name, payload=b"synthetic evidence", policy=None, with_triage=False, transform=None):
        # Receptum fictum defectum refert; executio probata non simulatur.
        folder = self.root / name
        folder.mkdir()
        write_new(folder / "input.bin", payload)
        policy = policy or Policy()
        receipt = {
            "schema": "custodia.receipt.v1", "version": __version__, "engine_sha256": "1" * 64,
            "started_utc": "2026-01-01T00:00:00+00:00", "finished_utc": "2026-01-01T00:00:01+00:00",
            "status": "failed", "provider": "triage",
            "input": {"artifact": "input.bin", "sha256": digest(payload), "bytes": len(payload)},
            "policy": policy.document, "policy_sha256": policy.sha256, "tools": {"engine_sha256": "1" * 64},
            "stages": [], "artifacts": [], "parent_receipt_sha256": None,
            "authenticity": "not_established", "scope": "recorded_execution_and_artifact_consistency",
        }
        if with_triage:
            observed = inspect_bytes(folder / "input.bin")
            if transform is not None:
                transform(observed)
            write_new(folder / "triage.json", canonical(observed))
            receipt["stages"] = [{"name": "triage", "status": "failed", "returncode": 1,
                                  "elapsed_seconds": 0.0, "enforcement": {}, "cleanup_verified": False,
                                  "artifact": "triage.json", "reused_from": None}]
        publish(folder, receipt)
        return folder

    def test_help_and_version_work_without_analysis(self):
        result = self.command("--help")
        self.assertEqual(result.returncode, 0)
        for word in (b"doctor", b"selftest", b"run", b"verify", b"compare", b"retry"):
            self.assertIn(word, result.stdout)
        result = self.command("--version")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.decode().strip(), "custodia " + __version__)
        self.assertEqual(result.stderr, b"")

    def test_subcommand_help_exposes_actual_options(self):
        result = self.command("run", "--help")
        self.assertEqual(result.returncode, 0)
        for option in (b"--out", b"--policy", b"--ghidra-home", b"--java-home", b"--wall-seconds", b"--json"):
            self.assertIn(option, result.stdout)
        self.assertEqual(self.command("inspect", "--help").returncode, 0)

    def test_policy_is_parseable_and_complete(self):
        result = self.command("policy")
        self.assertEqual(result.returncode, 0)
        document = json.loads(result.stdout)
        self.assertEqual(document["schema"], "custodia.policy.v1")
        self.assertGreater(document["memory_mib"], document["scratch_mib"])
        self.assertGreaterEqual(document["wall_seconds"], 5)
        self.assertLessEqual(document["decompile_count"], 10)
        self.assertEqual(result.stderr, b"")

    def test_invalid_arguments_do_not_echo_terminal_controls(self):
        for arguments in ((), ("unknown\x1b[31m",), ("run",), ("run", "sample", "--out", "case", "--wall-seconds", "NaN"),
                          ("policy", "--surprise\x1b[2J")):
            with self.subTest(arguments=arguments):
                result = self.command(*arguments)
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, b"")
                self.assertIn(b"Invalid arguments", result.stderr)

    def test_invalid_policy_is_rejected_before_output_creation(self):
        for option, value in (("--wall-seconds", "0"), ("--memory-mib", "0")):
            with self.subTest(option=option):
                result = self.command("run", self.root / "missing", "--out", self.root / "output", option, value)
                self.assertEqual(result.returncode, 2)
                self.assertIn(b"Policy field", result.stderr)
                self.assertFalse((self.root / "output").exists())
        document = self.root / "bad-policy.json"
        document.write_text('{"schema":"custodia.policy.v1","wall_seconds":10}')
        result = self.command("run", "missing", "--out", "output", "--policy", document)
        self.assertEqual(result.returncode, 2)
        self.assertIn(b"policy", result.stderr)
        self.assertFalse((self.root / "output").exists())

    def test_tool_pair_is_required_without_starting_analysis(self):
        result = self.command("run", "missing", "--out", "output", "--ghidra-home", self.root / "private-tool")
        self.assertEqual(result.returncode, 2)
        self.assertIn(b"both --ghidra-home and --java-home", result.stderr)
        self.assertNotIn(b"private-tool", result.stderr)
        self.assertFalse((self.root / "output").exists())

    def test_verify_and_inspect_are_consistency_only(self):
        case = self.make_session("case")
        before = {path.name: path.read_bytes() for path in case.iterdir()}
        result = self.command("verify", case, "--json")
        self.assertEqual(result.returncode, 0, result.stderr)
        value = json.loads(result.stdout)
        self.assertTrue(value["valid"])
        self.assertEqual(value["authenticity"], "not_established")
        self.assertFalse(value["execution_repeated"])
        self.assertEqual(value["artifacts_verified"], 1)
        result = self.command("inspect", case)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(b"FAILED", result.stdout)
        self.assertIn(b"authenticity not established", result.stdout)
        self.assertEqual(before, {path.name: path.read_bytes() for path in case.iterdir()})

    def test_compare_distinguishes_input_and_policy(self):
        first = self.make_session("first")
        second = self.make_session("second", payload=b"different evidence", policy=replace(Policy(), memory_mib=3072))
        same = self.command("compare", first, first, "--json")
        self.assertEqual(same.returncode, 0, same.stderr)
        same_value = json.loads(same.stdout)
        self.assertTrue(same_value["same_input"])
        self.assertTrue(same_value["same_policy"])
        different = self.command("compare", first, second, "--json")
        self.assertEqual(different.returncode, 0, different.stderr)
        value = json.loads(different.stdout)
        self.assertFalse(value["same_input"])
        self.assertFalse(value["same_policy"])
        self.assertTrue(value["same_engine"])
        self.assertIsNone(value["sampled_functions_added"])
        self.assertEqual(value["vulnerability_verdict"], "not_performed")
        text = self.command("compare", first, second)
        self.assertEqual(text.returncode, 0)
        self.assertIn(b"DIFFERENT", text.stdout)
        self.assertIn(b"no vulnerability verdict", text.stdout)

    def test_tampered_and_missing_sessions_fail_without_path_disclosure(self):
        case = self.make_session("case")
        (case / "input.bin").write_bytes(b"altered")
        for command in ("verify", "inspect"):
            result = self.command(command, case)
            self.assertEqual(result.returncode, 2)
            self.assertIn(b"differ", result.stderr)
            self.assertEqual(result.stdout, b"")
        result = self.command("verify", self.root / "private-label\x1b[31m")
        self.assertEqual(result.returncode, 2)
        self.assertNotIn(b"private-label", result.stderr)
        self.assertNotIn(str(self.root).encode(), result.stderr)

    def test_malformed_receipt_has_sanitized_error(self):
        folder = self.root / "bad-receipt"
        folder.mkdir()
        (folder / "receipt.json").write_bytes(b'{"schema": "\xff\x1b[31m"}')
        result = self.command("inspect", folder, "--json")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, b"")
        self.assertIn(b"Invalid", result.stderr)


    def test_show_real_triage_overview_uses_complete_verified_inventory(self):
        payload = b"first-string\0second-string\0third-string"
        case = self.make_session("retained", payload=payload, with_triage=True)
        verified = self.command("verify", case, "--json")
        self.assertEqual(verified.returncode, 0, verified.stderr)
        self.assertEqual(json.loads(verified.stdout)["artifacts_verified"], 2)
        before = {path.name: path.read_bytes() for path in case.iterdir()}
        result = self.command("show", case)
        self.assertEqual(result.returncode, 0, result.stderr)
        overview = json.loads(result.stdout)
        self.assertEqual(overview["bytes"], len(payload))
        self.assertEqual(overview["sha256"], digest(payload))
        self.assertEqual(overview["ascii_runs_at_least_6"], 3)
        self.assertFalse(overview["target_executed"])
        self.assertEqual(overview["classification"], "not_performed")
        self.assertEqual(self.command("show", case, "--json").stdout, result.stdout)
        self.assertEqual(before, {path.name: path.read_bytes() for path in case.iterdir()})

    def test_show_applies_display_limit_without_changing_retained_count(self):
        case = self.make_session("rows", payload=b"first-string\0second-string\0third-string", with_triage=True)
        for limit, expected in ((1, 1), (100, 3)):
            with self.subTest(limit=limit):
                result = self.command("show", case, "--section", "strings", "--limit", limit)
                self.assertEqual(result.returncode, 0, result.stderr)
                value = json.loads(result.stdout)
                self.assertEqual(value["retained_rows"], 3)
                self.assertEqual(value["displayed_rows"], expected)
                self.assertEqual(len(value["items"]), expected)
                self.assertEqual(value["items"][0]["value"], "first-string")
                self.assertEqual(value["scope"], "retained_export_sample_only")
        for limit in (0, -1, 101, "not-a-number"):
            with self.subTest(limit=limit):
                result = self.command("show", case, "--section", "strings", "--limit", limit)
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, b"")

    def test_show_refuses_missing_or_malformed_sections(self):
        empty = self.make_session("without-triage")
        missing = self.command("show", empty)
        self.assertEqual(missing.returncode, 2)
        self.assertEqual(missing.stdout, b"")
        self.assertIn(b"no retained triage", missing.stderr)
        case = self.make_session("triage-only", with_triage=True)
        for section in ("functions", "imports", "exports", "decompile"):
            with self.subTest(section=section):
                result = self.command("show", case, "--section", section)
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, b"")
                self.assertIn(b"requires a retained Ghidra report", result.stderr)
        invalid = self.command("show", case, "--section", "unsupported")
        self.assertEqual(invalid.returncode, 2)
        malformed = self.make_session("malformed-section", with_triage=True,
                                      transform=lambda report: report.update(ascii_strings={"unexpected": "map"}))
        result = self.command("show", malformed, "--section", "strings")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, b"")
        self.assertIn(b"section is malformed", result.stderr)

    def test_show_verifies_artifacts_before_emitting_their_content(self):
        case = self.make_session("tampered-finding", with_triage=True)
        report = json.loads((case / "triage.json").read_bytes())
        report["ascii_strings"] = [{"offset": 0, "value": "unverified-secret-marker", "truncated": False}]
        (case / "triage.json").write_bytes(canonical(report))
        result = self.command("show", case, "--section", "strings")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, b"")
        self.assertNotIn(b"unverified-secret-marker", result.stderr)
        self.assertIn(b"differ", result.stderr)
        intact = self.make_session("unexpected-artifact", with_triage=True)
        (intact / "unlisted.json").write_text("{}")
        result = self.command("show", intact, "--section", "strings")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, b"")
        self.assertIn(b"Unexpected", result.stderr)

    def test_show_escapes_terminal_and_bidi_controls_in_retained_json(self):
        hostile = "name\x1b[2J\u202eright\u2066inside\u2069\x07"
        # Notae adversariae leguntur; fides a digestione sola non oritur.
        case = self.make_session("hostile-finding", with_triage=True,
                                 transform=lambda report: report.update(ascii_strings=[
                                     {"offset": 0, "value": hostile, "truncated": False}]))
        result = self.command("show", case, "--section", "strings")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn(b"\x07", result.stdout)
        for character in ("\u202e", "\u2066", "\u2069"):
            self.assertNotIn(character.encode("utf-8"), result.stdout)
        self.assertIn(b"\\u001b", result.stdout)
        self.assertIn(b"\\u202e", result.stdout)
        self.assertIn(b"\\u0007", result.stdout)
        self.assertEqual(json.loads(result.stdout)["items"][0]["value"], hostile)
        self.assertEqual(self.command("show", case, "--section", "strings", "--json").stdout, result.stdout)


if __name__ == "__main__":
    unittest.main()
