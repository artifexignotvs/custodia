"""Check fixed provider boundaries and complete content identity."""

from pathlib import Path
import json
import os
import re
import subprocess
import tempfile
import unittest

from custodia.providers.ghidra import sandbox_command, sandbox_environment, tool_identity


class ProviderBoundaryTests(unittest.TestCase):
    def test_static_invocation_cannot_accept_target_arguments(self):
        command = sandbox_command({"target": "-postScript attacker.java", "script": "attacker.java"})
        self.assertEqual(command[0], "/opt/ghidra/support/analyzeHeadless")
        self.assertIn("/input/sample.bin", command)
        self.assertEqual(command[command.index("-postScript") + 1], "CustodiaReport.java")
        self.assertNotIn("attacker.java", command)
        self.assertEqual(command[command.index("-max-cpu") + 1], "1")

    def test_limits_reject_types_and_out_of_range(self):
        for key, value in [("max_functions", 1001), ("max_functions", True), ("decompile_count", 11),
                           ("decompile_count", -1), ("decompile_seconds", "10"), ("analysis_seconds", 0)]:
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                sandbox_command({key: value})
        with self.assertRaises(ValueError):
            sandbox_environment({"heap_mb": 4097})

    def test_environment_is_controlled_and_uses_isolated_cache(self):
        values = sandbox_environment({"JAVA_HOME": "/home/other", "heap_mb": 512})
        self.assertEqual(values["JAVA_HOME"], "/opt/java")
        self.assertEqual(values["PATH"], "/opt/java/bin:/usr/bin:/bin")
        self.assertEqual(values["GHIDRA_HEADLESS_MAXMEM"], "512M")
        self.assertIn("-Duser.home=/work/home", values["GHIDRA_HEADLESS_JAVA_OPTIONS"])
        self.assertIn("-Dapplication.cachedir=/work/cache", values["GHIDRA_HEADLESS_JAVA_OPTIONS"])
        self.assertNotIn("JAVA_TOOL_OPTIONS", values)

    def make_tree(self, base):
        root = Path(base) / "tool"
        (root / "Ghidra").mkdir(parents=True)
        (root / "support").mkdir()
        (root / "Ghidra/application.properties").write_text("application.version=12.1.4\n")
        (root / "support/analyzeHeadless").write_text("#!/bin/sh\n")
        (root / "support/analyzeHeadless").chmod(0o755)
        return root

    def test_identity_includes_bytes_and_executable_bit_without_host_path(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = self.make_tree(temporary)
            initial = tool_identity(root)
            self.assertEqual(initial["version"], "12.1.4")
            self.assertTrue(initial["tested_version"])
            self.assertEqual(initial["file_count"], 2)
            self.assertNotIn(temporary, str(initial))
            self.assertEqual(initial, tool_identity(root))
            (root / "support/analyzeHeadless").write_text("#!/bin/sh\nexit 1\n")
            changed = tool_identity(root)
            self.assertNotEqual(initial["tree_sha256"], changed["tree_sha256"])
            (root / "support/analyzeHeadless").chmod(0o644)
            self.assertNotEqual(changed["tree_sha256"], tool_identity(root)["tree_sha256"])

    def test_symlink_and_special_file_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = self.make_tree(temporary)
            (root / "escape").symlink_to("/etc/passwd")
            with self.assertRaises(ValueError):
                tool_identity(root)
            (root / "escape").unlink()
            os.mkfifo(root / "pipe")
            with self.assertRaises(ValueError):
                tool_identity(root)

    def test_missing_distribution_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(ValueError):
                tool_identity(Path(temporary))


@unittest.skipUnless(os.environ.get("CUSTODIA_TEST_GHIDRA") == "1", "optional verified Ghidra toolchain integration")
class GhidraIntegrationTests(unittest.TestCase):
    """Use an explicitly supplied toolchain and a newly compiled benign fixture."""

    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="custodia-integration-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.work = Path(cls.temporary.name)
        cls.repo = Path(__file__).resolve().parents[1]
        cls.ghidra = Path(os.environ["CUSTODIA_GHIDRA_HOME"]).resolve(strict=True)
        cls.java = Path(os.environ["CUSTODIA_JAVA_HOME"]).resolve(strict=True)
        cls.identity = tool_identity(cls.ghidra)
        if not (cls.java / "bin/javac").is_file():
            raise ValueError("Integration requires a JDK, not a JRE")
        cls.sample = cls.work / "sample.bin"
        subprocess.run(["gcc", "-O0", "-fno-pie", "-no-pie", "-g0", "-Wl,--build-id=none",
                        str(cls.repo / "examples/fixture.c"), "-o", str(cls.sample)], check=True,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)

    def isolated(self, config):
        from custodia.backend import Limits, run
        result = run(["/usr/bin/python3", "-I", "/opt/custodia/worker.py", "ghidra", json.dumps(config)],
                     {"/opt/custodia": self.repo / "src/custodia", "/input/sample.bin": self.sample,
                      "/opt/ghidra": self.ghidra, "/opt/java": self.java},
                     Limits(memory_mib=1536, pids=128, wall_seconds=120, scratch_mib=512))
        self.assertEqual(result.status, "completed", result.stderr.decode("utf-8", "replace"))
        self.assertTrue(result.cleanup_verified)
        self.assertTrue(result.enforcement["verified"])
        worker = json.loads(result.stdout)
        self.assertEqual(worker["status"], "completed", worker.get("diagnostics"))
        return worker["result"]

    def test_native_and_isolated_semantic_equivalence(self):
        config = {"max_functions": 1000, "decompile_count": 3, "decompile_seconds": 10,
                  "analysis_seconds": 60, "heap_mb": 512}
        native = self.work / "native"
        for part in ("projects", "home", "cache", "tmp"):
            (native / part).mkdir(parents=True, exist_ok=True)
        substitutions = {"/opt/ghidra": str(self.ghidra), "/opt/java": str(self.java),
                         "/opt/custodia": str(self.repo / "src/custodia"),
                         "/input/sample.bin": str(self.sample), "/work": str(native)}
        def local(value):
            pattern = "|".join(re.escape(source) for source in substitutions)
            return re.sub(pattern, lambda match: substitutions[match.group(0)], value)
        environment = {key: local(value) for key, value in sandbox_environment(config).items()}
        environment.update({"LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "TZ": "UTC"})
        completed = subprocess.run([local(value) for value in sandbox_command(config)], env=environment,
                                   stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   timeout=120)
        self.assertEqual(completed.returncode, 0)
        reference = json.loads((native / "report.json").read_text())
        isolated = self.isolated(config)
        self.assertEqual(reference, isolated)
        self.assertEqual(reference["schema"], "custodia.ghidra-report.v1")
        self.assertFalse(reference["analysis_timed_out"])
        self.assertIn("main", {row["name"] for row in reference["functions"]["items"]})
        self.assertIn("evidence_score", {row["name"] for row in reference["functions"]["items"]})
        self.assertTrue(all(row["completed"] for row in reference["decompilations"]))
        self.assertEqual(reference["decompilations"][0]["name"], "main")
        self.assertEqual(tool_identity(self.ghidra), self.identity)

    def test_explicit_output_cap_is_visible(self):
        report = self.isolated({"max_functions": 2, "decompile_count": 0,
                                "analysis_seconds": 60, "heap_mb": 512})
        self.assertEqual(len(report["functions"]["items"]), 2)
        self.assertTrue(report["functions"]["truncated"])
        self.assertEqual(report["decompilations"], [])
        self.assertEqual(report["status"], "completed")


if __name__ == "__main__":
    unittest.main()
