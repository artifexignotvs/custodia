"""Validation and opt-in tests of the real Linux execution boundary."""
from __future__ import annotations

import json
import os
from pathlib import Path
import signal
import tempfile
import threading
import unittest
from unittest.mock import patch

from custodia.backend import Limits, doctor, run


class BackendValidationTests(unittest.TestCase):
    def test_resource_bounds_reject_boolean_unbounded_and_noninteger_values(self):
        for name, value in (("memory_mib", 63), ("memory_mib", 16385), ("pids", 0),
                            ("cpu_percent", 801), ("wall_seconds", 0), ("wall_seconds", True),
                            ("scratch_mib", 0), ("output_bytes", 2**40), ("pids", 8.5)):
            with self.subTest(name=name, value=value), self.assertRaises(ValueError):
                Limits(**{name: value})

    def test_argv_rejects_missing_relative_nul_and_oversized_arguments(self):
        for argv in ([], ["python3"], ["/usr/bin/true", "a\x00b"],
                     ["/usr/bin/true", "x" * 16385], ["/usr/bin/true"] * 257):
            with self.subTest(argv=str(argv)[:30]), self.assertRaises(ValueError):
                run(argv, {})

    def test_mount_destination_is_allowlisted(self):
        with self.assertRaises(ValueError):
            run(["/usr/bin/true"], {"/run/user": Path("/tmp")})

    def test_mounts_reject_symlinks_and_incorrect_types(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sample = root / "sample"
            sample.write_bytes(b"evidence")
            link = root / "link"
            link.symlink_to(sample)
            for mounts in ({"/input/sample.bin": link}, {"/input/sample.bin": root},
                           {"/opt/custodia": sample}, {"/input/sample.bin": Path("relative")},
                           {"/input/sample.bin": root / "missing"}):
                with self.subTest(mounts=str(mounts)), self.assertRaises(ValueError):
                    run(["/usr/bin/true"], mounts)

    def test_missing_boundary_never_runs_the_requested_program(self):
        with patch("custodia.backend._prerequisites", return_value=(False, "unavailable")), \
             patch("custodia.backend.subprocess.Popen") as spawn:
            result = run(["/usr/bin/true"], {})
        self.assertEqual(result.status, "unavailable")
        self.assertFalse(result.enforcement["verified"])
        spawn.assert_not_called()


_GUARD = "import os,socket; assert os.environ.get('CUSTODIA_BOUNDARY') == '1' and socket.gethostname() == 'custodia' and os.getuid() == 65534\n"


@unittest.skipUnless(os.environ.get("CUSTODIA_INTEGRATION") == "1", "set CUSTODIA_INTEGRATION=1 for real boundary tests")
class BackendIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.health = doctor()
        if not cls.health["available"]:
            raise AssertionError("Requested integration host cannot enforce the boundary")

    def execute(self, code, mounts=None, **changes):
        values = {"memory_mib": 128, "pids": 16, "wall_seconds": 6, "scratch_mib": 8, "output_bytes": 4096}
        values.update(changes)
        return run(["/usr/bin/python3", "-I", "-c", _GUARD + code], mounts or {}, Limits(**values))

    def assert_clean(self, result):
        self.assertTrue(result.enforcement["verified"])
        self.assertTrue(result.cleanup_verified)

    def test_network_host_marker_environment_and_readonly_input(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            marker = root / "private-marker"
            marker.write_text("private control marker")
            sample = root / "sample"
            sample.write_bytes(b"controlled evidence")
            code = f'''import json
result = {{"marker_visible":os.path.exists({str(marker)!r}),"home":os.listdir("/home"),"hostname":socket.gethostname(),"uid":os.getuid(),"input":open("/input/sample.bin","rb").read().decode(),"host_env":os.environ.get("CUSTODIA_PRIVATE_CONTROL")}}
status=dict(line.split(":",1) for line in open("/proc/self/status") if ":" in line)
result["nnp"]=status["NoNewPrivs"].strip();result["caps"]=status["CapEff"].strip()
s=socket.socket();s.settimeout(1)
try: s.connect(("192.0.2.1",80));result["network"]=False
except OSError: result["network"]=True
try: open("/input/sample.bin","wb").write(b"changed");result["readonly"]=False
except OSError as error: result["readonly"]=error.errno == 30
print(json.dumps(result))'''
            with patch.dict(os.environ, {"CUSTODIA_PRIVATE_CONTROL": "must-not-cross"}):
                result = self.execute(code, {"/input/sample.bin": sample})
            self.assertEqual(sample.read_bytes(), b"controlled evidence")
        self.assertEqual(result.status, "completed", result.stderr)
        self.assertEqual(json.loads(result.stdout), {
            "marker_visible": False, "home": [], "hostname": "custodia", "uid": 65534,
            "input": "controlled evidence", "host_env": None, "nnp": "1", "caps": "0000000000000000",
            "network": True, "readonly": True,
        })
        self.assert_clean(result)

    def test_aggregate_pids_are_denied_without_unbounded_forking(self):
        result = self.execute('''import subprocess,json
children=[];error_number=None
try:
 for _ in range(16):children.append(subprocess.Popen(["/usr/bin/sleep","2"]))
except OSError as error:error_number=error.errno
finally:
 for child in children:child.terminate()
 for child in children:child.wait()
print(json.dumps({"errno":error_number,"children":len(children)}))''', pids=8)
        self.assertEqual(result.status, "completed", result.stderr)
        proof = json.loads(result.stdout)
        self.assertEqual(proof["errno"], 11)
        self.assertGreater(proof["children"], 0)
        self.assertLess(proof["children"], 16)
        self.assertEqual(result.enforcement["pids_max"], 8)
        self.assert_clean(result)

    def test_aggregate_memory_limit_kills_the_entire_group(self):
        result = self.execute('''import subprocess,time
children=[subprocess.Popen(["/usr/bin/python3","-I","-c","import resource,time;resource.setrlimit(resource.RLIMIT_AS,(128*1024*1024,128*1024*1024));data=bytearray(40*1024*1024);time.sleep(4)"]) for _ in range(2)]
time.sleep(4)''', memory_mib=64)
        self.assertEqual(result.status, "memory_limit", result.stderr)
        self.assertEqual(result.enforcement["memory_max_bytes"], 64 * 1024 * 1024)
        self.assert_clean(result)

    def test_timeout_cleans_a_detached_child(self):
        result = self.execute('''import subprocess,time
subprocess.Popen(["/usr/bin/sleep","20"],start_new_session=True)
print("detached-child-started",flush=True)
time.sleep(20)''', wall_seconds=1)
        self.assertEqual(result.status, "timeout", result.stderr)
        self.assertIn(b"detached-child-started", result.stdout)
        self.assertLess(result.elapsed_seconds, 10)
        self.assert_clean(result)

    def test_combined_output_limit_kills_and_bounds_capture(self):
        result = self.execute('''for _ in range(16):
 os.write(1,b"x"*16384)
 os.write(2,b"y"*16384)''', output_bytes=4096)
        self.assertEqual(result.status, "output_limit", result.stderr[:100])
        self.assertEqual(len(result.stdout) + len(result.stderr), 4096)
        self.assert_clean(result)

    def test_scratch_capacity_is_enforced_and_root_is_readonly(self):
        result = self.execute('''import json
proof={}
try:open("/work/fill","wb").write(bytes(2*1024*1024));proof["full"]=False
except OSError as error:proof["full"]=error.errno == 28
try:open("/root-file","wb").write(b"x");proof["root"]=False
except OSError as error:proof["root"]=error.errno == 30
print(json.dumps(proof))''', scratch_mib=1)
        self.assertEqual(result.status, "completed", result.stderr)
        self.assertEqual(json.loads(result.stdout), {"full": True, "root": True})
        self.assert_clean(result)

    def test_arguments_with_dollar_signs_are_not_expanded_by_service_manager(self):
        result = self.execute('print("${HOME}:$USER:$$")')
        self.assertEqual(result.status, "completed", result.stderr)
        self.assertEqual(result.stdout, b"${HOME}:$USER:$$\n")
        self.assert_clean(result)

    def test_interruption_cleans_the_execution_group(self):
        timer = threading.Timer(0.5, lambda: os.kill(os.getpid(), signal.SIGINT))
        timer.start()
        try:
            result = self.execute('''import subprocess,time
subprocess.Popen(["/usr/bin/sleep","20"],start_new_session=True)
print("interrupt-ready",flush=True)
time.sleep(20)''', wall_seconds=10)
        finally:
            timer.cancel()
        self.assertEqual(result.status, "interrupted", result.stderr)
        self.assertIn(b"interrupt-ready", result.stdout)
        self.assertLess(result.elapsed_seconds, 8)
        self.assert_clean(result)


if __name__ == "__main__":
    unittest.main()
