from __future__ import annotations

import copy
from pathlib import Path
import tempfile
import unittest

from custodia import receipt
from custodia.policy import Policy
from custodia.safeio import Invalid, canonical, digest, write_new
from custodia.triage import inspect


class ReceiptTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.directory = Path(self.temporary.name)
        self.payload = b"synthetic binary evidence"
        write_new(self.directory / "input.bin", self.payload)
        self.triage = inspect(self.directory / "input.bin")
        write_new(self.directory / "triage.json", canonical(self.triage))
        policy = Policy()
        self.document = {
            "schema": "custodia.receipt.v1", "version": "0.1.0", "engine_sha256": "1" * 64,
            "started_utc": "2026-01-01T00:00:00+00:00", "finished_utc": "2026-01-01T00:00:01+00:00",
            "status": "completed", "provider": "triage",
            "input": {"artifact": "input.bin", "sha256": digest(self.payload), "bytes": len(self.payload)},
            "policy": policy.document, "policy_sha256": policy.sha256,
            "tools": {"engine_sha256": "1" * 64},
            "stages": [self.stage("triage")], "artifacts": [], "parent_receipt_sha256": None,
            "authenticity": "not_established", "scope": "recorded_execution_and_artifact_consistency",
        }

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def stage(name: str) -> dict:
        policy = Policy()
        enforcement = {"verified": True, "backend": "bubblewrap+systemd-user-cgroup-v2",
                       "memory_max_bytes": policy.memory_mib * 1024**2, "memory_swap_max_bytes": 0,
                       "pids_max": policy.pids, "scratch_max_bytes": policy.scratch_mib * 1024**2,
                       "cpu_quota_us": 100000, "cpu_period_us": 100000, "wall_seconds": 179,
                       "network": "isolated", "capabilities": "none", "termination": "control-group",
                       "readonly_input": True, "isolated_home": True}
        return {"name": name, "status": "completed", "returncode": 0,
                "elapsed_seconds": 0.1, "enforcement": enforcement,
                "cleanup_verified": True, "artifact": name + ".json", "reused_from": None}

    def publish(self, document: dict | None = None) -> None:
        receipt.publish(self.directory, document if document is not None else self.document)

    def rewrite(self, document: dict) -> None:
        raw = canonical(document)
        (self.directory / "receipt.json").write_bytes(raw)
        manifest = f"{digest(raw)}  receipt.json\n" + "".join(
            f"{item['sha256']}  {item['name']}\n" for item in document["artifacts"]
        )
        (self.directory / "SHA256SUMS").write_text(manifest)

    def test_valid_receipt_establishes_consistency_only(self) -> None:
        self.publish()
        result = receipt.verify(self.directory)
        self.assertTrue(result["valid"])
        self.assertEqual(result["authenticity"], "not_established")
        self.assertFalse(result["execution_repeated"])

    def test_altered_artifact_rejected(self) -> None:
        self.publish()
        (self.directory / "input.bin").write_bytes(b"changed")
        with self.assertRaises(Invalid):
            receipt.verify(self.directory)

    def test_altered_manifest_rejected(self) -> None:
        self.publish()
        (self.directory / "SHA256SUMS").write_bytes(b"unexpected\n")
        with self.assertRaises(Invalid):
            receipt.verify(self.directory)

    def test_extra_file_or_symlink_is_rejected(self) -> None:
        self.publish()
        extra = self.directory / "unexpected"
        extra.write_bytes(b"extra")
        with self.assertRaises(Invalid):
            receipt.verify(self.directory)
        extra.unlink()
        extra.symlink_to("input.bin")
        with self.assertRaises(Invalid):
            receipt.verify(self.directory)

    def test_inventory_cannot_traverse_or_repeat(self) -> None:
        self.publish()
        for name in ("../input.bin", "/input.bin", [], {}, None):
            with self.subTest(name=name):
                changed = copy.deepcopy(self.document)
                changed["artifacts"][0]["name"] = name
                self.rewrite(changed)
                with self.assertRaises(Invalid):
                    receipt.verify(self.directory)
        changed = copy.deepcopy(self.document)
        changed["artifacts"].append(copy.deepcopy(changed["artifacts"][0]))
        self.rewrite(changed)
        with self.assertRaises(Invalid):
            receipt.verify(self.directory)

    def test_malformed_types_are_cleanly_rejected(self) -> None:
        self.publish()
        mutations = [
            ("status", []), ("status", {}), ("provider", []), ("policy", []),
            ("input", []), ("artifacts", {}), ("stages", {}), ("engine_sha256", []),
            ("authenticity", "verified"), ("scope", "universal_security_proof"),
        ]
        for field, value in mutations:
            with self.subTest(field=field, value=value):
                changed = copy.deepcopy(self.document)
                changed[field] = value
                if field == "artifacts":
                    (self.directory / "receipt.json").write_bytes(canonical(changed))
                else:
                    self.rewrite(changed)
                with self.assertRaises(Invalid):
                    receipt.verify(self.directory)

    def test_completed_stage_requires_clean_execution(self) -> None:
        self.publish()
        for field, value in (("cleanup_verified", False), ("enforcement", []),
                             ("enforcement", {"verified": False}), ("artifact", None),
                             ("returncode", 1), ("returncode", True)):
            with self.subTest(field=field, value=value):
                changed = copy.deepcopy(self.document)
                changed["stages"][0][field] = value
                self.rewrite(changed)
                with self.assertRaises(Invalid):
                    receipt.verify(self.directory)

    def test_false_session_completion_rejected(self) -> None:
        self.publish()
        for stages in ([], [dict(self.document["stages"][0], status="timeout")]):
            changed = copy.deepcopy(self.document)
            changed["stages"] = stages
            self.rewrite(changed)
            with self.assertRaises(Invalid):
                receipt.verify(self.directory)

    def test_triage_identity_must_match_input_even_with_fresh_checksums(self) -> None:
        for field, value in (("sha256", "0" * 64), ("bytes", 999), ("bytes", True)):
            with self.subTest(field=field):
                (self.directory / "triage.json").write_bytes(canonical({**self.triage, field: value}))
                self.publish()
                with self.assertRaises(Invalid):
                    receipt.verify(self.directory)
                (self.directory / "receipt.json").unlink()
                (self.directory / "SHA256SUMS").unlink()

    def test_completed_analysis_cannot_hide_timeout(self) -> None:
        self.document["provider"] = "ghidra"
        for name, version in (("ghidra", "12.1.4"), ("java", "21.0.8")):
            self.document["tools"][name] = {"name": name, "version": version,
                                           "tree_sha256": "2" * 64, "file_count": 1,
                                           "size_bytes": 1, "tested_version": True}
        self.document["stages"].append(self.stage("analysis"))
        for status, timed_out in (("partial", True), ("completed", True), ("completed", None)):
            with self.subTest(status=status, timed_out=timed_out):
                report = {"schema": "custodia.ghidra-report.v1", "status": status,
                          "analysis_timed_out": timed_out, "functions": {"items": []}}
                (self.directory / "analysis.json").write_bytes(canonical(report))
                self.publish()
                with self.assertRaises(Invalid):
                    receipt.verify(self.directory)
                (self.directory / "receipt.json").unlink()
                (self.directory / "SHA256SUMS").unlink()

    def test_forged_enforcement_values_rejected(self) -> None:
        self.publish()
        for field, value in (("memory_max_bytes", 1), ("memory_swap_max_bytes", 1),
                             ("pids_max", 999), ("cpu_quota_us", 1), ("cpu_period_us", True),
                             ("wall_seconds", 999), ("scratch_max_bytes", 1), ("readonly_input", False),
                             ("termination", "process-only"), ("network", "shared")):
            with self.subTest(field=field):
                changed = copy.deepcopy(self.document)
                changed["stages"][0]["enforcement"][field] = value
                self.rewrite(changed)
                with self.assertRaises(Invalid):
                    receipt.verify(self.directory)

    def test_reuse_requires_matching_parent_identity(self) -> None:
        self.publish()
        changed = copy.deepcopy(self.document)
        changed["stages"][0]["status"] = "reused"
        changed["stages"][0]["reused_from"] = "3" * 64
        self.rewrite(changed)
        with self.assertRaises(Invalid):
            receipt.verify(self.directory)
        changed["parent_receipt_sha256"] = "4" * 64
        self.rewrite(changed)
        with self.assertRaises(Invalid):
            receipt.verify(self.directory)

    def test_publish_does_not_overwrite(self) -> None:
        self.publish()
        before = (self.directory / "receipt.json").read_bytes()
        with self.assertRaises(Invalid):
            self.publish()
        self.assertEqual((self.directory / "receipt.json").read_bytes(), before)

    def test_retained_unattached_report_still_requires_its_schema(self) -> None:
        self.document["status"] = "failed"
        self.document["stages"] = []
        (self.directory / "triage.json").write_bytes(b"[]\n")
        self.publish()
        with self.assertRaises(Invalid):
            receipt.verify(self.directory)

    def test_oversized_elapsed_integer_is_a_clean_validation_error(self) -> None:
        self.document["stages"][0]["elapsed_seconds"] = 10**1000
        self.publish()
        with self.assertRaises(Invalid):
            receipt.verify(self.directory)


if __name__ == "__main__":
    unittest.main()
