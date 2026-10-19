"""Stage orchestration; inputs are never executed."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import time

from . import __version__
from .backend import Limits, doctor, run
from .identity import engine_identity, java_identity
from .policy import Policy
from .receipt import publish, verify
from .reports import validate_result, validate_enforcement
from .safeio import Invalid, canonical, digest, hash_file, new_directory, parse, read, snapshot, write_new


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _worker_result(raw: bytes, name: str, identity: dict) -> dict:
    envelope = parse(raw)
    if not isinstance(envelope, dict) or set(envelope) != {"schema", "status", "result", "diagnostics"} or envelope["schema"] != "custodia.worker.v1" or envelope["status"] not in ("completed", "partial", "failed") or not isinstance(envelope["diagnostics"], dict):
        raise Invalid("Invalid worker result envelope.")
    result = envelope["result"]
    if envelope["status"] != "failed":
        validate_result(result, name, identity, envelope["status"] == "completed")
    elif result is not None:
        raise Invalid("Failed worker result contains an ambiguous payload.")
    return envelope


def run_session(source: Path, output: Path, policy: Policy, *, ghidra_home: Path | None = None, java_home: Path | None = None, retry: Path | None = None, progress=None) -> dict:
    if bool(ghidra_home) != bool(java_home):
        raise Invalid("Ghidra analysis requires both --ghidra-home and --java-home.")
    available = doctor()
    if not available.get("available"):
        raise Invalid("Required isolation is unavailable. Run doctor for supported prerequisites.")
    provider = "ghidra" if ghidra_home else "triage"
    engine = engine_identity()
    tools = {"engine_sha256": engine}
    if ghidra_home:
        from .providers.ghidra import tool_identity
        try:
            tools["ghidra"] = tool_identity(ghidra_home)
            tools["java"] = java_identity(java_home)
        except (ValueError, OSError, RuntimeError):
            raise Invalid("Trusted tool distribution identity could not be established.") from None
        if not tools["ghidra"]["tested_version"] or not tools["java"]["version"].startswith("21."):
            raise Invalid("This release supports Ghidra 12.1.4 with a full JDK 21 distribution.")
    parent = verify(retry) if retry else None
    if parent and parent["receipt"]["provider"] != provider:
        raise Invalid("Retry must retain the original provider choice.")
    new_directory(output)
    try:
        identity = snapshot(source, output / "input.bin")
    except Exception:
        try:
            output.rmdir()
        except OSError:
            pass
        raise
    receipt = {"schema": "custodia.receipt.v1", "version": __version__, "engine_sha256": engine, "started_utc": _now(), "finished_utc": None, "status": "failed", "provider": provider, "input": identity, "policy": policy.document, "policy_sha256": policy.sha256, "tools": tools, "stages": [], "artifacts": [], "parent_receipt_sha256": parent["receipt_sha256"] if parent else None, "authenticity": "not_established", "scope": "recorded_execution_and_artifact_consistency"}
    mounts = {"/opt/custodia": Path(__file__).resolve().parent, "/input/sample.bin": (output / "input.bin").resolve()}
    if ghidra_home:
        mounts.update({"/opt/ghidra": ghidra_home.absolute(), "/opt/java": java_home.absolute()})
    deadline = time.monotonic() + policy.wall_seconds
    stage_names = ["triage", "analysis"] if ghidra_home else ["triage"]
    try:
        for name in stage_names:
            if name == "triage" and parent and parent["receipt"]["engine_sha256"] == engine and parent["receipt"]["policy_sha256"] == policy.sha256 and parent["receipt"]["input"] == identity and parent["receipt"]["tools"] == tools:
                old = next((s for s in parent["receipt"]["stages"] if s["name"] == "triage" and s["status"] in ("completed", "reused")), None)
                if old:
                    copied = read(retry / "triage.json")
                    expected = next(row for row in parent["receipt"]["artifacts"] if row["name"] == "triage.json")
                    if digest(copied) != expected["sha256"] or len(copied) != expected["bytes"]:
                        raise Invalid("Parent triage changed after verification.")
                    validate_result(parse(copied), "triage", identity, True)
                    write_new(output / "triage.json", copied)
                    reused = {**old, "status": "reused", "reused_from": parent["receipt_sha256"]}
                    receipt["stages"].append(reused)
                    if progress:
                        progress(name, "reused")
                    continue
            remaining = int(deadline - time.monotonic())
            if remaining < 1:
                receipt["status"] = "timeout"
                break
            if progress:
                progress(name, "running")
            limits = Limits(memory_mib=policy.memory_mib, pids=policy.pids, cpu_percent=policy.cpu_percent, wall_seconds=remaining, scratch_mib=policy.scratch_mib, output_bytes=policy.output_bytes)
            argv = ["/usr/bin/python3", "-I", "/opt/custodia/worker.py", "triage"]
            if name == "analysis":
                config = policy.ghidra_config()
                config["analysis_seconds"] = min(config["analysis_seconds"], remaining)
                argv = ["/usr/bin/python3", "-I", "/opt/custodia/worker.py", "ghidra", canonical(config).decode("ascii").strip()]
            outcome = run(argv, mounts, limits)
            stage = {"name": name, "status": outcome.status, "returncode": outcome.returncode, "elapsed_seconds": round(outcome.elapsed_seconds, 6), "enforcement": outcome.enforcement, "cleanup_verified": outcome.cleanup_verified, "artifact": None, "reused_from": None}
            diagnostics = {"backend_status": outcome.status, "backend_stderr_bytes": len(outcome.stderr), "backend_stderr_sha256": digest(outcome.stderr)}
            if outcome.stdout and outcome.status in ("completed", "failed"):
                try:
                    envelope = _worker_result(outcome.stdout, name, identity)
                    stage["status"] = envelope["status"]
                    diagnostics["worker"] = envelope["diagnostics"]
                    if envelope["result"] is not None:
                        stage["artifact"] = name + ".json"
                        write_new(output / stage["artifact"], canonical(envelope["result"]))
                except Invalid:
                    stage["status"] = "protocol_error"
            elif outcome.status == "completed":
                stage["status"] = "protocol_error"
            if not outcome.cleanup_verified and outcome.status != "unavailable":
                stage["status"] = "cleanup_failed"
            if stage["status"] == "completed" and (outcome.returncode != 0 or outcome.enforcement.get("verified") is not True):
                stage["status"] = "protocol_error"
            if stage["status"] == "completed":
                try:
                    validate_enforcement(outcome.enforcement, policy)
                except Invalid:
                    stage["status"] = "protocol_error"
            write_new(output / (name + "-diagnostics.json"), canonical(diagnostics))
            receipt["stages"].append(stage)
            if progress:
                progress(name, stage["status"])
            if stage["status"] != "completed":
                receipt["status"] = stage["status"]
                break
        else:
            receipt["status"] = "completed"
        if hash_file(output / "input.bin") != (identity["sha256"], identity["bytes"]):
            receipt["status"] = "protocol_error"
        if engine_identity() != engine:
            receipt["status"] = "protocol_error"
        if ghidra_home and (tool_identity(ghidra_home) != tools["ghidra"] or java_identity(java_home) != tools["java"]):
            receipt["status"] = "protocol_error"
    except KeyboardInterrupt:
        receipt["status"] = "interrupted"
    except Exception:
        receipt["status"] = "protocol_error"
        raise
    finally:
        receipt["finished_utc"] = _now()
        publish(output, receipt)
    return receipt


def compare(left: Path, right: Path) -> dict:
    before, after = verify(left), verify(right)
    l, r = before["receipt"], after["receipt"]
    def names(directory):
        if not (directory / "analysis.json").exists():
            return None
        report = parse(read(directory / "analysis.json"))
        return sorted({row["name"] for row in report.get("functions", {}).get("items", []) if isinstance(row, dict) and isinstance(row.get("name"), str)})
    old, new = names(left), names(right)
    return {"schema": "custodia.comparison.v1", "before_receipt_sha256": before["receipt_sha256"], "after_receipt_sha256": after["receipt_sha256"], "same_input": l["input"] == r["input"], "same_policy": l["policy_sha256"] == r["policy_sha256"], "same_engine": l["engine_sha256"] == r["engine_sha256"], "same_tools": l["tools"] == r["tools"], "status_before": l["status"], "status_after": r["status"], "sampled_functions_added": sorted(set(new) - set(old)) if old is not None and new is not None else None, "sampled_functions_removed": sorted(set(old) - set(new)) if old is not None and new is not None else None, "scope": "exported_function_sample_only", "vulnerability_verdict": "not_performed"}
