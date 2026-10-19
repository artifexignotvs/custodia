"""Portable artifact consistency checks, not an authenticity assertion."""

from __future__ import annotations

from pathlib import Path
from datetime import datetime
import math
import re

from .policy import from_document
from .safeio import Invalid, canonical, digest, hash_file, parse, read, write_new
from .reports import validate_result, validate_enforcement

ARTIFACTS = {"input.bin", "triage.json", "analysis.json", "triage-diagnostics.json", "analysis-diagnostics.json"}
SHA = re.compile(r"[a-f0-9]{64}\Z")
STATES = {"completed", "partial", "failed", "timeout", "memory_limit", "output_limit", "unavailable", "interrupted", "protocol_error", "cleanup_failed", "reused"}


def inventory(directory: Path) -> list:
    result = []
    for name in sorted(ARTIFACTS):
        path = directory / name
        if path.exists():
            value, size = hash_file(path)
            result.append({"name": name, "sha256": value, "bytes": size})
    return result


def publish(directory: Path, receipt: dict) -> None:
    receipt["artifacts"] = inventory(directory)
    raw = canonical(receipt)
    write_new(directory / "receipt.json", raw)
    lines = [f"{digest(raw)}  receipt.json\n"]
    lines += [f"{item['sha256']}  {item['name']}\n" for item in receipt["artifacts"]]
    write_new(directory / "SHA256SUMS", "".join(lines).encode("ascii"))


def verify(directory: Path) -> dict:
    if directory.is_symlink() or not directory.is_dir():
        raise Invalid("Session must be a regular directory.")
    raw = read(directory / "receipt.json")
    receipt = parse(raw)
    required = {"schema", "version", "engine_sha256", "started_utc", "finished_utc", "status", "provider", "input", "policy", "policy_sha256", "tools", "stages", "artifacts", "parent_receipt_sha256", "authenticity", "scope"}
    if not isinstance(receipt, dict) or set(receipt) != required or receipt["schema"] != "custodia.receipt.v1":
        raise Invalid("Unknown or incomplete receipt schema.")
    policy = from_document(receipt["policy"])
    if policy.sha256 != receipt["policy_sha256"] or not isinstance(receipt["status"], str) or receipt["status"] not in STATES or receipt["provider"] not in ("triage", "ghidra"):
        raise Invalid("Receipt policy, status or provider is inconsistent.")
    if not isinstance(receipt["engine_sha256"], str) or not SHA.fullmatch(receipt["engine_sha256"]):
        raise Invalid("Receipt engine identity is invalid.")
    if not isinstance(receipt["version"], str) or not re.fullmatch(r"\d+\.\d+\.\d+", receipt["version"]):
        raise Invalid("Receipt version is invalid.")
    try:
        dates = [datetime.fromisoformat(receipt[key]) for key in ("started_utc", "finished_utc")]
        if any(date.utcoffset() is None or date.utcoffset().total_seconds() != 0 for date in dates):
            raise ValueError
    except (TypeError, ValueError, OverflowError):
        raise Invalid("Receipt timestamps must be UTC dates.") from None
    parent = receipt["parent_receipt_sha256"]
    if parent is not None and (not isinstance(parent, str) or not SHA.fullmatch(parent)):
        raise Invalid("Invalid parent receipt identity.")
    tools = receipt["tools"]
    if not isinstance(tools, dict) or tools.get("engine_sha256") != receipt["engine_sha256"] or set(tools) != ({"engine_sha256"} if receipt["provider"] == "triage" else {"engine_sha256", "ghidra", "java"}):
        raise Invalid("Tool inventory contradicts the provider.")
    for name in ("ghidra", "java") if receipt["provider"] == "ghidra" else ():
        tool = tools[name]
        if not isinstance(tool, dict) or tool.get("name") != name or not isinstance(tool.get("version"), str) or not isinstance(tool.get("tree_sha256"), str) or not SHA.fullmatch(tool["tree_sha256"]) or any(type(tool.get(key)) is not int or tool[key] < 1 for key in ("file_count", "size_bytes")):
            raise Invalid("Invalid tool identity record.")
    if receipt["authenticity"] != "not_established" or receipt["scope"] != "recorded_execution_and_artifact_consistency":
        raise Invalid("Receipt claims an unsupported assurance scope.")
    artifacts = receipt["artifacts"]
    if not isinstance(artifacts, list) or not 1 <= len(artifacts) <= len(ARTIFACTS):
        raise Invalid("Invalid artifact inventory.")
    names = []
    for item in artifacts:
        if not isinstance(item, dict) or set(item) != {"name", "sha256", "bytes"} or not isinstance(item["name"], str) or item["name"] not in ARTIFACTS or type(item["bytes"]) is not int or item["bytes"] < 0:
            raise Invalid("Invalid artifact entry.")
        if item["name"] in names or not isinstance(item["sha256"], str) or not SHA.fullmatch(item["sha256"]):
            raise Invalid("Duplicate artifact or invalid digest.")
        names.append(item["name"])
        actual, size = hash_file(directory / item["name"])
        if actual != item["sha256"] or size != item["bytes"]:
            raise Invalid("Artifact bytes differ from the receipt.")
    if "input.bin" not in names:
        raise Invalid("The session has no input snapshot.")
    source = receipt["input"]
    if not isinstance(source, dict) or set(source) != {"artifact", "sha256", "bytes"} or type(source["bytes"]) is not int or source != next({"artifact": r["name"], "sha256": r["sha256"], "bytes": r["bytes"]} for r in artifacts if r["name"] == "input.bin"):
        raise Invalid("Input identity differs from the inventory.")
    for name in ("triage", "analysis"):
        if name + ".json" in names:
            validate_result(parse(read(directory / (name + ".json"))), name, source)
    entries = list(directory.iterdir())
    if {entry.name for entry in entries} != set(names) | {"receipt.json", "SHA256SUMS"} or any(entry.is_symlink() or not entry.is_file() for entry in entries):
        raise Invalid("Unexpected, missing or non-regular session artifact.")
    expected = f"{digest(raw)}  receipt.json\n" + "".join(f"{item['sha256']}  {item['name']}\n" for item in artifacts)
    if read(directory / "SHA256SUMS", 8192) != expected.encode("ascii"):
        raise Invalid("Checksum manifest does not match the receipt.")
    stages = receipt["stages"]
    if not isinstance(stages, list) or len(stages) > 2:
        raise Invalid("Invalid stage list.")
    seen = set()
    for stage in stages:
        keys = {"name", "status", "returncode", "elapsed_seconds", "enforcement", "cleanup_verified", "artifact", "reused_from"}
        if not isinstance(stage, dict) or set(stage) != keys or stage.get("name") not in ("triage", "analysis") or stage["name"] in seen or not isinstance(stage.get("status"), str) or stage["status"] not in STATES:
            raise Invalid("Invalid or duplicate stage record.")
        if receipt["provider"] == "triage" and stage["name"] != "triage":
            raise Invalid("Stage contradicts the selected provider.")
        if type(stage["cleanup_verified"]) is not bool or not isinstance(stage["enforcement"], dict) or (stage["returncode"] is not None and type(stage["returncode"]) is not int) or type(stage["elapsed_seconds"]) not in (int, float) or not 0 <= stage["elapsed_seconds"] <= 86400 or not math.isfinite(stage["elapsed_seconds"]):
            raise Invalid("Invalid stage execution record.")
        if stage["status"] == "reused":
            if parent is None or stage["reused_from"] != parent or stage["name"] != "triage":
                raise Invalid("Reused stage has no matching parent receipt.")
        elif stage["reused_from"] is not None:
            raise Invalid("Fresh stage unexpectedly claims reuse.")
        seen.add(stage["name"])
        artifact = stage.get("artifact")
        if artifact is not None and artifact not in names:
            raise Invalid("Stage artifact is missing.")
        if stage["status"] in ("completed", "reused"):
            if artifact != stage["name"] + ".json" or stage["cleanup_verified"] is not True or stage["returncode"] != 0:
                raise Invalid("Completed stage lacks its declared evidence.")
            validate_enforcement(stage["enforcement"], policy)
        if artifact is not None:
            if artifact != stage["name"] + ".json":
                raise Invalid("Stage result has an unexpected artifact name.")
            value = parse(read(directory / artifact))
            validate_result(value, stage["name"], source, stage["status"] in ("completed", "reused"))
    if receipt["status"] == "completed":
        needed = {"triage"} if receipt["provider"] == "triage" else {"triage", "analysis"}
        if seen != needed or any(s["status"] not in ("completed", "reused") for s in stages):
            raise Invalid("Session completion contradicts its stage records.")
    return {"schema": "custodia.verification.v1", "valid": True, "receipt_sha256": digest(raw), "artifacts_verified": len(artifacts), "authenticity": "not_established", "execution_repeated": False, "receipt": receipt}
