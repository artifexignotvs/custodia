"""Executable, bounded evidence about this machine's isolation boundary."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import secrets
import socket
import tempfile
import time
from typing import Any

from . import __version__, backend


CHECK_IDS = (
    "isolation", "host_canary", "input_readonly", "network", "pids",
    "memory", "timeout", "output", "scratch",
)
FACT_KEYS = {
    "isolation": ("capabilities_zero", "no_new_privileges", "hostname_isolated",
                  "unprivileged_uid", "environment_not_inherited"),
    "host_canary": ("host_file_hidden",),
    "input_readonly": ("write_denied",),
    "network": ("host_listener_unreachable", "udp_route_denied", "tcp_route_denied",
                "no_dns_configuration"),
    "pids": ("fork_limit_enforced", "children_started"),
    "memory": (),
    "timeout": ("detached_child_started",),
    "output": (),
    "scratch": ("scratch_limit_enforced",),
}


def _check(identifier: str, status: str, **details: object) -> dict[str, Any]:
    return {"id": identifier, "status": status, "details": details}


def _facts(outcome: Any, identifier: str) -> dict[str, Any] | None:
    try:
        value = json.loads(outcome.stdout.decode("utf-8"))
    except (ValueError, UnicodeDecodeError, AttributeError):
        return None
    if not isinstance(value, dict) or value.get("probe") != identifier:
        return None
    facts = value.get("facts")
    if not isinstance(facts, dict) or type(value.get("ok")) is not bool:
        return None
    # Formae clausae prohibent effusionem rerum privatarum.
    if any(key not in facts for key in FACT_KEYS[identifier]):
        return None
    result: dict[str, Any] = {"ok": value["ok"]}
    for key in FACT_KEYS[identifier]:
        item = facts[key]
        if key == "children_started":
            if type(item) is not int or not 0 <= item <= 20:
                return None
        elif type(item) is not bool:
            return None
        result[key] = item
    return result


def _enforced(outcome: Any) -> bool:
    return isinstance(outcome.enforcement, dict) and outcome.enforcement.get("verified") is True


def _evaluate(identifier: str, outcome: Any, limits: Any) -> dict[str, Any]:
    if outcome.status == "unavailable":
        return _check(identifier, "unavailable", reason="isolation_backend_unavailable")
    if not _enforced(outcome):
        return _check(identifier, "fail", reason="enforcement_not_verified")
    if not outcome.cleanup_verified:
        return _check(identifier, "fail", reason="process_cleanup_not_verified")
    if identifier == "memory":
        return _check(identifier, "pass" if outcome.status == "memory_limit" else "fail",
                      memory_limit_enforced=outcome.status == "memory_limit",
                      cleanup_verified=True)
    if identifier == "output":
        bounded = len(outcome.stdout) + len(outcome.stderr) <= limits.output_bytes
        ok = outcome.status == "output_limit" and bounded
        return _check(identifier, "pass" if ok else "fail", output_limit_enforced=ok,
                      captured_bytes=len(outcome.stdout) + len(outcome.stderr),
                      output_limit_bytes=limits.output_bytes, cleanup_verified=True)
    facts = _facts(outcome, identifier)
    if facts is None:
        return _check(identifier, "fail", reason="invalid_probe_result")
    ok = facts.pop("ok")
    expected_status = "timeout" if identifier == "timeout" else "completed"
    ok = ok and outcome.status == expected_status
    if identifier != "timeout":
        ok = ok and outcome.returncode == 0
    for key, value in facts.items():
        if key != "children_started":
            ok = ok and value is True
    if identifier == "pids":
        ok = ok and facts["children_started"] < 20
    return _check(identifier, "pass" if ok else "fail", **facts, cleanup_verified=True)


def _limits(identifier: str) -> Any:
    return backend.Limits(
        memory_mib=64 if identifier == "memory" else 128,
        pids=12 if identifier == "pids" else 32,
        cpu_percent=100,
        wall_seconds=1 if identifier == "timeout" else 4,
        scratch_mib=1 if identifier == "scratch" else 8,
        output_bytes=65536,
    )


def _run(identifier: str, mounts: dict[str, Path], args: list[str] | None = None) -> tuple[Any, Any]:
    limits = _limits(identifier)
    outcome = backend.run(
        ["/usr/bin/python3", "-I", "-B", "/opt/custodia/probes.py", "--sandbox-probe",
         identifier, *(args or [])],
        mounts=mounts,
        limits=limits,
    )
    return outcome, limits


def run_selftest() -> dict[str, Any]:
    """Run real probes; unavailable isolation never becomes a passing check.

    These observations concern this host and these bounded probes. They are not
    a proof against kernel vulnerabilities or every hostile input.
    """
    started = time.monotonic()
    checks: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="custodia-selftest-") as temporary:
        root = Path(temporary)
        # Permissio hospitis probationem isolationis filesystem non simulet.
        root.chmod(0o755)
        source = root / "sample.bin"
        source.write_bytes(b"CUSTODIA synthetic readonly evidence\n")
        source.chmod(0o666)
        original_digest = hashlib.sha256(source.read_bytes()).digest()
        canary = root / "host-only-canary"
        canary.write_bytes(secrets.token_bytes(32))
        canary.chmod(0o644)
        mounts = {"/opt/custodia": Path(__file__).resolve().parent,
                  "/input/sample.bin": source}
        sentinel = "CUSTODIA_SELFTEST_HOST_SECRET"
        previous = os.environ.get(sentinel)
        os.environ[sentinel] = secrets.token_hex(16)
        try:
            outcome, limits = _run("isolation", mounts)
        finally:
            if previous is None:
                os.environ.pop(sentinel, None)
            else:
                os.environ[sentinel] = previous
        initial = _evaluate("isolation", outcome, limits)
        checks.append(initial)
        if initial["status"] != "pass":
            checks.extend(_check(identifier, "unavailable", reason="isolation_preflight_failed")
                          for identifier in CHECK_IDS[1:])
        else:
            for identifier in CHECK_IDS[1:]:
                if identifier == "network":
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
                        listener.bind(("127.0.0.1", 0))
                        listener.listen(1)
                        listener.setblocking(False)
                        outcome, limits = _run(identifier, mounts, [str(listener.getsockname()[1])])
                        check = _evaluate(identifier, outcome, limits)
                        try:
                            connection, _ = listener.accept()
                        except BlockingIOError:
                            check["details"]["host_listener_received_connection"] = False
                        else:
                            connection.close()
                            check["status"] = "fail"
                            check["details"]["host_listener_received_connection"] = True
                else:
                    args = [str(canary)] if identifier == "host_canary" else []
                    outcome, limits = _run(identifier, mounts, args)
                    check = _evaluate(identifier, outcome, limits)
                if identifier == "input_readonly":
                    try:
                        unchanged = hashlib.sha256(source.read_bytes()).digest() == original_digest
                    except OSError:
                        unchanged = False
                    check["details"]["host_input_hash_unchanged"] = unchanged
                    if not unchanged:
                        check["status"] = "fail"
                checks.append(check)
    passed = all(item["status"] == "pass" for item in checks)
    unsupported = any(item["status"] == "unavailable" for item in checks)
    status = "passed" if passed else ("failed" if any(item["status"] == "fail" for item in checks)
                                      else "unavailable")
    return {
        "schema": "custodia.selftest.v1",
        "version": __version__,
        "status": status,
        "passed": passed,
        "unsupported": unsupported,
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "checks": checks,
        "scope": "Bounded checks on this host; not a universal sandbox or kernel-security proof.",
    }
