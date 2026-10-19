"""Bounded diagnostics executed exclusively by the verified isolation backend."""

from __future__ import annotations

import errno
import json
import os
from pathlib import Path
import resource
import signal
import socket
import sys
import time


def _status() -> dict[str, str]:
    return dict(
        line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines()
        if ":" in line
    )


def _guard() -> bool:
    # Custodia probata ante experimenta: numquam in hospite currere.
    try:
        status = _status()
        return (
            os.environ.get("CUSTODIA_ISOLATED") == "1"
            and socket.gethostname() == "custodia"
            and os.getuid() == 65534
            and int(status.get("CapEff", "1"), 16) == 0
            and status.get("NoNewPrivs", "0").strip() == "1"
        )
    except (OSError, ValueError):
        return False


def _emit(probe: str, ok: bool, **facts: object) -> None:
    print(json.dumps({"probe": probe, "ok": ok, "facts": facts}, sort_keys=True), flush=True)


def _isolation() -> None:
    status = _status()
    facts = {
        "capabilities_zero": int(status.get("CapEff", "1"), 16) == 0,
        "no_new_privileges": status.get("NoNewPrivs", "0").strip() == "1",
        "hostname_isolated": socket.gethostname() == "custodia",
        "unprivileged_uid": os.getuid() == 65534,
        "environment_not_inherited": "CUSTODIA_SELFTEST_HOST_SECRET" not in os.environ,
    }
    _emit("isolation", all(facts.values()), **facts)


def _host_canary(path: str) -> None:
    # Semita secreta in relationem numquam transit.
    hidden = not os.path.exists(path)
    _emit("host_canary", hidden, host_file_hidden=hidden)


def _input_readonly() -> None:
    denied = False
    try:
        with open("/input/sample.bin", "ab") as handle:
            handle.write(b"mutation-attempt")
    except OSError as error:
        denied = error.errno == errno.EROFS
    _emit("input_readonly", denied, write_denied=denied)


def _network(port: str) -> None:
    facts: dict[str, bool] = {}
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as stream:
        stream.settimeout(0.35)
        try:
            stream.connect(("127.0.0.1", int(port)))
            facts["host_listener_unreachable"] = False
        except OSError:
            facts["host_listener_unreachable"] = True
    unreachable = {errno.ENETUNREACH, errno.EHOSTUNREACH, errno.EACCES, errno.EPERM}
    for label, kind in (("udp_route_denied", socket.SOCK_DGRAM),
                        ("tcp_route_denied", socket.SOCK_STREAM)):
        with socket.socket(socket.AF_INET, kind) as client:
            client.settimeout(0.35)
            try:
                client.connect(("192.0.2.1", 9))
                facts[label] = False
            except OSError as error:
                facts[label] = error.errno in unreachable
    dns = Path("/etc/resolv.conf")
    try:
        facts["no_dns_configuration"] = not any(
            line.strip().startswith("nameserver") for line in dns.read_text().splitlines()
        )
    except FileNotFoundError:
        facts["no_dns_configuration"] = True
    _emit("network", all(facts.values()), **facts)


def _pids() -> None:
    children: list[int] = []
    denied = False
    try:
        # Numerus finitus etiam si limes externus desit.
        for _ in range(20):
            try:
                pid = os.fork()
            except OSError as error:
                denied = error.errno == errno.EAGAIN
                break
            if pid == 0:
                time.sleep(1.5)
                os._exit(0)
            children.append(pid)
    finally:
        for pid in children:
            try:
                os.waitpid(pid, 0)
            except ChildProcessError:
                pass
    _emit("pids", denied, fork_limit_enforced=denied, children_started=len(children))


def _memory() -> None:
    children: list[int] = []
    # Duo filii tantum; octoginta mebibyta summa petita.
    for _ in range(2):
        pid = os.fork()
        if pid == 0:
            allocation = bytearray(40 * 1024 * 1024)
            for position in range(0, len(allocation), 4096):
                allocation[position] = 1
            time.sleep(2)
            os._exit(0)
        children.append(pid)
    for pid in children:
        os.waitpid(pid, 0)
    _emit("memory", False, memory_limit_triggered=False)


def _timeout() -> None:
    pid = os.fork()
    if pid == 0:
        os.setsid()
        _emit("timeout", True, detached_child_started=True)
        time.sleep(5)
        os._exit(0)
    time.sleep(5)
    os.waitpid(pid, 0)


def _output() -> None:
    # Quattuor mebibyta tantum; productio semper finita.
    for _ in range(512):
        os.write(sys.stdout.fileno(), b"x" * 8192)


def _scratch() -> None:
    denied = False
    try:
        with open("/work/scratch-limit-test", "wb", buffering=0) as handle:
            for _ in range(32):
                handle.write(b"s" * 65536)
    except OSError as error:
        denied = error.errno == errno.ENOSPC
    _emit("scratch", denied, scratch_limit_enforced=denied)


def main() -> int:
    if len(sys.argv) < 3 or sys.argv[1] != "--sandbox-probe" or not _guard():
        print("Diagnostic requires the verified isolation backend.", file=sys.stderr)
        return 78
    # Limites interiores sunt subsidium, non probatio custodiae.
    signal.alarm(5)
    resource.setrlimit(resource.RLIMIT_AS, (128 * 1024 * 1024, 128 * 1024 * 1024))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    probes = {
        "isolation": _isolation,
        "host_canary": lambda: _host_canary(sys.argv[3]),
        "input_readonly": _input_readonly,
        "network": lambda: _network(sys.argv[3]),
        "pids": _pids,
        "memory": _memory,
        "timeout": _timeout,
        "output": _output,
        "scratch": _scratch,
    }
    if sys.argv[2] not in probes:
        return 64
    try:
        probes[sys.argv[2]]()
    except Exception:
        # Erroris genus tantum, sine semitis vel rebus privatis.
        _emit(sys.argv[2], False, probe_error=True)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
