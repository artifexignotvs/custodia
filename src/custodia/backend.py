"""Fail-closed Linux execution boundary for trusted analysis adapters."""
from __future__ import annotations

import base64
from dataclasses import dataclass, field
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import time
import uuid


_HANDSHAKE = b"CUSTODIA_ENFORCEMENT_V1 "
_DESTINATIONS = frozenset({"/input/sample.bin", "/opt/custodia", "/opt/ghidra", "/opt/java"})
_SYSTEM_ENV = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"}


@dataclass(frozen=True)
class Limits:
    memory_mib: int = 1024
    pids: int = 64
    cpu_percent: int = 100
    wall_seconds: int = 60
    scratch_mib: int = 256
    output_bytes: int = 4 * 1024 * 1024

    def __post_init__(self) -> None:
        bounds = {
            "memory_mib": (64, 16384), "pids": (8, 512),
            "cpu_percent": (1, 800), "wall_seconds": (1, 3600),
            "scratch_mib": (1, 8192), "output_bytes": (1024, 64 * 1024 * 1024),
        }
        for name, (minimum, maximum) in bounds.items():
            value = getattr(self, name)
            if type(value) is not int or not minimum <= value <= maximum:
                raise ValueError(f"{name} must be an integer from {minimum} to {maximum}")


@dataclass(frozen=True)
class Outcome:
    status: str
    returncode: int | None
    stdout: bytes = b""
    stderr: bytes = b""
    elapsed_seconds: float = 0.0
    enforcement: dict = field(default_factory=dict)
    cleanup_verified: bool = False


def _environment() -> dict[str, str]:
    env = dict(_SYSTEM_ENV)
    # Solum canales administri ad patrem pertinent; filius ambitum purgat.
    for name in ("XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS"):
        if name in os.environ:
            env[name] = os.environ[name]
    env["HOME"] = str(Path.home())
    return env


def _validate(argv: list[str], mounts: dict[str, Path]) -> dict[str, str]:
    if not isinstance(argv, list) or not argv or len(argv) > 256:
        raise ValueError("argv must contain from 1 to 256 arguments")
    if any(not isinstance(arg, str) or "\x00" in arg or len(arg.encode()) > 16384 for arg in argv):
        raise ValueError("arguments must be bounded strings without NUL bytes")
    if sum(len(arg.encode()) + 1 for arg in argv) > 65536:
        raise ValueError("combined arguments exceed 65536 bytes")
    if not argv[0].startswith("/"):
        raise ValueError("the sandbox executable must use an absolute path")
    if not isinstance(mounts, dict) or set(mounts) - _DESTINATIONS:
        raise ValueError("unsupported readonly mount destination")
    result = {}
    for destination, source in mounts.items():
        path = Path(source)
        if not path.is_absolute() or path.is_symlink():
            raise ValueError("readonly sources must be absolute, non-symlink paths")
        if len(os.fsencode(path)) > 4096 or "\x00" in str(path):
            raise ValueError("readonly source path is invalid")
        try:
            resolved = path.resolve(strict=True)
            mode = resolved.stat().st_mode
        except (OSError, RuntimeError) as exc:
            raise ValueError("readonly source is unavailable") from exc
        valid_type = stat.S_ISREG(mode) if destination == "/input/sample.bin" else stat.S_ISDIR(mode)
        if not valid_type:
            raise ValueError("readonly source has an invalid type")
        result[destination] = str(resolved)
    return result


def _prerequisites() -> tuple[bool, str]:
    if sys.platform != "linux":
        return False, "Linux is required"
    if os.geteuid() == 0:
        return False, "Run as an unprivileged user"
    if not Path("/sys/fs/cgroup/cgroup.controllers").is_file():
        return False, "A cgroup v2 hierarchy is required"
    if any(shutil.which(program, path="/usr/bin:/bin") is None for program in ("bwrap", "systemd-run", "systemctl", "python3")):
        return False, "bubblewrap, systemd user services and Python are required"
    try:
        python = subprocess.run(["/usr/bin/python3", "-I", "-c", "import sys; raise SystemExit(sys.version_info < (3, 11))"], capture_output=True, timeout=3, env=_environment())
        if python.returncode:
            return False, "System Python 3.11 or later is required"
        version = subprocess.run(["/usr/bin/systemd-run", "--version"], capture_output=True, timeout=3, env=_environment()).stdout
        match = re.match(rb"systemd (\d+)", version)
        if not match or int(match.group(1)) < 254:
            return False, "systemd 254 or later is required"
    except (OSError, subprocess.SubprocessError):
        return False, "The service manager is unavailable"
    return True, "available"


def _bubblewrap(argv: list[str], mounts: dict[str, str], limits: Limits) -> list[str]:
    command = ["/usr/bin/bwrap", "--unshare-all", "--unshare-user", "--unshare-cgroup",
               "--disable-userns", "--die-with-parent", "--new-session", "--cap-drop", "ALL",
               "--uid", "65534", "--gid", "65534", "--hostname", "custodia",
               "--ro-bind", "/usr/bin", "/usr/bin", "--ro-bind", "/usr/lib", "/usr/lib",
               "--symlink", "usr/bin", "/bin", "--symlink", "usr/lib", "/lib"]
    if Path("/usr/lib64").is_dir():
        command += ["--ro-bind", "/usr/lib64", "/usr/lib64", "--symlink", "usr/lib64", "/lib64"]
    if Path("/etc/ld.so.cache").is_file():
        command += ["--ro-bind", "/etc/ld.so.cache", "/etc/ld.so.cache"]
    command += ["--proc", "/proc", "--dev", "/dev", "--tmpfs", "/proc/sys",
                "--remount-ro", "/proc/sys", "--remount-ro", "/proc", "--remount-ro", "/dev",
                "--size", str(limits.scratch_mib * 1024 * 1024), "--tmpfs", "/work",
                "--dir", "/work/tmp", "--dir", "/work/home", "--dir", "/work/cache", "--symlink", "work/tmp", "/tmp",
                "--dir", "/home", "--dir", "/input", "--dir", "/opt"]
    for destination, source in sorted(mounts.items()):
        command += ["--ro-bind", source, destination]
    command += ["--remount-ro", "/", "--clearenv", "--setenv", "PATH", "/usr/bin",
                "--setenv", "LANG", "C.UTF-8", "--setenv", "LC_ALL", "C.UTF-8",
                "--setenv", "HOME", "/work/home", "--setenv", "TMPDIR", "/work/tmp",
                "--setenv", "CUSTODIA_BOUNDARY", "1", "--setenv", "CUSTODIA_ISOLATED", "1",
                "--setenv", "PYTHONDONTWRITEBYTECODE", "1",
                "--chdir", "/work", "--"]
    return command + argv


def _seconds(value: str) -> float:
    factors = {"us": 0.000001, "ms": 0.001, "s": 1, "min": 60, "h": 3600}
    total = 0.0
    for token in value.split():
        match = re.fullmatch(r"(\d+(?:\.\d+)?)(us|ms|min|h|s)", token)
        if match is None:
            raise ValueError("unsupported service duration")
        total += float(match.group(1)) * factors[match.group(2)]
    return total


def _read_enforcement(limits: Limits, unit: str) -> tuple[dict, str]:
    rows = Path("/proc/self/cgroup").read_text().splitlines()
    relative = next(row.split(":", 2)[2] for row in rows if row.startswith("0::"))
    if not relative.startswith("/") or ".." in Path(relative).parts:
        raise ValueError("invalid control group")
    group = Path("/sys/fs/cgroup") / relative.lstrip("/")
    if group.name != unit:
        raise ValueError("execution is outside the expected control group")
    memory = (group / "memory.max").read_text().strip()
    swap = (group / "memory.swap.max").read_text().strip()
    pids = (group / "pids.max").read_text().strip()
    quota, period = (group / "cpu.max").read_text().split()
    oom = (group / "memory.oom.group").read_text().strip()
    expected_memory = limits.memory_mib * 1024 * 1024
    if memory != str(expected_memory) or swap != "0" or pids != str(limits.pids) or oom != "1":
        raise ValueError("control group limits differ")
    if quota == "max" or int(period) <= 0 or int(quota) * 100 != int(period) * limits.cpu_percent:
        raise ValueError("CPU controller limit differs")
    properties = subprocess.run(
        ["/usr/bin/systemctl", "--user", "show", unit,
         "--property=Type,RuntimeMaxUSec,TimeoutStopUSec,KillMode,SendSIGKILL,OOMPolicy,Delegate,Restart"],
        capture_output=True, timeout=3, stdin=subprocess.DEVNULL,
    )
    values = dict(line.split("=", 1) for line in properties.stdout.decode().splitlines() if "=" in line)
    if properties.returncode or any(values.get(key) != value for key, value in {
        "Type": "exec", "KillMode": "control-group", "SendSIGKILL": "yes",
        "OOMPolicy": "kill", "Delegate": "no", "Restart": "no",
    }.items()):
        raise ValueError("required service controls differ")
    if _seconds(values.get("RuntimeMaxUSec", "")) != limits.wall_seconds or _seconds(values.get("TimeoutStopUSec", "")) != 1:
        raise ValueError("service deadline differs")
    public = {
        "backend": "bubblewrap+systemd-user-cgroup-v2", "verified": True,
        "memory_max_bytes": int(memory), "memory_swap_max_bytes": int(swap), "pids_max": int(pids),
        "cpu_quota_us": int(quota), "cpu_period_us": int(period),
        "wall_seconds": limits.wall_seconds, "scratch_max_bytes": limits.scratch_mib * 1024 * 1024,
        "network": "isolated", "readonly_input": True, "isolated_home": True,
        "capabilities": "none", "hostname": "custodia", "termination": "control-group",
    }
    return public, str(group)


def _launch(encoded: str) -> int:
    # Prius fines probantur; tum demum instrumentum incipit.
    try:
        configuration = json.loads(base64.urlsafe_b64decode(encoded))
        limits = Limits(**configuration["limits"])
        enforcement, group = _read_enforcement(limits, configuration["unit"])
        payload = {"ok": True, "enforcement": enforcement, "private_group": group}
        os.write(2, _HANDSHAKE + json.dumps(payload, separators=(",", ":")).encode() + b"\n")
        command = _bubblewrap(configuration["argv"], configuration["mounts"], limits)
        os.execve(command[0], command, _SYSTEM_ENV)
    except (OSError, ValueError, KeyError, StopIteration, TypeError, subprocess.SubprocessError):
        os.write(2, _HANDSHAKE + b'{"ok":false,"reason":"Required isolation controls could not be verified"}\n')
        return 125
    return 125


def _unit_state(unit: str) -> dict[str, str] | None:
    try:
        result = subprocess.run(
            ["/usr/bin/systemctl", "--user", "show", unit,
             "--property=LoadState,ActiveState,SubState,Result,ControlGroup,ExecMainStatus,ExecMainCode"],
            capture_output=True, timeout=4, env=_environment(), stdin=subprocess.DEVNULL,
        )
        if result.returncode not in (0, 1):
            return None
        return dict(line.split("=", 1) for line in result.stdout.decode(errors="replace").splitlines() if "=" in line)
    except (OSError, subprocess.SubprocessError):
        return None


def _stop(unit: str) -> None:
    for arguments in (["stop", unit], ["kill", "--kill-whom=all", "--signal=KILL", unit]):
        try:
            subprocess.run(["/usr/bin/systemctl", "--user", *arguments], capture_output=True,
                           timeout=4, env=_environment(), stdin=subprocess.DEVNULL)
        except (OSError, subprocess.SubprocessError):
            pass


def _cleanup(unit: str, group: str | None) -> bool:
    _stop(unit)
    state = _unit_state(unit)
    inactive = bool(state) and state.get("ActiveState") in {"inactive", "failed"}
    empty = group is None
    if group is not None:
        try:
            events = Path(group, "cgroup.events").read_text()
            empty = "populated 0" in events.splitlines()
        except FileNotFoundError:
            empty = True
        except OSError:
            empty = False
    try:
        subprocess.run(["/usr/bin/systemctl", "--user", "reset-failed", unit], capture_output=True,
                       timeout=3, env=_environment(), stdin=subprocess.DEVNULL)
    except (OSError, subprocess.SubprocessError):
        pass
    return inactive and empty


def _redact(data: bytes, sources: dict[str, str], unit: str) -> bytes:
    for destination, source in sorted(sources.items(), key=lambda item: len(item[1]), reverse=True):
        data = data.replace(os.fsencode(source), destination.encode())
        escaped = source.replace("\\", "\\134").replace(" ", "\\040").replace("\t", "\\011").replace("\n", "\\012")
        data = data.replace(os.fsencode(escaped), destination.encode())
    return data.replace(unit.encode(), b"<execution-unit>").replace(unit.removesuffix(".service").encode(), b"<execution-unit>")


def run(argv: list[str], mounts: dict[str, Path], limits: Limits = Limits()) -> Outcome:
    """Run inside an enforced boundary; never downgrade to host execution."""
    if not isinstance(limits, Limits):
        raise ValueError("limits must be a Limits instance")
    sources = _validate(argv, mounts)
    available, reason = _prerequisites()
    if not available:
        return Outcome("unavailable", None, stderr=reason.encode(), enforcement={"verified": False})
    started = time.monotonic()
    unit = f"custodia-{uuid.uuid4().hex}.service"
    configuration = {"argv": argv, "mounts": sources, "limits": vars(limits), "unit": unit}
    encoded = base64.urlsafe_b64encode(json.dumps(configuration, separators=(",", ":")).encode()).decode()
    command = ["/usr/bin/systemd-run", "--user", "--quiet", "--wait", "--pipe", "--service-type=exec",
               "--expand-environment=no", f"--unit={unit}",
               f"--property=MemoryMax={limits.memory_mib * 1024 * 1024}", "--property=MemorySwapMax=0",
               f"--property=TasksMax={limits.pids}", f"--property=CPUQuota={limits.cpu_percent}%",
               "--property=CPUQuotaPeriodSec=100ms", f"--property=RuntimeMaxSec={limits.wall_seconds}",
               "--property=OOMPolicy=kill", "--property=KillMode=control-group", "--property=TimeoutStopSec=1",
               "--property=SendSIGKILL=yes", "--property=Restart=no", "--property=LimitCORE=0",
               "/usr/bin/python3", "-I", str(Path(__file__).resolve()), "--launch", encoded]
    output = {"stdout": bytearray(), "stderr": bytearray()}
    handshake = bytearray()
    accepted = False
    enforcement: dict = {"verified": False}
    group: str | None = None
    status: str | None = None
    process: subprocess.Popen | None = None
    returncode = None
    try:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   stdin=subprocess.DEVNULL, close_fds=True, env=_environment())
        with selectors.DefaultSelector() as selector:
            for label, stream in (("stdout", process.stdout), ("stderr", process.stderr)):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, label)
            deadline = started + limits.wall_seconds + 8
            while selector.get_map():
                if time.monotonic() >= deadline and status is None:
                    status = "timeout" if accepted else "unavailable"
                    _stop(unit)
                    deadline = time.monotonic() + 4
                for key, _ in selector.select(0.1):
                    data = os.read(key.fileobj.fileno(), 65536)
                    if not data:
                        selector.unregister(key.fileobj)
                        continue
                    label = key.data
                    if label == "stderr" and not accepted:
                        handshake.extend(data)
                        if b"\n" not in handshake:
                            if len(handshake) > 16384:
                                status = "unavailable"
                                _stop(unit)
                            continue
                        first, _, remaining = bytes(handshake).partition(b"\n")
                        try:
                            if not first.startswith(_HANDSHAKE):
                                raise ValueError("missing handshake")
                            proof = json.loads(first[len(_HANDSHAKE):])
                            if proof.get("ok") is not True or proof["enforcement"].get("verified") is not True:
                                raise ValueError("unverified controls")
                            enforcement = proof["enforcement"]
                            group = proof["private_group"]
                            if not isinstance(group, str) or not group.startswith("/sys/fs/cgroup/") or ".." in Path(group).parts:
                                raise ValueError("invalid control group")
                            accepted = True
                            deadline = min(deadline, time.monotonic() + limits.wall_seconds + 2)
                            data = remaining
                            handshake.clear()
                        except (ValueError, KeyError, TypeError):
                            status = "unavailable"
                            _stop(unit)
                            continue
                    remaining = limits.output_bytes - len(output["stdout"]) - len(output["stderr"])
                    output[label].extend(data[:max(0, remaining)])
                    if len(data) > remaining and status is None:
                        status = "output_limit"
                        _stop(unit)
                        deadline = time.monotonic() + 4
                if status is not None and process.poll() is not None and not selector.get_map():
                    break
                if status is not None and time.monotonic() >= deadline:
                    break
        try:
            returncode = process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            _stop(unit)
            process.kill()
            returncode = process.wait(timeout=3)
    except KeyboardInterrupt:
        status = "interrupted"
        _stop(unit)
        if process is not None:
            try:
                returncode = process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                returncode = process.wait(timeout=3)
    except (OSError, subprocess.SubprocessError):
        status = "unavailable"
        _stop(unit)
    finally:
        if process is not None:
            for stream in (process.stdout, process.stderr):
                if stream is not None:
                    stream.close()
    state = _unit_state(unit) or {}
    cleaned = _cleanup(unit, group)
    if status is None:
        if not accepted:
            status = "unavailable"
        elif state.get("Result") == "oom-kill":
            status = "memory_limit"
        elif state.get("Result") == "timeout":
            status = "timeout"
        else:
            status = "completed" if returncode == 0 else "failed"
    if status == "unavailable":
        output = {"stdout": bytearray(), "stderr": bytearray(b"Required isolation controls are unavailable; execution was refused.")}
    elif not cleaned and status == "completed":
        status = "failed"
    stdout = _redact(bytes(output["stdout"]), sources, unit)
    stderr = _redact(bytes(output["stderr"]), sources, unit)
    if len(stdout) + len(stderr) > limits.output_bytes:
        stdout = stdout[:limits.output_bytes]
        stderr = stderr[:limits.output_bytes - len(stdout)]
        if status in {"completed", "failed"}:
            status = "output_limit"
    return Outcome(status, returncode, stdout, stderr,
                   round(time.monotonic() - started, 6), enforcement, cleaned)


def doctor() -> dict:
    """Check the actual boundary with a harmless isolated process."""
    available, reason = _prerequisites()
    if not available:
        return {"available": False, "reason": reason, "enforcement": {"verified": False}}
    result = run(["/usr/bin/python3", "-I", "-c", "print('boundary-ready')"], {},
                 Limits(memory_mib=128, pids=16, wall_seconds=5, scratch_mib=8, output_bytes=4096))
    ready = result.status == "completed" and result.stdout == b"boundary-ready\n" and result.cleanup_verified
    return {"available": ready, "reason": "available" if ready else "Required isolation controls could not be verified",
            "status": result.status, "enforcement": result.enforcement, "cleanup_verified": result.cleanup_verified}


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--launch":
        raise SystemExit(_launch(sys.argv[2]))
    raise SystemExit("This module is an internal execution boundary.")
