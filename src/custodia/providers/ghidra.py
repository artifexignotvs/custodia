"""Build a fixed headless Ghidra invocation; no target is executed."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import stat
from typing import Any

TESTED_VERSION = "12.1.4"
_MAX_TOOL_BYTES = 8 * 1024**3
_MAX_TOOL_FILES = 100_000


def _number(config: dict[str, Any], name: str, default: int, lower: int, upper: int) -> int:
    value = config.get(name, default)
    if isinstance(value, bool) or not isinstance(value, int) or not lower <= value <= upper:
        raise ValueError(f"{name} must be an integer from {lower} to {upper}")
    return value


def sandbox_command(config: dict[str, Any]) -> list[str]:
    """Return only fixed paths and validated numeric arguments."""
    functions = _number(config, "max_functions", 1000, 1, 1000)
    count = _number(config, "decompile_count", 3, 0, 10)
    seconds = _number(config, "decompile_seconds", 10, 1, 60)
    analysis = _number(config, "analysis_seconds", 120, 1, 3600)
    return [
        "/opt/ghidra/support/analyzeHeadless", "/work/projects", "analysis",
        "-import", "/input/sample.bin", "-scriptPath", "/opt/custodia/providers/scripts",
        "-postScript", "CustodiaReport.java", "/work/report.json",
        str(functions), str(count), str(seconds),
        "-analysisTimeoutPerFile", str(analysis), "-max-cpu", "1",
        "-log", "/work/ghidra.log", "-scriptlog", "/work/script.log", "-deleteProject",
    ]


def sandbox_environment(config: dict[str, Any]) -> dict[str, str]:
    """Return an explicit environment addition for the already isolated worker."""
    heap = _number(config, "heap_mb", 1024, 256, 4096)
    return {
        "PATH": "/opt/java/bin:/usr/bin:/bin",
        "JAVA_HOME": "/opt/java",
        "HOME": "/work/home",
        "XDG_CONFIG_HOME": "/work/home/config",
        "XDG_CACHE_HOME": "/work/cache",
        "TMPDIR": "/work/tmp",
        "GHIDRA_HEADLESS_MAXMEM": f"{heap}M",
        "GHIDRA_HEADLESS_JAVA_OPTIONS": (
            "-Duser.home=/work/home -Djava.io.tmpdir=/work/tmp "
            "-Dapplication.settingsdir=/work/home/settings "
            "-Dapplication.cachedir=/work/cache "
            "-Dapplication.tempdir=/work/tmp -Djava.awt.headless=true "
            "-Duser.timezone=UTC -XX:ActiveProcessorCount=2"
        ),
    }


def tool_identity(home: Path) -> dict[str, Any]:
    """Hash every regular distribution file without publishing local paths.

    This identifies the supplied bytes; it does not authenticate their publisher.
    Symlinks and special files are rejected rather than escaping the selected tree.
    """
    home = Path(home)
    if home.is_symlink() or not home.is_dir():
        raise ValueError("Ghidra home must be a regular directory, not a symlink")
    properties = home / "Ghidra/application.properties"
    launcher = home / "support/analyzeHeadless"
    if not properties.is_file() or not launcher.is_file():
        raise ValueError("Ghidra home lacks the release properties or headless launcher")
    digest = hashlib.sha256(b"custodia-tool-tree-v1\x00")
    count = total = 0
    version_content: bytes | None = None

    # Omnia instrumenti membra recensentur; nexus non sequimur.
    def visit(directory: Path):
        nonlocal count, total, version_content
        for entry in sorted(os.scandir(directory), key=lambda item: item.name):
            path = Path(entry.path)
            relative = path.relative_to(home).as_posix().encode("utf-8")
            info = entry.stat(follow_symlinks=False)
            if stat.S_ISLNK(info.st_mode):
                raise ValueError("Ghidra distribution contains a symlink")
            if stat.S_ISDIR(info.st_mode):
                yield from visit(path)
                continue
            if not stat.S_ISREG(info.st_mode):
                raise ValueError("Ghidra distribution contains a non-regular file")
            count += 1
            total += info.st_size
            if count > _MAX_TOOL_FILES or total > _MAX_TOOL_BYTES:
                raise ValueError("Ghidra distribution exceeds the identity scan limit")
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            file_digest = hashlib.sha256()
            actual = 0
            captured = bytearray() if path == properties else None
            try:
                before = os.fstat(descriptor)
                if (before.st_dev, before.st_ino, before.st_size) != (info.st_dev, info.st_ino, info.st_size):
                    raise ValueError("Ghidra distribution changed during the identity scan")
                while chunk := os.read(descriptor, 1024 * 1024):
                    actual += len(chunk)
                    if actual > info.st_size:
                        raise ValueError("Ghidra distribution changed during the identity scan")
                    file_digest.update(chunk)
                    if captured is not None:
                        captured.extend(chunk)
                        if len(captured) > 65536:
                            raise ValueError("Ghidra release properties exceed the size limit")
                after = os.fstat(descriptor)
                if actual != before.st_size or (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                    raise ValueError("Ghidra distribution changed during the identity scan")
            finally:
                os.close(descriptor)
            if captured is not None:
                version_content = bytes(captured)
            yield (relative, info.st_mode & 0o111, actual, file_digest.digest())

    for relative, executable, size, file_hash in visit(home):
        digest.update(len(relative).to_bytes(4, "big"))
        digest.update(relative)
        digest.update(executable.to_bytes(2, "big"))
        digest.update(size.to_bytes(8, "big"))
        digest.update(file_hash)
    if version_content is None:
        raise ValueError("Ghidra release properties were not included in the scan")
    match = re.search(rb"(?m)^application\.version=([A-Za-z0-9.+_-]{1,64})\s*$", version_content)
    if match is None:
        raise ValueError("Ghidra release version is missing or malformed")
    version = match.group(1).decode("ascii")
    return {
        "name": "ghidra", "version": version, "tree_sha256": digest.hexdigest(),
        "file_count": count, "size_bytes": total, "tested_version": version == TESTED_VERSION,
    }
