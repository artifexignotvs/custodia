"""Trusted sandbox entrypoint. Codicem alienum numquam exsequere."""

from __future__ import annotations

import json
import os
from pathlib import Path
import selectors
import subprocess
import sys

# Via nota sola admittitur; argumenta specimen non fiunt.
sys.path.insert(0, "/opt")


def ghidra(config: dict) -> dict:
    from custodia.providers.ghidra import sandbox_command, sandbox_environment

    for name in ("projects", "home", "cache", "tmp"):
        Path("/work", name).mkdir(exist_ok=True)
    environment = {"PATH": "/usr/bin:/bin", "HOME": "/work/home", "TMPDIR": "/work/tmp", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", **sandbox_environment(config)}
    process = subprocess.Popen(sandbox_command(config), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment, close_fds=True)
    collected = bytearray()
    truncated = False
    selector = selectors.DefaultSelector()
    for stream in (process.stdout, process.stderr):
        os.set_blocking(stream.fileno(), False)
        selector.register(stream, selectors.EVENT_READ)
    while selector.get_map():
        for key, _ in selector.select(timeout=0.2):
            chunk = os.read(key.fd, 8192)
            if not chunk:
                selector.unregister(key.fileobj)
                key.fileobj.close()
            else:
                remaining = 32768 - len(collected)
                collected.extend(chunk[:max(0, remaining)])
                truncated |= len(chunk) > remaining
    selector.close()
    code = process.wait()
    from custodia.safeio import parse, read

    report = parse(read(Path("/work/report.json"), 4 * 1024 * 1024), 4 * 1024 * 1024) if Path("/work/report.json").exists() else None
    if report is not None and (not isinstance(report, dict) or report.get("schema") != "custodia.ghidra-report.v1"):
        raise ValueError("Invalid provider report")
    partial = code != 0 or report is None or bool(report.get("analysis_timed_out", False)) or report.get("status") != "completed"
    return {"schema": "custodia.worker.v1", "status": "failed" if report is None else "partial" if partial else "completed", "result": report, "diagnostics": {"provider_exit_code": code, "log_excerpt": collected.decode("utf-8", "replace"), "log_truncated": truncated}}


def main():
    if os.environ.get("CUSTODIA_BOUNDARY") != "1" or not Path("/input/sample.bin").is_file():
        raise SystemExit("Worker requires the configured analysis boundary.")
    try:
        if sys.argv[1] == "triage":
            from custodia.triage import inspect
            result = {"schema": "custodia.worker.v1", "status": "completed", "result": inspect(Path("/input/sample.bin")), "diagnostics": {}}
        elif sys.argv[1] == "ghidra" and len(sys.argv) == 3:
            result = ghidra(json.loads(sys.argv[2]))
        else:
            raise ValueError("Invalid worker mode")
        sys.stdout.write(json.dumps(result, sort_keys=True, ensure_ascii=True, allow_nan=False) + "\n")
    except Exception:
        sys.stdout.write(json.dumps({"schema": "custodia.worker.v1", "status": "failed", "result": None, "diagnostics": {"error": "provider_worker_failed"}}) + "\n")
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
