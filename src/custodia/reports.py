"""Reject contradictory evidence before displaying or reusing it."""

from .safeio import Invalid


def validate_result(value, name, identity, completed=False):
    expected = "custodia.triage.v1" if name == "triage" else "custodia.ghidra-report.v1"
    if not isinstance(value, dict) or value.get("schema") != expected:
        raise Invalid("Invalid analysis result schema.")
    if name == "triage":
        if value.get("sha256") != identity["sha256"] or type(value.get("bytes")) is not int or value["bytes"] != identity["bytes"]:
            raise Invalid("Triage identity contradicts the input snapshot.")
        if value.get("target_executed") is not False or value.get("classification") != "not_performed":
            raise Invalid("Triage claims an unsupported analysis scope.")
    else:
        if value.get("status") not in ("partial", "completed") or type(value.get("analysis_timed_out")) is not bool:
            raise Invalid("Invalid provider completion record.")
        if completed and (value["status"] != "completed" or value["analysis_timed_out"] or value.get("decompilation_failed") is True):
            raise Invalid("Analysis completion contradicts its report.")
        functions = value.get("functions")
        if not isinstance(functions, dict) or not isinstance(functions.get("items"), list) or len(functions["items"]) > 1000:
            raise Invalid("Invalid bounded function inventory.")
        if any(not isinstance(row, dict) or not isinstance(row.get("name"), str) or len(row["name"]) > 256 for row in functions["items"]):
            raise Invalid("Invalid bounded function entry.")


def validate_enforcement(value, policy):
    if not isinstance(value, dict) or value.get("verified") is not True:
        raise Invalid("Completed stage lacks verified enforcement.")
    exact = {"memory_max_bytes": policy.memory_mib * 1024**2, "memory_swap_max_bytes": 0,
             "pids_max": policy.pids, "scratch_max_bytes": policy.scratch_mib * 1024**2}
    if any(type(value.get(key)) is not int or value[key] != expected for key, expected in exact.items()):
        raise Invalid("Recorded resource controls contradict the policy.")
    quota, period, wall = value.get("cpu_quota_us"), value.get("cpu_period_us"), value.get("wall_seconds")
    if type(quota) is not int or type(period) is not int or period <= 0 or quota * 100 != period * policy.cpu_percent or type(wall) is not int or not 1 <= wall <= policy.wall_seconds:
        raise Invalid("Recorded CPU or deadline controls contradict the policy.")
    if any(value.get(key) != expected for key, expected in {"backend": "bubblewrap+systemd-user-cgroup-v2", "network": "isolated", "capabilities": "none", "termination": "control-group"}.items()) or value.get("readonly_input") is not True or value.get("isolated_home") is not True:
        raise Invalid("Recorded isolation controls are incomplete.")
