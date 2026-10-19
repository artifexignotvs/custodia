"""A small terminal interface. Res probatae, non promissa."""

from __future__ import annotations

import argparse
from dataclasses import replace
import json
from pathlib import Path
import sys
import tempfile

from . import __version__
from .backend import doctor
from .policy import Policy, from_document
from .receipt import verify
from .safeio import Invalid, canonical, parse, read
from .selftest import run_selftest
from .session import compare, run_session


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise Invalid("Invalid arguments. Use --help for the command syntax.")


def parser():
    cli = Parser(prog="custodia", description="Bounded binary analysis. Inspect the sample. Keep the boundary.")
    cli.add_argument("--version", action="version", version="custodia " + __version__)
    commands = cli.add_subparsers(dest="command", required=True, parser_class=Parser)
    for name, help_text in (("doctor", "Verify live isolation prerequisites"), ("selftest", "Exercise nine real boundary checks")):
        item = commands.add_parser(name, help=help_text)
        item.add_argument("--json", action="store_true")
    item = commands.add_parser("policy", help="Print the complete default policy as JSON")
    for name in ("run", "retry", "demo"):
        item = commands.add_parser(name, help={"run": "Analyze an input without executing it", "retry": "Create a new attempt from a verified session", "demo": "Analyze a built-in synthetic byte sample"}[name])
        if name != "demo":
            item.add_argument("source", type=Path, metavar="SESSION" if name == "retry" else "SAMPLE")
        item.add_argument("--out", required=True, type=Path, help="New directory; never overwritten")
        item.add_argument("--policy", type=Path, help="Complete custodia.policy.v1 JSON policy")
        item.add_argument("--wall-seconds", type=int, help="Override analysis wall deadline")
        item.add_argument("--memory-mib", type=int, help="Override aggregate memory ceiling")
        if name != "demo":
            item.add_argument("--ghidra-home", type=Path, help="Trusted Ghidra 12.1.4 distribution")
            item.add_argument("--java-home", type=Path, help="Trusted full JDK 21 distribution")
        item.add_argument("--json", action="store_true")
    for name in ("inspect", "verify"):
        item = commands.add_parser(name, help="Verify and summarize a session" if name == "inspect" else "Verify saved artifact consistency")
        item.add_argument("source", type=Path, metavar="SESSION")
        item.add_argument("--json", action="store_true")
    item = commands.add_parser("compare", help="Compare two verified sessions")
    item.add_argument("before", type=Path)
    item.add_argument("after", type=Path)
    item.add_argument("--json", action="store_true")
    item = commands.add_parser("show", help="Read bounded findings from a verified session")
    item.add_argument("source", type=Path, metavar="SESSION")
    item.add_argument("--section", choices=("overview", "functions", "imports", "exports", "strings", "decompile"), default="overview")
    item.add_argument("--limit", type=int, default=20, help="Maximum displayed rows, 1 to 100")
    item.add_argument("--json", action="store_true")
    return cli


def emit(value):
    sys.stdout.write(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True, allow_nan=False) + "\n")


def _summary(receipt):
    print("CUSTODIA / " + __version__)
    print("Analysis       " + receipt["status"].upper())
    print("Provider       " + receipt["provider"])
    print("Input SHA256   " + receipt["input"]["sha256"])
    print("Input bytes    " + str(receipt["input"]["bytes"]))
    print("Limits         " + str(receipt["policy"]["memory_mib"]) + " MiB / " + str(receipt["policy"]["pids"]) + " tasks / " + str(receipt["policy"]["wall_seconds"]) + " seconds")
    for stage in receipt["stages"]:
        print("  " + stage["name"].ljust(13) + stage["status"].upper() + " / cleanup " + ("verified" if stage["cleanup_verified"] else "unverified"))
    print("Receipt scope  Artifact consistency; authenticity not established")


def _policy(args):
    policy = from_document(parse(read(args.policy, 65536))) if args.policy else Policy()
    changes = {name: getattr(args, name) for name in ("wall_seconds", "memory_mib") if getattr(args, name) is not None}
    return replace(policy, **changes)


def _show(args):
    if not 1 <= args.limit <= 100:
        raise Invalid("Display limit must be from 1 to 100.")
    receipt = verify(args.source)["receipt"]
    names = {row["name"] for row in receipt["artifacts"]}
    if "triage.json" not in names:
        raise Invalid("This session has no retained triage findings.")
    triage = parse(read(args.source / "triage.json"))
    analysis = parse(read(args.source / "analysis.json")) if "analysis.json" in names else None
    if args.section == "overview":
        fields = ("format", "architecture", "header_status", "entropy_bits_per_byte", "bytes", "sha256", "ascii_runs_at_least_6", "classification", "target_executed")
        result = {key: triage.get(key) for key in fields}
        if analysis:
            result["program"] = analysis.get("program")
            result["analysis_timed_out"] = analysis.get("analysis_timed_out")
    else:
        if analysis is None and args.section != "strings":
            raise Invalid("This section requires a retained Ghidra report.")
        if args.section == "decompile":
            rows = analysis.get("decompilations")
        elif args.section == "strings" and analysis is None:
            rows = triage.get("ascii_strings")
        else:
            container = analysis.get(args.section)
            rows = container.get("items") if isinstance(container, dict) else None
        if not isinstance(rows, list):
            raise Invalid("The requested report section is malformed.")
        result = {"section": args.section, "retained_rows": len(rows), "displayed_rows": min(len(rows), args.limit), "items": rows[:args.limit], "scope": "retained_export_sample_only"}
    # Notae alienae terminalem regere non debent.
    emit(result)


def main(argv=None):
    try:
        args = parser().parse_args(argv)
        if args.command == "policy":
            emit(Policy().document)
            return 0
        if args.command == "doctor":
            result = doctor()
            if args.json:
                emit(result)
            else:
                print("CUSTODIA / boundary " + ("AVAILABLE" if result["available"] else "UNAVAILABLE"))
                if result["available"]:
                    print("Live enforcement and process cleanup verified. Run selftest for adversarial checks.")
                else:
                    print("Requires Linux, systemd >=254 user services, cgroup v2, bubblewrap and system Python >=3.11.")
                    print("No analysis was started. See docs/BOUNDARIES.md.")
            return 0 if result["available"] else 4
        if args.command == "selftest":
            result = run_selftest()
            if args.json:
                emit(result)
            else:
                print("CUSTODIA / boundary self-test")
                for check in result["checks"]:
                    print("  " + check["id"].ljust(16) + check["status"].upper())
                print("Result         " + result["status"].upper())
                print("Scope          Bounded checks on this host; no universal containment claim")
            return 0 if result["passed"] else 4 if result["status"] == "unavailable" else 3
        if args.command in ("verify", "inspect"):
            result = verify(args.source)
            if args.json:
                emit(result)
            elif args.command == "inspect":
                _summary(result["receipt"])
                print("Files verified " + str(result["artifacts_verified"]))
            else:
                print("CONSISTENT / " + str(result["artifacts_verified"]) + " artifacts")
                print("Receipt SHA256 " + result["receipt_sha256"])
                print("Authenticity not established. Analysis was not repeated.")
            return 0
        if args.command == "compare":
            result = compare(args.before, args.after)
            if args.json:
                emit(result)
            else:
                for label in ("input", "policy", "engine", "tools"):
                    print(label.capitalize().ljust(16) + ("SAME" if result["same_" + label] else "DIFFERENT"))
                print("Status          " + result["status_before"] + " -> " + result["status_after"])
                for label in ("sampled_functions_added", "sampled_functions_removed"):
                    rows = result[label]
                    print(label.replace("_", " ").capitalize() + ": " + ("not available" if rows is None else str(len(rows))))
                print("Exported function sample only; no vulnerability verdict.")
            return 0
        if args.command == "show":
            _show(args)
            return 0
        policy = _policy(args)
        progress = lambda name, status: print("  " + name.ljust(12) + status, file=sys.stderr)
        options = {"progress": progress}
        if args.command == "demo":
            # Specimen fictum tantum; nec compilatio nec executio.
            with tempfile.TemporaryDirectory(prefix="custodia-demo-") as temporary:
                sample = Path(temporary) / "sample.bin"
                sample.write_bytes(b"\0asm\x01\0\0\0\0\x16\x15CUSTODIA byte fixture")
                result = run_session(sample, args.out, policy, **options)
        else:
            source = args.source
            options.update(ghidra_home=args.ghidra_home, java_home=args.java_home)
            if args.command == "retry":
                previous = verify(source)["receipt"]
                if args.policy is None:
                    changes = {key: getattr(args, key) for key in ("wall_seconds", "memory_mib") if getattr(args, key) is not None}
                    policy = replace(from_document(previous["policy"]), **changes)
                options["retry"] = source
                source = source / "input.bin"
            result = run_session(source, args.out, policy, **options)
        if args.json:
            emit(result)
        else:
            _summary(result)
        return 0 if result["status"] == "completed" else 130 if result["status"] == "interrupted" else 4 if result["status"] == "unavailable" else 3
    except Invalid as error:
        print("custodia: " + str(error), file=sys.stderr)
        return 2
    except (OSError, ValueError, RuntimeError):
        print("custodia: Operation failed. Check trusted inputs and available storage; existing artifacts were not overwritten.", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("custodia: Interrupted.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
