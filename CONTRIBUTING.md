# Contributing

Start with a reproducible failure or a narrowly described workflow. Improvements should preserve the fail-closed execution boundary, bounded inputs and outputs, explicit result states, and portable verification.

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e .
python -m unittest discover -s tests -v
```

Portable tests do not require Ghidra or a live isolation backend. Skipped integration tests are not passes. To run actual boundary checks on a supported unprivileged Linux host:

```sh
CUSTODIA_INTEGRATION=1 python -m unittest discover -s tests -v
custodia selftest --json
```

The [Ghidra guide](docs/GHIDRA.md) documents explicit native-versus-isolated integration testing with the included benign fixture. Never substitute an untrusted sample into the native reference test.

Keep changes focused. Include meaningful regression tests for security or data-consistency defects. No implicit network downloads, arbitrary shell commands, target execution, hidden fallback execution, or telemetry. Preserve upstream license notices. Public test data must be synthetic or explicitly redistributable and free of personal data.

An implementation claim should point to a test, a recorded observation, or a clearly stated limit. A new provider needs bounded output, fixed invocation, resource enforcement, completion semantics and benign equivalence tests before it belongs in the supported interface.
