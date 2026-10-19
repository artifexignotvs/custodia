# Validation and reproduction

CUSTODIA separates portable software tests, installed-package acceptance, real Linux boundary tests, and real Ghidra analysis. Passing one layer does not imply that the others ran.

The [0.1.0 machine-readable record](validation.json) identifies the tested engine and released wheel, the full 104-test run with no skips, and the installed wheel's live boundary and analysis scenarios. It records maintainer observations, not independent attestation.

## Automated repository checks

The CI workflow uses Ubuntu 24.04 with Python 3.11 and 3.13. It:

1. Runs the portable source test suite with live isolation and external-tool integration explicitly disabled.
2. Builds both a wheel and a source distribution.
3. Creates a fresh virtual environment for each distribution and installs that artifact without fetching runtime dependencies.
4. Copies the installed-acceptance runner outside the checkout and executes it with Python isolated mode, with `PYTHONPATH` and `PYTHONHOME` removed.
5. Checks installed imports, version metadata, the console entrypoint, the packaged original Java exporter, controlled fixture observations, saved-session verification, comparison and tamper rejection.

The source distribution is installed independently; passing the wheel test does not substitute for testing the source archive. Build dependencies are installed separately. The package has no declared Python runtime dependencies.

CI does **not** claim that hosted runners enforce the required namespaces, user service controls or Ghidra behavior. The relevant tests are reported as skipped when their explicit gates are disabled. The workflow does not relax host security settings to make them pass. Its actions are pinned to full commit identifiers.

Portable source reproduction:

```sh
CUSTODIA_INTEGRATION=0 CUSTODIA_TEST_GHIDRA=0 \
  PYTHONPATH=src python3 -m unittest discover -s tests -p 'test_*.py' -v
python3 -m pip install build 'setuptools>=77' wheel
python3 -m build
```

For installed acceptance, create a new virtual environment, install one selected wheel or source archive, and copy `tests/installed_acceptance.py` to a working directory outside the source checkout. From that directory run:

```sh
/path/to/fresh-environment/bin/python -B -I installed_acceptance.py
```

Repeat with another new environment for the other artifact. The acceptance runner asserts that imports come from its own installation and that isolated mode is active. It never claims to have run live containment tests.

## Real Linux boundary checks

On a supported host, use the installed commands:

```sh
custodia doctor --json
custodia selftest --json
custodia demo --out demo-session
custodia verify demo-session --json
```

`doctor` verifies a small actual execution boundary and cleanup. `selftest` performs nine bounded checks covering namespace/capability/environment settings, an inaccessible host marker, read-only input, blocked network access, aggregate process and memory enforcement, detached-child timeout cleanup, captured-output limits, and scratch capacity. The marker and input are created specifically for the test; no personal host files are used as test data.

The additional integration tests include handled Ctrl+C cleanup and literal argument preservation. Enable them explicitly from a source checkout:

```sh
CUSTODIA_INTEGRATION=1 PYTHONPATH=src \
  python3 -m unittest discover -s tests -p 'test_*.py' -v
```

A requested real integration run fails if its host cannot enforce the boundary; it does not quietly convert itself into a portable-only success. The external Ghidra tests still require their separate gate and trusted tool paths.

The local validation host successfully exercised the actual namespace and cgroup controls, including group OOM termination, process-count refusal, detached-child cleanup, output truncation with termination, and scratch exhaustion. These observations apply to the tested host and code revision, not every possible Linux installation. See [the security model](SECURITY.md) for the exact trust assumptions and remaining metadata exposure.

## Real Ghidra checks

The optional integration uses the separately supplied, verified Ghidra 12.1.4 distribution and a full JDK 21. It compiles the included benign C fixture without executing the resulting binary, compares the isolated provider report with a native reference analysis of that same controlled fixture, and tests an explicit export cap.

```sh
CUSTODIA_TEST_GHIDRA=1 \
CUSTODIA_GHIDRA_HOME=/path/to/ghidra_12.1.4_PUBLIC \
CUSTODIA_JAVA_HOME=/path/to/jdk-21 \
PYTHONPATH=src python3 -m unittest discover -s tests -p test_ghidra_provider.py -v
```

The native reference is limited to the newly compiled included fixture. It is a comparison test, not an unconfined fallback for ordinary analysis. Do not substitute an untrusted specimen. Normal submitted inputs belong inside `custodia run`.

The local reference report and isolated report matched field for field, including selected decompiled C. Separate isolated checks exercised bounded export and genuine provider timeout behavior. Toolchain digests, findings and reproduction details are documented in [the Ghidra provider guide](GHIDRA.md). This is evidence for the tested specimen and toolchain, not proof of universal analysis equivalence.

## Reading validation records

Release validation records should identify the tested revision or artifact digest, interpreter and tool versions, command family, completed checks, failures and explicit skips. They should omit hostnames, account names, source-directory paths, service identifiers and private inputs. Test totals belong to the exact candidate that produced them; this document deliberately does not freeze a count while the suite evolves.

A portable CI pass, a boundary self-test pass, an installed-package acceptance pass and a successful Ghidra comparison are different facts. A receipt whose hashes match establishes saved-artifact consistency, not authorship, trusted timing or independent execution attestation. No validation result here constitutes upstream endorsement, operating-system inclusion, or a guarantee that every malicious input is contained.
