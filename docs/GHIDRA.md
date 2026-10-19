# Ghidra provider

CUSTODIA runs Ghidra headless inside its Linux execution boundary. The submitted file is imported for static analysis; the adapter does not execute it. An original, bundled Java post-script exports bounded findings and selected decompilations. Ghidra and the JDK are separate, user-supplied dependencies.

## Tested toolchain

The reference toolchain is **Ghidra 12.1.4 with a 64-bit JDK 21** on Linux x86-64. A Java runtime alone is insufficient: the JDK must include `bin/javac`.

Use the requirements of the selected release. The development branch can require a newer Java version than the published release. The [12.1.4 Getting Started guide](https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.4_build/GhidraDocs/GettingStarted.md) specifies Java 21 and lists 4 GB of RAM and 1 GB of storage as its general installation requirements. CUSTODIA applies its own per-run resource limits; large inputs may need higher limits or produce partial results.

The validated downloads were:

| Component | Official release | Archive SHA-256 |
| --- | --- | --- |
| Ghidra 12.1.4 | [Official release](https://github.com/NationalSecurityAgency/ghidra/releases/tag/Ghidra_12.1.4_build), `ghidra_12.1.4_PUBLIC_20260921.zip` | `ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db` |
| Temurin JDK 21.0.12.1+1, Linux x64 | [Official release](https://github.com/adoptium/temurin21-binaries/releases/tag/jdk-21.0.12.1%2B1), `OpenJDK21U-jdk_x64_linux_hotspot_21.0.12.1_1.tar.gz` | `ce79869e1307ed8ee1e2baa86a412b1eb5b75d10a01006d788a6f968bcfaee94` |

These digests were checked against the official release asset metadata and downloaded bytes. They identify the tested downloads, not a promise that a dependency has no vulnerabilities. Review upstream security advisories when selecting a toolchain.

Extract into dedicated directories, preserving archive permissions and timestamps. In particular, incorrect source/compiler timestamps can cause Ghidra to attempt recompiling language specifications. The tool directories are mounted read-only during analysis. Do not put credentials, private projects, unrelated extensions, or personal files inside them. A modified distribution has a different content identity.

CUSTODIA does not download tools during a run. It does not bundle Ghidra or a JDK. Their upstream licenses continue to apply; Ghidra's main project is licensed under [Apache 2.0](https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.4_build/LICENSE), with dependency notices in its distribution.

## Run a harmless specimen

From a source checkout, compile the included fixture without executing it:

```sh
gcc -O0 -fno-pie -no-pie -g0 -Wl,--build-id=none examples/fixture.c -o sample.bin
custodia run sample.bin --out case \
  --ghidra-home /path/to/ghidra_12.1.4_PUBLIC \
  --java-home /path/to/jdk-21
```

Point `--ghidra-home` at the directory containing `support/analyzeHeadless`; point `--java-home` at the directory containing `bin/java` and `bin/javac`. The backend must pass its actual enforcement checks. A missing execution boundary is an error, and does not trigger a native fallback.

The provider uses fixed paths and a fixed post-script. Sample filenames cannot supply headless flags, scripts, or shell commands. The environment uses an isolated home, cache, settings directory, temporary directory, and explicit Java path. User Java options and analysis scripts are not inherited.

## What the report contains

The provider report uses schema `custodia.ghidra-report.v1`:

- Format, language, compiler, image base, pointer size, and endianness.
- Memory blocks with addresses, sizes, permissions, and initialization state.
- Internal functions in address order, plus the program's total function count. That total includes external functions; the exported sample does not.
- Imported symbols and external entry points. These are Ghidra's recovered model, not a guarantee about runtime behavior.
- Defined top-level string data, with addresses and visible truncation flags.
- Selected decompiled C, with per-function completion, truncation, and failure information.
- Analysis timeout state, completed phases, and the applied export limits.

Decompilation selects `main` first if it appears in the exported function sample, then non-thunk functions by address. It does not recover an entire source tree. The supplied file's SHA-256 and tool identities belong to the parent receipt, separate from the provider's findings.

Default export bounds are 1,000 internal functions, 2,000 imports, 2,000 external entry points, 256 memory blocks, and 2,000 strings. The string pass examines at most 100,000 defined data items, skips string items larger than 4,096 bytes, and limits exported string values and names to 256 characters. The report records these limits and relevant truncation or skip counters.

The default selection is three decompilations, each with a ten-second decompiler timeout and at most 32,768 exported characters. At most ten functions can be requested through the provider configuration. The decompiler also has bounded instruction, jump-table, and response-size settings. Serialized reports are limited to 4 MiB.

These are output and provider limits, in addition to the process boundary's memory, process-count, CPU, scratch-space, and overall time limits. They do not estimate how much of an unknown program has been understood. A completed report means its requested bounded phases finished, not that every behavior or function was recovered.

## Partial results and failure

Ghidra's `-analysisTimeoutPerFile` interrupts auto-analysis and then runs the post-script. CUSTODIA records this as `analysis_timed_out: true` and a partial report. It never relabels that report as complete merely because the headless process exited successfully.

The Java exporter atomically replaces a scratch-space checkpoint after metadata, the function overview, symbols, strings, and each decompilation. If the provider stops but the worker can still read a valid checkpoint, completed phases can be exported as partial results. A missing or invalid report is a provider failure.

An overall wall-time or resource-limit termination can kill the worker before it exports a checkpoint. In that case, Ghidra findings may be unavailable; previously committed parent-side triage remains separate. Scratch-space checkpoints are not a promise of persistent Ghidra results after the entire execution boundary is terminated.

Decompilation failures, truncated output, unsupported imports, and analysis timeouts require review. Neither an empty report nor a successful parse certifies that an input is safe.

## Validation and reproduction

Validation used the included benign C fixture, compiled locally without executing the resulting specimen. The complete parsed report from isolated Ghidra was compared with a direct native Ghidra run using the same verified toolchain and script. **Every report field matched**, including all selected decompiled C bodies. Two native runs also produced identical report bytes. The Ghidra distribution's complete content identity was unchanged after these runs.

The fixture produced 19 internal function records, five imported symbols, 13 external entry points, and three successful decompilations. These counts describe that compiler/toolchain combination; other compilers or versions may produce different counts. The comparison demonstrates semantic preservation for this small specimen, not universal equivalence for all formats or adversarial binaries.

Additional real isolated checks verified:

- A two-function export cap returned exactly two records, a truncation flag, and no decompilations when zero were requested.
- A one-second auto-analysis limit on a trusted system C library produced a genuine Ghidra analysis timeout, retained bounded findings, and returned a partial result.
- The boundary reported verified enforcement and verified cleanup for each run.

The toolchain integration tests are opt-in, because Ghidra and a JDK are not installed by the package:

```sh
CUSTODIA_TEST_GHIDRA=1 \
CUSTODIA_GHIDRA_HOME=/path/to/ghidra_12.1.4_PUBLIC \
CUSTODIA_JAVA_HOME=/path/to/jdk-21 \
PYTHONPATH=src python3 -m unittest discover -s tests -p test_ghidra_provider.py -v
```

This requires GCC, the explicitly selected trusted toolchain, and working Linux isolation. The native reference run analyzes only the newly compiled included fixture with a controlled environment. Do not replace that test fixture with an untrusted specimen: ordinary analysis belongs inside `custodia run`.

The implementation uses Ghidra's documented [headless interface](https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.4_build/Ghidra/RuntimeScripts/Common/support/analyzeHeadlessREADME.md) and [decompiler API](https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/DecompInterface.html). It does not alter Ghidra, replace its analyzers, or claim upstream endorsement.
