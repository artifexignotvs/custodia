# Execution boundaries and current limits

This document describes the implemented technical preview. Features not listed here must not be inferred from a successful run or from the presence of a receipt.

## Work performed

A session first creates a bounded, hashed copy of one regular input file. Static triage computes byte statistics and bounded header/string observations. With the optional Ghidra provider, the second stage imports the same snapshot into a temporary headless project and exports a bounded report and a selected decompilation sample.

The submitted file is not intentionally executed. There is no network service, cloud submission, automatic download, interactive target shell, dynamic malware analysis, disk acquisition, memory acquisition, exploit generation or malware classification. The application uses Linux namespaces and cgroups; it is not a VM or an independent kernel.

| Area | Implemented behavior | Boundary of the claim |
| --- | --- | --- |
| Filesystem | Selected runtime and tool trees and the input are read-only; work files stay in a size-limited temporary filesystem. | Trusted runtime files are readable. Host metadata is not fully hidden. |
| Network | A fresh network namespace is used without host networking or exposed service sockets. | This does not cover kernel escapes or a hostile host administrator. |
| Memory | Cgroup aggregate memory maximum, zero swap, and group OOM termination. | Kernel accounting is authoritative; it is not a per-language heap guarantee. |
| Processes | Aggregate task limit includes threads, helpers and children. | A requested limit is not the number of child processes a parser can additionally create. |
| CPU | Cgroup quota controls the entire stage's execution rate. | 100% means roughly one CPU of quota, not all host CPUs or a total CPU-seconds budget. |
| Time | A stage has a service deadline and a parent deadline; session stages share a remaining-time budget. | Host preflight, input copying, tool hashing and final publication are outside the configured execution budget. |
| Output | Combined captured standard output and error have a byte cap; overflow stops the group. | Ghidra's internal log excerpt has its own smaller cap. A truncated stream is not a complete report. |
| Cleanup | Whole-group stop and observed inactive/empty group are checked. | Abrupt controller death cannot produce a final cleanup assertion; the service deadline remains active. |
| Verification | File hashes, inventory, policy and declared completion consistency are checked. | No signer identity, trusted clock, remote attestation or independent execution proof is established. |

## Public session policy

The CLI session policy is stricter than the internal backend limits used by boundary tests.

| Setting | Default | Accepted range |
| --- | ---: | ---: |
| Aggregate memory | 2,048 MiB | 128–8,192 MiB |
| Tasks, including threads | 128 | 16–512 |
| CPU quota | 100% of one CPU | 1–400% |
| Execution wall budget | 180 seconds | 5–3,600 seconds |
| Scratch capacity | 512 MiB | 16–2,048 MiB |
| Captured output | 8 MiB | 64 KiB–16 MiB |
| Exported function sample | 1,000 | 1–1,000 |
| Decompiled function sample | 3 | 0–10 |
| Per-function decompilation timeout | 10 seconds | 1–60 seconds |
| Ghidra analysis timeout | 120 seconds | 1–3,600 seconds, bounded by remaining execution time |

Scratch capacity must be smaller than the aggregate memory limit. Scratch pages also consume memory charged to the service. Giving a job a large scratch capacity does not reserve that amount of RAM. A policy can be valid but insufficient to complete a particular analysis; that run should fail or time out explicitly.

Input snapshots are limited to **128 MiB**. Ordinary structured JSON artifacts are read with a **16 MiB** limit. The worker reads the Ghidra report with a **4 MiB** limit and retains at most **32 KiB** of its combined log excerpt. These limits are not promises that every input within them can be analyzed successfully.

The optional provider supports the tested **Ghidra 12.1.4** and a separately supplied **full JDK 21**. Other distributions are not silently treated as equivalent. The application records distribution tree identities without copying the tools into the session and compares those identities again after the stage loop.

## Visible runtime and writable state

The sandbox exposes host `/usr/bin`, `/usr/lib`, optional `/usr/lib64`, and the dynamic loader cache when present. Compatibility symlinks provide `/bin`, `/lib` and `/lib64`. It does not expose all of host `/usr`, `/etc`, `/run`, `/sys` or the home directory.

The only configurable read-only mount destinations are:

- `/input/sample.bin` for the session snapshot.
- `/opt/custodia` for the trusted worker and original adapters.
- `/opt/ghidra` for the selected Ghidra distribution.
- `/opt/java` for the selected JDK distribution.

`/work` is a new size-limited temporary filesystem. It holds the private home, cache, temporary files, analysis project and report. `/tmp` points into that work area. Root, runtime, input, tool, proc and device directory mounts are read-only; required minimal device interfaces remain available. The analysis process has no direct writable host output-directory mount. Results return through bounded pipes and are published by the trusted host controller.

The environment contains fixed runtime settings. `CUSTODIA_BOUNDARY` and related worker guards prevent accidental direct invocation; they are not authentication tokens or security evidence. The pre-execution controller checks, namespace setup and live boundary tests provide the relevant checks.

## Preservation, retries and comparisons

Completed stages are published as separate artifacts. If a later stage times out or exhausts a limit, earlier completed artifacts remain available. This is stage preservation, not recovery of a killed process's private scratch filesystem. Ghidra projects are temporary and are not resumable checkpoints.

A retry creates a new session. It can reuse completed triage only after verifying the previous session and matching the input, policy, engine and tool identities. The reused stage is marked explicitly and links to the parent receipt digest. The analysis stage is run again; no incomplete in-memory Ghidra state is resumed. Keep a retry source stable while it is verified and copied.

Comparison reports input, policy, engine, tool and status differences, plus changes in the exported function-name sample when available. It is not a full semantic binary diff, coverage proof, vulnerability verdict, or proof that two executables behave identically.

## Failure and interruption

Completion requires a valid worker result, successful backend return, verified enforcement and confirmed cleanup. Resource limits and refusal are explicit states. A worker protocol error or uncertain cleanup is not accepted as completion.

A handled Ctrl+C attempts group termination and receipt publication. SIGKILL, power loss, or a controller crash can leave an incomplete session directory without a final receipt. Such a directory is not a valid completed session. If the transient service was started, its independent runtime limit still applies; it can remain active until that deadline and shutdown processing finish.

`doctor` runs a small real boundary check. `selftest` exercises specific network, file and resource controls with bounded harmless probes. Their success is evidence about that host and those test cases at that time. It is not exhaustive validation of the kernel, all analysis inputs, or every possible parser action.

## Sharing and authenticity

The session includes the exact input snapshot and may include extracted private strings, decompiled content and provider diagnostics. No encryption, automatic redaction of arbitrary secrets, secure erasure, signing authority, or trusted timestamp service is provided.

A matching checksum establishes consistency with the supplied manifest. It does not establish who produced it. The receipt identifies its scope as `recorded_execution_and_artifact_consistency` and its authenticity as `not_established`.

See [the security model](SECURITY.md) for the trusted-host assumptions, remaining metadata exposure, and vulnerability reporting guidance.
