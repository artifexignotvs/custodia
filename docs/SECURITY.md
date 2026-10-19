# Security model

CUSTODIA is a Linux terminal workbench for static binary analysis. It imports a submitted file into trusted analysis tools inside a restricted process environment. It does not intentionally launch the submitted binary, provide an interactive malware execution environment, or replace a virtual machine.

The boundary is intended to contain a compromised parser that attempts to read unrelated host files, contact the network, modify the submitted snapshot, create excessive processes, exhaust its assigned memory, or leave children running. The host kernel is shared. Kernel vulnerabilities, attacks on the host administrator, physical access, and malicious changes by another process with the same host account are outside this claim.

## What must be trusted

The following are part of the trusted computing base:

- The Linux kernel, host administrator, systemd user manager, bubblewrap, system Python, and the host runtime files exposed under `/usr/bin` and `/usr/lib`.
- CUSTODIA's installed code and its original analysis adapter scripts.
- The selected Ghidra and full JDK distributions. These are supplied separately; CUSTODIA does not authenticate their publisher or download them automatically.
- The output directory's parent and the local filesystem used to store sessions. They must not be modified concurrently by another actor.

Use trusted, stable tool distributions and keep them unchanged throughout a session. Content hashes identify scanned files; they do not make an untrusted distribution trustworthy. The engine, input and selected external tool trees are checked before execution and again after the stage loop. Matching before-and-after identities do not prove that a hostile host process left every byte unchanged between those checks.

The supported Ghidra adapter targets Ghidra 12.1.4 with a full JDK 21 distribution. A JRE without `javac` is insufficient. Distribution identities and the selected policy are recorded with results.

## Enforced execution boundary

CUSTODIA requires an unprivileged Linux account, a working systemd user service manager, cgroup v2 controllers, a compatible bubblewrap installation, and system Python 3.11 or later at `/usr/bin/python3`. The systemd requirement is version 254 or later. Supported hosts must provide the runtime layout under `/usr/bin` and `/usr/lib`. A different Python in an activated environment does not replace the system interpreter used inside the boundary.

Before starting the parser, a trusted launcher checks the running service's actual memory, swap, process and CPU controller values. It also checks the service type, runtime deadline, shutdown timeout, group termination policy, OOM policy, and absence of delegation or restart. Missing or mismatched controls cause refusal. There is no unconfined fallback.

The process environment uses:

- Separate user, mount, PID, IPC, network, UTS and cgroup namespaces, with further user namespaces disabled.
- No effective capabilities and the no-new-privileges setting established by bubblewrap.
- A new terminal session, closed extra descriptors, and no interactive standard input.
- A fixed internal hostname and user identity, an explicit environment, and an empty host-home view.
- Read-only runtime, tool and input mounts; a separate, size-limited temporary work filesystem.
- A network namespace without a host interface, route, resolver configuration or exposed host service socket.
- Cgroup limits shared by the whole process tree, including threads and parser children.

No host home, host `/run`, system bus, user bus, container socket, or host cgroup filesystem is mounted into the parser environment. `/proc` belongs to the isolated PID namespace; `/proc/sys` is masked. CUSTODIA does not currently install a dedicated syscall allowlist. Namespace isolation is not a separate kernel.

The input is copied to a regular session file before analysis and mounted read-only. Its digest and size are checked after the stages finish. The original file is never opened for writing. Read-only mounting prevents modification of that snapshot by the parser; it does not prevent a compromised parser from copying bytes into its own scratch space and running code there.

## Termination and resource limits

A fresh transient service contains each stage. Memory and process limits apply to the whole service, not separately to each child. Swap is disabled for that service. An out-of-memory kill terminates the group. CPU quota limits its execution rate relative to one CPU; it is not a total CPU-time allowance.

The independent service deadline and the parent controller both bound stage execution. Timeout, captured-output overflow and a handled Ctrl+C request cause whole-group termination. Cleanup checks require an inactive service and an empty or removed cgroup when its path was captured. A result whose cleanup cannot be confirmed is not accepted as completed.

Ctrl+C handling is best effort while the controller is alive. If the controller is killed with SIGKILL, crashes, or loses power, it cannot write a final receipt or run its cleanup handler. The already-started service retains its independent runtime limit, but immediate cleanup after controller death is not promised. Bubblewrap's parent-death setting refers to its service-side parent; it is not an immediate liveness link to the original terminal command.

The configured wall budget begins after host preflight, tool identity scans and input snapshot creation. It is not a deadline for the entire command. Service shutdown, final hashing and receipt publication also take time. A stuck kernel or unavailable service manager can prevent timely cleanup; such conditions must not be interpreted as successful isolation verification.

## Results are evidence records, not attestations

A session contains a plaintext input snapshot, bounded analysis artifacts, diagnostics, a receipt, and a checksum manifest. Directory creation requests private permissions, but CUSTODIA does not encrypt these files or securely erase them. The submitted file and its extracted strings may themselves be confidential.

`verify` checks recorded artifact consistency, inventory, schemas, policy identity and declared completion relationships. It does not repeat execution, authenticate the author, prove the host was uncompromised, establish a trusted timestamp, or certify that a finding is correct. Someone who can replace the files can also construct a matching receipt and checksum manifest. Receipts explicitly state `authenticity: not_established`.

Parser output remains untrusted. A compromised parser may produce plausible but false analysis while staying inside the boundary. A successful boundary test proves the tested controls behaved as observed; it does not prove that every parser, kernel and input is safe.

## Host metadata and sharing

The fixed internal hostname, cleared environment and omitted source filenames reduce accidental disclosure. They do not create an anonymous machine. Kernel and hardware metadata remain observable. In particular, namespace mount information can reveal bind-source path metadata and numeric identifiers from the host. Runtime files may contain distribution information.

Structured enforcement records omit host source paths, service identifiers and host account identity. Captured output redacts known mount-source paths. This is a convenience against accidental disclosure, not a guarantee against arbitrary encodings or a hostile parser deliberately including metadata in a result. Ghidra diagnostics and extracted strings must be reviewed before a session is shared publicly.

## Reporting a suspected vulnerability

Use the repository's private vulnerability reporting facility when it is available. Include the affected version, host prerequisites, expected boundary, observed result, and a minimal harmless reproducer. Avoid publishing private inputs or an uncoordinated working escape. Public issues are appropriate for non-sensitive compatibility failures and sanitized error reports.

For an isolation failure, preserve the receipt and the exact policy privately. Distinguish a refused run, a correctly enforced resource limit, an inaccurate analysis result and a demonstrated boundary violation.
