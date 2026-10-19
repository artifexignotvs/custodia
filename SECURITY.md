# Security policy

CUSTODIA 0.1.x is a technical preview. Security fixes target the latest published 0.1.x version. Its containment model relies on a trusted, updated Linux kernel, system service manager, bubblewrap, Python runtime and selected analysis toolchain.

Read [the threat model](docs/SECURITY.md) and [enforcement details](docs/BOUNDARIES.md). Do not interpret a completed analysis, passing probe suite, or matching hash as a guarantee that a specimen or host is safe.

Please report a potential boundary escape or confidential-data exposure through the repository's private vulnerability reporting interface when available. Do not place credentials, private specimen data, or weaponized escape instructions in a public issue. For ordinary reproducible defects, provide a minimized benign example and sanitized diagnostic facts.

There is no guaranteed response time, bounty, certification, or independent security audit claim for this preview.
