# Security policy

## Supported code

Security fixes are applied to the current `main` branch and the latest published
release. Older snapshots and generated artifacts are not independently
maintained.

## Report a vulnerability privately

Do not open a public issue for a suspected vulnerability, leaked credential, or
bypass of a security boundary. Use GitHub's
[private vulnerability reporting](https://github.com/willtran87/project-py-security-suite/security/advisories/new)
workflow. If that channel is unavailable, contact the repository owner through
their verified GitHub profile before sharing sensitive details.

Include the affected version or commit, operating system, scan profile,
reproduction steps, expected and observed behavior, and security impact. Attach
only sanitized evidence. Never include real credentials, private source code,
customer data, signing keys, or restricted scanner databases.

Maintainers will coordinate disclosure and remediation through the private
advisory. Publish details only after an agreed fix and disclosure plan.

## Security boundaries

The suite orchestrates locally installed tools; it does not create a network
sandbox. `--network-isolated` records an operator assertion that an external
egress-denied boundary already exists. A clean report is evidence about the
configured perspectives and inputs, not proof that software is vulnerability
free.
