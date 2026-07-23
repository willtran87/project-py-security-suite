# Python Security Suite documentation

Last reviewed: 2026-07-23

Markdown files in this directory are the canonical project documentation.

| Document | Purpose |
|---|---|
| [Design](design.md) | Architecture, trust boundaries, data flow, policy model, report contract, and roadmap |
| [Operations](operations.md) | Native no-Docker preparation, isolated installation, scanning, GitHub publication, and troubleshooting |
| [Configuration](configuration.md) | TOML schema, profiles, policy layering, CLI flags, and exit codes |
| [Compatibility and coverage matrix](compatibility-matrix.md) | Tool roles, overlap, applicability, platform support, limitations, and acquisition |
| [Production security gate](production-security.md) | Strict release profile, residual risk, and companion dynamic and artifact controls |
| [Project README](../README.md) | Concise introduction and quick-start paths |

## Documentation rules

- Update the `Last reviewed` date when behavior or pinned tool versions change.
- Treat source code and generated manifests as the final authority when a
  document and implementation disagree.
- Keep commands copyable and identify whether they run in a connected
  preparation lane or an isolated execution lane.
- Never describe `--network-isolated` as creating a sandbox. It records an
  operator attestation that an external boundary is already active.
- Keep scanner acquisition separate from scanning. Only the connected
  preparation lane may download packages or advisory data.
- Add a compatibility-matrix entry before making a scanner required.

## Current verified baseline

The current native baseline is Windows x86-64 with Python 3.11:

- Bandit 1.9.4
- Semgrep 1.170.0
- detect-secrets 1.5.0
- OSV-Scanner 2.3.8
- Ruff 0.15.22
- CycloneDX Python 7.3.0
- zizmor 1.28.0
- ScanCode Toolkit 32.5.0
- Trivy 0.69.3
- Gitleaks 8.30.1
- TruffleHog 3.95.9
- Syft 1.49.0
- Grype 0.116.0
- check-wheel-contents 0.6.3
- Twine 6.2.0
- PyPI attestations 0.0.29
- `run-codeql` 1.6.0

The latest repository `comprehensive` self-scan selected all 19 adapters.
Thirteen of 15 applicable scanners completed with zero findings and no
failure, timeout, or parse error. CycloneDX, zizmor, Pysa, and GuardDog were
correctly `not applicable` for this repository and native host.

CodeQL and PyPI attestation verification were correctly `unavailable` because
the separately governed CodeQL CLI/query pack and expected publisher,
provenance objects, and trust cache were not staged. The diagnostic result is
therefore `INCOMPLETE`; the connected workstation also did not attest an
external egress-denied boundary. This is fail-closed behavior, not a clean
production result.

The checked report is in
`.artifacts/native-comprehensive-final-self-scan`. It includes:

- the GitHub-ready Markdown, HTML, SARIF, and normalized JSON reports;
- a sanitized evidence record for each selected scanner;
- an artifact CycloneDX SBOM whose two components came from safely expanded
  wheel and source distributions;
- `artifact-manifest.json` with SHA-256 bindings for both distributions; and
- a checksum manifest that was independently verified after generation.

The source test suite currently has 50 tests, including fixtures for all
adapters, private scanner-home isolation, artifact digest binding, and
path-traversal rejection during distribution expansion.
