# Python Security Suite documentation

Last reviewed: 2026-08-01

Markdown files in this directory are the canonical project documentation.

| Document | Purpose |
|---|---|
| [Design](design.md) | Architecture, trust boundaries, data flow, policy model, report contract, and roadmap |
| [Operations](operations.md) | Native no-Docker preparation, isolated installation, scanning, GitHub publication, and troubleshooting |
| [Configuration](configuration.md) | TOML schema, profiles, policy layering, CLI flags, and exit codes |
| [Compatibility and coverage matrix](compatibility-matrix.md) | Tool roles, overlap, applicability, platform support, limitations, and acquisition |
| [Tool selection](tool-selection.md) | Admission criteria, added tools, rejected candidates, and review cadence |
| [Production security gate](production-security.md) | Strict release profile, residual risk, and companion dynamic and artifact controls |
| [Offline companion assurance](companion-assurance.md) | Property tests, fuzzing, API/DAST, threat modeling, reproducibility, provenance, and malware evidence |
| [Security Passport and risk intelligence](security-passport.md) | Signed release evidence, offline verification, KEV/EPSS/VEX enrichment, lifecycle baselines, and effectiveness metrics |
| [Project README](../README.md) | Concise introduction and quick-start paths |
| [Security policy](../SECURITY.md) | Private vulnerability reporting and supported-code policy |
| [Contributing](../CONTRIBUTING.md) | Trust-model constraints, validation, and pull-request expectations |
| [Changelog](../CHANGELOG.md) | Release-facing record of notable behavior and security changes |

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
- mypy 2.1.0
- Vulture 2.16
- Tach 0.35.0
- Flawfinder 2.0.20
- actionlint 1.7.12
- Hadolint 2.14.0
- Microsoft DevSkim CLI 1.0.70
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
- deptry 0.24.0
- diff-cover 10.2.0
- Checkov 3.2.494
- PSScriptAnalyzer 1.25.0
- ShellCheck 0.11.0
- Pyright 1.1.411 on Node.js 20.20.2
- Cosign 3.1.2

The current `comprehensive` profile selects all 62 adapters. The 2026-08-02
dogfood baseline completed all 35 applicable adapters; 27 conditional adapters
were correctly not applicable, with zero unavailable, failed, timed-out, or
parse-error tools. The externally isolated run correctly produced `FAIL`: two
high-severity Cosign findings block the intentionally unsigned wheel and source
distribution. No production source file remains below the 80% per-file coverage
threshold, and the repository-wide coverage gate passes with useful headroom.
Code security, secrets, dependency-vulnerability, architecture, and quality
perspectives were clean. No public signing service was contacted for this run.
The native `doctor` preflight reports 35 ready and 27 not-applicable tools with
zero disabled or unavailable prerequisites before scanner execution.

The checked report is in
`.artifacts/final-self-scan-v58`. It includes:

- the GitHub-ready Markdown, HTML, SARIF, SonarQube external-issue, and
  normalized JSON reports;
- a sanitized evidence record for each selected scanner;
- source and artifact CycloneDX SBOMs, including a frozen, offline, integrity-
  verified `uv.lock` export for source dependencies;
- `artifact-manifest.json` with SHA-256 bindings for both distributions;
- Pylint, Radon, coverage, and JUnit derived assurance summaries;
- target-bound finding lifecycle, live digest-pinned KEV/EPSS evidence,
  effectiveness metrics, SSDF claims, and a Security Passport;
- a checksum manifest that was independently verified after generation.

The source test suite currently records 274 passing tests and one platform-
limited symlink test skip. It includes property-test replay and fixtures for all
adapters, private scanner-home isolation, artifact digest binding, path-
traversal rejection during distribution expansion, hardened XML evidence
ingestion, archive-link rejection, governed risk acceptance, database
freshness, detection validation, repository-health additions, trusted-lane
evidence validation, and the SonarQube export. Combined line-and-branch
coverage is 91.94%, and branch coverage is 84.43%, so both measures pass the
80% policy threshold. No production source file remains below the per-file
coverage reporting threshold.

The companion detection proof is in
`.artifacts/detection-validation-v7`; its summary confirms six normalized
findings across Bandit, Semgrep, and detect-secrets, with required attribution,
classification, location, citations, impact, and remediation, 100% expected-
perspective recall, and zero findings on the safe negative control.
