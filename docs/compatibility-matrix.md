# Python Security Suite compatibility and coverage matrix

Last reviewed: 2026-07-23

See the [documentation index](index.md), [solution design](design.md), and
[operations guide](operations.md) for the surrounding architecture.

## Meaning of support

`Adapter implemented` means the suite can construct an offline-oriented
command, normalize the documented output, attribute findings, and report tool
health. It does not mean every binary is shipped in the Windows standard
bundle. Enterprise approval, platform compatibility, licenses, local data, and
query or model bundles remain deployment responsibilities.

Conditional tools report `not applicable` when their input does not exist.
This is distinct from `unavailable`, which means relevant analysis could not be
performed.

## Portfolio

| Tool | Primary perspective | Isolation behavior | Profile placement | Adapter |
|---|---|---|---|---:|
| Bandit | Python AST security patterns | Local source only | quick, standard, all broader profiles | Yes |
| Semgrep CE | Organization-defined structural Python rules | Local immutable rules; metrics and version checks disabled | standard and broader | Yes |
| detect-secrets | Credential-shaped and high-entropy values | Online verification disabled; values never retained | quick, standard, broader | Yes |
| OSV-Scanner | Known vulnerable dependencies | Local OSV snapshot, offline mode, no resolution | standard and broader | Yes |
| CycloneDX Python | Reproducible Python SBOM evidence | Reads supported local lock or pinned requirement data | extended and broader | Yes |
| Ruff `S` | Independent, fast Python security AST checks | `--isolated`, no cache, local source only | extended and broader | Yes |
| zizmor | GitHub Actions, composite-action, and Dependabot risks | Explicit `--offline`; SARIF output | extended and broader when GitHub files exist | Yes |
| Pysa / Pyre | Interprocedural Python source-to-sink taint | Local code, configuration, models, and stubs | deep, comprehensive, and production | Yes |
| Trivy | IaC, deployment configuration, and license policy | Offline scan; DB, check, VEX, version, and telemetry updates disabled | supply-chain and comprehensive | Yes |
| GuardDog | Malicious Python package and source heuristics | Local target only; GuardDog's own sandbox remains enabled | supply-chain and comprehensive | Yes |
| ScanCode Toolkit | License, origin, and package-metadata inventory | Local rules and files; no target execution | supply-chain and comprehensive | Yes |
| Gitleaks | Current-tree, archive, and Git-history secrets | Local Git or directory mode; 100% secret redaction | supply-chain and broader | Yes |
| TruffleHog | Independent credential detectors | Filesystem mode; verification and update checks disabled; raw values discarded | supply-chain and broader | Yes |
| CodeQL through `run-codeql` | Deep semantic and data-flow queries | Pre-staged local CLI and packs; auto-download rejected; temporary source mirror | deep, comprehensive, production, release | Yes |
| Syft | Final-distribution component SBOM | Local `dist` input; update checks disabled | artifact, comprehensive, release | Yes |
| Grype | Final-distribution vulnerabilities | Local `dist` input and staged database; auto-update disabled | artifact, comprehensive, release | Yes |
| check-wheel-contents | Wheel structure and inclusion mistakes | Local wheels only; repository config disabled | artifact, comprehensive, release | Yes |
| Twine | Distribution metadata and description validity | `twine check --strict`; no publication or index access | artifact, comprehensive, release | Yes |
| PyPI attestations | Distribution digest and Trusted Publisher provenance | Local distribution and provenance object; `--offline` verification | artifact, comprehensive, release | Yes |

## Coverage comparison

Legend: **P** primary, **S** secondary, **E** evidence producer, **C**
conditional, and `-` not intended.

| Capability | Bandit | Semgrep | detect-secrets | OSV | CycloneDX | Ruff | zizmor | Pysa | Trivy | GuardDog | ScanCode | Gitleaks | TruffleHog | CodeQL |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| Python AST patterns | P | S | - | - | - | S | - | - | - | S | - | - | - | S |
| Custom enterprise rules | C | P | C | - | - | C | C | P | C | C | C | C | C | P |
| Cross-file data flow | - | C | - | - | - | - | - | P | - | - | - | - | - | P |
| Working-tree secrets | S | C | P | - | - | S | - | - | - | - | - | P | P | C |
| Git-history secrets | - | - | - | - | - | - | - | - | - | - | - | P | C | - |
| Vulnerable dependencies | - | - | - | P | E | - | - | - | - | - | C | - | - | C |
| SBOM / component evidence | - | - | - | C | P | - | - | - | C | - | P | - | - | - |
| Malicious-package behavior | - | C | - | - | - | - | - | - | - | P | - | - | C | C |
| GitHub workflow security | - | C | - | - | - | - | P | - | C | - | - | - | - | C |
| IaC / deployment security | - | C | - | - | - | - | - | - | P | - | - | - | - | C |
| License governance | - | - | - | - | E | - | - | - | P | - | P | - | - | - |

Overlap is intentional, but correlated observations do not become multiple
risk votes. Ruff begins as an independent comparison perspective alongside
Bandit. Trivy is restricted to `misconfig,license` so it does not duplicate
OSV-Scanner and the dedicated secret scanners. TruffleHog adds detector
diversity but never verifies credentials over the network.

Artifact controls are intentionally conditional:

| Capability | Syft | Grype | Wheel contents | Twine | PyPI attestations |
|---|:---:|:---:|:---:|:---:|:---:|
| Final artifact inventory | P | S | E | E | E |
| Artifact vulnerabilities | C | P | - | - | - |
| Wheel structure/content | C | - | P | - | - |
| Publication metadata | - | - | C | P | - |
| Publisher identity and digest | - | - | - | - | P |
| Offline operation | P | P | P | P | P |

## Platform and acquisition compatibility

| Tool | Windows native | Linux native | macOS native | Acquisition notes |
|---|---:|---:|---:|---|
| Suite, Bandit, detect-secrets, CycloneDX | Yes | Yes | Yes | Approved Python wheelhouse |
| Semgrep | Yes | Yes | Yes | Platform wheel or approved binary |
| OSV-Scanner | Yes | Yes | Yes | Release binary plus local advisory snapshot |
| Ruff | Yes | Yes | Yes | Platform wheel or standalone binary |
| zizmor | Yes | Yes | Yes | Platform wheel or standalone binary |
| Pysa / Pyre | No supported native Windows workflow; use WSL | Yes | Yes | Python package plus organization models |
| Trivy | Yes | Yes | Yes | Standalone binary; optionally pre-stage cache/check assets |
| GuardDog 3.x | Upstream sandbox dependency limits native Windows | Yes | Yes | Python wheelhouse; scan only local inputs in the secure lane |
| ScanCode Toolkit | Yes with compatible Python/platform wheels | Yes | Yes | Separate sidecar environment, large wheel closure, and substantially longer runtime |
| Gitleaks | Yes | Yes | Yes | Standalone binary |
| TruffleHog | Yes | Yes | Yes | Standalone binary; verification is forcibly disabled |
| CodeQL through `run-codeql` | Yes | Yes | Yes | `run-codeql` wheel plus approved CodeQL bundle, local packs, isolated home, and applicable GitHub license |
| Syft and Grype | Yes | Yes | Yes | Standalone binaries; Grype additionally needs a staged vulnerability database |
| check-wheel-contents, Twine, PyPI attestations | Yes | Yes | Yes | Approved Python wheelhouse; provenance files, offline trust cache, and expected publisher identity are release inputs |

The Windows native bundle script now pins and downloads Bandit, Semgrep,
detect-secrets, Ruff, CycloneDX Python, zizmor, ScanCode, and the suite from
Python wheels, including `run-codeql`, check-wheel-contents, Twine, and
`pypi-attestations`. It also includes OSV-Scanner and its PyPI advisory
snapshot, Trivy, Gitleaks, Syft, Grype with a connected-lane database snapshot,
and TruffleHog. The licensed CodeQL CLI and packs, Pysa, and current GuardDog
still require separately approved assets or a compatible native runner.

No Docker image is required for any suite adapter.

## Applicability

| Tool | Reported `not applicable` when |
|---|---|
| CycloneDX Python | No Poetry lock, Pipenv lock, or pinned requirements input exists |
| zizmor | No workflow, composite action, or Dependabot configuration exists |
| Pysa | No Python source or repository Pyre/Pysa configuration exists |
| Trivy | No supported deployment, dependency, or license input exists |
| GuardDog | Native Windows is in use, or no Python source/package content exists |
| CodeQL | No Python source exists |
| Syft, Grype, Twine, PyPI attestations | No built wheel or source distribution exists under `artifacts_path` |
| check-wheel-contents | No built wheel exists under `artifacts_path` |

Other selected tools are generally applicable to any non-empty Python
repository. A pre-staged CodeQL CLI, isolated home, and Python query pack are
prerequisites, not applicability tests. Missing approved assets make a required
deep scan `INCOMPLETE`; `run-codeql` is never permitted to download them.

## Report behavior

- CycloneDX produces `sbom.cdx.json`.
- Syft safely expands wheels and source distributions into a bounded temporary
  tree, produces `artifact-sbom.cdx.json`, and produces
  `artifact-manifest.json` with the SHA-256 and size of every original
  distribution. Archive links, special files, path traversal, excessive
  member counts, and oversized expansion are rejected.
- Grype scans the same safely expanded artifact view against its staged local
  vulnerability database.
- ScanCode produces a compact `scancode-inventory.json`.
- ScanCode's aggregate role is bounded to package metadata, dependency locks,
  license/notice/readme files, and conventional vendored-source roots. It
  excludes generated/tool roots, scans a symlink-free staging directory with
  one local worker, caps per-file work at 120 seconds, and retains only files
  with findings. Use a separate full-tree ScanCode job when forensic
  copyright/origin due diligence is required.
- Gitleaks is invoked with full redaction, and the adapter discards `Secret`,
  `Match`, and source-line content.
- TruffleHog disables verification and updates, then discards `Raw`, `RawV2`,
  and all detected secret material.
- PyPI attestations emits high-severity normalized findings for missing,
  invalid, digest-mismatched, or publisher-mismatched provenance.
- GuardDog code snippets are not retained.
- Native SARIF from zizmor and CodeQL is normalized into the suite's combined
  SARIF rather than copied verbatim.
- The CodeQL adapter does not use `run-codeql --no-fail`; exit code 1 is
  interpreted as findings only when exactly one expected Python SARIF exists.
  Missing SARIF remains a failed or parse-error analysis.
- Every finding preserves tool, version, native rule, native severity,
  priority, classifications, location, impact, remediation, and citations.
- `action-plan.md` provides a compact finding-remediation table and a separate
  coverage-restoration table with official tool references.
- `assurance-case.md` records which control areas were verified, partially
  covered, not applicable, or require external release evidence.

## Deliberately excluded as core scanners

| Tool | Reason |
|---|---|
| pip-audit | Overlaps OSV-Scanner and lacks the same first-class preloaded advisory snapshot model for this isolation contract |
| Safety | Offline commercial data and licensing would add a separate entitlement/update dependency while overlapping OSV |
| Dlint | Mostly overlaps Bandit and Ruff; unique-rule value should be demonstrated before another AST gate is added |
| OpenSSF Scorecard | Repository-host metadata and API access conflict with the isolated execution lane |
| Hypothesis, Atheris, Schemathesis, OWASP ZAP | Recommended dynamic/property/fuzz/API controls; they execute target behavior and belong in a separate disposable sandbox |

## Primary references

- [Bandit documentation](https://bandit.readthedocs.io/)
- [Semgrep documentation](https://semgrep.dev/docs/)
- [detect-secrets](https://github.com/Yelp/detect-secrets)
- [OSV-Scanner offline mode](https://google.github.io/osv-scanner/usage/offline-mode/)
- [CycloneDX Python](https://cyclonedx-bom-tool.readthedocs.io/en/stable/)
- [Ruff security rules](https://docs.astral.sh/ruff/rules/#flake8-bandit-s)
- [zizmor usage](https://docs.zizmor.sh/usage/)
- [Pysa](https://pyre-check.org/docs/pysa-basics/)
- [Trivy air-gap guidance](https://trivy.dev/docs/latest/guide/advanced/air-gap/)
- [Trivy March 2026 security advisory](https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23)
- [GuardDog](https://github.com/DataDog/guarddog)
- [ScanCode Toolkit](https://scancode-toolkit.readthedocs.io/en/latest/)
- [Gitleaks](https://github.com/gitleaks/gitleaks)
- [run-codeql](https://pypi.org/project/run-codeql/)
- [CodeQL CLI](https://docs.github.com/en/code-security/concepts/code-scanning/codeql/codeql-cli)
- [Syft](https://github.com/anchore/syft)
- [Grype](https://github.com/anchore/grype)
- [TruffleHog detector configuration](https://trufflesecurity.com/docs/customizing-detection)
- [check-wheel-contents](https://github.com/jwodder/check-wheel-contents)
- [Twine check](https://twine.readthedocs.io/en/stable/#twine-check)
- [PyPI digital attestations](https://docs.pypi.org/attestations/)
