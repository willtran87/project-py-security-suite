# Changelog

All notable changes are documented here. The project follows semantic versioning
for published releases.

## Unreleased

- Raised combined statement-and-branch coverage above the enforced 80% gate
  with fail-closed tests for CodeQL, CycloneDX, Security Passport integrity,
  portfolio adapters, and passive test-evidence parsing.
- Expanded the suite to 252 passing tests while preserving actionable per-file
  coverage reporting in consolidated reports.
- Resolved four consecutive reports' lowest-coverage files, raised combined
  line-and-branch coverage to 91.19%, and added runtime-guard coverage for
  offline linters, staging, Pysa, Trivy, Cosign, artifact scanners, passive
  evidence adapters, cross-tool finding correlation, offline databases,
  applicability decisions, malformed evidence, temporary-file cleanup, SARIF
  normalization, license metadata, complexity, and repository inventory.
- Clarified Security Passport verification output by separating integrity,
  authenticity, source-report verification, policy outcome, and release
  approval while retaining the original machine-readable policy field.
- Added concise `pysec verify --format text` output with explicit release
  blockers; JSON remains the backward-compatible default.
- Corrected Grype freshness preflight to read its authoritative internal
  `db_metadata.build_timestamp` instead of the later filesystem modification
  time, preventing a stale cache from failing only after scanner execution.
- Reworked Markdown triage so the scan-policy disposition, blocking findings,
  and applicable scanner execution gaps appear first; conditional controls
  remain fully auditable in a collapsed informational section.
- Split summary rendering into focused report sections, keeping the public
  artifact contract stable while reducing `render_summary` from Radon rank E
  during dogfooding to rank A in the final implementation.

### Added

- Offline-first orchestration for 62 governed security, supply-chain, quality,
  architecture, test-assurance, repository-health, and artifact perspectives.
- Consolidated Markdown, HTML, SARIF, SonarQube, JSON, SBOM, evidence, checksum,
  lifecycle, intelligence, effectiveness, and assurance-claim artifacts.
- Digest-pinned KEV, EPSS, VEX, baseline, risk-acceptance, and scanner inputs.
- In-toto/SLSA Security Passports with Cosign 2 detached signing, explicitly
  authorized Cosign 3 bundle signing, and local verification.
- `doctor`, `inspect`, `verify-report`, `attest`, and `verify` operator commands.
- Complete source distributions containing governance, schemas, operational
  scripts, examples, locked companion metadata, and test sources.

### Security

- Target and scanner before/after integrity checks, bounded output and parsing,
  path and symlink defenses, sanitized diagnostics, secret-context redaction,
  fail-closed configuration layering, and external-isolation attestation.
- Cosign 3 signing fails closed unless network-capable signing is explicitly
  acknowledged; signing configurations can be pinned to an approved service.
- Security Passport publication is failure-atomic: signing failures preserve
  existing evidence and discard incomplete staging directories.

### Performance

- Maintained-file discovery prunes generated and tool-owned directories before
  traversal, materially reducing comprehensive preflight and scan duration.
