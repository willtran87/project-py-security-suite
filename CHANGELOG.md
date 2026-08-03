# Changelog

All notable changes are documented here. The project follows semantic versioning
for published releases.

## Unreleased

- Hardened report and Security Passport integrity verification to reject
  unchecksummed injected files; Passport publication now adds pre-resolution
  link and junction rejection, staged checksum read-back, validation of existing
  overwrite targets, collision-safe semantics, and failed-swap rollback.
- Corrected Diff Cover normalization so a file is reported only when its own
  changed-line coverage is below policy, eliminating false findings for files
  above the configured threshold that still have some uncovered lines.
- Made `pysec verify` fail closed for release automation: it now exits `0` only
  for an approved passport and exits `1` when integrity succeeds but signature,
  source-report, or scan-policy approval remains unsatisfied.
- Made report publication failure-atomic through private sibling staging,
  checksum-chain and manifest self-verification, and a final rename; corrected
  output-link validation to occur before path resolution and added
  publication-time link/collision checks.
- Hardened generated Markdown, HTML, and SARIF citation links with strict
  HTTP(S) parsing, host and port validation, credential rejection, bounded
  length, and control/Markdown-delimiter filtering.
- Hardened `pysec inspect` as an untrusted-report boundary: terminal-facing
  values are bounded and neutralize control/bidirectional characters, while
  citation links are restricted to well-formed HTTP(S) references.
- Added finding classifications, authoritative citations, and direct HTML
  evidence links to `pysec inspect`; action-plan finding IDs now deep-link to
  their full cited finding cards for faster GitHub artifact triage.
- Made `pysec doctor` decision-oriented: it now distinguishes preflight
  proceed/block from release approval, reports required/applicable readiness,
  labels optional attention without false blocking, and emits structured
  blocking reasons for CI consumers.
- Removed wall-clock deadlines from filesystem-backed security property tests
  while retaining generated examples and assertions, preventing cold Windows
  I/O from creating non-reproducible assurance failures.
- Raised combined statement-and-branch coverage above the enforced 80% gate
  with fail-closed tests for CodeQL, CycloneDX, Security Passport integrity,
  portfolio adapters, and passive test-evidence parsing.
- Expanded the suite to 258 passing tests while preserving actionable per-file
  coverage reporting in consolidated reports.
- Resolved four consecutive reports' lowest-coverage files, raised combined
  line-and-branch coverage to 91.64%, and added runtime-guard coverage for
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
- Strengthened `pysec inspect` with a checksum-backed scan-policy disposition,
  applicability-aware scanner accounting, policy reasons, and actionable
  finding ID, lifecycle, scanner-rule, owner, location, and remediation detail.
- Corrected terminal scanner health so an applicable disabled or skipped tool
  is an execution gap rather than being mislabeled as not applicable.
- Reused the typed `Outcome` model for inspection dispositions, eliminating a
  Bandit B105 false positive without adding a security suppression.
- Refined the self-contained HTML dashboard with an explicit decision badge, a
  balanced scanner-health grid, prominent execution-gap and applicability
  counts, and a collapsed audit table for conditional controls.
- Decomposed HTML report assembly from Radon rank D to rank A while preserving
  the offline single-file artifact and strict content-security policy.

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
