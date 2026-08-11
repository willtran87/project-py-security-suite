# Changelog

All notable changes are documented here. The project follows semantic versioning
for published releases.

## Unreleased

- Version portfolio health at 1.1 with separate execution, observed-risk,
  evidence, and release grades. Conditional controls now carry deterministic
  owner-routed activation recipes in JSON, Markdown, and offline HTML, backed
  by one shared readiness classifier so preflight and reports cannot drift.
- Validate the rolling OSV PyPI archive before bundling with bounded size,
  path, CRC, JSON, unique-ID, affected-record, and timestamp checks; emit a
  compact connected-lane validation receipt.
- Seal `source-inventory.json` with every source path, size, and SHA-256;
  path-based clean effectiveness labels must now exist in that unchanged,
  aggregate-bound inventory instead of passing on an invented filename.
  Independent report verification now also rejects malformed, non-canonical,
  unsorted, duplicate, aggregate-mismatched, or manifest-unbound inventories.
- Expand the retained behavioral qualification to 10 reviewed labels across
  Bandit, Semgrep, and detect-secrets (7 TP, 3 TN, no FP/FN) with exact current
  executable-digest continuity.
- Dogfood the final candidate with all 36 applicable controls completed and no
  unavailable/failed scanner; six newly exposed implementation findings were
  corrected, leaving only the two expected unsigned-distribution findings.
- Repair the pinned Actionlint Windows bundle asset name (`windows_amd64`),
  retaining exact SHA-256 verification and fail-closed connected preparation.
- Include hidden files in native-bundle inventory generation so PowerShell
  Gallery metadata participates in the exact closed-set transfer contract.

- Add `verify-native-bundle` with independent manifest-digest binding,
  closed-set file verification, link and path defenses, bounded wheel/CRC
  inspection, and optional fail-closed `pip --isolated --no-index` resolution
  for every schema 2.0 Python environment. Native installation now rejects
  injected files, links, size changes, and case-insensitive path collisions.
- Upgrade `qualify-bundle` to schema 1.1 so a digest-bound labeled-corpus
  evaluation and its verified source report can enforce minimum labels, named
  tools, required perspectives, and exact unchanged scanner-digest continuity
  in the same decision without claiming that qualification reran scanners or
  granted release authority.

- Add relocatable, traversal-safe `@bundle/...` configuration paths; generate
  portable native scanner configurations; add a non-mutating, schema-governed
  `provision-plan`; and separate source, test, dependency, artifact, and
  governance admission decisions in JSON, Markdown, and offline HTML reports.
- Add `adapter-check`, a strict non-executing 63-adapter SDK qualification
  receipt, and `generate-ci`, a no-install GitHub workflow generator that
  requires immutable action pins and an explicit enterprise isolation check.
- Add `qualify-bundle` to join adapter contracts with target-specific readiness
  and executable identity, `config-check` for tolerant schema/portability advice,
  and `generate-hooks` for local non-executing pre-commit diagnostics. All three
  emit strict, non-authoritative contracts and perform no acquisition.
- Add `pysec init` with safe library, API, CLI, worker, and monorepo templates;
  version doctor readiness at 1.1 with ordered actions, explain mode, and atomic
  JSON or GitHub-ready Markdown publication. Activation-free module invocation
  now discovers console scripts beside its interpreter before declaring them
  unavailable, while retaining executable integrity checks. Equivalent
  prerequisites are grouped into root-cause remediation batches without
  dropping per-control reasons, and top-level help now leads operators through
  initialize, preflight, scan, and inspect.
- Consolidate semantically equivalent finding remediation into one owner-routed
  action without losing finding or artifact evidence. Promotion Markdown and
  HTML now surface priority, action ID, authority, target date, evidence
  subjects, and safely encoded suggested commands.
- Add atomic `evidence-pack` and `verify-evidence-pack` workflows that compose
  verified decision, lifecycle, audience, annotation, policy, release-manifest,
  and audit artifacts into one portable closed directory. Optional previous
  reports add trend/reachability context; optional distributions add an exact
  controlled-signing handoff; optional configuration adds value-redacted,
  profile-matched provenance. Approved effectiveness and Passport receipts now
  flow through release readiness and become required release-manifest/audit
  evidence; historical performance thresholds flow into the retained trend.
- Add durable finding lifecycle/SLA registers, verified GitHub annotations,
  audience-specific promotion exports, value-redacted configuration provenance,
  absolute scanner performance budgets, multi-scenario coverage union, and
  cross-repository portfolio aggregation.
- Add deterministic portable audit packages whose verifier rechecks every file,
  every evidence digest, and the embedded sealed report after relocation.

- Add locally verified VCS ancestry to production/release finding baselines and
  `baseline-candidate` for exact-digest external approval handoff.
- Version release readiness at 1.2 with causal root/derived blocker hierarchy,
  eliminating umbrella policy failures from the actionable root count.
- Add `trend` for longitudinal comparison of 2-100 sealed reports and
  `release-manifest` for a closed, digest-bound release evidence index.
- Add GitHub-ready Markdown and standalone offline HTML promotion views, plus
  digest-grouped scanner identity review in governance evidence drafts.
- Add exact-set, checksum-bound `prepare-signing` and
  `verify-signing-request` handoffs so a controlled signer receives precisely
  the distributions scanned, with no private key entering the scan lane.
- Add `promotion-plan`, a non-authoritative consolidated view of lifecycle
  state, assurance-claim closure, evidence quality, scanner reliability,
  conditional domains, retention, artifact relationships, audience views, and
  prioritized actions.
- Reject incomparable finding baselines when profiles or selected scanner sets
  differ; findings become `unclassified` instead of being mislabeled as new.
- Require known versions for applicable production scanners and parse Cosign's
  machine-readable version output.
- Let release policy require positive and negative effectiveness labels, a
  minimum perspective count, named scanners, and minimum labels per scanner.
- Remove the redundant generic scan-policy action when specific failed controls
  already explain the release block.
- Distinguish digest matching from organization authorization for every primary
  and auxiliary scanner entry point; repository-local pins no longer satisfy
  the release trust gate.
- Version release readiness at 1.1 with prioritized, owner-routed remediation
  actions grouped by repository, signing, organization-security, approver, and
  cross-functional authority.
- Add `evidence-draft`, a checksum-bound but explicitly non-authoritative handoff
  of scanner identities, intelligence snapshots, isolation bindings, and exact
  artifacts requiring controlled signing.
- Add organization-authorized, digest-bound isolation and offline-intelligence
  receipts; production and release fail closed when required authority is absent.
- Add `release-check`, a unified decision over report integrity, policy,
  findings, claims, operational coverage, isolation, scanner trust,
  intelligence approval, effectiveness, and Passport verification.
- Add digest-bound `reachability-diff` gating for new disconnected code, state
  regressions, new reportable islands, and lost runtime observations.
- Add atomic JSON receipt output to `pysec verify` and strict offline schemas for
  all new governed sidecars.
- Make Markdown and HTML summaries distinguish operational coverage, scan policy,
  and release readiness, with the first evidence gap as the next action.

- Add process-tree termination on timeout and interruption so scanner children
  do not survive aborted scans.
- Add digest-bound, expiring organization scanner-trust catalogs and retain all
  application decisions as sealed evidence.
- Add release distribution signing with per-artifact Sigstore bundles and a
  checksummed provenance manifest.
- Make SSDF assurance claims fail closed on provenance findings, stale governed
  context, security findings, and missing isolation attestations.
- Add verified, digest-bound labeled-corpus benchmarking with confusion-matrix,
  precision, recall, specificity, and F1 output.
- Add a 12-domain operational coverage scorecard to Markdown and JSON reports.
- Add per-island reachability confidence factors and stricter graph-output path
  validation; generated reachability documents now use schema 1.2.

- Add bounded offline Python reachability analysis with packaging, main,
  framework, and configured roots; three-state executable/load-only/disconnected
  classification; confidence-bearing direct, framework, callback, and polymorphic
  dispatch paths; optional bounded coverage.py corroboration; ranked module and
  symbol islands; state-appropriate normalized findings; and a sealed schema-1.2
  `reachability.json` graph artifact.
- Improve reachability precision with constructor lifecycle edges, concrete
  imported/local/chained receiver resolution, literal internal dynamic-import
  loading, statically false and `TYPE_CHECKING` branch pruning, WSGI/ASGI runtime
  roots, Django configuration and registration paths, and per-island evidence
  strength, removal readiness, blockers, and ordered actions.
- Parse Tach 0.35 violations from its native stderr stream and expand the
  dogfood architecture contract so every production module and dependency is
  explicit instead of silently treating an exit-code-1 run as clean.
- Restructure the documentation index around operator goals, add trust-boundary
  and coverage-flow Mermaid diagrams, condense the README capability summary,
  and refresh verified scanner, test, coverage, and self-scan evidence through
  2026-08-06.
- Version inspection and inspection-verification contracts at 1.3 with an
  exact action summary covering the requested limit, available actions,
  returned actions, omissions, and truncation; terminal inspection now makes
  bounded or summary-only views explicit instead of silently hiding work.
- Make P0-P4 the authoritative finding order across Markdown, HTML, action
  queues, terminal inspection, and inspection JSON, ensuring KEV and high-EPSS
  escalation cannot be displayed below lower-priority native severities; add
  concise decision context, summary, and impact to terminal actions.
- Version inspection and inspection-verification contracts at 1.2 while
  retaining the frozen 1.0 and 1.1 schemas; prioritized findings now expose
  priority, blocking decision, confidence, area, description, and impact in
  strict machine-readable output, and terminal triage displays the same
  priority.
- Add ownership-coverage metrics and priority-bucketed owner work queues to the
  action plan; consolidate risk, lifecycle, scanner attribution,
  classifications, and the first authoritative reference into a compact triage
  row without widening the table.
- Put finding ownership and the first authoritative citation directly in the
  action table, and include observed tool versions in digest-grouped scanner
  provenance batches so reviewers can assign and verify work without rebuilding
  context from other report files.
- Make the action plan bind artifact findings to full SHA-256 and byte-size
  identities, and group scanner approval candidates by executable digest so
  reviewers can perform one provenance decision before recording every affected
  policy binding.
- Version inspection and inspection-verification contracts at 1.1 while retaining
  the frozen 1.0 schemas for offline compatibility; prioritized machine-readable
  actions now carry validated artifact path, SHA-256, and byte-size identity and
  terminal inspection cites the same digest evidence.
- Bind Cosign findings directly to the affected distribution SHA-256 and byte
  size, render copy-ready artifact identity evidence in Markdown and HTML, and
  replace source-line guidance that was misleading for binary or repository-
  level findings.
- Close the Cosign missing-bundle integrity gap by rechecking the approved
  executable after its version probe even when no `verify-blob` command can run;
  an entry-point mutation now fails the scanner while retaining the provenance
  findings already collected.
- Make assurance-case status and next actions evidence-aware across clean,
  finding-bearing, incomplete, not-applicable, VCS, and externally generated
  dynamic-control states; include Cosign in artifact assurance and remove
  contradictory requests to regenerate already passing evidence.
- Make `verify-report` emit and atomically publish a strict, self-identifying
  report-verification receipt; bundle its version-explicit Draft 2020-12 schema
  for offline export and include the receipt in the GitHub artifact workflow.
- Add version-explicit `pysec schema` discovery and atomic export for both
  report-inspection contracts, allowing disconnected CI and policy engines to
  retrieve the exact installed Draft 2020-12 schemas without source-tree or
  network access and without silently replacing an existing contract.
- Promote scanner entry-point approval and post-execution integrity to
  first-class Markdown, HTML, terminal, and inspection-JSON summary metrics,
  with named and bounded trust-remediation actions, risk-ordered action-plan
  rows, provenance-gated copy-ready TOML approval candidates, and structured
  machine-actionable trust records with unique-digest review workload, governed
  by a strict self-identifying Draft 2020-12 JSON Schema and a safe atomic
  sidecar export that cannot alter the sealed source report; the GitHub Actions
  reference publishes that sidecar with the complete report, using portable
  artifact-relative links without runner workspace disclosure; offline
  verification recomputes and binds its exact semantics to the sealed report,
  then emits a separately schema-governed portable verification receipt.
- Emit stable, structured JSON errors for machine-readable CLI commands and
  redact, bound, and neutralize operator-facing error text.
- Reject undeclared wheel, sdist, or zip files beside governed release subjects
  during deployment-time Passport verification, cap hostile directory walks,
  and bound mismatch diagnostics.
- Require the detached Passport statement to exactly match the verified report's
  embedded statement and validate portable verification-material identity.
- Require deployment-time hashing of every declared release-artifact subject
  before a signed Security Passport can approve promotion.
- Bind the embedded Security Passport's exact, duplicate-free source and
  distribution subject set to the validated artifact manifest.
- Verify the embedded in-toto/SLSA Security Passport during report verification,
  require exact input coverage, and bind its source, policy, outcome, profile,
  scanner health, finding counts, and lifecycle evidence to the scan manifest.
- Validate every declared report artifact as a unique, present, normalized,
  in-report file or directory and reject ambiguous portable evidence paths.
- Require every canonical report artifact and exact scan-manifest binding during
  verification, and prevent derived evidence from shadowing reserved bindings.
- Serialize final report publication with an atomic sibling lock so concurrent
  publishers cannot race the verified rename and rollback window.
- Preserve the prior verified report throughout replacement generation and
  roll it back if atomic publication of the verified successor fails.
- Require a complete, checksum-verified canonical report before `--overwrite`
  may recursively replace a non-empty output directory.
- Reject symbolic links and Windows junctions in every governed path component
  inside the scan target, before path normalization can erase their identity.
- Extended governed path checks to passive artifact/provenance roots and reject
  linked wheel, sdist, or ZIP entries before artifact scanners consume them.
- Consolidated CLI, scan, doctor, report-output, and Security Passport path
  validation onto the shared path-safety primitives to prevent boundary drift.
- Closed the remaining CLI scan-target bypass by validating the requested target
  before resolution rather than passing an already-resolved path downstream.
- Added shared pre-resolution path validation for configuration, scanner assets,
  policy ledgers, finding baselines, and intelligence snapshots so governed
  repository-relative inputs cannot hide links or junctions during resolution.
- Rejected report, Passport, signing-key, password, signing-config, and public-key
  links or junctions before path resolution, and bounded untrusted evidence-tree
  traversal independently of checksum-manifest size.
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
