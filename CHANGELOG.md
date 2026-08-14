# Changelog

All notable changes are documented here. The project follows semantic versioning
for published releases.

## Unreleased

- Cross-reference redacted production-source secret candidates with retained
  sensitive-data sink routes when they share the exact sink file or the secret
  file occurs on the bounded Graphify route to the sink. The new bounded ledger
  preserves distance, current-tree/history alignment, verification, protection,
  validation, scanner assurance, owners, citations, and lane-specific closure
  actions in Markdown, HTML, SARIF, JSON schema, and finding evidence. Each
  intersection also carries a fail-closed validation handoff that joins
  Graphify-selected or route-mapped tests with exact retained execution,
  aggregate coverage, source-revision binding, scanner assurance, shared-test
  quality, findings, and ownership. Candidate tests never imply a canary
  assertion: reports explicitly require a synthetic credential canary. It never
  retains secret material or presents file-route proximity as symbol-level data
  flow, credential validity, runtime execution, or proof of disclosure.
- Add a bounded secret-provenance assessment ledger that cross-references every
  retained secret candidate with its source, graph, built-artifact, Git-history,
  scanner-assurance, verification, lifecycle, ownership, and redaction context.
  Markdown, HTML, SARIF, schemas, and closure work now provide lane-specific
  review actions for production source, tests, generated evidence, artifacts,
  and repository controls without retaining secret values, suppressing a
  finding, or treating test/generated context as proof of a false positive.
- Add a bounded end-to-end sensitive-data route ledger that joins confirmed
  exposure findings and review-worthy sink inventory to every retained entry
  point, runtime state, data class, trust boundary, observed protection,
  scanner assurance, validation status, lifecycle, and ownership handoff.
  Applicable CWE, OWASP, OpenTelemetry, and scanner citations now remain
  bounded and attributable through the ledger, Markdown/HTML finding context,
  SARIF, schemas, and closure criteria. Missing citation provenance becomes an
  explicit closure gap, while citations remain classification and remediation
  guidance rather than proof of attacker control, data flow, or disclosure.
- Cross-reference every review target with Graphify file membership, the sealed
  source inventory, built-artifact manifest, target kind, scanner, area, and
  path type before interpreting a missing Python entry-point route. Unrouted
  targets now distinguish actionable Python model gaps from artifact controls,
  generated evidence, validation code, and non-Python repository controls.
  Reports, finding/SARIF context, schemas, and closure work preserve the native
  evidence-lane action without dropping the finding or inventing an irrelevant
  Python entry point.
- Cross-reference shared validation-test hotspots with active findings in the
  exact test file and retained CODEOWNERS. Campaigns now grade shared-test
  evidence as strong, qualified, weak, or not established; carry finding/tool/
  severity and campaign-to-test owner alignment; and propagate quality gaps to
  review factors, owner queues, reports, and closure criteria. This expanded
  factor contract is versioned as `shared-control-review-v5`.
- Cross-reference each shared validation campaign with the exact contributing
  scanner posture of every retained route. Campaigns now retain assessed and
  missing route counts, trust/execution/perspective states, contributing and
  approved tools, evidence lanes, and a fail-closed prerequisite. Scanner trust,
  execution, or unresolved-route gaps raise transparent review factors, flow to
  owner queues and reports, and prevent passing tests from serving as closure
  evidence until the underlying route evidence is assured. The expanded factor
  contract is versioned as `shared-control-review-v4`.
- Require a valid producer-verified payload-binding receipt, not merely a
  matching declared source digest, before validation-campaign evidence is
  revision-aligned. Risk routes now distinguish mismatched, unverified,
  undeclared, and unavailable source identity; retain exact evidence payload
  digests and binding filenames; and propagate the state through review
  factors, owner queues, reports, schemas, and closure criteria. The changed
  factor contract is explicitly versioned as `shared-control-review-v3`.
- Join every retained entry, transit, and target file on a risk route to the
  bounded CODEOWNERS rule set, preserving exact path order. Reports now expose
  stable ownership handoffs, collaborating owners, unowned route segments,
  target-owner mismatches, owner coordination queues, and closure criteria.
  Missing ownership evidence remains distinct from evidence proving an unowned
  file. Alternate entry-path ordering is covered by adversarial tests.
- Cross-reference comparable finding lifecycle with exact route change scope,
  validation state, declared-entry runtime observations, owners, and scanner
  assurance. Routes, finding/SARIF evidence, Markdown/HTML, owner queues, and
  closure work now distinguish baseline-new/regressed changed-line work,
  modified pre-existing debt, and lifecycle evidence gaps. Missing,
  unconfigured, malformed, or incomparable baseline evidence fails closed and
  never turns a finding's default `new` value into a change-origin claim.
- Cross-reference every routed and unrouted target with the exact contributing
  scanner's execution, evidence lane, normalized/unique contribution, primary
  and helper integrity, before/after continuity, and organization approval.
  `effectiveness.json` 1.1 and its bundled schema now expose per-tool posture;
  risk routes separately report perspective, trust, execution, unassessed, and
  suite-derived states through findings, SARIF, Markdown/HTML, boundary/advisory
  intersections, owner queues, and closure criteria. The join does not alter
  native severity or treat tool approval as finding correctness.
- Clarify that every configured output from one test lane—including Cobertura
  XML used by diff-cover—must participate in the same source-binding operation,
  preventing an excluded evidence payload from creating a false revision
  mismatch between coverage, JUnit, and the sealed scan inventory.
- Add `risk-paths.json`, a bounded offline synthesis of declared reachability
  entry points, Graphify file relations, normalized findings, review-worthy
  sensitive-data sinks, runtime state, coverage, focused tests, structural
  risks, and CODEOWNERS. Stable routes and explicit unrouted model gaps flow
  back into finding JSON, Markdown, HTML, and SARIF with actionable validation
  steps and explicit aligned/gap/partial/not-assessed states, while
  interpretation remains conservative about exploitability and leakage.
  Cross-route convergence now identifies shared transit/target control points,
  consolidates validation work, and creates exact owner queues without merging
  or multiplying native findings. Each hotspot now produces a stable shared
  validation campaign by joining direct/transitive Graphify test selection,
  exact retained case execution, and hotspot file coverage. Campaigns bind
  control points and selected tests to the source inventory, distinguish
  aligned, mismatched, and unbound test/coverage revisions, and expose a
  factor-by-factor shared-control review score. Review model v2 cross-references
  structural change risk, exact uncovered changed lines, and runtime observation
  gaps, while failed-test factors cite only the retained execution artifacts.
  Cross-campaign validation-test hotspots now identify one source-bound test file
  selected for multiple shared controls, retain direct/transitive/context
  selection modes without double-counting JUnit cases, expose sole-test
  dependencies, and propagate stable IDs into routes, findings, SARIF, owner
  queues, reports, and closure criteria.
  Alias-aware dependency advisories now become bounded importer targets by
  joining evidence-fusion clusters to exact Graphify source importers and
  declared entry points. Citation-bearing routes retain package lineage,
  KEV/EPSS/VEX context, scanner-attributed fixed versions, path-specific
  runtime/coverage, owners, focused tests, validation, and closure actions;
  they link back to every native cluster finding without multiplying findings
  and explicitly do not claim vulnerable-function invocation or exploitability.
  A bounded per-importer assessment ledger prevents one importer's passing tests,
  ownership, or coverage from masking a validation gap at another importer.
  Exact-path exposure/advisory intersections now connect a sensitive SDK sink
  route to the same package/advisory importer route, retaining trust boundary,
  data class, protection, threat, validation, owner, citation, report, SARIF,
  and closure context without claiming disclosure or vulnerable-function use.
  Advisory importer routes now cross-reference source and built-artifact SBOM
  package lineage. Comparable inventories distinguish matched versions, drift,
  source-only, and artifact-only components; missing inventories fail closed as
  evidence gaps. Reports and closure work retain exact versions and exact-match
  fixed-version evidence without inferring semantic-version safety.
  Risk routes now retain a bounded exposure matrix for every declared entry
  point that Graphify can connect to the same target. Stable exposure IDs,
  exact file/edge sequences, entry kinds, omissions, owner-queue counts,
  finding/SARIF context, and interface-aware closure criteria preserve attack-
  surface breadth without multiplying findings or claiming runtime exposure.
  Each exposure now joins its exact declared reachability target node and
  distinguishes observed, unobserved, and unavailable runtime evidence.
  Interface-specific runtime gaps flow into intersections, owner queues,
  reports, SARIF, and closure criteria without treating non-observation as
  proof that an interface is dead or inaccessible.
  Campaign IDs, scores, revision state, evidence gaps, and actions propagate
  through findings, SARIF, reports, owner queues, and closure work. Add
  `pysec-evidence bind` to atomically create
  payload-verified source-binding sidecars for coverage and JUnit evidence.
  Bundle and document the version 1.0 schema.
- Version promotion plans at 1.2 and cross-reference sealed closure-plan 1.2
  validation work with optional digest-bound operational-trend 1.3 evidence.
  Promotion now fails closed on current validation debt or blocking validation
  regressions, preserves stable CODEOWNER work queues and exact closure
  references, and surfaces concise trajectory, owner, action, anomaly, and
  evidence-binding views for developers, security, release engineering,
  executives, and auditors. Evidence packs build trend evidence before
  promotion, retain a readable trend Markdown artifact, and bind the trend's
  latest snapshot to the exact promoted report.
- Version operational trend at 1.3 and require both a current closure ledger and
  retained diff-coverage change-assessment scope before claiming validation
  subjects are new or resolved. Missing assessment scope now produces an
  explicit comparability reason and anomaly; owner deltas become unavailable
  instead of falsely reporting debt resolution. Release readiness and promotion
  apply the same fail-closed rule, so an empty closure queue without retained
  change scope cannot approve a candidate.
- Give Graphify JSON files a bounded 64 MiB adapter allowance while retaining
  the generic scanner-stream cap for stdout and stderr. This prevents healthy
  medium-sized AST graphs from becoming parse errors without relaxing node,
  edge, path, origin, token, or report-artifact validation.
- Cross-reference structural change impacts, graph-selected tests, case-level
  execution, changed-line coverage, whole-file coverage, and retained
  CODEOWNERS rules into one stable owned closure item per changed file. Closure
  plan 1.2 consolidates overlapping coverage work, cites exact uncovered lines
  and tests, and defines evidence-based acceptance criteria. `release-check`
  now fails closed on missing current closure evidence or unresolved validation
  mismatches and preserves those owners and citations in causal remediation.
  Omitted change-impact details become an explicit P1 completeness item rather
  than silently passing a large change at the bounded artifact limit. Release
  actions cite the closure item plus a compact decisive evidence set while the
  full test ledger remains available in the sealed closure plan. Native
  Coverage/diff-cover observations for the same file are folded into that work
  item with their finding IDs and scanner attribution, while `findings.json`
  remains unchanged.
- Add owner/evidence-condition rollups above the detailed closure ledger and
  version release readiness at 1.3. File-level validation subjects remain exact
  in `closure-plan.json`, while release remediation groups only subjects with
  identical owner, priority, authority, action, and blocker. Stable group IDs,
  explicit group/subject totals, and closure-item-first evidence preserve
  causality while reducing repetitive production actions.
- Version operational trend at 1.2 and join each independently verified
  closure-plan 1.2 ledger into longitudinal repository health. Stable validation
  subjects now expose new/resolved/unchanged debt, state/priority/owner/routing
  transitions, owner-queue history, first-to-latest deltas, and adjacent-scan
  anomalies for debt growth, ownership erosion, failing-test regression, or
  missing comparable evidence. Missing closure evidence is never interpreted as
  zero validation debt.
  `pysec trend --format markdown` renders bounded GitHub tables for movement,
  validation continuity, owner queues, state/routing transitions, anomalies,
  scanner reliability, and the verified timeline; terminal output degrades
  unsupported glyphs safely while the UTF-8 artifact remains intact.
- Version evidence fusion at 1.2 and sensitive-data exposure synthesis at 1.4.
  Passive JUnit, Hypothesis, and Schemathesis ingestion now retains a bounded,
  output-free case/file/result ledger. Advisory remediation cross-references
  Graphify-selected focused tests with exact current execution evidence and
  reports passing, failing, incomplete, unobserved, unavailable, and unselected
  states without treating aggregate green totals or pre-remediation passes as
  future-build validation. Closure and release-readiness actions retain the
  contributing test-evidence artifacts. CycloneDX dependency relationships now
  identify bounded introducing-root paths for transitive advisories, while
  pipdeptree environment-health evidence qualifies path confidence and exposes
  missing, cyclic, or conflicting installed dependencies. Bounded CODEOWNERS rule metadata now
  routes exact advisory import paths even when those files have no separate
  normalized finding; prior schemas remain bundled.
- Cross-reference Graphify-selected tests with bounded JUnit, Hypothesis, and
  Schemathesis case execution plus diff/file coverage. Structural synthesis 1.2
  now distinguishes aligned, failing, incomplete, unobserved, unavailable, and
  unselected validation evidence for changed files. Evidence fusion 1.3 and
  data exposure 1.5 explicitly flag the contradiction where focused tests pass
  while affected changed lines or dependency import paths remain uncovered.
- Consolidate scanner-reported fixed versions, approved offline CISA KEV/FIRST
  EPSS/CycloneDX VEX intelligence, alias-aware advisories, source dependency
  relationship, exact imports, reachability, runtime observations, and deptry
  signals into one conservative remediation context per distinct advisory.
  Reports now show P0-P4 priority, action kind, scanner-attributed fixed-version
  candidates, evidence basis, uncertainties, and verification steps. VEX
  bounded/resolved states require scope and provenance validation and never
  suppress the native finding automatically. SDK disclosure-boundary reports
  surface the same decisions and dedicated summary counters.
- Join advisory import paths to reverse Graphify test dependencies, retained
  file coverage, and CODEOWNERS-derived finding ownership. Remediation records
  now name focused direct/transitive tests, selection confidence, responsible
  owners, and import paths below 80% coverage. Closure planning uses the stable
  advisory cluster ID to create one owned work item across alias-equivalent
  scanner observations while retaining all finding IDs, tools, citations,
  uncertainties, and acceptance evidence. Version closure-plan output at 1.1
  with distinct-advisory/observation counters and retain schema 1.0. Release
  readiness now performs the same advisory-ID consolidation and carries fused
  priority, ownership, import paths, and focused tests into its operational
  remediation actions.
- Version evidence fusion at 1.1 with package-scoped, transitive advisory-alias
  clustering. CVE, GHSA, PYSEC, and OSV identifiers can now converge across
  OSV-Scanner, Grype, and other normalized package findings while retaining
  every native scanner source. Reports distinguish distinct actionable
  advisories from alias-equivalent observations and feed that cleaner count,
  canonical identifiers, tools, versions, and citations into SDK disclosure
  review. Retain the evidence-fusion 1.0 schema for existing consumers.
- Cross-reference distinct package advisories with CycloneDX direct/transitive
  relationships, exact Graphify external-import edges, importing-file
  reachability/runtime state, and deptry declaration findings. Report
  executable, load-only, disconnected, incomplete, unused, and contradictory
  use evidence without changing severity or claiming vulnerable-function
  exploitability.
- Treat OSV-Scanner exit code `1` as a completed scan with vulnerabilities,
  preserving its valid offline JSON findings for normalization, policy, and
  SDK/data-exposure correlation instead of misreporting the required scanner as
  failed.
- Version sensitive-data exposure synthesis at 1.3 and close the evidence loop:
  finalized fusion tiers, corroboration, changed-line coverage, runtime and
  reachability state, graph blast radius, and related findings now flow back
  into exposure assessments and portable reports. Cross-reference inventory-only
  sink surfaces with changed-line, coverage, reachability, runtime, graph, and
  nearby-finding evidence so reviewers can prioritize unconfirmed disclosure
  controls without treating them as vulnerabilities. Join CODEOWNERS-derived
  ownership, graph-selected tests, structural hotspot IDs, and change-risk
  scores into both confirmed findings and review surfaces. Correlate disclosure
  SDKs with normalized package findings and finalized source/artifact lineage,
  retaining advisory citations and distinguishing matched lineage from package
  risk. Generate bounded contextual verification plans without changing scanner
  severity; retain schemas 1.2, 1.1, and 1.0 for existing consumers.
- Version sensitive-data exposure synthesis at 1.2 with local alias propagation,
  credential/personal/financial/health/request-content context, trust-boundary
  and risk-factor evidence, explicit protection kinds, and prioritized review
  surfaces. Add scanner-backed detection for secrets interpolated into outbound
  URLs and broad runtime or environment state exported to telemetry; retain 1.1
  and 1.0 schemas for existing consumers.
- Add CWE-532/200/201/209/359/598 sensitive-data rules for logging, telemetry,
  request collections, URL queries, raw client errors, and risky Sentry PII
  configuration. Expand the non-executing SDK/sink inventory with custom and
  bound loggers, process streams, OpenTelemetry header capture, and additional
  observability SDKs; strengthen transformation handling so generic hashes,
  masks, filters, HMACs, and tokens no longer suppress taint by name alone.
- Harden sensitive-data detection with credential-named object/dictionary
  sources, runtime-state dump detection, additional tracing SDK sinks, precise
  request-versus-response payload modeling, recursive monorepo dependency
  discovery, and bounded `.env`/TOML/YAML/INI capture-configuration review.
  Add OpenTelemetry GenAI content-capture and wildcard HTTP-header controls,
  expand cloud and GenAI observability SDK coverage, and version the exposure
  artifact at 1.1 while retaining schema 1.0 for existing consumers.

- Add pinned Graphify code-only scanning, strict AST/token/path validation,
  normalized graph evidence, and graph-aware finding blast radius, structural
  hotspots, and cross-tool neighborhoods.
- Add bounded cross-tool evidence fusion across semantic classifications,
  changed-line coverage, reachability, runtime observations, graph centrality,
  complexity, source/artifact SBOMs, and artifact manifests. Findings now carry
  explicit review tiers and cross-stage lineage without changing severity.
- Add structural synthesis across Graphify, reachability, Vulture, runtime
  coverage, Radon, Tach, ownership, and normalized findings. Reports now
  distinguish likely removable from likely dynamic dead-code candidates,
  classify latent attack-surface and missing-entry-point islands, and correlate
  import cycles with architecture and security findings.
- Version structural synthesis at 1.1 with graph-guided direct/transitive test
  targeting, compound changed-file risk scoring, conservative orphan-symbol
  discovery, and concrete island boundary evidence that distinguishes test-only
  fixtures from probable missing production entry points. Schema 1.0 remains
  available for existing consumers.

- Add a verified, machine-readable closure plan that turns findings, governance
  gaps, conditional controls, coverage hotspots, and reachability warnings into
  stable owner-routed actions with acceptance criteria and evidence references.
- Add closed-set reproducible-build comparison and deterministic Python sdist
  normalization. Comparison rejects self-comparison, emits scanner-consumable
  mismatch findings, and preserves the external boundary for independent build
  provenance.
- Publish a 52-item findings-driven enhancement register, wire the closure plan
  into every report, and document the activation, ownership, and authority
  boundary for controls that cannot be honestly completed inside one repository.
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
