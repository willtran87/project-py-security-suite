# Python Security Suite design

Status: alpha foundation  
Last reviewed: 2026-08-31

## Purpose

Python Security Suite coordinates several complementary, locally installed
security scanners against Python projects. It normalizes their output into one
finding model, correlates overlapping observations, evaluates an explicit
policy, and writes a self-contained report suitable for humans, automation, and
GitHub artifacts.

The design prioritizes:

- operation inside an externally enforced, egress-denied enterprise boundary;
- no target imports, package installation, dependency resolution, or target
  code execution during a scan;
- independently useful Python code, secret, customizable rule, and dependency
  perspectives;
- deterministic local scanner assets and advisory data;
- honest `INCOMPLETE` results when required evidence or scanner health is
  missing; and
- concise reports that retain traceability to the originating tool, native
  rule, classification, location, version, and reference.

## System context

```mermaid
flowchart LR
    subgraph Connected["Approved connected update lane"]
        Prep["prepare-native-bundle.ps1"]
        Sources["Pinned tools and rules,<br/>OSV + Grype + KEV + EPSS + VEX snapshots"]
        ScorecardCollect["Authorized Scorecard collection<br/>bounded JSON evidence"]
        Bundle["Native bundle<br/>bundle-manifest.json + SHA-256"]
        Sources --> Prep --> Bundle
    end

    Transfer["Controlled artifact transfer"]

    subgraph Boundary["Enterprise egress-denied execution boundary"]
        Install["install-native-tools.ps1<br/>hash verification + pip --no-index"]
        Project["Python project<br/>read-only by policy"]
        Suite["Python Security Suite"]
        Scanners["89 governed adapters<br/>security | quality | testing | policy | architecture | supply chain | artifact | governance"]
        Analyzers["Native contextual analyzers<br/>framework | contract | validation | health | architecture | domain assurance"]
        Reports["Markdown | HTML | SARIF | SonarQube | JSON<br/>SBOM + validation + architecture + domain coverage + Security Passport"]
        Standards["635 versioned standards references + 215 assurance packs<br/>deterministic catalog export + verified source-manifest compiler<br/>66-item publisher quarantine + signed promotion"]
        Benchmarks["262 governed benchmark families + 192 maintained adapters<br/>application/identity/AI/safety/resilience/operations/calibration/repository truth<br/>repeated statistical fuzzing + temporal calibration<br/>exact equal-tail/mean statistics + full SLSA materials"]
        ExtensionEvidence["96 suite-owned semantic integrations<br/>strict JSON + source/subject binding<br/>ransomware/sanitization/OT/crisis/IEC-provider/risk/crosswalk/LNG-EV oracles<br/>independent replay + domain negative cases"]
        BenchmarkTrust["Root-signed external benchmark trust<br/>lifecycle-aware downstream receipt admission<br/>leased intent/checkpoint recovery<br/>HSM/KMS receipts + trusted-time rotation anchors"]
        AssuranceCase["ISO 15026 + SACM 2.3 assurance case<br/>claims + evidence + defeaters + confidence + review"]
        Priority["CVSS v4 + SSVC<br/>source evidence only"]
        OSCAL["OSCAL 1.2.2 lifecycle<br/>7 official-schema-valid models"]
        Contracts["Version-explicit JSON Schemas<br/>installed package resources"]
        Install --> Suite
        Project --> Suite
        Suite --> Scanners
        Scanners --> Suite
        Suite --> Analyzers
        Analyzers --> Suite
        Standards --> Suite
        Benchmarks --> ExtensionEvidence --> Suite
        BenchmarkTrust --> Benchmarks
        AssuranceCase --> Suite
        Suite --> Priority
        Suite --> OSCAL
        Suite --> Reports
        Suite --> Contracts
    end

    GitHub["GitHub artifact,<br/>workflow summary, and SARIF"]

    Bundle --> Transfer --> Install
    ScorecardCollect --> Transfer
    Reports --> GitHub
    Contracts --> GitHub
```

The adapter portfolio and the native contextual analyzers are different
layers. Adapters acquire or normalize independent tool and companion evidence;
native analyzers operate on the sealed source snapshot and retained artifacts.
`capability-manifest.json` records the former's selection and execution truth,
while the contextual artifacts state their own bounded inputs, parse errors,
and completeness.

Industry assurance is also layered deliberately. Stable publications enter the
versioned crosswalk; organization-selected profiles turn applicable references
into controls and procedures; maintained adapters define measurable evidence
contracts; and authorized disposable lanes execute adversarial or conformance
cases. A2A, CSP/SRI, TLP/IEP/VERIS, SESIP, DORA, FFIEC, C5, and FCC coverage
therefore does not imply certification or regulatory approval. Draft CSP3,
SRI2, Trusted Types, and BSI TR-03183 remain in the non-normative watchlist,
and the retired FFIEC CAT is excluded from current claims.

Enhanced benchmark execution is an explicit guarded transaction. Code cannot
skip or repeat a phase, and the replay transition is committed before any
untrusted stage runs.

```mermaid
stateDiagram-v2
    [*] --> Authorized
    Authorized --> ManifestAdmitted
    ManifestAdmitted --> TrustAdmitted
    TrustAdmitted --> EvidenceVerified
    EvidenceVerified --> ReplayCommitted
    ReplayCommitted --> StagesExecuted
    StagesExecuted --> InputsReverified
    InputsReverified --> Scored
    Scored --> ReceiptAssembled
    ReceiptAssembled --> ReceiptSigned: enhanced schema
    ReceiptAssembled --> Completed: legacy schema
    ReceiptSigned --> Completed
    Authorized --> Failed: admission or execution error
    ManifestAdmitted --> Failed: admission or execution error
    TrustAdmitted --> Failed: admission or execution error
    EvidenceVerified --> Failed: admission or execution error
    ReplayCommitted --> Failed: admission or execution error
    StagesExecuted --> Failed: admission or execution error
```

### Contextual analysis and validation

```mermaid
flowchart TB
    Source["Sealed source snapshot"] --> Frameworks["Framework model coverage<br/>models + positive/negative canaries"]
    Source --> Contracts["Application contracts<br/>code/OpenAPI/auth + exact advisory calls"]
    OpenAPI["OpenAPI + approved baseline"] --> Contracts
    ContractPolicy["Declared endpoint/test obligations"] --> Contracts
    Contracts --> Scenarios["Actionable scenarios<br/>actor + oracle + subject + repeat"]
    Scenarios --> CapabilityRoute{"Consumer capability"}
    CapabilityRoute --> AuthTasks["Authorization tasks<br/>allow | deny | tenant | replay"]
    CapabilityRoute --> PropertyTasks["Property tasks<br/>Schemathesis | Hypothesis"]
    Source --> Health["Code health<br/>complexity + async/exception/state risks + clones"]
    HealthPolicy["Code-health threshold policy"] --> Health
    Health --> RankedHealth["Ranked bounded detail + root-cause review queue<br/>family + symbol + symptoms + priority"]
    Source --> Architecture["Static architecture<br/>module/symbol calls + unified entry points + dynamic imports + policy"]
    Reachability["Semantic reachability<br/>typed receivers + framework dispatch"] --> Architecture
    NativePolicy["Native architecture policy"] --> PolicySelect{"Native present?"}
    TachPolicy["Tach fallback policy"] --> PolicySelect
    PolicySelect --> Architecture
    EdgeBaseline["Approved edge baseline"] --> Architecture
    Source --> Domains["Cross-domain applicability<br/>33 governed assurance areas"]
    Correlate --> Findings["Normalized findings"]
    Findings --> LLMPlan["LLM adversarial plan<br/>digest context + objective oracle"]
    Domains --> LLMPlan
    Contracts --> LLMPlan
    RankedHealth --> LLMPlan
    Architecture --> LLMPlan
    LLMPlan --> Model["External LLM planner<br/>repository text remains untrusted data"]
    Model --> Proposal["Schema-bound proposal<br/>plan + source + model + prompt digests"]
    Proposal --> ProposalCheck["Confined validator<br/>execution_authorized = false"]
    ProposalCheck --> Approval{"Human execution approval"}
    Approval --> Sandbox["Disposable network-denied lane<br/>read-only source + generated-tests writes"]
    Sandbox --> AdversarialTools["Deterministic tools + application-owned oracle"]
    AdversarialTools --> Proof["Authenticated source-bound proof<br/>negative control + mutation + failed case"]
    Proof --> Findings
    DomainPolicy["Domain obligations<br/>owner + subjects + requirements"] --> Domains
    ToolEvidence --> Domains
    Domains --> DomainStatus["Source/artifact/test-bound<br/>coverage + policy gaps"]
    History["Bounded sealed Git history"] --> Temporal["Architecture history<br/>co-change + finding hotspots"]
    ToolEvidence["Normalized scanner evidence"] --> Correlate["Conservative finding correlation<br/>semantic anchor | flow sink | location"]
    Frameworks --> Correlate
    Contracts --> Correlate
    AuthTasks --> Reports["Contextual artifact summaries"]
    PropertyTasks --> Reports
    RankedHealth --> Correlate
    Architecture --> Refactor["Ranked refactoring targets<br/>exact contracts kept distinct from heuristics"]
    Refactor --> Correlate
    Temporal --> Correlate
    DomainStatus --> Correlate
    DomainStatus --> Reports
    Correlate --> Validation["Finding validation<br/>independent proof dimensions"]
    AuthTasks --> AuthorizedLane["Separate authorized execution lane"]
    PropertyTasks --> AuthorizedLane
    AuthorizedLane --> Runtime["Digest-bound runtime and reproduction evidence"]
    Runtime --> Validation
    Validation --> Policy["Policy + closure ownership"]
    Capabilities["Profile intent + tool runs"] --> Manifest["Capability manifest"]
    Manifest --> Policy
```

Framework, contract, and cross-domain assurance analysis run for every profile
so model, behavioral, and specialized-domain gaps stay visible. Generated contract scenarios and their tokenized companion
commands remain authorized-lane plans until source-bound passing evidence
satisfies a declared obligation. Code health,
static architecture, and architecture history run for `audit`, `quality`,
`repo`, `comprehensive`, `production`, and `release`. Declared architecture
violations remain distinct from heuristic topology and maintainability signals.
Validation does not convert structural inference into exploitability: attacker
control, path confirmation, runtime execution, harmful effect, reproduction,
and production parity remain independent dimensions.

The adversarial branch has two separate authority decisions. The proposal
validator establishes only schema, digest, path, tool, and oracle constraints;
it always returns `execution_authorized: false`. An externally administered
human-approved sandbox performs any test execution. A campaign becomes a
confirmed defect only when authenticated evidence binds the source revision,
campaign, and exact failed ledger case.

### Evidence-plane-aware route synthesis

Risk-route synthesis does not assume every normalized finding belongs on a
production Python call path. It cross-references the exact target with the
Graphify file model, sealed source inventory, built-artifact manifest, target
kind, scanner, finding area, and path type before selecting an action.

```mermaid
flowchart LR
    Target["Normalized review target"] --> Join{"Route applicability"}
    Graph["Graphify file membership"] --> Join
    Source["Sealed source inventory"] --> Join
    Artifact["Built-artifact manifest"] --> Join
    Identity["Target kind + scanner + area + path"] --> Join
    Join -->|"Python runtime source"| Route["Declared-entry route or explicit model gap"]
    Join -->|"Artifact control"| Release["Release integrity / provenance lane"]
    Join -->|"Generated evidence"| Producer["Evidence producer / scan-scope lane"]
    Join -->|"Validation code"| Test["Shared-test quality lane"]
    Join -->|"Non-Python control"| Native["Native repository / IaC / configuration lane"]
    Route --> Report["Finding + report + closure"]
    Release --> Report
    Producer --> Report
    Test --> Report
    Native --> Report
```

This classification never suppresses a finding or changes native severity. It
prevents an artifact-provenance failure, generated JUnit file, or test-quality
finding from being mislabeled as a missing production entry point while keeping
real Python graph and entry-model gaps fail-visible.

### Typed cross-evidence leverage

After risk-route synthesis, the suite creates `advanced-analysis.json`. This
bounded relationship layer uses stable subject identities and keeps structural
inference distinct from native scanner confirmation.

```mermaid
flowchart TB
    Routes["Risk routes + Graphify"] --> Dominators["File dominators + alternate paths"]
    SARIF["Native SARIF codeFlows"] --> Taint["Confirmed taint sequences"]
    Artifact["Wheel metadata + RECORD"] --> Parity["Published activation parity"]
    Assurance["pytm + mutmut + tests"] --> Trace["Threat/control/test traceability"]
    Exposure["Sensitive-data routes"] --> Privacy["Telemetry protection topology"]
    Advisory["SBOM + KEV/EPSS + final artifact"] --> Trust["Dependency trust routes"]
    Dominators --> Evidence["Typed evidence graph"]
    Taint --> Evidence
    Parity --> Evidence
    Trace --> Evidence
    Privacy --> Evidence
    Trust --> Evidence
    Evidence --> Reports["Markdown + HTML + JSON"]
    Evidence --> Delta["Digest-bound advanced-diff"]
```

Control dominance is a file-graph property only. The report calls the subject a
candidate control until implementation, scanner, and test evidence establish
its behavior. `advanced-diff` compares approved SHA-256-bound artifacts and
fails on retained attack-surface regressions without treating a clean delta as
proof of safety. See [Advanced cross-evidence analysis](advanced-analysis.md).

The scan lane emits an unsigned in-toto Statement using the SLSA Verification
Summary Attestation predicate. A separate approval lane verifies the report and
signs that exact statement with an external Cosign key. Deployment consumers
verify the signature material, statement subject, applied-policy digest, report
checksum manifest, exact embedded-statement identity, and every referenced
evidence digest without running a scanner. Subject-containing payload
directories are closed sets for Python distributions: undeclared wheels,
sdists, and zip archives are rejected. The verifier caps directory entries and
samples mismatch details to preserve bounded work and bounded diagnostics.
Machine-facing CLI paths also preserve a stable JSON error envelope, while all
operator-facing errors share bounded control-safe redaction.
Markdown, HTML, and terminal/JSON inspection surface entry-point trust as a
top-level metric, keeping cryptographic approval distinct from a successful
before/after observation. The action plan expands each trust gap into a
risk-ordered remediation row with a compact digest identifier. A collapsed
candidate block retains complete copy-ready SHA-256 values in valid TOML while
making clear that observation is not provenance approval. Terminal inspection
keeps a bounded preview while the JSON inspection contract retains every
affected entry point as a priority-ordered structured action. Candidate-binding
and unique-digest counts make shared executable review work explicit without
collapsing the individual policy bindings. A strict bundled Draft 2020-12
schema and self-identifying offline URN make this output a versioned integration
contract rather than an informal JSON shape. A derived inspection sidecar is
atomically published outside the sealed report, preserving the report's exact
checksum set while giving CI and GitHub artifact consumers a stable standalone
document. Its report entry points and finding anchors are artifact-relative,
preventing runner-path disclosure and preserving links after relocation;
terminal rendering performs local resolution only at the presentation edge.
Offline sidecar verification recomputes this normalized view from the sealed
report and requires exact semantic equality, binding the sidecar digest to the
report checksum digest without confusing consistency with signer authenticity.
A strict report-verification receipt makes checksum and semantic validation
portable without requiring an inspection. A separate strict receipt schema
binds a successful inspection comparison to that sealed report. The `schema`
command retrieves all three contracts from installed package resources and can
atomically stage it for a disconnected consumer. Explicit `1.0` names and URNs
prevent a policy engine from silently selecting a newer contract.

```mermaid
flowchart LR
    Update["Connected intelligence update"] --> Snapshots["Digest-pinned KEV, EPSS, and VEX"]
    Snapshots --> Scan["Isolated scan and enrichment"]
    Previous["Approved prior findings digest"] --> Delta["Lifecycle comparison"]
    Scan --> Delta
    Delta --> Statement["Security Passport statement"]
    Statement --> Approval["Separate approval signer"]
    Approval --> Signed["Cosign 2 detached signature<br/>or Cosign 3 bundle"]
    Artifacts["Presented wheel and sdist"] --> Verify
    Signed --> Verify["Offline deployment verification"]
```

The connected lane is an acquisition and curation boundary. The execution lane
does not need Docker, a package index, the Semgrep registry, OSV services, or
credential verification services. The native bundle currently targets Windows
x86-64 and Python 3.11.

```mermaid
flowchart LR
    Source["Exact source revision"] --> BuildA["Clean build A"]
    Source --> BuildB["Clean build B"]
    BuildA --> Normalize["normalize-sdist<br/>reviewed fixed epoch"]
    BuildB --> Normalize
    Normalize --> Compare["compare-builds<br/>exact set + byte identity"]
    Source --> Scan["Isolated comprehensive scan"]
    Compare --> Payload["Wheel + sdist identities<br/>reproducibility evidence"]
    Scan --> Seal["Checksum-sealed report"]
    Seal --> Decision["release-check"]
    Seal --> Closure["closure-plan<br/>owned evidence backlog"]
    Seal --> Diff["diff-coverage<br/>retained change scope"]
    Closure -->|"validation alignment"| Decision
    Diff -->|"assessment completeness"| Decision
    Decision --> Plan["promotion-plan"]
    Seal --> Baseline["baseline-candidate<br/>revision + exact digest"]
    Seal --> Trend["trend<br/>verified report history"]
    Closure -->|"validation debt + owner continuity"| Trend
    Diff -->|"comparability scope"| Trend
    Closure -->|"owned validation queues"| Plan
    Diff -->|"assessment availability"| Plan
    Trend -->|"digest-bound trajectory + regressions"| Plan
    Payload --> Request["prepare-signing<br/>closed artifact set"]
    Seal --> Request
    Request --> Signer["Independent controlled signer"]
    Signer --> Verify["Offline bundle + subject verification"]
    Verify --> Passport["Signed Security Passport"]
    Passport --> Admission["Organization admission controller"]
    Plan --> Pack["evidence-pack<br/>atomic closed directory"]
    Pack --> Manifest["release-manifest<br/>closed evidence set"]
    Passport --> Manifest
    Manifest --> Admission
```

`closure-plan.json` is generated inside the same atomic report publication. It
joins active findings, governance integrity gaps, conditional activation,
coverage hotspots, reachability uncertainty, and changed-file validation
mismatches without becoming an admission decision. For each changed file it
consolidates Graphify-selected tests, exact case results, changed-line and
whole-file coverage, findings, and retained CODEOWNERS rules. Stable work IDs
survive reruns when the underlying issue is unchanged;
authority labels prevent repository automation from self-approving external
signing, isolation, scanner trust, or release controls.

Operational trend 1.3 reads that closure evidence and its retained diff-coverage
assessment scope from each independently verified report. Stable work IDs
distinguish new, resolved, unchanged, and state-transitioned validation subjects
only when both endpoints contain current ledger and assessment evidence;
CODEOWNERS routing produces owner-queue history and ownership deltas only under
that same condition. Debt growth, ownership erosion, failing-test regression,
and missing ledger or scope evidence become explicit anomalies.

The evidence-pack application layer composes existing verified services; it
does not create a second evidence model. Payload files are generated in private
staging, the release manifest binds selected decision records to the report,
the audit archive embeds the sealed report and those records, and the outer
pack manifest closes every readable artifact. Only a fully re-verified staging
tree is atomically renamed into place.

The scan lane produces evidence and candidate requests, never organizational
authority. Platform security attests isolation, security tooling approves exact
scanner entry points, vulnerability management approves intelligence,
controlled signing holds keys, and the release approver owns admission.

`--network-isolated` does not enforce network denial. It attests that the
enterprise runner, VM, firewall, or equivalent external control already does.

Production and release add a second statement: bounded evidence whose SHA-256
is pinned by organization policy, whose target and source digest match this
scan, and whose validity window covers scan start. Repository configuration
cannot promote its own evidence to `organization_approved`. Intelligence
approval uses the same authority split and binds the exact KEV, EPSS, and VEX
snapshot set.

```mermaid
flowchart LR
    Org["Organization policy<br/>approved evidence digests"] --> Validate["Bounded evidence validation"]
    Runner["External controller<br/>egress denial + signature verification"] --> Evidence["Isolation attestation"]
    Repo["Immutable repository digest"] --> Evidence
    Evidence --> Validate
    Report --> Draft["Non-authoritative evidence draft"]
    Draft --> Review["Independent provenance and policy review"]
    Review --> Org
    Snapshots["Exact KEV | EPSS | VEX digests"] --> Approval["Intelligence approval"]
    Approval --> Validate
    Report["Verified report"] --> Gate["release-check"]
    Validate --> Gate
    Effectiveness["Labeled benchmark"] --> Gate
    Passport["Passport verification"] --> Gate
    Gate --> Decision{"APPROVED?"}
```

Scanner identity carries two independent facts through the manifest: whether
the observed executable matched a configured digest, and whether that digest
originated in organization policy. The release gate requires both plus an
unchanged post-execution digest. This prevents a repository from approving its
own toolchain while preserving useful local tamper detection.

## Continuous assurance gates

```mermaid
flowchart LR
    PullRequest[Pull request] --> CI[Protected continuous integration]
    MainPush[Push to main] --> CI
    CI --> Tests[Cross-platform tests]
    CI --> Coverage[Branch + changed-line + critical-module coverage]
    CI --> Schema[Schema/runtime + public API compatibility]
    CI --> Workflow[Digest-verified actionlint + zizmor]
    CI --> Architecture[Dependency graph + file/function/decision ratchets]
    CI --> Performance[Repeated p95 + throughput + memory + growth budgets]
    Schedule[Scheduled assurance] --> Daily[Daily parser assurance]
    Daily --> Fuzz[Persistent JSON/XML/archive/adapter<br/>bytecode/Wasm/native parser fuzzing]
    Schedule --> Weekly[Weekly deep assurance]
    Weekly --> Mutation[Security-critical mutation testing]
    Weekly --> Resilience[Timeout + flood + rollback + cleanup drills]
    Weekly --> Providers[Protected live HSM/Vault/KMS conformance]
    Tests --> Gate[Release evidence]
    Coverage --> Gate
    Schema --> Gate
    Workflow --> Gate
    Architecture --> Gate
    Performance --> Gate
    Mutation --> Gate
    Fuzz --> Gate
    Resilience --> Gate
    Providers --> Gate
```

Benchmark and release command registration are isolated in
`cli_benchmark_arguments.py` and `cli_release_arguments.py`; execution
transitions, receipt construction, signing, scoring, and performance assurance
remain separate modules. Shared repository traversal, governance replay,
atomic publication, process-input policy, and diagnostic redaction are isolated
behind focused modules. The 12,000-line assurance data block is separated into
standards, benchmark, and profile catalogs, leaving the evaluation engine near
5,300 lines. Tach enforces exact imports across 148 production module boundaries.
A separate strongly-connected-component ratchet permits only one explicitly
recorded legacy trust/runtime cycle group and rejects any new member, edge
expansion, or additional cycle. CI also freezes concentration ceilings and rejects
accidental file, function, or decision growth while later extractions can lower
each ceiling without weakening behavior.

The continuous gate currently protects 58 commands, 469 positional/option
contracts, 164 immutable versioned schema contracts, three console-script
targets, and two Python callable signatures; enforces concentration
ceilings across 14 files, 13 functions, and 6 decision-node budgets; and repeats
five representative workloads five times plus one isolated full-repository
analysis pipeline. The workload suite covers 10,000-case
strict JSON/classification scoring, canonical evidence serialization, and the
complete bundled-schema catalog plus real production-source inventory and AST
parsing. The isolated workload executes the actual code-health and static-
architecture analyzers with child-process peak-memory and wall-clock budgets.
The pull
request gate also requires Docker/rootless-Podman, cross-platform containment,
PostgreSQL/Kafka, and authenticated Chromium/Firefox/WebKit lanes. The browser
gate verifies literal parametrization from the test AST and then proves every
required engine/role combination passed from retained JUnit evidence. Protected
provider drills remain separate because their deployment authority does not fit
an untrusted pull-request runner.

## Runtime architecture

```mermaid
flowchart TD
    CLI["CLI<br/>pysec scan"]
    Config["Configuration loader<br/>defaults + organization + repository"]
    Guard["Policy weakening guard"]
    Inventory["Target inventory + initial content digest<br/>tool/cache directories excluded"]
    Orchestrator["Orchestrator<br/>bounded parallel execution"]
    TrustCatalog["Organization trust catalog<br/>digest-bound + approved + expiring"]
    ToolTrust["Entry-point trust gate<br/>resolve + SHA-256 + approved digest"]
    FinalSnapshot["Final target content digest"]

    subgraph Adapters["Scanner adapter boundary"]
        Fast["Fast Python security<br/>Bandit | Semgrep | Ruff S"]
        Quality["Code quality and architecture<br/>Ruff | Pylint | mypy | Pyright | deptry | Vulture | Radon | Tach | Reachability | Graphify"]
        Tests["Passive test evidence<br/>coverage.py | diff-cover | bounded JUnit cases"]
        Secrets["Secrets<br/>detect-secrets | Gitleaks | TruffleHog"]
        Supply["Supply chain<br/>OSV | CycloneDX | GuardDog"]
        Pipeline["Repository controls<br/>zizmor | actionlint | Hadolint | Checkov | Trivy | PSScriptAnalyzer | ShellCheck"]
        Governance["Governance evidence<br/>REUSE | OpenSSF Scorecard"]
        Deep["Deep and native analysis<br/>Pysa | run-codeql | DevSkim | Flawfinder"]
        Artifact["Release artifacts<br/>Syft | Grype | wheel | Twine | PyPI attestations | Cosign"]
    end

    Normalize["Normalized findings<br/>stable ID + source + citations"]
    Correlate["Correlation<br/>path + line + logical rule"]
    Exposure["Sensitive-data synthesis<br/>taint + configuration + SDK/sink + graph context"]
    Policy["Policy evaluation"]
    Report["Report writers"]

    CLI --> Config --> Guard --> Inventory --> Orchestrator --> ToolTrust
    TrustCatalog --> ToolTrust
    ToolTrust --> Fast
    ToolTrust --> Quality
    ToolTrust --> Tests
    ToolTrust --> Secrets
    ToolTrust --> Supply
    ToolTrust --> Pipeline
    ToolTrust --> Governance
    ToolTrust --> Deep
    ToolTrust --> Artifact
    Fast --> Normalize
    Quality --> Normalize
    Tests --> Normalize
    Secrets --> Normalize
    Supply --> Normalize
    Pipeline --> Normalize
    Governance --> Normalize
    Deep --> Normalize
    Artifact --> Normalize
    Normalize --> Correlate --> Exposure --> FinalSnapshot --> Policy --> Report
```

The orchestrator runs only scanners selected by the active profile. Each
adapter owns command construction, prerequisite checks, entry-point digest
verification, version detection, timeout handling, output parsing,
classification mapping, and scanner-specific remediation guidance. The entry
point is rehashed after execution; a mismatch or mid-scan change fails closed.
Python console scanners can additionally pin and recheck the complete
recursively installed distribution closure.

Subprocesses reject abusive argv, timeout, output, and environment sizes before
host interaction. They receive a reduced environment, deterministic executable search
path, and a disposable private home, app-data, and cache root. Ambient proxy,
loader, Python import, and user-site configuration are not forwarded. Output is
spooled to private temporary files and the complete process tree is terminated
as soon as either stream exceeds its byte limit, so truncation cannot follow an
unbounded in-memory capture. A configured digest-pinned sandbox launcher wraps
both version and scan commands.

### Enforced suite architecture

The repository dogfoods Tach with a checked-in [`tach.toml`](../tach.toml).

Cross-tool joins are governed by the
[evidence-fusion contract](evidence-fusion.md). The fusion layer links semantic
classifications, source and artifact package inventories, exact artifact
digests, changed-line coverage, runtime observations, complexity, ownership,
and graph neighborhoods. It emits explanatory triage context without changing
scanner severity or treating missing observations as negative evidence.
Every top-level production module has an explicit boundary, root leakage is
forbidden, and undeclared or unused dependencies fail because exact mode is
enabled. The configuration/governance and adapter/repository-surface cycles have
been eliminated; dependency-neutral governance quorum verification has also
removed the assurance-profile module from the bootstrap cycle. Attestation
format parsing now receives its native replay executor through an explicit
protocol, removing the format parser from command-execution cycle debt while
retaining fail-closed replay and failure-domain validation. The repository
currently carries one explicit seven-module
trust/runtime cycle-debt group. `validate_architecture_cycles.py`
computes strongly connected components from the synchronized graph and fails on
any expansion or new cycle; shrinking a group also fails until the baseline is
deliberately lowered in the same reviewed change.

```mermaid
flowchart TB
    Entry["Entrypoints<br/>cli | __main__ | evidence ingest"] --> Application["Application<br/>orchestrator"]
    Entry --> Services["Services<br/>config | policy | reports | inventory | correlation | source context"]
    Application --> Integrations["Integrations<br/>scanner adapters"]
    Application --> Services
    Application --> Core["Core<br/>models | execution | package metadata"]
    Integrations --> Services
    Integrations --> Core
    Services --> Core
    Graph["Tach exact graph<br/>146 boundaries"] --> Debt["SCC debt ratchet<br/>1 frozen group / 7 modules"]
    Debt -->|new or expanded cycle| Fail["CI failure"]
    Graph --> Evidence["Schema-valid architecture assurance<br/>edges + SCCs + concentration"]
    Evidence --> Artifact["90-day CI evidence artifact"]
```

Tach findings use the common quality-domain contract: tool and native rule,
classification, file and line, bounded source excerpt, impact, remediation,
and an official rule citation. A boundary change therefore appears as an
actionable report item rather than an opaque scanner failure.

The bundled [reachability analyzer](reachability.md) adds a second structural
view. It follows bounded, typed AST edges from declared or discovered application
roots and separates executable, load-only, and disconnected code. Direct calls,
constructor lifecycle, concrete imported/local receivers, bounded polymorphic
dispatch, callback references, literal internal dynamic imports, and recognized
framework configuration or registration are distinct from imports and
definitions. Statically false and `TYPE_CHECKING` branches are pruned. Every node
and edge explains its confidence and predecessor. Optional coverage.py JSON adds
observed, not-observed, or not-measured corroboration. The sealed
`reachability.json` records representative execution sequences, applied precision
features, and ranked islands with removal readiness, blockers, and ordered actions
without importing or executing target code.

[Static risk-route synthesis](risk-paths.md) combines the complementary graph
views after finding, structural, exposure, and evidence-fusion enrichment. A
bounded multi-source search starts at declared reachability entry points and
walks deterministic Graphify file relations to normalized findings,
review-worthy sensitive-data sinks, and evidence-fusion advisory importer
paths. Each route carries runtime state, changed-
line and coverage evidence, focused tests, validation gaps, owners, related
findings, and exact supporting artifacts. It also joins each target's exact
contributing scanners to effectiveness 1.1 and scanner-trust evidence, keeping
completion, primary/helper integrity, before/after continuity, organization
approval, normalized/unique contribution, and perspective breadth separate.
Suite-derived correlations remain labeled as derived and never manufacture an
independent scanner perspective. Unrouted targets retain the same assurance
context. Finding targets additionally join digest-approved baseline
comparability to exact lifecycle, changed-line scope, validation, entry-runtime,
and scanner-assurance evidence. This identifies baseline-new or regressed work
on changed lines and modified pre-existing debt while failing closed when a
baseline is absent or incompatible; default `new` never becomes an unsupported
change-origin claim. Unrouted Python targets are also joined to exact retained
structural-island path or line membership. Reachability state, Graphify boundary
edges, candidate entry paths, Vulture corroboration, runtime/coverage
counter-evidence, focused tests, scanner assurance, and owners then produce a
bounded model-path, scope-separation, remediate-or-retire, or further-review
decision. Unrouted targets remain explicit model gaps; neither a route, its
absence, nor island membership is treated as an exploitability, safety, or
dead-code verdict. Routes converging on the same non-entry file become bounded
shared control points with one cross-target validation action. Exact primary
and alternate-entry file order is joined to retained CODEOWNERS last-match
rules. This creates stable owner-to-owner boundary records, identifies unowned
segments and target-owner mismatches, and fans the route into every responsible
coordination queue. The target finding owner remains independently attributed;
missing CODEOWNERS evidence never becomes an unsupported unowned-file claim.
Exact route and hotspot IDs are also grouped into owner queues so teams can
coordinate one
remediation/test campaign without collapsing the underlying findings. Each
hotspot also becomes a stable validation campaign: reverse Graphify edges select
direct/transitive tests, bounded case inventories establish observed execution,
file coverage exposes unexercised shared-control code, and structural synthesis
adds changed-line risk while reachability contributes runtime observation state.
Each campaign also resolves its exact route IDs back to contributing-tool
posture. Scanner execution, integrity, approval, and perspective state therefore
travel with the tests they selected; passing tests cannot erase a trust or
execution gap in the route evidence.
The factorized review model cites each contributing artifact and keeps the native
findings unchanged.

Package findings frequently point at a lockfile rather than executable source.
Risk-route synthesis now uses alias-aware advisory clusters as the identity
boundary and promotes each exact Graphify importer path as a bounded target.
The resulting route retains KEV/EPSS/VEX context, dependency lineage,
scanner-attributed fixes, citations, owners, tests, coverage, and validation;
it links back to every native cluster finding without duplicating the finding.
This answers “which entry point reaches an affected package importer?” while
explicitly leaving vulnerable-function invocation and exploitability unproven.
Instead of collapsing a target to one shortest origin, risk synthesis retains
up to 25 exact file routes from every declared entry point that reaches it.
Duplicate declarations on one file remain distinct interfaces, bounded
omissions are counted, and one primary route remains stable so finding identity
does not multiply. Reports and closure can therefore coordinate CLI, module,
worker, or framework-interface validation separately. Each declaration's exact
reachability target node supplies an interface-local observed, unobserved, or
unavailable runtime state; path-level runtime evidence is not borrowed.
Each importer also joins exact source and built-artifact package inventories,
distinguishing matched versions, drift, source-only, artifact-only, and missing
composition evidence without interpreting a version string as proof of safety.
When data-exposure synthesis also retains an SDK sink on the same exact path,
risk synthesis requires matching package and advisory-cluster identity before
emitting a sensitive-boundary dependency intersection. The compound record
coordinates boundary-control and dependency-remediation review while explicitly
leaving disclosure, attacker control, and vulnerable-function use unproven.
Confirmed exposure findings and review-worthy sink inventory also become a
separate end-to-end sensitive-data route ledger. It preserves the evidence
basis and joins entry-interface breadth, exact runtime state, data class, sink,
trust boundary, observed protection, scanner assurance, validation, lifecycle,
CODEOWNERS handoffs, and bounded applicable citations without converting static
coincidence into a leakage claim. Confirmed routes inherit normalized finding
references; inventory routes select sink-family standards from the data-exposure
artifact. Missing citation provenance is counted and becomes closure work, while
the references remain guidance rather than route validation.

```mermaid
flowchart LR
    Entry["Declared entry points"] --> Search["Bounded static route search"]
    Runtime["Exact entry target-node runtime evidence"] --> Matrix
    Graph["Graphify file relations"] --> Search
    Findings["Normalized findings"] --> Targets["Review targets"]
    Exposure["Sensitive sink surfaces"] --> Targets
    Advisories["Alias-aware advisories<br/>fix + KEV/EPSS/VEX"] --> Importers["Exact dependency importers"]
    Lineage["Source/artifact package lineage"] --> Importers
    Graph --> Importers
    Importers --> Targets
    Exposure --> ExactJoin["Exact path/package/advisory join"]
    Importers --> ExactJoin
    ExactJoin --> Targets
    Targets --> Search
    Effectiveness["Tool completion + contribution"] --> Assurance["Exact contributing-tool assurance"]
    Trust["Primary/helper integrity<br/>continuity + approval"] --> Assurance
    Assurance --> Routed
    Delta["Approved finding baseline + delta"] --> Lifecycle["Lifecycle/change attribution"]
    Targets --> Lifecycle
    Binding --> Lifecycle
    Lifecycle --> Routed
    Search --> Matrix["Per-target multi-entry exposure matrix"]
    Ownership["Retained CODEOWNERS rules"] --> OwnerPath["Ordered file ownership + handoffs"]
    Matrix --> OwnerPath
    OwnerPath --> Routed["Bounded risk routes"]
    Search --> Routed
    Routed --> SensitiveRoutes["End-to-end sensitive-data routes<br/>boundary + protection + assurance"]
    Citations["Finding citations + sink-family standards"] --> SensitiveRoutes
    Routed --> Hotspots["Shared control points"]
    Graph --> Campaigns["Graph-selected validation campaigns"]
    Hotspots --> Campaigns
    Routed --> CampaignAssurance["Per-campaign route assurance"]
    Assurance --> CampaignAssurance
    CampaignAssurance --> Campaigns
    Tests["Case-level execution"] --> Binding["Exact source digest + producer-verified payload receipts"]
    Coverage["Hotspot file coverage"] --> Binding
    Inventory["Sealed source inventory"] --> Binding
    Binding --> Campaigns
    Context["Complexity + graph centrality<br/>change risk + runtime state"] --> Campaigns
    Campaigns --> SharedTests["Cross-campaign shared-test hotspots"]
    Routed --> Queues["Owner route queues"]
    Campaigns --> Queues
    SharedTests --> Queues
    Routed --> Routes["risk-paths.json"]
    SensitiveRoutes --> Routes
    Hotspots --> Routes
    Campaigns --> Routes
    SharedTests --> Routes
    Queues --> Routes
    Routes --> Report["Finding cards + summary + SARIF"]
```

[Structural synthesis](structural-synthesis.md) then cross-validates these islands
and Vulture candidates against Graphify references, runtime coverage, Radon
complexity, Tach boundaries, ownership, and security findings. This produces
advisory removal/dynamic-use dispositions, latent attack-surface classifications,
and import-cycle hotspots without changing native scanner severity. Schema 1.2
also joins diff coverage to reverse Graphify paths for direct/transitive test
selection and compound change-risk scoring, discovers conservative structural
orphans, retains concrete island boundary evidence for missing-root versus
test-only triage, and cross-checks selected tests against exact case execution
and changed-line coverage.

[Sensitive-data exposure synthesis](data-exposure.md) adds a distinct disclosure
view. Bundled Semgrep rules establish credential, private-field, and request
collection paths into logs, telemetry, and URL queries; detect raw exception
responses and risky automatic-PII configuration; and allow Pysa/CodeQL to supply
organization models. A bounded AST inventory identifies logging, process-output,
observability, analytics, metrics, URL-query, client-response, header-capture,
and egress SDK surfaces without treating presence as a finding. The synthesis
joins exact sink and SDK evidence to Graphify, reachability, coverage, runtime,
changed-code, and related-finding context. Finalized evidence-fusion results
feed back into the exposure artifact as triage tiers and contextual verification
plans. Inventory-only sink surfaces receive the same bounded structural/test
context and evidence-specific verification steps for review ordering, but remain
explicitly separate from vulnerabilities. Structural synthesis and CODEOWNERS
also contribute accountable owners, exact graph-selected tests, change-risk
scores, and island/import-cycle identifiers, turning triage into a bounded
owner-and-test handoff. Finalized source/artifact lineage and normalized package
findings add a separate SDK dependency lane with advisory citations and explicit
matched-versus-risk semantics. Package-scoped CVE/GHSA/PYSEC/OSV alias clusters
prevent reciprocal advisory records from overstating distinct risk while
retaining every scanner source and enabling OSV/Grype corroboration.
Risk-route synthesis then carries those exposure semantics across each declared
entry route. Reports and closure work distinguish scanner-confirmed
source-to-sink evidence from inventory-only surfaces while presenting
protection, runtime, assurance, validation, lifecycle, and owner gaps together.
Those clusters also join CycloneDX dependency roots, exact Graphify import
edges, importing-file reachability/runtime state, and deptry findings. The
result is actionable dependency-use context with explicit incomplete and
conflicting states, never an exploitability verdict or severity override.
OSV and Grype fixed-version records plus approved offline KEV, EPSS, and VEX
then form a per-advisory remediation context. It retains scanner attribution,
uses the established P0-P4 priority model, adapts the action to dependency-use
evidence, and carries uncertainties and verification steps. It deliberately
does not guess a minimum safe version, accept VEX without scoped validation, or
change native severity.
Reverse Graphify edges then map each exact importing file to direct/transitive
tests, while retained coverage and CODEOWNERS-derived finding ownership provide
validation gaps and responsible teams. The closure plan keys work by advisory
cluster, consolidating alias-equivalent observations without dropping native
finding IDs or scanner attribution.
It separately keys changed-file validation work by repository path, merging an
overlapping whole-file coverage hotspot into the same owned item. Release
readiness consumes these items as a causal validation-alignment control and
retains their owner, priority, action, and evidence references.
Native Coverage/diff-cover findings for that path are folded into the same work
item with their IDs and scanner attribution but remain unchanged in the finding
ledger.
The human closure view rolls exact subjects up by owner and validation state.
Release readiness 1.3 then groups remediation only across identical owner,
priority, authority, action, and causal blocker tuples. Each group retains stable
closure-item references before bounded source and artifact citations.
Evidence-fusion 1.3 also joins those graph-selected test files to exact,
repository-normalized case records from JUnit, Hypothesis, and Schemathesis.
It reports current passing, failing, incomplete, unobserved, unavailable, or
unselected evidence while preserving the requirement to rerun after remediation.
Aggregate totals cannot establish that any particular selected file executed.
Passing selected tests whose affected dependency import paths remain uncovered
are reported as an explicit validation mismatch.
CWE/OWASP/OpenTelemetry-backed actions remain
independent of native scanner severity and no sensitive values are retained.

## Scan sequence

```mermaid
sequenceDiagram
    actor Operator
    participant Boundary as Enterprise boundary
    participant CLI as pysec CLI
    participant Config as Config loader
    participant Orch as Orchestrator
    participant Tools as Applicable selected tools
    participant Integrity as Integrity verifier
    participant Policy as Policy engine
    participant Reports as Report writers
    participant GitHub

    Operator->>Boundary: Verify egress denial
    Operator->>CLI: scan target --network-isolated
    CLI->>Config: Load organization and repository TOML
    Config-->>CLI: Protected merged configuration
    CLI->>Orch: Start selected profile
    Orch->>Integrity: Snapshot target paths, sizes, and content
    Orch->>Tools: Evaluate input applicability
    Tools->>Integrity: Resolve and hash scanner entry points
    Integrity-->>Tools: Approved or fail closed
    par Bounded independent execution
        Orch->>Tools: Python SAST and deep analysis
        Orch->>Tools: Secrets and Git history
        Orch->>Tools: Dependency and package integrity
        Orch->>Tools: CI, IaC, and license governance
        Orch->>Tools: Pre-generated coverage and JUnit evidence
        Orch->>Tools: Built-artifact and provenance controls
    end
    Tools->>Integrity: Rehash scanner and helper entry points
    Tools-->>Orch: Native JSON and health state
    Orch->>Integrity: Snapshot target again
    Integrity-->>Orch: Unchanged or incomplete
    Orch->>Policy: Correlated findings and tool records
    Policy-->>Reports: PASS, WARN, FAIL, or INCOMPLETE
    Reports-->>CLI: Checksummed report directory
    CLI-->>GitHub: Summary, artifact, SARIF, and SonarQube issues
    CLI-->>Operator: Policy exit code
```

## Scanner portfolio

The original quick and standard profiles remain stable. Opt-in profiles layer
additional perspectives:

| Layer | Tools | Contribution |
|---|---|---|
| Standard baseline | Bandit, Semgrep, detect-secrets, OSV-Scanner | Python AST, governed patterns, current-tree secrets, vulnerable dependencies |
| Extended | CycloneDX Python, Ruff, zizmor | SBOM evidence, parser diversity, GitHub workflow security |
| Deep | Pysa, CodeQL through `run-codeql` | Interprocedural and semantic data-flow analysis |
| Supply chain | Trivy, GuardDog, ScanCode, Gitleaks, TruffleHog | IaC, licenses, malicious packages, origin inventory, diverse secret detectors |
| Artifact | Syft, Grype, check-wheel-contents, Twine, PyPI attestations, Cosign | Final-distribution SBOM, vulnerabilities, source parity, contents, metadata, signatures, identity, and provenance |
| Quality, structure, and test evidence | Ruff quality/format, Pylint, mypy, Pyright, deptry, Vulture, Radon, Tach, reachability, Graphify, coverage, diff-cover, JUnit, PSScriptAnalyzer, ShellCheck, actionlint, Hadolint, REUSE | Correctness, formatting, type contracts, dependency declarations, dead code, entry-point sequences, disconnected islands, graph impact, complexity, dependency boundaries, test adequacy/outcomes, scripts, workflows, containers, and SPDX metadata |
| Deep IaC | Checkov plus Trivy, Hadolint, actionlint, and zizmor | Graph-aware cloud/IaC policies plus independent deployment and pipeline perspectives |
| Governance evidence | OpenSSF Scorecard evidence ingestion | Repository-host controls generated in a separately authorized connected lane |
| Repository insight | Conftest, KICS, pipdeptree, git-sizer, validate-pyproject, Vale, KubeLinter | Organization policy, IaC diversity, environment health, Git scale, packaging metadata, prose, and Kubernetes readiness |
| Trusted-lane evidence | Hypothesis, Schemathesis, CrossHair, Atheris, ClusterFuzzLite, mutmut, ZAP, Nuclei, browser and authorization contracts, IAST, Falco, Kubescape, Prowler, RASP, native sanitizers, MobSF, TLS, polyglot analysis, pytm, check-manifest, ClamAV, GitHub attestations, in-toto, reproducible builds, final OCI image, YARA | Fresh, coverage-bearing, canary-verified, signed bounded results from execution- or release-sensitive companion controls |
| Production | Source/repository portfolio plus strict readiness checks | Fail-closed pre-release source gate |
| Release | Comprehensive portfolio plus a required built distribution | Fail-closed artifact promotion gate |

The comprehensive and release profiles select every adapter. Conditional tools
first inspect repository inputs. No matching input produces a visible
`not applicable` record; a missing binary for relevant input produces
`INCOMPLETE`.

Production adds release-context requirements: a full VCS checkout, a
recognized lock plus dependency assurance when dependencies are declared,
configured Pysa analysis for Python source, and medium-or-higher blocking.

Detailed overlap, platform, acquisition, and licensing guidance is maintained
in the [compatibility matrix](compatibility-matrix.md).

Generated reports, native tool environments, virtual environments, dependency
trees, caches, and version-control metadata are excluded where supported to
avoid scanning vendored tools or counting duplicated generated source. Build
and distribution files remain inside the before/after integrity snapshot even
when they are excluded from maintained-source counts.

## Finding model

```mermaid
classDiagram
    class Finding {
        finding_id
        fingerprint
        title
        description
        impact
        remediation
        severity
        confidence
        area
        status
        blocking
    }
    class Location {
        path
        start_line
        end_line
        package
        version
        ecosystem
    }
    class Source {
        tool
        version
        rule_id
        native_severity
        message
    }
    class Citation {
        kind
        identifier
        title
        uri
    }
    Finding "1" --> "1..*" Location
    Finding "1" --> "1..*" Source
    Finding "1" --> "0..*" Citation
```

Every finding has a stable suite ID and fingerprint. Correlation first prefers
one exact semantic subject, then one native source-to-sink flow sink, and then
falls back to the primary path, line, and logical rule. Ambiguous semantic or
flow identities remain partitioned. Correlation preserves all unique sources
and citations while selecting the strongest severity and confidence.

Classifications favor native CWE metadata. Adapters add conservative mappings
where a scanner does not supply one, such as CWE-798 for credential findings.

## Policy decision model

```mermaid
flowchart TD
    Start["Scan records and findings"]
    Attest{"Required isolation<br/>attested?"}
    Health{"Every applicable required<br/>tool completed?"}
    Blocking{"Any finding at a<br/>blocking severity?"}
    Findings{"Any findings?"}
    Incomplete["INCOMPLETE<br/>exit 2"]
    Fail["FAIL<br/>exit 1"]
    Warn["WARN<br/>exit 0"]
    Pass["PASS<br/>exit 0"]

    Start --> Attest
    Attest -- No --> Incomplete
    Attest -- Yes --> Health
    Health -- No --> Incomplete
    Health -- Yes --> Blocking
    Blocking -- Yes --> Fail
    Blocking -- No --> Findings
    Findings -- Yes --> Warn
    Findings -- No --> Pass
```

Completeness is evaluated before vulnerability severity. A missing, failed,
timed-out, or unparsable applicable required scanner cannot produce a clean
result. A non-applicable conditional tool is explicitly skipped without
weakening completeness. A connected diagnostic may execute all scanners with
`--diagnostic-without-isolation`, but its outcome remains `INCOMPLETE`.

## Report contract

Each scan creates a dedicated directory:

```text
report/
|-- summary.md
|-- action-plan.md
|-- assurance-case.md
|-- index.html
|-- results.sarif
|-- findings.json
|-- scan-manifest.json
|-- checksums.sha256
|-- sbom.cdx.json                  # when CycloneDX is applicable
|-- scancode-inventory.json        # when ScanCode is applicable
|-- pylint-summary.json            # Pylint counts/statistics
|-- radon-complexity.json           # complete rank C+ complexity evidence
|-- reachability.json               # three-state topology, explanations, coverage, and islands
|-- graphify.json                    # validated code-only topology
|-- graph-analysis.json              # graph-aware finding neighborhoods
|-- risk-paths.json                  # entry routes, shared campaigns, owners, and validation gaps
|-- structural-synthesis.json        # dead code, island boundaries, change risk, and test targets
|-- data-exposure.json               # sensitive-data paths and SDK/sink review surfaces
|-- evidence-fusion.json             # semantic and cross-stage evidence joins
|-- coverage-summary.json           # validated pre-generated coverage
|-- junit-summary.json              # bounded output-free test case/file/result ledger
|-- reuse-compliance.json           # when REUSE opt-in is present
`-- evidence/
    |-- bandit.json
    |-- semgrep.json
    |-- detect-secrets.json
    `-- osv-scanner.json
```

Inspection sidecars, both verification receipts, and exported schemas remain beside
this directory rather than inside it. This preserves the sealed report's exact
file set. The CLI exports schemas from package resources with this flow:

```mermaid
flowchart LR
    Verify["pysec verify-report REPORT"] --> Receipt["Atomic report-verification receipt"]
    CLI["pysec schema NAME"] --> Registry["Version-explicit local registry"]
    Registry --> Resource["Installed Draft 2020-12 resource"]
    Resource --> Stdout["Standard output"]
    Resource --> Atomic["Validated temporary file"]
    Atomic --> Export["Atomic disconnected contract export"]
    Receipt --> Consumer["Disconnected policy or audit consumer"]
    Export --> Consumer
```

- `summary.md` is optimized for GitHub workflow summaries and rapid triage; it
  leads with the scan-policy disposition and separates applicable execution
  gaps from conditional controls that did not match the repository.
- `action-plan.md` separates prioritized finding remediation from scanner
  coverage-restoration work and collapses informational not-applicable rows
  without removing their reasons, re-enable conditions, or references. It binds
  artifact findings to complete immutable identities and groups scanner approval
  candidates into unique-digest provenance review batches before presenting the
  copy-ready policy bindings. Finding rows retain ownership and an authoritative
  reference alongside risk, lifecycle, and classification context. Ownership
  coverage and priority-bucketed queues surface assignment gaps, while each
  provenance batch records the observed tool version.
- `assurance-case.md` states what the static scan demonstrated and identifies
  required artifact, provenance, dynamic-test, and threat-review evidence. Its
  next actions are evidence-aware: completed clean controls retain evidence,
  active findings require remediation, and partial controls preserve both
  coverage-restoration and finding-remediation work.
- `index.html` is a self-contained complete human report with an explicit
  decision badge, a balanced scanner-health summary, actionable coverage gaps,
  and expandable not-applicable control evidence.
- Source findings show highlighted, line-numbered context. Binary artifact
  findings instead show the exact normalized path, SHA-256, and byte size; they
  never imply that a source line exists for a wheel or archive.
- `results.sarif` supports GitHub code-scanning ingestion.
- `findings.json` is the stable machine-readable finding collection.
- `source-inventory.json` binds each maintained source path, byte size, and
  SHA-256 to the aggregate source digest and supports non-invented clean-corpus
  labels without retaining source contents. It is a canonical required report
  artifact, not optional derived evidence; independent verification recomputes
  its bounded, strictly sorted, duplicate-free aggregate and manifest binding.
- `scan-manifest.json` records tool health, versions, inventory, policy
  reasons, timestamps, profile, and isolation attestation.
- `checksums.sha256` protects report integrity after generation. Verification
  also requires every canonical artifact and its exact scan-manifest binding,
  plus every declared derived file or directory. Missing, duplicated, linked,
  ambiguous, or boundary-crossing bindings are rejected, so a self-consistent
  but partial report cannot be presented as complete.
- `security-passport.json` is parsed and validated as an in-toto/SLSA statement;
  its exact input digest set and source, policy, outcome, profile, findings,
  tool-status, intelligence, and baseline claims must agree with the manifest.
  Its duplicate-free subject set must exactly match the source inventory and
  every distribution digest in `artifact-manifest.json`.
- `sbom.cdx.json` and `scancode-inventory.json` are governed derived evidence.
- `evidence/*.json` contains sanitized diagnostics and output hashes, not
  secret values or raw scanner output.

The Markdown summary places actionable findings before tool-health detail and
shows the first 20 in full. Each file-backed finding carries a bounded excerpt
with two context lines, exact line numbers, and an affected-line marker.
The HTML report adds a prioritized review table, stable finding anchors,
responsive tables, and a high-contrast source panel. Normalized JSON preserves
the excerpt metadata, while SARIF uses `region` and `contextRegion` snippets for
GitHub code-scanning presentation.

Secret findings never embed the source value. They retain the file and line
citation but replace content with an explicit redaction notice. Source paths
are resolved beneath the target, symlink and traversal escapes are rejected,
common credential assignments in non-secret context are redacted, and line
length and context are bounded. Complete results remain in HTML, JSON, and
SARIF.

The risk-path synthesis further cross-references each redacted secret candidate
with its content lane, source/graph/artifact membership, current-tree or
Git-history origin, scanner verification and assurance, lifecycle, and owners.
This produces `secret_provenance_assessments` and lane-specific closure criteria
without copying the candidate value or changing the finding's severity or
status. Generated evidence and test fixtures remain review contexts, not
automatic false-positive classifications.

```mermaid
flowchart LR
    Scanners["detect-secrets | Gitleaks | TruffleHog"] --> Normalize["Redacted normalized findings"]
    Inventory["Source + graph + artifact inventory"] --> Join{"Provenance join"}
    History["Current tree + Git history"] --> Join
    Trust["Verification + scanner assurance"] --> Join
    Normalize --> Join
    Join --> Ledger["Bounded secret provenance ledger"]
    Ledger --> Reports["Finding cards + SARIF"]
    Ledger --> Actions["Lane-specific closure work"]
    Sensitive["Sensitive-data sink routes"] --> Intersect{"Exact path or bounded route member?"}
    Ledger --> Intersect
    Intersect --> Compound["Secret-to-sink review intersections"]
    Campaign["Validation campaigns<br/>tests + execution + coverage"] --> Handoff["Source-bound validation handoff"]
    Quality["Scanner assurance + shared-test quality"] --> Handoff
    Compound --> Handoff
    Compound --> Reports
    Handoff --> Reports
    Handoff --> Actions
```

The compound intersection is emitted only for production-source candidates in
the exact sink file or on the ordered Graphify file route to that sink. It
preserves file-hop distance, history/current-tree alignment, protection,
validation, scanner assurance, and owners. It remains static co-location
evidence: symbol-level value flow, credential validity, runtime execution, and
disclosure require separate proof.

The handoff cross-references Graphify-selected or route-mapped candidate tests
with retained JUnit execution, aggregate coverage, producer-verified source
binding, route-scanner assurance, shared-test findings, and ownership. It fails
closed on gaps and deliberately reports canary validation as not established;
candidate test proximity is not evidence that a secret assignment was exercised.

When an exact sink/advisory intersection and a secret/sink intersection cite the
same retained sensitive route, risk-path synthesis creates a third bounded
ledger rather than asking reviewers to discover the relationship manually.

```mermaid
flowchart TD
    SecretSink["Secret / sink ledger"] --> Identity{"Same sensitive route ID"}
    SinkAdvisory["Sink / SDK advisory ledger"] --> Identity
    Identity --> Compound["Secret / boundary / advisory ledger"]
    Compound --> Reports["Markdown + HTML + SARIF + JSON"]
    Compound --> Closure["Coordinated credential, protection, dependency closure"]
```

Stable route identity prevents accidental joins across unrelated sinks in the
same file or package. The compound record preserves both source IDs, runtime,
validation, lifecycle, assurance, ownership, and citations, but remains derived
review context rather than taint, disclosure, or exploitability evidence.

## Configuration and policy ownership

Configuration is layered in this order:

1. secure built-in defaults;
2. optional organization policy;
3. optional repository configuration; and
4. an optional CLI profile override.

Repository configuration cannot weaken organization-mandated network denial,
isolation attestation, target-code prohibition, required scanners, blocking
severities, approved risk-ledger digest, or incomplete-scan behavior. Unknown
settings are rejected.

```mermaid
flowchart LR
    Scan["Normalized findings"] --> Ledger{"Approved risk ledger configured?"}
    Ledger -->|"No"| Active["Active findings"]
    Ledger -->|"Yes"| Validate["Validate hash, fingerprint, owner, rationale, expiry"]
    Validate -->|"Invalid, expired, duplicate, or stale"| Incomplete["INCOMPLETE"]
    Validate -->|"Exact match"| Governed["Governed finding retained in JSON audit"]
    Validate -->|"No match"| Active
    Active --> Gate{"Blocking policy"}
    Gate --> Fail["FAIL or WARN"]
    Governed --> Gate
```

See [configuration.md](configuration.md) for the complete supported schema.

## Hostile parser containment

Native binaries and Python bytecode never give parser libraries a mutable path
inside the target checkout. The suite reads each regular file through the
bounded path-safety layer, writes the exact accepted bytes to a private
exclusive snapshot, and invokes a dedicated worker with output, scratch,
resident-memory, and time limits. Direct boundary-graph use requires a governed
OS sandbox by default; repository development profiles must opt out explicitly.
WebAssembly validation remains in-process but uses Wasmtime validation plus
bounded section, name, import, memory, and start-function parsing. All three
families have dedicated coverage-guided fuzz targets and retained corpora.

```mermaid
flowchart LR
    Target["Untrusted repository file"] --> SafeRead["Race-safe regular-file read<br/>1 MiB input ceiling"]
    SafeRead --> Snapshot["Private O_EXCL snapshot<br/>exact accepted bytes"]
    Snapshot --> Sandbox["Digest-pinned OS sandbox<br/>required by safe default"]
    Sandbox --> Worker["Bytecode or PE/ELF/Mach-O worker<br/>time + output + scratch + 256 MiB RSS"]
    Worker --> Validate["Strict canonical edge validation"]
    Validate --> Graph["Boundary graph imports<br/>hardening + dynamic dispatch"]
    Fuzz["Atheris bytecode/Wasm/native corpora"] --> Worker
    Fuzz --> Wasm["Wasmtime + bounded Wasm sections"]
    Wasm --> Graph
    Worker -->|timeout, crash, malformed, limit| Incomplete["Unsupported / INCOMPLETE"]
```

## Security properties

### Controls implemented

- Scanner versions and external native assets are pinned.
- The native installer verifies every bundle entry before installation.
- The installer writes each resolved scanner entry-point SHA-256 to the native
  configuration; production and release profiles require these approved
  bindings, including a separate CodeQL CLI digest.
- Scanner and helper entry points are rehashed after execution.
- Multi-artifact verifiers preserve that invariant when prerequisite evidence is
  absent: Cosign rehashes its entry point after the version probe even when
  every artifact is missing a bundle and no `verify-blob` command can be issued.
- The target is content-hashed before and after the scanner portfolio; a
  changed source or distribution artifact makes the result `INCOMPLETE`.
- Native package installation uses `pip --no-index`.
- OSV-Scanner requires a local advisory database and disables resolution.
- OSV rejects missing or older-than-policy database markers; Grype reads the
  authoritative internal database build timestamp so copied stale databases
  cannot appear fresh from their filesystem metadata.
- `uv.lock` is exported with hash-verified `uv --frozen --offline`; the
  temporary pinned graph is converted by CycloneDX without dependency access.
- Semgrep uses local rules with metrics and version checks disabled.
- detect-secrets disables network verification and redacts candidate values.
- Gitleaks uses full redaction; GuardDog matched code is discarded.
- TruffleHog disables verification and updates and discards raw secret values.
- zizmor is forced offline.
- Trivy disables database, check, VEX, version, and telemetry updates.
- `run-codeql` requires a pre-staged CodeQL CLI and local Python query pack;
  auto-download is rejected and analysis uses a temporary source mirror.
- Syft disables update checks; Grype disables database and application updates
  and requires a staged database.
- PyPI distribution attestations are verified with local provenance and
  `--offline`.
- Target code is never imported or executed by the suite.
- Coverage and JUnit adapters validate only pre-generated evidence. XML DTDs,
  entities, symlinks, oversized inputs, and excessive report counts are
  rejected; test output and failure bodies are never retained.
- Scanner processes receive a low-credential environment without ambient
  proxies and with disposable private home/cache paths.
- Required scanner failure produces `INCOMPLETE`, never `PASS`.
- Production and release require completed revision-bound companion evidence;
  conditional absence cannot silently pass those gates.
- Exact, expiring risk acceptances remain auditable while active SARIF and
  action queues exclude only validated matches.
- A disposable detection corpus proves independent Bandit, Semgrep, and
  detect-secrets findings through the real aggregate path.
- Report overwrite requires a valid suite manifest and rejects unsafe roots or
  linked destinations. Report publication is failure-atomic: a private sibling
  staging tree is checksummed, then its checksum chain and manifest are read
  back and verified before the final rename; a destination that appears during
  rendering is never overwritten.

### Controls supplied by the enterprise platform

- Network egress denial and proof of that boundary.
- CPU, memory, process, and wall-clock quotas beyond per-tool timeouts.
- Read-only source mounts. The suite detects content changes and creates report
  directories/files with private 0700/0600 modes, but the enterprise boundary
  still controls the source mount and platform ACL inheritance.
- Bundle transport, provenance, malware inspection, and approval.
- Artifact retention, access control, signing, and audit logging.

### Residual risks

- SHA-256 manifests and entry-point bindings detect substitution relative to
  an approved digest but are not publisher signatures. Python console scripts
  can close the imported-package gap with `runtime_closure_sha256`; native
  dynamic-library closure still depends on the approved sandbox image/bundle.
- Database refresh still depends on the connected update lane, while maximum
  accepted age is enforced during isolated execution.
- Local rules and advisory snapshots define the achievable coverage.
- Static analysis produces false positives and cannot prove absence of
  vulnerabilities.
- A project without resolved dependency versions limits OSV evidence.
- The current native bundle is Windows x86-64 only.

## Verified implementation state

The native Windows self-scan process verifies:

- the `comprehensive` profile selects all 89 adapters;
- the latest readiness assessment identifies 37 applicable controls and 26
  conditional or content-not-applicable controls, with no unavailable scanner;
- Pylint, Radon, Ruff formatting, coverage, and JUnit adapters executed through
  unchanged observed entry-point bindings and emitted normalized derived
  evidence; organization approval remains an external decision;
- the separately generated branch-coverage evidence records 90.07% combined
  line-and-branch coverage across 13,486 statements and 4,558 branches,
  including 92.98% statement and 81.48% branch coverage; JUnit records 495
  collected tests, 494 passes, one platform-limited skip, and no failures or
  errors;
- CycloneDX completed from `uv.lock` through a frozen offline export with a
  hash-verified helper; zizmor, actionlint, Pysa, GuardDog, Flawfinder, and
  REUSE were correctly not applicable to this repository and native host;
- CodeQL completed with the staged local CLI/query pack; PyPI attestations were
  correctly not applicable because these dogfood artifacts have no Trusted
  Publisher repository identity;
- Syft and Grype inspected safely expanded wheel and source distributions;
- two fixed-epoch builds produced identical wheels and, after deterministic
  metadata normalization, identical source distributions; the artifact
  manifest bound both distributions by SHA-256;
- all generated report checksums verified and target content remained
  unchanged;
- every observed scanner and helper entry point was confirmed unchanged after
  execution; each remains explicitly routed as independent
  provenance-approval work rather than being locally self-approved;
- the 2026-08-10 comprehensive outcome was `INCOMPLETE` solely because the
  required external network-isolation attestation was absent; fresh local
  intelligence and complete scanner execution did not weaken that boundary;
- exactly two high-severity Cosign observations remain for intentionally absent
  wheel and source-distribution bundles, with no testing-coverage findings; and
- the bundled reachability analyzer completed its schema-1.2 three-state model
  at medium confidence because bounded polymorphic dispatch was used: four
  entry points, no disconnected code, and no reportable islands; coverage
  corroborated every executable node and nearly every load-only node; and
- code security, secrets, dependency-vulnerability, architecture, and quality
  perspectives had no unresolved repository finding. `closure-plan.json`
  preserves the remaining governed and conditional work as stable owned
  actions. Release remains blocked until the external
  isolation authority attests the exact run, the scanner identities are
  independently approved, and a controlled signing lane supplies bundles for
  both exact artifact digests.

## Expanded implementation state

Adapters, parser fixtures, applicability handling, profiles, attribution, and
offline command construction are implemented for all 64 portfolio tools,
including CodeQL through `run-codeql`, final-distribution controls, seven
repository-health scanners, and trusted-lane evidence adapters including final
OCI-image assurance.

The rollout remains deliberately staged:

1. keep existing quick and standard policy contracts stable;
2. validate `extended` on representative Python repositories;
3. tune organization Pysa models and CodeQL packs before enabling `deep`;
4. approve platform binaries and license policy before enabling
   `supply-chain`; and
5. make `comprehensive` required only after tool availability, runtime, and
   false-positive rates are measured on enterprise runners.
