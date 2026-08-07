# Python Security Suite design

Status: alpha foundation  
Last reviewed: 2026-08-07

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
        Scanners["63 governed adapters<br/>security | quality | testing | policy | architecture | supply chain | artifact | governance"]
        Reports["Markdown | HTML | SARIF | SonarQube | JSON<br/>SBOM + delta + intelligence + Security Passport"]
        Contracts["Version-explicit JSON Schemas<br/>installed package resources"]
        Install --> Suite
        Project --> Suite
        Suite --> Scanners
        Scanners --> Suite
        Suite --> Reports
        Suite --> Contracts
    end

    GitHub["GitHub artifact,<br/>workflow summary, and SARIF"]

    Bundle --> Transfer --> Install
    ScorecardCollect --> Transfer
    Reports --> GitHub
    Contracts --> GitHub
```

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
    Snapshots["Exact KEV | EPSS | VEX digests"] --> Approval["Intelligence approval"]
    Approval --> Validate
    Report["Verified report"] --> Gate["release-check"]
    Validate --> Gate
    Effectiveness["Labeled benchmark"] --> Gate
    Passport["Passport verification"] --> Gate
    Gate --> Decision{"APPROVED?"}
```

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
        Quality["Code quality and architecture<br/>Ruff | Pylint | mypy | Pyright | deptry | Vulture | Radon | Tach | Reachability"]
        Tests["Passive test evidence<br/>coverage.py | diff-cover | JUnit XML"]
        Secrets["Secrets<br/>detect-secrets | Gitleaks | TruffleHog"]
        Supply["Supply chain<br/>OSV | CycloneDX | GuardDog"]
        Pipeline["Repository controls<br/>zizmor | actionlint | Hadolint | Checkov | Trivy | PSScriptAnalyzer | ShellCheck"]
        Governance["Governance evidence<br/>REUSE | OpenSSF Scorecard"]
        Deep["Deep and native analysis<br/>Pysa | run-codeql | DevSkim | Flawfinder"]
        Artifact["Release artifacts<br/>Syft | Grype | wheel | Twine | PyPI attestations | Cosign"]
    end

    Normalize["Normalized findings<br/>stable ID + source + citations"]
    Correlate["Correlation<br/>path + line + logical rule"]
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
    Normalize --> Correlate --> FinalSnapshot --> Policy --> Report
```

The orchestrator runs only scanners selected by the active profile. Each
adapter owns command construction, prerequisite checks, entry-point digest
verification, version detection, timeout handling, output parsing,
classification mapping, and scanner-specific remediation guidance. The
entry point is rehashed after execution; a mismatch or mid-scan change fails
closed.

Subprocesses receive a reduced environment and a disposable private home,
app-data, and cache root. Ambient proxy variables and user site packages are
not forwarded. A timeout or interruption terminates the scanner's complete
process tree and waits for cleanup, preventing orphaned child analyzers. Raw
scanner output is not retained in the report; evidence contains sanitized tool
health and output digests.

### Enforced suite architecture

The repository dogfoods Tach with a checked-in [`tach.toml`](../tach.toml).
Every internal dependency is explicit, unconfigured source modules are
forbidden, circular dependencies fail the check, and unused declarations fail
because exact mode is enabled.

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
| Quality, structure, and test evidence | Ruff quality/format, Pylint, mypy, Pyright, deptry, Vulture, Radon, Tach, reachability, coverage, diff-cover, JUnit, PSScriptAnalyzer, ShellCheck, actionlint, Hadolint, REUSE | Correctness, formatting, type contracts, dependency declarations, dead code, entry-point sequences, disconnected islands, complexity, dependency boundaries, test adequacy/outcomes, scripts, workflows, containers, and SPDX metadata |
| Deep IaC | Checkov plus Trivy, Hadolint, actionlint, and zizmor | Graph-aware cloud/IaC policies plus independent deployment and pipeline perspectives |
| Governance evidence | OpenSSF Scorecard evidence ingestion | Repository-host controls generated in a separately authorized connected lane |
| Repository insight | Conftest, KICS, pipdeptree, git-sizer, validate-pyproject, Vale, KubeLinter | Organization policy, IaC diversity, environment health, Git scale, packaging metadata, prose, and Kubernetes readiness |
| Trusted-lane evidence | Hypothesis, Schemathesis, CrossHair, Atheris, mutmut, ZAP, pytm, check-manifest, ClamAV, GitHub attestations, in-toto, reproducible builds, final OCI image, YARA | Bounded results from execution- or release-sensitive companion controls |
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

Every finding has a stable suite ID and fingerprint. Scanner observations at
the same path, line, and logical rule are correlated. Correlation preserves all
unique sources and citations while selecting the strongest severity and
confidence.

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
|-- coverage-summary.json           # validated pre-generated coverage
|-- junit-summary.json              # validated test result metadata
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
- File-system permissions and read-only source mounts. The suite detects
  content changes but does not itself make a native target read-only.
- Bundle transport, provenance, malware inspection, and approval.
- Artifact retention, access control, signing, and audit logging.

### Residual risks

- SHA-256 manifests and entry-point bindings detect substitution relative to
  an approved digest but are not publisher signatures. A Python console-script
  digest does not cover every imported package file.
- Database refresh still depends on the connected update lane, while maximum
  accepted age is enforced during isolated execution.
- Local rules and advisory snapshots define the achievable coverage.
- Static analysis produces false positives and cannot prove absence of
  vulnerabilities.
- A project without resolved dependency versions limits OSV evidence.
- The current native bundle is Windows x86-64 only.

## Verified implementation state

The native Windows self-scan process verifies:

- the `comprehensive` profile selects all 63 adapters;
- all 36 applicable scanners completed without failures, timeouts, or parse
  errors; 27 conditional scanners were correctly not applicable;
- Pylint, Radon, Ruff formatting, coverage, and JUnit adapters executed through
  approved entry-point bindings and emitted normalized derived evidence;
- the separately generated branch-coverage evidence records 92.55% combined
  line-and-branch coverage and 85.96% branch coverage, satisfying both 80%
  repository gates with no per-file hotspots; JUnit records 319 passing tests,
  one platform-limited symlink skip, and no failures or errors;
- CycloneDX completed from `uv.lock` through a frozen offline export with a
  hash-verified helper; zizmor, actionlint, Pysa, GuardDog, Flawfinder, and
  REUSE were correctly not applicable to this repository and native host;
- CodeQL completed with the staged local CLI/query pack; PyPI attestations were
  correctly not applicable because these dogfood artifacts have no Trusted
  Publisher repository identity;
- Syft and Grype inspected safely expanded wheel and source distributions;
- the artifact manifest bound both distributions by SHA-256;
- all generated report checksums verified and target content remained
  unchanged;
- all 38 observed scanner and helper entry points were confirmed unchanged
  after execution; 13 were also bound to approved digests, while the remaining
  25 are explicitly reported as provenance-approval work;
- the 2026-08-06 isolated comprehensive outcome was `INCOMPLETE` because the
  digest-pinned KEV and EPSS snapshots were 5.00 days old against a 3-day
  maximum; the suite failed closed despite complete scanner execution;
- exactly two high-severity Cosign observations remain for intentionally absent
  wheel and source-distribution bundles, with no testing-coverage findings; and
- the bundled reachability analyzer completed its schema-1.2 three-state model
  at medium confidence because bounded polymorphic dispatch was used: four roots,
  73 modules, 964 nodes, 6,983 explained edges, 871 executable nodes, 93 load-only
  nodes, no disconnected nodes, and no reportable islands; coverage corroborated
  every executable node and 92 load-only nodes exercised directly or indirectly
  by tests; and
- code security, secrets, dependency-vulnerability, architecture, and quality
  perspectives had no findings. Release remains blocked until approved
  intelligence is refreshed and an approved signing lane supplies bundles for
  both exact artifact digests.

## Expanded implementation state

Adapters, parser fixtures, applicability handling, profiles, attribution, and
offline command construction are implemented for all 63 portfolio tools,
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
