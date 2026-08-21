# Advanced cross-evidence analysis

Last reviewed: 2026-08-13

`advanced-analysis.json` turns retained scanner, route, artifact, threat, test,
mutation, telemetry, and dependency evidence into typed relationships and
decision-oriented review records. The analysis is offline, bounded, and does
not execute target code.

## Analysis pipeline

```mermaid
flowchart LR
    Graph["Graphify file topology"] --> Controls["Control dominance and bypasses"]
    Routes["Entry-to-risk routes"] --> Controls
    SARIF["CodeQL SARIF codeFlows"] --> Taint["Confirmed source-to-sink paths"]
    Wheels["Wheel entry_points.txt + RECORD"] --> Parity["Artifact activation parity"]
    Threats["pytm threats"] --> Trace["Threat-control-test traceability"]
    Tests["JUnit, coverage, mutmut"] --> Trace
    Routes --> Privacy["Telemetry privacy topology"]
    Taint --> Privacy
    SBOM["SBOM, advisory, provenance evidence"] --> Trust["Dependency trust routes"]
    Controls --> Evidence["Typed evidence graph"]
    Taint --> Evidence
    Parity --> Evidence
    Trace --> Evidence
    Privacy --> Evidence
    Trust --> Evidence
```

## Decisions produced

| Analysis | Exact evidence required | Decision |
|---|---|---|
| Control topology | Graphify file edges, exact route entry IDs mapped through reachability, retained validation campaigns | A candidate control is mandatory on every route-scoped static path, bypass-capable, absent from retained routes, or `not-established` when entry identity or graph connectivity is incomplete |
| Taint-path fusion | Native SARIF `codeFlows` plus normalized finding identity | Preserves bounded execution order, nesting, importance, and source/sink kinds; route alignment requires a sink matching the finding plus the complete ordered native file path as a subsequence of one retained entry exposure |
| Artifact route parity | Digest-bound wheel, ZIP member structure, `entry_points.txt`, `RECORD`, source graph, declared entry points | Detects ambiguous or unsafe archive members and determines whether published commands and plugins are modeled, graph-only, or absent from reviewed source |
| Threat traceability | Exact pytm finding path, mapped control campaign, case-level execution, complete inventory, source-revision binding | Separates selected test candidates from source-bound passing observations and keeps security-test intent `not-established` until an abuse-case assertion is reviewed |
| Mutation leverage | Exact mutmut finding path, control candidate, and source-bound case execution | A security-relevant control mutation survived; selected or passing tests are distinguished from mutation-killing evidence |
| Telemetry privacy | Sensitive-data route, protection status, candidate controls, aligned native taint steps | Assesses every aligned path against its retained sink, distinguishes native sanitizer kinds from heuristic labels, exposes partial redaction and exact pre-sink control correlation, and withholds a protected decision when evidence is incomplete |
| Dependency trust | Exact advisory importer, advisory and final-artifact versions, KEV/EPSS, runtime and scanner assurance | Distinguishes an affected version in the artifact, a fixed version, comparable absence, unresolved versions, and missing composition evidence before assigning review weight |

The suite calls a file a **candidate control** only when a retained
`shared-transit` convergence hotspot or its validation campaign identifies it.
Ordinary target concentration is not control evidence. Dominance proves a graph
property, not that the implementation authenticates, authorizes, validates, or
redacts correctly. A bypass means an alternate static file path exists; it is
not an exploitability claim.

Dominance is computed independently for each route's declared entry identities.
Unrelated application entry points cannot create a false bypass for a route that
does not retain them. Conversely, the analysis does not fall back to global
roots when a route entry ID is missing or its target is disconnected in the
retained graph; it reports `not-established` and creates an evidence-repair
handoff instead of claiming that the control is mandatory or bypassable.

## Release regression comparison

Compare two independently retained artifacts only after approving their exact
SHA-256 digests:

```text
pysec advanced-diff BEFORE/advanced-analysis.json AFTER/advanced-analysis.json \
  --baseline-sha256 BASELINE_SHA256 \
  --current-sha256 CURRENT_SHA256 \
  --format markdown --output advanced-delta.md
```

The command fails with exit code `1` when it observes any of the following:

- a mandatory candidate control becomes bypass-capable;
- telemetry protection or redaction ordering regresses;
- a dependency trust route moves to a higher review tier;
- a new scanner-confirmed taint path appears;
- an existing scanner-confirmed path loses ordered entry-route alignment;
- a new unmodeled published entry point appears; or
- a new wheel `RECORD` identity gap appears.

Both inputs are regular files, size-bounded, schema-identified, and
digest-verified before comparison. A passing delta means no retained regression;
it does not prove safe runtime behavior or absence of vulnerabilities.

Wheel inspection validates archive structure before interpreting `RECORD`:
duplicate names, case collisions, traversal or platform-ambiguous paths,
symlinks, encrypted entries, unverifiably large members, suspicious compression
ratios, and excessive total expansion are retained as integrity gaps. Exact ZIP
member counts are preserved instead of collapsing duplicate central-directory
entries into a set. `RECORD` validation rejects duplicate rows, missing hashes
or sizes on ordinary members, invalid self-metadata, weak or unknown hash
algorithms, and digest mismatches while accepting fixed-length SHA-384, SHA-512,
and BLAKE2 hashes in addition to SHA-256.

## Report interpretation

`summary.md` and `index.html` show counts and the highest-value control,
telemetry, and dependency decisions. `advanced-analysis.json` remains the
complete machine contract and includes:

- stable subject and relationship IDs;
- contributing evidence artifact names;
- exact source paths and lines when available;
- scanner-confirmed versus structural classifications;
- owner and test handoffs;
- actionable remediation; and
- explicit limitations and truncation counts.

`route_alignment: aligned` is deliberately strict. The final native sink must
match the normalized finding location, and every source-to-sink file transition
must occur in the same order within one retained entry-point exposure. Sharing
only the sink, sharing an unordered file set, a conflicting sink line, a path
outside the exposure, or contradictory native source/sink markers cannot create
route corroboration. Those flows remain scanner-confirmed but are reported as
`not-established` with a reconciliation action. Native `executionOrder` is used
when every retained step supplies it; otherwise the SARIF array order is kept.
For a code flow containing multiple threads, complete execution order with no
bounded thread or step omissions combines the retained steps into one
deterministic cross-thread sequence. Equal order values across different threads
remain simultaneous and receive a stable display order, but simultaneous
source/sink endpoints cannot establish data-flow direction. Missing order keeps
threads separate, while duplicate order values within the same thread invalidate
promotion as required by SARIF. Portable flow summaries expose represented
threads, combination status, omitted threads, and invalid, duplicate, or
simultaneous order counts. Advanced analysis treats an explicit
`unclassified-code-flow` decision as authoritative instead of re-promoting it
from bounded kinds alone.
Run-level `threadFlowLocations` caches are resolved before this normalization.
An indexed step inherits its cached location, ordering, kinds, and message only
when its array index is valid, the cached self-index agrees, and every nested
overlay property matches the cached value. Invalid, unresolved, or conflicting
references receive explicit non-repository markers, demote the entire native
flow to unclassified, and are summarized by resolution status. This prevents a
broken cache reference from becoming scanner-confirmed source-to-sink evidence
while allowing valid compact producer output to retain its complete route.
Regenerated SARIF retains only bounded per-flow counts and semantic status, not
the complete path messages, as `sarif_code_flow_summary`.
Generic SARIF `codeFlows` are not automatically taint evidence: promotion
requires a security-domain `path-problem` rule or correctly ordered native
`source` and `sink` kinds. Other paths remain bounded in normalized finding
evidence as `unclassified-code-flow` and do not inflate taint-path counts.

Telemetry redaction is evaluated per aligned native path. Export position is the
retained sink endpoint, not a substring guess from messages such as `log` or
`send`. A route receives `redaction-before-export` only when every aligned,
complete path contains a redaction marker before that sink. Native sanitizer
kinds are distinguished from bounded path/message heuristics; mixed paths are
reported as `redaction-not-on-all-confirmed-paths`. Candidate controls are also
correlated by exact file occurrence before each native sink. A missing
occurrence prevents a protected claim but is not called a runtime bypass,
because data-flow scanners may omit non-data-flow control frames.
Heuristic names remain review evidence only: `protected-static-route` requires
an explicit native sanitizer kind on every aligned path, in addition to the
route's observed protection and mandatory-control correlation.

Threat and control test joins follow the mapped control's campaign IDs rather
than looking for a test campaign at the threat sink. `candidate_test_files` are
selection evidence only. A file reaches `verified_test_files` only when the
campaign retains a complete case inventory, a passing observation for that
exact file, complete source-inventory membership, and an aligned evidence
revision. Even then, the record remains a test candidate: execution and line
coverage do not establish that the test contains a negative or abuse-case
assertion for the threat. Stale, partial, failed, and unbound evidence cannot
reduce the corresponding report or closure-plan gap.

Dependency scoring compares retained advisory versions with exact artifact
versions. Merely having an artifact SBOM no longer implies that the package is
present. Comparable absence contributes no shipped-package weight; affected,
fixed, unresolved, and unavailable artifact states remain distinct in the
machine record and release delta.

Actionable bypasses, artifact parity failures, privacy gaps, elevated dependency
trust routes, threat traceability gaps, and surviving security mutations are
also promoted into `closure-plan.json` with an owner, priority, acceptance
criteria, and evidence references.

Native SARIF path retention excludes source snippets and arbitrary execution
state so reports do not create a secondary sensitive-data store. Scanner-owned
finding text, native step messages, and artifact locations are sanitized at the
adapter boundary:
credential assignments, authorization values, URL userinfo, JWTs, known token
formats, and private-key material are removed before normalization, while
secret-scanner lanes replace all unstructured result and path text fail closed.
Non-file URI locations become an explicit external-artifact marker rather than
persisting credentials, queries, or other URI state as repository paths.
SARIF results also retain up to 25 ordered, distinct native locations instead
of collapsing multi-file evidence to the first location. The primary location
continues to determine stable finding identity, while reported, retained,
duplicate, malformed, and limit-omitted counts make evidence loss auditable.
Secondary locations can therefore participate in graph, exposure, and native
sink correlation without multiplying scanner findings. Portable SARIF output
preserves the retained location set and its completeness summary.
SARIF result-state semantics are normalized before findings enter correlation.
Explicit `pass`, `notApplicable`, and baseline `absent` results are not treated
as active findings; unknown or future states remain reviewable. Native
suppression states are retained as bounded counts only and remain informational:
an accepted scanner or source suppression does not replace the suite's
digest-bound policy acceptance process.
Rule attribution follows both SARIF `ruleId` and positional `ruleIndex`
references across the tool driver and `tool.extensions`. An absent component
reference selects the driver; an extension index or unique component GUID
selects its own rule table, while a supplied component name is verification
only. Nested rule IDs, indexes, and GUIDs must agree with the selected
descriptor, including SARIF's single hierarchical ID component allowance.
Index-only and GUID-only results inherit the exact descriptor title, severity,
classification, and guidance. Contradictory, cross-component, out-of-range,
ambiguous, or malformed references fail parsing instead of attaching unrelated
metadata. The chosen rule and component attribution basis remains available in
normalized and portable SARIF evidence.
Result messages resolve inline text or Markdown, then rule-level message
templates, then the selected driver or extension's `globalMessageStrings`
table. This component-scoped precedence prevents colliding driver and extension
message IDs from changing the reported narrative. Numeric arguments and escaped
braces are expanded with fixed input/output bounds; malformed arguments become
explicit markers and missing placeholders remain visible. Evidence records the
lookup component plus resolution and completeness counts, never raw arguments,
and secret lanes still discard the entire dynamic message fail closed.
Regenerated portable SARIF uses the resolved finding description as its result
message rather than repeating the rule title. Credential redaction runs before
every dynamic-text bound so truncation cannot turn a recognizable token into a
retained, unrecognized fragment.
Artifact paths resolve SARIF `originalUriBaseIds` and per-location `uriBaseId`
chains before repository normalization. Resolution is shared by result
locations and native-flow steps, bounded to 20 ancestors, and fails closed on
missing, malformed, cyclic, over-deep, or external bases. Bounded resolution
counts make path confidence auditable without retaining base identifiers or
credential-bearing URIs.
Run-level SARIF artifact tables are also resolved when a result or native-flow
step supplies only `artifactLocation.index`. Index chains are bounded to 20
indirections and reject invalid types, missing records, absent locations,
cycles, external URIs, and paths outside the scan target with explicit
non-repository states. Direct artifact URIs remain authoritative when present,
which keeps partially redundant producer output usable without trusting a
malformed optional index.
SARIF severity decisions retain their exact basis. A finite `security-severity`
score in the inclusive 0-10 range remains the strongest security signal,
including an explicit zero; invalid and non-finite values are counted and
cannot raise priority. Otherwise explicit result level, compatible producer
`problem.severity`, rule `defaultConfiguration.level`, and the SARIF default
`warning` level are considered in order. Non-failure result kinds normalize to
informational regardless of stray failure severity metadata. Result or rule
rank is validated in the inclusive 0-100 range and retained as tool-relative
priority evidence, but it is never converted into cross-tool severity. The
decision, effective native level, score/rank basis, and invalid-input counts are
preserved in normalized and portable SARIF evidence.
When `result.provenance.invocationIndex` selects a run invocation, driver or
extension `ruleConfigurationOverrides` are evaluated before rule defaults.
If provenance is present but its index is omitted, a single run invocation
defaults to index zero as required by SARIF; multiple or absent invocations do
not guess. Evidence distinguishes explicit, defaulted, and unresolved indices.
Descriptor ID, index, GUID, and tool-component references must identify the
same resolved rule; the override list is bounded to 1,000 entries, and exactly
one matching configuration is required. Malformed containers, invalid or
conflicting descriptors, ambiguous matches, out-of-range invocations, and
unresolved tool-component references are counted and ignored. Only validated
`level` and `rank` fields enter the severity decision; arbitrary override
parameters are not retained.
