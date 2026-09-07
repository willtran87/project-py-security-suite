# Professional acceptance and measured detection limits

The acceptance gates distinguish product correctness, public benchmark results,
and production approval. Passing one does not establish the others.

### Imported LDAP factories and bounded native value proofs

`pysec/ldap-factory-filter-injection` tracks native import identities across
module and handler scopes, and verifies the imported factory's available source.
Explicit returns must resolve to `ldap3.Connection` objects; decorated factories,
rebound exports and observed module-attribute overrides are excluded from this
summary. Native object tracking follows receiver aliases and lifecycle calls.
The query uses CodeQL's existing untrusted sources and emits native flow paths.
An existing upstream LDAP flow to the same sink coordinates prevents a duplicate.
Filter escaping is a barrier; DN escaping is modeled as flow into the filter,
consistent with the library's requirement to use
[filter escaping for search input](https://ldap3.readthedocs.io/en/latest/searches.html).

Shared native value proofs additionally cover nonmatching literal string cases
and closed local list sequences. String evaluation is bounded to ASCII text,
128 characters and six reference/subscript steps. List evaluation accepts an
empty, nonescaping local list, at most 16 consecutive discarded append/pop
operations, literal nonnegative pop/read indices and a proved constant selected
element. Aliases, other uses, closures and unsupported mutations reject the proof.
Path/XPath exclusions continue to require complete analysis and retained original
alerts plus native comparison evidence. These bounds are deliberate modeling
limits, not claims of general Python symbolic execution.

The new adversarial corpus also records 15 existing native misses involving list
aliases, element writes, extend, insert and closure mutation across LDAP, path
and XPath sinks. `detection-known-gaps.json` keeps their vulnerable labels and
sources. A test-only native query verifies that no constant-value barrier is
created for them. Those checks measure refinement safety and are reported
separately from successful detection regressions. They do not count as detected
vulnerabilities; a newly detected case must move into the detection gate.

Local validation passes all 154 native CodeQL detection cases, including 26
required retained proof records, and all 15 separate known-gap proof-rejection
checks. The full Python suite passes 1,888 tests and 499 subtests, with 20 skips.
All 100 focused detector/acceptance tests and 36 accuracy-contract tests pass,
along with Ruff, mypy, Pyright, architecture limits, cycle and public API checks.
The 141 Semgrep regression cases and rule bytes are unchanged in this increment.

The complete installed-wheel public benchmark reconciles all 1,236 Python files
in each of Bandit, Semgrep and CodeQL. Combined results change from 295 TP, 148 FP,
157 FN and 630 TN to **308 TP, 118 FP, 144 FN and 660 TN**: precision improves
from 66.6% to 72.3%, and recall from 65.3% to 68.1%. LDAP improves from 0/16 to
13/16 vulnerable cases, with 0 false positives across its 13 safe labels.
CodeQL excludes 61 path/XPath alerts using retained native comparison evidence.
The per-engine reduction is 19 path and 12 XPath false positives; one overlaps
another engine's alert, so the combined reduction is 30.

All 331 existing protected engine/case detections survive. The regression
baseline adds the 13 newly detected LDAP cases, for 344 protections, and tightens
CodeQL FP ceilings from 51 to 32 for path traversal and 30 to 18 for XPath.
LDAP's FN ceiling falls from 16 to 3 and its FP ceiling remains zero. Other
ceilings, public labels and the separate accuracy policy remain unchanged.

The strict overall accuracy gate still fails. LDAP cases `BenchmarkTest00506`,
`BenchmarkTest00895` and `BenchmarkTest00896` remain missed; public XSS recall
remains 0/31. The public corpus guided development and is not an independent
holdout. Upstream LDAP findings outside the new factory summary can still have
different precision limits. This increment does not establish general injection
coverage, independent production approval or industry certification.

Evidence is retained in `.artifacts/ldap-final-native.json`,
`.artifacts/ldap-installed-benchmark.json`,
`.artifacts/ldap-baseline-verification.json`, `.artifacts/ldap-full-pytest.log`
and `.artifacts/ldap-installed-asset-verification.json`. The baseline verification
applies tighter ceilings to the completed measurement without repeating it.
The benchmark and final wheels differ only in adapter line-ending normalization
and the wheel record; their query bytes and adapter syntax trees agree, as recorded
in `.artifacts/ldap-wheel-equivalence.json`. Earlier failed native integration,
stopped evaluation and storage-exhaustion diagnostics remain available; their
interpretation is corrected in `.artifacts/ldap-diagnostic-corrections.json`.

All five final installed-wheel scenarios pass: positive/negative controls,
original identity, relocation, partial extraction and unavailable tools. The
complete scan retains eight native exclusions with original alerts and flow
evidence; the partial scan retains the alerts and applies zero exclusions.
LDAP factory positive/escaping controls and native paths pass through the public
CLI. The installed benchmark and final acceptance report agree on query-asset
digest `2810f341bd823f065853857626c4d80dbbad56a91993189c02e5642215ef1160`.
Final evidence is in `.artifacts/ldap-installed-acceptance.json`, with the
complete scan's native evidence and manifest separately retained in
`.artifacts/ldap-installed-complete-codeql-evidence.json` and
`.artifacts/ldap-installed-complete-manifest.json`.

### Native statement-branch precision increment

The CodeQL comparison model now handles direct assignment values in unreachable
`if` bodies and `else` branches. It uses the existing bounded integer evaluator
and native local SSA definitions to prove the condition. It does not discard a
variable's other uses or suppress alerts based on local AST review hints. The
original flow must exist, every refined flow to the sink must be absent, and
complete native analysis must support the comparison before an alert is excluded.

Twenty additional path/XPath cases cover both unreachable branches, reachable
input, reassignment, unknown conditions, phi bindings, escaping closures, loops,
unsupported arithmetic and reintroduced taint. All 69 native CodeQL cases pass,
including 22 required proof records. Installed acceptance additionally checks
live and unreachable branches for both sink types, retains original alerts and
native proof records, and requires partial scans to retain the original alerts.

The complete three-engine public measurement reduced combined false positives
from 160 to 148: six path cases and six XPath cases. True positives remain 295,
false negatives 157, and true negatives increase to 630. Combined precision is
66.6%, with recall unchanged at 65.3%. All 1,236 Python files reconciled for every
engine and all 331 protected engine/case detections remained. CodeQL FP ceilings
tighten from 57 to 51 for CWE-22 and from 36 to 30 for CWE-643. False-negative
ceilings, protected detections, public labels and the accuracy policy are unchanged.
The stricter accuracy gate still fails; this is development evidence, not an
independent production evaluation.

The removed false positives are path cases `00086`, `00174`, `00352`, `00525`,
`00611`, `00913` and XPath cases `00105`, `00467`, `00468`, `00935`, `01028`,
`01031` (each prefixed `BenchmarkTest`).

Final local verification passed 93 focused tests, all 69 native CodeQL cases,
and all five installed-wheel scenarios. The complete installed scan retained
the branch alerts and their native proof records as exclusion evidence; partial
extraction retained the alerts and applied zero exclusions. Native validation,
the external benchmark and installed query assets agree on their bytes. Lint,
formatting, architecture limits and public API checks passed. The existing
Semgrep rules were unchanged; the full Python test suite was not rerun for this
query-only product change.

Local evidence is retained in `.artifacts/branch-native-detection.json`,
`.artifacts/branch-external-benchmark.json`,
`.artifacts/branch-baseline-verification.json`, and
`.artifacts/branch-installed-acceptance.json`. The baseline verification applies
the tightened ceilings to the completed measurement without repeating the scan.

The initial LDAP diagnostics incorrectly attributed zero results to request-taint
propagation. Those runs reused cached query results after the query changed.
Fresh evaluation established that native request sources already work; the
remaining import-binding gap concerns module imports outside the handler.
Supplemental analyses now explicitly request reevaluation. The retained initial
diagnostics are superseded by fresh runs, not evidence of a source-model defect.
General XSS coverage and independent holdout validation remain open.

### Narrow injection coverage and repeatability qualification

Two additional bundled Semgrep rules cover specific, reviewable cases:

- `python.request-to-ldap` follows Flask request values into an LDAP search filter
  when the receiver is an inline `ldap3.Connection(...)` or its construction is
  the immediately preceding statement. Positional and keyword filter arguments
  and import aliases are supported. Real filter escaping is modeled; ignored
  escaping, DN escaping, HTML escaping and helpers named like encoders do not
  remove the finding. Factory-returned connections, intervening statements and
  receiver aliases are outside this rule's scope.
- `python.request-to-unsafe-html` detects direct Flask request reads passed to
  `markupsafe.Markup` or `django.utils.safestring.mark_safe`. This reports unsafe
  trust marking, without claiming that the value is subsequently rendered.
  It deliberately does not follow variable aliases or general string operations:
  MarkupSafe concatenation and formatting can escape inputs automatically.
  Escaped values, autoescaped templates, JSON responses and safe MarkupSafe
  operations have negative controls. This is not general reflected-XSS coverage.

The native Semgrep gate now contains 141 cases, including 39 new injection
controls. Both rules are also exercised through installed-wheel scans with
positive and negative inputs, source relocation and stable finding identities.
The broader HTML taint prototype was rejected because it could flag safe
MarkupSafe concatenation. The initial LDAP prototype's zero-result measurement
was subsequently invalidated by cached query reuse, as described above.

The LDAP encoder model handles simple-name arguments and literal-key source
reads without hiding nested operations. Installed acceptance exposed a false
positive for a directly escaped request lookup; that case and nested unsafe
calls inside encoder arguments are now included in the native regression gate.
Single-argument request reads are enumerated separately to retain nested sources
inside another request lookup's default value. The gate includes both unsafe
and static-filter controls for this case.

Product and qualification scans explicitly use two Semgrep workers. Six initial
full-corpus scans, three each at 14 and two workers, were complete and identical.
Neither setting reproduced the previously observed internal timeout. This
comparison does not establish that reducing workers fixes that upstream issue.

`scripts/qualify_semgrep.py` runs a fixed number of attempts (three by default)
against an existing source corpus. Each attempt compares names and exact Python
source bytes before and after execution and against the first observed input.
The runner also checks rule and launcher bytes before and after each execution.
Changed inputs, native errors, incomplete coverage, version changes and finding
drift fail qualification; later success cannot erase an earlier failure. Reports
retain digests, counts and failure categories without source text. The launcher
digest is not a digest of the entire engine installation, and boundary snapshots
cannot detect a change that is restored within an execution. Product scan
isolation remains a separate control.

Inputs are limited to 10,000 Python files, 1 MiB per file, 64 MiB total and 100,000
filesystem entries. Links and empty Python inventories fail qualification. CI
runs this gate on the pinned public corpus and retains the attempt report even
when the gate fails. The final three local repetitions reconciled all 1,236
Python files and retained the same 179 normalized Semgrep findings as the prior
rules. These additions therefore do not improve the current public benchmark's
LDAP or XSS recall. Accuracy targets and protected-detection baselines remain
unchanged; production effectiveness approval is still outstanding.

Local validation for this increment passed 1,883 unit/integration tests (20
skipped), all 141 native Semgrep cases, three full-corpus repetitions, and all
five installed-wheel scenarios. The final Bandit/Semgrep external measurement
was complete and passed its existing regression gate. Final rule digests agree
across native validation, repeatability, benchmark and installed package bytes.
Type checks, lint, workflow syntax, architecture and public-API gates also passed.
CodeQL implementation and query assets were unchanged in this increment; its
previous native validation and three-engine measurement below were not rerun.

The models follow the documented semantics of
[ldap3 filter escaping](https://ldap3.readthedocs.io/en/latest/searches.html) and
[MarkupSafe trust marking](https://markupsafe.palletsprojects.com/en/stable/escaping/)
and [formatting](https://markupsafe.palletsprojects.com/en/stable/formatting/).

### Native CodeQL precision increment

Native comparison queries now refine path and XPath flows through a narrow class
of constant conditional expressions. They retain the original source/sink models,
path-normalization states and sanitizers, adding only a bounded constant-value
barrier. A comparison record is emitted only when the original flow exists and
no refined flow remains to any node at that sink's complete source coordinates.
Live integration requires complete extraction and successful native invocations;
unknown or failed evidence retains the original alerts. Original findings are
resolved and redacted through the normal parser and saved with the comparison
records in `evidence/codeql.json`. Local AST hints do not authorize exclusions.

The public benchmark moved from 172 to 160 combined false positives, with true
positives unchanged at 295 and false negatives unchanged at 157. True negatives
increased to 618. Combined precision is 64.8%, with recall still 65.3%. All 1,236
Python files reconciled in every engine and all 331 protected engine/case
detections remained. The CodeQL false-positive ceilings tighten from 65 to 57 for
CWE-22 and from 40 to 36 for CWE-643; false-negative ceilings, protected cases,
upstream labels and the separate accuracy policy remain unchanged.

The twelve removed combined false positives are path cases `00004`, `00010`,
`00091`, `00094`, `00095`, `00354`, `00360`, `00441` and XPath cases `00106`,
`00465`, `00680`, `00762` (each prefixed `BenchmarkTest`). That earlier refinement
did not handle constant `if` statements such as `BenchmarkTest00086`; the
statement-branch increment above extends that model.

The native regression corpus adds 44 path/XPath cases to the five credential
cases, covering arithmetic comparisons, reassignment, phi bindings, escaping
closures, unsupported operators, large intermediates, and competing taint flows.
Validation attempts under the earlier 600-second stage budget hit a Windows
native quota and remain failed artifacts. The expanded validation now separates
primary and supplemental stages, with a bounded 1,200-second budget per stage
and a 4 GiB CodeQL memory hint. Product scanner quotas and the accuracy policy
are unchanged; this larger developer gate compiles and evaluates more queries.
All 49 native CodeQL cases pass, including 18 required comparison records. These
additional global analyses add runtime: initial local CodeQL measurements rose
from 273 seconds to 420–459 seconds. Those runs shared the host with other work
and are not a controlled performance benchmark.
Final local verification passed 1,873 tests, with 20 skips and 499 passing
subtests. All five installed-wheel acceptance scenarios passed; the complete
scan retained excluded-alert evidence, while incomplete extraction excluded
nothing. Installed adapter and query bytes matched the workspace. The final
benchmark matched the current query digest and passed the tightened baseline,
while correctly failing the unchanged accuracy gate.
The public corpus is development evidence, not an independent holdout; the
strict accuracy gate still fails. The earlier Semgrep timeout remains unresolved.

### Path precision and repeatability increment

The Semgrep path rule now excludes only value occurrences in branches whose
conditions its native evaluator proves unreachable. Unknown conditions and
reachable branches remain tainted. The model also propagates identity and `str()`
list-comprehension elements. Constant bodies and encoded bodies are negative
controls. A narrowly scoped `secure_filename` model accepts a simple-name
argument without clearing other uses of that variable; nested path operations
remain detectable. Arbitrary helper names are not trusted.

The expanded regression corpus has 102 Semgrep cases, including live/dead branch
pairs, arithmetic conditions, reassignment, aliases, ignored sanitizer returns,
and a path operation nested inside an encoder. Native validation runs a fixed
three attempts by default and keeps every result. A timeout, missing file,
malformed output, engine-version change, classification drift, duplicate finding,
or lost finding cannot be hidden by a subsequent successful attempt.

The reviewed public path change removes Semgrep alerts on negative-labeled cases
`BenchmarkTest00086`, `BenchmarkTest00095`, and `BenchmarkTest00441`: each selects
a fixed value through a constant condition. Its false-positive ceiling tightens
from eight to five; the false-negative ceiling and all protected detections remain
unchanged. These cases still have CodeQL alerts, so this is an engine-specific
precision improvement, not a reduction in the combined false-positive count.
That increment did not refine CodeQL findings; the independent accuracy policy
remains unchanged.

The Semgrep increment's three-engine run completed its native coverage checks and passed the
strengthened regression baseline. Combined counts remain 295 true positives,
157 false negatives, 172 false positives and 606 true negatives; all 331 protected
engine/case detections remain. The strict accuracy command still exits nonzero
because the separate accuracy thresholds fail. This final run does not invalidate
the intermittent timeout evidence from earlier retained runs.

Three identical full-corpus native diagnostic scans reproduced a timeout once,
on the path rule in `BenchmarkTest00468`; the other two did not time out. Candidate
scans also exposed timeouts in other functions. The pinned Semgrep implementation
sets its internal taint fixpoint limit to 0.2 seconds, independently of the outer
scan deadline ([pinned engine limits](https://github.com/semgrep/semgrep/blob/v1.175.0/src/configuring/Limits_semgrep.ml)).
This identifies the limit, not a proven cause of the variable execution time.
The engine timeout remains unresolved; no limit was raised and no failing run
was discarded. Broad production readiness remains unestablished.

### Current qualification: native dataflow timeouts

Semgrep 1.175.0 can place dataflow fixpoint timeouts in
`time.fixpoint_timeouts` while returning exit zero, an empty `errors` array,
and a complete scanned-file inventory. The adapter now counts these failures,
retains valid findings, and marks analysis partial. Malformed profiling metadata
also prevents success. Timeout messages and source paths are not copied into
coverage diagnostics.

A follow-up run against all 1,236 maintained Python files in the pinned public
corpus exposed one such timeout in the existing rules. The Bandit/Semgrep
regression counts remained within their unchanged ceilings, but the benchmark
correctly failed its completion gate. An additional native scan did not reproduce
the timeout, so it must be treated as an intermittent analysis limitation.
Earlier measurements labeled complete predate this check and do not establish
complete dataflow analysis. Their recorded findings remain useful observations.
Do not retry until green and discard the incomplete run.

The injection expansion experiment is not enabled in the bundled rules. Its
broad LDAP candidate produced six correct detections and two false positives
on the public LDAP labels; its broad Flask-return XSS candidate produced six
correct detections and eleven false positives, with a dataflow timeout also
reported. These are development observations, not accepted detection gains.
The accuracy thresholds, protected detections, and regression ceilings remain
unchanged. Framework-specific flow models and independent validation remain
necessary before claiming professional detection coverage.

## Installed product acceptance

`scripts/validate_product_acceptance.py` requires a wheel installed into a clean
environment. It starts Python with `-I`, verifies the package came from
`site-packages`, creates sources outside the checkout, and invokes the public
`pysec scan` command. It verifies the resulting report seal with the installed
package. No target application code is executed.

The required CI matrix covers Windows, Linux, and macOS. A separate Linux lane
adds the pinned CodeQL CLI, runner, primary queries and supplemental libraries.
Assertions cover:

- Expected findings and a parameterized SQL negative control.
- Parser failures that retain valid findings and report partial coverage,
  including a CodeQL extraction warning despite an otherwise successful invocation.
- Python file inventory reconciliation for Bandit, Semgrep, and CodeQL.
- An unavailable scanner that publishes an incomplete, verifiable report.
- Cross-file credential, SQL, SSRF and filesystem paths through CodeQL, with
  retained SARIF traces.
- Bundled query and dependency lock files in the installed wheel.
- Diagnostic scans remaining `incomplete`, without acquiring release approval.

The functional acceptance run intentionally uses the documented diagnostic mode.
The existing containment integration lanes remain responsible for validating
actual egress denial. An offline scanner configuration is not an egress boundary.

Local preparation follows the same locked workflow:

```text
uv sync --locked --project containers/scanner --python 3.13
uv build --wheel --no-sources --out-dir .artifacts/acceptance-dist
uv export --frozen --no-dev --no-emit-project --output-file .artifacts/acceptance-requirements.txt
uv venv .artifacts/acceptance-env --python 3.13
```

Install the exported requirements with `uv pip install --require-hashes`, then
install the wheel with `--no-deps`. Run the acceptance script with absolute
`--python`, `--bandit`, and `--semgrep` paths. To include CodeQL, also supply
`--codeql`, `--codeql-runner`, and an isolated `--codeql-home` containing the
approved packs. `--output` retains structured acceptance evidence.

## Externally authored benchmark

The public OWASP Python v0.1 benchmark supplies 1,230 labels across 14 CWE
categories. Its Git revision, normalized Python source digest and label digest
are pinned in `tests/fixtures/external-benchmark.lock.json`. Source and labels
remain upstream; this package does not redistribute them. The upstream project
describes this version as preliminary, and label disputes remain a limitation.

The measurement copies Python sources into a separate scan root. Expected labels,
repository configuration, and previous scanner results stay outside that root.
Scoring requires both the case identity and the expected CWE, and counts a case
once even when multiple findings match. A different reported CWE does not satisfy
the label: these metrics measure matching detection/classification labels, not
exploit reproduction. Wilson intervals describe sampling uncertainty; synthetic
cases are not a representative random sample of production software.

```text
python scripts/benchmark_external.py --source PATH_TO_PINNED_CHECKOUT --lock tests/fixtures/external-benchmark.lock.json --baseline tests/fixtures/external-benchmark.baseline.json --bandit ABSOLUTE_BANDIT --semgrep ABSOLUTE_SEMGREP --output .artifacts/benchmark/external.json
```

Use the locked Python 3.13 scanner environment. The older local Python 3.11
Bandit environment could not parse 470 upstream cases with newer Python syntax;
the coverage gate rejected that measurement as partial. This is why runtime
compatibility and successful parsing must precede any accuracy claim.

The initial Bandit/Semgrep measurement, reported complete before the profiling
timeout check above, produced 115 true positives,
337 false negatives, 36 false positives and 742 true negatives under this exact
case/CWE method. These are the combined results for those two engines, not the
full deep profile. CodeQL is now also measured in the three-engine Python
source-security benchmark described below. The public baseline exposes substantial gaps; it is not a production
accuracy target. The CI regression gate rejects increases in false positives or
false negatives in any engine/CWE pair, and rejects incomplete measurements.
Changing a baseline requires reviewing the case-level rationale and retained
evidence, not merely accepting a new aggregate score.

Baselines also carry `protected_detections`, indexed by engine and expected CWE.
Each protected positive case must remain detected by that engine with its exact
CWE. New detections cannot compensate for losing a protected case. Missing case
evidence, duplicate identities, changed labels, and invalid protection entries
fail the check. Aggregate false-positive and false-negative ceilings still apply.
These baseline identities are only used after scanning; they are never input
to a detector or used as rule exemptions.

## Three-engine measurement and accuracy targets

Supply `--codeql`, `--codeql-runner`, and `--codeql-home` together to measure the
Bandit, bundled Semgrep, primary CodeQL security-and-quality, and supplemental
CodeQL query results in one run. This `python-source-security` profile measures
the three source-analysis engines. It does not exercise every adapter or every
orchestration/reporting stage in the configurable `deep` product profile;
installed-product acceptance tests those stages separately.

```text
python scripts/benchmark_external.py --source PATH_TO_PINNED_CHECKOUT --lock tests/fixtures/external-benchmark.lock.json --baseline tests/fixtures/external-benchmark-source-security.baseline.json --bandit ABSOLUTE_BANDIT --semgrep ABSOLUTE_SEMGREP --codeql ABSOLUTE_CODEQL --codeql-runner ABSOLUTE_RUNNER --codeql-home ABSOLUTE_APPROVED_HOME --accuracy-policy tests/fixtures/external-benchmark.accuracy-policy.json --require-accuracy --output .artifacts/benchmark/source-security.json
```

Schema 1.1 retains every case's expected label, outcome, reported CWEs, rule IDs,
relative finding locations, and whether a CodeQL path trace was retained. It
flags cases with other classifications for review without changing strict
case/CWE scoring. Numeric CWE identifiers are canonicalized (`CWE-089` and
`CWE-89` are the same identifier); different CWE categories are not merged.
Unresolved finding locations invalidate a measurement and unattributed location
samples are retained for diagnosis. Source snippets and raw detector messages are not copied into
case evidence. Reports also include detector versions, executable digests,
runtime platform, rules digests, coverage, and measured durations. These single
run timings are not warm-cache or percentile performance claims.

The separate accuracy policy requires all three engines and targets at least
80% precision, 80% recall, and no more than 10% false-positive rate in every
measured CWE, with at least five positive and five negative cases per category.
These are explicit project engineering targets, not an industry-mandated
threshold or an organization-approved production policy. Undefined precision,
missing categories/engines, insufficient samples, incomplete coverage, invalid
rates, and failed thresholds cannot pass the accuracy gate.

Ordinary CI enforces the reviewed regression ceilings and always publishes the
accuracy decision. `--require-accuracy` additionally returns a failing exit code
when accuracy targets fail. The CI manual-run input `require_detection_accuracy`
enables that strict readiness check. Release assurance always calls the same
reusable accuracy workflow with enforcement enabled, and both independent
release builders depend on its success. Failed accuracy therefore blocks the
release artifact chain. A green ordinary CI run does not mean the accuracy
targets passed. Production approval still requires the independent evidence below.

### Recorded local measurement before the profiling-timeout check

The Windows run with Bandit 1.9.4, Semgrep 1.175.0, and CodeQL 2.26.4 reconciled
all 1,236 Python files in each engine, with no extraction errors or unresolved
finding locations. The 1,230 labeled cases produced:

| Engine selection | True positives | False negatives | False positives | True negatives |
| --- | ---: | ---: | ---: | ---: |
| Bandit | 108 | 344 | 25 | 753 |
| Bundled Semgrep rules | 109 | 343 | 20 | 758 |
| CodeQL primary and supplemental | 114 | 338 | 150 | 628 |
| Combined three-engine result | 295 | 157 | 172 | 606 |

Combined precision is 63.2% and recall is 65.3% under exact case/CWE scoring,
up from 54.1% and 44.9%. This adds 92 correctly classified positive cases without
increasing false positives or losing any of the 239 previously protected
engine/case detections. The strengthened baseline now protects 331 engine/case
detections and tightens Semgrep's weak-hash false-negative ceiling to three and
its insecure-cookie ceiling to zero. No false-positive ceiling was raised.
The separate accuracy policy fails. The strict command exited nonzero as
required while retaining the full measurement. The regression baseline
records the measured improvement; it does not turn these scores into acceptable
production performance. Adding engines finds additional cases and also adds
false alarms, so these measurements support targeted analysis improvements,
not a broad accuracy claim.

Local validation passed 1,818 tests (20 skipped), strict mypy and Pyright,
architecture/API checks, and five installed-wheel acceptance scenarios covering
normal analysis, the original and relocated identity controls, partial analysis,
and an unavailable scanner. Real Semgrep acceptance passed 64 detection cases,
source/rule relocation, and a distinct-origin collision control. Linux/macOS acceptance and the Linux
three-engine benchmark are configured in CI and still require execution there.

### Reviewed source-model baseline changes

The detection-quality increment adds `python.weak-cryptographic-hash` and
`python.response-cookie-insecure`. The hash rule detects direct and named hashlib
constructors, preserves strong-hash negative controls, and respects the explicit
`usedforsecurity=False` declaration. That declaration states non-security intent;
it does not make a weak hash cryptographically safe.

The cookie rule follows known Flask, Django, Starlette, and FastAPI response
objects to `set_cookie(..., secure=False)`. It follows aliases and drops an
unrelated reassignment. It does not yet diagnose omitted flags, every response
subclass, or deployment-wide cookie policy. Severity remains a warning and
cookie sensitivity and HTTPS deployment still require review.

All 71 original weak-hash positives already had Bandit B324 evidence classified
as CWE-327. The new rule supplies the precise CWE-328 classification without
globally equating these CWEs or rewriting native Bandit evidence. The remaining
Semgrep misses in this category are `BenchmarkTest00485`, `BenchmarkTest00582`,
and `BenchmarkTest00708`; all contain match statements before the hash constructor.
This correlation is recorded for further engine investigation, not a proven
root cause or a reason to change the upstream labels. Weak-hash score gains must
not be described as newly discovering vulnerabilities that Bandit already flagged.

The expanded real-detector corpus includes 64 cases, including response aliases,
rebinding, secure cookies, strong hashes, explicit non-security hashing, and
unrelated APIs. Installed acceptance also requires the two new rules, precise
CWE classification, and secure negative controls through the public scan CLI.
These are development regressions, not independent or unseen application evidence.

The API semantics are documented by [Python hashlib](https://docs.python.org/3/library/hashlib.html),
[Flask cookie security](https://flask.palletsprojects.com/en/stable/web-security/),
and [Bandit B324](https://bandit.readthedocs.io/en/latest/plugins/b324_hashlib.html).

The header/cookie source expansion adds detections for the positive path cases
`BenchmarkTest00449` and `BenchmarkTest01196`, and the positive SQL case
`BenchmarkTest00454`. It also flags two negative-labeled path cases:

- `BenchmarkTest00441`: Semgrep taint analysis does not resolve the constant
  arithmetic branch that selects a fixed filename. This is a false positive.
- `BenchmarkTest00442`: the code rejects `../` but still accepts backslash
  traversal on Windows. The upstream negative label is retained unchanged;
  the alert counts as a false positive in this benchmark, with the platform
  limitation recorded for review.

The reviewed Semgrep path ceiling changes from six to eight false positives and
63 to 61 false negatives; SQL false negatives decrease from five to four. The
independent accuracy targets remain unchanged. This is a documented recall/
precision tradeoff, not evidence of improved precision or an unseen evaluation.
No benchmark identifiers or special-case exemptions are used in detection rules.

Public benchmark results must not be relabeled as an unseen holdout or independent
certification. Production effectiveness approval still uses the existing
signed-corpus, trusted-time, replay-protected evaluation described in
[effectiveness.md](effectiveness.md). Representative application pilots,
independently reviewed labels, organization-approved accuracy thresholds, and
external security review remain required evidence before making broad readiness
claims. NIST SSDF provides a framework for organizing this release evidence.

## Scanner execution boundary

### Stable identity and review evidence

Every bundled Semgrep rule declares a stable `pysec_rule_id`. The adapter keeps
native origin information for collision checks and uses governed metadata for
public finding identities. Real acceptance scans
relocate both the source and rule files and require identical rule IDs, finding
IDs, and fingerprints. Installed-wheel acceptance also relocates the source
through the public CLI with the same scanner selection on each run. A native
collision control verifies that distinct rule origins cannot claim one governed
ID. Governed rule bytes use the repository's LF policy, with a test binding the
model-manifest digests to those exact bytes. Legacy findings whose IDs included temporary configuration
paths can appear as newly identified findings after this change. Review that
one-time baseline transition; do not automatically transfer suppressions by
matching only a rule-name suffix. Colliding governed native origins remain errors.

CodeQL path and XPath alerts can carry `constant_sink_review` evidence when a
bounded local AST evaluation finds an entirely constant string argument. The
review includes the finding identity, location, decoded-source digest, reason,
and limitation, without copying literal values. Findings with this hint remain
actionable: the hint does not suppress, downgrade, validate, or change their
classification. Local syntax alone cannot establish runtime call binding or the
native query's sink semantics. Unknown imports, unsupported execution constructs,
ambiguous lines, and exhausted budgets produce no hint. The benchmark records
these reviews separately and keeps the original detection counts and labels.
The initial post-scan evaluation identified seven XPath review candidates, all
upstream negative cases. That local review alone did not change detection counts.
The separate native refinement described in [effectiveness](effectiveness.md)
requires complete native flow comparisons and keeps original findings in report
evidence. Local review hints still cannot remove alerts.

The evaluator never runs target code. Source and AST sizes are bounded by the
shared parser; the additional cache holds at most four ASTs. Expression depth,
evaluation steps, strings, and integer sizes have explicit limits. Review work
uses the same CodeQL deadline and the same sealed source mirror as native analysis.

### Native analysis

CodeQL consumes one sealed dependency snapshot for primary and supplemental
analysis. SARIF and mirrored source reads are bounded regular-file operations.
A shared deadline begins before preparation, with cooperative checks during
asset reads, copying, and stage transitions. Individual blocking filesystem or
OS operations cannot be preempted by these checks. Native execution remains
bounded by process supervision. Resource diagnostics distinguish measured
memory, output, scratch and wall-clock failures; an ambiguous Windows quota exit
is labeled `native-quota` rather than guessing its cause.

Bandit, Semgrep, and CodeQL compare a pre-execution Python inventory with engine-reported
files. Missing metadata produces `unknown`; missing, unexpected, invalid, or
failed files produce `partial`. Either state retains findings but prevents a
completed result. CodeQL uses successfully-extracted-file notifications and
also checks warnings and invocation success: a file can be reported extracted
while a syntax error prevents complete analysis. SARIF artifact lists alone
are not treated as coverage evidence. This inventory reconciliation covers these three
engines and maintained Python files; it does not claim independent file-level
coverage for every other adapter or language.

For locally generated CodeQL SARIF, the adapter binds an omitted `%SRCROOT%`
definition to the exact mirrored source directory used to create the database.
It preserves explicit base definitions and still rejects outside-target paths.
Imported SARIF keeps the generic unresolved-base behavior; it does not inherit
this native execution context.

Large native SARIF has a dedicated two-million-node, 64 MiB character budget,
in addition to each adapter's byte limit. The general governance JSON limit is
unchanged. Duplicate keys, non-finite numbers, excessive nesting, and oversized
strings remain rejected.

Sources: [OWASP Benchmark](https://owasp.org/www-project-benchmark/),
[NIST SSDF](https://csrc.nist.gov/pubs/sp/800/218/final).
