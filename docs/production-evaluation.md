# Production evaluation work package

Last reviewed: 2026-09-08

The implemented controls support a controlled professional pilot. A general
production-readiness decision still needs the evidence below. The public OWASP
Python corpus has guided detector development and must remain classified as
development data. Its strict accuracy failures are release blockers under the
current project policy.

## Freeze and independently review the application corpus

An evaluator who did not author the detector changes should select representative
Flask, Django and FastAPI applications and freeze their source revisions. For each
reviewed case, retain the application revision and source digest, CWE, expected
vulnerable or fixed result, affected route and source/sink locations, reproduction
or code-review rationale, reviewer identity and review date. Include safe paired
controls, overlapping hook names, imported factories, framework escaping and
collection mutation patterns. Do not infer a safe label from a missing finding.

Separate corpus authorship, detector implementation and the release decision.
The reviewer must record disagreements and unresolved labels before measurements
are used for approval. Freeze the scanner wheel, rules, tool versions and policy
before revealing holdout results to detector authors. If those results guide a
detector change, move that corpus into development evidence and select a fresh
holdout for the subsequent independent decision.

Use the existing [governed benchmark execution and receipt workflow](benchmark-operations.md)
to bind source, labels, toolchain and semantic evidence to the deployment's
authorized evaluator. A local aggregate report does not replace that workflow or
authorize a signer. No independent reviewer or holdout has been supplied for the
current increment, so independent approval remains outstanding.

## Measure the supported operating range

Qualification now separates runtime identity verification from native scan time.
Use those measurements to identify the actual bottleneck before changing integrity
checks. One corpus and three repetitions do not establish a maximum supported
repository size or a latency percentile.

| Evaluation | Required observation | Acceptance decision |
| --- | --- | --- |
| Representative small, typical and largest intended repositories | File and byte inventory, cold/warm wall time, full coverage, process-tree memory and temporary storage | Declare supported sizes only for completed measured runs |
| Intended concurrent scan load | Per-run identities, throughput, peak resource use and isolated output directories | No mixed evidence, lost results or unintended shared state |
| Cancellation and timeout during each major phase | Process-tree termination, remaining evidence and cleanup/recovery behavior | Incomplete work stays incomplete and a subsequent run recovers |
| Constrained storage | Failure before writing, during report replacement and during native extraction | Prior evidence remains valid; partial reports cannot pass |
| Supported Windows and Linux release environments | Required CI gates against the same built wheel, locked dependencies and native tools | Local Windows results cannot stand in for an unexecuted Linux job |

The current increment has local regression coverage for interrupted checkpoints,
concurrent archive creation and an injected disk-full write failure. These are
functional controls, not completed native load or capacity measurements. Real
capacity limits and remote release jobs remain to be established on the intended
deployment hosts.

## Keep release decisions explicit

The current source-security policy requires the configured engines, minimum case
counts and per-CWE precision and recall of at least 0.8, with false-positive rate
at most 0.1. The policy file is authoritative. Preserve all protected engine/case
detections when improving the model; aggregate gains cannot conceal lost cases.

XPath, path traversal, remaining XSS misses and unsupported mutation flows need
further detector work. Nonliteral dynamic imports still have uncertain module
identity and retain medium-precision treatment. Keep those limits visible in
customer-facing scope and release evidence until they are measured and resolved.

The release authority should review the [generated measurements](validation-results.md),
the independent corpus record, supported operating range and required remote CI
results together. Passing local functional checks is useful evidence; it does not
by itself grant production approval or certification.
