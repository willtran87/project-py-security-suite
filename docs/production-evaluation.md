# Production evaluation work package

Last reviewed: 2026-09-12

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
functional controls, not completed native load or capacity measurements. Capacity
limits must be measured on the intended deployment hosts. Cross-platform CI and
the Linux production-container self-scan are recorded separately in the
[current acceptance evidence](professional-acceptance.md#current-validation-increment).
`scripts/qualify_native_capacity.py` now provides fixed serial
and concurrent real-scanner waves, report verification, resource measurements and
a native-phase cancellation check. Run it with an installed wheel, frozen source,
explicit scanner configuration and predeclared timeout/resource budgets. The first
full-repository 300-second pilot failed before native scanning and retained a
valid incomplete report; do not use it as a passing capacity measurement.

The host capacity driver explicitly records missing external network-isolation
attestation. It accepts that one policy reason for diagnostic timing only;
missing scanner evidence, partial coverage, other incomplete reasons and invalid
reports still fail. These host measurements never confer production qualification.

For the current full-repository measurement, the frozen input contains 4,200 files
and 51,247,813 bytes. The explicit configuration selects Bandit and Semgrep only,
with two scanner workers per scan, a 900-second scan deadline and 180-second
per-tool deadlines. Three serial waves and three waves of two concurrent scans
are required, followed by scanner-phase cancellation. The wave budgets
are 2 GiB sampled process-tree memory and 1 GiB private scratch, and cancellation
must produce a verified incomplete report within 15 seconds. These inputs and
budgets were fixed before the run; an unfinished or failed repetition cannot
establish a supported range.

The final wheel passes this complete diagnostic qualification. All nine ordinary
scans complete both engines, preserve source integrity, verify their reports and
produce identical finding identities. Source, configuration and installed package
bytes remain unchanged. Scanner-phase cancellation takes 12.580 seconds through
report verification and leaves source identity explicitly unverified.

| Concurrent scans | Complete waves | Wave wall time (seconds) | Peak observed RSS (MiB) | Peak observed private scratch (MiB) |
| --- | ---: | --- | ---: | ---: |
| 1 | 3 | 455.321–541.816 | 865.0 | 66.9 |
| 2 | 3 | 450.150–478.137 | 1,623.8 | 133.9 |

Wave time includes worker supervision and startup; individual ordinary scans take
443.532–536.891 seconds. The ten retained reports occupy approximately 867.7 MiB,
separately from private scratch and external runtime caches. Sampling includes a
100 ms pause plus collection overhead, so peaks between observations may be missed.

The record is `.artifacts/release-repair/capacity9-final.json`, run
`8ffbb1d16ced42778a29654653660bd5`, SHA-256
`8756b7ce2efd8c5a479fa6d5653fd350121ccc1cf1f77af439620f8d2d5278d7`.
It binds the same wheel as the [generated validation results](validation-results.md).
The earlier reference wheel completed its nine ordinary scans but failed its
47.145-second cancellation check; that failed qualification remains retained in
`capacity2-final.json` and is not part of this passing result.

A separate direct probe observes the actual native Bandit scan command after at
least one CPU-second, requests cancellation, confirms the observed process has
terminated and verifies the resulting incomplete report. Cancellation through
report verification takes 6.370 seconds; the same installed wheel remains intact
and post-scan source identity remains unverified. This distinguishes active-engine
cancellation from the capacity driver's scanner-phase callback. The local record
is `active-cancel9.json`, SHA-256
`2530c2398017e17e946523cc8dbe127261248cc1ebec389f8a4fda7686e6206a`;
it binds the retained `probe_active_cancellation.py` source by digest. This one
Bandit observation does not qualify every engine or cancellation phase.

The recorded host is Windows 10.0.19045 with Python 3.14.5. Other validation work
is concurrent on this host, and neither the OS filesystem cache nor storage
hardware is reset between repetitions. Even a passing run establishes only the
recorded diagnostic workload, not cold-cache latency, a service percentile, all
production scanners, Linux concurrency or a maximum supported repository size.

## Keep release decisions explicit

The current source-security policy requires the configured engines, minimum case
counts and per-CWE precision and recall of at least 0.8, with false-positive rate
at most 0.1. The policy file is authoritative. Preserve all protected engine/case
detections when improving the model; aggregate gains cannot conceal lost cases.

The 15 tracked collection-mutation misses now pass native regression checks with
paired safe overwrites. XPath, path traversal and remaining XSS benchmark errors
still require measured evaluation against the unchanged accuracy policy.
Nonliteral dynamic imports still have uncertain module
identity and retain medium-precision treatment. Keep those limits visible in
customer-facing scope and release evidence until they are measured and resolved.

The release authority should review the [generated measurements](validation-results.md),
the independent corpus record, supported operating range and required remote CI
results together. Passing local functional checks is useful evidence; it does not
by itself grant production approval or certification.
