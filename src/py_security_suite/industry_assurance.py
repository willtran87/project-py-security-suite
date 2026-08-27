from __future__ import annotations

import math
import uuid
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .path_safety import read_regular_file
from .strict_json import loads as strict_loads


_POLICY_PATH = "security/industry-assurance-policy.json"
_MAX_POLICY_BYTES = 4 * 1024 * 1024
_DIGEST = "0123456789abcdef"

_STANDARDS: tuple[dict[str, Any], ...] = (
    {
        "id": "OWASP-ASVS",
        "version": "5.0.0",
        "kind": "verification",
        "reference": "https://owasp.org/www-project-application-security-verification-standard/",
        "evidence": ["security-requirements-coverage.json"],
    },
    {
        "id": "OWASP-MASVS",
        "version": "2.1.0",
        "kind": "verification",
        "reference": "https://mas.owasp.org/MASVS/",
        "evidence": ["security-requirements-coverage.json"],
    },
    {
        "id": "OWASP-TCASVS",
        "version": "5.0.0",
        "kind": "verification",
        "reference": "https://github.com/OWASP/TCASVS",
        "evidence": ["security-requirements-coverage.json"],
    },
    {
        "id": "NIST-SSDF",
        "version": "1.1",
        "kind": "lifecycle",
        "reference": "https://csrc.nist.gov/pubs/sp/800/218/final",
        "evidence": [
            "capability-manifest.json",
            "finding-validation.json",
            "effectiveness.json",
        ],
    },
    {
        "id": "NIST-CSF",
        "version": "2.0",
        "kind": "governance",
        "reference": "https://www.nist.gov/cyberframework",
        "evidence": ["capability-manifest.json", "domain-assurance.json"],
    },
    {
        "id": "OWASP-SAMM",
        "version": "2.1.0",
        "kind": "maturity",
        "reference": "https://owaspsamm.org/model/",
        "evidence": ["capability-manifest.json", "effectiveness.json"],
    },
    {
        "id": "OpenSSF-OSPS",
        "version": "2026.02.19",
        "kind": "project-baseline",
        "reference": "https://baseline.openssf.org/versions/2026-02-19",
        "evidence": [
            "capability-manifest.json",
            "scanner-trust.json",
            "trust-policy-attestation.json",
        ],
    },
    {
        "id": "CWE-TOP-25",
        "version": "2025",
        "kind": "weakness-taxonomy",
        "reference": "https://cwe.mitre.org/top25/",
        "evidence": ["finding-validation.json", "effectiveness.json"],
    },
    {
        "id": "OWASP-TOP-10",
        "version": "2025",
        "kind": "risk-taxonomy",
        "reference": "https://owasp.org/Top10/2025/",
        "evidence": ["finding-validation.json", "application-contract-analysis.json"],
    },
    {
        "id": "OWASP-API-TOP-10",
        "version": "2023",
        "kind": "risk-taxonomy",
        "reference": "https://owasp.org/API-Security/editions/2023/en/0x00-toc/",
        "evidence": [
            "application-contract-analysis.json",
            "runtime-surface-binding.json",
        ],
    },
    {
        "id": "CAPEC",
        "version": "policy-pinned",
        "kind": "attack-pattern-taxonomy",
        "reference": "https://capec.mitre.org/",
        "evidence": ["risk-paths.json", "llm-adversarial-plan.json"],
    },
    {
        "id": "MITRE-ATTACK",
        "version": "policy-pinned",
        "kind": "adversary-taxonomy",
        "reference": "https://attack.mitre.org/",
        "evidence": ["risk-paths.json", "advanced-analysis.json"],
    },
    {
        "id": "MITRE-ATLAS",
        "version": "policy-pinned",
        "kind": "ai-adversary-taxonomy",
        "reference": "https://atlas.mitre.org/",
        "evidence": ["llm-adversarial-plan.json"],
    },
    {
        "id": "OWASP-LLM-TOP-10",
        "version": "2025",
        "kind": "ai-risk-taxonomy",
        "reference": "https://genai.owasp.org/llm-top-10/",
        "evidence": ["llm-adversarial-plan.json"],
    },
    {
        "id": "NIST-AI-RMF",
        "version": "1.0",
        "kind": "ai-risk",
        "reference": "https://airc.nist.gov/RMF_Knowledge_Base/AI_RMF",
        "evidence": ["llm-adversarial-plan.json", "domain-assurance.json"],
    },
    {
        "id": "NIST-AI-600-1",
        "version": "1.0",
        "kind": "generative-ai-profile",
        "reference": "https://doi.org/10.6028/NIST.AI.600-1",
        "evidence": ["llm-adversarial-plan.json"],
    },
    {
        "id": "ISO-IEC-25010",
        "version": "2023",
        "kind": "product-quality",
        "reference": "https://www.iso.org/standard/78176.html",
        "evidence": ["code-health.json", "effectiveness.json"],
    },
    {
        "id": "ISO-IEC-IEEE-42010",
        "version": "2022",
        "kind": "architecture-description",
        "reference": "https://www.iso.org/standard/74393.html",
        "evidence": ["static-architecture.json", "architecture-history.json"],
    },
    {
        "id": "CISQ-QUALITY",
        "version": "2020",
        "kind": "quality-measures",
        "reference": "https://www.omg.org/spec/ASCQM/",
        "evidence": ["code-health.json", "static-architecture.json"],
    },
)

_BENCHMARKS: tuple[dict[str, Any], ...] = (
    {
        "id": "pysec-governed-holdout",
        "version": "2.0",
        "kind": "labeled-corpus",
        "source": "installed effectiveness corpus contract",
        "languages": ["multi"],
        "lane": "core-verified-report",
    },
    {
        "id": "owasp-benchmark",
        "version": "policy-pinned",
        "kind": "sast-dast",
        "source": "https://owasp.org/www-project-benchmark/",
        "languages": ["java", "python"],
        "lane": "authorized-companion",
    },
    {
        "id": "nist-sard-juliet",
        "version": "1.3",
        "kind": "sast",
        "source": "https://samate.nist.gov/SARD/",
        "languages": ["c", "cpp", "java", "csharp"],
        "lane": "authorized-companion",
    },
    {
        "id": "owasp-juice-shop",
        "version": "policy-pinned",
        "kind": "dast",
        "source": "https://owasp.org/www-project-juice-shop/",
        "languages": ["javascript"],
        "lane": "authorized-companion",
    },
    {
        "id": "owasp-webgoat",
        "version": "policy-pinned",
        "kind": "dast",
        "source": "https://owasp.org/www-project-webgoat/",
        "languages": ["java"],
        "lane": "authorized-companion",
    },
    {
        "id": "owasp-crapi",
        "version": "policy-pinned",
        "kind": "api-dast",
        "source": "https://owasp.org/www-project-crapi/",
        "languages": ["api"],
        "lane": "authorized-companion",
    },
    {
        "id": "cyberseceval-2",
        "version": "2",
        "kind": "llm-security",
        "source": "https://github.com/meta-llama/PurpleLlama/tree/main/CybersecurityBenchmarks",
        "languages": ["multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "python-real-world-holdout",
        "version": "organization-pinned",
        "kind": "real-world",
        "source": "organization-approved corpus",
        "languages": ["python"],
        "lane": "authorized-companion",
    },
)

_INTEROPERABILITY = (
    ("SARIF", "2.1.0", ("results.sarif",)),
    ("CycloneDX", "1.6", ("sbom.cdx.json", "artifact-sbom.cdx.json")),
    ("SPDX", "2.x/3.x", ("reuse-compliance.json",)),
    ("CycloneDX-VEX", "1.6", ("risk-intelligence.json",)),
    ("OpenVEX", "0.2", ("risk-intelligence.json",)),
    ("CSAF-VEX", "2.0", ("risk-intelligence.json",)),
    ("OSCAL", "1.1.2", ("oscal-assessment-results.json",)),
)


def build_industry_assurance(
    target: Path, artifacts: dict[str, Any]
) -> tuple[dict[str, dict[str, Any]], list[str]]:
    """Build bounded benchmark, standards, and OSCAL assurance artifacts."""

    target = target.resolve()
    policy, errors = _load_policy(target)
    source_sha256 = _source_sha256(artifacts)
    crosswalk = _crosswalk(artifacts)
    assessment = _assessment(policy, artifacts, crosswalk, errors)
    registry = _benchmark_registry(policy, source_sha256)
    scorecard = _benchmark_scorecard(target, artifacts, registry, source_sha256)
    delta = _benchmark_delta(target, policy, scorecard, errors)
    oscal = _oscal(assessment, source_sha256)
    industry = {
        "schema_version": "1.0",
        "analysis": "industry-standards-and-benchmark-assurance",
        "complete": not errors
        and assessment["complete"] is True
        and (
            scorecard["benchmarks_enabled"] == 0
            or (scorecard["complete"] is True and scorecard["passed"] is True)
        ),
        "policy_present": policy["present"],
        "policy_path": _POLICY_PATH if policy["present"] else None,
        "standards_registered": len(crosswalk["catalogs"]),
        "benchmarks_registered": len(registry["benchmarks"]),
        "controls_assessed": assessment["controls_assessed"],
        "controls_satisfied": assessment["controls_satisfied"],
        "benchmarks_executed": scorecard["benchmarks_executed"],
        "interoperability": _interoperability(artifacts),
        "artifact_contracts": [
            "standards-crosswalk.json",
            "control-assessment.json",
            "benchmark-registry.json",
            "benchmark-scorecard.json",
            "benchmark-delta.json",
            "oscal-assessment-results.json",
        ],
        "parse_errors": errors[:100],
        "claim_boundary": (
            "Registration or evidence mapping is not certification. Benchmark scores "
            "apply only to the pinned corpus, tool set, source, and execution environment."
        ),
    }
    return {
        "industry-assurance.json": industry,
        "standards-crosswalk.json": crosswalk,
        "control-assessment.json": assessment,
        "benchmark-registry.json": registry,
        "benchmark-scorecard.json": scorecard,
        "benchmark-delta.json": delta,
        "oscal-assessment-results.json": oscal,
    }, errors


def _load_policy(target: Path) -> tuple[dict[str, Any], list[str]]:
    default = {
        "present": False,
        "enforce": False,
        "controls": [],
        "benchmarks": [],
        "benchmark_baseline_path": None,
    }
    path = target / _POLICY_PATH
    if not path.is_file():
        return default, []
    try:
        _, payload = read_regular_file(
            path,
            "industry assurance policy",
            maximum_bytes=_MAX_POLICY_BYTES,
            boundary=target,
        )
        value = strict_loads(payload)
        _validate_policy(value)
        return {"present": True, **value}, []
    except (OSError, TypeError, ValueError) as exc:
        return {**default, "present": True}, [f"{_POLICY_PATH}: {type(exc).__name__}"]


def _validate_policy(value: object) -> None:
    required = {
        "schema_version",
        "enforce",
        "controls",
        "benchmarks",
        "benchmark_baseline_path",
    }
    if (
        not isinstance(value, dict)
        or set(value) != required
        or value.get("schema_version") != "1.0"
        or not isinstance(value.get("enforce"), bool)
    ):
        raise ValueError("invalid industry assurance policy")
    controls = value.get("controls")
    benchmarks = value.get("benchmarks")
    if (
        not isinstance(controls, list)
        or len(controls) > 10_000
        or not isinstance(benchmarks, list)
        or len(benchmarks) > 100
    ):
        raise ValueError("industry assurance policy collections are invalid")
    known_standards = {item["id"] for item in _STANDARDS}
    known_benchmarks = {item["id"] for item in _BENCHMARKS}
    identities: set[tuple[str, str]] = set()
    for control in controls:
        if not isinstance(control, dict) or set(control) != {
            "standard",
            "control_id",
            "objective",
            "applicable",
            "evidence_artifacts",
        }:
            raise ValueError("industry assurance control fields are invalid")
        identity = (str(control.get("standard")), str(control.get("control_id")))
        evidence = control.get("evidence_artifacts")
        if (
            identity[0] not in known_standards
            or identity in identities
            or not _text(identity[1], 160)
            or not _text(control.get("objective"), 1000)
            or not isinstance(control.get("applicable"), bool)
            or not isinstance(evidence, list)
            or len(evidence) > 100
            or not all(_artifact_name(item) for item in evidence)
        ):
            raise ValueError("industry assurance control is invalid")
        identities.add(identity)
    seen: set[str] = set()
    for benchmark in benchmarks:
        if not isinstance(benchmark, dict) or set(benchmark) != {
            "id",
            "enabled",
            "corpus_sha256",
            "evidence_artifact",
            "minimum_precision",
            "minimum_recall",
            "minimum_f1",
            "maximum_false_positive_rate",
        }:
            raise ValueError("industry benchmark fields are invalid")
        identifier = str(benchmark.get("id") or "")
        digest = str(benchmark.get("corpus_sha256") or "")
        if (
            identifier not in known_benchmarks
            or identifier in seen
            or not isinstance(benchmark.get("enabled"), bool)
            or not _digest(digest)
            or not _artifact_name(benchmark.get("evidence_artifact"))
        ):
            raise ValueError("industry benchmark declaration is invalid")
        for name in (
            "minimum_precision",
            "minimum_recall",
            "minimum_f1",
            "maximum_false_positive_rate",
        ):
            if not _ratio(benchmark.get(name)):
                raise ValueError("industry benchmark threshold is invalid")
        seen.add(identifier)
    baseline = value.get("benchmark_baseline_path")
    if baseline is not None and not _safe_relative(baseline):
        raise ValueError("benchmark baseline path is unsafe")


def _crosswalk(artifacts: dict[str, Any]) -> dict[str, Any]:
    catalogs = []
    mappings = []
    for standard in _STANDARDS:
        present = [name for name in standard["evidence"] if name in artifacts]
        catalogs.append(
            {key: value for key, value in standard.items() if key != "evidence"}
        )
        mappings.append(
            {
                "standard": standard["id"],
                "evidence_artifacts": list(standard["evidence"]),
                "evidence_present": present,
                "mapping_status": "evidence-surface-present"
                if present
                else "not-observed",
            }
        )
    return {
        "schema_version": "1.0",
        "analysis": "versioned-industry-standards-crosswalk",
        "catalogs_registered": len(catalogs),
        "catalogs": catalogs,
        "mappings": mappings,
        "claim_boundary": "A crosswalk identifies related evidence surfaces; it does not establish control conformance or certification.",
    }


def _assessment(
    policy: dict[str, Any],
    artifacts: dict[str, Any],
    crosswalk: dict[str, Any],
    errors: list[str],
) -> dict[str, Any]:
    controls = []
    for value in policy["controls"]:
        evidence = list(value["evidence_artifacts"])
        present = [name for name in evidence if _complete_artifact(artifacts.get(name))]
        missing = [name for name in evidence if name not in present]
        applicable = value["applicable"] is True
        status = (
            "not-applicable"
            if not applicable
            else "satisfied"
            if evidence and not missing
            else "gap"
        )
        controls.append(
            {
                "standard": value["standard"],
                "control_id": value["control_id"],
                "objective": value["objective"],
                "applicable": applicable,
                "status": status,
                "evidence_required": evidence,
                "evidence_present": present,
                "gaps": [f"missing or incomplete artifact: {name}" for name in missing],
            }
        )
    counts = Counter(item["status"] for item in controls)
    applicable_count = sum(item["applicable"] for item in controls)
    satisfied = counts["satisfied"]
    complete = not errors and (not policy["enforce"] or satisfied == applicable_count)
    return {
        "schema_version": "1.0",
        "analysis": "evidence-backed-industry-control-assessment",
        "complete": complete,
        "policy_present": policy["present"],
        "enforced": policy["enforce"],
        "catalogs_registered": crosswalk["catalogs_registered"],
        "controls_assessed": len(controls),
        "applicable_controls": applicable_count,
        "controls_satisfied": satisfied,
        "status_counts": {
            name: counts.get(name, 0) for name in ("satisfied", "gap", "not-applicable")
        },
        "controls": controls,
        "parse_errors": errors[:100],
        "claim_boundary": "Only declared controls with complete named evidence are satisfied; assessment is not third-party certification.",
    }


def _benchmark_registry(policy: dict[str, Any], source_sha256: str) -> dict[str, Any]:
    declarations = {item["id"]: item for item in policy["benchmarks"]}
    benchmarks = []
    tasks = []
    for registered in _BENCHMARKS:
        declaration = declarations.get(registered["id"])
        enabled = bool(declaration and declaration["enabled"])
        entry = {
            **registered,
            "enabled": enabled,
            "corpus_sha256": declaration["corpus_sha256"] if declaration else None,
            "evidence_artifact": declaration["evidence_artifact"]
            if declaration
            else None,
            "thresholds": (
                {
                    name: declaration[name]
                    for name in (
                        "minimum_precision",
                        "minimum_recall",
                        "minimum_f1",
                        "maximum_false_positive_rate",
                    )
                }
                if declaration
                else None
            ),
        }
        benchmarks.append(entry)
        if enabled:
            if declaration is None:  # pragma: no cover - established by enabled
                raise AssertionError("enabled benchmark lacks a declaration")
            tasks.append(
                {
                    "benchmark_id": registered["id"],
                    "lane": registered["lane"],
                    "command": [
                        "pysec",
                        "benchmark",
                        "${PYSEC_BENCHMARK_REPORT}",
                        "--corpus",
                        "${PYSEC_BENCHMARK_CORPUS}",
                        "--corpus-sha256",
                        declaration["corpus_sha256"],
                        "--format",
                        "json",
                        "--output",
                        declaration["evidence_artifact"],
                    ],
                    "network_policy": "deny",
                    "disposable_target_required": registered["lane"]
                    == "authorized-companion",
                    "source_bound": bool(source_sha256),
                }
            )
    return {
        "schema_version": "1.0",
        "analysis": "industry-benchmark-registry",
        "source_sha256": source_sha256,
        "benchmarks_registered": len(benchmarks),
        "benchmarks_enabled": sum(item["enabled"] for item in benchmarks),
        "benchmarks": benchmarks,
        "tasks": tasks,
        "required_metrics": [
            "precision",
            "recall",
            "specificity",
            "f1",
            "mcc",
            "balanced_accuracy",
            "false_positive_rate",
        ],
        "required_strata": [
            "cwe",
            "language",
            "parser_variant",
            "boundary_type",
            "severity",
            "mutation_operator",
        ],
        "claim_boundary": "External vulnerable applications and corpora execute only in separately authorized disposable companion lanes.",
    }


def _benchmark_scorecard(
    target: Path,
    artifacts: dict[str, Any],
    registry: dict[str, Any],
    source_sha256: str,
) -> dict[str, Any]:
    rows = []
    for benchmark in registry["benchmarks"]:
        if not benchmark["enabled"]:
            continue
        value = artifacts.get(benchmark["evidence_artifact"])
        evidence_source = "governed-artifact" if isinstance(value, dict) else "missing"
        if not isinstance(value, dict):
            try:
                _, payload = read_regular_file(
                    target / benchmark["evidence_artifact"],
                    "benchmark evidence",
                    maximum_bytes=_MAX_POLICY_BYTES,
                    boundary=target,
                )
                loaded = strict_loads(payload)
                value = loaded if isinstance(loaded, dict) else None
                evidence_source = "sealed-snapshot" if value is not None else "invalid"
            except (OSError, TypeError, ValueError):
                value = None
        valid = _benchmark_evidence(value, benchmark)
        metrics = value.get("metrics", {}) if valid and isinstance(value, dict) else {}
        thresholds = benchmark["thresholds"] or {}
        passed = bool(valid and _meets_thresholds(metrics, thresholds))
        rows.append(
            {
                "benchmark_id": benchmark["id"],
                "corpus_sha256": benchmark["corpus_sha256"],
                "evidence_artifact": benchmark["evidence_artifact"],
                "evidence_source": evidence_source,
                "evidence_present": isinstance(value, dict),
                "evidence_valid": valid,
                "passed": passed,
                "metrics": {
                    name: metrics.get(name) for name in registry["required_metrics"]
                },
                "gaps": []
                if passed
                else _benchmark_gaps(value, valid, metrics, thresholds),
            }
        )
    executed = sum(item["evidence_valid"] for item in rows)
    passed_count = sum(item["passed"] for item in rows)
    benchmark_scope = [
        {"benchmark_id": item["benchmark_id"], "corpus_sha256": item["corpus_sha256"]}
        for item in rows
    ]
    return {
        "schema_version": "1.0",
        "analysis": "industry-benchmark-scorecard",
        "source_sha256": source_sha256,
        "benchmarks_enabled": len(rows),
        "benchmarks_executed": executed,
        "benchmarks_passed": passed_count,
        "complete": executed == len(rows),
        "passed": bool(rows) and passed_count == len(rows),
        "benchmarks": rows,
        "benchmark_scope": benchmark_scope,
        "aggregate_metrics": _aggregate_metrics(rows),
        "claim_boundary": "Scores are corpus-specific measurements and do not prove absence of vulnerabilities in other software.",
    }


def _benchmark_evidence(value: object, benchmark: dict[str, Any]) -> bool:
    if not isinstance(value, dict) or value.get("verdict") not in {"pass", "fail"}:
        return False
    corpus = value.get("corpus")
    metrics = value.get("metrics")
    return bool(
        isinstance(corpus, dict)
        and corpus.get("sha256") == benchmark["corpus_sha256"]
        and isinstance(metrics, dict)
        and all(
            name in metrics for name in ("precision", "recall", "specificity", "f1")
        )
        and value.get("replay_protected") is True
        and isinstance(corpus.get("authority"), dict)
        and corpus["authority"].get("organization_approved") is True
    )


def _meets_thresholds(metrics: dict[str, Any], thresholds: dict[str, Any]) -> bool:
    return (
        all(
            isinstance(metrics.get(name), (int, float))
            and float(metrics[name]) >= float(thresholds[threshold])
            for name, threshold in (
                ("precision", "minimum_precision"),
                ("recall", "minimum_recall"),
                ("f1", "minimum_f1"),
            )
        )
        and isinstance(metrics.get("false_positive_rate"), (int, float))
        and float(metrics["false_positive_rate"])
        <= float(thresholds["maximum_false_positive_rate"])
    )


def _benchmark_gaps(
    value: object, valid: bool, metrics: dict[str, Any], thresholds: dict[str, Any]
) -> list[str]:
    if not isinstance(value, dict):
        return ["benchmark evidence is missing"]
    if not valid:
        return [
            "benchmark evidence lacks approved corpus authority, replay protection, or digest binding"
        ]
    gaps = []
    for metric, threshold, direction in (
        ("precision", "minimum_precision", "minimum"),
        ("recall", "minimum_recall", "minimum"),
        ("f1", "minimum_f1", "minimum"),
        ("false_positive_rate", "maximum_false_positive_rate", "maximum"),
    ):
        observed = metrics.get(metric)
        limit = thresholds[threshold]
        if (
            not isinstance(observed, (int, float))
            or (direction == "minimum" and observed < limit)
            or (direction == "maximum" and observed > limit)
        ):
            gaps.append(f"{metric} does not meet {threshold}={limit}")
    return gaps


def _aggregate_metrics(rows: list[dict[str, Any]]) -> dict[str, float | None]:
    result: dict[str, float | None] = {}
    for name in (
        "precision",
        "recall",
        "specificity",
        "f1",
        "mcc",
        "balanced_accuracy",
        "false_positive_rate",
    ):
        values = [
            float(row["metrics"][name])
            for row in rows
            if row["evidence_valid"]
            and isinstance(row["metrics"].get(name), (int, float))
        ]
        result[name] = round(sum(values) / len(values), 6) if values else None
    return result


def _benchmark_delta(
    target: Path, policy: dict[str, Any], scorecard: dict[str, Any], errors: list[str]
) -> dict[str, Any]:
    path_value = policy.get("benchmark_baseline_path")
    baseline: dict[str, Any] | None = None
    if path_value:
        try:
            path = target / str(path_value)
            _, payload = read_regular_file(
                path,
                "benchmark baseline",
                maximum_bytes=_MAX_POLICY_BYTES,
                boundary=target,
            )
            loaded = strict_loads(payload)
            if (
                not isinstance(loaded, dict)
                or loaded.get("analysis") != "industry-benchmark-scorecard"
            ):
                raise ValueError("invalid benchmark baseline")
            baseline = loaded
        except (OSError, TypeError, ValueError) as exc:
            errors.append(f"{path_value}: {type(exc).__name__}")
    current = scorecard["aggregate_metrics"]
    previous = baseline.get("aggregate_metrics", {}) if baseline else {}
    deltas = {
        name: round(float(current[name]) - float(previous[name]), 6)
        if isinstance(current.get(name), (int, float))
        and isinstance(previous.get(name), (int, float))
        else None
        for name in current
    }
    regressions = [
        name
        for name, value in deltas.items()
        if isinstance(value, float)
        and (
            (name == "false_positive_rate" and value > 0)
            or (name != "false_positive_rate" and value < 0)
        )
    ]
    return {
        "schema_version": "1.0",
        "analysis": "industry-benchmark-delta",
        "baseline_present": baseline is not None,
        "comparable": baseline is not None
        and baseline.get("benchmark_scope") == scorecard.get("benchmark_scope"),
        "current_metrics": current,
        "baseline_metrics": previous,
        "metric_deltas": deltas,
        "regressions": regressions,
        "claim_boundary": "A delta is comparable only for the same benchmark families and pinned corpus digests.",
    }


def _oscal(assessment: dict[str, Any], source_sha256: str) -> dict[str, Any]:
    identity = uuid.uuid5(
        uuid.NAMESPACE_URL, f"pysec:{source_sha256 or 'unknown'}:industry-assessment"
    )
    now = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    findings = []
    observations = []
    for index, control in enumerate(assessment["controls"]):
        observation_uuid = str(
            uuid.uuid5(
                identity,
                f"observation:{index}:{control['standard']}:{control['control_id']}",
            )
        )
        observations.append(
            {
                "uuid": observation_uuid,
                "title": control["objective"],
                "description": "; ".join(control["evidence_present"])
                or "No retained evidence",
                "methods": ["EXAMINE"],
                "collected": now,
                "relevant-evidence": [
                    {"description": name, "href": name}
                    for name in control["evidence_present"]
                ],
            }
        )
        if control["status"] == "gap":
            findings.append(
                {
                    "uuid": str(uuid.uuid5(identity, f"finding:{index}")),
                    "title": f"{control['standard']} {control['control_id']} evidence gap",
                    "description": "; ".join(control["gaps"]),
                    "target": {
                        "type": "objective-id",
                        "target-id": control["control_id"],
                        "status": {"state": "not-satisfied"},
                    },
                    "related-observations": [{"observation-uuid": observation_uuid}],
                }
            )
    return {
        "assessment-results": {
            "uuid": str(identity),
            "metadata": {
                "title": "Python Security Suite industry control assessment",
                "last-modified": now,
                "version": "1.0",
                "oscal-version": "1.1.2",
            },
            "results": [
                {
                    "uuid": str(uuid.uuid5(identity, "result")),
                    "title": "Evidence-backed industry standards assessment",
                    "description": assessment["claim_boundary"],
                    "start": now,
                    "reviewed-controls": {
                        "control-selections": [
                            {
                                "description": "Policy-declared controls",
                                "include-controls": [
                                    {
                                        "control-id": f"{item['standard']}:{item['control_id']}"
                                    }
                                    for item in assessment["controls"]
                                ],
                            }
                        ]
                    },
                    "observations": observations,
                    "findings": findings,
                }
            ],
        }
    }


def _interoperability(artifacts: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    intelligence = artifacts.get("risk-intelligence.json")
    vex_formats = (
        set(intelligence.get("vex_formats", []))
        if isinstance(intelligence, dict)
        and isinstance(intelligence.get("vex_formats"), list)
        else set()
    )
    for name, version, evidence in _INTEROPERABILITY:
        present = any(item in artifacts for item in evidence)
        if name in {"CycloneDX-VEX", "OpenVEX", "CSAF-VEX"}:
            present = name.casefold().replace("-vex", "") in vex_formats
        if name == "OSCAL":
            present = True
        rows.append(
            {
                "format": name,
                "version": version,
                "status": "supported" if present else "not-observed",
                "evidence_artifacts": list(evidence),
            }
        )
    return rows


def _source_sha256(artifacts: dict[str, Any]) -> str:
    value = artifacts.get("source-inventory.json")
    digest = str(value.get("source_sha256") or "") if isinstance(value, dict) else ""
    return digest if _digest(digest) else ""


def _complete_artifact(value: object) -> bool:
    return isinstance(value, dict) and value.get("complete") is not False


def _artifact_name(value: object) -> bool:
    return (
        _text(value, 200)
        and Path(str(value)).name == str(value)
        and str(value).endswith(".json")
    )


def _safe_relative(value: object) -> bool:
    if not _text(value, 500):
        return False
    path = Path(str(value))
    return not path.is_absolute() and ".." not in path.parts


def _digest(value: str) -> bool:
    return len(value) == 64 and all(character in _DIGEST for character in value)


def _ratio(value: object) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(float(value))
        and 0 <= float(value) <= 1
    )


def _text(value: object, maximum: int) -> bool:
    return isinstance(value, str) and 0 < len(value) <= maximum
