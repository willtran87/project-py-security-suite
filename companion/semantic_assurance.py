from __future__ import annotations

import argparse
import hashlib
import math
import os
import tempfile
from pathlib import Path
from typing import Any

try:
    from companion.evidence_authority import verify_authority
    from companion.strict_json import dumps as strict_dumps
    from companion.strict_json import loads as strict_loads
except ModuleNotFoundError:  # Direct script execution.
    from evidence_authority import verify_authority  # type: ignore[import-not-found,no-redef]
    from strict_json import dumps as strict_dumps  # type: ignore[import-not-found,no-redef]
    from strict_json import loads as strict_loads  # type: ignore[import-not-found,no-redef]


REQUIRED_CONTROLS = {
    "surface-inventory": {
        "declared-observed",
        "retired-absence",
        "version-ownership",
        "shadow-surface",
    },
    "event-security": {
        "producer-authorization",
        "consumer-authorization",
        "message-signing",
        "replay-resistance",
        "idempotency",
        "schema-enforcement",
        "dead-letter-isolation",
        "poison-message-containment",
    },
    "database-security": {
        "least-privilege",
        "row-level-security",
        "migration-safety",
        "query-boundary",
        "backup-restore",
        "audit-trail",
    },
    "ai-security": {
        "prompt-injection",
        "tool-authorization",
        "least-agency",
        "memory-boundary",
        "output-handling",
        "data-exfiltration",
    },
    "ruleset-regression": {
        "true-positive",
        "true-negative",
        "mutation",
        "parser-variant",
        "false-positive-budget",
    },
}
_OUTCOMES = {"allow", "block", "clean", "detected", "present", "absent", "pass"}
_SEVERITIES = {"critical", "high", "medium", "low", "informational"}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Derive bounded semantic assurance evidence from an oracle contract."
    )
    parser.add_argument("--kind", choices=sorted(REQUIRED_CONTROLS), required=True)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    document = _read(args.input)
    normalized = analyze(document, args.kind, context=args.input)
    _write(args.output, normalized)
    return 0


def analyze(value: object, kind: str, *, context: Path | None = None) -> dict[str, Any]:
    required_root = {"schema_version", "kind", "cases", "canary_id"}
    if kind == "ruleset-regression":
        required_root.add("baseline")
    if not isinstance(value, dict) or set(value) != required_root:
        raise ValueError("semantic assurance root fields do not match the contract")
    if value.get("schema_version") != "1.0" or value.get("kind") != kind:
        raise ValueError("semantic assurance schema or kind is invalid")
    cases = value.get("cases")
    if not isinstance(cases, list) or not 1 <= len(cases) <= 10_000:
        raise ValueError("semantic assurance requires 1 to 10000 cases")
    canary_id = _label(value.get("canary_id"), "canary ID", 160)
    baseline = value.get("baseline") if kind == "ruleset-regression" else None
    advanced_ruleset = (
        isinstance(baseline, dict) and baseline.get("schema_version") == "2.0"
    )
    normalized = [_case(case, advanced_ruleset=advanced_ruleset) for case in cases]
    ids = [case["id"] for case in normalized]
    if len(ids) != len(set(ids)):
        raise ValueError("semantic assurance case IDs must be unique")
    controls = {case["control"] for case in normalized}
    missing = REQUIRED_CONTROLS[kind] - controls
    if missing:
        raise ValueError(f"semantic assurance is missing controls: {sorted(missing)}")
    canaries = [case for case in normalized if case["id"] == canary_id]
    if len(canaries) != 1 or canaries[0]["expected"] != canaries[0]["observed"]:
        raise ValueError("semantic assurance canary was not observed successfully")
    findings = [_finding(case, kind) for case in normalized if _failed(case)]
    if kind == "ruleset-regression":
        findings.extend(
            _regression_findings(
                normalized, value.get("baseline"), cases, context=context
            )
        )
    targets = {case["target_id"] for case in normalized}
    coverage = round(100.0 * len(controls) / len(REQUIRED_CONTROLS[kind]), 6)
    control_records = {}
    for control in sorted(controls):
        control_cases = [case for case in normalized if case["control"] == control]
        subject = {
            "cases": len(control_cases),
            "failed_cases": sum(_failed(case) for case in control_cases),
            "case_ids_sha256": hashlib.sha256(
                strict_dumps(sorted(case["id"] for case in control_cases)).encode()
            ).hexdigest(),
            "observations_sha256": hashlib.sha256(
                strict_dumps(control_cases).encode()
            ).hexdigest(),
        }
        control_records[control] = subject
    proof_subject = {"schema_version": "1.0", "controls": control_records}
    control_proof = {
        **proof_subject,
        "proof_sha256": hashlib.sha256(
            strict_dumps(proof_subject).encode()
        ).hexdigest(),
    }
    return {
        "execution": {
            "status": "completed",
            "targets_discovered": len(targets),
            "targets_exercised": len(targets),
            "requests": len(normalized),
            "coverage_percent": coverage,
            "coverage_metric": "required-semantic-control-coverage",
            "roles": sorted({case["role"] for case in normalized}),
            "features": sorted(controls),
            "skipped_checks": [],
            "canaries_expected": 1,
            "canaries_observed": 1,
            "control_proof": control_proof,
        },
        "findings": findings,
    }


def _case(value: object, *, advanced_ruleset: bool = False) -> dict[str, str]:
    required = {
        "id",
        "target_id",
        "role",
        "control",
        "expected",
        "observed",
        "severity",
        "classification",
    }
    if advanced_ruleset:
        required |= {"rule_id", "stratum", "mutation_operator"}
    if not isinstance(value, dict) or set(value) != required:
        raise ValueError("semantic assurance case fields do not match the contract")
    expected = _label(value.get("expected"), "expected outcome", 40)
    observed = _label(value.get("observed"), "observed outcome", 40)
    if expected not in _OUTCOMES or observed not in _OUTCOMES:
        raise ValueError("semantic assurance outcome is unsupported")
    severity = _label(value.get("severity"), "severity", 20)
    if severity not in _SEVERITIES:
        raise ValueError("semantic assurance severity is unsupported")
    result = {
        "id": _label(value.get("id"), "case ID", 160),
        "target_id": _label(value.get("target_id"), "target ID", 200),
        "role": _label(value.get("role"), "role", 100),
        "control": _label(value.get("control"), "control", 100),
        "expected": expected,
        "observed": observed,
        "severity": severity,
        "classification": _label(value.get("classification"), "classification", 160),
    }
    if advanced_ruleset:
        result.update(
            {
                "rule_id": _label(value.get("rule_id"), "rule ID", 200),
                "stratum": _label(value.get("stratum"), "case stratum", 160),
                "mutation_operator": _optional_label(
                    value.get("mutation_operator"), "mutation operator", 160
                ),
            }
        )
    return result


def _failed(case: dict[str, str]) -> bool:
    return case["expected"] != case["observed"]


def _finding(case: dict[str, str], kind: str) -> dict[str, object]:
    return {
        "rule_id": f"{kind}:{case['control']}",
        "title": f"{case['control']} assurance failed",
        "message": "The observed semantic outcome did not match the approved oracle.",
        "path": "<semantic-assurance>",
        "severity": case["severity"],
        "classification": case["classification"],
        "impact": "A required security behavior is absent or has regressed.",
        "remediation": "Correct the behavior and retain this case as a signed regression oracle.",
        "area": kind,
        "domain": "security",
        "evidence": {
            "case_id": case["id"],
            "target_id": case["target_id"],
            "control": case["control"],
            "expected": case["expected"],
            "observed": case["observed"],
        },
    }


def _regression_findings(
    cases: list[dict[str, str]],
    value: object,
    raw_cases: list[object],
    *,
    context: Path | None = None,
) -> list[dict[str, object]]:
    required = {
        "true_positive_rate",
        "true_negative_rate",
        "mutation_rate",
        "corpus_sha256",
        "ruleset_sha256",
        "sample_sizes",
        "confidence_level",
    }
    v2_extra = {
        "schema_version",
        "training_corpus_sha256",
        "holdout_corpus_sha256",
        "per_rule_confusion_matrices",
        "strata",
        "mutation_operators",
        "family_wise_alpha",
        "minimum_power",
        "minimum_detectable_effect",
        "authority",
    }
    if not isinstance(value, dict) or (
        set(value) != required and set(value) != required | v2_extra
    ):
        raise ValueError("ruleset baseline fields do not match the contract")
    advanced = set(value) == required | v2_extra
    if advanced and value.get("schema_version") != "2.0":
        raise ValueError("advanced ruleset baseline schema_version must be 2.0")
    metrics = {"true_positive_rate", "true_negative_rate", "mutation_rate"}
    baseline = {name: _percentage(value.get(name), name) for name in metrics}
    for name in ("corpus_sha256", "ruleset_sha256"):
        digest = str(value.get(name) or "")
        if len(digest) != 64 or any(
            character not in "0123456789abcdef" for character in digest
        ):
            raise ValueError(f"ruleset baseline {name} is invalid")
    observed_corpus = hashlib.sha256(
        strict_dumps(raw_cases).encode("utf-8")
    ).hexdigest()
    if value.get("corpus_sha256") != observed_corpus:
        raise ValueError("ruleset baseline corpus SHA-256 does not match its cases")
    if advanced:
        _validate_ruleset_authority(value, observed_corpus, raw_cases, context)
    confidence = value.get("confidence_level")
    if isinstance(confidence, bool) or not isinstance(confidence, (int, float)):
        raise ValueError("ruleset confidence_level must be numeric")
    confidence = float(confidence)
    if not 0.8 <= confidence <= 0.999:
        raise ValueError("ruleset confidence_level must be between 0.8 and 0.999")
    sample_sizes = value.get("sample_sizes")
    if not isinstance(sample_sizes, dict) or set(sample_sizes) != metrics:
        raise ValueError("ruleset sample_sizes do not match required metrics")
    groups = {
        "true_positive_rate": [
            case for case in cases if case["control"] == "true-positive"
        ],
        "true_negative_rate": [
            case for case in cases if case["control"] == "true-negative"
        ],
        "mutation_rate": [case for case in cases if case["control"] == "mutation"],
    }
    findings: list[dict[str, object]] = []
    effective_confidence = confidence
    if advanced:
        effective_confidence = 1.0 - float(value["family_wise_alpha"]) / len(groups)
    for metric, selected in groups.items():
        if not selected:
            raise ValueError(f"ruleset regression has no cases for {metric}")
        required_size = _positive_integer(sample_sizes.get(metric), metric)
        if len(selected) < required_size:
            raise ValueError(f"ruleset regression corpus is undersized for {metric}")
        current = 100.0 * sum(not _failed(case) for case in selected) / len(selected)
        lower, upper = _wilson_interval(
            sum(not _failed(case) for case in selected),
            len(selected),
            effective_confidence,
        )
        if current + 1e-9 < baseline[metric]:
            findings.append(
                {
                    "rule_id": f"ruleset-regression:{metric}",
                    "title": f"Ruleset {metric.replace('_', ' ')} regressed",
                    "message": "The current semantic corpus score is below its signed baseline.",
                    "path": "<ruleset-regression>",
                    "severity": "high",
                    "classification": "CWE-693",
                    "impact": "Scanner rule changes can silently reduce detection quality.",
                    "remediation": "Restore the lost detections or explicitly approve a new signed baseline.",
                    "area": "ruleset-regression",
                    "domain": "security",
                    "evidence": {
                        "metric": metric,
                        "baseline_percent": round(baseline[metric], 6),
                        "current_percent": round(current, 6),
                        "confidence_level": confidence,
                        "simultaneous_confidence_level": round(effective_confidence, 8),
                        "confidence_lower_percent": round(lower * 100.0, 6),
                        "confidence_upper_percent": round(upper * 100.0, 6),
                        "sample_size": len(selected),
                        "corpus_sha256": observed_corpus,
                        "ruleset_sha256": value["ruleset_sha256"],
                    },
                }
            )
    return findings


def _validate_ruleset_authority(
    value: dict[str, Any],
    observed_corpus: str,
    raw_cases: list[object],
    context: Path | None,
) -> None:
    if context is None:
        raise ValueError("advanced ruleset baseline requires its input path")
    training = str(value.get("training_corpus_sha256") or "")
    holdout = str(value.get("holdout_corpus_sha256") or "")
    if not all(_is_digest(item) for item in (training, holdout)):
        raise ValueError("ruleset training and holdout digests are invalid")
    if training == holdout or holdout != observed_corpus:
        raise ValueError("ruleset holdout must be observed and distinct from training")
    strata = value.get("strata")
    if (
        not isinstance(strata, list)
        or not 1 <= len(strata) <= 100
        or any(
            not isinstance(item, str) or not item.strip() or len(item) > 160
            for item in strata
        )
    ):
        raise ValueError("ruleset strata are invalid")
    if len(set(strata)) != len(strata):
        raise ValueError("ruleset strata must be unique")
    operators = value.get("mutation_operators")
    if (
        not isinstance(operators, list)
        or not 1 <= len(operators) <= 100
        or any(
            not isinstance(item, str) or not item.strip() or len(item) > 160
            for item in operators
        )
    ):
        raise ValueError("ruleset mutation operators are invalid")
    matrices = value.get("per_rule_confusion_matrices")
    if not isinstance(matrices, list) or not matrices:
        raise ValueError("ruleset per-rule confusion matrices are required")
    seen: set[str] = set()
    for matrix in matrices:
        if not isinstance(matrix, dict) or set(matrix) != {
            "rule_id",
            "true_positive",
            "true_negative",
            "false_positive",
            "false_negative",
        }:
            raise ValueError("ruleset confusion matrix fields are invalid")
        rule = _label(matrix.get("rule_id"), "ruleset rule ID", 200)
        if rule in seen:
            raise ValueError("ruleset confusion matrix rule IDs must be unique")
        seen.add(rule)
        for name in (
            "true_positive",
            "true_negative",
            "false_positive",
            "false_negative",
        ):
            raw = matrix.get(name)
            if isinstance(raw, bool) or not isinstance(raw, int) or raw < 0:
                raise ValueError("ruleset confusion matrix counts must be non-negative")
    _verify_observed_rule_qualification(
        raw_cases, matrices, set(strata), set(operators)
    )
    alpha = value.get("family_wise_alpha")
    power = value.get("minimum_power")
    effect = value.get("minimum_detectable_effect")
    if (
        not isinstance(alpha, (int, float))
        or isinstance(alpha, bool)
        or not 0.001 <= float(alpha) <= 0.2
    ):
        raise ValueError("ruleset family_wise_alpha is invalid")
    if (
        not isinstance(power, (int, float))
        or isinstance(power, bool)
        or not 0.8 <= float(power) <= 0.999
    ):
        raise ValueError("ruleset minimum_power is invalid")
    if (
        not isinstance(effect, (int, float))
        or isinstance(effect, bool)
        or not 0.001 <= float(effect) <= 0.5
    ):
        raise ValueError("ruleset minimum_detectable_effect is invalid")
    per_test_alpha = float(alpha) / 3.0
    required_power_size = math.ceil(
        (_normal_quantile(1.0 - per_test_alpha / 2.0) + _normal_quantile(float(power)))
        ** 2
        * 0.25
        / float(effect) ** 2
    )
    sample_sizes = value.get("sample_sizes")
    if not isinstance(sample_sizes, dict) or any(
        _positive_integer(sample_sizes.get(metric), metric) < required_power_size
        for metric in ("true_positive_rate", "true_negative_rate", "mutation_rate")
    ):
        raise ValueError("ruleset corpus is underpowered for its detectable effect")
    _verify_ruleset_subgroup_power(raw_cases, required_power_size)
    verify_authority(
        context,
        value.get("authority"),
        purpose="ruleset-regression-baseline",
        subject={
            "ruleset_sha256": value["ruleset_sha256"],
            "training_corpus_sha256": training,
            "holdout_corpus_sha256": holdout,
            "per_rule_confusion_matrices": matrices,
            "strata": strata,
            "mutation_operators": operators,
            "minimum_detectable_effect": float(effect),
            "minimum_power": float(power),
            "family_wise_alpha": float(alpha),
            "sample_sizes": value["sample_sizes"],
            "confidence_level": float(value["confidence_level"]),
            "true_positive_rate": float(value["true_positive_rate"]),
            "true_negative_rate": float(value["true_negative_rate"]),
            "mutation_rate": float(value["mutation_rate"]),
        },
    )


def _verify_observed_rule_qualification(
    raw_cases: list[object],
    matrices: list[object],
    strata: set[str],
    operators: set[str],
) -> None:
    observed: dict[str, dict[str, int]] = {}
    observed_strata: set[str] = set()
    observed_operators: set[str] = set()
    for item in raw_cases:
        if not isinstance(item, dict):
            raise ValueError("advanced ruleset cases must be objects")
        rule = _label(item.get("rule_id"), "ruleset case rule ID", 200)
        stratum = _label(item.get("stratum"), "ruleset case stratum", 160)
        operator = _optional_label(
            item.get("mutation_operator"), "ruleset case mutation operator", 160
        )
        if item.get("expected") not in {"detected", "clean"} or item.get(
            "observed"
        ) not in {"detected", "clean"}:
            raise ValueError("advanced ruleset outcomes must be detected or clean")
        observed_strata.add(stratum)
        if operator:
            observed_operators.add(operator)
        counts = observed.setdefault(
            rule,
            {
                "true_positive": 0,
                "true_negative": 0,
                "false_positive": 0,
                "false_negative": 0,
            },
        )
        expected_positive = item.get("expected") == "detected"
        observed_positive = item.get("observed") == "detected"
        category = (
            "true_positive"
            if expected_positive and observed_positive
            else "false_negative"
            if expected_positive
            else "false_positive"
            if observed_positive
            else "true_negative"
        )
        counts[category] += 1
    declared = {
        str(item["rule_id"]): {
            name: item[name]
            for name in (
                "true_positive",
                "true_negative",
                "false_positive",
                "false_negative",
            )
        }
        for item in matrices
        if isinstance(item, dict)
    }
    if declared != observed:
        raise ValueError(
            "ruleset per-rule confusion matrices do not match observed cases"
        )
    if observed_strata != strata:
        raise ValueError("ruleset strata do not match observed cases")
    if observed_operators != operators:
        raise ValueError("ruleset mutation operators do not match observed cases")


def _verify_ruleset_subgroup_power(raw_cases: list[object], required_size: int) -> None:
    rules: dict[str, dict[str, int]] = {}
    strata: dict[str, int] = {}
    operators: dict[str, int] = {}
    for item in raw_cases:
        if not isinstance(item, dict):
            continue
        rule = str(item.get("rule_id") or "")
        expected = str(item.get("expected") or "")
        bucket = rules.setdefault(rule, {"positive": 0, "negative": 0})
        bucket["positive" if expected == "detected" else "negative"] += 1
        stratum = str(item.get("stratum") or "")
        strata[stratum] = strata.get(stratum, 0) + 1
        operator = str(item.get("mutation_operator") or "")
        if operator:
            operators[operator] = operators.get(operator, 0) + 1
    if any(
        counts["positive"] < required_size or counts["negative"] < required_size
        for counts in rules.values()
    ):
        raise ValueError("ruleset per-rule qualification is underpowered")
    if any(count < required_size for count in strata.values()):
        raise ValueError("ruleset stratum qualification is underpowered")
    if any(count < required_size for count in operators.values()):
        raise ValueError("ruleset mutation-operator qualification is underpowered")


def _is_digest(value: str) -> bool:
    return len(value) == 64 and all(
        character in "0123456789abcdef" for character in value
    )


def _positive_integer(value: object, label: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 1 <= value <= 1_000_000
    ):
        raise ValueError(f"{label} sample size must be a positive integer")
    return value


def _wilson_interval(
    successes: int, total: int, confidence: float
) -> tuple[float, float]:
    # Acklam's inverse-normal approximation keeps the companion self-contained.
    z = _normal_quantile(0.5 + confidence / 2.0)
    proportion = successes / total
    denominator = 1.0 + z * z / total
    center = (proportion + z * z / (2.0 * total)) / denominator
    margin = (
        z
        * math.sqrt(
            proportion * (1.0 - proportion) / total + z * z / (4.0 * total * total)
        )
        / denominator
    )
    return max(0.0, center - margin), min(1.0, center + margin)


def _normal_quantile(probability: float) -> float:
    # Peter J. Acklam's rational approximation, sufficient for assurance bounds.
    a = (
        -39.6968302866538,
        220.946098424521,
        -275.928510446969,
        138.357751867269,
        -30.6647980661472,
        2.50662827745924,
    )
    b = (
        -54.4760987982241,
        161.585836858041,
        -155.698979859887,
        66.8013118877197,
        -13.2806815528857,
    )
    c = (
        -0.00778489400243029,
        -0.322396458041136,
        -2.40075827716184,
        -2.54973253934373,
        4.37466414146497,
        2.93816398269878,
    )
    d = (0.00778469570904146, 0.32246712907004, 2.445134137143, 3.75440866190742)
    low, high = 0.02425, 0.97575
    if probability < low:
        q = math.sqrt(-2.0 * math.log(probability))
        return (((((c[0] * q + c[1]) * q + c[2]) * q + c[3]) * q + c[4]) * q + c[5]) / (
            (((d[0] * q + d[1]) * q + d[2]) * q + d[3]) * q + 1
        )
    if probability > high:
        q = math.sqrt(-2.0 * math.log(1.0 - probability))
        return -(
            ((((c[0] * q + c[1]) * q + c[2]) * q + c[3]) * q + c[4]) * q + c[5]
        ) / ((((d[0] * q + d[1]) * q + d[2]) * q + d[3]) * q + 1)
    q = probability - 0.5
    r = q * q
    return (
        (((((a[0] * r + a[1]) * r + a[2]) * r + a[3]) * r + a[4]) * r + a[5])
        * q
        / (((((b[0] * r + b[1]) * r + b[2]) * r + b[3]) * r + b[4]) * r + 1)
    )


def _percentage(value: object, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{label} must be a percentage")
    result = float(value)
    if not 0.0 <= result <= 100.0:
        raise ValueError(f"{label} must be between 0 and 100")
    return result


def _label(value: object, label: str, maximum: int) -> str:
    result = str(value or "").strip()
    if (
        not result
        or len(result) > maximum
        or any(ord(character) < 32 for character in result)
    ):
        raise ValueError(f"{label} is invalid")
    return result


def _optional_label(value: object, label: str, maximum: int) -> str:
    result = str(value or "").strip()
    if len(result) > maximum or any(ord(character) < 32 for character in result):
        raise ValueError(f"{label} is invalid")
    return result


def _read(path: Path) -> object:
    if (
        path.is_symlink()
        or not path.is_file()
        or path.stat().st_size > 64 * 1024 * 1024
    ):
        raise ValueError("semantic assurance input must be a bounded regular file")
    return strict_loads(path.read_bytes())


def _write(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and (path.is_symlink() or not path.is_file()):
        raise ValueError("semantic assurance output is not replaceable")
    payload = (strict_dumps(value, indent=2) + "\n").encode()
    descriptor, name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


if __name__ == "__main__":
    raise SystemExit(main())
