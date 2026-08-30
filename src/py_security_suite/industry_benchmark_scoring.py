from __future__ import annotations

import math
from typing import Any, cast


_DIGEST_CHARACTERS = frozenset("0123456789abcdef")


def protocol_metrics_valid(protocol: str, metrics: object) -> bool:
    """Validate scorecard metrics without importing the assurance catalog."""
    if not isinstance(metrics, dict):
        return False
    if protocol == "temporal-calibration":
        legacy = all(
            _ratio(metrics.get(name))
            for name in (
                "brier_score",
                "expected_calibration_error",
                "recall_at_budget",
                "effort",
            )
        ) and _count(metrics.get("observations"), 100)
        return legacy or (
            _ratio(metrics.get("brier_score")) and _count(metrics.get("cases"), 100)
        )
    if protocol == "verification-competition":
        valid = all(
            _count(metrics.get(name)) for name in ("correct", "incorrect", "unknown")
        ) and (_finite_number(metrics.get("score")) or _ratio(metrics.get("accuracy")))
        return valid and ("cases" not in metrics or _count(metrics.get("cases"), 20))
    if protocol == "test-generation":
        legacy = (
            _ratio(metrics.get("coverage"))
            and _count(metrics.get("faults_detected"))
            and _count(metrics.get("valid_tests"), 1)
            and _finite_number(metrics.get("score"))
        )
        return legacy or (
            _ratio(metrics.get("accuracy")) and _count(metrics.get("cases"), 20)
        )
    if protocol == "fuzzing-statistical":
        legacy = (
            _count(metrics.get("trials"), 10)
            and _finite_number(metrics.get("median_edges"), 0)
            and _finite_number(metrics.get("effect_size"))
            and -1 <= float(metrics["effect_size"]) <= 1
            and _ratio(metrics.get("p_value"))
        )
        return legacy or (
            _count(metrics.get("trials"), 10)
            and _count(metrics.get("executions"), 1)
            and _ratio(metrics.get("coverage_gain"))
        )
    if protocol == "stochastic-adversarial":
        return _count(metrics.get("repetitions"), 5) and all(
            _ratio(metrics.get(name))
            for name in ("attack_success_rate", "utility_retention", "variance")
        )
    if protocol == "assessor-agreement":
        return (
            _count(metrics.get("reviewers"), 2)
            and _count(metrics.get("cases"), 1)
            and _ratio(metrics.get("inter_rater_agreement"))
            and float(metrics["inter_rater_agreement"]) >= 0.8
        )
    if protocol == "biometric-performance":
        return (
            _count(metrics.get("genuine_attempts"), 1)
            and _count(metrics.get("impostor_attempts"), 1)
            and _count(metrics.get("attack_attempts"), 1)
            and _count(metrics.get("demographic_groups"), 1)
            and metrics.get("threshold_locked") is True
            and all(
                _ratio(metrics.get(name))
                for name in (
                    "false_match_rate",
                    "false_non_match_rate",
                    "iapar",
                    "fmr_wilson_upper_95",
                    "fnmr_wilson_upper_95",
                    "iapar_wilson_upper_95",
                    "worst_group_fmr_wilson_upper_95",
                    "worst_group_fnmr_wilson_upper_95",
                )
            )
        )
    if protocol == "proficiency-testing":
        agreement = metrics.get("chance_corrected_agreement")
        agreement_value = (
            float(agreement)
            if isinstance(agreement, (int, float)) and not isinstance(agreement, bool)
            else -2.0
        )
        return (
            _count(metrics.get("participants"), 2)
            and _count(metrics.get("cases"), 1)
            and _count(metrics.get("rounds"), 1)
            and metrics.get("blinded") is True
            and _ratio(metrics.get("agreement"))
            and _ratio(metrics.get("reference_accuracy"))
            and _finite_number(agreement)
            and -1 <= agreement_value <= 1
        )
    if protocol == "conformance":
        return (
            _count(metrics.get("passed_cases"))
            and _count(metrics.get("failed_cases"))
            and _count(metrics.get("negative_cases"), 1)
            and _ratio(metrics.get("conformance_rate"))
            and ("cases" not in metrics or _count(metrics.get("cases"), 10))
        )
    if protocol == "detection-evaluation":
        legacy = (
            _count(metrics.get("techniques"), 1)
            and _count(metrics.get("detections"))
            and _ratio(metrics.get("analytic_coverage"))
            and _ratio(metrics.get("false_positive_rate"))
            and _finite_number(metrics.get("latency_ms"), 0)
        )
        return legacy or (
            _count(metrics.get("cases"), 20)
            and all(
                _ratio(metrics.get(name))
                for name in ("precision", "recall", "f1", "false_positive_rate")
            )
        )
    return False


def protocol_acceptance(value: object) -> bool:
    if not isinstance(value, dict):
        return False
    acceptance = value.get("acceptance")
    return bool(
        isinstance(acceptance, dict)
        and _digest(str(acceptance.get("criteria_sha256") or ""))
        and acceptance.get("met") is True
        and isinstance(acceptance.get("authority"), dict)
        and acceptance["authority"].get("organization_approved") is True
        and (
            "organization_id" not in acceptance["authority"]
            or _text(acceptance["authority"].get("organization_id"), 128)
        )
    )


def meets_protocol_thresholds(metrics: object, thresholds: dict[str, Any]) -> bool:
    if not isinstance(metrics, dict) or not thresholds:
        return False
    for threshold, limit in thresholds.items():
        metric = threshold.removeprefix("minimum_").removeprefix("maximum_")
        if metric == "attack_success_rate":
            metric = (
                "attack_success_rate_wilson_upper_95"
                if "attack_success_rate_wilson_upper_95" in metrics
                else metric
            )
        observed = metrics.get(metric)
        if not _finite_number(observed):
            return False
        observed_value = float(cast(int | float, observed))
        if threshold.startswith("minimum_") and observed_value < float(limit):
            return False
        if threshold.startswith("maximum_") and observed_value > float(limit):
            return False
    return True


def _finite_number(value: object, minimum: float | None = None) -> bool:
    return bool(
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(float(value))
        and (minimum is None or float(value) >= minimum)
    )


def _count(value: object, minimum: int = 0) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= minimum


def _ratio(value: object) -> bool:
    return _finite_number(value) and 0 <= float(cast(int | float, value)) <= 1


def _digest(value: str) -> bool:
    return len(value) == 64 and all(
        character in _DIGEST_CHARACTERS for character in value
    )


def _text(value: object, maximum: int) -> bool:
    return isinstance(value, str) and 1 <= len(value) <= maximum
