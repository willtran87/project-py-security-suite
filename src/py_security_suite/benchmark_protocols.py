from __future__ import annotations

import math
from typing import Any


PROTOCOL_THRESHOLD_FIELDS: dict[str, frozenset[str]] = {
    "classification": frozenset(
        {
            "minimum_precision",
            "minimum_recall",
            "minimum_f1",
            "maximum_false_positive_rate",
        }
    ),
    "detection-evaluation": frozenset(
        {
            "minimum_precision",
            "minimum_recall",
            "minimum_f1",
            "maximum_false_positive_rate",
        }
    ),
    "verification-competition": frozenset({"minimum_accuracy"}),
    "test-generation": frozenset({"minimum_accuracy"}),
    "conformance": frozenset({"minimum_outcome_accuracy", "minimum_conformance_rate"}),
    "temporal-calibration": frozenset({"maximum_brier_score"}),
    "stochastic-adversarial": frozenset(
        {"maximum_attack_success_rate", "minimum_mean_utility"}
    ),
    "assessor-agreement": frozenset(
        {"minimum_agreement", "minimum_chance_corrected_agreement"}
    ),
    "biometric-performance": frozenset(
        {
            "maximum_fmr_wilson_upper_95",
            "maximum_fnmr_wilson_upper_95",
            "maximum_iapar_wilson_upper_95",
            "maximum_worst_group_fmr_wilson_upper_95",
            "maximum_worst_group_fnmr_wilson_upper_95",
        }
    ),
    "proficiency-testing": frozenset(
        {
            "minimum_agreement",
            "minimum_chance_corrected_agreement",
            "minimum_reference_accuracy",
        }
    ),
    "fuzzing-statistical": frozenset({"minimum_executions", "minimum_coverage_gain"}),
}


PROTOCOL_MINIMUM_CASES: dict[str, int] = {
    "classification": 20,
    "detection-evaluation": 20,
    "verification-competition": 20,
    "test-generation": 20,
    "conformance": 10,
    "temporal-calibration": 100,
    "stochastic-adversarial": 30,
    "assessor-agreement": 20,
    "biometric-performance": 300,
    "proficiency-testing": 10,
    "fuzzing-statistical": 10,
}


def validate_protocol_thresholds(protocol: str, value: object) -> list[str]:
    """Return deterministic threshold-contract gaps for one scoring protocol."""
    expected = PROTOCOL_THRESHOLD_FIELDS.get(protocol)
    if expected is None:
        return [f"unsupported benchmark protocol: {protocol}"]
    if not isinstance(value, dict) or set(value) != expected:
        return [
            "benchmark thresholds must contain exactly: " + ", ".join(sorted(expected))
        ]
    gaps: list[str] = []
    for name, item in value.items():
        if (
            not isinstance(item, (int, float))
            or isinstance(item, bool)
            or not math.isfinite(float(item))
            or float(item) < 0
            or (name != "minimum_executions" and float(item) > 1)
        ):
            gaps.append(f"benchmark threshold {name} is invalid")
    return gaps


def protocol_sufficiency_gaps(
    protocol: str,
    cases: list[Any],
    *,
    minimum_cases: int | None = None,
) -> list[str]:
    """Evaluate minimum statistical and stratum sufficiency before scoring."""
    floor = PROTOCOL_MINIMUM_CASES.get(protocol)
    if floor is None:
        return [f"unsupported benchmark protocol: {protocol}"]
    required = max(floor, minimum_cases or 0)
    gaps = (
        []
        if len(cases) >= required
        else [f"protocol requires at least {required} cases"]
    )

    if protocol in {"classification", "detection-evaluation"}:
        positives = sum(
            item.get("expected_positive") is True
            for item in cases
            if isinstance(item, dict)
        )
        negatives = sum(
            item.get("expected_positive") is False
            for item in cases
            if isinstance(item, dict)
        )
        if positives < 5:
            gaps.append("classification protocol requires at least five positive cases")
        if negatives < 5:
            gaps.append("classification protocol requires at least five negative cases")
    elif protocol == "conformance":
        expected = [
            item.get("expected_outcome") for item in cases if isinstance(item, dict)
        ]
        for outcome, minimum in (("pass", 2), ("fail", 2), ("not-applicable", 1)):
            if expected.count(outcome) < minimum:
                gaps.append(
                    f"conformance protocol requires at least {minimum} expected {outcome} case(s)"
                )
    elif protocol == "stochastic-adversarial":
        attacked = sum(
            item.get("attacked") is True for item in cases if isinstance(item, dict)
        )
        controls = sum(
            item.get("attacked") is False for item in cases if isinstance(item, dict)
        )
        if attacked < 20:
            gaps.append("stochastic protocol requires at least 20 attacked trials")
        if controls < 5:
            gaps.append(
                "stochastic protocol requires at least five unattacked controls"
            )
    elif protocol == "assessor-agreement":
        rater_counts = {
            len(item.get("ratings", []))
            for item in cases
            if isinstance(item, dict) and isinstance(item.get("ratings"), list)
        }
        if not rater_counts or min(rater_counts) < 2:
            gaps.append("assessor protocol requires at least two independent raters")
    elif protocol == "biometric-performance":
        trial_types = [
            item.get("trial_type") for item in cases if isinstance(item, dict)
        ]
        for trial_type in ("genuine", "impostor", "presentation-attack"):
            if trial_types.count(trial_type) < 100:
                gaps.append(
                    f"biometric protocol requires at least 100 {trial_type} trials"
                )
    elif protocol == "proficiency-testing":
        rounds = {
            item.get("round")
            for item in cases
            if isinstance(item, dict) and isinstance(item.get("round"), int)
        }
        participant_counts = {
            len(item.get("participant_results", []))
            for item in cases
            if isinstance(item, dict)
            and isinstance(item.get("participant_results"), list)
        }
        if len(rounds) < 2:
            gaps.append("proficiency protocol requires at least two rounds")
        if not participant_counts or min(participant_counts) < 3:
            gaps.append("proficiency protocol requires at least three participants")
    return gaps
