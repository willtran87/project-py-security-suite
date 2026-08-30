from __future__ import annotations

import math

import pytest

from py_security_suite.benchmark_protocols import (
    PROTOCOL_THRESHOLD_FIELDS,
    protocol_sufficiency_gaps,
    validate_protocol_thresholds,
)
from py_security_suite.industry_benchmark_scoring import (
    meets_protocol_thresholds,
    protocol_acceptance,
    protocol_metrics_valid,
)


@pytest.mark.parametrize(
    ("protocol", "metrics"),
    [
        (
            "temporal-calibration",
            {
                "brier_score": 0.1,
                "expected_calibration_error": 0.1,
                "recall_at_budget": 0.8,
                "effort": 0.2,
                "observations": 100,
            },
        ),
        ("temporal-calibration", {"brier_score": 0.1, "cases": 100}),
        (
            "verification-competition",
            {"correct": 18, "incorrect": 1, "unknown": 1, "accuracy": 0.9},
        ),
        (
            "test-generation",
            {"coverage": 0.8, "faults_detected": 2, "valid_tests": 5, "score": 1.0},
        ),
        ("test-generation", {"accuracy": 0.9, "cases": 20}),
        (
            "fuzzing-statistical",
            {"trials": 10, "median_edges": 100, "effect_size": 0.4, "p_value": 0.01},
        ),
        (
            "fuzzing-statistical",
            {"trials": 10, "executions": 1000, "coverage_gain": 0.2},
        ),
        (
            "stochastic-adversarial",
            {
                "repetitions": 5,
                "attack_success_rate": 0.1,
                "utility_retention": 0.9,
                "variance": 0.1,
            },
        ),
        (
            "assessor-agreement",
            {"reviewers": 2, "cases": 20, "inter_rater_agreement": 0.8},
        ),
        (
            "biometric-performance",
            {
                "genuine_attempts": 100,
                "impostor_attempts": 100,
                "attack_attempts": 100,
                "demographic_groups": 2,
                "threshold_locked": True,
                "false_match_rate": 0.01,
                "false_non_match_rate": 0.01,
                "iapar": 0.01,
                "fmr_wilson_upper_95": 0.02,
                "fnmr_wilson_upper_95": 0.02,
                "iapar_wilson_upper_95": 0.02,
                "worst_group_fmr_wilson_upper_95": 0.03,
                "worst_group_fnmr_wilson_upper_95": 0.03,
            },
        ),
        (
            "proficiency-testing",
            {
                "participants": 3,
                "cases": 10,
                "rounds": 2,
                "blinded": True,
                "agreement": 0.9,
                "reference_accuracy": 0.9,
                "chance_corrected_agreement": 0.8,
            },
        ),
        (
            "conformance",
            {
                "passed_cases": 8,
                "failed_cases": 2,
                "negative_cases": 2,
                "conformance_rate": 0.8,
                "cases": 10,
            },
        ),
        (
            "detection-evaluation",
            {
                "techniques": 10,
                "detections": 8,
                "analytic_coverage": 0.8,
                "false_positive_rate": 0.1,
                "latency_ms": 10,
            },
        ),
        (
            "detection-evaluation",
            {
                "cases": 20,
                "precision": 0.9,
                "recall": 0.8,
                "f1": 0.85,
                "false_positive_rate": 0.1,
            },
        ),
    ],
)
def test_protocol_metric_contracts_accept_complete_evidence(
    protocol: str, metrics: dict[str, object]
) -> None:
    assert protocol_metrics_valid(protocol, metrics) is True


def test_protocol_metric_contracts_reject_wrong_types_and_bounds() -> None:
    assert protocol_metrics_valid("unknown", {}) is False
    assert protocol_metrics_valid("conformance", []) is False
    assert (
        protocol_metrics_valid(
            "proficiency-testing",
            {
                "participants": 3,
                "cases": 10,
                "rounds": 2,
                "blinded": True,
                "agreement": 0.9,
                "reference_accuracy": 0.9,
                "chance_corrected_agreement": 2,
            },
        )
        is False
    )
    assert (
        protocol_metrics_valid(
            "fuzzing-statistical",
            {
                "trials": 10,
                "median_edges": 100,
                "effect_size": math.inf,
                "p_value": 0.1,
            },
        )
        is False
    )


def test_protocol_acceptance_and_threshold_direction_are_fail_closed() -> None:
    accepted = {
        "acceptance": {
            "criteria_sha256": "a" * 64,
            "met": True,
            "authority": {"organization_approved": True, "organization_id": "lab"},
        }
    }
    assert protocol_acceptance(accepted) is True
    assert protocol_acceptance({}) is False
    assert protocol_acceptance([]) is False
    assert (
        meets_protocol_thresholds(
            {"precision": 0.9, "false_positive_rate": 0.1},
            {"minimum_precision": 0.8, "maximum_false_positive_rate": 0.2},
        )
        is True
    )
    assert (
        meets_protocol_thresholds({"precision": 0.7}, {"minimum_precision": 0.8})
        is False
    )
    assert (
        meets_protocol_thresholds(
            {"attack_success_rate_wilson_upper_95": 0.3},
            {"maximum_attack_success_rate": 0.2},
        )
        is False
    )
    assert meets_protocol_thresholds({}, {}) is False


def test_threshold_contracts_cover_every_registered_protocol() -> None:
    for protocol, fields in PROTOCOL_THRESHOLD_FIELDS.items():
        valid = {
            field: (10 if field == "minimum_executions" else 0.5) for field in fields
        }
        assert validate_protocol_thresholds(protocol, valid) == []
        invalid = dict(valid)
        invalid[next(iter(fields))] = float("nan")
        assert validate_protocol_thresholds(protocol, invalid)
    assert validate_protocol_thresholds("unknown", {})
    assert validate_protocol_thresholds("classification", [])


def test_protocol_sufficiency_checks_each_specialized_design() -> None:
    assert protocol_sufficiency_gaps("unknown", [])
    assert protocol_sufficiency_gaps("classification", [])
    conformance = [
        {"expected_outcome": outcome}
        for outcome in ("pass", "pass", "fail", "fail", "not-applicable")
    ] * 2
    assert protocol_sufficiency_gaps("conformance", conformance) == []
    stochastic = [{"attacked": True}] * 25 + [{"attacked": False}] * 5
    assert protocol_sufficiency_gaps("stochastic-adversarial", stochastic) == []
    assessors = [{"ratings": ["a", "b"]}] * 20
    assert protocol_sufficiency_gaps("assessor-agreement", assessors) == []
    biometric = sum(
        (
            [{"trial_type": name}] * 100
            for name in ("genuine", "impostor", "presentation-attack")
        ),
        [],
    )
    assert protocol_sufficiency_gaps("biometric-performance", biometric) == []
    proficiency = [
        {"round": round_id, "participant_results": [1, 2, 3]}
        for round_id in (1, 2)
        for _ in range(5)
    ]
    assert protocol_sufficiency_gaps("proficiency-testing", proficiency) == []
