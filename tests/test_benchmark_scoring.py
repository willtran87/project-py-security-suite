from __future__ import annotations

import pytest

from py_security_suite.benchmark_scoring import (
    _score_normalized_result,
    _threshold_failures,
    _uncertainty_failures,
    _wilson_lower,
    _wilson_upper,
)


def _score(protocol: str, cases: list[object]) -> dict[str, object]:
    return _score_normalized_result(
        {
            "schema_version": "1.0",
            "benchmark_id": "benchmark-1",
            "protocol": protocol,
            "cases": cases,
        },
        benchmark_id="benchmark-1",
        protocol=protocol,
    )


def _case(case_id: str, **values: object) -> dict[str, object]:
    return {"id": case_id, **values, "strata": {"language": "python"}}


@pytest.mark.parametrize("protocol", ["classification", "detection-evaluation"])
def test_classification_scores_all_confusion_matrix_outcomes(protocol: str) -> None:
    metrics = _score(
        protocol,
        [
            _case("tp", expected_positive=True, observed_positive=True),
            _case("fp", expected_positive=False, observed_positive=True),
            _case("tn", expected_positive=False, observed_positive=False),
            _case("fn", expected_positive=True, observed_positive=False),
        ],
    )

    assert metrics["true_positive"] == 1
    assert metrics["false_positive"] == 1
    assert metrics["true_negative"] == 1
    assert metrics["false_negative"] == 1
    assert metrics["balanced_accuracy"] == 0.5


@pytest.mark.parametrize("protocol", ["verification-competition", "test-generation"])
def test_outcome_accuracy_tracks_unknown_results(protocol: str) -> None:
    metrics = _score(
        protocol,
        [
            _case("correct", expected="pass", observed="pass"),
            _case("unknown", expected="fail", observed="unknown"),
        ],
    )

    assert metrics["correct"] == 1
    assert metrics["incorrect"] == 1
    assert metrics["unknown"] == 1
    assert metrics["accuracy"] == 0.5


def test_conformance_scores_applicable_negative_and_not_applicable_cases() -> None:
    metrics = _score(
        "conformance",
        [
            _case("pass", expected_outcome="pass", observed_outcome="pass"),
            _case("negative", expected_outcome="fail", observed_outcome="fail"),
            _case(
                "na",
                expected_outcome="not-applicable",
                observed_outcome="not-applicable",
            ),
        ],
    )

    assert metrics["applicable_case_count"] == 2
    assert metrics["passed_cases"] == 1
    assert metrics["failed_cases"] == 1
    assert metrics["negative_cases"] == 1
    assert metrics["outcome_accuracy"] == 1.0


def test_temporal_calibration_computes_brier_score() -> None:
    metrics = _score(
        "temporal-calibration",
        [
            _case("positive", predicted_probability=0.75, observed=True),
            _case("negative", predicted_probability=0.25, observed=False),
        ],
    )

    assert metrics == {"case_count": 2, "brier_score": 0.0625}


def test_stochastic_scoring_limits_compromises_to_attacked_trials() -> None:
    metrics = _score(
        "stochastic-adversarial",
        [
            _case("blocked", attacked=True, compromised=False, utility=0.8),
            _case("compromised", attacked=True, compromised=True, utility=0.4),
            _case("control", attacked=False, compromised=True, utility=1.0),
        ],
    )

    assert metrics["attacked_trials"] == 2
    assert metrics["attack_success_rate"] == 0.5
    assert metrics["mean_utility"] == pytest.approx(0.733333333333)
    assert metrics["utility_variance"] == pytest.approx(0.062222222222)


def test_assessor_agreement_uses_fixed_rater_panel_and_chance_correction() -> None:
    metrics = _score(
        "assessor-agreement",
        [
            _case("one", ratings=["high", "high", "low"]),
            _case("two", ratings=["low", "low", "low"]),
        ],
    )

    assert metrics["reviewers"] == 3
    assert metrics["agreement"] == pytest.approx(2 / 3)
    assert isinstance(metrics["chance_corrected_agreement"], float)


def test_biometric_scoring_covers_demographics_and_attack_instruments() -> None:
    metrics = _score(
        "biometric-performance",
        [
            {
                "id": "g-a",
                "trial_type": "genuine",
                "accepted": True,
                "strata": {"demographic": "a"},
            },
            {
                "id": "i-a",
                "trial_type": "impostor",
                "accepted": False,
                "strata": {"demographic": "a"},
            },
            {
                "id": "g-b",
                "trial_type": "genuine",
                "accepted": False,
                "strata": {"demographic": "b"},
            },
            {
                "id": "i-b",
                "trial_type": "impostor",
                "accepted": True,
                "strata": {"demographic": "b"},
            },
            {
                "id": "attack",
                "trial_type": "presentation-attack",
                "accepted": False,
                "strata": {"attack_instrument": "mask"},
            },
        ],
    )

    assert metrics["demographic_groups"] == 2
    assert metrics["attack_instrument_groups"] == 1
    assert metrics["false_match_rate"] == 0.5
    assert metrics["false_non_match_rate"] == 0.5
    assert metrics["iapar"] == 0.0


def test_proficiency_scoring_tracks_rounds_accuracy_and_agreement() -> None:
    metrics = _score(
        "proficiency-testing",
        [
            _case(
                "round-1",
                assigned_value="pass",
                participant_results=["pass", "pass", "fail"],
                round=1,
            ),
            _case(
                "round-2",
                assigned_value="fail",
                participant_results=["fail", "fail", "fail"],
                round=2,
            ),
        ],
    )

    assert metrics["participants"] == 3
    assert metrics["rounds"] == 2
    assert metrics["reference_accuracy"] == pytest.approx(5 / 6)


def test_fuzzing_scoring_aggregates_campaigns() -> None:
    metrics = _score(
        "fuzzing-statistical",
        [
            _case(
                "one",
                executions=100,
                unique_crashes=1,
                coverage_before=0.4,
                coverage_after=0.6,
            ),
            _case(
                "two",
                executions=200,
                unique_crashes=0,
                coverage_before=0.6,
                coverage_after=0.7,
            ),
        ],
    )

    assert metrics == {
        "case_count": 2,
        "executions": 300,
        "unique_crashes": 1,
        "coverage_gain": 0.15,
    }


@pytest.mark.parametrize(
    ("value", "message"),
    [
        ({}, "expected schema_version"),
        (
            {
                "schema_version": "1.0",
                "benchmark_id": "wrong",
                "protocol": "classification",
                "cases": [{}],
            },
            "identity does not match",
        ),
        (
            {
                "schema_version": "1.0",
                "benchmark_id": "benchmark-1",
                "protocol": "classification",
                "cases": [],
            },
            "non-empty bounded array",
        ),
    ],
)
def test_normalized_result_rejects_invalid_envelopes(
    value: object, message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        _score_normalized_result(
            value, benchmark_id="benchmark-1", protocol="classification"
        )


def test_normalized_result_rejects_unsupported_protocol() -> None:
    with pytest.raises(ValueError, match="protocol is unsupported"):
        _score_normalized_result(
            {
                "schema_version": "1.0",
                "benchmark_id": "benchmark-1",
                "protocol": "future-protocol",
                "cases": [{"id": "one"}],
            },
            benchmark_id="benchmark-1",
            protocol="future-protocol",
        )


@pytest.mark.parametrize(
    "case",
    [
        "not-an-object",
        {"id": "duplicate", "expected": "a", "observed": "a", "strata": {}},
    ],
)
def test_case_identity_is_strict_and_unique(case: object) -> None:
    cases = [
        {"id": "duplicate", "expected": "a", "observed": "a", "strata": {}},
        case,
    ]
    with pytest.raises(ValueError, match="case|identifiers"):
        _score("verification-competition", cases)


@pytest.mark.parametrize(
    ("protocol", "case", "message"),
    [
        (
            "temporal-calibration",
            _case("bad", predicted_probability=1.1, observed=True),
            "calibration observation",
        ),
        (
            "stochastic-adversarial",
            _case("bad", attacked=True, compromised=False, utility=True),
            "stochastic utility",
        ),
        (
            "assessor-agreement",
            _case("bad", ratings=["one"]),
            "assessor ratings",
        ),
        (
            "biometric-performance",
            {"id": "bad", "trial_type": "genuine", "accepted": True, "strata": {}},
            "requires demographic",
        ),
        (
            "proficiency-testing",
            _case("bad", assigned_value="pass", participant_results=["pass"], round=1),
            "assigned value or results",
        ),
        (
            "fuzzing-statistical",
            _case(
                "bad",
                executions=-1,
                unique_crashes=0,
                coverage_before=0.1,
                coverage_after=0.2,
            ),
            "fuzzing counts",
        ),
    ],
)
def test_protocol_contracts_reject_invalid_cases(
    protocol: str, case: dict[str, object], message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        _score(protocol, [case])


def test_conservative_thresholds_and_uncertainty_use_interval_bounds() -> None:
    metrics = {
        "precision": 0.95,
        "precision_wilson_lower_95": 0.7,
        "false_positive_rate": 0.01,
        "false_positive_rate_wilson_upper_95": 0.2,
        "precision_interval_width_95": 0.25,
    }

    assert _threshold_failures(
        metrics,
        {"minimum_precision": 0.8, "maximum_false_positive_rate": 0.1},
        conservative=True,
    ) == [
        "precision_wilson_lower_95 is below minimum_precision",
        "false_positive_rate_wilson_upper_95 exceeds maximum_false_positive_rate",
    ]
    assert _uncertainty_failures(
        metrics, {"maximum_confidence_interval_width": 0.2}
    ) == ["confidence interval width 0.250000 exceeds 0.200000"]
    assert (
        _uncertainty_failures(
            {"accuracy": 1.0}, {"maximum_confidence_interval_width": 0.2}
        )
        == []
    )


def test_wilson_bounds_handle_zero_trials_and_bound_observed_rate() -> None:
    assert _wilson_lower(0, 0) == 0.0
    assert _wilson_upper(0, 0) == 0.0
    assert _wilson_lower(8, 10) < 0.8 < _wilson_upper(8, 10)
