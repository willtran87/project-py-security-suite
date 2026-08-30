from __future__ import annotations

import json

import pytest

from py_security_suite.benchmark_pipeline import (
    BenchmarkExecutionPhase,
    BenchmarkExecutionTracker,
    evaluate_normalized_payload,
    run_benchmark_stages,
)


def test_execution_tracker_requires_ordered_non_reentrant_transitions() -> None:
    tracker = BenchmarkExecutionTracker()
    ordered = [
        BenchmarkExecutionPhase.AUTHORIZED,
        BenchmarkExecutionPhase.MANIFEST_ADMITTED,
        BenchmarkExecutionPhase.TRUST_ADMITTED,
        BenchmarkExecutionPhase.EVIDENCE_VERIFIED,
        BenchmarkExecutionPhase.REPLAY_COMMITTED,
        BenchmarkExecutionPhase.STAGES_EXECUTED,
        BenchmarkExecutionPhase.INPUTS_REVERIFIED,
        BenchmarkExecutionPhase.SCORED,
        BenchmarkExecutionPhase.RECEIPT_ASSEMBLED,
        BenchmarkExecutionPhase.RECEIPT_SIGNED,
        BenchmarkExecutionPhase.COMPLETED,
    ]
    for phase in ordered:
        tracker.advance(phase)

    assert tracker.phase is BenchmarkExecutionPhase.COMPLETED
    assert tracker.history == ["created", *(item.value for item in ordered)]
    with pytest.raises(RuntimeError, match="invalid benchmark execution transition"):
        tracker.advance(BenchmarkExecutionPhase.SCORED)
    with pytest.raises(RuntimeError, match="cannot fail terminal"):
        tracker.fail()


def test_execution_tracker_can_fail_once_from_nonterminal_phase() -> None:
    tracker = BenchmarkExecutionTracker()
    tracker.advance(BenchmarkExecutionPhase.AUTHORIZED)
    tracker.fail()
    assert tracker.history == ["created", "authorized", "failed"]
    with pytest.raises(RuntimeError, match="cannot fail terminal"):
        tracker.fail()


def test_stage_runner_attempts_cleanup_after_primary_failure() -> None:
    observed: list[str] = []

    def execute(stage: dict[str, object]) -> dict[str, object]:
        name = str(stage["name"])
        observed.append(name)
        return {"name": name, "status": "failed" if name == "run" else "passed"}

    result = run_benchmark_stages(
        [{"name": "run"}, {"name": "postprocess"}, {"name": "cleanup"}], execute
    )

    assert observed == ["run", "cleanup"]
    assert result.decision == "fail"
    assert result.failure_reason == "stage run failed"


def test_stage_runner_preserves_cleanup_failure() -> None:
    result = run_benchmark_stages(
        [{"name": "run"}, {"name": "cleanup"}],
        lambda stage: (
            {"name": stage["name"], "status": "failed"}
            if stage["name"] == "cleanup"
            else {"name": stage["name"], "status": "passed"}
        ),
    )
    assert result.failure_reason == "stage cleanup failed"


def test_stage_runner_attempts_cleanup_when_executor_raises() -> None:
    observed: list[str] = []

    def execute(stage: dict[str, object]) -> dict[str, object]:
        name = str(stage["name"])
        observed.append(name)
        if name == "run":
            raise OSError("injected process termination")
        return {"name": name, "status": "passed"}

    with pytest.raises(OSError, match="injected process termination"):
        run_benchmark_stages([{"name": "run"}, {"name": "cleanup"}], execute)
    assert observed == ["run", "cleanup"]


def test_normalized_evaluation_scores_and_applies_conservative_thresholds() -> None:
    manifest = {
        "benchmark_id": "benchmark-1",
        "protocol": "classification",
        "thresholds": {"minimum_precision": 0.8},
        "evaluation": {
            "minimum_cases": 1,
            "maximum_confidence_interval_width": 1.0,
        },
    }
    payload = json.dumps(
        {
            "schema_version": "1.0",
            "benchmark_id": "benchmark-1",
            "protocol": "classification",
            "cases": [
                {
                    "id": f"positive-{index}",
                    "expected_positive": True,
                    "observed_positive": True,
                    "strata": {},
                }
                for index in range(10)
            ]
            + [
                {
                    "id": f"negative-{index}",
                    "expected_positive": False,
                    "observed_positive": False,
                    "strata": {},
                }
                for index in range(10)
            ],
        }
    ).encode()

    result = evaluate_normalized_payload(payload, manifest=manifest, enhanced=True)

    assert result.case_count == 20
    assert result.metrics is not None
    assert result.statistical_sufficiency["complete"] is True
    assert "precision_wilson_lower_95 is below" in str(result.failure_reason)


def test_normalized_evaluation_fails_closed_on_invalid_or_insufficient_data() -> None:
    manifest = {
        "benchmark_id": "benchmark-1",
        "protocol": "classification",
        "thresholds": {},
        "evaluation": {
            "minimum_cases": 2,
            "maximum_confidence_interval_width": 1.0,
        },
    }
    malformed = evaluate_normalized_payload(
        b"not-json", manifest=manifest, enhanced=True
    )
    insufficient = evaluate_normalized_payload(
        json.dumps(
            {
                "schema_version": "1.0",
                "benchmark_id": "benchmark-1",
                "protocol": "classification",
                "cases": [
                    {
                        "id": "one",
                        "expected_positive": True,
                        "observed_positive": True,
                        "strata": {},
                    }
                ],
            }
        ).encode(),
        manifest=manifest,
        enhanced=True,
    )

    assert malformed.metrics is None
    assert "normalized result is invalid" in str(malformed.failure_reason)
    assert insufficient.metrics is None
    assert insufficient.statistical_sufficiency["complete"] is False
