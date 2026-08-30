from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from .benchmark_protocols import protocol_sufficiency_gaps
from .benchmark_scoring import (
    _score_normalized_result,
    _threshold_failures,
    _uncertainty_failures,
)
from .strict_json import loads as strict_loads


class BenchmarkExecutionPhase(StrEnum):
    CREATED = "created"
    AUTHORIZED = "authorized"
    MANIFEST_ADMITTED = "manifest-admitted"
    TRUST_ADMITTED = "trust-admitted"
    EVIDENCE_VERIFIED = "evidence-verified"
    REPLAY_COMMITTED = "replay-committed"
    STAGES_EXECUTED = "stages-executed"
    INPUTS_REVERIFIED = "inputs-reverified"
    SCORED = "scored"
    RECEIPT_ASSEMBLED = "receipt-assembled"
    RECEIPT_SIGNED = "receipt-signed"
    COMPLETED = "completed"
    FAILED = "failed"


_ALLOWED_TRANSITIONS = {
    BenchmarkExecutionPhase.CREATED: {BenchmarkExecutionPhase.AUTHORIZED},
    BenchmarkExecutionPhase.AUTHORIZED: {BenchmarkExecutionPhase.MANIFEST_ADMITTED},
    BenchmarkExecutionPhase.MANIFEST_ADMITTED: {BenchmarkExecutionPhase.TRUST_ADMITTED},
    BenchmarkExecutionPhase.TRUST_ADMITTED: {BenchmarkExecutionPhase.EVIDENCE_VERIFIED},
    BenchmarkExecutionPhase.EVIDENCE_VERIFIED: {
        BenchmarkExecutionPhase.REPLAY_COMMITTED
    },
    BenchmarkExecutionPhase.REPLAY_COMMITTED: {BenchmarkExecutionPhase.STAGES_EXECUTED},
    BenchmarkExecutionPhase.STAGES_EXECUTED: {
        BenchmarkExecutionPhase.INPUTS_REVERIFIED
    },
    BenchmarkExecutionPhase.INPUTS_REVERIFIED: {BenchmarkExecutionPhase.SCORED},
    BenchmarkExecutionPhase.SCORED: {BenchmarkExecutionPhase.RECEIPT_ASSEMBLED},
    BenchmarkExecutionPhase.RECEIPT_ASSEMBLED: {
        BenchmarkExecutionPhase.RECEIPT_SIGNED,
        BenchmarkExecutionPhase.COMPLETED,
    },
    BenchmarkExecutionPhase.RECEIPT_SIGNED: {BenchmarkExecutionPhase.COMPLETED},
    BenchmarkExecutionPhase.COMPLETED: set(),
    BenchmarkExecutionPhase.FAILED: set(),
}


@dataclass(slots=True)
class BenchmarkExecutionTracker:
    """Fail-closed transition guard for the benchmark execution transaction."""

    phase: BenchmarkExecutionPhase = BenchmarkExecutionPhase.CREATED
    history: list[str] = field(default_factory=lambda: ["created"])

    def advance(self, phase: BenchmarkExecutionPhase) -> None:
        if phase not in _ALLOWED_TRANSITIONS[self.phase]:
            raise RuntimeError(
                f"invalid benchmark execution transition: {self.phase} -> {phase}"
            )
        self.phase = phase
        self.history.append(phase.value)

    def fail(self) -> None:
        if self.phase in {
            BenchmarkExecutionPhase.COMPLETED,
            BenchmarkExecutionPhase.FAILED,
        }:
            raise RuntimeError(
                f"cannot fail terminal benchmark execution phase: {self.phase}"
            )
        self.phase = BenchmarkExecutionPhase.FAILED
        self.history.append(BenchmarkExecutionPhase.FAILED.value)


@dataclass(frozen=True, slots=True)
class StageRunResult:
    stages: list[dict[str, Any]]
    decision: str
    failure_reason: str | None


def run_benchmark_stages(
    stages: list[dict[str, Any]],
    execute: Callable[[dict[str, Any]], dict[str, Any]],
) -> StageRunResult:
    """Run ordered stages and guarantee one cleanup attempt after early failure."""
    receipts: list[dict[str, Any]] = []
    decision = "pass"
    failure_reason: str | None = None
    try:
        for stage in stages:
            receipt = execute(stage)
            receipts.append(receipt)
            if receipt["status"] != "passed":
                decision = "fail"
                failure_reason = f"stage {stage['name']} {receipt['status']}"
                break
    finally:
        completed_names = {item["name"] for item in receipts}
        for cleanup in (
            item
            for item in stages
            if item["name"] == "cleanup" and "cleanup" not in completed_names
        ):
            receipt = execute(cleanup)
            receipts.append(receipt)
            if receipt["status"] != "passed" and decision == "pass":
                decision = "fail"
                failure_reason = f"cleanup stage {receipt['status']}"
    return StageRunResult(receipts, decision, failure_reason)


@dataclass(frozen=True, slots=True)
class NormalizedEvaluation:
    metrics: dict[str, Any] | None
    case_count: int
    statistical_sufficiency: dict[str, Any]
    failure_reason: str | None


def evaluate_normalized_payload(
    payload: bytes,
    *,
    manifest: dict[str, Any],
    enhanced: bool,
) -> NormalizedEvaluation:
    """Parse, validate, score, and threshold one bounded normalized result."""
    statistical_sufficiency: dict[str, Any] = {
        "enforced": enhanced,
        "complete": not enhanced,
        "gaps": [],
    }
    try:
        result = strict_loads(payload)
        cases = result.get("cases") if isinstance(result, dict) else None
        sufficiency_gaps = (
            protocol_sufficiency_gaps(
                manifest["protocol"],
                cases,
                minimum_cases=manifest.get("evaluation", {}).get("minimum_cases"),
            )
            if isinstance(cases, list)
            else ["normalized benchmark cases are missing"]
        )
        statistical_sufficiency = {
            "enforced": enhanced,
            "complete": not sufficiency_gaps,
            "gaps": sufficiency_gaps,
        }
        if enhanced and sufficiency_gaps:
            raise ValueError("; ".join(sufficiency_gaps))
        metrics = _score_normalized_result(
            result,
            benchmark_id=manifest["benchmark_id"],
            protocol=manifest["protocol"],
        )
        case_count = metrics.pop("case_count")
        threshold_failures = _threshold_failures(
            metrics,
            manifest["thresholds"],
            conservative=enhanced,
        )
        if enhanced:
            threshold_failures.extend(
                _uncertainty_failures(metrics, manifest["evaluation"])
            )
        return NormalizedEvaluation(
            metrics=metrics,
            case_count=case_count,
            statistical_sufficiency=statistical_sufficiency,
            failure_reason="; ".join(threshold_failures) or None,
        )
    except (TypeError, ValueError) as exc:
        return NormalizedEvaluation(
            metrics=None,
            case_count=0,
            statistical_sufficiency=statistical_sufficiency,
            failure_reason=f"normalized result is invalid: {exc}",
        )
