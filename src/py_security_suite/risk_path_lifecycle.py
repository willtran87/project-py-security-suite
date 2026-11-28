"""Baseline and change-lifecycle attribution for risk-path targets."""

from __future__ import annotations

from typing import Any

from .risk_path_values import _object, _strings, _nonnegative_integer
from .risk_path_common import _optional_string


__all__ = [
    "_baseline_lifecycle_context",
    "_bounded_baseline_match",
    "_change_lifecycle_attribution",
    "_change_lifecycle_review_factors",
]


def _baseline_lifecycle_context(value: Any) -> dict[str, Any]:
    """Validate whether finding lifecycle is comparable before using it."""
    if not isinstance(value, dict) or value.get("schema_version") not in {
        "1.0",
        "1.1",
    }:
        return {
            "state": "not-established",
            "configured": False,
            "comparable": False,
            "reasons": ["finding-delta evidence is unavailable or invalid"],
            "evidence_artifacts": [],
        }
    if value.get("configured") is False:
        return {
            "state": "not-configured",
            "configured": False,
            "comparable": False,
            "reasons": ["no approved finding baseline was configured"],
            "evidence_artifacts": ["finding-delta.json"],
        }
    comparison = _object(value.get("comparison"))
    reasons = _strings(comparison.get("reasons") or value.get("errors"), 20)
    if value.get("configured") is True and comparison.get("comparable") is True:
        return {
            "state": "comparable",
            "configured": True,
            "comparable": True,
            "reasons": [],
            "evidence_artifacts": ["finding-delta.json"],
        }
    if value.get("configured") is True and comparison.get("comparable") is False:
        return {
            "state": "incomparable",
            "configured": True,
            "comparable": False,
            "reasons": reasons or ["configured finding baseline is not comparable"],
            "evidence_artifacts": ["finding-delta.json"],
        }
    return {
        "state": "not-established",
        "configured": value.get("configured") is True,
        "comparable": False,
        "reasons": reasons or ["finding baseline comparability was not established"],
        "evidence_artifacts": ["finding-delta.json"],
    }


def _bounded_baseline_match(value: Any) -> dict[str, str | None]:
    match = _object(value)
    return {
        "match_strategy": _optional_string(match.get("match_strategy")),
        "previous_finding_id": _optional_string(match.get("previous_finding_id")),
        "previous_fingerprint": _optional_string(match.get("previous_fingerprint")),
        "previous_status": _optional_string(match.get("previous_status")),
    }


def _change_lifecycle_attribution(
    target: dict[str, Any], baseline: dict[str, Any]
) -> dict[str, Any] | None:
    if target.get("kind") != "finding":
        return None
    lifecycle = str(target.get("lifecycle_status") or "unclassified")
    validation = _object(target.get("validation"))
    changed = validation.get("changed_line")
    change_scope = (
        "changed-line"
        if changed is True
        else "outside-retained-change-scope"
        if changed is False
        else "not-established"
    )
    baseline_state = str(baseline.get("state") or "not-established")
    classification = _change_lifecycle_classification(
        baseline_state, lifecycle, change_scope
    )
    validation_status = str(validation.get("assessment_status") or "not-assessed")
    signal = _change_lifecycle_review_signal(
        baseline_state, lifecycle, change_scope, validation_status
    )
    assurance = str(
        _object(target.get("evidence_assurance")).get("review_status") or "not-assessed"
    )
    result: dict[str, Any] = {
        "baseline_state": baseline_state,
        "baseline_configured": baseline.get("configured") is True,
        "baseline_comparable": baseline.get("comparable") is True,
        "baseline_reasons": _strings(baseline.get("reasons"), 20),
        "lifecycle_status": lifecycle,
        "baseline_match": _object(target.get("baseline_match")),
        "change_scope": change_scope,
        "classification": classification,
        "review_signal": signal,
        "validation_status": validation_status,
        "evidence_assurance_status": assurance,
        "entry_point_runtime_statuses": {
            "observed": 0,
            "not-observed": 0,
            "not-available": 0,
        },
        "review_factors": [],
        "evidence_artifacts": list(baseline.get("evidence_artifacts") or []),
        "recommended_action": _change_lifecycle_action(
            baseline_state, lifecycle, change_scope, validation_status
        ),
    }
    result["review_factors"] = _change_lifecycle_review_factors(result)
    return result


def _change_lifecycle_classification(
    baseline_state: str, lifecycle: str, change_scope: str
) -> str:
    if baseline_state != "comparable":
        return "baseline-" + baseline_state
    prefix = {
        "new": "baseline-new",
        "regression": "regression",
        "existing": "existing",
    }.get(lifecycle, "lifecycle-unclassified")
    return {
        "changed-line": prefix + "-on-changed-line",
        "outside-retained-change-scope": prefix + "-outside-change-scope",
    }.get(change_scope, prefix + "-change-scope-unavailable")


def _change_lifecycle_review_signal(
    baseline_state: str,
    lifecycle: str,
    change_scope: str,
    validation_status: str,
) -> str:
    if baseline_state != "comparable":
        return "baseline-not-established"
    validation_gap = validation_status in {"gap", "partial", "not-assessed"}
    if lifecycle in {"new", "regression"}:
        if change_scope == "changed-line":
            return (
                "baseline-new-or-regressed-change-gap"
                if validation_gap
                else "baseline-new-or-regressed-change-aligned"
            )
        return "baseline-new-or-regressed-outside-change"
    if lifecycle == "existing" and change_scope == "changed-line":
        return "existing-change-gap" if validation_gap else "existing-change-aligned"
    return "existing-or-unclassified-debt"


def _change_lifecycle_review_factors(value: dict[str, Any]) -> list[str]:
    runtime = _object(value.get("entry_point_runtime_statuses"))
    factors = [
        "baseline:" + str(value.get("baseline_state") or "not-established"),
        "lifecycle:" + str(value.get("lifecycle_status") or "unclassified"),
        "change:" + str(value.get("change_scope") or "not-established"),
        "validation:" + str(value.get("validation_status") or "not-assessed"),
        "evidence:" + str(value.get("evidence_assurance_status") or "not-assessed"),
    ]
    for status in ("observed", "not-observed", "not-available"):
        count = _nonnegative_integer(runtime.get(status))
        if count:
            factors.append(f"entry-runtime:{status}:{count}")
    return factors


def _change_lifecycle_action(
    baseline_state: str,
    lifecycle: str,
    change_scope: str,
    validation_status: str,
) -> str:
    if baseline_state != "comparable":
        return (
            "Do not attribute the finding's default lifecycle to the current change; "
            "supply a digest-approved comparable findings baseline or record the "
            "change-origin decision outside this derived route context."
        )
    validation_gap = validation_status in {"gap", "partial", "not-assessed"}
    if lifecycle in {"new", "regression"} and change_scope == "changed-line":
        action = (
            "Review this baseline-new or regressed finding as exact changed-line "
            "release work; remediate it or record a governed disposition."
        )
        if validation_gap:
            action += " Close the linked focused-test and coverage gap before release."
        return action
    if lifecycle in {"new", "regression"}:
        return (
            "Review the baseline-new or regressed finding, but do not attribute it "
            "to the retained change scope without exact changed-line evidence."
        )
    if lifecycle == "existing" and change_scope == "changed-line":
        return (
            "Review the modified pre-existing finding for risk amplification and "
            + (
                "close the linked validation gap."
                if validation_gap
                else "retain aligned regression evidence."
            )
        )
    return (
        "Track the finding as pre-existing debt under its owner and remediation policy."
    )
