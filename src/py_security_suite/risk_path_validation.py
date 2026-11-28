from __future__ import annotations

from typing import Any

from .risk_path_values import _object, _strings
from .risk_path_common import (
    _artifact_available,
    _optional_boolean,
    _optional_number,
    _optional_string,
    _test_execution_available,
)


__all__ = [
    "_assess_validation",
    "_entry_runtime_context",
    "_entry_runtime_counts",
    "_runtime_context",
    "_surface_validation",
    "_validation_context",
]


def _entry_runtime_context(
    entry: dict[str, Any], runtime_index: dict[str, dict[str, Any]]
) -> dict[str, Any]:
    target = _optional_string(entry.get("target"))
    record = runtime_index.get(target or "")
    state = _optional_string(record.get("reachability_state")) if record else None
    observation = (
        _optional_string(record.get("runtime_observation")) if record else None
    )
    assessment = (
        "observed"
        if observation == "observed"
        else "not-observed"
        if observation == "not-observed"
        else "not-available"
    )
    return {
        "target_node_id": target,
        "node_evidence_available": record is not None,
        "reachability_state": state,
        "runtime_observation": observation,
        "assessment": assessment,
        "evidence_artifacts": ["reachability.json"] if record is not None else [],
    }


def _entry_runtime_counts(values: Any) -> dict[str, int]:
    exposures = list(values)
    by_entry: dict[str, dict[str, Any]] = {}
    for exposure in exposures:
        if not isinstance(exposure, dict):
            continue
        entry = _object(exposure.get("entry_point"))
        identifier = _optional_string(entry.get("id"))
        if identifier:
            by_entry[identifier] = exposure
    return {
        status: sum(
            _object(exposure.get("runtime_context")).get("assessment") == status
            for exposure in by_entry.values()
        )
        for status in ("observed", "not-observed", "not-available")
    }


def _validation_context(
    source: dict[str, Any], structural: dict[str, Any], exposure: dict[str, Any]
) -> dict[str, Any]:
    change = _object(structural.get("change_impact"))
    cross = _object(exposure.get("cross_references"))
    mapped = _strings(
        change.get("associated_test_files")
        or change.get("direct_test_files")
        or cross.get("mapped_test_files"),
        25,
    )
    return {
        "changed_line": _optional_boolean(source.get("changed_line")),
        "line_covered": _optional_boolean(source.get("line_covered")),
        "coverage_percent": _optional_number(source.get("coverage_percent")),
        "mapped_test_files": mapped,
        "focused_test_status": _optional_string(
            change.get("focused_test_validation_status")
            or cross.get("focused_test_validation_status")
        ),
        "coverage_alignment": _optional_string(
            change.get("test_coverage_alignment")
            or cross.get("test_coverage_alignment")
        ),
        "gap_reasons": _strings(
            change.get("validation_gap_reasons") or cross.get("validation_gap_reasons"),
            10,
        ),
        "action": _optional_string(
            change.get("validation_action") or cross.get("validation_action")
        ),
    }


def _surface_validation(structural: dict[str, Any]) -> dict[str, Any]:
    return {
        "changed_line": _optional_boolean(structural.get("changed_line")),
        "line_covered": _optional_boolean(structural.get("line_covered")),
        "coverage_percent": _optional_number(structural.get("coverage_percent")),
        "mapped_test_files": _strings(structural.get("mapped_test_files"), 25),
        "focused_test_status": _optional_string(
            structural.get("focused_test_validation_status")
        ),
        "coverage_alignment": _optional_string(
            structural.get("test_coverage_alignment")
        ),
        "gap_reasons": _strings(structural.get("validation_gap_reasons"), 10),
        "action": _optional_string(structural.get("validation_action")),
    }


def _assess_validation(
    validation: dict[str, Any], artifacts: dict[str, Any]
) -> dict[str, Any]:
    evidence = {
        "change_scope": _artifact_available(
            artifacts.get("diff-coverage.json"), "src_stats"
        ),
        "coverage": _artifact_available(
            artifacts.get("coverage-summary.json"), "files"
        ),
        "test_execution": _test_execution_available(artifacts),
    }
    explicit = bool(
        validation.get("changed_line") is not None
        or validation.get("line_covered") is not None
        or validation.get("coverage_percent") is not None
        or validation.get("mapped_test_files")
        or validation.get("focused_test_status")
        or validation.get("coverage_alignment")
        or validation.get("gap_reasons")
    )
    reasons: list[str] = []
    if not evidence["change_scope"]:
        reasons.append("retained change scope is unavailable")
    if not evidence["coverage"]:
        reasons.append("retained line coverage is unavailable")
    if not evidence["test_execution"]:
        reasons.append("retained test execution is unavailable")
    aligned = validation.get("coverage_alignment") == "aligned-current-evidence" or (
        validation.get("line_covered") is True
        and validation.get("focused_test_status") == "passed"
    )
    if _has_validation_gap(validation):
        status = "gap"
    elif all(evidence.values()) and aligned:
        status = "aligned"
    elif explicit:
        status = "partial"
    else:
        status = "not-assessed"
    if status in {"partial", "not-assessed"}:
        if validation.get("line_covered") is not True:
            reasons.append("target line coverage is not established")
        if not validation.get("mapped_test_files"):
            reasons.append("focused tests are not mapped")
        if validation.get("focused_test_status") != "passed":
            reasons.append("focused test execution is not established")
    return validation | {
        "assessment_status": status,
        "assessment_reasons": reasons,
        "evidence_available": evidence,
    }


def _runtime_context(
    source: dict[str, Any], structural: dict[str, Any]
) -> dict[str, list[str]]:
    island = _object(structural.get("island"))
    return {
        "reachability_states": _strings(
            source.get("reachability_states") or island.get("state"), 10
        ),
        "observations": _strings(
            source.get("runtime_observations") or island.get("runtime_observation"),
            10,
        ),
    }


def _has_validation_gap(value: dict[str, Any]) -> bool:
    return bool(
        value.get("line_covered") is False
        or value.get("gap_reasons")
        or value.get("coverage_alignment")
        in {
            "coverage-gap",
            "coverage-not-available",
            "test-evidence-not-available",
            "tests-failing",
            "tests-incomplete",
            "tests-not-observed",
            "not-selected",
        }
    )
