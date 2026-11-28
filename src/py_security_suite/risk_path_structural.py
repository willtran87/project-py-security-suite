"""Unrouted structural-island intersections for risk-path targets."""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from .risk_path_values import _object, _strings
from .risk_path_common import _digest, _objects, _path, _priority_rank


__all__ = [
    "_attach_unrouted_structural_intersections",
    "_unrouted_structural_intersections",
]


_MAX_CONTEXT_UNROUTED_STRUCTURAL_INTERSECTIONS = 5


def _unrouted_structural_intersections(
    unrouted: list[dict[str, Any]], structural: Any
) -> list[dict[str, Any]]:
    """Join Python route gaps to exact retained structural-island membership."""
    if not isinstance(structural, dict):
        return []
    islands = _objects(structural.get("island_assessments"), 500)
    boundaries = {
        str(item.get("island_id")): item
        for item in _objects(structural.get("island_boundary_assessments"), 500)
        if item.get("island_id")
    }
    result: list[dict[str, Any]] = []
    for record in unrouted:
        applicability = _object(record.get("route_applicability"))
        if applicability.get("assessment") != "route-applicable":
            continue
        target = _object(record.get("target"))
        for island in islands:
            evidence_basis = _target_island_membership_basis(target, island)
            if evidence_basis is None:
                continue
            boundary = boundaries.get(str(island.get("island_id")), {})
            result.append(
                _unrouted_structural_intersection(
                    record,
                    target,
                    island,
                    boundary,
                    evidence_basis=evidence_basis,
                )
            )
    return sorted(
        result,
        key=lambda item: (
            _priority_rank(str(item["priority"])),
            {
                "static-runtime-model-conflict": 0,
                "candidate-missing-entry-point": 1,
                "dormant-risk-review": 2,
                "attack-surface-retirement-candidate": 3,
            }.get(str(item["risk_signal"]), 4),
            str(item["intersection_id"]),
        ),
    )


def _target_island_membership_basis(
    target: dict[str, Any], island: dict[str, Any]
) -> str | None:
    target_path = _path(target.get("path"))
    island_paths = {_path(value) for value in _strings(island.get("paths"), 500)}
    if not target_path or target_path not in island_paths:
        return None
    primary_path = _path(island.get("primary_path"))
    target_line = target.get("line")
    start = island.get("primary_start_line")
    end = island.get("primary_end_line")
    if (
        target_path == primary_path
        and isinstance(target_line, int)
        and isinstance(start, int)
        and isinstance(end, int)
    ):
        if not start <= target_line <= end:
            return None
        return "exact-line-island-membership"
    return "exact-path-island-membership"


def _unrouted_structural_intersection(
    record: dict[str, Any],
    target: dict[str, Any],
    island: dict[str, Any],
    boundary: dict[str, Any],
    *,
    evidence_basis: str,
) -> dict[str, Any]:
    target_id = str(target.get("id") or "unknown-target")
    island_id = str(island.get("island_id") or "unknown-island")
    observation = str(island.get("runtime_observation") or "unknown")
    boundary_classification = str(
        boundary.get("boundary_classification") or "not-established"
    )
    island_classification = str(island.get("classification") or "orphaned-code-review")
    dead_code_ids = _strings(island.get("dead_code_finding_ids"), 25)
    risk_signal, decision, action = _unrouted_structural_decision(
        observation=observation,
        boundary_classification=boundary_classification,
        island_classification=island_classification,
        island_state=str(island.get("state") or "unknown"),
        dead_code_corroborated=bool(dead_code_ids),
    )
    target_owners = _strings(record.get("owners"), 100)
    island_owners = _strings(island.get("owners"), 100)
    validation = _object(record.get("validation"))
    evidence_artifacts = {
        "structural-synthesis.json",
        "reachability.json",
        *({"graphify.json"} if boundary else set()),
        *(
            {"coverage-summary.json"}
            if island.get("minimum_file_coverage_percent") is not None
            else set()
        ),
        *({"junit-summary.json"} if boundary.get("direct_test_files") else set()),
    }
    return {
        "intersection_id": "unrouted-structural-"
        + _digest(
            {
                "target_id": target_id,
                "island_id": island_id,
                "evidence_basis": evidence_basis,
            }
        )[:16],
        "priority": str(record.get("priority") or "P4"),
        "evidence_basis": evidence_basis,
        "target_id": target_id,
        "target_kind": str(target.get("kind") or "unknown"),
        "target_finding_id": target.get("finding_id"),
        "path": _path(target.get("path")) or ".",
        "line": target.get("line") if isinstance(target.get("line"), int) else None,
        "island_id": island_id,
        "island_state": str(island.get("state") or "unknown"),
        "island_classification": island_classification,
        "island_confidence": str(island.get("confidence") or "unknown"),
        "island_kind": str(island.get("kind") or "unknown"),
        "island_lines_of_code": max(0, int(island.get("lines_of_code") or 0)),
        "runtime_observation": observation,
        "minimum_file_coverage_percent": island.get("minimum_file_coverage_percent"),
        "boundary_classification": boundary_classification,
        "candidate_entry_paths": _strings(boundary.get("candidate_entry_paths"), 25),
        "direct_test_files": _strings(boundary.get("direct_test_files"), 25),
        "external_inbound_files": _strings(island.get("external_inbound_files"), 20),
        "external_outbound_files": _strings(island.get("external_outbound_files"), 20),
        "dead_code_finding_ids": dead_code_ids,
        "security_finding_ids": _strings(island.get("security_finding_ids"), 25),
        "architecture_finding_ids": _strings(island.get("tach_finding_ids"), 25),
        "target_validation": validation,
        "target_evidence_assurance": record["evidence_assurance"],
        "target_owners": target_owners,
        "island_owners": island_owners,
        "coordination_owners": sorted({*target_owners, *island_owners})[:100],
        "risk_signal": risk_signal,
        "decision": decision,
        "evidence": _strings(island.get("evidence"), 25),
        "counter_evidence": _strings(island.get("counter_evidence"), 25),
        "recommended_action": action,
        "evidence_artifacts": sorted(evidence_artifacts),
        "interpretation": (
            "Exact retained island membership explains a static route gap but does not "
            "prove dead code, safety, exploitability, or production inaccessibility. "
            "Runtime observations and boundary references are counter-evidence that "
            "must be resolved before removal."
        ),
    }


def _unrouted_structural_decision(
    *,
    observation: str,
    boundary_classification: str,
    island_classification: str,
    island_state: str,
    dead_code_corroborated: bool,
) -> tuple[str, str, str]:
    if observation == "observed" or boundary_classification == "runtime-model-gap":
        return (
            "static-runtime-model-conflict",
            "model-runtime-path",
            "Use the retained runtime observation to model the missing callback, registry, plugin, framework, or generated edge; keep the target actionable until the route model and replacement evidence agree.",
        )
    if boundary_classification == "candidate-missing-entry-point":
        return (
            "candidate-missing-entry-point",
            "model-missing-entry-point",
            "Inspect the cited production inbound paths and add the missing entry point or dynamic edge; if the integration is obsolete, retire it only after owner review and focused regression evidence.",
        )
    if boundary_classification == "test-only-or-fixture":
        return (
            "test-only-scope-disagreement",
            "separate-test-scope-or-model-entry",
            "Confirm the code is intentionally test-only, move it under an explicit test scope when appropriate, or model the missing production root before changing the target's disposition.",
        )
    if island_classification == "latent-attack-surface":
        return (
            "dormant-risk-review",
            "remediate-or-retire-dormant-risk",
            "Treat the finding and dormant capability as one owner decision: remediate it if retained, or remove the capability with focused tests and a clean reachability, structural, and security rescan.",
        )
    if (
        island_state == "disconnected"
        and dead_code_corroborated
        and boundary_classification == "closed-boundary"
    ):
        return (
            "attack-surface-retirement-candidate",
            "evaluate-attack-surface-retirement",
            "Validate dynamic loading and ownership, then consider removing the closed disconnected capability; require focused tests and a clean reachability, Vulture, Graphify, and security rescan before closure.",
        )
    return (
        "unrouted-structural-review",
        "resolve-structural-route-disagreement",
        "Resolve the retained island, boundary, runtime, ownership, and validation evidence before adding an entry point, suppressing the route gap, or removing code.",
    )


def _compact_unrouted_structural_intersection(item: dict[str, Any]) -> dict[str, Any]:
    return {
        key: item[key]
        for key in (
            "intersection_id",
            "priority",
            "evidence_basis",
            "target_kind",
            "path",
            "line",
            "island_id",
            "island_state",
            "island_classification",
            "island_confidence",
            "runtime_observation",
            "minimum_file_coverage_percent",
            "boundary_classification",
            "candidate_entry_paths",
            "direct_test_files",
            "dead_code_finding_ids",
            "security_finding_ids",
            "coordination_owners",
            "risk_signal",
            "decision",
            "recommended_action",
            "evidence_artifacts",
            "interpretation",
        )
    }


def _attach_unrouted_structural_intersections(
    unrouted: list[dict[str, Any]], intersections: list[dict[str, Any]]
) -> None:
    by_target: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item in intersections:
        by_target[str(item["target_id"])].append(item)
    for record in unrouted:
        target_id = str(_object(record.get("target")).get("id") or "")
        matches = by_target.get(target_id, [])
        retained = matches[:_MAX_CONTEXT_UNROUTED_STRUCTURAL_INTERSECTIONS]
        record["unrouted_structural_intersection_ids"] = [
            str(item["intersection_id"]) for item in retained
        ]
        record["unrouted_structural_intersections"] = [
            _compact_unrouted_structural_intersection(item) for item in retained
        ]
        record["unrouted_structural_intersections_omitted"] = max(
            0, len(matches) - len(retained)
        )
