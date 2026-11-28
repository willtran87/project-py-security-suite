"""Owner work-queue aggregation for risk-path remediation."""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from .risk_path_values import _object, _strings, _nonnegative_integer
from .risk_path_common import (
    _MAX_EXPOSURE_ADVISORY_INTERSECTIONS,
    _digest,
    _objects,
    _priority_rank,
)
from .risk_path_validation import _entry_runtime_counts


__all__ = [
    "_owner_work_queues",
]


def _owner_work_queues(
    routes: list[dict[str, Any]],
    hotspots: list[dict[str, Any]],
    campaigns: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    campaign_by_id = {str(campaign["campaign_id"]): campaign for campaign in campaigns}
    hotspot_by_route: dict[str, set[str]] = defaultdict(set)
    for hotspot in hotspots:
        for route_id in hotspot["route_ids"]:
            hotspot_by_route[route_id].add(hotspot["hotspot_id"])
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for route in routes:
        ownership = _object(route.get("ownership_context"))
        owners = _strings(ownership.get("coordination_owners"), 100)
        if ownership.get("unowned_files"):
            owners.append("Unassigned")
        owners = sorted(set(owners or route["owners"] or ["Unassigned"]))
        for owner in owners:
            grouped[str(owner)].append(route)
    result: list[dict[str, Any]] = []
    for owner, owned_routes in grouped.items():
        route_ids = sorted({str(route["route_id"]) for route in owned_routes})
        priorities = {
            priority: sum(route["priority"] == priority for route in owned_routes)
            for priority in ("P0", "P1", "P2", "P3", "P4")
        }
        assessments = {
            status: sum(
                route["validation"]["assessment_status"] == status
                for route in owned_routes
            )
            for status in ("aligned", "gap", "partial", "not-assessed")
        }
        queue_id = "queue-" + _digest({"owner": owner, "routes": route_ids})[:16]
        campaign_ids = sorted(
            {
                str(route_campaign_id)
                for route in owned_routes
                for route_campaign_id in route["validation_campaign_ids"]
            }
        )
        owned_campaigns = [
            campaign_by_id[campaign_id]
            for campaign_id in campaign_ids
            if campaign_id in campaign_by_id
        ]
        intersection_ids = sorted(
            {
                str(intersection_id)
                for route in owned_routes
                for intersection_id in route.get(
                    "exposure_advisory_intersection_ids", []
                )
            }
        )[:_MAX_EXPOSURE_ADVISORY_INTERSECTIONS]
        multi_entry_routes = sum(
            int(route["entry_point_exposure_count"]) > 1 for route in owned_routes
        )
        entry_runtime_counts = _entry_runtime_counts(
            exposure
            for route in owned_routes
            for exposure in route["entry_point_exposures"]
        )
        unobserved_entry_ids = sorted(
            {
                str(exposure["entry_point"]["id"])
                for route in owned_routes
                for exposure in route["entry_point_exposures"]
                if exposure["runtime_context"]["assessment"] == "not-observed"
            }
        )
        unavailable_entry_ids = sorted(
            {
                str(exposure["entry_point"]["id"])
                for route in owned_routes
                for exposure in route["entry_point_exposures"]
                if exposure["runtime_context"]["assessment"] == "not-available"
            }
        )
        assurance_counts = {
            status: sum(
                route["evidence_assurance"]["review_status"] == status
                for route in owned_routes
            )
            for status in (
                "assured",
                "perspective-gap",
                "trust-gap",
                "execution-gap",
                "not-assessed",
                "derived-analysis",
            )
        }
        trust_gap_routes = assurance_counts["trust-gap"]
        execution_gap_routes = assurance_counts["execution-gap"]
        perspective_gap_routes = assurance_counts["perspective-gap"]
        unassessed_assurance_routes = (
            assurance_counts["not-assessed"] + assurance_counts["derived-analysis"]
        )
        changed_lifecycle_routes = sum(
            _object(route.get("change_lifecycle_attribution")).get("classification")
            in {"baseline-new-on-changed-line", "regression-on-changed-line"}
            for route in owned_routes
        )
        changed_lifecycle_gap_routes = sum(
            _object(route.get("change_lifecycle_attribution")).get("review_signal")
            == "baseline-new-or-regressed-change-gap"
            for route in owned_routes
        )
        existing_changed_routes = sum(
            _object(route.get("change_lifecycle_attribution")).get("classification")
            == "existing-on-changed-line"
            for route in owned_routes
        )
        lifecycle_unassessed_routes = sum(
            route["target"]["kind"] == "finding"
            and _object(route.get("change_lifecycle_attribution")).get("baseline_state")
            != "comparable"
            for route in owned_routes
        )
        ownership_summary = _owner_queue_ownership_summary(owner, owned_routes)
        result.append(
            {
                "queue_id": queue_id,
                "owner": owner,
                "priority": min(
                    (str(route["priority"]) for route in owned_routes),
                    key=_priority_rank,
                ),
                "routes": len(route_ids),
                "targets": len({str(route["target"]["id"]) for route in owned_routes}),
                "route_ids": route_ids,
                "target_ids": sorted(
                    {str(route["target"]["id"]) for route in owned_routes}
                ),
                "convergence_hotspot_ids": sorted(
                    {
                        hotspot_id
                        for route_id in route_ids
                        for hotspot_id in hotspot_by_route.get(route_id, set())
                    }
                ),
                "validation_campaign_ids": campaign_ids,
                "validation_test_hotspot_ids": sorted(
                    {
                        str(hotspot_id)
                        for campaign in owned_campaigns
                        for hotspot_id in campaign["shared_test_hotspot_ids"]
                    }
                ),
                "exposure_advisory_intersection_ids": intersection_ids,
                "exposure_advisory_intersections": len(intersection_ids),
                "multi_entry_routes": multi_entry_routes,
                "retained_entry_point_ids": sorted(
                    {
                        str(exposure["entry_point"]["id"])
                        for route in owned_routes
                        for exposure in route["entry_point_exposures"]
                    }
                ),
                "entry_point_exposures_omitted": sum(
                    int(route["entry_point_exposures_omitted"])
                    for route in owned_routes
                ),
                "entry_point_runtime_statuses": entry_runtime_counts,
                "unobserved_entry_point_ids": unobserved_entry_ids,
                "entry_points_without_runtime_evidence": unavailable_entry_ids,
                "evidence_assurance_statuses": assurance_counts,
                "tool_trust_gap_routes": trust_gap_routes,
                "tool_execution_gap_routes": execution_gap_routes,
                "single_perspective_routes": perspective_gap_routes,
                "unassessed_tool_evidence_routes": unassessed_assurance_routes,
                "baseline_new_or_regressed_changed_routes": changed_lifecycle_routes,
                "baseline_new_or_regressed_changed_routes_with_validation_gaps": changed_lifecycle_gap_routes,
                "existing_finding_routes_at_changed_lines": existing_changed_routes,
                "routes_without_comparable_finding_lifecycle": lifecycle_unassessed_routes,
                **ownership_summary,
                "shared_validation_test_files": len(
                    {
                        str(hotspot_id)
                        for campaign in owned_campaigns
                        for hotspot_id in campaign["shared_test_hotspot_ids"]
                    }
                ),
                "campaigns_by_review_tier": {
                    tier: sum(
                        campaign["review_tier"] == tier for campaign in owned_campaigns
                    )
                    for tier in ("critical", "high", "medium", "low")
                },
                "campaigns_revision_mismatched": sum(
                    campaign["source_snapshot"]["evidence_revision_binding"]
                    == "mismatch"
                    for campaign in owned_campaigns
                ),
                "campaigns_revision_unverified": sum(
                    campaign["source_snapshot"]["evidence_revision_binding"]
                    == "unverified"
                    for campaign in owned_campaigns
                ),
                "campaigns_revision_unbound": sum(
                    campaign["source_snapshot"]["evidence_revision_binding"]
                    == "not-established"
                    for campaign in owned_campaigns
                ),
                "campaigns_blocked_by_route_assurance": sum(
                    campaign["route_evidence_assurance"][
                        "tool_assurance_prerequisite_met"
                    ]
                    is not True
                    for campaign in owned_campaigns
                ),
                "campaigns_with_route_trust_gaps": sum(
                    int(
                        campaign["route_evidence_assurance"]["route_statuses"][
                            "trust-gap"
                        ]
                    )
                    > 0
                    for campaign in owned_campaigns
                ),
                "campaigns_with_route_execution_gaps": sum(
                    int(
                        campaign["route_evidence_assurance"]["route_statuses"][
                            "execution-gap"
                        ]
                    )
                    > 0
                    for campaign in owned_campaigns
                ),
                "campaigns_with_qualified_shared_test_evidence": sum(
                    campaign["shared_test_evidence_quality"]["assessment"]
                    == "qualified"
                    for campaign in owned_campaigns
                ),
                "campaigns_with_weak_shared_test_evidence": sum(
                    campaign["shared_test_evidence_quality"]["assessment"]
                    in {"weak", "not-established"}
                    for campaign in owned_campaigns
                ),
                "shared_test_file_finding_ids": sorted(
                    {
                        str(finding_id)
                        for campaign in owned_campaigns
                        for finding_id in campaign["shared_test_evidence_quality"][
                            "test_file_finding_ids"
                        ]
                    }
                ),
                "cross_owner_shared_test_files": sorted(
                    {
                        str(path)
                        for campaign in owned_campaigns
                        for path in campaign["shared_test_evidence_quality"][
                            "cross_owner_test_files"
                        ]
                    }
                ),
                "unowned_shared_test_files": sorted(
                    {
                        str(path)
                        for campaign in owned_campaigns
                        for path in campaign["shared_test_evidence_quality"][
                            "unowned_test_files"
                        ]
                    }
                ),
                "campaigns_with_uncovered_changed_lines": sum(
                    bool(campaign["control_point_context"]["uncovered_changed_lines"])
                    for campaign in owned_campaigns
                ),
                "campaigns_with_runtime_observation_gaps": sum(
                    any(
                        factor["id"] == "runtime-observation-gap"
                        for factor in campaign["review_factors"]
                    )
                    for campaign in owned_campaigns
                ),
                "highest_campaign_review_score": max(
                    (int(campaign["review_score"]) for campaign in owned_campaigns),
                    default=0,
                ),
                "routes_by_priority": priorities,
                "validation_statuses": assessments,
                "recommended_action": _owner_queue_action(
                    owner,
                    assessments,
                    owned_campaigns,
                    len(intersection_ids),
                    multi_entry_routes,
                    len(unobserved_entry_ids),
                    len(unavailable_entry_ids),
                    trust_gap_routes,
                    execution_gap_routes,
                    perspective_gap_routes,
                    unassessed_assurance_routes,
                    changed_lifecycle_routes,
                    changed_lifecycle_gap_routes,
                    existing_changed_routes,
                    lifecycle_unassessed_routes,
                    ownership_summary,
                ),
            }
        )
    result.sort(
        key=lambda item: (
            _priority_rank(str(item["priority"])),
            -int(item["routes"]),
            str(item["owner"]),
        )
    )
    return result


def _owner_queue_action(
    owner: str,
    assessments: dict[str, int],
    campaigns: list[dict[str, Any]],
    exposure_advisory_intersections: int,
    multi_entry_routes: int,
    unobserved_entry_points: int,
    unavailable_entry_points: int,
    trust_gap_routes: int,
    execution_gap_routes: int,
    perspective_gap_routes: int,
    unassessed_assurance_routes: int,
    changed_lifecycle_routes: int,
    changed_lifecycle_gap_routes: int,
    existing_changed_routes: int,
    lifecycle_unassessed_routes: int,
    ownership_summary: dict[str, Any],
) -> str:
    mismatched = sum(
        campaign["source_snapshot"]["evidence_revision_binding"] == "mismatch"
        for campaign in campaigns
    )
    unverified = sum(
        campaign["source_snapshot"]["evidence_revision_binding"] == "unverified"
        for campaign in campaigns
    )
    unbound = sum(
        campaign["source_snapshot"]["evidence_revision_binding"] == "not-established"
        for campaign in campaigns
    )
    changed_gaps = sum(
        bool(campaign["control_point_context"]["uncovered_changed_lines"])
        for campaign in campaigns
    )
    runtime_gaps = sum(
        any(
            factor["id"] == "runtime-observation-gap"
            for factor in campaign["review_factors"]
        )
        for campaign in campaigns
    )
    shared_suffix = _owner_queue_context_suffix(
        campaigns,
        exposure_advisory_intersections,
        multi_entry_routes,
        unobserved_entry_points,
        unavailable_entry_points,
        trust_gap_routes,
        execution_gap_routes,
        perspective_gap_routes,
        unassessed_assurance_routes,
        changed_lifecycle_routes,
        changed_lifecycle_gap_routes,
        existing_changed_routes,
        lifecycle_unassessed_routes,
        ownership_summary,
    )
    if mismatched:
        return (
            f"{owner}: discard and regenerate evidence for {mismatched} revision-"
            "mismatched campaign(s) before route disposition." + shared_suffix
        )
    if unverified:
        return (
            f"{owner}: discard and regenerate evidence for {unverified} campaign(s) "
            "whose source digest lacks a verified payload-binding receipt before "
            "route disposition." + shared_suffix
        )
    if assessments["gap"]:
        action = (
            f"{owner}: close {assessments['gap']} explicit validation gap(s), then "
            "rerun every route in this queue."
        )
        if unbound:
            action += (
                f" Bind regenerated evidence for {unbound} campaign(s) to the "
                "sealed source digest."
            )
        if changed_gaps:
            action += f" Cover changed lines in {changed_gaps} campaign(s)."
        if runtime_gaps:
            action += f" Retain runtime evidence for {runtime_gaps} campaign(s)."
        return action + shared_suffix
    incomplete = assessments["partial"] + assessments["not-assessed"]
    if unbound:
        return (
            f"{owner}: bind regenerated test/coverage evidence to the sealed source "
            f"digest for {unbound} campaign(s), then rerun the owned routes."
            + shared_suffix
        )
    if incomplete:
        return (
            f"{owner}: produce complete change, coverage, and focused-test evidence "
            f"for {incomplete} route(s) before disposition." + shared_suffix
        )
    if changed_gaps or runtime_gaps:
        actions = []
        if changed_gaps:
            actions.append(f"cover changed lines in {changed_gaps} campaign(s)")
        if runtime_gaps:
            actions.append(f"retain runtime evidence for {runtime_gaps} campaign(s)")
        return f"{owner}: " + " and ".join(actions) + "." + shared_suffix
    return (
        f"{owner}: coordinate the shared remediation and regression-test scope."
        + shared_suffix
    )


def _owner_queue_context_suffix(
    campaigns: list[dict[str, Any]],
    exposure_advisory_intersections: int,
    multi_entry_routes: int,
    unobserved_entry_points: int,
    unavailable_entry_points: int,
    trust_gap_routes: int,
    execution_gap_routes: int,
    perspective_gap_routes: int,
    unassessed_assurance_routes: int,
    changed_lifecycle_routes: int,
    changed_lifecycle_gap_routes: int,
    existing_changed_routes: int,
    lifecycle_unassessed_routes: int,
    ownership_summary: dict[str, Any],
) -> str:
    shared_test_hotspots = len(
        {
            str(hotspot_id)
            for campaign in campaigns
            for hotspot_id in campaign["shared_test_hotspot_ids"]
        }
    )
    weak_shared_test_campaigns = sum(
        campaign["shared_test_evidence_quality"]["assessment"]
        in {"weak", "not-established"}
        for campaign in campaigns
    )
    qualified_shared_test_campaigns = sum(
        campaign["shared_test_evidence_quality"]["assessment"] == "qualified"
        for campaign in campaigns
    )
    shared_test_findings = len(
        {
            str(finding_id)
            for campaign in campaigns
            for finding_id in campaign["shared_test_evidence_quality"][
                "test_file_finding_ids"
            ]
        }
    )
    parts = [
        (
            shared_test_hotspots,
            f"Coordinate {shared_test_hotspots} shared validation-test hotspot(s).",
        ),
        (
            weak_shared_test_campaigns,
            f"Restore strong shared-test evidence for {weak_shared_test_campaigns} campaign(s).",
        ),
        (
            qualified_shared_test_campaigns,
            f"Review qualified shared-test evidence for {qualified_shared_test_campaigns} campaign(s).",
        ),
        (
            shared_test_findings,
            f"Resolve or govern {shared_test_findings} finding(s) in shared test files.",
        ),
        (
            exposure_advisory_intersections,
            "Coordinate boundary controls and dependency remediation for "
            f"{exposure_advisory_intersections} exact-path exposure/advisory "
            "intersection(s).",
        ),
        (
            multi_entry_routes,
            f"Coordinate interface-specific validation for {multi_entry_routes} "
            "route(s) reached from multiple declared entry points.",
        ),
        (
            unobserved_entry_points,
            f"Retain representative runtime evidence for {unobserved_entry_points} "
            "unobserved declared interface(s).",
        ),
        (
            unavailable_entry_points,
            f"Model exact reachability nodes for {unavailable_entry_points} "
            "declared interface(s) without runtime evidence.",
        ),
        (
            execution_gap_routes,
            f"Complete contributing scanners for {execution_gap_routes} route(s) "
            "with execution-evidence gaps.",
        ),
        (
            trust_gap_routes,
            "Obtain integrity verification and organization approval for "
            f"contributing scanners on {trust_gap_routes} route(s).",
        ),
        (
            perspective_gap_routes,
            "Add an independent applicable validation perspective for "
            f"{perspective_gap_routes} single-perspective route(s), or record a "
            "governed sufficiency rationale.",
        ),
        (
            unassessed_assurance_routes,
            "Review source evidence and establish tool assurance for "
            f"{unassessed_assurance_routes} unassessed or suite-derived route(s).",
        ),
        (
            existing_changed_routes,
            f"Check {existing_changed_routes} modified pre-existing finding "
            "route(s) for risk amplification.",
        ),
        (
            lifecycle_unassessed_routes,
            "Establish comparable lifecycle evidence for "
            f"{lifecycle_unassessed_routes} finding route(s) before making "
            "change-origin claims.",
        ),
    ]
    lifecycle_part = (
        "Prioritize "
        f"{changed_lifecycle_gap_routes} baseline-new or regressed changed-line "
        "route(s) with validation gaps before release."
        if changed_lifecycle_gap_routes
        else "Review "
        f"{changed_lifecycle_routes} baseline-new or regressed changed-line route(s) "
        "against the exact change."
    )
    if changed_lifecycle_routes:
        parts.append((changed_lifecycle_routes, lifecycle_part))
    ownership_boundaries = (
        _nonnegative_integer(ownership_summary.get("ownership_boundaries")) or 0
    )
    unowned_files = _strings(ownership_summary.get("unowned_route_files"), 225)
    ownership_gaps = (
        _nonnegative_integer(ownership_summary.get("routes_without_ownership_evidence"))
        or 0
    )
    parts.extend(
        [
            (
                ownership_boundaries,
                f"Coordinate {ownership_boundaries} exact ownership handoff(s) "
                "across the owned routes.",
            ),
            (
                len(unowned_files),
                f"Assign CODEOWNERS responsibility for {len(unowned_files)} "
                "unowned route file(s).",
            ),
            (
                ownership_gaps,
                f"Establish route ownership evidence for {ownership_gaps} route(s).",
            ),
        ]
    )
    return "".join(f" {text}" for count, text in parts if count)


def _owner_queue_ownership_summary(
    owner: str, routes: list[dict[str, Any]]
) -> dict[str, Any]:
    contexts = [_object(route.get("ownership_context")) for route in routes]
    all_owners = sorted(
        {
            candidate
            for context in contexts
            for candidate in _strings(context.get("coordination_owners"), 100)
        }
    )
    collaborators = [candidate for candidate in all_owners if candidate != owner]
    boundary_ids = sorted(
        {
            str(boundary.get("boundary_id"))
            for context in contexts
            for boundary in _objects(context.get("boundaries"), 200)
            if isinstance(boundary, dict) and boundary.get("boundary_id")
        }
    )
    unowned = sorted(
        {
            path
            for context in contexts
            for path in _strings(context.get("unowned_files"), 225)
        }
    )
    return {
        "collaborating_owners": collaborators,
        "ownership_boundary_ids": boundary_ids,
        "ownership_boundaries": len(boundary_ids),
        "routes_crossing_ownership_boundaries": sum(
            (_nonnegative_integer(context.get("boundary_count")) or 0) > 0
            for context in contexts
        ),
        "routes_with_unowned_segments": sum(
            bool(context.get("unowned_files")) for context in contexts
        ),
        "routes_without_ownership_evidence": sum(
            context.get("evidence_available") is not True for context in contexts
        ),
        "unowned_route_files": unowned,
    }
