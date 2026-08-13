from __future__ import annotations

import hashlib
import json
from collections import defaultdict, deque
from itertools import pairwise
from typing import Any

from .models import Citation, Finding, FindingStatus
from .ownership import owners_for_path, ownership_rules_from_artifact
from .prioritization import finding_priority
from .validation_alignment import (
    TEST_EVIDENCE_ARTIFACTS,
    build_test_execution_index,
    focused_test_execution,
    test_coverage_alignment,
)


_GRAPHIFY_REFERENCE = "https://graphify.com/docs/cli"
_REACHABILITY_REFERENCE = "docs/reachability.md"
_RISK_PATH_REFERENCE = "docs/risk-paths.md"
_ROUTE_RELATIONS = frozenset(
    {"calls", "imports", "imports_from", "depends_on", "references", "uses"}
)
_RELATION_ORDER = {
    "calls": 0,
    "uses": 1,
    "references": 2,
    "imports_from": 3,
    "imports": 4,
    "depends_on": 5,
}
_MAX_ENTRY_POINTS = 100
_MAX_GRAPH_FILES = 100_000
_MAX_ROUTE_HOPS = 8
_MAX_TARGETS = 10_000
_MAX_ROUTES = 250
_MAX_UNROUTED = 250
_MAX_CONVERGENCE_HOTSPOTS = 50
_MAX_VALIDATION_TEST_HOTSPOTS = 100
_MAX_OWNER_QUEUES = 100
_MAX_CAMPAIGN_TESTS = 50
_MAX_CAMPAIGN_MISSING_LINES = 100
_MAX_TEST_GRAPH_NEIGHBORS = 500
_MAX_ADVISORY_IMPORT_PATHS = 50
_MAX_FINDING_ADVISORY_ROUTES = 25
_MAX_EXPOSURE_ADVISORY_INTERSECTIONS = 100
_MAX_ENTRY_POINT_EXPOSURES = 25
_TOOL_RUN_STATUSES = frozenset(
    {"completed", "unavailable", "failed", "timed_out", "parse_error", "skipped"}
)
_TOOL_ASSURANCE_STATUSES = frozenset(
    {
        "approved",
        "approval-gap",
        "integrity-gap",
        "not-established",
        "execution-gap",
        "not-applicable",
    }
)


def build_risk_paths(
    findings: list[Finding], artifacts: dict[str, Any]
) -> dict[str, Any]:
    """Build conservative entry-point-to-review-target routes.

    Routes are static review context. They neither prove attacker control nor
    establish runtime exploitability, data flow, or vulnerability reachability.
    """
    graph = artifacts.get("graphify.json")
    reachability = artifacts.get("reachability.json")
    exposure = artifacts.get("data-exposure.json")
    fusion = artifacts.get("evidence-fusion.json")
    structural = artifacts.get("structural-synthesis.json")
    adjacency, graph_available, graph_truncated = _file_graph(graph)
    entry_points = _entry_points(reachability)
    entry_point_runtime = _entry_point_runtime_index(reachability)
    path_context = _campaign_control_context_index(structural, reachability)
    tool_posture = _tool_posture_index(artifacts.get("effectiveness.json"))
    baseline_context = _baseline_lifecycle_context(artifacts.get("finding-delta.json"))
    ownership_rules = ownership_rules_from_artifact(artifacts.get("finding-delta.json"))
    dependency_targets, dependency_targets_omitted = _dependency_advisory_targets(
        fusion, path_context
    )
    candidate_targets = [
        *_finding_targets(findings),
        *_sink_surface_targets(exposure),
        *dependency_targets,
    ]
    targets = sorted(candidate_targets, key=_candidate_order)[:_MAX_TARGETS]
    for target in targets:
        target["validation"] = _assess_validation(target["validation"], artifacts)
        target["evidence_assurance"] = _target_evidence_assurance(target, tool_posture)
        attribution = _change_lifecycle_attribution(target, baseline_context)
        if attribution is not None:
            target["change_lifecycle_attribution"] = attribution
    routed, unrouted = _route_targets(
        entry_points,
        targets,
        adjacency,
        graph_available=graph_available,
    )
    routed.sort(key=_route_order)
    unrouted.sort(key=_target_order)
    retained_routes = routed[:_MAX_ROUTES]
    _attach_entry_point_exposures(
        retained_routes, entry_points, adjacency, entry_point_runtime
    )
    for route in retained_routes:
        _attach_route_ownership(route, ownership_rules)
        attribution = route.get("change_lifecycle_attribution")
        if isinstance(attribution, dict):
            attribution["entry_point_runtime_statuses"] = _entry_runtime_counts(
                route["entry_point_exposures"]
            )
            attribution["review_factors"] = _change_lifecycle_review_factors(
                attribution
            )
    all_convergence_hotspots = _convergence_hotspots(retained_routes)
    convergence_hotspots = all_convergence_hotspots[:_MAX_CONVERGENCE_HOTSPOTS]
    validation_campaigns = _validation_campaigns(
        convergence_hotspots,
        adjacency,
        artifacts,
    )
    all_validation_test_hotspots = _validation_test_hotspots(validation_campaigns)
    validation_test_hotspots = all_validation_test_hotspots[
        :_MAX_VALIDATION_TEST_HOTSPOTS
    ]
    test_hotspot_ids_by_campaign: dict[str, list[str]] = defaultdict(list)
    for hotspot in validation_test_hotspots:
        for campaign_id in hotspot["campaign_ids"]:
            test_hotspot_ids_by_campaign[str(campaign_id)].append(
                str(hotspot["test_hotspot_id"])
            )
    for campaign in validation_campaigns:
        campaign["shared_test_hotspot_ids"] = sorted(
            test_hotspot_ids_by_campaign.get(str(campaign["campaign_id"]), [])
        )
    campaign_by_hotspot = {
        str(campaign["hotspot_id"]): campaign for campaign in validation_campaigns
    }
    campaign_by_id = {
        str(campaign["campaign_id"]): campaign for campaign in validation_campaigns
    }
    hotspot_ids_by_route: dict[str, list[str]] = defaultdict(list)
    campaign_ids_by_route: dict[str, list[str]] = defaultdict(list)
    for hotspot in convergence_hotspots:
        hotspot_campaign = campaign_by_hotspot.get(str(hotspot["hotspot_id"]))
        hotspot["validation_campaign_id"] = (
            str(hotspot_campaign["campaign_id"])
            if hotspot_campaign is not None
            else None
        )
        for route_id in hotspot["route_ids"]:
            hotspot_ids_by_route[route_id].append(hotspot["hotspot_id"])
            if hotspot_campaign is not None:
                campaign_ids_by_route[route_id].append(hotspot_campaign["campaign_id"])
    for route in retained_routes:
        route["convergence_hotspot_ids"] = sorted(
            hotspot_ids_by_route.get(route["route_id"], [])
        )
        route["validation_campaign_ids"] = sorted(
            campaign_ids_by_route.get(route["route_id"], [])
        )
        route["validation_test_hotspot_ids"] = sorted(
            {
                hotspot_id
                for campaign_id in route["validation_campaign_ids"]
                if str(campaign_id) in campaign_by_id
                for hotspot_id in campaign_by_id[str(campaign_id)][
                    "shared_test_hotspot_ids"
                ]
            }
        )
    all_exposure_advisory_intersections = _exposure_advisory_intersections(
        retained_routes
    )
    exposure_advisory_intersections = all_exposure_advisory_intersections[
        :_MAX_EXPOSURE_ADVISORY_INTERSECTIONS
    ]
    intersection_ids_by_route: dict[str, list[str]] = defaultdict(list)
    for intersection in exposure_advisory_intersections:
        for route_id in intersection["route_ids"]:
            intersection_ids_by_route[str(route_id)].append(
                str(intersection["intersection_id"])
            )
    for route in retained_routes:
        route["exposure_advisory_intersection_ids"] = sorted(
            intersection_ids_by_route.get(str(route["route_id"]), [])
        )
    all_owner_work_queues = _owner_work_queues(
        retained_routes,
        convergence_hotspots,
        validation_campaigns,
    )
    owner_work_queues = all_owner_work_queues[:_MAX_OWNER_QUEUES]
    retained_route_ids = {
        route["target"]["finding_id"]: route
        for route in retained_routes
        if route["target"].get("finding_id")
    }
    _attach_finding_routes(
        findings,
        retained_route_ids,
        retained_routes,
        unrouted,
        validation_campaigns,
        exposure_advisory_intersections,
    )
    validation_gaps = sum(
        route["validation"]["assessment_status"] == "gap" for route in routed
    )
    route_priorities: dict[str, int] = defaultdict(int)
    for route in routed:
        route_priorities[str(route["priority"])] += 1
    return {
        "schema_version": "1.0",
        "schema_id": "urn:project-py-security-suite:risk-paths:1.0",
        "authoritative": False,
        "purpose": (
            "bounded multi-entry static routes from declared Python entry points to normalized "
            "findings, review-worthy sensitive-data sink surfaces, and exact "
            "dependency-advisory importers, with bounded compound intersections"
        ),
        "summary": {
            "graph_available": graph_available,
            "reachability_available": isinstance(reachability, dict)
            and reachability.get("schema_version") == "1.2",
            "entry_points": len(entry_points),
            "candidate_targets": len(candidate_targets) + dependency_targets_omitted,
            "targets_analyzed": len(targets),
            "finding_targets": sum(
                target["kind"] == "finding" for target in candidate_targets
            ),
            "sink_surface_targets": sum(
                target["kind"] == "sink-surface" for target in candidate_targets
            ),
            "dependency_advisory_import_targets": sum(
                target["kind"] == "dependency-advisory-import"
                for target in candidate_targets
            )
            + dependency_targets_omitted,
            "routed_targets": len(routed),
            "unrouted_targets": len(unrouted),
            "routed_findings": sum(
                route["target"]["kind"] == "finding" for route in routed
            ),
            "routed_sink_surfaces": sum(
                route["target"]["kind"] == "sink-surface" for route in routed
            ),
            "routed_dependency_advisory_imports": sum(
                route["target"]["kind"] == "dependency-advisory-import"
                for route in routed
            ),
            "retained_entry_point_exposures": sum(
                len(route["entry_point_exposures"]) for route in retained_routes
            ),
            "observed_entry_point_exposures": sum(
                exposure["runtime_context"]["assessment"] == "observed"
                for route in retained_routes
                for exposure in route["entry_point_exposures"]
            ),
            "unobserved_entry_point_exposures": sum(
                exposure["runtime_context"]["assessment"] == "not-observed"
                for route in retained_routes
                for exposure in route["entry_point_exposures"]
            ),
            "entry_point_exposures_without_runtime_evidence": sum(
                exposure["runtime_context"]["assessment"] == "not-available"
                for route in retained_routes
                for exposure in route["entry_point_exposures"]
            ),
            "multi_entry_routes_with_unobserved_interfaces": sum(
                int(route["entry_point_exposure_count"]) > 1
                and any(
                    exposure["runtime_context"]["assessment"] == "not-observed"
                    for exposure in route["entry_point_exposures"]
                )
                for route in retained_routes
            ),
            "multi_entry_routes_with_runtime_evidence_gaps": sum(
                int(route["entry_point_exposure_count"]) > 1
                and any(
                    exposure["runtime_context"]["assessment"] == "not-available"
                    for exposure in route["entry_point_exposures"]
                )
                for route in retained_routes
            ),
            "routes_with_multiple_entry_points": sum(
                int(route["entry_point_exposure_count"]) > 1
                for route in retained_routes
            ),
            "security_routes_with_multiple_entry_points": sum(
                int(route["entry_point_exposure_count"]) > 1
                and route["target"]["domain"] in {"security", "supply-chain"}
                for route in retained_routes
            ),
            "maximum_entry_points_per_route": max(
                (int(route["entry_point_exposure_count"]) for route in retained_routes),
                default=0,
            ),
            "routes_with_entry_point_exposure_truncation": sum(
                int(route["entry_point_exposures_omitted"]) > 0
                for route in retained_routes
            ),
            "assured_evidence_routes": sum(
                route["evidence_assurance"]["review_status"] == "assured"
                for route in routed
            ),
            "single_perspective_routes": sum(
                route["evidence_assurance"]["perspective_assessment"] == "single-tool"
                for route in routed
            ),
            "independently_corroborated_routes": sum(
                route["evidence_assurance"]["perspective_assessment"]
                == "independent-corroboration"
                for route in routed
            ),
            "routes_with_tool_trust_gaps": sum(
                route["evidence_assurance"]["review_status"] == "trust-gap"
                for route in routed
            ),
            "routes_with_tool_execution_gaps": sum(
                route["evidence_assurance"]["review_status"] == "execution-gap"
                for route in routed
            ),
            "routes_without_tool_assurance": sum(
                route["evidence_assurance"]["review_status"]
                in {"not-assessed", "derived-analysis"}
                for route in routed
            ),
            "routes_with_comparable_finding_lifecycle": sum(
                _object(route.get("change_lifecycle_attribution")).get("baseline_state")
                == "comparable"
                for route in routed
            ),
            "routes_without_comparable_finding_lifecycle": sum(
                route["target"]["kind"] == "finding"
                and _object(route.get("change_lifecycle_attribution")).get(
                    "baseline_state"
                )
                != "comparable"
                for route in routed
            ),
            "baseline_new_or_regressed_routes": sum(
                _object(route.get("change_lifecycle_attribution")).get(
                    "lifecycle_status"
                )
                in {"new", "regression"}
                and _object(route.get("change_lifecycle_attribution")).get(
                    "baseline_state"
                )
                == "comparable"
                for route in routed
            ),
            "baseline_new_or_regressed_changed_routes": sum(
                _object(route.get("change_lifecycle_attribution")).get("classification")
                in {"baseline-new-on-changed-line", "regression-on-changed-line"}
                for route in routed
            ),
            "baseline_new_or_regressed_changed_routes_with_validation_gaps": sum(
                _object(route.get("change_lifecycle_attribution")).get("review_signal")
                == "baseline-new-or-regressed-change-gap"
                for route in routed
            ),
            "existing_finding_routes_at_changed_lines": sum(
                _object(route.get("change_lifecycle_attribution")).get("classification")
                == "existing-on-changed-line"
                for route in routed
            ),
            "routes_with_ownership_evidence": sum(
                _object(route.get("ownership_context")).get("evidence_available")
                is True
                for route in retained_routes
            ),
            "routes_crossing_ownership_boundaries": sum(
                (
                    _nonnegative_integer(
                        _object(route.get("ownership_context")).get("boundary_count")
                    )
                    or 0
                )
                > 0
                for route in retained_routes
            ),
            "routes_with_unowned_segments": sum(
                bool(_object(route.get("ownership_context")).get("unowned_files"))
                for route in retained_routes
            ),
            "routes_without_ownership_evidence": sum(
                _object(route.get("ownership_context")).get("evidence_available")
                is not True
                for route in retained_routes
            ),
            "ownership_boundaries": sum(
                _nonnegative_integer(
                    _object(route.get("ownership_context")).get("boundary_count")
                )
                or 0
                for route in retained_routes
            ),
            "distinct_route_owners": len(
                {
                    owner
                    for route in retained_routes
                    for owner in _strings(
                        _object(route.get("ownership_context")).get("distinct_owners"),
                        100,
                    )
                }
            ),
            "unrouted_dependency_advisory_imports": sum(
                target["target"]["kind"] == "dependency-advisory-import"
                for target in unrouted
            ),
            "distinct_routed_dependency_advisories": len(
                {
                    str(route["correlations"]["advisory_cluster_id"])
                    for route in routed
                    if route["target"]["kind"] == "dependency-advisory-import"
                }
            ),
            "known_exploited_dependency_routes": sum(
                route["target"]["kind"] == "dependency-advisory-import"
                and route["correlations"].get("known_exploited") is True
                for route in routed
            ),
            "high_epss_dependency_routes": sum(
                route["target"]["kind"] == "dependency-advisory-import"
                and route["correlations"].get("epss_high") is True
                for route in routed
            ),
            "dependency_routes_with_fixed_versions": sum(
                route["target"]["kind"] == "dependency-advisory-import"
                and route["correlations"].get("fix_available") is True
                for route in routed
            ),
            "dependency_routes_with_validation_gaps": sum(
                route["target"]["kind"] == "dependency-advisory-import"
                and route["validation"]["assessment_status"] == "gap"
                for route in routed
            ),
            "dependency_routes_at_changed_importers": sum(
                route["target"]["kind"] == "dependency-advisory-import"
                and isinstance(route["correlations"].get("change_risk_score"), int)
                for route in routed
            ),
            "dependency_routes_with_uncovered_changed_lines": sum(
                route["target"]["kind"] == "dependency-advisory-import"
                and bool(route["correlations"].get("uncovered_changed_lines"))
                for route in routed
            ),
            "dependency_routes_with_comparable_package_lifecycle": sum(
                route["target"]["kind"] == "dependency-advisory-import"
                and _object(route["correlations"].get("package_lifecycle")).get(
                    "comparison_available"
                )
                is True
                for route in routed
            ),
            "dependency_routes_with_version_drift": sum(
                route["target"]["kind"] == "dependency-advisory-import"
                and _object(route["correlations"].get("package_lifecycle")).get(
                    "assessment"
                )
                == "version-drift"
                for route in routed
            ),
            "dependency_routes_source_only_in_comparable_inventory": sum(
                route["target"]["kind"] == "dependency-advisory-import"
                and _object(route["correlations"].get("package_lifecycle")).get(
                    "assessment"
                )
                == "source-only"
                for route in routed
            ),
            "dependency_routes_artifact_only_in_comparable_inventory": sum(
                route["target"]["kind"] == "dependency-advisory-import"
                and _object(route["correlations"].get("package_lifecycle")).get(
                    "assessment"
                )
                == "artifact-only"
                for route in routed
            ),
            "dependency_routes_with_composition_evidence_gaps": sum(
                route["target"]["kind"] == "dependency-advisory-import"
                and _object(route["correlations"].get("package_lifecycle")).get(
                    "assessment"
                )
                in {
                    "source-inventory-unavailable",
                    "artifact-inventory-unavailable",
                    "composition-inventories-unavailable",
                    "package-not-observed",
                }
                for route in routed
            ),
            "dependency_routes_with_exact_fixed_version_in_artifact": sum(
                route["target"]["kind"] == "dependency-advisory-import"
                and _object(route["correlations"].get("package_lifecycle")).get(
                    "artifact_fixed_version_exact_match"
                )
                is True
                for route in routed
            ),
            "exposure_advisory_intersections": len(all_exposure_advisory_intersections),
            "known_exploited_exposure_advisory_intersections": sum(
                item["known_exploited"] for item in all_exposure_advisory_intersections
            ),
            "unprotected_exposure_advisory_intersections": sum(
                item["protection_status"] == "not-observed"
                for item in all_exposure_advisory_intersections
            ),
            "exposure_advisory_intersections_with_validation_gaps": sum(
                "gap" in item["validation_statuses"].values()
                for item in all_exposure_advisory_intersections
            ),
            "runtime_observed_routes": sum(
                "observed" in route["runtime_context"]["observations"]
                for route in routed
            ),
            "coverage_gap_routes": sum(
                route["validation"]["line_covered"] is False for route in routed
            ),
            "validation_gap_routes": validation_gaps,
            "validation_assessed_routes": sum(
                route["validation"]["assessment_status"]
                in {"aligned", "gap", "partial"}
                for route in routed
            ),
            "validation_unassessed_routes": sum(
                route["validation"]["assessment_status"] == "not-assessed"
                for route in routed
            ),
            "owned_routes": sum(bool(route["owners"]) for route in routed),
            "convergence_hotspots": len(convergence_hotspots),
            "shared_control_points": sum(
                hotspot["kind"] != "target-concentration"
                for hotspot in convergence_hotspots
            ),
            "routes_in_convergence_hotspots": len(
                {
                    route_id
                    for hotspot in convergence_hotspots
                    for route_id in hotspot["route_ids"]
                }
            ),
            "owner_work_queues": len(owner_work_queues),
            "owner_queues_with_exposure_advisory_intersections": sum(
                bool(queue["exposure_advisory_intersection_ids"])
                for queue in owner_work_queues
            ),
            "validation_campaigns": len(validation_campaigns),
            "shared_validation_test_hotspots": len(validation_test_hotspots),
            "campaigns_using_shared_tests": len(
                {
                    campaign_id
                    for hotspot in validation_test_hotspots
                    for campaign_id in hotspot["campaign_ids"]
                }
            ),
            "routes_using_shared_tests": len(
                {
                    route_id
                    for hotspot in validation_test_hotspots
                    for route_id in hotspot["route_ids"]
                }
            ),
            "single_test_dependency_campaigns": len(
                {
                    campaign_id
                    for hotspot in validation_test_hotspots
                    for campaign_id in hotspot["single_test_dependency_campaign_ids"]
                }
            ),
            "campaigns_with_selected_tests": sum(
                bool(campaign["selected_test_files"])
                for campaign in validation_campaigns
            ),
            "campaigns_with_failing_tests": sum(
                campaign["focused_test_validation_status"] == "failed"
                for campaign in validation_campaigns
            ),
            "campaigns_with_coverage_gaps": sum(
                campaign["test_coverage_alignment"] == "coverage-gap"
                for campaign in validation_campaigns
            ),
            "campaigns_with_changed_controls": sum(
                isinstance(campaign["control_point_context"]["change_risk_score"], int)
                for campaign in validation_campaigns
            ),
            "campaigns_with_uncovered_changed_lines": sum(
                bool(campaign["control_point_context"]["uncovered_changed_lines"])
                for campaign in validation_campaigns
            ),
            "campaigns_with_runtime_observation_gaps": sum(
                any(
                    factor["id"] == "runtime-observation-gap"
                    for factor in campaign["review_factors"]
                )
                for campaign in validation_campaigns
            ),
            "campaigns_aligned_current_evidence": sum(
                campaign["test_coverage_alignment"] == "aligned-current-evidence"
                for campaign in validation_campaigns
            ),
            "campaigns_requiring_evidence": sum(
                campaign["test_coverage_alignment"]
                in {
                    "not-selected",
                    "test-evidence-not-available",
                    "tests-not-observed",
                    "tests-incomplete",
                    "coverage-not-available",
                }
                for campaign in validation_campaigns
            ),
            "unique_campaign_test_files": len(
                {
                    str(path)
                    for campaign in validation_campaigns
                    for path in campaign["selected_test_files"]
                }
            ),
            "campaigns_by_review_tier": {
                tier: sum(
                    campaign["review_tier"] == tier for campaign in validation_campaigns
                )
                for tier in ("critical", "high", "medium", "low")
            },
            "campaigns_revision_aligned": sum(
                campaign["source_snapshot"]["evidence_revision_binding"] == "aligned"
                for campaign in validation_campaigns
            ),
            "campaigns_revision_mismatched": sum(
                campaign["source_snapshot"]["evidence_revision_binding"] == "mismatch"
                for campaign in validation_campaigns
            ),
            "campaigns_revision_unverified": sum(
                campaign["source_snapshot"]["evidence_revision_binding"] == "unverified"
                for campaign in validation_campaigns
            ),
            "campaigns_revision_unbound": sum(
                campaign["source_snapshot"]["evidence_revision_binding"]
                == "not-established"
                for campaign in validation_campaigns
            ),
            "campaigns_with_source_bound_control_points": sum(
                campaign["source_snapshot"]["control_point_binding"] is not None
                for campaign in validation_campaigns
            ),
            "selected_test_source_bindings": sum(
                int(campaign["source_snapshot"]["selected_test_files_bound"])
                for campaign in validation_campaigns
            ),
            "routes_by_priority": {
                priority: route_priorities.get(priority, 0)
                for priority in ("P0", "P1", "P2", "P3", "P4")
            },
        },
        "evidence_availability": {
            "graphify_file_graph": graph_available,
            "declared_entry_points": bool(entry_points),
            "runtime_observation": _artifact_available(reachability, "nodes"),
            "change_scope": _artifact_available(
                artifacts.get("diff-coverage.json"), "src_stats"
            ),
            "coverage": _artifact_available(
                artifacts.get("coverage-summary.json"), "files"
            ),
            "test_execution": _test_execution_available(artifacts),
            "structural_synthesis": isinstance(
                artifacts.get("structural-synthesis.json"), dict
            ),
            "tool_effectiveness_and_trust": bool(tool_posture),
            "comparable_finding_lifecycle": baseline_context["state"] == "comparable",
            "route_ownership": bool(ownership_rules),
            "data_exposure": isinstance(exposure, dict),
            "dependency_advisory_imports": isinstance(fusion, dict)
            and isinstance(fusion.get("advisory_clusters"), list),
            "source_inventory": isinstance(
                artifacts.get("source-inventory.json"), dict
            ),
        },
        "routes": retained_routes,
        "convergence_hotspots": convergence_hotspots,
        "validation_campaigns": validation_campaigns,
        "validation_test_hotspots": validation_test_hotspots,
        "exposure_advisory_intersections": exposure_advisory_intersections,
        "owner_work_queues": owner_work_queues,
        "unrouted_targets": unrouted[:_MAX_UNROUTED],
        "truncation": {
            "graph_files_omitted": graph_truncated,
            "entry_points_omitted": max(
                0, _raw_entry_point_count(reachability) - _MAX_ENTRY_POINTS
            ),
            "targets_omitted": dependency_targets_omitted
            + max(0, len(candidate_targets) - _MAX_TARGETS),
            "dependency_advisory_import_targets_omitted": dependency_targets_omitted,
            "entry_point_exposures_omitted": sum(
                int(route["entry_point_exposures_omitted"]) for route in retained_routes
            ),
            "routes_omitted": max(0, len(routed) - _MAX_ROUTES),
            "unrouted_targets_omitted": max(0, len(unrouted) - _MAX_UNROUTED),
            "convergence_hotspots_omitted": max(
                0, len(all_convergence_hotspots) - _MAX_CONVERGENCE_HOTSPOTS
            ),
            "validation_test_hotspots_omitted": max(
                0,
                len(all_validation_test_hotspots) - _MAX_VALIDATION_TEST_HOTSPOTS,
            ),
            "exposure_advisory_intersections_omitted": max(
                0,
                len(all_exposure_advisory_intersections)
                - _MAX_EXPOSURE_ADVISORY_INTERSECTIONS,
            ),
            "owner_work_queues_omitted": max(
                0, len(all_owner_work_queues) - _MAX_OWNER_QUEUES
            ),
        },
        "interpretation_limits": [
            "A static route is a review path, not proof of attacker-controlled input, vulnerable-function reachability, exploitability, or sensitive-data flow.",
            "Multiple declared entry-point routes establish bounded static interface breadth only; they do not prove distinct runtime interfaces, external exposure, attacker control, or execution.",
            "Entry-point runtime observation proves only that the exact retained reachability node executed during supplied tests; non-observation or missing node evidence does not prove an interface is dead or inaccessible.",
            "Route evidence assurance reports scanner completion, executable integrity continuity, organization approval, and perspective breadth separately; a gap does not invalidate a finding, and approval does not prove correctness.",
            "Finding lifecycle is attributed to a change only when finding-delta evidence proves a comparable approved baseline; default new status without that comparison is reported as not established.",
            "Route ownership applies retained CODEOWNERS-style rules to exact static file paths; a handoff is coordination evidence, not proof of organizational approval, runtime responsibility, or access control.",
            "No bounded route may indicate reflection, registries, dependency injection, generated code, framework dispatch, or an incomplete entry-point model.",
            "Runtime observation proves only that code executed during retained tests; absence of observation does not prove dead code.",
            "Sensitive-data sink surfaces are inventory signals unless a normalized scanner finding establishes a source-to-sink concern.",
            "A dependency-advisory import route proves only a retained static path to a source file that imports the affected distribution; it does not prove invocation of a vulnerable function, attacker control, or exploitability.",
            "Package lifecycle comparison proves only what the retained source and built-artifact composition inventories report; it does not prove inventory completeness, runtime loading, semantic version safety, or vulnerable-function use.",
            "An exposure-advisory intersection proves only that a retained sensitive sink and an affected SDK importer share an exact source path and advisory identity; it does not prove the SDK processed the sensitive value, that data leaked, or that the vulnerable function executed.",
            "Graph-selected tests are bounded static candidates; passing selected tests and full retained coverage improve regression confidence but do not prove security, exploitability, or complete runtime behavior.",
            "The shared-control review score is a transparent triage aid, not native scanner severity, exploitability probability, or an admission decision.",
            "A shared validation test hotspot identifies concentrated regression responsibility; it does not prove test independence, assertion quality, or sufficient behavioral coverage.",
            "A sealed report binds its current source inventory, but pre-generated test and coverage evidence is revision-aligned only when each producer declares the same aggregate source digest.",
        ],
        "references": [
            _GRAPHIFY_REFERENCE,
            _REACHABILITY_REFERENCE,
            _RISK_PATH_REFERENCE,
        ],
    }


def _file_graph(value: Any) -> tuple[dict[str, dict[str, str]], bool, int]:
    if not isinstance(value, dict) or value.get("schema_version") != "1.0":
        return {}, False, 0
    topology = value.get("topology")
    edges = topology.get("file_edges") if isinstance(topology, dict) else None
    if not isinstance(edges, list):
        return {}, False, 0
    candidates: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
    known: set[str] = set()
    omitted_paths: set[str] = set()
    for edge in edges:
        if not isinstance(edge, dict):
            continue
        source, target, relation = (
            _path(edge.get("source")),
            _path(edge.get("target")),
            str(edge.get("relation") or ""),
        )
        if not source or not target or relation not in _ROUTE_RELATIONS:
            continue
        if source not in known and len(known) >= _MAX_GRAPH_FILES:
            omitted_paths.add(source)
            continue
        known.add(source)
        if target not in known and len(known) >= _MAX_GRAPH_FILES:
            omitted_paths.add(target)
            continue
        known.add(target)
        candidates[source][target].add(relation)
    adjacency = {
        source: {
            target: min(
                relations,
                key=lambda relation: (_RELATION_ORDER.get(relation, 99), relation),
            )
            for target, relations in sorted(targets.items())
        }
        for source, targets in sorted(candidates.items())
    }
    return adjacency, True, len(omitted_paths)


def _entry_points(value: Any) -> list[dict[str, Any]]:
    raw = value.get("entry_points") if isinstance(value, dict) else None
    if not isinstance(raw, list):
        return []
    result: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for item in raw:
        if not isinstance(item, dict):
            continue
        path = _path(item.get("path"))
        identifier = str(item.get("id") or "").strip()
        if not path or not identifier or (identifier, path) in seen:
            continue
        seen.add((identifier, path))
        result.append(
            {
                "id": identifier[:500],
                "kind": str(item.get("kind") or "unknown")[:100],
                "declared_as": str(item.get("declared_as") or path)[:1000],
                "path": path,
                "line": _positive_integer(item.get("line")),
                "target": _optional_string(item.get("target")),
            }
        )
    return sorted(result, key=lambda item: (item["path"], item["id"]))[
        :_MAX_ENTRY_POINTS
    ]


def _entry_point_runtime_index(value: Any) -> dict[str, dict[str, Any]]:
    raw = value.get("nodes") if isinstance(value, dict) else None
    nodes = raw if isinstance(raw, list) else []
    result: dict[str, dict[str, Any]] = {}
    for item in nodes[:_MAX_GRAPH_FILES]:
        if not isinstance(item, dict):
            continue
        identifier = _optional_string(item.get("id"))
        if not identifier:
            continue
        result[identifier] = {
            "reachability_state": _optional_string(item.get("state")),
            "runtime_observation": _optional_string(item.get("runtime_observation")),
        }
    return result


def _finding_targets(findings: list[Finding]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for finding in findings:
        if finding.status is FindingStatus.SUPPRESSED or not finding.locations:
            continue
        location = finding.locations[0]
        path = _path(location.path)
        if not path or path in {".", "<outside-target>"}:
            continue
        fusion = _object(finding.evidence.get("fusion"))
        source = _object(fusion.get("source_context"))
        structural = _object(finding.evidence.get("structural_synthesis"))
        exposure = _object(finding.evidence.get("data_exposure"))
        validation = _validation_context(source, structural, exposure)
        result.append(
            {
                "kind": "finding",
                "id": finding.finding_id,
                "finding_id": finding.finding_id,
                "path": path,
                "line": location.start_line,
                "label": finding.title[:1000],
                "domain": finding.domain,
                "area": finding.area,
                "severity": finding.severity.value,
                "lifecycle_status": finding.status.value,
                "baseline_match": _bounded_baseline_match(
                    finding.evidence.get("baseline")
                ),
                "priority": finding_priority(
                    severity=finding.severity.value,
                    classifications=finding.classifications,
                    evidence=finding.evidence,
                ),
                "tools": sorted({source.tool for source in finding.sources})[:25],
                "classifications": sorted(set(finding.classifications))[:50],
                "owners": _strings(finding.evidence.get("owners"), 20),
                "runtime_context": _runtime_context(source, structural),
                "validation": validation,
                "correlations": _finding_correlations(finding, fusion, structural),
                "recommended_action": _recommended_action(
                    finding.remediation, validation, exposure
                ),
                "evidence_artifacts": _finding_evidence_artifacts(
                    finding, fusion, structural, exposure
                ),
            }
        )
    return result


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


def _sink_surface_targets(value: Any) -> list[dict[str, Any]]:
    surfaces = value.get("sink_surfaces") if isinstance(value, dict) else None
    if not isinstance(surfaces, list):
        return []
    result: list[dict[str, Any]] = []
    for surface in surfaces:
        if not isinstance(surface, dict) or surface.get("scope") != "production":
            continue
        structural = _object(surface.get("structural_context"))
        if not _review_worthy_surface(surface, structural):
            continue
        path = _path(surface.get("path"))
        if not path:
            continue
        line = _positive_integer(surface.get("line"))
        label = str(surface.get("label") or surface.get("sink_family") or "sink")
        identifier = (
            "surface-" + _digest({"path": path, "line": line, "label": label})[:16]
        )
        priority = {
            "high": "P1",
            "medium": "P2",
            "low": "P3",
        }.get(str(surface.get("review_priority") or "medium"), "P2")
        validation = _surface_validation(structural)
        dependency = _object(surface.get("sdk_dependency_context"))
        exact_advisories = _surface_dependency_advisories(dependency, path)
        result.append(
            {
                "kind": "sink-surface",
                "id": identifier,
                "finding_id": None,
                "path": path,
                "line": line,
                "label": label[:1000],
                "domain": "security",
                "area": "data-exposure",
                "severity": None,
                "priority": priority,
                "tools": ["pysec-data-exposure"],
                "classifications": _surface_classifications(surface),
                "owners": _strings(structural.get("owners"), 20),
                "runtime_context": {
                    "reachability_states": _strings(
                        structural.get("reachability_states"), 10
                    ),
                    "observations": _strings(
                        structural.get("runtime_observations"), 10
                    ),
                },
                "validation": validation,
                "correlations": {
                    "related_finding_ids": _strings(
                        structural.get("related_finding_ids"), 50
                    ),
                    "related_tools": _strings(structural.get("related_tools"), 25),
                    "structural_risk_ids": _strings(
                        structural.get("structural_risk_ids"), 25
                    ),
                    "sink_family": str(surface.get("sink_family") or "unknown")[:100],
                    "data_classes": _strings(surface.get("data_classes"), 25),
                    "protection_status": str(
                        surface.get("protection_status") or "unknown"
                    )[:100],
                    "trust_boundary": str(surface.get("trust_boundary") or "unknown")[
                        :100
                    ],
                    "sdk": _optional_string(surface.get("sdk")),
                    "sdk_package_risk": dependency.get("risk_present") is True,
                    "sdk_risk_tier": _optional_string(dependency.get("risk_tier")),
                    "exact_path_sdk_advisories": exact_advisories,
                },
                "recommended_action": _surface_action(surface, structural),
                "evidence_artifacts": sorted(
                    {
                        "data-exposure.json",
                        *(
                            ["structural-synthesis.json"]
                            if structural.get("context_available")
                            else []
                        ),
                    }
                ),
            }
        )
    return result


def _surface_dependency_advisories(
    dependency: dict[str, Any], path: str
) -> list[dict[str, Any]]:
    """Retain only advisory records whose exact importer ledger matches the sink."""
    if dependency.get("risk_present") is not True:
        return []
    raw_clusters = dependency.get("advisory_clusters")
    clusters = raw_clusters if isinstance(raw_clusters, list) else []
    result: list[dict[str, Any]] = []
    for cluster in clusters[:50]:
        if not isinstance(cluster, dict):
            continue
        usage = _object(cluster.get("dependency_usage"))
        raw_assessments = usage.get("import_path_assessments")
        assessments = raw_assessments if isinstance(raw_assessments, list) else []
        assessment = next(
            (
                item
                for item in assessments[:_MAX_ADVISORY_IMPORT_PATHS]
                if isinstance(item, dict) and _path(item.get("path")) == path
            ),
            None,
        )
        cluster_id = _optional_string(cluster.get("cluster_id"))
        package = _optional_string(cluster.get("package"))
        primary = _optional_string(cluster.get("primary_identifier"))
        if assessment is None or not cluster_id or not package or not primary:
            continue
        threat = _object(cluster.get("threat_context"))
        remediation = _object(cluster.get("remediation_context"))
        priority = str(remediation.get("priority") or "P4")
        if priority not in {"P0", "P1", "P2", "P3", "P4"}:
            priority = "P4"
        result.append(
            {
                "cluster_id": cluster_id,
                "primary_identifier": primary,
                "package": package,
                "finding_ids": _strings(cluster.get("finding_ids"), 100),
                "tools": _strings(cluster.get("tools"), 25),
                "known_exploited": threat.get("known_exploited") is True,
                "epss_high": threat.get("epss_high") is True,
                "fix_available": remediation.get("fix_available") is True,
                "priority": priority,
                "import_assessment": _optional_string(assessment.get("assessment")),
                "import_lines": _positive_integers(assessment.get("import_lines"), 100),
            }
        )
    return sorted(
        result,
        key=lambda item: (
            _priority_rank(str(item["priority"])),
            str(item["package"]),
            str(item["cluster_id"]),
        ),
    )[:50]


def _package_lineage_index(value: dict[str, Any]) -> dict[str, dict[str, Any]]:
    raw_lineage = value.get("package_lineage")
    lineage = raw_lineage if isinstance(raw_lineage, list) else []
    result: dict[str, dict[str, Any]] = {}
    for item in lineage[:_MAX_TARGETS]:
        if not isinstance(item, dict):
            continue
        package = _optional_string(item.get("package"))
        status = _optional_string(item.get("status"))
        if not package or status not in {
            "matched",
            "version-drift",
            "source-only",
            "artifact-only",
        }:
            continue
        result[package] = {
            "package": package,
            "status": status,
            "source_versions": _strings(item.get("source_versions"), 50),
            "artifact_versions": _strings(item.get("artifact_versions"), 50),
            "finding_ids": _strings(item.get("finding_ids"), 100),
        }
    return result


def _composition_evidence(value: dict[str, Any]) -> dict[str, Any]:
    raw_lanes = value.get("evidence_lanes")
    lanes = raw_lanes if isinstance(raw_lanes, list) else []
    by_name = {
        str(item.get("lane")): item
        for item in lanes
        if isinstance(item, dict) and item.get("lane")
    }
    source = _object(by_name.get("source_composition"))
    artifact = _object(by_name.get("artifact_composition"))
    source_artifacts = _strings(source.get("available_artifacts"), 25)
    artifact_artifacts = _strings(artifact.get("available_artifacts"), 25)
    return {
        "source_inventory_available": "sbom.cdx.json" in source_artifacts,
        "artifact_inventory_available": "artifact-sbom.cdx.json" in artifact_artifacts,
        "source_execution_gaps": _strings(source.get("execution_gaps"), 25),
        "artifact_execution_gaps": _strings(artifact.get("execution_gaps"), 25),
        "evidence_artifacts": sorted({*source_artifacts, *artifact_artifacts}),
    }


def _package_lifecycle_assessment(
    lineage: dict[str, Any] | None,
    composition: dict[str, Any],
    fixed_versions: list[str],
) -> dict[str, Any]:
    source_available = composition.get("source_inventory_available") is True
    artifact_available = composition.get("artifact_inventory_available") is True
    comparison_available = source_available and artifact_available
    status = str(lineage.get("status")) if lineage else "not-available"
    source_versions = _strings(lineage.get("source_versions"), 50) if lineage else []
    artifact_versions = (
        _strings(lineage.get("artifact_versions"), 50) if lineage else []
    )
    if comparison_available:
        assessment = status if lineage else "package-not-observed"
    elif source_available:
        assessment = "artifact-inventory-unavailable"
    elif artifact_available:
        assessment = "source-inventory-unavailable"
    else:
        assessment = "composition-inventories-unavailable"
    fixed_match = (
        bool(set(artifact_versions) & set(fixed_versions))
        if artifact_versions and fixed_versions
        else None
    )
    version_match = (
        status == "matched"
        if comparison_available and status in {"matched", "version-drift"}
        else None
    )
    return {
        "assessment": assessment,
        "lineage_status": status,
        "comparison_available": comparison_available,
        "source_inventory_available": source_available,
        "artifact_inventory_available": artifact_available,
        "source_versions": source_versions,
        "artifact_versions": artifact_versions,
        "source_artifact_versions_match": version_match,
        "artifact_fixed_version_exact_match": fixed_match,
        "finding_ids": _strings(lineage.get("finding_ids"), 100) if lineage else [],
        "source_execution_gaps": _strings(composition.get("source_execution_gaps"), 25),
        "artifact_execution_gaps": _strings(
            composition.get("artifact_execution_gaps"), 25
        ),
        "evidence_artifacts": _strings(composition.get("evidence_artifacts"), 10),
    }


def _dependency_advisory_targets(
    value: Any,
    path_context: dict[str, dict[str, Any]],
) -> tuple[list[dict[str, Any]], int]:
    """Promote advisory importer paths into bounded static review targets."""
    clusters = value.get("advisory_clusters") if isinstance(value, dict) else None
    if not isinstance(clusters, list):
        return [], 0
    lineage_by_package = _package_lineage_index(value)
    composition_evidence = _composition_evidence(value)
    result: list[dict[str, Any]] = []
    omitted = 0
    seen: set[tuple[str, str]] = set()
    for cluster in clusters[:_MAX_TARGETS]:
        if not isinstance(cluster, dict):
            continue
        cluster_id = str(cluster.get("cluster_id") or "").strip()[:500]
        package = str(cluster.get("package") or "").strip()[:500]
        primary = str(cluster.get("primary_identifier") or cluster_id).strip()[:500]
        usage = _object(cluster.get("dependency_usage"))
        if not cluster_id or not package or not primary:
            continue
        remediation = _object(cluster.get("remediation_context"))
        threat = _object(cluster.get("threat_context"))
        package_lifecycle = _package_lifecycle_assessment(
            lineage_by_package.get(package),
            composition_evidence,
            _strings(remediation.get("fixed_version_candidates"), 25),
        )
        finding_ids = _strings(cluster.get("finding_ids"), 100)
        tools = _strings(cluster.get("tools"), 25)
        versions = _strings(cluster.get("versions"), 25)
        identifiers = _strings(cluster.get("identifiers"), 50)
        citations = _advisory_citations(cluster.get("citations"))
        fallback_owners = _strings(
            usage.get("import_path_owners") or remediation.get("owners"), 20
        )
        raw_ownership = usage.get("import_path_ownership")
        ownership_records = raw_ownership if isinstance(raw_ownership, list) else []
        ownership_by_path = {
            owned_path: _strings(record.get("owners"), 20)
            for record in ownership_records[:_MAX_ADVISORY_IMPORT_PATHS]
            if isinstance(record, dict) and (owned_path := _path(record.get("path")))
        }
        priority = str(remediation.get("priority") or "P2")
        if priority not in {"P0", "P1", "P2", "P3", "P4"}:
            priority = "P2"
        severity = str(cluster.get("highest_severity") or "unknown").casefold()
        if severity not in {
            "critical",
            "high",
            "medium",
            "low",
            "informational",
            "unknown",
        }:
            severity = "unknown"
        raw_coverage = usage.get("import_path_coverage")
        coverage_records = raw_coverage if isinstance(raw_coverage, list) else []
        coverage_by_path = {
            path: _optional_number(record.get("coverage_percent"))
            for record in coverage_records
            if isinstance(record, dict) and (path := _path(record.get("path")))
        }
        raw_assessments = usage.get("import_path_assessments")
        assessment_records = (
            raw_assessments if isinstance(raw_assessments, list) else []
        )
        assessment_by_path = {
            assessed_path: record
            for record in assessment_records[:_MAX_ADVISORY_IMPORT_PATHS]
            if isinstance(record, dict) and (assessed_path := _path(record.get("path")))
        }
        raw_dependency_paths = usage.get("dependency_paths")
        dependency_paths = (
            [item for item in raw_dependency_paths[:25] if isinstance(item, dict)]
            if isinstance(raw_dependency_paths, list)
            else []
        )
        import_paths = sorted(
            {
                path
                for raw_path in _strings(
                    usage.get("import_paths"), _MAX_ADVISORY_IMPORT_PATHS
                )
                if (path := _path(raw_path))
            }
        )[:_MAX_ADVISORY_IMPORT_PATHS]
        for path in import_paths:
            key = (cluster_id, path)
            if key in seen:
                continue
            seen.add(key)
            if len(result) >= _MAX_TARGETS:
                omitted += 1
                continue
            context = path_context.get(path, _empty_campaign_control_context())
            path_assessment = _object(assessment_by_path.get(path))
            owners = (
                _strings(path_assessment.get("owners"), 20)
                if path_assessment
                else ownership_by_path.get(path) or fallback_owners
            )
            reachability_states = _strings(
                (
                    path_assessment.get("reachability_states")
                    if path_assessment
                    else context.get("reachability_states")
                ),
                10,
            )
            runtime_observations = _strings(
                (
                    path_assessment.get("runtime_observations")
                    if path_assessment
                    else context.get("runtime_observations")
                ),
                10,
            )
            target_id = (
                "dependency-import-"
                + _digest({"cluster_id": cluster_id, "path": path})[:16]
            )
            result.append(
                {
                    "kind": "dependency-advisory-import",
                    "id": target_id,
                    "finding_id": None,
                    "path": path,
                    "line": None,
                    "label": f"{primary} in {package} imported by {path}"[:1000],
                    "domain": "supply-chain",
                    "area": "dependency-vulnerabilities",
                    "severity": severity,
                    "priority": priority,
                    "tools": tools,
                    "classifications": _dependency_advisory_classifications(
                        identifiers, threat
                    ),
                    "owners": owners,
                    "runtime_context": {
                        "reachability_states": reachability_states,
                        "observations": runtime_observations,
                    },
                    "validation": _dependency_advisory_validation(
                        path, usage, coverage_by_path, path_assessment
                    ),
                    "correlations": {
                        "advisory_cluster_id": cluster_id,
                        "primary_identifier": primary,
                        "identifiers": identifiers,
                        "package": package,
                        "versions": versions,
                        "related_finding_ids": finding_ids,
                        "source_relationship": _optional_string(
                            usage.get("source_relationship")
                        ),
                        "dependency_paths": dependency_paths,
                        "dependency_path_confidence": _optional_string(
                            usage.get("dependency_path_confidence")
                        ),
                        "dependency_usage_assessment": _optional_string(
                            path_assessment.get("assessment")
                            if path_assessment
                            else usage.get("assessment")
                        ),
                        "import_modules": _strings(
                            (
                                path_assessment.get("import_modules")
                                if path_assessment
                                else usage.get("import_modules")
                            ),
                            50,
                        ),
                        "import_lines": _positive_integers(
                            path_assessment.get("import_lines"), 100
                        ),
                        "import_path_assessment": path_assessment or None,
                        "known_exploited": bool(threat.get("known_exploited")),
                        "epss_probability": _optional_number(
                            threat.get("epss_probability")
                        ),
                        "epss_percentile": _optional_number(
                            threat.get("epss_percentile")
                        ),
                        "epss_high": bool(threat.get("epss_high")),
                        "vex_disposition": _optional_string(
                            threat.get("vex_disposition")
                        ),
                        "fix_available": bool(remediation.get("fix_available")),
                        "fixed_version_candidates": _strings(
                            remediation.get("fixed_version_candidates"), 25
                        ),
                        "action_kind": _optional_string(remediation.get("action_kind")),
                        "package_lifecycle": package_lifecycle,
                        "advisory_citations": citations,
                        "change_risk_score": context.get("change_risk_score"),
                        "change_priority": context.get("change_priority"),
                        "uncovered_changed_lines": list(
                            context.get("uncovered_changed_lines") or []
                        )[:_MAX_CAMPAIGN_MISSING_LINES],
                    },
                    "recommended_action": _dependency_advisory_action(
                        package,
                        primary,
                        path,
                        remediation,
                        path_assessment or usage,
                        package_lifecycle,
                    ),
                    "evidence_artifacts": sorted(
                        {
                            "evidence-fusion.json",
                            *_strings(usage.get("evidence_artifacts"), 25),
                            *_strings(path_assessment.get("evidence_artifacts"), 25),
                            *_strings(package_lifecycle.get("evidence_artifacts"), 10),
                            *(
                                ["risk-intelligence.json"]
                                if threat.get("intelligence_available") is True
                                or threat.get("intelligence_sources")
                                else []
                            ),
                        }
                    ),
                }
            )
    return result, omitted


def _dependency_advisory_validation(
    path: str,
    usage: dict[str, Any],
    coverage_by_path: dict[str, float | None],
    path_assessment: dict[str, Any],
) -> dict[str, Any]:
    exact = bool(path_assessment)
    alignment = _optional_string(
        path_assessment.get("test_coverage_alignment")
        if exact
        else usage.get("test_coverage_alignment")
    )
    uncovered = set(_strings(usage.get("uncovered_import_paths"), 50))
    gap_reasons = _strings(
        (
            path_assessment.get("validation_gap_reasons")
            if exact
            else usage.get("validation_gap_reasons")
        ),
        10,
    )
    if not exact and alignment == "coverage-gap" and path not in uncovered:
        alignment = None
        gap_reasons = [
            reason for reason in gap_reasons if "cover" not in reason.casefold()
        ]
    return {
        "changed_line": None,
        "line_covered": None,
        "coverage_percent": _optional_number(path_assessment.get("coverage_percent"))
        if exact
        else coverage_by_path.get(path),
        "mapped_test_files": _strings(
            (
                path_assessment.get("recommended_test_files")
                if exact
                else usage.get("recommended_test_files")
            ),
            25,
        ),
        "focused_test_status": _optional_string(
            path_assessment.get("focused_test_validation_status")
            if exact
            else usage.get("focused_test_validation_status")
        ),
        "coverage_alignment": alignment,
        "gap_reasons": gap_reasons,
        "action": (
            "Use this exact importer assessment; do not infer validation from other import paths."
            if exact
            else None
        ),
    }


def _dependency_advisory_classifications(
    identifiers: list[str], threat: dict[str, Any]
) -> list[str]:
    values = {"DEPENDENCY-ADVISORY", *identifiers}
    if threat.get("known_exploited") is True:
        values.add("CISA-KEV")
    if threat.get("epss_high") is True:
        values.add("EPSS-HIGH")
    vex = _optional_string(threat.get("vex_disposition"))
    if vex:
        values.add("VEX-" + vex.upper().replace("_", "-")[:100])
    return sorted(values)[:50]


def _advisory_citations(value: Any) -> list[dict[str, str | None]]:
    if not isinstance(value, list):
        return []
    result: list[dict[str, str | None]] = []
    seen: set[tuple[str, str | None]] = set()
    for item in value[:25]:
        if not isinstance(item, dict):
            continue
        identifier = str(item.get("identifier") or "").strip()[:500]
        uri_value = item.get("uri")
        uri = str(uri_value).strip()[:4000] if isinstance(uri_value, str) else None
        if not identifier or (identifier, uri) in seen:
            continue
        seen.add((identifier, uri))
        result.append(
            {
                "identifier": identifier,
                "title": str(item.get("title") or identifier).strip()[:1000],
                "uri": uri,
            }
        )
    return result


def _dependency_advisory_action(
    package: str,
    primary: str,
    path: str,
    remediation: dict[str, Any],
    usage: dict[str, Any],
    lifecycle: dict[str, Any],
) -> str:
    action = str(remediation.get("recommended_action") or "").strip()
    if not action:
        action = (
            f"Review {primary} for {package}, establish vulnerable-function use, "
            "then upgrade, remove, mitigate, or record a governed VEX disposition."
        )
    tests = _strings(usage.get("recommended_test_files"), 5)
    if tests:
        action += " Re-run focused importer tests: " + ", ".join(tests) + "."
    else:
        action += f" Add a focused test that exercises dependency use from {path}."
    lifecycle_assessment = str(lifecycle.get("assessment") or "not-available")
    if lifecycle_assessment == "version-drift":
        action += (
            " Reconcile source and built-artifact versions, then verify remediation "
            "against the exact packaged component."
        )
    elif lifecycle_assessment == "artifact-only":
        action += (
            " Identify and govern the artifact-only introduction path before release."
        )
    elif lifecycle_assessment == "source-only":
        action += (
            " Verify the package is intentionally excluded from the complete built "
            "artifact inventory before treating source-only status as risk reduction."
        )
    elif lifecycle_assessment in {
        "source-inventory-unavailable",
        "artifact-inventory-unavailable",
        "composition-inventories-unavailable",
        "package-not-observed",
    }:
        action += (
            " Produce complete source and built-artifact composition evidence for "
            "this package before lifecycle disposition."
        )
    return action[:2000]


def _exposure_advisory_intersections(
    routes: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Join exact-path SDK sink routes to the same advisory importer route."""
    dependency_routes = {
        (
            str(route["target"]["path"]),
            str(route["correlations"].get("advisory_cluster_id") or ""),
            str(route["correlations"].get("package") or ""),
        ): route
        for route in routes
        if route["target"].get("kind") == "dependency-advisory-import"
    }
    result: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for sink_route in routes:
        if sink_route["target"].get("kind") != "sink-surface":
            continue
        path = str(sink_route["target"]["path"])
        raw_advisories = sink_route["correlations"].get("exact_path_sdk_advisories")
        advisories = raw_advisories if isinstance(raw_advisories, list) else []
        for advisory in advisories[:50]:
            if not isinstance(advisory, dict):
                continue
            cluster_id = str(advisory.get("cluster_id") or "")
            package = str(advisory.get("package") or "")
            dependency_route = dependency_routes.get((path, cluster_id, package))
            if dependency_route is None:
                continue
            pair = (
                str(sink_route["route_id"]),
                str(dependency_route["route_id"]),
            )
            if pair in seen:
                continue
            seen.add(pair)
            priorities = sorted(
                [str(sink_route["priority"]), str(dependency_route["priority"])],
                key=_priority_rank,
            )
            intersection_id = (
                "exposure-advisory-"
                + _digest(
                    {
                        "sink_route_id": pair[0],
                        "dependency_route_id": pair[1],
                        "cluster_id": cluster_id,
                    }
                )[:16]
            )
            owners = sorted(
                {
                    *_strings(sink_route.get("owners"), 20),
                    *_strings(dependency_route.get("owners"), 20),
                }
            )[:20]
            finding_ids = sorted(
                {
                    *_strings(
                        sink_route["correlations"].get("related_finding_ids"), 50
                    ),
                    *_strings(advisory.get("finding_ids"), 100),
                    *_strings(
                        dependency_route["correlations"].get("related_finding_ids"),
                        100,
                    ),
                }
            )[:100]
            entry_exposures = {
                str(exposure["exposure_id"]): exposure
                for route in (sink_route, dependency_route)
                for exposure in route["entry_point_exposures"]
            }
            result.append(
                {
                    "intersection_id": intersection_id,
                    "priority": priorities[0] if priorities else "P4",
                    "path": path,
                    "line": sink_route["target"].get("line"),
                    "route_ids": [pair[0], pair[1]],
                    "sink_route_id": pair[0],
                    "sink_target_id": str(sink_route["target"]["id"]),
                    "dependency_route_id": pair[1],
                    "dependency_target_id": str(dependency_route["target"]["id"]),
                    "advisory_cluster_id": cluster_id,
                    "primary_identifier": str(
                        dependency_route["correlations"].get("primary_identifier")
                        or cluster_id
                    ),
                    "package": package,
                    "sdk": _optional_string(sink_route["correlations"].get("sdk")),
                    "sink_family": str(
                        sink_route["correlations"].get("sink_family") or "unknown"
                    ),
                    "trust_boundary": str(
                        sink_route["correlations"].get("trust_boundary") or "unknown"
                    ),
                    "data_classes": _strings(
                        sink_route["correlations"].get("data_classes"), 25
                    ),
                    "protection_status": str(
                        sink_route["correlations"].get("protection_status") or "unknown"
                    ),
                    "finding_ids": finding_ids,
                    "tools": sorted(
                        {
                            *_strings(sink_route["target"].get("tools"), 25),
                            *_strings(dependency_route["target"].get("tools"), 25),
                        }
                    )[:25],
                    "owners": owners,
                    "known_exploited": dependency_route["correlations"].get(
                        "known_exploited"
                    )
                    is True,
                    "epss_high": dependency_route["correlations"].get("epss_high")
                    is True,
                    "fix_available": dependency_route["correlations"].get(
                        "fix_available"
                    )
                    is True,
                    "package_lifecycle": _object(
                        dependency_route["correlations"].get("package_lifecycle")
                    ),
                    "entry_point_exposure_ids": sorted(entry_exposures),
                    "entry_point_ids": sorted(
                        {
                            str(exposure["entry_point"]["id"])
                            for exposure in entry_exposures.values()
                        }
                    ),
                    "entry_point_exposure_count": len(
                        {
                            str(exposure["entry_point"]["id"])
                            for exposure in entry_exposures.values()
                        }
                    ),
                    "entry_point_exposures_omitted": max(
                        int(sink_route["entry_point_exposures_omitted"]),
                        int(dependency_route["entry_point_exposures_omitted"]),
                    ),
                    "entry_point_runtime_statuses": _entry_runtime_counts(
                        entry_exposures.values()
                    ),
                    "validation_statuses": {
                        "sink": str(
                            sink_route["validation"].get("assessment_status")
                            or "not-assessed"
                        ),
                        "dependency": str(
                            dependency_route["validation"].get("assessment_status")
                            or "not-assessed"
                        ),
                    },
                    "evidence_assurance_statuses": {
                        "sink": str(
                            sink_route["evidence_assurance"].get("review_status")
                            or "not-assessed"
                        ),
                        "dependency": str(
                            dependency_route["evidence_assurance"].get("review_status")
                            or "not-assessed"
                        ),
                    },
                    "advisory_citations": list(
                        dependency_route["correlations"].get("advisory_citations") or []
                    )[:25],
                    "evidence_artifacts": sorted(
                        {
                            "data-exposure.json",
                            "evidence-fusion.json",
                            "risk-paths.json",
                            *_strings(sink_route.get("evidence_artifacts"), 25),
                            *_strings(dependency_route.get("evidence_artifacts"), 25),
                        }
                    ),
                    "recommended_action": (
                        "Review the exact SDK sink/import path for sensitive-field "
                        "minimization and redaction, establish whether the advisory's "
                        "vulnerable function can process this boundary data, then apply "
                        "the retained dependency remediation and rerun both sink and "
                        "importer validation."
                    ),
                }
            )
    return sorted(
        result,
        key=lambda item: (
            _priority_rank(str(item["priority"])),
            str(item["path"]),
            int(item["line"] or 0),
            str(item["intersection_id"]),
        ),
    )


def _route_targets(
    entry_points: list[dict[str, Any]],
    targets: list[dict[str, Any]],
    adjacency: dict[str, dict[str, str]],
    *,
    graph_available: bool,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    if not entry_points:
        return [], [
            _unrouted(target, "declared entry-point evidence is unavailable")
            for target in targets
        ]
    parent, origin, depth = _multi_source_paths(entry_points, adjacency)
    entries_by_id = {item["id"]: item for item in entry_points}
    routed: list[dict[str, Any]] = []
    unrouted: list[dict[str, Any]] = []
    for target in targets:
        path = target["path"]
        if path not in origin:
            reason = (
                "Graphify file-route evidence is unavailable"
                if not graph_available
                else f"no declared-entry-point route was found within {_MAX_ROUTE_HOPS} file hops"
            )
            unrouted.append(_unrouted(target, reason))
            continue
        files, edges = _reconstruct_route(path, parent)
        entry = entries_by_id[origin[path]]
        route_id = (
            "route-"
            + _digest(
                {
                    "entry_point": entry["id"],
                    "target": target["id"],
                    "files": files,
                }
            )[:16]
        )
        routed.append(
            {
                "route_id": route_id,
                "priority": target["priority"],
                "entry_point": entry,
                "target": _public_target(target),
                "hop_count": depth[path],
                "files": files,
                "edges": edges,
                "owners": target["owners"],
                "runtime_context": target["runtime_context"],
                "validation": target["validation"],
                "evidence_assurance": target["evidence_assurance"],
                **(
                    {
                        "change_lifecycle_attribution": target[
                            "change_lifecycle_attribution"
                        ]
                    }
                    if "change_lifecycle_attribution" in target
                    else {}
                ),
                "correlations": target["correlations"],
                "recommended_action": target["recommended_action"],
                "evidence_artifacts": sorted(
                    {
                        "reachability.json",
                        *(
                            {"graphify.json"}
                            if graph_available and depth[path] > 0
                            else set()
                        ),
                        *target["evidence_artifacts"],
                        *target["evidence_assurance"]["evidence_artifacts"],
                        *_strings(
                            _object(target.get("change_lifecycle_attribution")).get(
                                "evidence_artifacts"
                            ),
                            10,
                        ),
                    }
                ),
            }
        )
    return routed, unrouted


def _attach_entry_point_exposures(
    routes: list[dict[str, Any]],
    entry_points: list[dict[str, Any]],
    adjacency: dict[str, dict[str, str]],
    runtime_index: dict[str, dict[str, Any]],
) -> None:
    """Retain every bounded declared-entry route without multiplying targets."""
    routes_by_path: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for route in routes:
        routes_by_path[str(route["target"]["path"])].append(route)
    entries_by_path: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for entry in entry_points:
        entries_by_path[str(entry["path"])].append(entry)
    candidates: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for _entry_path, entries in sorted(entries_by_path.items()):
        representative = entries[0]
        parent, _origin, depth = _multi_source_paths([representative], adjacency)
        for target_path, target_routes in routes_by_path.items():
            if target_path not in depth:
                continue
            files, edges = _reconstruct_route(target_path, parent)
            for route in target_routes:
                for entry in entries:
                    primary = (
                        entry["id"] == route["entry_point"]["id"]
                        and entry["path"] == route["entry_point"]["path"]
                    )
                    candidates[str(route["route_id"])].append(
                        {
                            "exposure_id": "entry-exposure-"
                            + _digest(
                                {
                                    "route_id": route["route_id"],
                                    "entry_point": entry["id"],
                                    "entry_path": entry["path"],
                                    "files": files,
                                }
                            )[:16],
                            "primary": primary,
                            "entry_point": entry,
                            "runtime_context": _entry_runtime_context(
                                entry, runtime_index
                            ),
                            "hop_count": depth[target_path],
                            "files": files,
                            "edges": edges,
                        }
                    )
    for route in routes:
        values = sorted(
            candidates.get(str(route["route_id"]), []),
            key=lambda item: (
                not item["primary"],
                int(item["hop_count"]),
                str(item["entry_point"]["kind"]),
                str(item["entry_point"]["path"]),
                str(item["entry_point"]["id"]),
            ),
        )
        route["entry_point_exposure_count"] = len(values)
        route["entry_point_exposures"] = values[:_MAX_ENTRY_POINT_EXPOSURES]
        route["entry_point_exposures_omitted"] = max(
            0, len(values) - _MAX_ENTRY_POINT_EXPOSURES
        )
        route["entry_point_kinds"] = sorted(
            {str(item["entry_point"]["kind"]) for item in values}
        )


def _attach_route_ownership(
    route: dict[str, Any], rules: list[tuple[str, list[str]]]
) -> None:
    """Join exact retained route files to bounded CODEOWNERS-style evidence."""
    exposures = route.get("entry_point_exposures")
    retained = exposures if isinstance(exposures, list) else []
    file_index: dict[str, dict[str, Any]] = {}
    boundary_index: dict[str, dict[str, Any]] = {}
    for exposure in retained[:_MAX_ENTRY_POINT_EXPOSURES]:
        if not isinstance(exposure, dict):
            continue
        exposure_id = str(exposure.get("exposure_id") or "unknown")
        files = _ordered_strings(exposure.get("files"), _MAX_ROUTE_HOPS + 1)
        ownership_path = _ownership_path_records(
            files,
            rules,
            entry_path=_path(_object(exposure.get("entry_point")).get("path")),
            target_path=_path(_object(route.get("target")).get("path")),
        )
        exposure["ownership_path"] = ownership_path
        exposure["ownership_boundary_ids"] = []
        for record in ownership_path:
            path = str(record["path"])
            aggregate = file_index.setdefault(
                path,
                {
                    "path": path,
                    "owners": list(record["owners"]),
                    "roles": set(),
                    "entry_point_exposure_ids": set(),
                },
            )
            aggregate["roles"].update(record["roles"])
            aggregate["entry_point_exposure_ids"].add(exposure_id)
        for source, target in pairwise(ownership_path):
            if source["owners"] == target["owners"]:
                continue
            boundary_id = (
                "ownership-boundary-"
                + _digest(
                    {
                        "source": source["path"],
                        "target": target["path"],
                        "source_owners": source["owners"],
                        "target_owners": target["owners"],
                    }
                )[:16]
            )
            boundary = boundary_index.setdefault(
                boundary_id,
                {
                    "boundary_id": boundary_id,
                    "source": source["path"],
                    "target": target["path"],
                    "source_owners": list(source["owners"]),
                    "target_owners": list(target["owners"]),
                    "entry_point_exposure_ids": set(),
                },
            )
            boundary["entry_point_exposure_ids"].add(exposure_id)
            exposure["ownership_boundary_ids"].append(boundary_id)
    file_records = [
        {
            **record,
            "roles": sorted(record["roles"]),
            "entry_point_exposure_ids": sorted(record["entry_point_exposure_ids"]),
        }
        for _path_value, record in sorted(file_index.items())
    ]
    boundaries = [
        {
            **record,
            "entry_point_exposure_ids": sorted(record["entry_point_exposure_ids"]),
        }
        for _identifier, record in sorted(boundary_index.items())
    ]
    evidence_available = bool(rules)
    unowned = (
        sorted(record["path"] for record in file_records if not record["owners"])
        if evidence_available
        else []
    )
    path_owners = sorted(
        {
            owner
            for record in file_records
            for owner in _strings(record.get("owners"), 20)
        }
    )
    target_owners = _strings(route.get("owners"), 20)
    coordination_owners = sorted({*path_owners, *target_owners})
    route["ownership_context"] = {
        "evidence_available": evidence_available,
        "ownership_rules": len(rules),
        "file_records": file_records,
        "boundaries": boundaries,
        "boundary_count": len(boundaries),
        "distinct_owners": path_owners,
        "target_owners": target_owners,
        "coordination_owners": coordination_owners,
        "target_owner_alignment": _target_owner_alignment(
            file_records,
            _path(_object(route.get("target")).get("path")),
            target_owners,
            evidence_available,
        ),
        "unowned_files": unowned,
        "coordination_status": _ownership_coordination_status(
            evidence_available, boundaries, unowned, coordination_owners
        ),
        "recommended_action": _ownership_coordination_action(
            evidence_available, boundaries, unowned, coordination_owners
        ),
        "evidence_artifacts": ["finding-delta.json"] if evidence_available else [],
    }


def _ownership_path_records(
    files: list[str],
    rules: list[tuple[str, list[str]]],
    *,
    entry_path: str | None,
    target_path: str | None,
) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for path in files:
        roles = []
        if path == entry_path:
            roles.append("entry")
        if path == target_path:
            roles.append("target")
        if not roles:
            roles.append("transit")
        result.append(
            {
                "path": path,
                "owners": owners_for_path(path, rules) if rules else [],
                "roles": roles,
            }
        )
    return result


def _target_owner_alignment(
    records: list[dict[str, Any]],
    target_path: str | None,
    target_owners: list[str],
    evidence_available: bool,
) -> str:
    if not evidence_available or not target_path:
        return "not-established"
    path_owners = next(
        (
            _strings(record.get("owners"), 20)
            for record in records
            if record.get("path") == target_path
        ),
        [],
    )
    if not path_owners:
        return "target-unowned"
    if not target_owners:
        return "target-owner-not-attributed"
    return "aligned" if set(path_owners) == set(target_owners) else "mismatch"


def _ownership_coordination_status(
    evidence_available: bool,
    boundaries: list[dict[str, Any]],
    unowned: list[str],
    owners: list[str],
) -> str:
    if not evidence_available:
        return "not-established"
    if unowned:
        return "unowned-segment"
    if boundaries or len(owners) > 1:
        return "cross-owner"
    return "single-owner"


def _ownership_coordination_action(
    evidence_available: bool,
    boundaries: list[dict[str, Any]],
    unowned: list[str],
    owners: list[str],
) -> str:
    if not evidence_available:
        return (
            "Retain bounded CODEOWNERS evidence and rerun route synthesis before "
            "assigning cross-file remediation responsibility."
        )
    if unowned:
        return (
            "Assign CODEOWNERS responsibility for every unowned route file, then "
            "coordinate remediation and validation across the retained handoffs."
        )
    if boundaries or len(owners) > 1:
        return (
            "Coordinate remediation, review, and regression evidence across every "
            "retained ownership handoff before route disposition."
        )
    return "Keep remediation and regression evidence with the retained route owner."


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


def _multi_source_paths(
    entry_points: list[dict[str, Any]], adjacency: dict[str, dict[str, str]]
) -> tuple[
    dict[str, tuple[str, str]],
    dict[str, str],
    dict[str, int],
]:
    parent: dict[str, tuple[str, str]] = {}
    origin: dict[str, str] = {}
    depth: dict[str, int] = {}
    queue: deque[str] = deque()
    for entry in entry_points:
        path = entry["path"]
        if path in origin:
            continue
        origin[path] = entry["id"]
        depth[path] = 0
        queue.append(path)
    while queue:
        source = queue.popleft()
        if depth[source] >= _MAX_ROUTE_HOPS:
            continue
        for target, relation in adjacency.get(source, {}).items():
            if target in origin:
                continue
            origin[target] = origin[source]
            depth[target] = depth[source] + 1
            parent[target] = (source, relation)
            queue.append(target)
    return parent, origin, depth


def _reconstruct_route(
    target: str, parent: dict[str, tuple[str, str]]
) -> tuple[list[str], list[dict[str, str]]]:
    files = [target]
    edges: list[dict[str, str]] = []
    current = target
    while current in parent:
        source, relation = parent[current]
        edges.append({"source": source, "target": current, "relation": relation})
        files.append(source)
        current = source
    files.reverse()
    edges.reverse()
    return files, edges


def _convergence_hotspots(routes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_path: dict[str, list[tuple[dict[str, Any], str]]] = defaultdict(list)
    for route in routes:
        files = route["files"]
        for index, path in enumerate(files):
            if index == 0:
                continue
            role = "target" if index == len(files) - 1 else "transit"
            by_path[path].append((route, role))
    result: list[dict[str, Any]] = []
    for path, observations in by_path.items():
        route_ids = sorted({route["route_id"] for route, _role in observations})
        target_ids = sorted(
            {str(route["target"]["id"]) for route, _role in observations}
        )
        if len(route_ids) < 2 or len(target_ids) < 2:
            continue
        roles = {role for _route, role in observations}
        kind = (
            "target-concentration"
            if roles == {"target"}
            else "shared-transit"
            if roles == {"transit"}
            else "mixed"
        )
        validation_counts = {
            status: sum(
                route["validation"]["assessment_status"] == status
                for route, _role in observations
            )
            for status in ("aligned", "gap", "partial", "not-assessed")
        }
        priorities = sorted(
            {str(route["priority"]) for route, _role in observations},
            key=_priority_rank,
        )
        hotspot_id = (
            "hotspot-" + _digest({"path": path, "routes": route_ids, "kind": kind})[:16]
        )
        result.append(
            {
                "hotspot_id": hotspot_id,
                "path": path,
                "kind": kind,
                "priority": priorities[0] if priorities else "P4",
                "route_ids": route_ids,
                "target_ids": target_ids,
                "finding_ids": sorted(
                    {
                        str(finding_id)
                        for route, _role in observations
                        for finding_id in [
                            route["target"].get("finding_id"),
                            *(
                                _strings(
                                    route["correlations"].get("related_finding_ids"),
                                    100,
                                )
                                if route["target"].get("kind")
                                == "dependency-advisory-import"
                                else []
                            ),
                        ]
                        if finding_id
                    }
                ),
                "entry_point_ids": sorted(
                    {str(route["entry_point"]["id"]) for route, _role in observations}
                ),
                "tools": sorted(
                    {
                        str(tool)
                        for route, _role in observations
                        for tool in route["target"]["tools"]
                    }
                )[:25],
                "target_domains": sorted(
                    {str(route["target"]["domain"]) for route, _role in observations}
                )[:25],
                "security_target_count": sum(
                    route["target"]["domain"] in {"security", "supply-chain"}
                    for route, _role in observations
                ),
                "owners": sorted(
                    {
                        str(owner)
                        for route, _role in observations
                        for owner in route["owners"]
                    }
                )[:20],
                "validation_statuses": validation_counts,
                "mapped_test_files": sorted(
                    {
                        str(test)
                        for route, _role in observations
                        for test in route["validation"]["mapped_test_files"]
                    }
                )[:50],
                "evidence_artifacts": sorted(
                    {
                        str(artifact)
                        for route, _role in observations
                        for artifact in route["evidence_artifacts"]
                    }
                ),
                "recommended_action": _hotspot_action(
                    path, len(route_ids), validation_counts, observations
                ),
            }
        )
    result.sort(
        key=lambda item: (
            _priority_rank(str(item["priority"])),
            -len(item["route_ids"]),
            -len(item["target_ids"]),
            str(item["path"]),
        )
    )
    return result


def _hotspot_action(
    path: str,
    route_count: int,
    validation: dict[str, int],
    observations: list[tuple[dict[str, Any], str]],
) -> str:
    if validation["gap"]:
        return (
            f"Close the {validation['gap']} route validation gap(s) at {path} with "
            "one focused integration-test plan that exercises every affected target."
        )
    if validation["not-assessed"] or validation["partial"]:
        return (
            f"Retain change scope, line coverage, and focused-test execution for all "
            f"{route_count} routes through {path}, then assess them together."
        )
    security_targets = sum(
        route["target"]["domain"] in {"security", "supply-chain"}
        for route, _role in observations
    )
    if security_targets:
        return (
            f"Review {path} as a shared security control point and rerun the mapped "
            "tests for every affected route after remediation."
        )
    return (
        f"Coordinate remediation at {path} and use the shared route set to avoid "
        "duplicated regression testing."
    )


def _validation_campaigns(
    hotspots: list[dict[str, Any]],
    adjacency: dict[str, dict[str, str]],
    artifacts: dict[str, Any],
) -> list[dict[str, Any]]:
    incoming = _reverse_adjacency(adjacency)
    coverage = _campaign_coverage_index(artifacts.get("coverage-summary.json"))
    control_context = _campaign_control_context_index(
        artifacts.get("structural-synthesis.json"),
        artifacts.get("reachability.json"),
    )
    source_sha256, source_files = _campaign_source_index(
        artifacts.get("source-inventory.json")
    )
    test_executions, test_evidence = build_test_execution_index(artifacts)
    campaigns: list[dict[str, Any]] = []
    for hotspot in hotspots:
        path = str(hotspot["path"])
        direct, transitive = _graph_selected_tests(path, incoming)
        route_mapped = sorted(
            {
                _path(value)
                for value in hotspot.get("mapped_test_files", [])
                if _is_test_path(_path(value))
            }
        )[:_MAX_CAMPAIGN_TESTS]
        selected = list(dict.fromkeys([*direct, *transitive, *route_mapped]))[
            :_MAX_CAMPAIGN_TESTS
        ]
        selection_confidence = (
            "high"
            if direct
            else "medium"
            if transitive
            else "context-only"
            if route_mapped
            else "not-available"
        )
        execution = focused_test_execution(
            selected,
            test_executions=test_executions,
            evidence=test_evidence,
        )
        coverage_record = coverage.get(path)
        missing_lines = (
            list(coverage_record["missing_lines"])
            if coverage_record is not None
            else []
        )
        percent = coverage_record.get("percent") if coverage_record else None
        coverage_available = isinstance(percent, (int, float))
        coverage_gap = bool(missing_lines) or (
            isinstance(percent, (int, float)) and float(percent) < 100.0
        )
        coverage_status = (
            "not-available"
            if not coverage_available
            else "gap"
            if coverage_gap
            else "covered"
        )
        alignment = test_coverage_alignment(
            execution,
            coverage_evidence_available=coverage_available,
            coverage_gap=coverage_gap,
            coverage_subject=(
                f"all executable lines in shared control-point file {path}"
            ),
        )
        campaign_id = (
            "campaign-"
            + _digest(
                {
                    "hotspot_id": hotspot["hotspot_id"],
                    "path": path,
                    "selected_tests": selected,
                }
            )[:16]
        )
        evidence_artifacts = sorted(
            {
                *({"graphify.json"} if direct or transitive else set()),
                *({"structural-synthesis.json"} if route_mapped else set()),
                *({"coverage-summary.json"} if coverage_available else set()),
                *test_evidence.get("sources", []),
            }
        )
        snapshot = _campaign_source_snapshot(
            path,
            selected,
            source_sha256=source_sha256,
            source_files=source_files,
            artifacts=artifacts,
            evidence_artifacts=evidence_artifacts,
        )
        context = control_context.get(
            path,
            _empty_campaign_control_context(),
        )
        review = _campaign_review_assessment(
            hotspot,
            execution_status=str(execution["focused_test_validation_status"]),
            test_execution_sources=_strings(
                execution.get("test_execution_sources"), 10
            ),
            coverage_status=coverage_status,
            context=context,
            revision_binding=str(snapshot["evidence_revision_binding"]),
        )
        campaigns.append(
            {
                "campaign_id": campaign_id,
                "hotspot_id": hotspot["hotspot_id"],
                "path": path,
                "priority": hotspot["priority"],
                "owners": list(hotspot["owners"]),
                "route_ids": list(hotspot["route_ids"]),
                "target_ids": list(hotspot["target_ids"]),
                "finding_ids": list(hotspot["finding_ids"]),
                "direct_test_files": direct,
                "transitive_test_files": transitive,
                "route_mapped_test_files": route_mapped,
                "selected_test_files": selected,
                "test_selection_confidence": selection_confidence,
                **execution,
                "coverage_status": coverage_status,
                "coverage_evidence_scope": (
                    "aggregate-retained-file" if coverage_available else "not-available"
                ),
                "coverage_attribution": "not-established",
                "coverage_percent": percent,
                "missing_line_count": (
                    int(coverage_record["missing_line_count"])
                    if coverage_record is not None
                    else 0
                ),
                "missing_lines": missing_lines[:_MAX_CAMPAIGN_MISSING_LINES],
                **alignment,
                "control_point_context": context,
                "source_snapshot": snapshot,
                **review,
                "recommended_action": _campaign_action(
                    str(alignment["test_coverage_alignment"]),
                    selected,
                    path,
                    revision_binding=str(snapshot["evidence_revision_binding"]),
                    context=context,
                ),
                "evidence_artifacts": sorted(
                    {
                        *evidence_artifacts,
                        *context["evidence_artifacts"],
                        *(
                            {"source-inventory.json"}
                            if snapshot["source_inventory_available"]
                            else set()
                        ),
                    }
                ),
                "interpretation": (
                    "Static test selection plus retained execution and coverage "
                    "evidence supports a shared regression plan. Coverage is "
                    "aggregate file evidence and is not attributed solely to the "
                    "selected tests; neither lane proves security, exploitability, "
                    "or complete runtime behavior."
                ),
            }
        )
    return campaigns


def _validation_test_hotspots(
    campaigns: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for campaign in campaigns:
        for path in campaign.get("selected_test_files", [])[:_MAX_CAMPAIGN_TESTS]:
            if isinstance(path, str) and path:
                grouped[path].append(campaign)
    result: list[dict[str, Any]] = []
    for test_path, selected_campaigns in grouped.items():
        campaign_ids = sorted(
            {str(campaign["campaign_id"]) for campaign in selected_campaigns}
        )
        if len(campaign_ids) < 2:
            continue
        execution_records = [
            record
            for campaign in selected_campaigns
            for record in campaign.get("focused_test_execution", [])
            if isinstance(record, dict) and record.get("path") == test_path
        ]
        bindings = [
            binding
            for campaign in selected_campaigns
            for binding in campaign["source_snapshot"].get("selected_test_bindings", [])
            if isinstance(binding, dict) and binding.get("path") == test_path
        ]
        unique_bindings = {
            json.dumps(binding, sort_keys=True, separators=(",", ":")): binding
            for binding in bindings
        }
        binding_consistent = (
            len(bindings) == len(selected_campaigns) and len(unique_bindings) == 1
        )
        source_binding = (
            next(iter(unique_bindings.values())) if len(unique_bindings) == 1 else None
        )
        single_dependency_ids = sorted(
            str(campaign["campaign_id"])
            for campaign in selected_campaigns
            if len(campaign.get("selected_test_files", [])) == 1
        )
        statuses = sorted(
            {
                str(record["status"])
                for record in execution_records
                if isinstance(record.get("status"), str)
            }
        )
        highest_score = max(
            int(campaign["review_score"]) for campaign in selected_campaigns
        )
        hotspot_id = (
            "test-hotspot-"
            + _digest({"path": test_path, "campaign_ids": campaign_ids})[:16]
        )
        result.append(
            {
                "test_hotspot_id": hotspot_id,
                "test_path": test_path,
                "campaign_ids": campaign_ids,
                "control_point_paths": sorted(
                    {str(campaign["path"]) for campaign in selected_campaigns}
                ),
                "route_ids": sorted(
                    {
                        str(route_id)
                        for campaign in selected_campaigns
                        for route_id in campaign["route_ids"]
                    }
                ),
                "target_ids": sorted(
                    {
                        str(target_id)
                        for campaign in selected_campaigns
                        for target_id in campaign["target_ids"]
                    }
                ),
                "finding_ids": sorted(
                    {
                        str(finding_id)
                        for campaign in selected_campaigns
                        for finding_id in campaign["finding_ids"]
                    }
                ),
                "owners": sorted(
                    {
                        str(owner)
                        for campaign in selected_campaigns
                        for owner in campaign["owners"]
                    }
                ),
                "highest_priority": min(
                    (str(campaign["priority"]) for campaign in selected_campaigns),
                    key=_priority_rank,
                ),
                "highest_review_score": highest_score,
                "highest_review_tier": _review_tier(highest_score),
                "direct_campaigns": sum(
                    test_path in campaign["direct_test_files"]
                    for campaign in selected_campaigns
                ),
                "transitive_campaigns": sum(
                    test_path in campaign["transitive_test_files"]
                    for campaign in selected_campaigns
                ),
                "route_mapped_campaigns": sum(
                    test_path in campaign["route_mapped_test_files"]
                    for campaign in selected_campaigns
                ),
                "single_test_dependency_campaign_ids": single_dependency_ids,
                "execution_statuses": statuses,
                "observed_case_count": max(
                    (int(record.get("tests") or 0) for record in execution_records),
                    default=0,
                ),
                "execution_sources": sorted(
                    {
                        str(source)
                        for record in execution_records
                        for source in record.get("sources", [])
                        if isinstance(source, str) and source
                    }
                ),
                "source_binding": source_binding,
                "source_binding_consistent": binding_consistent,
                "recommended_action": _validation_test_hotspot_action(
                    test_path,
                    statuses=statuses,
                    campaigns=len(campaign_ids),
                    controls=len(
                        {str(campaign["path"]) for campaign in selected_campaigns}
                    ),
                    single_dependencies=len(single_dependency_ids),
                    source_binding_consistent=binding_consistent,
                ),
                "evidence_artifacts": sorted(
                    {
                        "graphify.json",
                        *(
                            {"source-inventory.json"}
                            if source_binding is not None
                            else set()
                        ),
                        *(
                            str(artifact)
                            for campaign in selected_campaigns
                            for artifact in campaign["evidence_artifacts"]
                        ),
                    }
                ),
                "interpretation": (
                    "This record identifies one test file selected for multiple "
                    "shared-control campaigns. Repeated selection supports coordinated "
                    "validation planning but does not establish independent assertions, "
                    "test quality, or sufficient behavioral coverage."
                ),
            }
        )
    result.sort(
        key=lambda item: (
            -int(item["highest_review_score"]),
            -len(item["campaign_ids"]),
            str(item["test_path"]),
        )
    )
    return result


def _validation_test_hotspot_action(
    test_path: str,
    *,
    statuses: list[str],
    campaigns: int,
    controls: int,
    single_dependencies: int,
    source_binding_consistent: bool,
) -> str:
    if not source_binding_consistent:
        return (
            f"Regenerate and source-bind {test_path}; complete consistent source "
            "identity is not established across its selected campaigns."
        )
    if "failed" in statuses:
        return f"Resolve failures in {test_path} before using it across {campaigns} shared-control campaigns."
    if "not-observed" in statuses or not statuses:
        return f"Execute {test_path} and retain case-level evidence before relying on it across {controls} controls."
    action = (
        f"Coordinate assertions and fixtures in {test_path} across {campaigns} "
        f"campaigns and {controls} shared controls."
    )
    if single_dependencies:
        action += (
            f" Add an independent focused test for {single_dependencies} campaign(s) "
            "that currently depend on this test alone."
        )
    return action


def _reverse_adjacency(
    adjacency: dict[str, dict[str, str]],
) -> dict[str, set[str]]:
    incoming: dict[str, set[str]] = defaultdict(set)
    for source, targets in adjacency.items():
        for target in targets:
            incoming[target].add(source)
    return incoming


def _graph_selected_tests(
    path: str, incoming: dict[str, set[str]]
) -> tuple[list[str], list[str]]:
    direct = sorted(
        candidate for candidate in incoming.get(path, set()) if _is_test_path(candidate)
    )[:_MAX_CAMPAIGN_TESTS]
    visited = {path}
    queue = deque([(path, 0)])
    transitive: set[str] = set()
    examined = 0
    while queue and examined < _MAX_TEST_GRAPH_NEIGHBORS:
        current, depth = queue.popleft()
        if depth >= 2:
            continue
        for candidate in sorted(incoming.get(current, set())):
            if candidate in visited:
                continue
            visited.add(candidate)
            examined += 1
            if _is_test_path(candidate):
                if candidate not in direct:
                    transitive.add(candidate)
            else:
                queue.append((candidate, depth + 1))
            if examined >= _MAX_TEST_GRAPH_NEIGHBORS:
                break
    return direct, sorted(transitive)[:_MAX_CAMPAIGN_TESTS]


def _campaign_coverage_index(value: Any) -> dict[str, dict[str, Any]]:
    files = value.get("files") if isinstance(value, dict) else None
    if not isinstance(files, list):
        return {}
    result: dict[str, dict[str, Any]] = {}
    for item in files[:_MAX_GRAPH_FILES]:
        if not isinstance(item, dict):
            continue
        path = _path(item.get("path"))
        if not path:
            continue
        summary = item.get("summary")
        percent = (
            _optional_number(summary.get("percent_covered"))
            if isinstance(summary, dict)
            else None
        )
        raw_missing = item.get("missing_lines")
        missing = (
            sorted(
                {
                    line
                    for line in raw_missing
                    if isinstance(line, int) and not isinstance(line, bool) and line > 0
                }
            )
            if isinstance(raw_missing, list)
            else []
        )
        result[path] = {
            "percent": percent,
            "missing_line_count": len(missing),
            "missing_lines": missing,
        }
    return result


def _campaign_control_context_index(
    structural_value: Any, reachability_value: Any
) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    assessments = (
        structural_value.get("finding_assessments")
        if isinstance(structural_value, dict)
        else None
    )
    if isinstance(assessments, list):
        for item in assessments[:_MAX_GRAPH_FILES]:
            if not isinstance(item, dict) or not (path := _path(item.get("path"))):
                continue
            degree = item.get("degree")
            complexity = item.get("maximum_complexity")
            record = result.setdefault(path, _empty_campaign_control_context())
            record.update(
                {
                    "graph_degree": _nonnegative_integer(degree),
                    "maximum_complexity": _nonnegative_integer(complexity),
                    "maximum_complexity_rank": _optional_string(
                        item.get("maximum_complexity_rank")
                    ),
                    "reachability_states": _strings(
                        item.get("reachability_states"), 10
                    ),
                    "evidence_artifacts": ["structural-synthesis.json"],
                }
            )
    changes = (
        structural_value.get("change_impact_assessments")
        if isinstance(structural_value, dict)
        else None
    )
    if isinstance(changes, list):
        for item in changes[:_MAX_GRAPH_FILES]:
            if not isinstance(item, dict) or not (path := _path(item.get("path"))):
                continue
            risk_score = _nonnegative_integer(item.get("risk_score"))
            record = result.setdefault(path, _empty_campaign_control_context())
            current_score = record.get("change_risk_score")
            if risk_score is None or (
                isinstance(current_score, int) and current_score > risk_score
            ):
                continue
            uncovered = sorted(
                {
                    line
                    for line in item.get("uncovered_changed_lines", [])
                    if isinstance(line, int) and not isinstance(line, bool) and line > 0
                }
            )[:_MAX_CAMPAIGN_MISSING_LINES]
            record.update(
                {
                    "change_risk_score": risk_score,
                    "change_priority": _optional_string(item.get("priority")),
                    "change_classification": _optional_string(
                        item.get("classification")
                    ),
                    "changed_lines": _nonnegative_integer(item.get("changed_lines")),
                    "uncovered_changed_lines": uncovered,
                    "changed_line_coverage_percent": _optional_number(
                        item.get("changed_line_coverage_percent")
                    ),
                    "evidence_artifacts": sorted(
                        {*record["evidence_artifacts"], "structural-synthesis.json"}
                    ),
                }
            )
    nodes = (
        reachability_value.get("nodes")
        if isinstance(reachability_value, dict)
        else None
    )
    runtime_by_path: dict[str, set[str]] = defaultdict(set)
    states_by_path: dict[str, set[str]] = defaultdict(set)
    if isinstance(nodes, list):
        for node in nodes[:_MAX_GRAPH_FILES]:
            if not isinstance(node, dict) or not (path := _path(node.get("path"))):
                continue
            observation = node.get("runtime_observation")
            state = node.get("state")
            if isinstance(observation, str) and observation:
                runtime_by_path[path].add(observation[:1000])
            if isinstance(state, str) and state:
                states_by_path[path].add(state[:1000])
    for path in sorted(set(runtime_by_path) | set(states_by_path)):
        record = result.setdefault(
            path,
            _empty_campaign_control_context(),
        )
        record["reachability_states"] = sorted(
            set(record["reachability_states"]) | states_by_path[path]
        )[:10]
        record["runtime_observations"] = sorted(runtime_by_path[path])[:10]
        record["evidence_artifacts"] = sorted(
            {*record["evidence_artifacts"], "reachability.json"}
        )
    return result


def _empty_campaign_control_context() -> dict[str, Any]:
    return {
        "graph_degree": None,
        "maximum_complexity": None,
        "maximum_complexity_rank": None,
        "change_risk_score": None,
        "change_priority": None,
        "change_classification": None,
        "changed_lines": None,
        "uncovered_changed_lines": [],
        "changed_line_coverage_percent": None,
        "reachability_states": [],
        "runtime_observations": [],
        "evidence_artifacts": [],
    }


def _campaign_source_index(
    value: Any,
) -> tuple[str | None, dict[str, dict[str, Any]]]:
    if not isinstance(value, dict) or value.get("schema_version") != "1.0":
        return None, {}
    aggregate = value.get("source_sha256")
    files = value.get("files")
    if not _is_digest(aggregate) or not isinstance(files, list):
        return None, {}
    result: dict[str, dict[str, Any]] = {}
    for item in files[:_MAX_GRAPH_FILES]:
        if not isinstance(item, dict) or not (path := _path(item.get("path"))):
            continue
        digest = item.get("sha256")
        size = item.get("size_bytes")
        if (
            not _is_digest(digest)
            or not isinstance(size, int)
            or isinstance(size, bool)
            or size < 0
        ):
            continue
        result[path] = {"path": path, "sha256": digest, "size_bytes": size}
    return str(aggregate), result


def _campaign_source_snapshot(
    path: str,
    selected: list[str],
    *,
    source_sha256: str | None,
    source_files: dict[str, dict[str, Any]],
    artifacts: dict[str, Any],
    evidence_artifacts: list[str],
) -> dict[str, Any]:
    selected_bindings = [
        source_files[test] for test in selected if test in source_files
    ]
    missing = [test for test in selected if test not in source_files]
    evidence_names = [
        name
        for name in evidence_artifacts
        if name == "coverage-summary.json" or name in TEST_EVIDENCE_ARTIFACTS
    ]
    evidence_bindings: list[dict[str, Any]] = []
    for name in evidence_names:
        evidence_bindings.append(
            _campaign_evidence_source_binding(
                name,
                artifacts.get(name),
                source_sha256=source_sha256,
            )
        )
    revision_binding = (
        "not-applicable"
        if not evidence_bindings
        else "mismatch"
        if any(item["status"] == "mismatch" for item in evidence_bindings)
        else "unverified"
        if any(item["status"] == "unverified" for item in evidence_bindings)
        else "aligned"
        if evidence_bindings
        and all(item["status"] == "aligned" for item in evidence_bindings)
        else "not-established"
    )
    reason = {
        "not-applicable": "No retained case or coverage evidence requires a source-revision binding.",
        "mismatch": "At least one retained case or coverage artifact declares a different source snapshot.",
        "unverified": "At least one retained case or coverage artifact declares the sealed source digest without a valid producer-verified payload-binding receipt.",
        "aligned": "Every retained case and coverage artifact declares the sealed source-inventory digest.",
        "not-established": "Retained case or coverage evidence does not completely declare the sealed source-inventory digest.",
    }[revision_binding]
    return {
        "source_inventory_available": source_sha256 is not None,
        "source_sha256": source_sha256,
        "control_point_binding": source_files.get(path),
        "selected_test_bindings": selected_bindings,
        "selected_test_files_bound": len(selected_bindings),
        "selected_test_files_missing": missing,
        "evidence_revision_binding": revision_binding,
        "evidence_revision_binding_reason": reason,
        "evidence_source_bindings": evidence_bindings,
    }


def _campaign_evidence_source_binding(
    name: str,
    value: Any,
    *,
    source_sha256: str | None,
) -> dict[str, Any]:
    document = _object(value)
    declared = document.get("source_sha256")
    binding = _object(document.get("evidence_binding"))
    evidence_sha256 = binding.get("evidence_sha256")
    binding_file = binding.get("binding_file")
    binding_verified = (
        binding.get("verified") is True
        and binding.get("schema_version") == "1.0"
        and _is_digest(evidence_sha256)
        and isinstance(binding_file, str)
        and bool(binding_file.strip())
    )
    status = (
        "no-source-inventory"
        if source_sha256 is None
        else "not-declared"
        if not _is_digest(declared)
        else "mismatch"
        if declared != source_sha256
        else "aligned"
        if binding_verified
        else "unverified"
    )
    return {
        "artifact": name,
        "declared_source_sha256": str(declared) if _is_digest(declared) else None,
        "binding_verified": binding_verified,
        "evidence_sha256": (
            str(evidence_sha256) if _is_digest(evidence_sha256) else None
        ),
        "binding_file": (
            str(binding_file)[:1000]
            if isinstance(binding_file, str) and binding_file.strip()
            else None
        ),
        "status": status,
    }


def _campaign_review_assessment(
    hotspot: dict[str, Any],
    *,
    execution_status: str,
    test_execution_sources: list[str],
    coverage_status: str,
    context: dict[str, Any],
    revision_binding: str,
) -> dict[str, Any]:
    factors: list[dict[str, Any]] = []

    def add(identifier: str, points: int, evidence: str, artifacts: list[str]) -> None:
        if points > 0:
            factors.append(
                {
                    "id": identifier,
                    "points": points,
                    "evidence": evidence,
                    "evidence_artifacts": artifacts,
                }
            )

    priority = str(hotspot.get("priority") or "P4")
    priority_points = {"P0": 40, "P1": 32, "P2": 24, "P3": 12, "P4": 4}.get(priority, 4)
    add(
        "highest-route-priority",
        priority_points,
        f"Highest converging route priority is {priority}.",
        ["findings.json", "risk-paths.json"],
    )
    route_count = len(hotspot.get("route_ids") or [])
    add(
        "route-convergence",
        min(20, max(0, route_count - 1) * 4),
        f"{route_count} distinct routes cross this control point.",
        ["graphify.json", "risk-paths.json"],
    )
    target_count = len(hotspot.get("target_ids") or [])
    add(
        "target-concentration",
        min(10, max(0, target_count - 1) * 2),
        f"{target_count} distinct review targets share this control point.",
        ["findings.json", "risk-paths.json"],
    )
    security_targets = int(hotspot.get("security_target_count") or 0)
    add(
        "security-targets",
        min(20, security_targets * 5),
        f"{security_targets} security or supply-chain target(s) converge here.",
        ["findings.json"],
    )
    tool_count = len(hotspot.get("tools") or [])
    add(
        "tool-diversity",
        min(6, max(0, tool_count - 1) * 2),
        f"{tool_count} distinct tools contribute target evidence.",
        ["findings.json"],
    )
    if coverage_status == "gap":
        add(
            "coverage-gap",
            10,
            "The shared control-point file has uncovered executable lines.",
            ["coverage-summary.json"],
        )
    elif coverage_status == "not-available":
        add(
            "coverage-unavailable",
            6,
            "File coverage is unavailable for the shared control point.",
            [],
        )
    execution_points = {
        "failed": 20,
        "not-selected": 12,
        "not-observed": 10,
        "incomplete": 8,
        "not-available": 8,
    }.get(execution_status, 0)
    add(
        "focused-test-state",
        execution_points,
        f"Focused test execution state is {execution_status}.",
        test_execution_sources,
    )
    change_risk = context.get("change_risk_score")
    change_points = (
        15
        if isinstance(change_risk, int) and change_risk >= 75
        else 10
        if isinstance(change_risk, int) and change_risk >= 50
        else 5
        if isinstance(change_risk, int) and change_risk > 0
        else 0
    )
    add(
        "changed-control-risk",
        change_points,
        "Changed shared control point has structural risk score "
        f"{change_risk} ({context.get('change_priority') or 'unclassified'}).",
        ["diff-coverage.json", "structural-synthesis.json"],
    )
    uncovered_changed = context.get("uncovered_changed_lines")
    uncovered_changed = uncovered_changed if isinstance(uncovered_changed, list) else []
    add(
        "uncovered-changed-lines",
        12 if uncovered_changed else 0,
        f"{len(uncovered_changed)} changed executable line(s) are uncovered: "
        + ", ".join(str(line) for line in uncovered_changed[:10])
        + ("." if len(uncovered_changed) <= 10 else ", …"),
        ["diff-coverage.json", "structural-synthesis.json"],
    )
    observations = set(_strings(context.get("runtime_observations"), 10))
    runtime_points = (
        0
        if "observed" in observations
        else 6
        if "not-observed" in observations
        else 4
        if observations & {"not-measured", "unknown"} or not observations
        else 0
    )
    add(
        "runtime-observation-gap",
        runtime_points,
        "Shared control point runtime state is "
        + (", ".join(sorted(observations)) if observations else "not available")
        + ".",
        (
            ["reachability.json"]
            if "reachability.json" in context.get("evidence_artifacts", [])
            else []
        ),
    )
    complexity = context.get("maximum_complexity")
    complexity_points = (
        15
        if isinstance(complexity, int) and complexity >= 30
        else 10
        if isinstance(complexity, int) and complexity >= 20
        else 0
    )
    add(
        "control-point-complexity",
        complexity_points,
        f"Maximum retained cyclomatic complexity is {complexity}.",
        ["structural-synthesis.json"],
    )
    degree = context.get("graph_degree")
    degree_points = (
        10
        if isinstance(degree, int) and degree >= 100
        else 5
        if isinstance(degree, int) and degree >= 25
        else 0
    )
    add(
        "graph-centrality",
        degree_points,
        f"Graph degree is {degree}.",
        ["graphify.json", "structural-synthesis.json"],
    )
    if not hotspot.get("owners"):
        add(
            "unassigned-owner",
            5,
            "No owner is assigned to the shared control point.",
            ["finding-delta.json"],
        )
    if revision_binding == "mismatch":
        add(
            "evidence-revision-mismatch",
            20,
            "Retained test or coverage evidence declares a different source snapshot.",
            ["source-inventory.json"],
        )
    elif revision_binding == "unverified":
        add(
            "evidence-binding-unverified",
            15,
            "Retained test or coverage evidence declares the sealed source digest without a valid producer-verified payload-binding receipt.",
            ["source-inventory.json"],
        )
    elif revision_binding == "not-established":
        add(
            "evidence-revision-unbound",
            5,
            "Retained test or coverage evidence is not fully bound to the sealed source snapshot.",
            ["source-inventory.json"],
        )
    score = min(100, sum(int(factor["points"]) for factor in factors))
    tier = _review_tier(score)
    return {
        "review_score_model": "shared-control-review-v3",
        "review_score": score,
        "review_tier": tier,
        "review_factors": factors,
    }


def _review_tier(score: int) -> str:
    return (
        "critical"
        if score >= 80
        else "high"
        if score >= 60
        else "medium"
        if score >= 35
        else "low"
    )


def _campaign_action(
    alignment: str,
    selected: list[str],
    path: str,
    *,
    revision_binding: str,
    context: dict[str, Any],
) -> str:
    tests = ", ".join(selected[:5])
    if alignment == "aligned-current-evidence":
        action = (
            f"Retain the passing focused-test and complete file-coverage evidence "
            f"for {path}; rerun the campaign after shared-control changes."
        )
    elif alignment == "coverage-gap":
        action = (
            f"Extend the passing selected tests until uncovered executable lines in "
            f"{path} are covered, then regenerate case and coverage evidence."
        )
    elif alignment == "tests-failing":
        action = "Resolve failing or errored selected tests before accepting this shared change."
    elif alignment == "tests-not-observed":
        action = "Run the selected tests and retain case-level evidence" + (
            f": {tests}." if tests else "."
        )
    elif alignment == "tests-incomplete":
        action = "Complete or explain skipped and unobserved selected tests, then retain a complete case inventory."
    elif alignment == "test-evidence-not-available":
        action = "Produce bounded case-level test evidence for the selected files" + (
            f": {tests}." if tests else "."
        )
    elif alignment == "coverage-not-available":
        action = f"Produce line coverage for {path} from the selected-test campaign."
    else:
        action = f"Add a focused test that reaches shared control point {path}, then retain execution and coverage evidence."
    uncovered_changed = context.get("uncovered_changed_lines")
    if isinstance(uncovered_changed, list) and uncovered_changed:
        lines = ", ".join(str(line) for line in uncovered_changed[:10])
        action += f" Prioritize uncovered changed line(s) {lines} in {path}."
    observations = set(_strings(context.get("runtime_observations"), 10))
    if "observed" not in observations and observations & {
        "not-observed",
        "not-measured",
        "unknown",
    }:
        action += " Retain runtime coverage that exercises this control point."
    if revision_binding in {"mismatch", "unverified"}:
        return (
            "Discard mismatched or unverified test/coverage evidence and regenerate "
            "it with a verified payload binding against the sealed source snapshot. "
            + action
        )
    if revision_binding == "not-established":
        return (
            action
            + " Bind the regenerated evidence to the sealed source-inventory digest."
        )
    return action


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
    parts = [
        (
            shared_test_hotspots,
            f"Coordinate {shared_test_hotspots} shared validation-test hotspot(s).",
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


def _attach_finding_routes(
    findings: list[Finding],
    routed: dict[str, dict[str, Any]],
    all_routed: list[dict[str, Any]],
    unrouted: list[dict[str, Any]],
    validation_campaigns: list[dict[str, Any]],
    exposure_advisory_intersections: list[dict[str, Any]],
) -> None:
    campaigns_by_id = {
        str(campaign["campaign_id"]): campaign for campaign in validation_campaigns
    }
    unrouted_by_id = {
        item["target"]["finding_id"]: item
        for item in unrouted
        if item["target"].get("finding_id")
    }
    advisory_routes_by_finding: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for candidate_route in all_routed:
        if candidate_route["target"].get("kind") != "dependency-advisory-import":
            continue
        for finding_id in _strings(
            candidate_route["correlations"].get("related_finding_ids"), 100
        ):
            advisory_routes_by_finding[finding_id].append(candidate_route)
    intersections_by_finding: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for intersection in exposure_advisory_intersections:
        for finding_id in _strings(intersection.get("finding_ids"), 100):
            intersections_by_finding[finding_id].append(intersection)
    for finding in findings:
        advisory_routes = sorted(
            advisory_routes_by_finding.get(finding.finding_id, []),
            key=_route_order,
        )[:_MAX_FINDING_ADVISORY_ROUTES]
        route = routed.get(finding.finding_id) or (
            advisory_routes[0] if advisory_routes else None
        )
        finding_intersections = sorted(
            intersections_by_finding.get(finding.finding_id, []),
            key=lambda item: (
                _priority_rank(str(item["priority"])),
                str(item["intersection_id"]),
            ),
        )[:25]
        if route is not None:
            lifecycle_attribution = _object(
                route.get("change_lifecycle_attribution")
            ) or _object(
                _object(unrouted_by_id.get(finding.finding_id)).get(
                    "change_lifecycle_attribution"
                )
            )
            context = {
                "status": "routed",
                "route_id": route["route_id"],
                "target_kind": route["target"]["kind"],
                "target_id": route["target"]["id"],
                "priority": route["priority"],
                "entry_point": route["entry_point"],
                "entry_point_exposure_count": route["entry_point_exposure_count"],
                "entry_point_exposures": route["entry_point_exposures"],
                "entry_point_exposures_omitted": route["entry_point_exposures_omitted"],
                "entry_point_kinds": route["entry_point_kinds"],
                "hop_count": route["hop_count"],
                "files": route["files"],
                "runtime_context": route["runtime_context"],
                "validation": route["validation"],
                "evidence_assurance": route["evidence_assurance"],
                "ownership_context": route["ownership_context"],
                "change_lifecycle_attribution": lifecycle_attribution,
                "convergence_hotspot_ids": route["convergence_hotspot_ids"],
                "validation_campaign_ids": route["validation_campaign_ids"],
                "validation_test_hotspot_ids": route["validation_test_hotspot_ids"],
                "exposure_advisory_intersection_ids": sorted(
                    {
                        *_strings(route.get("exposure_advisory_intersection_ids"), 100),
                        *(
                            str(item["intersection_id"])
                            for item in finding_intersections
                        ),
                    }
                ),
                "exposure_advisory_intersections": [
                    _compact_exposure_advisory_intersection(item)
                    for item in finding_intersections
                ],
                "validation_campaigns": [
                    {
                        key: campaign[key]
                        for key in (
                            "campaign_id",
                            "hotspot_id",
                            "path",
                            "selected_test_files",
                            "shared_test_hotspot_ids",
                            "focused_test_validation_status",
                            "coverage_status",
                            "coverage_evidence_scope",
                            "coverage_attribution",
                            "coverage_percent",
                            "test_coverage_alignment",
                            "validation_gap_reasons",
                            "control_point_context",
                            "source_snapshot",
                            "review_score_model",
                            "review_score",
                            "review_tier",
                            "review_factors",
                            "recommended_action",
                        )
                    }
                    for campaign_id in route["validation_campaign_ids"]
                    if (campaign := campaigns_by_id.get(campaign_id)) is not None
                ],
                "recommended_action": route["recommended_action"],
                "evidence_artifact": "risk-paths.json",
            }
            if advisory_routes:
                context.update(
                    {
                        "dependency_advisory_route_ids": [
                            str(item["route_id"]) for item in advisory_routes
                        ],
                        "dependency_advisory_import_paths": sorted(
                            {str(item["target"]["path"]) for item in advisory_routes}
                        ),
                        "dependency_advisory_cluster_ids": sorted(
                            {
                                str(item["correlations"]["advisory_cluster_id"])
                                for item in advisory_routes
                            }
                        ),
                        "dependency_advisory_routes": [
                            _compact_dependency_advisory_route(item)
                            for item in advisory_routes
                        ],
                    }
                )
            finding.evidence["risk_path"] = context
            _add_route_citations(finding)
        elif finding.finding_id in unrouted_by_id:
            record = unrouted_by_id[finding.finding_id]
            finding.evidence["risk_path"] = {
                "status": "unrouted",
                "reason": record["reason"],
                "evidence_assurance": record["evidence_assurance"],
                "change_lifecycle_attribution": _object(
                    record.get("change_lifecycle_attribution")
                ),
                "evidence_artifact": "risk-paths.json",
            }
            _add_route_citations(finding)


def _compact_dependency_advisory_route(
    route: dict[str, Any],
) -> dict[str, Any]:
    correlations = route["correlations"]
    target = route["target"]
    return {
        "route_id": route["route_id"],
        "target_id": target["id"],
        "priority": route["priority"],
        "advisory_cluster_id": correlations.get("advisory_cluster_id"),
        "primary_identifier": correlations.get("primary_identifier"),
        "package": correlations.get("package"),
        "versions": list(correlations.get("versions") or [])[:25],
        "import_path": target["path"],
        "import_modules": list(correlations.get("import_modules") or [])[:50],
        "import_lines": list(correlations.get("import_lines") or [])[:100],
        "dependency_usage_assessment": correlations.get("dependency_usage_assessment"),
        "import_path_assessment": correlations.get("import_path_assessment"),
        "entry_point": route["entry_point"],
        "entry_point_exposure_count": route["entry_point_exposure_count"],
        "entry_point_exposures": list(route["entry_point_exposures"]),
        "entry_point_exposures_omitted": route["entry_point_exposures_omitted"],
        "entry_point_kinds": list(route["entry_point_kinds"]),
        "entry_point_runtime_statuses": _entry_runtime_counts(
            route["entry_point_exposures"]
        ),
        "hop_count": route["hop_count"],
        "files": list(route["files"]),
        "runtime_context": route["runtime_context"],
        "validation": route["validation"],
        "evidence_assurance": route["evidence_assurance"],
        "ownership_context": route["ownership_context"],
        "validation_campaign_ids": list(route["validation_campaign_ids"]),
        "exposure_advisory_intersection_ids": list(
            route.get("exposure_advisory_intersection_ids") or []
        )[:100],
        "known_exploited": correlations.get("known_exploited") is True,
        "epss_probability": correlations.get("epss_probability"),
        "fix_available": correlations.get("fix_available") is True,
        "fixed_version_candidates": list(
            correlations.get("fixed_version_candidates") or []
        )[:25],
        "package_lifecycle": _object(correlations.get("package_lifecycle")),
        "change_risk_score": correlations.get("change_risk_score"),
        "change_priority": correlations.get("change_priority"),
        "uncovered_changed_lines": list(
            correlations.get("uncovered_changed_lines") or []
        )[:_MAX_CAMPAIGN_MISSING_LINES],
        "advisory_citations": list(correlations.get("advisory_citations") or [])[:25],
        "recommended_action": route["recommended_action"],
    }


def _compact_exposure_advisory_intersection(
    value: dict[str, Any],
) -> dict[str, Any]:
    return {
        key: value[key]
        for key in (
            "intersection_id",
            "priority",
            "path",
            "line",
            "sink_route_id",
            "dependency_route_id",
            "advisory_cluster_id",
            "primary_identifier",
            "package",
            "sdk",
            "sink_family",
            "trust_boundary",
            "data_classes",
            "protection_status",
            "known_exploited",
            "epss_high",
            "fix_available",
            "package_lifecycle",
            "entry_point_exposure_ids",
            "entry_point_ids",
            "entry_point_exposure_count",
            "entry_point_exposures_omitted",
            "entry_point_runtime_statuses",
            "evidence_assurance_statuses",
            "validation_statuses",
            "advisory_citations",
            "recommended_action",
        )
    }


def _add_route_citations(finding: Finding) -> None:
    existing = {citation.identifier for citation in finding.citations}
    for identifier, title, uri in (
        (
            "pysec-static-risk-route",
            "Suite bounded static risk-route synthesis",
            _RISK_PATH_REFERENCE,
        ),
        (
            "graphify-code-graph",
            "Graphify deterministic code graph context",
            _GRAPHIFY_REFERENCE,
        ),
    ):
        if identifier not in existing:
            finding.citations.append(
                Citation(
                    kind="supporting_evidence",
                    identifier=identifier,
                    title=title,
                    uri=uri,
                )
            )


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


def _tool_posture_index(value: Any) -> dict[str, dict[str, Any]]:
    raw = value.get("tool_posture") if isinstance(value, dict) else None
    records = raw if isinstance(raw, list) else []
    result: dict[str, dict[str, Any]] = {}
    for item in records[:500]:
        if not isinstance(item, dict):
            continue
        tool = _optional_string(item.get("tool"))
        status = _optional_string(item.get("status"))
        assurance = _optional_string(item.get("assurance_status"))
        if (
            not tool
            or status not in _TOOL_RUN_STATUSES
            or assurance not in _TOOL_ASSURANCE_STATUSES
        ):
            continue
        result[tool] = {
            "tool": tool,
            "status": status,
            "applicable": item.get("applicable") is True,
            "evidence_lane": str(item.get("evidence_lane") or "other")[:100],
            "normalized_findings": _nonnegative_integer(item.get("normalized_findings"))
            or 0,
            "unique_normalized_findings": _nonnegative_integer(
                item.get("unique_normalized_findings")
            )
            or 0,
            "executable_integrity_verified": _optional_boolean(
                item.get("executable_integrity_verified")
            ),
            "executable_organization_approved": (
                item.get("executable_organization_approved") is True
            ),
            "executable_unchanged": _optional_boolean(item.get("executable_unchanged")),
            "auxiliary_executable_present": (
                item.get("auxiliary_executable_present") is True
            ),
            "auxiliary_executable_integrity_verified": _optional_boolean(
                item.get("auxiliary_executable_integrity_verified")
            ),
            "auxiliary_executable_organization_approved": _optional_boolean(
                item.get("auxiliary_executable_organization_approved")
            ),
            "auxiliary_executable_unchanged": _optional_boolean(
                item.get("auxiliary_executable_unchanged")
            ),
            "assurance_status": assurance,
        }
    return result


def _target_evidence_assurance(
    target: dict[str, Any], posture: dict[str, dict[str, Any]]
) -> dict[str, Any]:
    origin = {
        "finding": "scanner-finding",
        "dependency-advisory-import": "dependency-advisory-fusion",
        "sink-surface": "derived-analysis",
    }.get(str(target.get("kind")), "derived-analysis")
    contributing = sorted(set(_strings(target.get("tools"), 25)))
    correlations = _object(target.get("correlations"))
    supporting = sorted(
        set(_strings(correlations.get("related_tools"), 25)) - set(contributing)
    )
    external_contributors = [
        tool for tool in contributing if not tool.startswith("pysec-")
    ]
    assessed_tools = (
        sorted(set(supporting)) if origin == "derived-analysis" else contributing
    )
    records = [posture[tool] for tool in assessed_tools if tool in posture]
    unassessed = sorted(set(assessed_tools) - set(posture))
    completed = sorted(
        str(record["tool"]) for record in records if record["status"] == "completed"
    )
    approved = sorted(
        str(record["tool"])
        for record in records
        if record["assurance_status"] == "approved"
    )
    execution_gaps = sorted(
        str(record["tool"])
        for record in records
        if record["assurance_status"] in {"execution-gap", "not-applicable"}
    )
    trust_gaps = sorted(
        str(record["tool"])
        for record in records
        if record["assurance_status"]
        in {"approval-gap", "integrity-gap", "not-established"}
    )
    corroboration = _optional_string(correlations.get("corroboration"))
    perspective = _perspective_assessment(origin, external_contributors, corroboration)
    review_status = _evidence_review_status(
        origin=origin,
        perspective=perspective,
        assessed_tools=assessed_tools,
        unassessed=unassessed,
        execution_gaps=execution_gaps,
        trust_gaps=trust_gaps,
    )
    return {
        "review_status": review_status,
        "origin": origin,
        "perspective_assessment": perspective,
        "corroboration": corroboration,
        "contributing_tools": contributing,
        "supporting_tools": supporting,
        "evidence_lanes": sorted({str(record["evidence_lane"]) for record in records}),
        "tool_records": records,
        "completed_tools": completed,
        "approved_tools": approved,
        "trust_gap_tools": trust_gaps,
        "execution_gap_tools": execution_gaps,
        "unassessed_tools": unassessed,
        "recommended_action": _evidence_assurance_action(
            review_status, trust_gaps, execution_gaps, unassessed
        ),
        "evidence_artifacts": (
            ["effectiveness.json", "scanner-trust.json"] if records else []
        ),
    }


def _perspective_assessment(
    origin: str, contributing_tools: list[str], corroboration: str | None
) -> str:
    if corroboration in {"independent", "cross-stage"}:
        return "independent-corroboration"
    if len(contributing_tools) > 1:
        return "multi-tool"
    if len(contributing_tools) == 1:
        return "single-tool"
    if origin == "derived-analysis":
        return "derived-analysis"
    return "not-established"


def _evidence_review_status(
    *,
    origin: str,
    perspective: str,
    assessed_tools: list[str],
    unassessed: list[str],
    execution_gaps: list[str],
    trust_gaps: list[str],
) -> str:
    if unassessed or (origin != "derived-analysis" and not assessed_tools):
        return "not-assessed"
    if execution_gaps:
        return "execution-gap"
    if trust_gaps:
        return "trust-gap"
    if origin == "derived-analysis":
        return "derived-analysis"
    if perspective in {"single-tool", "not-established"}:
        return "perspective-gap"
    return "assured"


def _evidence_assurance_action(
    status: str,
    trust_gaps: list[str],
    execution_gaps: list[str],
    unassessed: list[str],
) -> str:
    if status == "execution-gap":
        return (
            "Complete the contributing scanner run(s) and retain normalized evidence: "
            + ", ".join(execution_gaps[:10])
            + "."
        )
    if status == "trust-gap":
        return (
            "Verify executable integrity and obtain organization approval for the "
            "contributing scanner binding(s): " + ", ".join(trust_gaps[:10]) + "."
        )
    if status == "not-assessed":
        return (
            "Retain completion and scanner-identity evidence for the contributing "
            "tool(s): " + ", ".join(unassessed[:10] or ["unknown"]) + "."
        )
    if status == "perspective-gap":
        return (
            "Validate the target with an independent applicable technique or record "
            "why the single retained scanner perspective is sufficient."
        )
    if status == "derived-analysis":
        return (
            "Review the suite-derived correlation against its cited source evidence; "
            "do not treat derived analysis as an independent scanner observation."
        )
    return "Preserve the approved multi-perspective evidence and rerun it after remediation."


def _empty_evidence_assurance(target: dict[str, Any]) -> dict[str, Any]:
    return _target_evidence_assurance(target, {})


def _finding_correlations(
    finding: Finding,
    fusion: dict[str, Any],
    structural: dict[str, Any],
) -> dict[str, Any]:
    island = _object(structural.get("island"))
    cycle = _object(structural.get("import_cycle"))
    advisory = _object(fusion.get("advisory_context"))
    return {
        "related_finding_ids": _strings(fusion.get("related_finding_ids"), 50),
        "related_tools": _strings(fusion.get("related_tools"), 25),
        "review_tier": _optional_string(fusion.get("review_tier")),
        "review_reasons": _strings(fusion.get("review_reasons"), 20),
        "corroboration": _optional_string(fusion.get("corroboration")),
        "island_id": _optional_string(island.get("island_id")),
        "import_cycle_id": _optional_string(cycle.get("cycle_id")),
        "advisory_cluster_id": _optional_string(advisory.get("cluster_id")),
        "known_exploited": bool(
            _object(finding.evidence.get("risk_intelligence")).get("known_exploited")
        ),
    }


def _finding_evidence_artifacts(
    finding: Finding,
    fusion: dict[str, Any],
    structural: dict[str, Any],
    exposure: dict[str, Any],
) -> list[str]:
    names = {"findings.json"}
    if fusion:
        names.add("evidence-fusion.json")
    if structural:
        names.add("structural-synthesis.json")
    if exposure:
        names.add("data-exposure.json")
    graph = finding.evidence.get("graph_context")
    if isinstance(graph, dict):
        names.add("graph-analysis.json")
    return sorted(names)


def _recommended_action(
    remediation: str, validation: dict[str, Any], exposure: dict[str, Any]
) -> str:
    if exposure:
        protection = str(exposure.get("protection_status") or "unknown")
        if protection in {"not-observed", "unknown"}:
            return (
                "Trace the concrete data classes across this static route, enforce "
                "allow-listing or redaction at the sink, then execute the mapped tests."
            )
    if validation.get("action"):
        return str(validation["action"])
    if not validation.get("mapped_test_files"):
        return (
            f"{remediation.rstrip()} Map focused tests to this entry-point route and "
            "retain their execution and coverage evidence."
        )[:2000]
    return remediation[:2000]


def _surface_action(surface: dict[str, Any], structural: dict[str, Any]) -> str:
    steps = _strings(surface.get("verification_steps"), 10)
    if structural.get("validation_action"):
        steps.append(str(structural["validation_action"]))
    if not steps:
        steps.append(
            "Trace concrete data classes across the route and verify filtering, redaction, and destination policy at the sink."
        )
    return " ".join(dict.fromkeys(steps))[:2000]


def _review_worthy_surface(surface: dict[str, Any], structural: dict[str, Any]) -> bool:
    return bool(
        surface.get("review_priority") == "high"
        or surface.get("data_classes")
        or structural.get("related_finding_ids")
        or _object(surface.get("sdk_dependency_context")).get("risk_present") is True
    )


def _surface_classifications(surface: dict[str, Any]) -> list[str]:
    family = str(surface.get("sink_family") or "unknown").upper().replace("_", "-")
    result = [f"SINK-{family}"]
    if surface.get("data_classes"):
        result.append("SENSITIVE-DATA-CONTEXT")
    if surface.get("protection_status") == "not-observed":
        result.append("PROTECTION-NOT-OBSERVED")
    return result


def _public_target(target: dict[str, Any]) -> dict[str, Any]:
    return {
        key: target[key]
        for key in (
            "kind",
            "id",
            "finding_id",
            "path",
            "line",
            "label",
            "domain",
            "area",
            "severity",
            "tools",
            "classifications",
        )
    }


def _unrouted(target: dict[str, Any], reason: str) -> dict[str, Any]:
    return {
        "priority": target["priority"],
        "target": _public_target(target),
        "owners": target["owners"],
        "evidence_assurance": target.get(
            "evidence_assurance", _empty_evidence_assurance(target)
        ),
        **(
            {"change_lifecycle_attribution": target["change_lifecycle_attribution"]}
            if "change_lifecycle_attribution" in target
            else {}
        ),
        "reason": reason,
        "recommended_action": (
            "Confirm framework, plugin, registry, generated-code, or external entry "
            "points and extend the governed reachability model before interpreting "
            "this target as unreachable."
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


def _route_order(value: dict[str, Any]) -> tuple[int, int, int, str]:
    return (
        _priority_rank(str(value["priority"])),
        {
            "finding": 0,
            "dependency-advisory-import": 1,
            "sink-surface": 2,
        }.get(str(value["target"]["kind"]), 3),
        -int(value["hop_count"]),
        str(value["route_id"]),
    )


def _target_order(value: dict[str, Any]) -> tuple[int, str]:
    return (
        _priority_rank(str(value["priority"])),
        str(value["target"]["id"]),
    )


def _candidate_order(value: dict[str, Any]) -> tuple[int, int, str]:
    return (
        _priority_rank(str(value["priority"])),
        {
            "finding": 0,
            "dependency-advisory-import": 1,
            "sink-surface": 2,
        }.get(str(value["kind"]), 3),
        str(value["id"]),
    )


def _priority_rank(value: str) -> int:
    return {"P0": 0, "P1": 1, "P2": 2, "P3": 3, "P4": 4}.get(value, 5)


def _artifact_available(value: Any, key: str) -> bool:
    return isinstance(value, dict) and isinstance(value.get(key), (dict, list))


def _test_execution_available(artifacts: dict[str, Any]) -> bool:
    return any(
        isinstance(artifacts.get(name), dict) for name in TEST_EVIDENCE_ARTIFACTS
    )


def _is_digest(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _raw_entry_point_count(value: Any) -> int:
    raw = value.get("entry_points") if isinstance(value, dict) else None
    return len(raw) if isinstance(raw, list) else 0


def _path(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    normalized = value.replace("\\", "/").strip()
    while normalized.startswith("./"):
        normalized = normalized[2:]
    if not normalized or normalized.startswith("/") or ".." in normalized.split("/"):
        return ""
    return normalized[:4000]


def _is_test_path(path: str) -> bool:
    normalized = _path(path).casefold()
    name = normalized.rsplit("/", 1)[-1]
    return (
        normalized.startswith("tests/")
        or "/tests/" in normalized
        or name.startswith("test_")
        or name.endswith("_test.py")
    )


def _object(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _objects(value: Any, limit: int) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value[:limit] if isinstance(item, dict)]


def _strings(value: Any, limit: int) -> list[str]:
    if isinstance(value, str):
        candidates = [value]
    elif isinstance(value, list):
        candidates = [str(item) for item in value if isinstance(item, (str, int))]
    else:
        candidates = []
    return sorted({item.strip()[:1000] for item in candidates if item.strip()})[:limit]


def _ordered_strings(value: Any, limit: int) -> list[str]:
    """Retain bounded string order for route and other sequence evidence."""
    if isinstance(value, str):
        candidates = [value]
    elif isinstance(value, list):
        candidates = [str(item) for item in value if isinstance(item, (str, int))]
    else:
        candidates = []
    result: list[str] = []
    seen: set[str] = set()
    for item in candidates:
        normalized = item.strip()[:1000]
        if normalized and normalized not in seen:
            result.append(normalized)
            seen.add(normalized)
        if len(result) >= limit:
            break
    return result


def _positive_integers(value: Any, limit: int) -> list[int]:
    if not isinstance(value, list):
        return []
    return sorted(
        {
            item
            for item in value
            if isinstance(item, int) and not isinstance(item, bool) and item > 0
        }
    )[:limit]


def _optional_string(value: Any) -> str | None:
    return str(value)[:1000] if isinstance(value, (str, int)) and str(value) else None


def _optional_boolean(value: Any) -> bool | None:
    return value if isinstance(value, bool) else None


def _optional_number(value: Any) -> float | None:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return round(float(value), 2)
    return None


def _positive_integer(value: Any) -> int | None:
    return (
        value
        if isinstance(value, int) and not isinstance(value, bool) and value > 0
        else None
    )


def _nonnegative_integer(value: Any) -> int | None:
    return (
        value
        if isinstance(value, int) and not isinstance(value, bool) and value >= 0
        else None
    )


def _digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
