from __future__ import annotations

from collections import defaultdict
from itertools import pairwise
from typing import Any

from . import risk_path_summary
from .risk_path_values import _object, _strings, _nonnegative_integer
from .models import Finding
from .ownership import ownership_rules_from_artifact
from .risk_path_campaigns import (
    _attach_shared_test_evidence_quality,
    _campaign_control_context_index,
    _empty_campaign_control_context,
    _refresh_validation_test_hotspot_review,
    _validation_campaigns,
    _validation_test_hotspots,
)
from .risk_path_common import (
    _GRAPHIFY_REFERENCE,
    _MAX_ADVISORY_IMPORT_PATHS,
    _MAX_CAMPAIGN_MISSING_LINES,
    _MAX_ENTRY_POINTS,
    _MAX_EXPOSURE_ADVISORY_INTERSECTIONS,
    _MAX_ROUTES,
    _MAX_ROUTE_HOPS,
    _MAX_SENSITIVE_ROUTE_CITATIONS,
    _RISK_PATH_REFERENCE,
    _STRUCTURAL_SYNTHESIS_REFERENCE,
    _artifact_available,
    _citation_records,
    _digest,
    _objects,
    _optional_number,
    _optional_string,
    _ordered_strings,
    _path,
    _positive_integers,
    _priority_rank,
    _route_order,
    _test_execution_available,
)
from .risk_path_dependencies import (
    _composition_evidence,
    _dependency_advisory_action,
    _dependency_advisory_classifications,
    _dependency_advisory_validation,
    _exposure_advisory_intersections,
    _package_lifecycle_assessment,
)
from .risk_path_evidence import _target_evidence_assurance, _tool_posture_index
from .risk_path_lifecycle import (
    _baseline_lifecycle_context,
    _change_lifecycle_attribution,
    _change_lifecycle_review_factors,
)
from .risk_path_owner_queues import _owner_work_queues
from .risk_path_ownership import (
    _ownership_coordination_action,
    _ownership_coordination_status,
    _ownership_path_records,
    _target_owner_alignment,
)
from .risk_path_routes import (
    _attach_finding_routes,
    _entry_point_runtime_index,
    _entry_points,
    _file_graph,
    _multi_source_paths,
    _reconstruct_route,
    _route_applicability_inventory,
    _route_targets,
    _target_route_applicability,
)
from .risk_path_secrets import (
    _attach_secret_exposure_advisory_intersections,
    _attach_secret_exposure_intersections,
    _attach_secret_provenance,
    _secret_exposure_advisory_intersections,
    _secret_exposure_intersections,
    _secret_finding_count,
    _secret_provenance_assessments,
)
from .risk_path_sensitive_routes import _sensitive_route_validation_handoff
from .risk_path_structural import (
    _attach_unrouted_structural_intersections,
    _unrouted_structural_intersections,
)
from .risk_path_targets import (
    _convergence_hotspots,
    _finding_targets,
    _sink_surface_targets,
)
from .risk_path_validation import (
    _assess_validation,
    _entry_runtime_context,
    _entry_runtime_counts,
)


_REACHABILITY_REFERENCE = "docs/reachability.md"


_MAX_TARGETS = 10_000


_MAX_UNROUTED = 250


_MAX_CONVERGENCE_HOTSPOTS = 50


_MAX_VALIDATION_TEST_HOTSPOTS = 100


_MAX_OWNER_QUEUES = 100


_MAX_SENSITIVE_DATA_ROUTES = 100


_MAX_SECRET_PROVENANCE_ASSESSMENTS = 250


_MAX_SECRET_EXPOSURE_INTERSECTIONS = 100


_MAX_SECRET_EXPOSURE_ADVISORY_INTERSECTIONS = 100


_MAX_UNROUTED_STRUCTURAL_INTERSECTIONS = 100


_MAX_ENTRY_POINT_EXPOSURES = 25


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
    route_inventory = _route_applicability_inventory(artifacts, graph)
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
        target["route_applicability"] = _target_route_applicability(
            target, route_inventory
        )
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
    retained_unrouted = unrouted[:_MAX_UNROUTED]
    all_unrouted_structural_intersections = _unrouted_structural_intersections(
        unrouted, structural
    )
    retained_unrouted_target_ids = {
        str(item["target"]["id"]) for item in retained_unrouted
    }
    retained_unrouted_structural_candidates = [
        item
        for item in all_unrouted_structural_intersections
        if str(item["target_id"]) in retained_unrouted_target_ids
    ]
    unrouted_structural_intersections = retained_unrouted_structural_candidates[
        :_MAX_UNROUTED_STRUCTURAL_INTERSECTIONS
    ]
    _attach_unrouted_structural_intersections(
        retained_unrouted, unrouted_structural_intersections
    )
    all_secret_provenance_assessments = _secret_provenance_assessments(
        findings,
        targets,
        {str(route["target"]["id"]) for route in routed},
    )
    secret_provenance_assessments = all_secret_provenance_assessments[
        :_MAX_SECRET_PROVENANCE_ASSESSMENTS
    ]
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
        retained_routes,
        adjacency,
        artifacts,
    )
    all_validation_test_hotspots = _validation_test_hotspots(
        validation_campaigns,
        findings,
        ownership_rules,
    )
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
    _attach_shared_test_evidence_quality(
        validation_campaigns, all_validation_test_hotspots
    )
    _refresh_validation_test_hotspot_review(
        all_validation_test_hotspots, validation_campaigns
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
    all_sensitive_data_routes = _sensitive_data_routes(
        retained_routes, validation_campaigns
    )
    sensitive_data_routes = all_sensitive_data_routes[:_MAX_SENSITIVE_DATA_ROUTES]
    all_secret_exposure_intersections = _secret_exposure_intersections(
        secret_provenance_assessments,
        sensitive_data_routes,
    )
    secret_exposure_intersections = all_secret_exposure_intersections[
        :_MAX_SECRET_EXPOSURE_INTERSECTIONS
    ]
    all_secret_exposure_advisory_intersections = (
        _secret_exposure_advisory_intersections(
            all_secret_exposure_intersections,
            all_exposure_advisory_intersections,
        )
    )
    retained_secret_intersection_ids = {
        str(item["intersection_id"]) for item in secret_exposure_intersections
    }
    retained_advisory_intersection_ids = {
        str(item["intersection_id"]) for item in exposure_advisory_intersections
    }
    retained_secret_exposure_advisory_candidates = [
        item
        for item in all_secret_exposure_advisory_intersections
        if item["secret_exposure_intersection_id"] in retained_secret_intersection_ids
        and item["exposure_advisory_intersection_id"]
        in retained_advisory_intersection_ids
    ]
    secret_exposure_advisory_intersections = (
        retained_secret_exposure_advisory_candidates[
            :_MAX_SECRET_EXPOSURE_ADVISORY_INTERSECTIONS
        ]
    )
    _attach_secret_exposure_advisory_intersections(
        secret_exposure_intersections,
        exposure_advisory_intersections,
        sensitive_data_routes,
        secret_exposure_advisory_intersections,
    )
    _attach_secret_exposure_intersections(
        secret_provenance_assessments,
        sensitive_data_routes,
        secret_exposure_intersections,
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
        sensitive_data_routes,
    )
    _attach_secret_provenance(findings, secret_provenance_assessments)
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
            ", end-to-end sensitive-data routes, and evidence-plane-aware "
            "unrouted dispositions, including conservative secret-to-sink "
            "route intersections and exact sensitive-route joins between secret, "
            "sink, and dependency-advisory evidence, plus exact retained structural-"
            "island explanations for Python route gaps"
        ),
        "summary": {
            **risk_path_summary.summarize_graph_available(graph_available),
            **risk_path_summary.summarize_reachability(reachability),
            **risk_path_summary.summarize_entry_points(entry_points),
            **risk_path_summary.summarize_candidate_targets_and_dependency_targets_omitted(
                candidate_targets, dependency_targets_omitted
            ),
            **risk_path_summary.summarize_targets(targets),
            **risk_path_summary.summarize_candidate_targets(candidate_targets),
            **risk_path_summary.summarize_routed(routed),
            **risk_path_summary.summarize_unrouted(unrouted),
            **risk_path_summary.summarize_unrouted_structural_intersections(
                all_unrouted_structural_intersections
            ),
            **risk_path_summary.summarize_routes(retained_routes),
            **risk_path_summary.summarize_exposure_advisory_intersections(
                all_exposure_advisory_intersections
            ),
            **risk_path_summary.summarize_sensitive_data_routes(
                all_sensitive_data_routes
            ),
            **risk_path_summary.summarize_secret_provenance_assessments(
                all_secret_provenance_assessments
            ),
            **risk_path_summary.summarize_secret_exposure_intersections(
                all_secret_exposure_intersections
            ),
            **risk_path_summary.summarize_secret_exposure_advisory_intersections(
                all_secret_exposure_advisory_intersections
            ),
            **risk_path_summary.summarize_validation_gaps(validation_gaps),
            **risk_path_summary.summarize_convergence_hotspots(convergence_hotspots),
            **risk_path_summary.summarize_owner_work_queues(owner_work_queues),
            **risk_path_summary.summarize_validation_campaigns(validation_campaigns),
            **risk_path_summary.summarize_validation_test_hotspots(
                validation_test_hotspots
            ),
            **risk_path_summary.summarize_route_priorities(route_priorities),
            "secret_candidates": _secret_finding_count(findings),
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
            "artifact_manifest": isinstance(
                artifacts.get("artifact-manifest.json"), dict
            ),
        },
        "routes": retained_routes,
        "convergence_hotspots": convergence_hotspots,
        "validation_campaigns": validation_campaigns,
        "validation_test_hotspots": validation_test_hotspots,
        "exposure_advisory_intersections": exposure_advisory_intersections,
        "sensitive_data_routes": sensitive_data_routes,
        "secret_provenance_assessments": secret_provenance_assessments,
        "secret_exposure_intersections": secret_exposure_intersections,
        "secret_exposure_advisory_intersections": (
            secret_exposure_advisory_intersections
        ),
        "owner_work_queues": owner_work_queues,
        "unrouted_structural_intersections": unrouted_structural_intersections,
        "unrouted_targets": retained_unrouted,
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
            "unrouted_structural_intersections_omitted": max(
                0,
                len(all_unrouted_structural_intersections)
                - len(unrouted_structural_intersections),
            ),
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
            "sensitive_data_routes_omitted": max(
                0, len(all_sensitive_data_routes) - _MAX_SENSITIVE_DATA_ROUTES
            ),
            "secret_provenance_assessments_omitted": max(
                0,
                _secret_finding_count(findings) - len(secret_provenance_assessments),
            ),
            "secret_exposure_intersections_omitted": max(
                0,
                len(all_secret_exposure_intersections)
                - _MAX_SECRET_EXPOSURE_INTERSECTIONS,
            ),
            "secret_exposure_advisory_intersections_omitted": max(
                0,
                len(all_secret_exposure_advisory_intersections)
                - len(secret_exposure_advisory_intersections),
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
            "An unrouted-target/structural-island intersection proves only exact retained path or line membership in the island assessment; it does not prove dead code, safety, exploitability, or production inaccessibility, and runtime or boundary counter-evidence must be resolved before removal.",
            "Artifact controls, generated evidence, validation code, and non-Python repository controls are not expected to have production Python routes; that disposition does not suppress, downgrade, validate, or resolve the underlying finding.",
            "Runtime observation proves only that code executed during retained tests; absence of observation does not prove dead code.",
            "Sensitive-data sink surfaces are inventory signals unless a normalized scanner finding establishes a source-to-sink concern.",
            "A sensitive-data route joins static entry-point, sink, protection, ownership, scanner-assurance, and validation evidence; it does not prove attacker-controlled input, runtime data flow, disclosure, or regulatory impact.",
            "A secret provenance assessment classifies where a redacted scanner candidate was observed and which evidence is available; it does not prove that the candidate is a real, active, exploitable, or unique credential, and generated or test context is never an automatic false-positive disposition.",
            "A secret exposure intersection proves only that a redacted candidate is in the same file as, or on the bounded Graphify file route to, a sensitive sink; it does not establish symbol-level data flow, that the candidate is a credential, that it reached the sink, or that disclosure occurred.",
            "A dependency-advisory import route proves only a retained static path to a source file that imports the affected distribution; it does not prove invocation of a vulnerable function, attacker control, or exploitability.",
            "Package lifecycle comparison proves only what the retained source and built-artifact composition inventories report; it does not prove inventory completeness, runtime loading, semantic version safety, or vulnerable-function use.",
            "An exposure-advisory intersection proves only that a retained sensitive sink and an affected SDK importer share an exact source path and advisory identity; it does not prove the SDK processed the sensitive value, that data leaked, or that the vulnerable function executed.",
            "A secret-exposure-advisory intersection proves only that the secret/sink and sink/advisory ledgers reference the identical retained sensitive route; it does not prove credential validity, symbol-level value flow, runtime disclosure, vulnerable-function execution, or exploitability.",
            "Graph-selected tests are bounded static candidates; passing selected tests and full retained coverage improve regression confidence but do not prove security, exploitability, or complete runtime behavior.",
            "The shared-control review score is a transparent triage aid, not native scanner severity, exploitability probability, or an admission decision.",
            "A shared validation test hotspot identifies concentrated regression responsibility; it does not prove test independence, assertion quality, or sufficient behavioral coverage.",
            "A sealed report binds its current source inventory, but pre-generated test and coverage evidence is revision-aligned only when each producer declares the same aggregate source digest.",
        ],
        "references": [
            _GRAPHIFY_REFERENCE,
            _REACHABILITY_REFERENCE,
            _RISK_PATH_REFERENCE,
            _STRUCTURAL_SYNTHESIS_REFERENCE,
        ],
    }


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


def _sensitive_data_routes(
    routes: list[dict[str, Any]],
    validation_campaigns: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Join exposure semantics to entry, assurance, ownership, and validation."""
    campaigns_by_id = {
        str(campaign["campaign_id"]): campaign for campaign in validation_campaigns
    }
    result: list[dict[str, Any]] = []
    for route in routes:
        target = route["target"]
        correlations = route["correlations"]
        confirmed = _object(correlations.get("sensitive_data_context"))
        inventory_surface = target.get("kind") == "sink-surface"
        if not confirmed and not inventory_surface:
            continue
        context = confirmed or {
            "concern": "review-worthy-sensitive-data-sink",
            "sink_family": correlations.get("sink_family"),
            "sink": target.get("label"),
            "sdk": correlations.get("sdk"),
            "confidence": None,
            "data_classes": correlations.get("data_classes"),
            "trust_boundary": correlations.get("trust_boundary"),
            "protection_status": correlations.get("protection_status"),
            "risk_factors": [],
            "review_priority": str(route.get("priority") or "P4"),
            "citations": correlations.get("citations"),
        }
        ownership = _object(route.get("ownership_context"))
        lifecycle = _object(route.get("change_lifecycle_attribution"))
        entry_exposures = _objects(
            route.get("entry_point_exposures"), _MAX_ENTRY_POINT_EXPOSURES
        )
        confidence = _optional_string(context.get("confidence"))
        if confidence not in {"high", "medium", "low"}:
            confidence = None
        record = {
            "sensitive_route_id": "sensitive-route-"
            + _digest(
                {
                    "route_id": route["route_id"],
                    "target_id": target["id"],
                    "sink_family": context.get("sink_family"),
                    "trust_boundary": context.get("trust_boundary"),
                }
            )[:16],
            "route_id": route["route_id"],
            "priority": route["priority"],
            "evidence_basis": (
                "scanner-confirmed-source-to-sink"
                if confirmed
                else "inventory-review-surface"
            ),
            "target_kind": target["kind"],
            "target_id": target["id"],
            "finding_id": target.get("finding_id"),
            "path": target["path"],
            "line": target.get("line"),
            "label": target["label"],
            "source_tools": _strings(target.get("tools"), 25),
            "classifications": _strings(target.get("classifications"), 50),
            "concern": str(context.get("concern") or "sensitive-data-exposure")[:200],
            "sink_family": str(context.get("sink_family") or "unknown")[:100],
            "sink": _optional_string(context.get("sink")),
            "sdk": _optional_string(context.get("sdk")),
            "confidence": confidence,
            "data_classes": _strings(context.get("data_classes"), 25),
            "trust_boundary": str(context.get("trust_boundary") or "unknown")[:100],
            "protection_status": str(context.get("protection_status") or "unknown")[
                :100
            ],
            "risk_factors": _strings(context.get("risk_factors"), 25),
            "citations": _citation_records(
                context.get("citations"),
                limit=_MAX_SENSITIVE_ROUTE_CITATIONS,
                default_kind="reference",
            ),
            "entry_point_ids": sorted(
                {
                    str(_object(item.get("entry_point")).get("id"))
                    for item in entry_exposures
                    if _object(item.get("entry_point")).get("id")
                }
            ),
            "entry_point_kinds": _strings(route.get("entry_point_kinds"), 25),
            "entry_point_exposure_count": int(route["entry_point_exposure_count"]),
            "entry_point_exposures_omitted": int(
                route["entry_point_exposures_omitted"]
            ),
            "entry_point_runtime_statuses": _entry_runtime_counts(entry_exposures),
            "validation_status": str(
                _object(route.get("validation")).get("assessment_status")
                or "not-assessed"
            ),
            "validation_handoff": _sensitive_route_validation_handoff(
                route, campaigns_by_id
            ),
            "evidence_assurance_status": str(
                _object(route.get("evidence_assurance")).get("review_status")
                or "not-assessed"
            ),
            "ownership_coordination_status": str(
                ownership.get("coordination_status") or "not-established"
            ),
            "ownership_boundaries": _nonnegative_integer(
                ownership.get("boundary_count")
            )
            or 0,
            "owners": _strings(ownership.get("coordination_owners"), 100),
            "route_files": _ordered_strings(route.get("files"), _MAX_ROUTE_HOPS + 1),
            "route_hop_count": int(route["hop_count"]),
            "change_lifecycle_classification": _optional_string(
                lifecycle.get("classification")
            ),
            "secret_exposure_intersection_ids": [],
            "secret_exposure_intersections": [],
            "secret_exposure_intersections_omitted": 0,  # nosec B105
            "exposure_advisory_intersection_ids": _strings(
                route.get("exposure_advisory_intersection_ids"), 100
            ),
            "evidence_artifacts": sorted(
                {
                    "data-exposure.json",
                    "risk-paths.json",
                    *_strings(route.get("evidence_artifacts"), 25),
                }
            ),
            "recommended_action": str(
                route.get("recommended_action")
                or "Trace, minimize, protect, and validate the sensitive-data route."
            )[:2000],
        }
        result.append(record)
    return sorted(
        result,
        key=lambda item: (
            _priority_rank(str(item["priority"])),
            0 if item["evidence_basis"] == "scanner-confirmed-source-to-sink" else 1,
            str(item["path"]),
            int(item["line"] or 0),
            str(item["sensitive_route_id"]),
        ),
    )


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
    unowned: list[str] = (
        sorted(
            _path(record.get("path"))
            for record in file_records
            if not record.get("owners")
        )
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


def _raw_entry_point_count(value: Any) -> int:
    raw = value.get("entry_points") if isinstance(value, dict) else None
    return len(raw) if isinstance(raw, list) else 0
