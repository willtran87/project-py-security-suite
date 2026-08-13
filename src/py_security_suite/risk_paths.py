from __future__ import annotations

import hashlib
import json
from collections import defaultdict, deque
from typing import Any

from .models import Citation, Finding, FindingStatus
from .prioritization import finding_priority


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
_MAX_OWNER_QUEUES = 100


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
    adjacency, graph_available, graph_truncated = _file_graph(graph)
    entry_points = _entry_points(reachability)
    candidate_targets = [
        *_finding_targets(findings),
        *_sink_surface_targets(exposure),
    ]
    targets = sorted(candidate_targets, key=_candidate_order)[:_MAX_TARGETS]
    for target in targets:
        target["validation"] = _assess_validation(target["validation"], artifacts)
    routed, unrouted = _route_targets(
        entry_points,
        targets,
        adjacency,
        graph_available=graph_available,
    )
    routed.sort(key=_route_order)
    unrouted.sort(key=_target_order)
    retained_routes = routed[:_MAX_ROUTES]
    all_convergence_hotspots = _convergence_hotspots(retained_routes)
    convergence_hotspots = all_convergence_hotspots[:_MAX_CONVERGENCE_HOTSPOTS]
    hotspot_ids_by_route: dict[str, list[str]] = defaultdict(list)
    for hotspot in convergence_hotspots:
        for route_id in hotspot["route_ids"]:
            hotspot_ids_by_route[route_id].append(hotspot["hotspot_id"])
    for route in retained_routes:
        route["convergence_hotspot_ids"] = sorted(
            hotspot_ids_by_route.get(route["route_id"], [])
        )
    all_owner_work_queues = _owner_work_queues(retained_routes, convergence_hotspots)
    owner_work_queues = all_owner_work_queues[:_MAX_OWNER_QUEUES]
    retained_route_ids = {
        route["target"]["finding_id"]: route
        for route in retained_routes
        if route["target"].get("finding_id")
    }
    _attach_finding_routes(findings, retained_route_ids, unrouted)
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
            "bounded static routes from declared Python entry points to normalized "
            "findings and review-worthy sensitive-data sink surfaces"
        ),
        "summary": {
            "graph_available": graph_available,
            "reachability_available": isinstance(reachability, dict)
            and reachability.get("schema_version") == "1.2",
            "entry_points": len(entry_points),
            "candidate_targets": len(candidate_targets),
            "targets_analyzed": len(targets),
            "finding_targets": sum(
                target["kind"] == "finding" for target in candidate_targets
            ),
            "sink_surface_targets": sum(
                target["kind"] == "sink-surface" for target in candidate_targets
            ),
            "routed_targets": len(routed),
            "unrouted_targets": len(unrouted),
            "routed_findings": sum(
                route["target"]["kind"] == "finding" for route in routed
            ),
            "routed_sink_surfaces": sum(
                route["target"]["kind"] == "sink-surface" for route in routed
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
            "test_execution": _artifact_available(
                artifacts.get("junit-summary.json"), "summary"
            ),
            "structural_synthesis": isinstance(
                artifacts.get("structural-synthesis.json"), dict
            ),
            "data_exposure": isinstance(exposure, dict),
        },
        "routes": retained_routes,
        "convergence_hotspots": convergence_hotspots,
        "owner_work_queues": owner_work_queues,
        "unrouted_targets": unrouted[:_MAX_UNROUTED],
        "truncation": {
            "graph_files_omitted": graph_truncated,
            "entry_points_omitted": max(
                0, _raw_entry_point_count(reachability) - _MAX_ENTRY_POINTS
            ),
            "targets_omitted": max(0, len(candidate_targets) - _MAX_TARGETS),
            "routes_omitted": max(0, len(routed) - _MAX_ROUTES),
            "unrouted_targets_omitted": max(0, len(unrouted) - _MAX_UNROUTED),
            "convergence_hotspots_omitted": max(
                0, len(all_convergence_hotspots) - _MAX_CONVERGENCE_HOTSPOTS
            ),
            "owner_work_queues_omitted": max(
                0, len(all_owner_work_queues) - _MAX_OWNER_QUEUES
            ),
        },
        "interpretation_limits": [
            "A static route is a review path, not proof of attacker-controlled input, vulnerable-function reachability, exploitability, or sensitive-data flow.",
            "No bounded route may indicate reflection, registries, dependency injection, generated code, framework dispatch, or an incomplete entry-point model.",
            "Runtime observation proves only that code executed during retained tests; absence of observation does not prove dead code.",
            "Sensitive-data sink surfaces are inventory signals unless a normalized scanner finding establishes a source-to-sink concern.",
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
            }
        )
    return sorted(result, key=lambda item: (item["path"], item["id"]))[
        :_MAX_ENTRY_POINTS
    ]


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
                    "sdk_package_risk": bool(
                        _object(surface.get("sdk_dependency_context")).get(
                            "package_findings"
                        )
                    ),
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
                    }
                ),
            }
        )
    return routed, unrouted


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
                        str(route["target"]["finding_id"])
                        for route, _role in observations
                        if route["target"].get("finding_id")
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


def _owner_work_queues(
    routes: list[dict[str, Any]], hotspots: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    hotspot_by_route: dict[str, set[str]] = defaultdict(set)
    for hotspot in hotspots:
        for route_id in hotspot["route_ids"]:
            hotspot_by_route[route_id].add(hotspot["hotspot_id"])
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for route in routes:
        owners = route["owners"] or ["Unassigned"]
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
                "routes_by_priority": priorities,
                "validation_statuses": assessments,
                "recommended_action": _owner_queue_action(owner, assessments),
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


def _owner_queue_action(owner: str, assessments: dict[str, int]) -> str:
    if assessments["gap"]:
        return (
            f"{owner}: close {assessments['gap']} explicit validation gap(s), then "
            "rerun every route in this queue."
        )
    incomplete = assessments["partial"] + assessments["not-assessed"]
    if incomplete:
        return (
            f"{owner}: produce complete change, coverage, and focused-test evidence "
            f"for {incomplete} route(s) before disposition."
        )
    return f"{owner}: coordinate the shared remediation and regression-test scope."


def _attach_finding_routes(
    findings: list[Finding],
    routed: dict[str, dict[str, Any]],
    unrouted: list[dict[str, Any]],
) -> None:
    unrouted_by_id = {
        item["target"]["finding_id"]: item
        for item in unrouted
        if item["target"].get("finding_id")
    }
    for finding in findings:
        route = routed.get(finding.finding_id)
        if route is not None:
            finding.evidence["risk_path"] = {
                "status": "routed",
                "route_id": route["route_id"],
                "priority": route["priority"],
                "entry_point": route["entry_point"],
                "hop_count": route["hop_count"],
                "files": route["files"],
                "runtime_context": route["runtime_context"],
                "validation": route["validation"],
                "convergence_hotspot_ids": route["convergence_hotspot_ids"],
                "recommended_action": route["recommended_action"],
                "evidence_artifact": "risk-paths.json",
            }
            _add_route_citations(finding)
        elif finding.finding_id in unrouted_by_id:
            record = unrouted_by_id[finding.finding_id]
            finding.evidence["risk_path"] = {
                "status": "unrouted",
                "reason": record["reason"],
                "evidence_artifact": "risk-paths.json",
            }
            _add_route_citations(finding)


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
        "test_execution": _artifact_available(
            artifacts.get("junit-summary.json"), "summary"
        ),
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
        or _object(surface.get("sdk_dependency_context")).get("package_findings")
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
        0 if value["target"]["kind"] == "finding" else 1,
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
        0 if value["kind"] == "finding" else 1,
        str(value["id"]),
    )


def _priority_rank(value: str) -> int:
    return {"P0": 0, "P1": 1, "P2": 2, "P3": 3, "P4": 4}.get(value, 5)


def _artifact_available(value: Any, key: str) -> bool:
    return isinstance(value, dict) and isinstance(value.get(key), (dict, list))


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


def _object(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _strings(value: Any, limit: int) -> list[str]:
    if isinstance(value, str):
        candidates = [value]
    elif isinstance(value, list):
        candidates = [str(item) for item in value if isinstance(item, (str, int))]
    else:
        candidates = []
    return sorted({item.strip()[:1000] for item in candidates if item.strip()})[:limit]


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


def _digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
