from __future__ import annotations

from collections import defaultdict, deque
from typing import Any

from .risk_path_values import _object, _strings
from .models import Citation, Finding
from .risk_path_common import (
    _GRAPHIFY_REFERENCE,
    _MAX_ENTRY_POINTS,
    _MAX_GRAPH_FILES,
    _MAX_ROUTE_HOPS,
    _RISK_PATH_REFERENCE,
    _STRUCTURAL_SYNTHESIS_REFERENCE,
    _digest,
    _is_test_path,
    _optional_string,
    _path,
    _positive_integer,
    _priority_rank,
    _route_order,
)
from .risk_path_dependencies import (
    _compact_dependency_advisory_route,
    _compact_exposure_advisory_intersection,
)
from .risk_path_evidence import _empty_evidence_assurance


__all__ = [
    "_attach_finding_routes",
    "_entry_point_runtime_index",
    "_entry_points",
    "_file_graph",
    "_multi_source_paths",
    "_reconstruct_route",
    "_route_applicability_inventory",
    "_route_targets",
    "_target_route_applicability",
]


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


_MAX_FINDING_ADVISORY_ROUTES = 25


_ARTIFACT_CONTROL_TOOLS = frozenset(
    {"check-wheel-contents", "cosign", "pypi-attestations", "twine"}
)


_GENERATED_EVIDENCE_NAMES = frozenset(
    {
        ".coverage",
        "artifact-manifest.json",
        "checksums.sha256",
        "coverage.json",
        "coverage.xml",
        "findings.json",
        "junit.xml",
        "results.sarif",
        "scan-manifest.json",
    }
)


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


def _route_applicability_inventory(
    artifacts: dict[str, Any], graph: Any
) -> dict[str, Any]:
    source_inventory = artifacts.get("source-inventory.json")
    artifact_manifest = artifacts.get("artifact-manifest.json")
    return {
        "graph_available": isinstance(graph, dict)
        and graph.get("schema_version") == "1.0",
        "graph_paths": _graph_paths(graph),
        "source_inventory_available": isinstance(source_inventory, dict),
        "source_paths": _manifest_paths(source_inventory, "files"),
        "artifact_manifest_available": isinstance(artifact_manifest, dict),
        "artifact_paths": _manifest_paths(artifact_manifest, "artifacts"),
    }


def _graph_paths(value: Any) -> set[str]:
    if not isinstance(value, dict) or value.get("schema_version") != "1.0":
        return set()
    paths = {
        path
        for item in value.get("nodes", [])
        if isinstance(item, dict)
        if (path := _path(item.get("path")))
    }
    topology = value.get("topology")
    edges = topology.get("file_edges") if isinstance(topology, dict) else []
    for edge in edges if isinstance(edges, list) else []:
        if not isinstance(edge, dict):
            continue
        paths.update(
            path for key in ("source", "target") if (path := _path(edge.get(key)))
        )
    return set(sorted(paths)[:_MAX_GRAPH_FILES])


def _manifest_paths(value: Any, key: str) -> set[str]:
    items = value.get(key) if isinstance(value, dict) else None
    if not isinstance(items, list):
        return set()
    return {
        path
        for item in items[:_MAX_GRAPH_FILES]
        if isinstance(item, dict)
        if (path := _path(item.get("path")))
    }


def _target_route_applicability(
    target: dict[str, Any], inventory: dict[str, Any]
) -> dict[str, Any]:
    path = str(target["path"])
    graph_available = inventory["graph_available"] is True
    source_available = inventory["source_inventory_available"] is True
    artifact_available = inventory["artifact_manifest_available"] is True
    graph_member = path in inventory["graph_paths"] if graph_available else None
    source_member = path in inventory["source_paths"] if source_available else None
    artifact_member = (
        path in inventory["artifact_paths"] if artifact_available else None
    )
    classification = _route_applicability_classification(
        target, artifact_member=artifact_member is True
    )
    applicable = classification == "python-runtime-source"
    reason, action = _route_applicability_guidance(classification)
    evidence_artifacts = [
        name
        for name, available in (
            ("graphify.json", graph_available),
            ("source-inventory.json", source_available),
            ("artifact-manifest.json", artifact_available),
        )
        if available
    ]
    return {
        "assessment": "route-applicable" if applicable else "not-route-applicable",
        "classification": classification,
        "reason": reason,
        "source_inventory_available": source_available,
        "source_inventory_member": source_member,
        "graph_available": graph_available,
        "graph_path_member": graph_member,
        "artifact_manifest_available": artifact_available,
        "artifact_manifest_member": artifact_member,
        "evidence_artifacts": evidence_artifacts,
        "recommended_action": action,
    }


def _route_applicability_classification(
    target: dict[str, Any], *, artifact_member: bool
) -> str:
    path = str(target["path"])
    normalized = path.casefold()
    area = str(target.get("area") or "").casefold()
    tools = {str(tool).casefold() for tool in target.get("tools", [])}
    if (
        artifact_member
        or normalized.startswith((".artifacts/", "dist/", "build/"))
        or "artifact" in area.split("-")
        or bool(tools & _ARTIFACT_CONTROL_TOOLS)
        or normalized.endswith((".whl", ".tar.gz"))
    ):
        return "artifact-control"
    if normalized.rsplit("/", 1)[
        -1
    ] in _GENERATED_EVIDENCE_NAMES or normalized.endswith(".pysec-binding.json"):
        return "generated-evidence"
    if _is_test_path(path):
        return "test-validation-source"
    if target.get("kind") in {"sink-surface", "dependency-advisory-import"}:
        return "python-runtime-source"
    if normalized.endswith((".py", ".pyi")):
        return "python-runtime-source"
    return "outside-python-runtime-model"


def _route_applicability_guidance(classification: str) -> tuple[str, str]:
    guidance = {
        "python-runtime-source": (
            "the target is Python runtime source and should be evaluated against declared entry points",
            "Confirm framework, plugin, registry, generated-code, or external entry points and extend the governed Python reachability model before interpreting this target as unreachable.",
        ),
        "artifact-control": (
            "the finding concerns a built-artifact, provenance, or source-parity control rather than a Python runtime path",
            "Resolve the artifact integrity, provenance, packaging, or source-parity control through the release evidence lane; do not add a Python entry point solely to route this target.",
        ),
        "generated-evidence": (
            "the target is generated test, coverage, or scan evidence rather than maintained Python runtime source",
            "Confirm the generated file belongs in scanner scope, remediate the evidence producer or exclusion policy as appropriate, and do not model the generated file as a Python entry point.",
        ),
        "test-validation-source": (
            "the target is validation code and is not expected to have a production entry-point route",
            "Resolve or govern the test-file finding as validation-evidence quality, then rerun affected campaigns; do not treat absence of a production route as proof that the test finding is harmless.",
        ),
        "outside-python-runtime-model": (
            "the target is outside the suite's Python runtime route model",
            "Use the target's native repository, configuration, infrastructure, or supply-chain scanner context; add a separate governed entry model only when this file is an actual runtime interface.",
        ),
    }
    return guidance[classification]


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


def _route_targets(
    entry_points: list[dict[str, Any]],
    targets: list[dict[str, Any]],
    adjacency: dict[str, dict[str, str]],
    *,
    graph_available: bool,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    parent, origin, depth = _multi_source_paths(entry_points, adjacency)
    entries_by_id = {item["id"]: item for item in entry_points}
    routed: list[dict[str, Any]] = []
    unrouted: list[dict[str, Any]] = []
    for target in targets:
        path = target["path"]
        applicability = target["route_applicability"]
        if applicability["assessment"] != "route-applicable":
            unrouted.append(_unrouted(target, str(applicability["reason"])))
            continue
        if not entry_points:
            unrouted.append(
                _unrouted(target, "declared entry-point evidence is unavailable")
            )
            continue
        if path not in origin:
            reason = (
                "Graphify file-route evidence is unavailable"
                if not graph_available
                else "the Python target path is absent from the retained Graphify file model"
                if applicability["graph_path_member"] is False
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
                "route_applicability": applicability,
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
                        *applicability["evidence_artifacts"],
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


def _attach_finding_routes(
    findings: list[Finding],
    routed: dict[str, dict[str, Any]],
    all_routed: list[dict[str, Any]],
    unrouted: list[dict[str, Any]],
    validation_campaigns: list[dict[str, Any]],
    exposure_advisory_intersections: list[dict[str, Any]],
    sensitive_data_routes: list[dict[str, Any]],
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
    sensitive_routes_by_finding = {
        str(item["finding_id"]): item
        for item in sensitive_data_routes
        if item.get("finding_id")
    }
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
                "route_applicability": route["route_applicability"],
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
                "sensitive_data_route": _object(
                    sensitive_routes_by_finding.get(finding.finding_id)
                ),
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
                            "route_evidence_assurance",
                            "shared_test_evidence_quality",
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
                "runtime_context": record["runtime_context"],
                "validation": record["validation"],
                "evidence_assurance": record["evidence_assurance"],
                "route_applicability": record["route_applicability"],
                "unrouted_structural_intersection_ids": record[
                    "unrouted_structural_intersection_ids"
                ],
                "unrouted_structural_intersections": record[
                    "unrouted_structural_intersections"
                ],
                "unrouted_structural_intersections_omitted": record[
                    "unrouted_structural_intersections_omitted"
                ],
                "recommended_action": record["recommended_action"],
                "change_lifecycle_attribution": _object(
                    record.get("change_lifecycle_attribution")
                ),
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
    risk_path = _object(finding.evidence.get("risk_path"))
    if (
        risk_path.get("unrouted_structural_intersection_ids")
        and "pysec-unrouted-structural-intersection" not in existing
    ):
        finding.citations.append(
            Citation(
                kind="supporting_evidence",
                identifier="pysec-unrouted-structural-intersection",
                title="Suite exact unrouted-target and structural-island intersection",
                uri=_STRUCTURAL_SYNTHESIS_REFERENCE,
            )
        )


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
    applicability = target["route_applicability"]
    return {
        "priority": target["priority"],
        "target": _public_target(target),
        "owners": target["owners"],
        "runtime_context": target["runtime_context"],
        "validation": target["validation"],
        "evidence_assurance": target.get(
            "evidence_assurance", _empty_evidence_assurance(target)
        ),
        "route_applicability": applicability,
        **(
            {"change_lifecycle_attribution": target["change_lifecycle_attribution"]}
            if "change_lifecycle_attribution" in target
            else {}
        ),
        "reason": reason,
        "recommended_action": applicability["recommended_action"],
        "unrouted_structural_intersection_ids": [],
        "unrouted_structural_intersections": [],
        "unrouted_structural_intersections_omitted": 0,
    }
