from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from typing import Any

from .models import Citation, Finding
from .structural_leverage import build_structural_leverage


_GRAPHIFY_REFERENCE = "https://graphify.com/docs/cli"
_VULTURE_REFERENCE = "https://github.com/jendrikseipp/vulture"
_REACHABILITY_REFERENCE = "docs/reachability.md"
_REFERENCE_RELATIONS = frozenset(
    {"calls", "imports", "imports_from", "depends_on", "references", "uses"}
)
_IMPORT_RELATIONS = frozenset({"imports", "imports_from", "re_exports"})
_MAX_DEAD_CODE = 100
_MAX_ISLANDS = 100
_MAX_CYCLES = 50


def build_structural_synthesis(
    findings: list[Finding], artifacts: dict[str, Any]
) -> dict[str, Any] | None:
    """Cross-reference structural evidence without asserting runtime truth."""
    graph = artifacts.get("graphify.json")
    reachability = artifacts.get("reachability.json")
    if not isinstance(graph, dict) and not isinstance(reachability, dict):
        return None

    graph_index = _graph_index(graph)
    coverage = _coverage_index(artifacts.get("coverage-summary.json"))
    complexity = _complexity_index(artifacts.get("radon-complexity.json"))
    findings_by_path = _findings_by_path(findings)
    reachability_nodes = _reachability_nodes(reachability)

    dead_candidates = [finding for finding in findings if _found_by(finding, "vulture")]
    dead_assessments = [
        _assess_dead_code(
            finding, graph_index, reachability_nodes, coverage, complexity
        )
        for finding in dead_candidates
    ]
    dead_by_path: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for assessment in dead_assessments:
        dead_by_path[str(assessment["path"])].append(assessment)

    raw_islands = (
        reachability.get("islands", []) if isinstance(reachability, dict) else []
    )
    island_assessments = [
        _assess_island(
            island,
            graph_index,
            findings_by_path,
            dead_by_path,
            coverage,
            complexity,
        )
        for island in raw_islands
        if isinstance(island, dict)
    ]
    island_assessments.sort(key=_island_order)

    cycles = _import_cycles(graph_index, findings_by_path, complexity)
    finding_assessments: list[dict[str, Any]] = []
    for assessment, finding in zip(dead_assessments, dead_candidates, strict=True):
        context = {
            key: value
            for key, value in assessment.items()
            if key not in {"finding_id", "title"}
        }
        finding.evidence["structural_synthesis"] = context
        _add_structural_citations(finding)
        finding_assessments.append(
            {"finding_id": finding.finding_id, "kind": "dead-code", **context}
        )

    _attach_island_context(findings, island_assessments, finding_assessments)
    _attach_cycle_context(findings, cycles, finding_assessments)
    leverage = build_structural_leverage(
        findings,
        artifacts,
        island_assessments,
        dead_assessments,
    )

    likely_removable = sum(
        item["disposition"] == "likely-removable" for item in dead_assessments
    )
    likely_dynamic = sum(
        item["disposition"] == "likely-dynamic" for item in dead_assessments
    )
    latent = sum(
        item["classification"] == "latent-attack-surface" for item in island_assessments
    )
    return {
        "schema_version": "1.2",
        "schema_id": "urn:project-py-security-suite:structural-synthesis:1.2",
        "authoritative": False,
        "purpose": (
            "advisory cross-reference of static topology, entry-point reachability, "
            "runtime coverage, case-level test execution, dead-code, complexity, "
            "architecture, and findings"
        ),
        "summary": {
            "dead_code_candidates": len(dead_assessments),
            "likely_removable_dead_code_candidates": likely_removable,
            "likely_dynamic_dead_code_candidates": likely_dynamic,
            "islands_analyzed": len(island_assessments),
            "likely_removable_islands": sum(
                item["classification"] == "likely-removable"
                for item in island_assessments
            ),
            "likely_dynamic_islands": sum(
                item["classification"] == "likely-dynamic"
                for item in island_assessments
            ),
            "latent_attack_surface_islands": latent,
            "import_cycles": len(cycles),
            "architecture_hotspots": sum(
                bool(item["tach_finding_ids"] or item["security_finding_ids"])
                for item in cycles
            ),
            **leverage["summary"],
        },
        "dead_code_assessments": dead_assessments[:_MAX_DEAD_CODE],
        "island_assessments": island_assessments[:_MAX_ISLANDS],
        "import_cycles": cycles[:_MAX_CYCLES],
        "change_impact_assessments": leverage["change_impact_assessments"],
        "orphan_symbol_candidates": leverage["orphan_symbol_candidates"],
        "island_boundary_assessments": leverage["island_boundary_assessments"],
        "finding_assessments": sorted(
            finding_assessments,
            key=lambda item: (str(item["finding_id"]), str(item["kind"])),
        )[:250],
        "truncation": {
            "dead_code_assessments_omitted": max(
                0, len(dead_assessments) - _MAX_DEAD_CODE
            ),
            "island_assessments_omitted": max(
                0, len(island_assessments) - _MAX_ISLANDS
            ),
            "import_cycles_omitted": max(0, len(cycles) - _MAX_CYCLES),
            **leverage["truncation"],
        },
        "interpretation_limits": [
            "Static reachability cannot fully model reflection, registries, plugins, dependency injection, generated code, or framework conventions.",
            "Runtime coverage demonstrates observed execution only; absence of coverage does not prove dead code.",
            "Graph references and import cycles indicate coupling, not exploitability or required behavior.",
            "Graph-mapped tests are prioritized targets, not a complete replacement for integration or system tests.",
            "Passing focused tests describe the scanned state only; coverage alignment must be regenerated after the final change.",
            "A structurally orphaned symbol remains advisory because Python framework, inheritance, and plugin dispatch can be implicit.",
            "Removal requires owner review, focused tests, and a clean isolated rescan.",
        ],
        "references": [
            _GRAPHIFY_REFERENCE,
            _VULTURE_REFERENCE,
            _REACHABILITY_REFERENCE,
        ],
    }


def _assess_dead_code(
    finding: Finding,
    graph: dict[str, Any],
    reachability: dict[str, list[dict[str, Any]]],
    coverage: dict[str, dict[str, Any]],
    complexity: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    location = finding.locations[0] if finding.locations else None
    path = location.path if location is not None else "."
    line = location.start_line if location is not None else None
    nodes = _containing_nodes(reachability.get(path, []), line)
    states = sorted(
        {str(item.get("state")) for item in nodes if isinstance(item.get("state"), str)}
    )
    observations = sorted(
        {
            str(item.get("runtime_observation"))
            for item in nodes
            if isinstance(item.get("runtime_observation"), str)
        }
    )
    graph_node = _nearest_graph_node(graph, path, line, _symbol_hints(finding))
    inbound = _node_references(graph, graph_node, inbound=True)
    outbound = _node_references(graph, graph_node, inbound=False)
    external_file_inbound = sorted(graph["file_incoming"].get(path, set()))[:10]
    coverage_state, coverage_percent = _line_coverage(coverage.get(path), line)

    signals, counter_signals = _dead_code_signals(
        nodes,
        states,
        observations,
        inbound,
        external_file_inbound,
        coverage_state,
    )
    disposition, confidence, action = _dead_code_disposition(
        states,
        observations,
        inbound,
        external_file_inbound,
        coverage_state,
    )

    return {
        "finding_id": finding.finding_id,
        "title": finding.title,
        "path": path,
        "line": line,
        "disposition": disposition,
        "confidence": confidence,
        "signals": signals,
        "counter_signals": counter_signals,
        "reachability_states": states,
        "runtime_observations": observations,
        "coverage_state": coverage_state,
        "coverage_percent": coverage_percent,
        "graph_node_id": graph_node.get("id") if graph_node else None,
        "graph_node_label": graph_node.get("label") if graph_node else None,
        "inbound_symbol_references": inbound[:10],
        "outbound_symbol_references": outbound[:10],
        "external_file_inbound": external_file_inbound,
        "maximum_complexity": complexity.get(path, {}).get("complexity"),
        "maximum_complexity_rank": complexity.get(path, {}).get("rank"),
        "recommended_action": action,
    }


def _dead_code_signals(
    nodes: list[dict[str, Any]],
    states: list[str],
    observations: list[str],
    inbound: list[dict[str, str]],
    external_file_inbound: list[str],
    coverage_state: str,
) -> tuple[list[str], list[str]]:
    signals: list[str] = ["Vulture reported a 100%-confidence static candidate"]
    counter_signals: list[str] = []
    if "disconnected" in states:
        signals.append(
            "entry-point analysis classified the containing scope as disconnected"
        )
    if coverage_state == "uncovered":
        signals.append("runtime coverage did not execute the reported line")
    if not inbound and not external_file_inbound:
        signals.append(
            "Graphify found no bounded inbound reference to the symbol or file"
        )
    if "observed" in observations:
        counter_signals.append("runtime coverage observed the containing scope")
    if any(state in {"executable", "load-only"} for state in states):
        counter_signals.append(
            "entry-point analysis retains the scope as executable or load-only"
        )
    if inbound:
        counter_signals.append("Graphify found inbound symbol references")
    if external_file_inbound:
        counter_signals.append("Graphify found imports or references from other files")
    if not nodes:
        counter_signals.append("no containing reachability node was available")
    if coverage_state == "unknown":
        counter_signals.append("line-level runtime coverage was unavailable")
    return signals, counter_signals


def _dead_code_disposition(
    states: list[str],
    observations: list[str],
    inbound: list[dict[str, str]],
    external_file_inbound: list[str],
    coverage_state: str,
) -> tuple[str, str, str]:
    if "observed" in observations or inbound:
        return (
            "likely-dynamic",
            "medium",
            "Treat the Vulture result as a dynamic-use candidate: inspect callers, registries, callbacks, framework conventions, and the observed test lane before changing code.",
        )
    if "disconnected" in states and coverage_state == "uncovered" and not inbound:
        return (
            "likely-removable",
            "medium" if external_file_inbound else "high",
            "Confirm with the owning team, remove in a focused change, run targeted and production-like tests, then require a clean isolated rescan.",
        )
    if coverage_state == "uncovered" and not inbound:
        return (
            "likely-removable",
            "low" if external_file_inbound else "medium",
            "Review as a removal candidate; first model missing entry points and dynamic framework behavior, then validate removal with focused tests.",
        )
    return (
        "needs-review",
        "low",
        "Resolve the conflicting or missing structural evidence before suppressing the finding or removing code.",
    )


def _assess_island(
    island: dict[str, Any],
    graph: dict[str, Any],
    findings_by_path: dict[str, list[Finding]],
    dead_by_path: dict[str, list[dict[str, Any]]],
    coverage: dict[str, dict[str, Any]],
    complexity: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    paths = _island_paths(island)
    inbound, outbound = _cross_island_edges(paths, graph)
    local_findings = _island_findings(paths, island, findings_by_path)
    security, tach, dead = _island_finding_groups(
        paths, island, local_findings, dead_by_path
    )
    observed = str(island.get("runtime_observation") or "") == "observed"
    state = str(island.get("state") or "disconnected")
    minimum_coverage, maximum_complexity = _island_metrics(paths, coverage, complexity)
    owners = _island_owners(local_findings)
    evidence, counter_evidence = _island_evidence(
        security, dead, inbound, minimum_coverage, observed, state
    )
    classification, action = _classify_island(security, dead, inbound, observed, state)
    loc = int(island.get("lines_of_code") or 0)
    impact_score = _island_impact(security, tach, state, loc, maximum_complexity)
    priority = (
        "high" if impact_score >= 60 else "medium" if impact_score >= 30 else "low"
    )
    return {
        "island_id": str(island.get("id") or "unknown-island"),
        "classification": classification,
        "priority": priority,
        "impact_score": impact_score,
        "state": state,
        "confidence": str(island.get("confidence") or "unknown"),
        "kind": str(island.get("kind") or "unknown"),
        "lines_of_code": loc,
        "paths": paths,
        "primary_path": str(island.get("primary_path") or (paths[0] if paths else ".")),
        "primary_start_line": island.get("primary_start_line"),
        "primary_end_line": island.get("primary_end_line"),
        "runtime_observation": str(island.get("runtime_observation") or "unknown"),
        "reportable": bool(island.get("reportable")),
        "external_inbound_files": inbound[:20],
        "external_outbound_files": outbound[:20],
        "security_finding_ids": security[:25],
        "dead_code_finding_ids": dead[:25],
        "tach_finding_ids": tach[:25],
        "all_finding_ids": sorted(local_findings)[:50],
        "owners": owners[:20],
        "minimum_file_coverage_percent": minimum_coverage,
        "maximum_complexity": maximum_complexity,
        "evidence": evidence,
        "counter_evidence": counter_evidence,
        "recommended_action": action,
    }


def _island_paths(island: dict[str, Any]) -> list[str]:
    return sorted(
        {str(path).replace("\\", "/") for path in island.get("paths", []) if path}
    )


def _cross_island_edges(
    paths: list[str], graph: dict[str, Any]
) -> tuple[list[str], list[str]]:
    path_set = set(paths)
    inbound = {
        source
        for path in paths
        for source in graph["file_incoming"].get(path, set())
        if source not in path_set
    }
    outbound = {
        target
        for path in paths
        for target in graph["file_outgoing"].get(path, set())
        if target not in path_set
    }
    return sorted(inbound), sorted(outbound)


def _island_findings(
    paths: list[str],
    island: dict[str, Any],
    findings_by_path: dict[str, list[Finding]],
) -> dict[str, Finding]:
    return {
        finding.finding_id: finding
        for path in paths
        for finding in findings_by_path.get(path, [])
        if _finding_overlaps_island(finding, island)
    }


def _island_finding_groups(
    paths: list[str],
    island: dict[str, Any],
    local_findings: dict[str, Finding],
    dead_by_path: dict[str, list[dict[str, Any]]],
) -> tuple[list[str], list[str], list[str]]:
    security = sorted(
        finding.finding_id
        for finding in local_findings.values()
        if finding.domain in {"security", "supply-chain"}
    )
    tach = sorted(
        finding.finding_id
        for finding in local_findings.values()
        if _found_by(finding, "tach")
    )
    dead = sorted(
        assessment["finding_id"]
        for path in paths
        for assessment in dead_by_path.get(path, [])
        if _assessment_overlaps_island(assessment, island)
    )
    return security, tach, dead


def _island_metrics(
    paths: list[str],
    coverage: dict[str, dict[str, Any]],
    complexity: dict[str, dict[str, Any]],
) -> tuple[float | None, int | None]:
    coverage_values = [
        float(coverage[path]["percent"])
        for path in paths
        if path in coverage and isinstance(coverage[path].get("percent"), (int, float))
    ]
    maximum_complexity = max(
        (
            int(complexity[path]["complexity"])
            for path in paths
            if isinstance(complexity.get(path, {}).get("complexity"), int)
        ),
        default=None,
    )
    return min(coverage_values) if coverage_values else None, maximum_complexity


def _island_owners(local_findings: dict[str, Finding]) -> list[str]:
    return sorted(
        {
            str(owner)
            for finding in local_findings.values()
            for owner in finding.evidence.get("owners", [])
            if isinstance(finding.evidence.get("owners"), list)
        }
    )


def _island_evidence(
    security: list[str],
    dead: list[str],
    inbound: list[str],
    minimum_coverage: float | None,
    observed: bool,
    state: str,
) -> tuple[list[str], list[str]]:
    evidence: list[str] = []
    counter_evidence: list[str] = []
    if security:
        evidence.append("security or supply-chain findings occur inside the island")
    if dead:
        evidence.append("Vulture dead-code candidates occur inside the island")
    if not inbound:
        evidence.append("Graphify found no cross-island inbound file reference")
    if minimum_coverage == 0:
        evidence.append("at least one island file has zero runtime coverage")
    if observed:
        counter_evidence.append("runtime coverage observed execution inside the island")
    if inbound:
        counter_evidence.append("Graphify found cross-island inbound references")
    if state == "load-only":
        counter_evidence.append("the scope is loaded or referenced from reachable code")
    return evidence, counter_evidence


def _classify_island(
    security: list[str],
    dead: list[str],
    inbound: list[str],
    observed: bool,
    state: str,
) -> tuple[str, str]:
    if security and state in {"disconnected", "load-only"}:
        return (
            "latent-attack-surface",
            "Prioritize security remediation and determine whether the island is a missing production entry point or removable dormant capability.",
        )
    if state == "disconnected" and inbound:
        return (
            "missing-entry-point",
            "Model the Graphify callers, framework registration, or dynamic entry point before treating this island as dead code.",
        )
    if state == "load-only" or observed:
        return (
            "likely-dynamic",
            "Trace registration and callback paths; retain until production-like runtime evidence resolves the static/runtime disagreement.",
        )
    if state == "disconnected" and dead and not inbound:
        return (
            "likely-removable",
            "Review with the owner, remove in a focused change, run targeted tests, and verify the reachability delta on the next isolated scan.",
        )
    return (
        "orphaned-code-review",
        "Establish ownership and intent, add a missing entry point when intentional, or remove after focused regression testing.",
    )


def _island_impact(
    security: list[str],
    tach: list[str],
    state: str,
    loc: int,
    maximum_complexity: int | None,
) -> int:
    return min(
        100,
        (40 if security else 0)
        + (20 if state == "disconnected" else 10)
        + min(25, loc // 40)
        + (15 if maximum_complexity is not None and maximum_complexity >= 20 else 0)
        + (10 if tach else 0),
    )


def _import_cycles(
    graph: dict[str, Any],
    findings_by_path: dict[str, list[Finding]],
    complexity: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    adjacency: dict[str, set[str]] = defaultdict(set)
    for edge in graph["file_edges"]:
        if edge["relation"] in _IMPORT_RELATIONS:
            adjacency[edge["source"]].add(edge["target"])
            adjacency.setdefault(edge["target"], set())
    components = _strongly_connected_components(adjacency)
    cycles: list[dict[str, Any]] = []
    for component in components:
        if len(component) < 2:
            continue
        paths = sorted(component)
        local = {
            finding.finding_id: finding
            for path in paths
            for finding in findings_by_path.get(path, [])
        }
        tach = sorted(
            finding.finding_id
            for finding in local.values()
            if _found_by(finding, "tach")
        )
        security = sorted(
            finding.finding_id
            for finding in local.values()
            if finding.domain in {"security", "supply-chain"}
        )
        internal_edges = sum(
            target in component for source in component for target in adjacency[source]
        )
        maximum_complexity = max(
            (
                int(complexity[path]["complexity"])
                for path in paths
                if isinstance(complexity.get(path, {}).get("complexity"), int)
            ),
            default=None,
        )
        cycles.append(
            {
                "cycle_id": "import-cycle-"
                + hashlib.sha256("\n".join(paths).encode("utf-8")).hexdigest()[:16],
                "paths": paths[:50],
                "file_count": len(paths),
                "internal_edge_count": internal_edges,
                "tach_finding_ids": tach[:25],
                "security_finding_ids": security[:25],
                "all_finding_ids": sorted(local)[:50],
                "maximum_complexity": maximum_complexity,
                "priority": "high"
                if security or tach
                else "medium"
                if len(paths) >= 5
                else "low",
                "recommended_action": (
                    "Break the cycle at a stable dependency boundary; prioritize interfaces "
                    "around files that also carry architecture, security, or complexity evidence."
                ),
            }
        )
    return sorted(
        cycles,
        key=lambda item: (
            {"high": 0, "medium": 1, "low": 2}[str(item["priority"])],
            -int(item["file_count"]),
            str(item["cycle_id"]),
        ),
    )


def _strongly_connected_components(
    adjacency: dict[str, set[str]],
) -> list[set[str]]:
    nodes = set(adjacency)
    for targets in adjacency.values():
        nodes.update(targets)
    reverse: dict[str, set[str]] = defaultdict(set)
    for source in nodes:
        reverse.setdefault(source, set())
        for target in adjacency.get(source, set()):
            reverse[target].add(source)

    visited: set[str] = set()
    finish_order: list[str] = []
    for root in sorted(nodes):
        if root in visited:
            continue
        stack: list[tuple[str, bool]] = [(root, False)]
        while stack:
            node, expanded = stack.pop()
            if expanded:
                finish_order.append(node)
                continue
            if node in visited:
                continue
            visited.add(node)
            stack.append((node, True))
            stack.extend(
                (neighbor, False)
                for neighbor in sorted(adjacency.get(node, set()), reverse=True)
                if neighbor not in visited
            )

    assigned: set[str] = set()
    result: list[set[str]] = []
    for root in reversed(finish_order):
        if root in assigned:
            continue
        component: set[str] = set()
        stack = [(root, False)]
        while stack:
            node, _ = stack.pop()
            if node in assigned:
                continue
            assigned.add(node)
            component.add(node)
            stack.extend(
                (neighbor, False)
                for neighbor in sorted(reverse[node], reverse=True)
                if neighbor not in assigned
            )
        result.append(component)
    return result


def _graph_index(value: Any) -> dict[str, Any]:
    file_edges: list[dict[str, str]] = []
    incoming: dict[str, set[str]] = defaultdict(set)
    outgoing: dict[str, set[str]] = defaultdict(set)
    nodes_by_path: dict[str, list[dict[str, Any]]] = defaultdict(list)
    nodes_by_id: dict[str, dict[str, Any]] = {}
    raw_edges: list[dict[str, Any]] = []
    if not isinstance(value, dict):
        return {
            "file_edges": file_edges,
            "file_incoming": incoming,
            "file_outgoing": outgoing,
            "nodes_by_path": nodes_by_path,
            "nodes_by_id": nodes_by_id,
            "edges": raw_edges,
        }
    topology = value.get("topology", {})
    for raw in topology.get("file_edges", []) if isinstance(topology, dict) else []:
        if not isinstance(raw, dict):
            continue
        source = raw.get("source")
        target = raw.get("target")
        relation = raw.get("relation")
        if (
            not isinstance(source, str)
            or not isinstance(target, str)
            or not isinstance(relation, str)
        ):
            continue
        edge = {"source": source, "target": target, "relation": relation}
        file_edges.append(edge)
        if relation in _REFERENCE_RELATIONS or relation in _IMPORT_RELATIONS:
            outgoing[source].add(target)
            incoming[target].add(source)
    for node in value.get("nodes", []):
        if not isinstance(node, dict) or not isinstance(node.get("id"), str):
            continue
        nodes_by_id[node["id"]] = node
        if isinstance(node.get("path"), str):
            nodes_by_path[node["path"].replace("\\", "/")].append(node)
    raw_edges.extend(
        raw
        for raw in value.get("edges", [])
        if isinstance(raw, dict) and raw.get("relation") in _REFERENCE_RELATIONS
    )
    return {
        "file_edges": file_edges,
        "file_incoming": incoming,
        "file_outgoing": outgoing,
        "nodes_by_path": nodes_by_path,
        "nodes_by_id": nodes_by_id,
        "edges": raw_edges,
    }


def _nearest_graph_node(
    graph: dict[str, Any],
    path: str,
    line: int | None,
    symbol_hints: set[str] | None = None,
) -> dict[str, Any] | None:
    candidates = graph["nodes_by_path"].get(path, [])
    if not candidates:
        return None
    if symbol_hints:
        symbol_matches = [
            node
            for node in candidates
            if _normalized_graph_label(node.get("label")) in symbol_hints
        ]
        if symbol_matches:
            candidates = symbol_matches
    if not isinstance(line, int):
        return candidates[0]
    preceding = [
        node
        for node in candidates
        if isinstance(node.get("line"), int) and int(node["line"]) <= line
    ]
    return (
        max(preceding, key=lambda item: int(item["line"]))
        if preceding
        else candidates[0]
    )


def _symbol_hints(finding: Finding) -> set[str]:
    quoted = re.findall(r"['\"]([A-Za-z_][A-Za-z0-9_.]*)['\"]", finding.description)
    return {
        value.rsplit(".", 1)[-1].casefold().rstrip("()") for value in quoted if value
    }


def _normalized_graph_label(value: Any) -> str:
    return str(value or "").rsplit(".", 1)[-1].casefold().rstrip("()")


def _node_references(
    graph: dict[str, Any], node: dict[str, Any] | None, *, inbound: bool
) -> list[dict[str, str]]:
    if node is None:
        return []
    node_id = node.get("id")
    result: list[dict[str, str]] = []
    for edge in graph["edges"]:
        if (edge.get("target") if inbound else edge.get("source")) != node_id:
            continue
        other_id = edge.get("source") if inbound else edge.get("target")
        other = graph["nodes_by_id"].get(other_id, {})
        result.append(
            {
                "relation": str(edge.get("relation") or "unknown"),
                "node_id": str(other_id or "unknown"),
                "path": str(other.get("path") or edge.get("path") or "."),
                "label": str(other.get("label") or other_id or "unknown"),
            }
        )
    return sorted(
        result, key=lambda item: (item["path"], item["label"], item["relation"])
    )


def _reachability_nodes(value: Any) -> dict[str, list[dict[str, Any]]]:
    result: dict[str, list[dict[str, Any]]] = defaultdict(list)
    if not isinstance(value, dict):
        return result
    for node in value.get("nodes", []):
        if isinstance(node, dict) and isinstance(node.get("path"), str):
            result[node["path"].replace("\\", "/")].append(node)
    return result


def _containing_nodes(
    nodes: list[dict[str, Any]], line: int | None
) -> list[dict[str, Any]]:
    if not isinstance(line, int):
        return nodes[:1]
    containing = [
        node
        for node in nodes
        if isinstance(node.get("start_line"), int)
        and isinstance(node.get("end_line"), int)
        and int(node["start_line"]) <= line <= int(node["end_line"])
    ]
    if containing:
        return sorted(
            containing,
            key=lambda item: int(item["end_line"]) - int(item["start_line"]),
        )
    return []


def _coverage_index(value: Any) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    if not isinstance(value, dict):
        return result
    for item in value.get("files", []):
        if not isinstance(item, dict) or not isinstance(item.get("path"), str):
            continue
        summary = item.get("summary", {})
        percent = summary.get("percent_covered") if isinstance(summary, dict) else None
        result[item["path"].replace("\\", "/")] = {
            "percent": float(percent)
            if isinstance(percent, (int, float)) and not isinstance(percent, bool)
            else None,
            "missing_lines": {
                int(line)
                for line in item.get("missing_lines", [])
                if isinstance(line, int) and not isinstance(line, bool)
            },
            "executed_lines": {
                int(line)
                for line in item.get("executed_lines", [])
                if isinstance(line, int) and not isinstance(line, bool)
            },
        }
    return result


def _line_coverage(
    item: dict[str, Any] | None, line: int | None
) -> tuple[str, float | None]:
    if not isinstance(item, dict):
        return "unknown", None
    percent = item.get("percent")
    if isinstance(line, int) and line in item.get("missing_lines", set()):
        return "uncovered", percent
    if isinstance(line, int) and line in item.get("executed_lines", set()):
        return "covered", percent
    if percent == 0:
        return "uncovered", percent
    return "unknown", percent


def _complexity_index(value: Any) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    if not isinstance(value, dict) or not isinstance(value.get("files"), dict):
        return result
    for raw_path, blocks in value["files"].items():
        candidates = _complexity_blocks(blocks) if isinstance(blocks, list) else []
        candidates = [
            item for item in candidates if isinstance(item.get("complexity"), int)
        ]
        if candidates:
            maximum = max(candidates, key=lambda item: int(item["complexity"]))
            result[str(raw_path).replace("\\", "/")] = {
                "complexity": int(maximum["complexity"]),
                "rank": str(maximum.get("rank") or ""),
            }
    return result


def _complexity_blocks(blocks: list[Any]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for item in blocks:
        if not isinstance(item, dict):
            continue
        result.append(item)
        for key in ("methods", "closures"):
            if isinstance(item.get(key), list):
                result.extend(_complexity_blocks(item[key]))
    return result


def _findings_by_path(findings: list[Finding]) -> dict[str, list[Finding]]:
    result: dict[str, list[Finding]] = defaultdict(list)
    for finding in findings:
        for location in finding.locations:
            if location.path not in {".", "<outside-target>"}:
                result[location.path.replace("\\", "/")].append(finding)
    return result


def _found_by(finding: Finding, tool: str) -> bool:
    return any(source.tool == tool for source in finding.sources)


def _finding_overlaps_island(finding: Finding, island: dict[str, Any]) -> bool:
    primary_path = island.get("primary_path")
    start, end = island.get("primary_start_line"), island.get("primary_end_line")
    for location in finding.locations:
        if (
            location.path != primary_path
            or not isinstance(start, int)
            or not isinstance(end, int)
        ):
            return True
        if location.start_line is None or start <= location.start_line <= end:
            return True
    return False


def _assessment_overlaps_island(
    assessment: dict[str, Any], island: dict[str, Any]
) -> bool:
    if assessment["path"] != island.get("primary_path"):
        return True
    start, end, line = (
        island.get("primary_start_line"),
        island.get("primary_end_line"),
        assessment.get("line"),
    )
    if (
        not isinstance(start, int)
        or not isinstance(end, int)
        or not isinstance(line, int)
    ):
        return True
    return start <= line <= end


def _attach_island_context(
    findings: list[Finding],
    islands: list[dict[str, Any]],
    result: list[dict[str, Any]],
) -> None:
    by_id = {finding.finding_id: finding for finding in findings}
    for island in islands:
        for finding_id in island["all_finding_ids"]:
            finding = by_id.get(finding_id)
            if finding is None:
                continue
            current = finding.evidence.setdefault("structural_synthesis", {})
            current["island"] = {
                key: island[key]
                for key in (
                    "island_id",
                    "classification",
                    "priority",
                    "impact_score",
                    "state",
                    "lines_of_code",
                    "runtime_observation",
                    "external_inbound_files",
                    "security_finding_ids",
                    "dead_code_finding_ids",
                    "recommended_action",
                )
            }
            _add_structural_citations(finding)
            result.append(
                {
                    "finding_id": finding_id,
                    "kind": "island",
                    **current["island"],
                }
            )


def _attach_cycle_context(
    findings: list[Finding],
    cycles: list[dict[str, Any]],
    result: list[dict[str, Any]],
) -> None:
    by_id = {finding.finding_id: finding for finding in findings}
    for cycle in cycles:
        for finding_id in cycle["all_finding_ids"]:
            finding = by_id.get(finding_id)
            if finding is None:
                continue
            current = finding.evidence.setdefault("structural_synthesis", {})
            current["import_cycle"] = {
                key: cycle[key]
                for key in (
                    "cycle_id",
                    "paths",
                    "file_count",
                    "tach_finding_ids",
                    "security_finding_ids",
                    "maximum_complexity",
                    "priority",
                    "recommended_action",
                )
            }
            _add_structural_citations(finding)
            result.append(
                {
                    "finding_id": finding_id,
                    "kind": "import-cycle",
                    **current["import_cycle"],
                }
            )


def _add_structural_citations(finding: Finding) -> None:
    existing = {citation.identifier for citation in finding.citations}
    for identifier, title, uri in (
        (
            "graphify-code-graph",
            "Graphify deterministic code graph context",
            _GRAPHIFY_REFERENCE,
        ),
        (
            "suite-reachability-model",
            "Suite entry-point and runtime reachability model",
            _REACHABILITY_REFERENCE,
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


def _island_order(item: dict[str, Any]) -> tuple[int, int, int, str]:
    return (
        {"high": 0, "medium": 1, "low": 2}.get(str(item["priority"]), 3),
        -int(item["impact_score"]),
        -int(item["lines_of_code"]),
        str(item["island_id"]),
    )
