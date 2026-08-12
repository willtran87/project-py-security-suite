from __future__ import annotations

from collections import defaultdict, deque
from typing import Any

from .models import Citation, Finding


_IMPACT_RELATIONS = frozenset(
    {"calls", "imports", "imports_from", "references", "uses"}
)
_SYMBOL_REFERENCE_RELATIONS = frozenset({"calls", "references", "uses"})
_MAX_CHANGE_IMPACTS = 100
_MAX_ORPHANS = 100
_MAX_BOUNDARIES = 100
_MAX_NEIGHBORS = 200


def build_structural_leverage(
    findings: list[Finding],
    artifacts: dict[str, Any],
    island_assessments: list[dict[str, Any]],
    dead_code_assessments: list[dict[str, Any]],
) -> dict[str, Any]:
    """Build bounded second-order structural conclusions from normalized evidence."""
    graph = _graph_index(artifacts.get("graphify.json"))
    reachability = _reachability_index(artifacts.get("reachability.json"))
    coverage = _coverage_index(artifacts.get("coverage-summary.json"))
    complexity = _complexity_index(artifacts.get("radon-complexity.json"))
    findings_by_path = _findings_by_path(findings)

    changes = _change_impacts(
        artifacts.get("diff-coverage.json"),
        graph,
        findings_by_path,
        coverage,
        complexity,
    )
    orphans = _orphan_symbols(
        graph,
        reachability,
        coverage,
        dead_code_assessments,
    )
    boundaries = _island_boundaries(island_assessments, graph)
    _attach_change_context(findings, changes)
    _attach_boundary_context(findings, boundaries)

    unique_tests = {
        test
        for item in changes
        for key in (
            "direct_test_files",
            "transitive_test_files",
            "associated_test_files",
        )
        for test in item[key]
    }
    return {
        "change_impact_assessments": changes[:_MAX_CHANGE_IMPACTS],
        "orphan_symbol_candidates": orphans[:_MAX_ORPHANS],
        "island_boundary_assessments": boundaries[:_MAX_BOUNDARIES],
        "summary": {
            "changed_python_files_analyzed": len(changes),
            "changed_files_without_mapped_tests": sum(
                not item["direct_test_files"]
                and not item["transitive_test_files"]
                and not item["associated_test_files"]
                for item in changes
            ),
            "changed_files_with_uncovered_lines": sum(
                bool(item["uncovered_changed_lines"]) for item in changes
            ),
            "high_priority_change_hotspots": sum(
                item["priority"] == "high" for item in changes
            ),
            "recommended_test_files": len(unique_tests),
            "orphan_symbol_candidates": len(orphans),
            "islands_with_boundary_evidence": sum(
                bool(item["inbound_edges"] or item["outbound_edges"])
                for item in boundaries
            ),
            "candidate_missing_entry_points": sum(
                item["boundary_classification"] == "candidate-missing-entry-point"
                for item in boundaries
            ),
            "test_only_island_candidates": sum(
                item["boundary_classification"] == "test-only-or-fixture"
                for item in boundaries
            ),
        },
        "truncation": {
            "change_impact_assessments_omitted": max(
                0, len(changes) - _MAX_CHANGE_IMPACTS
            ),
            "orphan_symbol_candidates_omitted": max(0, len(orphans) - _MAX_ORPHANS),
            "island_boundary_assessments_omitted": max(
                0, len(boundaries) - _MAX_BOUNDARIES
            ),
        },
    }


def _change_impacts(
    value: Any,
    graph: dict[str, Any],
    findings_by_path: dict[str, list[Finding]],
    coverage: dict[str, dict[str, Any]],
    complexity: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    stats = value.get("src_stats") if isinstance(value, dict) else None
    if not isinstance(stats, dict):
        return []
    result: list[dict[str, Any]] = []
    for raw_path, raw_stat in stats.items():
        path = _path(raw_path)
        if (
            not path.endswith(".py")
            or _is_test_path(path)
            or not isinstance(raw_stat, dict)
        ):
            continue
        covered = _integer_set(raw_stat.get("covered_lines"))
        uncovered = _integer_set(raw_stat.get("violation_lines"))
        changed = covered | uncovered
        if not changed:
            continue
        direct_tests, transitive_tests = _mapped_tests(path, graph["incoming"])
        associated_tests = _associated_tests(
            path, graph, direct_tests, transitive_tests
        )
        upstream = _walk(graph["incoming"], path)
        downstream = _walk(graph["outgoing"], path)
        local_findings = findings_by_path.get(path, [])
        security = sorted(
            finding.finding_id
            for finding in local_findings
            if finding.domain in {"security", "supply-chain"}
        )
        all_findings = sorted(finding.finding_id for finding in local_findings)
        percent = _number(raw_stat.get("percent_covered"))
        risk_score = _change_risk_score(
            changed=len(changed),
            uncovered=len(uncovered),
            test_mapping=(
                "direct"
                if direct_tests
                else "transitive"
                if transitive_tests
                else "associated"
                if associated_tests
                else "none"
            ),
            upstream=len(upstream),
            security=bool(security),
            complexity=complexity.get(path, {}).get("complexity"),
        )
        classification, action = _change_classification(
            direct_tests,
            transitive_tests,
            associated_tests,
            uncovered,
            upstream,
        )
        coverage_percent = coverage.get(path, {}).get("percent")
        result.append(
            {
                "path": path,
                "classification": classification,
                "priority": _priority(risk_score),
                "risk_score": risk_score,
                "changed_lines": len(changed),
                "covered_changed_lines": len(covered),
                "uncovered_changed_lines": sorted(uncovered)[:100],
                "changed_line_coverage_percent": percent,
                "file_coverage_percent": coverage_percent,
                "direct_test_files": direct_tests[:25],
                "transitive_test_files": transitive_tests[:25],
                "associated_test_files": associated_tests[:25],
                "test_selection_confidence": (
                    "high" if direct_tests else "medium" if transitive_tests else "low"
                ),
                "two_hop_upstream_files": len(upstream),
                "two_hop_downstream_files": len(downstream),
                "upstream_files": sorted(upstream)[:25],
                "downstream_files": sorted(downstream)[:25],
                "finding_ids": all_findings[:25],
                "security_finding_ids": security[:25],
                "maximum_complexity": complexity.get(path, {}).get("complexity"),
                "maximum_complexity_rank": complexity.get(path, {}).get("rank"),
                "recommended_action": action,
            }
        )
    return sorted(
        result,
        key=lambda item: (-int(item["risk_score"]), str(item["path"])),
    )


def _change_risk_score(
    *,
    changed: int,
    uncovered: int,
    test_mapping: str,
    upstream: int,
    security: bool,
    complexity: Any,
) -> int:
    uncovered_ratio = uncovered / changed if changed else 0.0
    return min(
        100,
        {"direct": 0, "transitive": 5, "associated": 10, "none": 30}[test_mapping]
        + round(uncovered_ratio * 30)
        + min(20, upstream * 2)
        + (15 if security else 0)
        + (10 if isinstance(complexity, int) and complexity >= 20 else 0),
    )


def _change_classification(
    direct_tests: list[str],
    transitive_tests: list[str],
    associated_tests: list[str],
    uncovered: set[int],
    upstream: set[str],
) -> tuple[str, str]:
    if not direct_tests and not transitive_tests and not associated_tests:
        return (
            "changed-without-mapped-tests",
            "Identify or add focused tests for the changed behavior; Graphify found no bounded test dependency path.",
        )
    if associated_tests and not direct_tests and not transitive_tests:
        test_text = ", ".join(associated_tests[:5])
        return (
            "package-surface-change",
            f"Run the associated tests ({test_text}) and add a focused import/API-contract test when the package surface changed intentionally.",
        )
    tests = direct_tests or transitive_tests
    test_text = ", ".join(tests[:5])
    if uncovered:
        return (
            "changed-lines-under-tested",
            f"Run and extend the mapped tests ({test_text}) until the cited changed lines are covered, then regenerate coverage evidence.",
        )
    if len(upstream) >= 10:
        return (
            "high-blast-radius-change",
            f"Run the mapped tests ({test_text}) and broader integration tests because the changed file has a wide static upstream neighborhood.",
        )
    return (
        "changed-with-targeted-tests",
        f"Prioritize the graph-mapped tests ({test_text}); retain the broader suite for dynamic paths that static analysis cannot see.",
    )


def _orphan_symbols(
    graph: dict[str, Any],
    reachability: dict[str, list[dict[str, Any]]],
    coverage: dict[str, dict[str, Any]],
    dead_code_assessments: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    referenced = {
        str(edge["target"])
        for edge in graph["raw_edges"]
        if edge.get("relation") in _SYMBOL_REFERENCE_RELATIONS
        and isinstance(edge.get("target"), str)
    }
    dead_by_location = {
        (_path(item.get("path")), item.get("line")): str(item.get("finding_id"))
        for item in dead_code_assessments
        if isinstance(item, dict)
    }
    result: list[dict[str, Any]] = []
    for node in graph["nodes"]:
        node_id = node.get("id")
        path = _path(node.get("path"))
        line = node.get("line")
        label = str(node.get("label") or "")
        if not _orphan_node_candidate(node, referenced, path, line, label):
            continue
        scopes = _containing_nodes(reachability.get(path, []), line)
        states = sorted(
            {
                str(item["state"])
                for item in scopes
                if isinstance(item.get("state"), str)
            }
        )
        observations = sorted(
            {
                str(item["runtime_observation"])
                for item in scopes
                if isinstance(item.get("runtime_observation"), str)
            }
        )
        coverage_state = _line_coverage(coverage.get(path), line)
        if (
            not scopes
            or "observed" in observations
            or coverage_state != "uncovered"
            or not any(state in {"load-only", "disconnected"} for state in states)
        ):
            continue
        vulture_id = dead_by_location.get((path, line))
        file_inbound = sorted(graph["incoming"].get(path, set()))[:20]
        classification, confidence = _orphan_classification(
            states, vulture_id, file_inbound
        )
        result.append(
            {
                "node_id": str(node_id),
                "label": label,
                "path": path,
                "line": line,
                "classification": classification,
                "confidence": confidence,
                "reachability_states": states,
                "runtime_observations": observations,
                "coverage_state": coverage_state,
                "external_file_inbound": file_inbound,
                "vulture_finding_id": vulture_id,
                "recommended_action": (
                    "Model framework, registry, inheritance, and plugin use; when none applies, remove in a focused change with graph-mapped tests and a clean reachability delta."
                ),
            }
        )
    return sorted(
        result,
        key=lambda item: (
            {"high": 0, "medium": 1, "low": 2}[str(item["confidence"])],
            str(item["path"]),
            int(item["line"]),
        ),
    )


def _orphan_node_candidate(
    node: dict[str, Any],
    referenced: set[str],
    path: str,
    line: Any,
    label: str,
) -> bool:
    normalized = label.casefold().rstrip("()")
    return (
        bool(node.get("callable"))
        and isinstance(node.get("id"), str)
        and node["id"] not in referenced
        and path.endswith(".py")
        and not _is_test_path(path)
        and isinstance(line, int)
        and not normalized.startswith(".__")
        and normalized not in {"main", "application", "app"}
    )


def _orphan_classification(
    states: list[str], vulture_id: str | None, file_inbound: list[str]
) -> tuple[str, str]:
    if vulture_id and "disconnected" in states and not file_inbound:
        return "corroborated-dead-code", "high"
    if vulture_id:
        return "corroborated-dead-code", "medium"
    if "disconnected" in states:
        return "disconnected-structural-orphan", "medium"
    return "unobserved-load-only-orphan", "low"


def _island_boundaries(
    islands: list[dict[str, Any]], graph: dict[str, Any]
) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for island in islands:
        paths = {_path(value) for value in island.get("paths", [])}
        inbound = _boundary_edges(paths, graph["file_edges"], inbound=True)
        outbound = _boundary_edges(paths, graph["file_edges"], inbound=False)
        tests = sorted(
            {edge["source"] for edge in inbound if _is_test_path(str(edge["source"]))}
        )
        production_roots = sorted(
            {
                edge["source"]
                for edge in inbound
                if not _is_test_path(str(edge["source"]))
            }
        )
        classification = _boundary_classification(
            str(island.get("state") or "disconnected"),
            inbound,
            tests,
            production_roots,
            str(island.get("runtime_observation") or "unknown"),
        )
        result.append(
            {
                "island_id": str(island.get("island_id") or "unknown-island"),
                "boundary_classification": classification,
                "paths": sorted(paths),
                "inbound_edges": inbound[:50],
                "outbound_edges": outbound[:50],
                "candidate_entry_paths": production_roots[:25],
                "direct_test_files": tests[:25],
                "boundary_relation_count": len(inbound) + len(outbound),
                "recommended_action": _boundary_action(classification),
            }
        )
    return sorted(result, key=lambda item: str(item["island_id"]))


def _boundary_edges(
    paths: set[str], file_edges: list[dict[str, Any]], *, inbound: bool
) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for edge in file_edges:
        source, target = _path(edge.get("source")), _path(edge.get("target"))
        crosses = (
            target in paths and source not in paths
            if inbound
            else source in paths and target not in paths
        )
        if crosses:
            result.append(
                {
                    "source": source,
                    "target": target,
                    "relation": str(edge.get("relation") or "unknown"),
                    "count": int(edge.get("count") or 1),
                }
            )
    return sorted(
        result,
        key=lambda item: (
            str(item["source"]),
            str(item["target"]),
            str(item["relation"]),
        ),
    )


def _boundary_classification(
    state: str,
    inbound: list[dict[str, Any]],
    tests: list[str],
    production_roots: list[str],
    observation: str,
) -> str:
    if state == "disconnected" and inbound and tests and not production_roots:
        return "test-only-or-fixture"
    if state == "disconnected" and production_roots:
        return "candidate-missing-entry-point"
    if observation == "observed":
        return "runtime-model-gap"
    if not inbound:
        return "closed-boundary"
    return "referenced-boundary"


def _boundary_action(classification: str) -> str:
    return {
        "test-only-or-fixture": "Confirm the code is intentionally test-only; move fixtures under an explicit test scope or model the production root.",
        "candidate-missing-entry-point": "Inspect the concrete inbound paths and add the missing production root or remove the orphaned integration.",
        "runtime-model-gap": "Use the observed runtime lane to model the unresolved callback, registry, plugin, or framework edge.",
        "closed-boundary": "Validate dynamic loading and ownership before treating the island as removable.",
        "referenced-boundary": "Review the concrete boundary relations and determine whether they represent executable or load-only use.",
    }[classification]


def _attach_change_context(
    findings: list[Finding], changes: list[dict[str, Any]]
) -> None:
    by_path = {str(item["path"]): item for item in changes}
    for finding in findings:
        if not finding.locations:
            continue
        change = by_path.get(_path(finding.locations[0].path))
        if change is None:
            continue
        structural = finding.evidence.setdefault("structural_synthesis", {})
        structural["change_impact"] = {
            key: change[key]
            for key in (
                "classification",
                "priority",
                "risk_score",
                "uncovered_changed_lines",
                "direct_test_files",
                "transitive_test_files",
                "associated_test_files",
                "test_selection_confidence",
                "two_hop_upstream_files",
                "recommended_action",
            )
        }
        _add_citation(
            finding,
            "graph-guided-test-selection",
            "Graphify and diff-cover change-impact correlation",
            "https://github.com/Bachmann1234/diff-cover",
        )


def _attach_boundary_context(
    findings: list[Finding], boundaries: list[dict[str, Any]]
) -> None:
    by_id = {finding.finding_id: finding for finding in findings}
    island_findings: dict[str, set[str]] = defaultdict(set)
    for finding in findings:
        structural = finding.evidence.get("structural_synthesis")
        island = structural.get("island") if isinstance(structural, dict) else None
        if isinstance(island, dict) and isinstance(island.get("island_id"), str):
            island_findings[island["island_id"]].add(finding.finding_id)
    for boundary in boundaries:
        for finding_id in island_findings.get(str(boundary["island_id"]), set()):
            finding = by_id[finding_id]
            structural = finding.evidence.setdefault("structural_synthesis", {})
            structural["island_boundary"] = {
                key: boundary[key]
                for key in (
                    "boundary_classification",
                    "candidate_entry_paths",
                    "direct_test_files",
                    "inbound_edges",
                    "recommended_action",
                )
            }


def _add_citation(finding: Finding, identifier: str, title: str, uri: str) -> None:
    if any(item.identifier == identifier for item in finding.citations):
        return
    finding.citations.append(
        Citation(
            kind="supporting_evidence",
            identifier=identifier,
            title=title,
            uri=uri,
        )
    )


def _graph_index(value: Any) -> dict[str, Any]:
    incoming: dict[str, set[str]] = defaultdict(set)
    outgoing: dict[str, set[str]] = defaultdict(set)
    file_edges: list[dict[str, Any]] = []
    nodes: list[dict[str, Any]] = []
    raw_edges: list[dict[str, Any]] = []
    if not isinstance(value, dict):
        return {
            "incoming": incoming,
            "outgoing": outgoing,
            "file_edges": file_edges,
            "nodes": nodes,
            "raw_edges": raw_edges,
        }
    topology = value.get("topology")
    for edge in topology.get("file_edges", []) if isinstance(topology, dict) else []:
        if not isinstance(edge, dict):
            continue
        source, target, relation = (
            edge.get("source"),
            edge.get("target"),
            edge.get("relation"),
        )
        if (
            not isinstance(source, str)
            or not isinstance(target, str)
            or not isinstance(relation, str)
        ):
            continue
        normalized: dict[str, Any] = {
            "source": _path(source),
            "target": _path(target),
            "relation": relation,
            "count": int(edge.get("count") or 1),
        }
        file_edges.append(normalized)
        if relation in _IMPACT_RELATIONS:
            outgoing[normalized["source"]].add(normalized["target"])
            incoming[normalized["target"]].add(normalized["source"])
    nodes.extend(item for item in value.get("nodes", []) if isinstance(item, dict))
    raw_edges.extend(item for item in value.get("edges", []) if isinstance(item, dict))
    return {
        "incoming": incoming,
        "outgoing": outgoing,
        "file_edges": file_edges,
        "nodes": nodes,
        "raw_edges": raw_edges,
    }


def _mapped_tests(
    path: str, incoming: dict[str, set[str]]
) -> tuple[list[str], list[str]]:
    direct = sorted(item for item in incoming.get(path, set()) if _is_test_path(item))
    all_upstream = _walk(incoming, path)
    transitive = sorted(
        item for item in all_upstream if _is_test_path(item) and item not in direct
    )
    return direct, transitive


def _associated_tests(
    path: str,
    graph: dict[str, Any],
    direct_tests: list[str],
    transitive_tests: list[str],
) -> list[str]:
    """Map package-surface files to tests of the modules they expose.

    This is intentionally reported separately from dependency-path evidence:
    the tests share an exported/imported target with the changed package file,
    but do not necessarily import the package surface itself.
    """
    if not path.endswith("/__init__.py"):
        return []
    exported = {
        str(edge["target"])
        for edge in graph["file_edges"]
        if edge.get("source") == path
        and edge.get("relation") in {"imports", "imports_from", "re_exports"}
    }
    excluded = set(direct_tests) | set(transitive_tests)
    associated: set[str] = set()
    for target in sorted(exported):
        associated.update(
            item for item in graph["incoming"].get(target, set()) if _is_test_path(item)
        )
        associated.update(
            item for item in _walk(graph["incoming"], target) if _is_test_path(item)
        )
        if len(associated) >= 25:
            break
    return sorted(associated - excluded)[:25]


def _walk(adjacency: dict[str, set[str]], root: str) -> set[str]:
    result: set[str] = set()
    queue = deque([(root, 0)])
    while queue and len(result) < _MAX_NEIGHBORS:
        current, depth = queue.popleft()
        if depth >= 2:
            continue
        for neighbor in sorted(adjacency.get(current, set())):
            if neighbor == root or neighbor in result:
                continue
            result.add(neighbor)
            queue.append((neighbor, depth + 1))
    return result


def _reachability_index(value: Any) -> dict[str, list[dict[str, Any]]]:
    result: dict[str, list[dict[str, Any]]] = defaultdict(list)
    if not isinstance(value, dict):
        return result
    for node in value.get("nodes", []):
        if isinstance(node, dict) and isinstance(node.get("path"), str):
            result[_path(node["path"])].append(node)
    return result


def _containing_nodes(nodes: list[dict[str, Any]], line: Any) -> list[dict[str, Any]]:
    if not isinstance(line, int):
        return []
    return [
        node
        for node in nodes
        if isinstance(node.get("start_line"), int)
        and isinstance(node.get("end_line"), int)
        and int(node["start_line"]) <= line <= int(node["end_line"])
    ]


def _coverage_index(value: Any) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    if not isinstance(value, dict):
        return result
    for item in value.get("files", []):
        if not isinstance(item, dict) or not isinstance(item.get("path"), str):
            continue
        raw_summary = item.get("summary")
        summary: dict[str, Any] = raw_summary if isinstance(raw_summary, dict) else {}
        result[_path(item["path"])] = {
            "percent": _number(summary.get("percent_covered")),
            "missing_lines": _integer_set(item.get("missing_lines")),
            "executed_lines": _integer_set(item.get("executed_lines")),
        }
    return result


def _line_coverage(item: dict[str, Any] | None, line: Any) -> str:
    if not isinstance(item, dict) or not isinstance(line, int):
        return "unknown"
    if line in item.get("missing_lines", set()) or item.get("percent") == 0:
        return "uncovered"
    if line in item.get("executed_lines", set()):
        return "covered"
    return "unknown"


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
            result[_path(raw_path)] = {
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
            result[_path(location.path)].append(finding)
    return result


def _integer_set(value: Any) -> set[int]:
    if not isinstance(value, list):
        return set()
    return {
        item
        for item in value
        if isinstance(item, int) and not isinstance(item, bool) and item > 0
    }


def _number(value: Any) -> float | None:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return round(float(value), 2)
    return None


def _path(value: Any) -> str:
    return str(value or ".").replace("\\", "/").lstrip("./") or "."


def _is_test_path(path: str) -> bool:
    normalized = _path(path).casefold()
    name = normalized.rsplit("/", 1)[-1]
    return (
        normalized.startswith("tests/")
        or "/tests/" in normalized
        or name.startswith("test_")
        or name.endswith("_test.py")
    )


def _priority(score: int) -> str:
    return "high" if score >= 60 else "medium" if score >= 30 else "low"
