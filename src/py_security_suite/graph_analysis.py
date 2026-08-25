from __future__ import annotations

from collections import defaultdict, deque
from typing import Any

from .models import Citation, Finding


_GRAPHIFY_REFERENCE = "https://graphify.com/docs/cli"
_IMPACT_RELATIONS = frozenset(
    {"calls", "imports", "imports_from", "depends_on", "references", "uses"}
)


def apply_graph_context(
    findings: list[Finding], artifacts: dict[str, Any]
) -> dict[str, Any] | None:
    """Join scanner findings to Graphify topology without changing severity."""
    graph = artifacts.get("graphify.json")
    if not isinstance(graph, dict) or graph.get("schema_version") != "1.0":
        return None
    topology = graph.get("topology")
    if not isinstance(topology, dict):
        return None

    outgoing: dict[str, set[str]] = defaultdict(set)
    incoming: dict[str, set[str]] = defaultdict(set)
    for raw in topology.get("file_edges", []):
        if not isinstance(raw, dict) or raw.get("relation") not in _IMPACT_RELATIONS:
            continue
        source, target = raw.get("source"), raw.get("target")
        if isinstance(source, str) and isinstance(target, str):
            outgoing[source].add(target)
            incoming[target].add(source)

    file_degrees = {
        item["path"]: int(item["degree"])
        for item in topology.get("top_files", [])
        if isinstance(item, dict)
        and isinstance(item.get("path"), str)
        and isinstance(item.get("degree"), int)
    }
    maximum_degree = max(file_degrees.values(), default=0)
    known_paths = set(file_degrees) | set(outgoing) | set(incoming)
    coverage = _coverage_index(artifacts.get("coverage-summary.json"), known_paths)
    reachability = _reachability_index(artifacts.get("reachability.json"), known_paths)
    complexity = _complexity_index(artifacts.get("radon-complexity.json"), known_paths)
    findings_by_path: dict[str, list[Finding]] = defaultdict(list)
    for finding in findings:
        for location in finding.locations:
            if location.path not in {".", "<outside-target>"}:
                findings_by_path[location.path].append(finding)

    contexts: list[dict[str, Any]] = []
    for finding in findings:
        if not finding.locations:
            continue
        path = finding.locations[0].path
        if path in {".", "<outside-target>"}:
            continue
        upstream = _walk(incoming, path)
        downstream = _walk(outgoing, path)
        related = _related_findings(
            finding, findings_by_path, {path, *upstream, *downstream}
        )
        degree = file_degrees.get(path, len(incoming[path]) + len(outgoing[path]))
        percentile = (
            round((degree / maximum_degree) * 100, 1) if maximum_degree else 0.0
        )
        context = {
            "path": path,
            "degree": degree,
            "centrality_percent_of_max": percentile,
            "direct_upstream_files": sorted(incoming[path])[:10],
            "direct_downstream_files": sorted(outgoing[path])[:10],
            "two_hop_upstream_count": len(upstream),
            "two_hop_downstream_count": len(downstream),
            "related_finding_ids": related[:10],
            "corroborating_evidence": {
                "coverage_percent": coverage.get(path),
                "reachability_states": reachability.get(path, {}).get("states", []),
                "runtime_observations": reachability.get(path, {}).get(
                    "runtime_observations", []
                ),
                "maximum_complexity": complexity.get(path, {}).get("complexity"),
                "maximum_complexity_rank": complexity.get(path, {}).get("rank"),
                "neighboring_scanners": _neighboring_tools(
                    findings_by_path, {path, *upstream, *downstream}
                ),
                "owners": _owners(finding),
            },
            "interpretation": _interpretation(
                degree,
                percentile,
                len(upstream),
                coverage.get(path),
                complexity.get(path, {}).get("rank"),
            ),
        }
        finding.evidence["graph_context"] = context
        if not any(
            citation.identifier == "graphify-code-graph"
            for citation in finding.citations
        ):
            finding.citations.append(
                Citation(
                    kind="supporting_evidence",
                    identifier="graphify-code-graph",
                    title="Graphify deterministic code graph context",
                    uri=_GRAPHIFY_REFERENCE,
                )
            )
        contexts.append({"finding_id": finding.finding_id, **context})

    clusters = _clusters(findings_by_path, outgoing, incoming)
    top_files = topology.get("top_files", [])
    structural_hotspots = _structural_hotspots(
        top_files, findings_by_path, coverage, reachability, complexity
    )
    return {
        "schema_version": "1.0",
        "schema_id": "urn:project-py-security-suite:graph-analysis:1.0",
        "authoritative": False,
        "purpose": "triage context; does not prove runtime reachability or exploitability",
        "graph_summary": graph.get("summary", {}),
        "finding_contexts": sorted(
            contexts,
            key=lambda item: (
                -int(item["two_hop_upstream_count"]),
                -int(item["degree"]),
                str(item["finding_id"]),
            ),
        ),
        "cross_tool_clusters": clusters,
        "structural_hotspots": structural_hotspots,
        "references": [_GRAPHIFY_REFERENCE],
    }


def _walk(adjacency: dict[str, set[str]], root: str) -> set[str]:
    visited: set[str] = set()
    queue = deque([(root, 0)])
    while queue and len(visited) < 100:
        current, depth = queue.popleft()
        if depth >= 2:
            continue
        for neighbor in sorted(adjacency[current]):
            if neighbor == root or neighbor in visited:
                continue
            visited.add(neighbor)
            queue.append((neighbor, depth + 1))
    return visited


def _related_findings(
    finding: Finding,
    findings_by_path: dict[str, list[Finding]],
    neighborhood: set[str],
) -> list[str]:
    related = {
        candidate.finding_id
        for path in neighborhood
        for candidate in findings_by_path[path]
        if candidate.finding_id != finding.finding_id
    }
    return sorted(related)


def _clusters(
    findings_by_path: dict[str, list[Finding]],
    outgoing: dict[str, set[str]],
    incoming: dict[str, set[str]],
) -> list[dict[str, Any]]:
    clusters: list[dict[str, Any]] = []
    for path in sorted(findings_by_path):
        neighborhood = {path, *outgoing[path], *incoming[path]}
        members = {
            finding.finding_id
            for member_path in neighborhood
            for finding in findings_by_path[member_path]
        }
        tools = {
            source.tool
            for member_path in neighborhood
            for finding in findings_by_path[member_path]
            for source in finding.sources
        }
        if len(members) >= 2 and len(tools) >= 2:
            clusters.append(
                {
                    "anchor_path": path,
                    "finding_ids": sorted(members)[:25],
                    "tools": sorted(tools),
                    "neighboring_files": sorted(neighborhood)[:25],
                }
            )
    unique = {item["anchor_path"]: item for item in clusters}
    return sorted(
        unique.values(),
        key=lambda item: (
            -len(item["tools"]),
            -len(item["finding_ids"]),
            item["anchor_path"],
        ),
    )[:25]


def _interpretation(
    degree: int,
    percentile: float,
    upstream: int,
    coverage: float | None,
    complexity_rank: Any,
) -> str:
    if coverage is not None and coverage < 80 and (percentile >= 50 or upstream >= 5):
        return "central graph neighborhood has a test-coverage gap; prioritize validation and regression tests"
    if str(complexity_rank or "").upper() in {"D", "E", "F"} and degree:
        return "connected graph neighborhood also has elevated complexity; reduce risk before broad changes"
    if percentile >= 75 or upstream >= 10:
        return "high-change-impact graph neighborhood; prioritize validation and regression tests"
    if degree:
        return "connected graph neighborhood; review adjacent callers and dependencies"
    return "no bounded cross-file impact path was established in the static graph"


def _coverage_index(value: Any, known_paths: set[str]) -> dict[str, float]:
    if not isinstance(value, dict) or not isinstance(value.get("files"), list):
        return {}
    result: dict[str, float] = {}
    for item in value["files"]:
        if not isinstance(item, dict) or not isinstance(item.get("summary"), dict):
            continue
        path = _match_path(item.get("path"), known_paths)
        percent = item["summary"].get("percent_covered")
        if (
            path is not None
            and isinstance(percent, (int, float))
            and not isinstance(percent, bool)
        ):
            result[path] = round(float(percent), 2)
    return result


def _reachability_index(
    value: Any, known_paths: set[str]
) -> dict[str, dict[str, list[str]]]:
    if not isinstance(value, dict) or not isinstance(value.get("nodes"), list):
        return {}
    states: dict[str, set[str]] = defaultdict(set)
    observations: dict[str, set[str]] = defaultdict(set)
    for item in value["nodes"]:
        if not isinstance(item, dict):
            continue
        path = _match_path(item.get("path"), known_paths)
        if path is None:
            continue
        state = item.get("state")
        observation = item.get("runtime_observation")
        if isinstance(state, str):
            states[path].add(state)
        if isinstance(observation, str):
            observations[path].add(observation)
    return {
        path: {
            "states": sorted(states[path]),
            "runtime_observations": sorted(observations[path]),
        }
        for path in states.keys() | observations.keys()
    }


def _complexity_index(value: Any, known_paths: set[str]) -> dict[str, dict[str, Any]]:
    if not isinstance(value, dict) or not isinstance(value.get("files"), dict):
        return {}
    result: dict[str, dict[str, Any]] = {}
    for raw_path, blocks in value["files"].items():
        path = _match_path(raw_path, known_paths)
        if path is None or not isinstance(blocks, list):
            continue
        candidates = [
            item
            for item in _complexity_blocks(blocks)
            if isinstance(item.get("complexity"), int)
        ]
        if candidates:
            maximum = max(candidates, key=lambda item: int(item["complexity"]))
            result[path] = {
                "complexity": int(maximum["complexity"]),
                "rank": str(maximum.get("rank") or ""),
                "symbol": str(maximum.get("name") or ""),
            }
    return result


def _complexity_blocks(blocks: list[Any]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for item in blocks:
        if not isinstance(item, dict):
            continue
        result.append(item)
        for key in ("methods", "closures"):
            nested = item.get(key, [])
            if isinstance(nested, list):
                result.extend(_complexity_blocks(nested))
    return result


def _match_path(value: Any, known_paths: set[str]) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.replace("\\", "/").lstrip("./")
    if normalized in known_paths:
        return normalized
    matches = [path for path in known_paths if normalized.endswith("/" + path)]
    return max(matches, key=len) if matches else None


def _neighboring_tools(
    findings_by_path: dict[str, list[Finding]], neighborhood: set[str]
) -> list[str]:
    return sorted(
        {
            source.tool
            for path in neighborhood
            for finding in findings_by_path[path]
            for source in finding.sources
        }
    )


def _owners(finding: Finding) -> list[str]:
    values = finding.evidence.get("owners", [])
    return sorted(str(value) for value in values) if isinstance(values, list) else []


def _structural_hotspots(
    top_files: Any,
    findings_by_path: dict[str, list[Finding]],
    coverage: dict[str, float],
    reachability: dict[str, dict[str, list[str]]],
    complexity: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    if not isinstance(top_files, list):
        return []
    result: list[dict[str, Any]] = []
    for item in top_files[:25]:
        if not isinstance(item, dict) or not isinstance(item.get("path"), str):
            continue
        path = item["path"]
        local = findings_by_path[path]
        result.append(
            {
                "path": path,
                "degree": int(item.get("degree", 0)),
                "finding_ids": sorted(finding.finding_id for finding in local),
                "tools": sorted(
                    {source.tool for finding in local for source in finding.sources}
                ),
                "coverage_percent": coverage.get(path),
                "reachability_states": reachability.get(path, {}).get("states", []),
                "maximum_complexity": complexity.get(path, {}).get("complexity"),
                "maximum_complexity_rank": complexity.get(path, {}).get("rank"),
            }
        )
    return result
