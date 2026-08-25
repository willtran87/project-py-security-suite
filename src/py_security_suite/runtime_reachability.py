from __future__ import annotations

import hashlib
from typing import Any

from .strict_json import canonical_bytes


def apply_runtime_trace_observations(
    reachability: object,
    runtime_trace: dict[str, Any],
    boundary_graph: dict[str, Any],
) -> dict[str, Any]:
    """Apply deployment-authenticated trace observations to exact static nodes."""

    result = {
        "complete": False,
        "trace_count": 0,
        "python_trace_count": 0,
        "matched_trace_count": 0,
        "observed_node_ids": [],
        "unmatched_edge_sha256": [],
    }
    if not isinstance(reachability, dict) or runtime_trace.get("complete") is not True:
        return result
    nodes = reachability.get("nodes")
    traces = runtime_trace.get("traces")
    if not isinstance(nodes, list) or not isinstance(traces, list):
        return result
    edges = {
        hashlib.sha256(canonical_bytes(edge)).hexdigest(): edge
        for edge in boundary_graph.get("edges") or []
        if isinstance(edge, dict)
    }
    observed: set[str] = set()
    unmatched: list[str] = []
    python_traces = 0
    matched_traces = 0
    for trace in traces:
        if not isinstance(trace, dict):
            continue
        edge_digest = str(trace.get("edge_sha256") or "")
        edge = edges.get(edge_digest)
        if not isinstance(edge, dict) or not str(edge.get("source") or "").endswith(
            ".py"
        ):
            continue
        python_traces += 1
        path = str(edge.get("source") or "")
        line = edge.get("line")
        matches = [
            node
            for node in nodes
            if isinstance(node, dict)
            and node.get("path") == path
            and isinstance(line, int)
            and int(node.get("start_line") or 0)
            <= line
            <= int(node.get("end_line") or 0)
        ]
        if not matches:
            unmatched.append(edge_digest)
            continue
        matched_traces += 1
        for node in matches:
            node["runtime_observation"] = "observed"
            observed.add(str(node.get("id") or ""))
    _refresh_summary(reachability)
    result.update(
        {
            "complete": not unmatched,
            "trace_count": len(traces),
            "python_trace_count": python_traces,
            "matched_trace_count": matched_traces,
            "observed_node_ids": sorted(observed),
            "unmatched_edge_sha256": sorted(set(unmatched)),
        }
    )
    return result


def _refresh_summary(document: dict[str, Any]) -> None:
    nodes = [item for item in document.get("nodes") or [] if isinstance(item, dict)]
    summary = document.get("summary")
    if not isinstance(summary, dict):
        return
    for state, key in (
        ("executable", "observed_executable_nodes"),
        ("load-only", "observed_load_only_nodes"),
    ):
        summary[key] = sum(
            item.get("state") == state and item.get("runtime_observation") == "observed"
            for item in nodes
        )
    summary["unobserved_executable_nodes"] = sum(
        item.get("state") == "executable"
        and item.get("runtime_observation") == "not-observed"
        for item in nodes
    )
