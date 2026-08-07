from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .execution import sha256_file
from .path_safety import resolve_regular_file

_MAX_GRAPH_BYTES = 128 * 1024 * 1024
_MAX_CHANGES = 200
_STATE_RANK = {"executable": 2, "load-only": 1, "disconnected": 0}


def compare_reachability(
    baseline: Path,
    current: Path,
    *,
    baseline_sha256: str,
    current_sha256: str,
) -> dict[str, Any]:
    """Compare two digest-bound reachability graphs without executing target code."""
    before = _graph(baseline, baseline_sha256, "baseline reachability graph")
    after = _graph(current, current_sha256, "current reachability graph")
    before_nodes = _nodes(before)
    after_nodes = _nodes(after)
    added = sorted(set(after_nodes) - set(before_nodes))
    removed = sorted(set(before_nodes) - set(after_nodes))
    shared = sorted(set(before_nodes) & set(after_nodes))
    regressions = [
        _transition(identifier, before_nodes[identifier], after_nodes[identifier])
        for identifier in shared
        if _STATE_RANK[after_nodes[identifier]["state"]]
        < _STATE_RANK[before_nodes[identifier]["state"]]
    ]
    improvements = [
        _transition(identifier, before_nodes[identifier], after_nodes[identifier])
        for identifier in shared
        if _STATE_RANK[after_nodes[identifier]["state"]]
        > _STATE_RANK[before_nodes[identifier]["state"]]
    ]
    new_disconnected = [
        _node_summary(identifier, after_nodes[identifier])
        for identifier in added
        if after_nodes[identifier]["state"] == "disconnected"
    ]
    lost_runtime_observation = [
        _transition(identifier, before_nodes[identifier], after_nodes[identifier])
        for identifier in shared
        if before_nodes[identifier]["runtime_observation"] == "observed"
        and after_nodes[identifier]["runtime_observation"] != "observed"
    ]
    reportable_before = _reportable_islands(before)
    reportable_after = _reportable_islands(after)
    new_reportable = sorted(reportable_after - reportable_before)
    blocking = bool(regressions or new_disconnected or new_reportable)
    return {
        "schema_version": "1.0",
        "verdict": "regression" if blocking else "pass",
        "scope": (
            "Digest-bound static reachability comparison. A passing delta does not "
            "prove runtime reachability or safe deletion."
        ),
        "baseline": _identity(before, baseline, baseline_sha256),
        "current": _identity(after, current, current_sha256),
        "counts": {
            "added_nodes": len(added),
            "removed_nodes": len(removed),
            "state_regressions": len(regressions),
            "state_improvements": len(improvements),
            "new_disconnected_nodes": len(new_disconnected),
            "lost_runtime_observations": len(lost_runtime_observation),
            "new_reportable_islands": len(new_reportable),
        },
        "changes": {
            "state_regressions": regressions[:_MAX_CHANGES],
            "state_improvements": improvements[:_MAX_CHANGES],
            "new_disconnected_nodes": new_disconnected[:_MAX_CHANGES],
            "lost_runtime_observations": lost_runtime_observation[:_MAX_CHANGES],
            "new_reportable_island_ids": new_reportable[:_MAX_CHANGES],
        },
        "omitted": {
            "state_regressions": max(0, len(regressions) - _MAX_CHANGES),
            "state_improvements": max(0, len(improvements) - _MAX_CHANGES),
            "new_disconnected_nodes": max(0, len(new_disconnected) - _MAX_CHANGES),
            "lost_runtime_observations": max(
                0, len(lost_runtime_observation) - _MAX_CHANGES
            ),
            "new_reportable_islands": max(0, len(new_reportable) - _MAX_CHANGES),
        },
    }


def _graph(path: Path, expected_digest: str, label: str) -> dict[str, Any]:
    source = resolve_regular_file(path, label)
    if source.stat().st_size > _MAX_GRAPH_BYTES:
        raise ValueError(f"{label} exceeds {_MAX_GRAPH_BYTES} bytes")
    digest = sha256_file(source)
    if digest != expected_digest.casefold():
        raise ValueError(f"{label} does not match the approved SHA-256")
    document = json.loads(source.read_bytes())
    if not isinstance(document, dict):
        raise TypeError(f"{label} root must be an object")
    if document.get("schema_version") not in {"1.1", "1.2"}:
        raise ValueError(f"{label} uses an unsupported schema version")
    return document


def _nodes(document: dict[str, Any]) -> dict[str, dict[str, str]]:
    values = document.get("nodes")
    if not isinstance(values, list):
        raise TypeError("reachability graph nodes must be an array")
    nodes: dict[str, dict[str, str]] = {}
    for value in values:
        if not isinstance(value, dict):
            raise TypeError("reachability graph nodes must be objects")
        identifier = str(value.get("id") or "")
        state = str(value.get("state") or "")
        if not identifier or len(identifier) > 1000 or identifier in nodes:
            raise ValueError("reachability node identifiers must be unique and bounded")
        if state not in _STATE_RANK:
            raise ValueError("reachability node state is invalid")
        nodes[identifier] = {
            "state": state,
            "path": str(value.get("path") or ""),
            "runtime_observation": str(
                value.get("runtime_observation") or "not-measured"
            ),
        }
    return nodes


def _reportable_islands(document: dict[str, Any]) -> set[str]:
    values = document.get("islands")
    if not isinstance(values, list):
        raise TypeError("reachability graph islands must be an array")
    return {
        str(value.get("id") or "")
        for value in values
        if isinstance(value, dict)
        and value.get("reportable") is True
        and value.get("id")
    }


def _transition(
    identifier: str, before: dict[str, str], after: dict[str, str]
) -> dict[str, str]:
    return {
        "id": identifier,
        "path": after["path"] or before["path"],
        "before": before["state"],
        "after": after["state"],
    }


def _node_summary(identifier: str, node: dict[str, str]) -> dict[str, str]:
    return {"id": identifier, "path": node["path"], "state": node["state"]}


def _identity(document: dict[str, Any], path: Path, digest: str) -> dict[str, Any]:
    summary = document.get("summary")
    nodes = int(summary.get("nodes") or 0) if isinstance(summary, dict) else 0
    return {
        "path": str(path.expanduser().resolve()),
        "sha256": digest.casefold(),
        "graph_sha256": str(document.get("analysis", {}).get("graph_sha256") or "")
        if isinstance(document.get("analysis"), dict)
        else "",
        "nodes": nodes,
    }
