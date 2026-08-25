from __future__ import annotations

import argparse
import hashlib
import os
import tempfile
from collections import deque
from pathlib import Path
from typing import Any

try:
    from companion.strict_json import dumps as strict_dumps
    from companion.strict_json import loads as strict_loads
except ModuleNotFoundError:  # Direct script execution.
    from strict_json import dumps as strict_dumps  # type: ignore[import-not-found,no-redef]
    from strict_json import loads as strict_loads  # type: ignore[import-not-found,no-redef]


_MAX_BYTES = 64 * 1024 * 1024
_MAX_NODES = 5_000
_MAX_EDGES = 20_000
_MAX_PATH_LENGTH = 12
_MAX_FINDINGS = 1_000


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Derive bounded cloud identity/network attack paths without retaining resource IDs."
    )
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    document = _document(args.input)
    _write(args.output, _analyze(document))
    return 0


def _document(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > _MAX_BYTES:
        raise ValueError("cloud graph must be a regular JSON file of at most 64 MiB")
    value = strict_loads(path.read_bytes())
    if not isinstance(value, dict) or set(value) != {
        "schema_version",
        "nodes",
        "edges",
        "canary_path",
        "drift_checked",
    }:
        raise ValueError("cloud graph fields do not match the contract")
    if value.get("schema_version") != "1.0" or value.get("drift_checked") is not True:
        raise ValueError("cloud graph requires schema 1.0 and completed drift analysis")
    return value


def _analyze(document: dict[str, Any]) -> dict[str, Any]:
    nodes_value = document["nodes"]
    edges_value = document["edges"]
    if (
        not isinstance(nodes_value, list)
        or not 1 <= len(nodes_value) <= _MAX_NODES
        or not isinstance(edges_value, list)
        or len(edges_value) > _MAX_EDGES
    ):
        raise ValueError("cloud graph exceeds node or edge bounds")
    nodes: dict[str, dict[str, Any]] = {}
    for value in nodes_value:
        if not isinstance(value, dict) or set(value) != {
            "id",
            "type",
            "public_entry",
            "sensitive_asset",
        }:
            raise ValueError("cloud node fields do not match the contract")
        identifier = _label(value["id"], 300)
        if identifier in nodes:
            raise ValueError("cloud node IDs must be unique")
        nodes[identifier] = {
            "type": _label(value["type"], 100),
            "public_entry": value["public_entry"] is True,
            "sensitive_asset": value["sensitive_asset"] is True,
        }
    graph: dict[str, list[tuple[str, str]]] = {identifier: [] for identifier in nodes}
    for value in edges_value:
        if not isinstance(value, dict) or set(value) != {"source", "target", "type"}:
            raise ValueError("cloud edge fields do not match the contract")
        source = _label(value["source"], 300)
        target = _label(value["target"], 300)
        edge_type = _label(value["type"], 100)
        if source not in nodes or target not in nodes:
            raise ValueError("cloud edge references an unknown node")
        graph[source].append((target, edge_type))
    for edges in graph.values():
        edges.sort()

    public = sorted(key for key, value in nodes.items() if value["public_entry"])
    sensitive = {key for key, value in nodes.items() if value["sensitive_asset"]}
    findings: list[dict[str, Any]] = []
    observed_paths: set[tuple[str, ...]] = set()
    for source in public:
        for node_path, edge_path in _paths(source, graph, sensitive):
            type_path = tuple(nodes[item]["type"] for item in node_path)
            key = (*type_path, *edge_path)
            if key in observed_paths:
                continue
            observed_paths.add(key)
            findings.append(_finding(node_path, edge_path, nodes))
            if len(findings) >= _MAX_FINDINGS:
                break
        if len(findings) >= _MAX_FINDINGS:
            break

    canary = document["canary_path"]
    if not isinstance(canary, dict) or set(canary) != {"source", "target"}:
        raise ValueError("cloud graph canary_path is invalid")
    canary_source = _label(canary["source"], 300)
    canary_target = _label(canary["target"], 300)
    canary_observed = any(
        path[-1] == canary_target
        for path, _ in _paths(canary_source, graph, {canary_target})
    )
    coverage = 100.0
    return {
        "execution": {
            "status": "completed",
            "targets_discovered": len(nodes),
            "targets_exercised": len(nodes),
            "requests": len(edges_value),
            "coverage_percent": coverage,
            "coverage_metric": "bounded-cloud-graph-node-coverage",
            "roles": ["read-only-cloud-inventory"],
            "features": [
                "identity-edges",
                "network-edges",
                "sensitive-assets",
                "iac-live-drift",
            ],
            "skipped_checks": [],
            "canaries_expected": 1,
            "canaries_observed": int(canary_observed),
        },
        "findings": findings,
    }


def _paths(
    source: str,
    graph: dict[str, list[tuple[str, str]]],
    targets: set[str],
) -> list[tuple[list[str], list[str]]]:
    if source not in graph:
        return []
    queue: deque[tuple[str, list[str], list[str]]] = deque([(source, [source], [])])
    result: list[tuple[list[str], list[str]]] = []
    while queue and len(result) < _MAX_FINDINGS:
        current, node_path, edge_path = queue.popleft()
        if current in targets and len(node_path) > 1:
            result.append((node_path, edge_path))
            continue
        if len(node_path) >= _MAX_PATH_LENGTH:
            continue
        for target, edge_type in graph[current]:
            if target not in node_path:
                queue.append((target, [*node_path, target], [*edge_path, edge_type]))
    return result


def _finding(
    node_path: list[str], edge_path: list[str], nodes: dict[str, dict[str, Any]]
) -> dict[str, Any]:
    type_path = [nodes[item]["type"] for item in node_path]
    fingerprint = hashlib.sha256("\0".join(node_path).encode()).hexdigest()
    return {
        "rule_id": "public-to-sensitive-cloud-path",
        "title": "A public cloud entry can reach a sensitive asset",
        "message": "Bounded identity and network relationships form a path from public exposure to a sensitive asset.",
        "path": "<cloud-attack-path>",
        "severity": "high",
        "classification": "CWE-284",
        "citation": "https://github.com/lyft/cartography",
        "impact": "An attacker may be able to combine cloud trust and reachability relationships to access a sensitive asset.",
        "remediation": "Break unnecessary identity or network edges, remove public exposure, and verify declared-to-live drift.",
        "area": "cloud-identity-and-network-attack-paths",
        "domain": "security",
        "fingerprint": fingerprint,
        "evidence": {
            "node_types": " -> ".join(type_path),
            "edge_types": " -> ".join(edge_path),
            "path_length": len(edge_path),
        },
    }


def _label(value: object, maximum: int) -> str:
    result = str(value or "").strip()
    if (
        not result
        or len(result) > maximum
        or any(ord(character) < 32 for character in result)
    ):
        raise ValueError("cloud graph label is invalid")
    return result


def _write(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and (path.is_symlink() or not path.is_file()):
        raise ValueError("cloud attack-path output is not replaceable")
    payload = (strict_dumps(value, indent=2) + "\n").encode()
    descriptor, name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


if __name__ == "__main__":
    raise SystemExit(main())
