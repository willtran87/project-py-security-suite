from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any

from ..models import Finding, normalize_repo_path
from .file_output import JsonFileScannerAdapter
from .staging import maintained_files


_LINE = re.compile(r"(?:^|:)L(?P<line>\d+)(?:$|[-:])")
_MAX_NODES = 250_000
_MAX_EDGES = 750_000
_MAX_TEXT = 4_096


class GraphifyAdapter(JsonFileScannerAdapter):
    """Collect a deterministic, local code-property graph from Graphify."""

    name = "graphify"
    output_filename = "graphify-out/graph.json"

    def not_applicable_reason(self, target: Path) -> str | None:
        if not maintained_files(target, frozenset({".py"})):
            return "no Python source files were found"
        return None

    def build_file_command(
        self, executable: str, target: Path, output: Path
    ) -> list[str]:
        # A fresh temporary parent is supplied by JsonFileScannerAdapter. The
        # code-only pass is Tree-sitter based and does not invoke an LLM.
        return [
            executable,
            "extract",
            str(target.resolve()),
            "--code-only",
            "--no-cluster",
            "--out",
            str(output.parents[1]),
            "--max-workers",
            "1",
        ]

    def parse(self, payload: str, target: Path) -> list[Finding]:
        _normalized_document(payload, target)
        return []

    def derived_artifacts(self, payload: str, target: Path) -> dict[str, Any]:
        return {"graphify.json": _normalized_document(payload, target)}


def _normalized_document(payload: str, target: Path) -> dict[str, Any]:
    document = json.loads(payload)
    if not isinstance(document, dict):
        raise TypeError("Graphify output must be an object")
    nodes = _list(document, "nodes", _MAX_NODES)
    edges = _list(document, "edges", _MAX_EDGES)
    hyperedges = _list(document, "hyperedges", _MAX_EDGES)
    input_tokens = _nonnegative_integer(document.get("input_tokens", 0), "input_tokens")
    output_tokens = _nonnegative_integer(
        document.get("output_tokens", 0), "output_tokens"
    )
    if input_tokens or output_tokens:
        raise ValueError("Graphify code-only output unexpectedly records model tokens")
    if hyperedges:
        raise ValueError("Graphify code-only output unexpectedly contains hyperedges")

    normalized_nodes: list[dict[str, Any]] = []
    node_paths: dict[str, str] = {}
    node_labels: dict[str, str] = {}
    seen_ids: set[str] = set()
    for raw in nodes:
        item = _object(raw, "node")
        node_id = _text(item.get("id"), "node id")
        if node_id in seen_ids:
            raise ValueError(f"duplicate Graphify node id: {node_id[:80]}")
        seen_ids.add(node_id)
        _ast_origin(item, "node")
        path = _path(target, item.get("source_file"))
        label = _text(item.get("label", node_id), "node label")
        line = _line(item.get("source_location"))
        node_paths[node_id] = path
        node_labels[node_id] = label
        normalized_nodes.append(
            {
                "id": node_id,
                "label": label,
                "path": path,
                "line": line,
                "kind": _optional_text(item.get("file_type")),
                "callable": bool(item.get("_callable", False)),
            }
        )

    normalized_edges: list[dict[str, Any]] = []
    relations: Counter[str] = Counter()
    confidences: Counter[str] = Counter()
    file_edges: Counter[tuple[str, str, str]] = Counter()
    degrees: Counter[str] = Counter()
    file_degrees: Counter[str] = Counter()
    for raw in edges:
        item = _object(raw, "edge")
        _ast_origin(item, "edge")
        source = _text(item.get("source"), "edge source")
        target_id = _text(item.get("target"), "edge target")
        edge_path = _path(target, item.get("source_file"))
        # Graphify intentionally uses implicit package/external endpoints for
        # some dependency edges. Preserve them as explicit bounded placeholders
        # so the normalized graph remains closed and independently consumable.
        if source not in seen_ids:
            _add_placeholder_node(
                source,
                edge_path,
                seen_ids,
                node_paths,
                node_labels,
                normalized_nodes,
            )
        if target_id not in seen_ids:
            _add_placeholder_node(
                target_id,
                ".",
                seen_ids,
                node_paths,
                node_labels,
                normalized_nodes,
            )
        relation = _text(item.get("relation"), "edge relation")
        confidence = _text(
            item.get("confidence", "EXTRACTED"), "edge confidence"
        ).upper()
        if confidence not in {"EXTRACTED", "INFERRED", "AMBIGUOUS"}:
            raise ValueError(f"unsupported Graphify confidence: {confidence}")
        path = edge_path
        normalized_edges.append(
            {
                "source": source,
                "target": target_id,
                "relation": relation,
                "confidence": confidence,
                "path": path,
                "line": _line(item.get("source_location")),
            }
        )
        relations[relation] += 1
        confidences[confidence] += 1
        degrees[source] += 1
        degrees[target_id] += 1
        source_path = node_paths[source]
        target_path = node_paths[target_id]
        if source_path != "." and target_path != "." and source_path != target_path:
            file_edges[(source_path, target_path, relation)] += 1
            file_degrees[source_path] += 1
            file_degrees[target_path] += 1

    top_nodes = [
        {
            "id": node_id,
            "label": node_labels[node_id],
            "path": node_paths[node_id],
            "degree": degree,
        }
        for node_id, degree in degrees.most_common(50)
    ]
    top_files = [
        {"path": path, "degree": degree}
        for path, degree in file_degrees.most_common(50)
    ]
    return {
        "schema_version": "1.0",
        "schema_id": "urn:project-py-security-suite:graphify-evidence:1.0",
        "tool": "graphify",
        "authoritative": False,
        "mode": {
            "code_only": True,
            "clustering": False,
            "model_calls": False,
            "target_execution": False,
        },
        "source_sha256": hashlib.sha256(payload.encode("utf-8")).hexdigest(),
        "summary": {
            "nodes": len(normalized_nodes),
            "edges": len(normalized_edges),
            "hyperedges": 0,
            "files": len({value for value in node_paths.values() if value != "."}),
            "callable_nodes": sum(bool(item["callable"]) for item in normalized_nodes),
            "relations": dict(sorted(relations.items())),
            "confidence": dict(sorted(confidences.items())),
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
        },
        "nodes": normalized_nodes,
        "edges": normalized_edges,
        "topology": {
            "top_nodes": top_nodes,
            "top_files": top_files,
            "file_edges": [
                {
                    "source": source,
                    "target": destination,
                    "relation": relation,
                    "count": count,
                }
                for (source, destination, relation), count in sorted(file_edges.items())
            ],
        },
    }


def _list(document: dict[str, Any], key: str, maximum: int) -> list[Any]:
    value = document.get(key, [])
    if not isinstance(value, list):
        raise TypeError(f"Graphify {key} must be a list")
    if len(value) > maximum:
        raise ValueError(f"Graphify {key} exceeds the bounded item limit")
    return value


def _object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise TypeError(f"Graphify {label} must be an object")
    return value


def _text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise TypeError(f"Graphify {label} must be a non-empty string")
    if len(value) > _MAX_TEXT:
        raise ValueError(f"Graphify {label} exceeds the text limit")
    return value.strip()


def _optional_text(value: Any) -> str | None:
    if value is None:
        return None
    return _text(value, "text")


def _nonnegative_integer(value: Any, label: str) -> int:
    if isinstance(value, bool):
        raise TypeError(f"Graphify {label} must be an integer")
    try:
        result = int(value)
    except (TypeError, ValueError) as exc:
        raise TypeError(f"Graphify {label} must be an integer") from exc
    if result < 0:
        raise ValueError(f"Graphify {label} must be non-negative")
    return result


def _ast_origin(item: dict[str, Any], label: str) -> None:
    origin = item.get("_origin", "ast")
    if origin != "ast":
        raise ValueError(f"Graphify {label} is not deterministic AST evidence")


def _path(target: Path, value: Any) -> str:
    if value in (None, ""):
        return "."
    path = normalize_repo_path(target, _text(value, "source path"))
    if path == "<outside-target>":
        raise ValueError("Graphify source path escapes the scan target")
    return path


def _line(value: Any) -> int | None:
    if value in (None, ""):
        return None
    text = _text(value, "source location")
    match = _LINE.search(text)
    return int(match.group("line")) if match else None


def _add_placeholder_node(
    node_id: str,
    path: str,
    seen_ids: set[str],
    node_paths: dict[str, str],
    node_labels: dict[str, str],
    normalized_nodes: list[dict[str, Any]],
) -> None:
    if len(normalized_nodes) >= _MAX_NODES:
        raise ValueError("Graphify synthesized endpoints exceed the node limit")
    seen_ids.add(node_id)
    node_paths[node_id] = path
    node_labels[node_id] = node_id
    normalized_nodes.append(
        {
            "id": node_id,
            "label": node_id,
            "path": path,
            "line": None,
            "kind": "external",
            "callable": False,
        }
    )
