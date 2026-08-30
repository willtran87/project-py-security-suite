from __future__ import annotations

import argparse
import ast
import json
import tomllib
from pathlib import Path
from typing import Any

from scripts.validate_architecture_cycles import _cyclic_components, _graph
from scripts.validate_architecture_limits import (
    _DECISION_NODES,
    _FILE_LINE_LIMITS,
    _FUNCTION_DECISION_LIMITS,
    _FUNCTION_LINE_LIMITS,
)


_ROOT = Path(__file__).resolve().parents[1]


def build_architecture_assurance() -> dict[str, Any]:
    """Produce machine-readable evidence from the enforced architecture ratchets."""

    document = tomllib.loads((_ROOT / "tach.toml").read_text(encoding="utf-8"))
    graph = _graph(document)
    parsed: dict[str, ast.Module] = {}

    def tree(relative: str) -> ast.Module:
        if relative not in parsed:
            parsed[relative] = ast.parse(
                (_ROOT / relative).read_text(encoding="utf-8"), filename=relative
            )
        return parsed[relative]

    files = []
    for relative, limit in sorted(_FILE_LINE_LIMITS.items()):
        observed = len((_ROOT / relative).read_text(encoding="utf-8").splitlines())
        files.append(
            {"path": relative, "observed_lines": observed, "maximum_lines": limit}
        )
    functions = []
    keys = sorted(set(_FUNCTION_LINE_LIMITS) | set(_FUNCTION_DECISION_LIMITS))
    for relative, name in keys:
        matches = [
            node
            for node in ast.walk(tree(relative))
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name == name
        ]
        if len(matches) != 1:
            raise ValueError(f"expected exactly one {relative}:{name}")
        function = matches[0]
        observed_lines = (function.end_lineno or function.lineno) - function.lineno + 1
        observed_decisions = sum(
            isinstance(node, _DECISION_NODES) for node in ast.walk(function)
        )
        functions.append(
            {
                "path": relative,
                "function": name,
                "observed_lines": observed_lines,
                "maximum_lines": _FUNCTION_LINE_LIMITS.get((relative, name)),
                "observed_decisions": observed_decisions,
                "maximum_decisions": _FUNCTION_DECISION_LIMITS.get((relative, name)),
            }
        )
    cycles = [sorted(component) for component in _cyclic_components(graph)]
    cycles.sort()
    return {
        "schema_version": "1.0",
        "module_boundaries": len(graph),
        "dependency_edges": sum(len(items) for items in graph.values()),
        "cyclic_components": cycles,
        "concentration": {"files": files, "functions": functions},
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path)
    arguments = parser.parse_args()
    result = build_architecture_assurance()
    rendered = json.dumps(result, indent=2, sort_keys=True)
    if arguments.output is not None:
        arguments.output.parent.mkdir(parents=True, exist_ok=True)
        arguments.output.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
