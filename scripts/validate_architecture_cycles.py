from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Any


_ROOT = Path(__file__).resolve().parents[1]
_CONFIG = _ROOT / "tach.toml"
_MINIMUM_MODULE_BOUNDARIES = 148
_ALLOWED_CYCLES = {
    frozenset(
        {
            "py_security_suite.checkpoint_authority",
            "py_security_suite.execution",
            "py_security_suite.failure_domain",
            "py_security_suite.operation_receipt",
            "py_security_suite.pinned_command",
            "py_security_suite.trusted_observation",
            "py_security_suite.trusted_time",
        }
    ),
}


def _cyclic_components(graph: dict[str, set[str]]) -> set[frozenset[str]]:
    index = 0
    indices: dict[str, int] = {}
    lowlinks: dict[str, int] = {}
    stack: list[str] = []
    active: set[str] = set()
    components: set[frozenset[str]] = set()

    def visit(node: str) -> None:
        nonlocal index
        indices[node] = index
        lowlinks[node] = index
        index += 1
        stack.append(node)
        active.add(node)
        for dependency in sorted(graph.get(node, set())):
            if dependency not in graph:
                continue
            if dependency not in indices:
                visit(dependency)
                lowlinks[node] = min(lowlinks[node], lowlinks[dependency])
            elif dependency in active:
                lowlinks[node] = min(lowlinks[node], indices[dependency])
        if lowlinks[node] != indices[node]:
            return
        component: set[str] = set()
        while stack:
            member = stack.pop()
            active.remove(member)
            component.add(member)
            if member == node:
                break
        if len(component) > 1 or node in graph.get(node, set()):
            components.add(frozenset(component))

    for node in sorted(graph):
        if node not in indices:
            visit(node)
    return components


def _graph(document: dict[str, Any]) -> dict[str, set[str]]:
    modules = document.get("modules")
    if not isinstance(modules, list):
        raise ValueError("tach configuration has no module boundaries")
    graph: dict[str, set[str]] = {}
    for module in modules:
        if not isinstance(module, dict):
            raise ValueError("tach module boundary is invalid")
        path = module.get("path")
        dependencies = module.get("depends_on")
        if (
            not isinstance(path, str)
            or not isinstance(dependencies, list)
            or any(not isinstance(item, str) for item in dependencies)
            or path in graph
        ):
            raise ValueError("tach module boundary is invalid or duplicated")
        graph[path] = set(dependencies)
    return graph


def main() -> int:
    document = tomllib.loads(_CONFIG.read_text(encoding="utf-8"))
    graph = _graph(document)
    failures: list[str] = []
    if document.get("exact") is not True or document.get("root_module") != "forbid":
        failures.append("Tach must enforce exact dependencies and forbid root leakage")
    if len(graph) < _MINIMUM_MODULE_BOUNDARIES:
        failures.append(
            f"module-boundary coverage regressed: {len(graph)} < "
            f"{_MINIMUM_MODULE_BOUNDARIES}"
        )
    observed = _cyclic_components(graph)
    if observed != _ALLOWED_CYCLES:
        added = observed - _ALLOWED_CYCLES
        removed = _ALLOWED_CYCLES - observed
        if added:
            failures.append(
                "new or expanded dependency cycles: "
                + "; ".join(
                    ", ".join(sorted(item)) for item in sorted(added, key=sorted)
                )
            )
        if removed:
            failures.append(
                "cycle baseline changed; lower the explicit debt ratchet: "
                + "; ".join(
                    ", ".join(sorted(item)) for item in sorted(removed, key=sorted)
                )
            )
    if failures:
        raise SystemExit("architecture cycle ratchet failed:\n" + "\n".join(failures))
    print(
        "architecture cycle ratchet passed for "
        f"{len(graph)} module boundaries and {len(observed)} explicit debt groups"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
