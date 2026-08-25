from __future__ import annotations

import ast
import hashlib
import json

from .strict_json import loads as strict_json_loads
import tomllib
from collections import defaultdict, deque
from dataclasses import asdict, dataclass, field
from itertools import pairwise
from pathlib import Path
from typing import Any

from .path_safety import resolve_regular_file


SCHEMA_VERSION = "1.2"
_EXCLUDED_PARTS = frozenset(
    {
        ".artifacts",
        ".git",
        ".mypy_cache",
        ".pysec-tools",
        ".pytest_cache",
        ".ruff_cache",
        ".tox",
        ".venv",
        "__pycache__",
        "build",
        "dist",
        "node_modules",
        "tests",
    }
)
_FRAMEWORK_DECORATORS = frozenset(
    {
        "api_route",
        "callback",
        "command",
        "consumer",
        "delete",
        "event",
        "get",
        "handler",
        "head",
        "listener",
        "options",
        "patch",
        "post",
        "put",
        "receiver",
        "route",
        "subscribe",
        "task",
        "websocket",
    }
)
_FRAMEWORK_REGISTRATION_CALLS = frozenset(
    {
        "add_api_route",
        "add_listener",
        "add_url_rule",
        "add_websocket_route",
        "connect",
        "include",
        "include_router",
        "path",
        "register",
        "register_blueprint",
        "register_task",
        "re_path",
        "subscribe",
    }
)
_FRAMEWORK_CONSTRUCTORS = frozenset(
    {
        "APIRouter",
        "Blueprint",
        "Celery",
        "FastAPI",
        "Flask",
        "Litestar",
        "Router",
        "Sanic",
    }
)
_FRAMEWORK_MODULE_PREFIXES = (
    "celery",
    "django",
    "fastapi",
    "flask",
    "litestar",
    "sanic",
    "sqlalchemy",
    "starlette",
)
_FRAMEWORK_CLASS_DISPATCH = {
    "APIView": frozenset({"delete", "get", "head", "options", "patch", "post", "put"}),
    "AsyncConsumer": frozenset({"connect", "disconnect", "receive"}),
    "BaseCommand": frozenset({"handle"}),
    "Consumer": frozenset({"connect", "disconnect", "receive"}),
    "MiddlewareMixin": frozenset(
        {"process_exception", "process_request", "process_response", "process_view"}
    ),
    "View": frozenset({"delete", "get", "head", "options", "patch", "post", "put"}),
    "ViewSet": frozenset(
        {"create", "destroy", "list", "partial_update", "retrieve", "update"}
    ),
}
_FRAMEWORK_MODULE_SETTINGS = frozenset(
    {"ASGI_APPLICATION", "ROOT_URLCONF", "WSGI_APPLICATION"}
)
_CONSTRUCTOR_METHODS = frozenset({"__init__", "__new__"})
_MAX_FILES = 20_000
_MAX_FILE_BYTES = 5 * 1024 * 1024
_MAX_SOURCE_BYTES = 250 * 1024 * 1024
_MAX_GRAPH_NODES = 50_000
_MAX_GRAPH_EDGES = 50_000
_MAX_ENTRY_POINTS = 5_000
_MAX_TRACED_ENTRY_POINTS = 100
_MAX_SEQUENCE_DEPTH = 40
_MAX_REPRESENTATIVE_SEQUENCES = 12
_MAX_DISPATCH_TARGETS = 100
_MAX_COVERAGE_BYTES = 64 * 1024 * 1024
_MAX_COVERAGE_LINES = 5_000_000


@dataclass(slots=True, frozen=True)
class GraphNode:
    id: str
    kind: str
    module: str
    name: str
    path: str
    start_line: int
    end_line: int
    lines_of_code: int


@dataclass(slots=True, frozen=True)
class GraphEdge:
    source: str
    target: str
    kind: str
    line: int
    confidence: str
    reason: str


@dataclass(slots=True)
class ReachabilityResult:
    executable: set[str]
    load_only: set[str]
    explanations: dict[str, dict[str, Any]]


@dataclass(slots=True)
class GraphTopology:
    reachability: ReachabilityResult
    reachable: set[str]
    executable_modules: set[str]
    loaded_modules: set[str]
    load_only_modules: set[str]
    disconnected_modules: set[str]
    islands: list[dict[str, Any]]


@dataclass(slots=True, frozen=True)
class EntryPoint:
    id: str
    kind: str
    target: str
    declared_as: str
    path: str | None = None
    line: int | None = None


@dataclass(slots=True)
class ModuleRecord:
    name: str
    path: Path
    relative_path: str
    is_package: bool
    tree: ast.Module
    lines_of_code: int
    definitions: dict[str, str] = field(default_factory=dict)
    framework_roots: list[tuple[str, int, str]] = field(default_factory=list)
    dispatch_members: set[str] = field(default_factory=set)
    framework_receivers: set[str] = field(default_factory=set)
    framework_symbols: set[str] = field(default_factory=set)


def analyze_project(
    target: Path,
    *,
    configured_entry_points: tuple[str, ...] = (),
    configured_source_roots: tuple[str, ...] = (),
    minimum_island_loc: int = 100,
    discover_framework_roots: bool = True,
    coverage_path: Path | None = None,
) -> dict[str, Any]:
    """Build a bounded static reachability graph without importing target code."""
    root = target.expanduser().resolve()
    if not root.is_dir():
        raise ValueError(f"reachability target is not a directory: {root}")
    if minimum_island_loc < 1:
        raise ValueError("minimum island LOC must be positive")

    source_roots, discovery_notes = _source_roots(root, configured_source_roots)
    modules, errors = _load_modules(root, source_roots)
    nodes, edges, dynamic_features, precision_features = _build_graph(modules, errors)
    entry_points, entry_errors = _discover_entry_points(
        root,
        modules,
        nodes,
        configured_entry_points,
        discover_framework_roots,
    )
    errors.extend(entry_errors)
    coverage, coverage_metadata, coverage_errors = _load_coverage_evidence(
        root, coverage_path
    )
    errors.extend(coverage_errors)
    runtime_observations = {
        identifier: _runtime_observation(node, coverage)
        for identifier, node in nodes.items()
    }
    topology = _graph_topology(
        modules,
        nodes,
        edges,
        entry_points,
        minimum_island_loc,
        runtime_observations,
    )
    confidence = _analysis_confidence(entry_points, errors, dynamic_features)
    warnings = _warnings(entry_points, dynamic_features, errors)
    _add_island_triage(
        topology.islands,
        dynamic_features,
        coverage_metadata,
        analysis_confidence=confidence,
    )
    if len(entry_points) > _MAX_TRACED_ENTRY_POINTS:
        warnings.append(
            f"Representative sequences are limited to the first "
            f"{_MAX_TRACED_ENTRY_POINTS} entry points; reachability includes all roots."
        )

    return _reachability_document(
        root=root,
        source_roots=source_roots,
        discovery_notes=discovery_notes,
        modules=modules,
        nodes=nodes,
        edges=edges,
        entry_points=entry_points,
        topology=topology,
        runtime_observations=runtime_observations,
        coverage_metadata=coverage_metadata,
        dynamic_features=dynamic_features,
        precision_features=precision_features,
        errors=errors,
        warnings=warnings,
        confidence=confidence,
        minimum_island_loc=minimum_island_loc,
        discover_framework_roots=discover_framework_roots,
    )


def _build_graph(
    modules: dict[str, ModuleRecord], errors: list[str]
) -> tuple[dict[str, GraphNode], set[GraphEdge], set[str], set[str]]:
    nodes, nodes_truncated = _definition_nodes(modules)
    if nodes_truncated:
        errors.append(
            f"graph node limit exceeded ({_MAX_GRAPH_NODES}); analysis is incomplete"
        )
    edges: set[GraphEdge] = set()
    dynamic_features: set[str] = set()
    precision_features: set[str] = set()
    for record in modules.values():
        visitor = _GraphVisitor(record, modules, nodes)
        visitor.visit(record.tree)
        edges.update(visitor.edges)
        dynamic_features.update(visitor.dynamic_features)
        precision_features.update(visitor.precision_features)
        if len(edges) > _MAX_GRAPH_EDGES:
            break
    edges.update(_structural_edges(modules, nodes))
    edges.update(_definition_edges(nodes))
    if any(edge.kind == "constructor-dispatch" for edge in edges):
        precision_features.add("constructor-lifecycle")
    return nodes, _limit_edges(edges, errors), dynamic_features, precision_features


def _structural_edges(
    modules: dict[str, ModuleRecord], nodes: dict[str, GraphNode]
) -> set[GraphEdge]:
    edges = {
        _graph_edge(
            source=_module_id(module),
            target=_module_id(module.rpartition(".")[0]),
            kind="package-init",
            line=1,
        )
        for module in modules
        if module.rpartition(".")[0] in modules
    }
    for member in nodes.values():
        if member.kind != "method":
            continue
        class_id = _symbol_id(member.module, member.name.rpartition(".")[0])
        if class_id not in nodes:
            continue
        leaf_name = member.name.rpartition(".")[2]
        if leaf_name in _CONSTRUCTOR_METHODS:
            kind = "constructor-dispatch"
        elif member.name in modules[member.module].dispatch_members:
            kind = "framework-dispatch"
        else:
            kind = "member"
        edges.add(
            _graph_edge(
                source=class_id,
                target=member.id,
                kind=kind,
                line=member.start_line,
            )
        )
        edges.add(
            _graph_edge(
                source=member.id,
                target=class_id,
                kind="owner",
                line=member.start_line,
            )
        )
    return edges


def _definition_edges(nodes: dict[str, GraphNode]) -> set[GraphEdge]:
    return {
        _graph_edge(
            source=_module_id(member.module),
            target=member.id,
            kind="definition",
            line=member.start_line,
        )
        for member in nodes.values()
        if member.kind in {"function", "class"} and "." not in member.name
    }


def _limit_edges(edges: set[GraphEdge], errors: list[str]) -> set[GraphEdge]:
    if len(edges) <= _MAX_GRAPH_EDGES:
        return edges
    if not any("graph edge limit exceeded" in error for error in errors):
        errors.append(
            f"graph edge limit exceeded ({_MAX_GRAPH_EDGES}); analysis is incomplete"
        )
    return set(sorted(edges, key=_edge_key)[:_MAX_GRAPH_EDGES])


def _graph_topology(
    modules: dict[str, ModuleRecord],
    nodes: dict[str, GraphNode],
    edges: set[GraphEdge],
    entry_points: list[EntryPoint],
    minimum_island_loc: int,
    runtime_observations: dict[str, str],
) -> GraphTopology:
    reachability = _reachability_states(entry_points, edges, nodes)
    reachable = reachability.executable | reachability.load_only
    executable_modules = {
        nodes[identifier].module for identifier in reachability.executable
    }
    loaded_modules = {nodes[identifier].module for identifier in reachable}
    load_only_modules = loaded_modules - executable_modules
    disconnected_modules = set(modules) - loaded_modules
    islands = _unreachable_islands(
        modules,
        nodes,
        edges,
        disconnected_modules,
        minimum_island_loc,
        runtime_observations,
    )
    islands.extend(
        _load_only_symbol_islands(
            nodes,
            edges,
            reachability,
            loaded_modules,
            minimum_island_loc,
            runtime_observations,
        )
    )
    islands.sort(key=lambda item: (-int(item["lines_of_code"]), str(item["id"])))
    return GraphTopology(
        reachability=reachability,
        reachable=reachable,
        executable_modules=executable_modules,
        loaded_modules=loaded_modules,
        load_only_modules=load_only_modules,
        disconnected_modules=disconnected_modules,
        islands=islands,
    )


def _reachability_document(
    *,
    root: Path,
    source_roots: list[Path],
    discovery_notes: list[str],
    modules: dict[str, ModuleRecord],
    nodes: dict[str, GraphNode],
    edges: set[GraphEdge],
    entry_points: list[EntryPoint],
    topology: GraphTopology,
    runtime_observations: dict[str, str],
    coverage_metadata: dict[str, Any],
    dynamic_features: set[str],
    precision_features: set[str],
    errors: list[str],
    warnings: list[str],
    confidence: str,
    minimum_island_loc: int,
    discover_framework_roots: bool,
) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "analysis": _analysis_document(
            nodes,
            edges,
            entry_points,
            coverage_metadata,
            confidence,
            errors,
            minimum_island_loc,
            discover_framework_roots,
        ),
        "scope": {
            "source_roots": [
                path.relative_to(root).as_posix() or "." for path in source_roots
            ],
            "modules": len(modules),
            "source_files": len(modules),
            "lines_of_code": sum(item.lines_of_code for item in modules.values()),
            "notes": discovery_notes,
        },
        "summary": _summary_document(
            modules, nodes, edges, entry_points, topology, runtime_observations
        ),
        "entry_points": [asdict(item) for item in entry_points],
        "representative_sequences": _representative_sequences(
            entry_points, edges, nodes
        ),
        "islands": topology.islands,
        "nodes": _node_documents(nodes, topology, runtime_observations, confidence),
        "edges": [asdict(edge) for edge in sorted(edges, key=_edge_key)],
        "dynamic_features": sorted(dynamic_features),
        "precision_features": sorted(precision_features),
        "warnings": warnings,
        "errors": errors,
    }


def _analysis_document(
    nodes: dict[str, GraphNode],
    edges: set[GraphEdge],
    entry_points: list[EntryPoint],
    coverage_metadata: dict[str, Any],
    confidence: str,
    errors: list[str],
    minimum_island_loc: int,
    discover_framework_roots: bool,
) -> dict[str, Any]:
    return {
        "mode": "offline-static-ast",
        "reachability_model": "executable-load-only-disconnected",
        "target_code_executed": False,
        "confidence": confidence,
        "complete": bool(entry_points) and not errors,
        "minimum_reported_island_loc": minimum_island_loc,
        "framework_root_discovery": discover_framework_roots,
        "graph_sha256": _graph_digest(nodes, edges, entry_points),
        "coverage_evidence": coverage_metadata,
        "limits": {
            "maximum_files": _MAX_FILES,
            "maximum_file_bytes": _MAX_FILE_BYTES,
            "maximum_source_bytes": _MAX_SOURCE_BYTES,
            "maximum_graph_nodes": _MAX_GRAPH_NODES,
            "maximum_graph_edges": _MAX_GRAPH_EDGES,
            "maximum_entry_points": _MAX_ENTRY_POINTS,
            "maximum_traced_entry_points": _MAX_TRACED_ENTRY_POINTS,
            "maximum_sequence_depth": _MAX_SEQUENCE_DEPTH,
        },
    }


def _summary_document(
    modules: dict[str, ModuleRecord],
    nodes: dict[str, GraphNode],
    edges: set[GraphEdge],
    entry_points: list[EntryPoint],
    topology: GraphTopology,
    runtime_observations: dict[str, str],
) -> dict[str, int]:
    reachability = topology.reachability
    disconnected_islands = _island_count(topology.islands, "disconnected")
    load_only_islands = _island_count(topology.islands, "load-only")
    return {
        "entry_points": len(entry_points),
        "nodes": len(nodes),
        "edges": len(edges),
        "reachable_nodes": len(topology.reachable),
        "reachable_modules": len(topology.loaded_modules),
        "unreachable_modules": len(topology.disconnected_modules),
        "executable_nodes": len(reachability.executable),
        "load_only_nodes": len(reachability.load_only),
        "disconnected_nodes": len(nodes) - len(topology.reachable),
        "executable_modules": len(topology.executable_modules),
        "load_only_modules": len(topology.load_only_modules),
        "disconnected_modules": len(topology.disconnected_modules),
        "unreachable_islands": disconnected_islands,
        "load_only_islands": load_only_islands,
        "disconnected_islands": disconnected_islands,
        "reportable_islands": sum(
            bool(island["reportable"]) for island in topology.islands
        ),
        "reportable_load_only_islands": sum(
            island.get("state") == "load-only" and bool(island["reportable"])
            for island in topology.islands
        ),
        "unreachable_lines_of_code": sum(
            modules[name].lines_of_code for name in topology.disconnected_modules
        ),
        "load_only_lines_of_code": _covered_lines(
            [
                nodes[identifier]
                for identifier in sorted(reachability.load_only)
                if nodes[identifier].kind != "module"
            ]
        ),
        "observed_executable_nodes": _observation_count(
            reachability.executable, runtime_observations, "observed"
        ),
        "unobserved_executable_nodes": _observation_count(
            reachability.executable, runtime_observations, "not-observed"
        ),
        "observed_load_only_nodes": _observation_count(
            reachability.load_only, runtime_observations, "observed"
        ),
    }


def _island_count(islands: list[dict[str, Any]], state: str) -> int:
    return sum(island.get("state") == state for island in islands)


def _observation_count(
    identifiers: set[str], observations: dict[str, str], state: str
) -> int:
    return sum(observations[identifier] == state for identifier in identifiers)


def _node_documents(
    nodes: dict[str, GraphNode],
    topology: GraphTopology,
    runtime_observations: dict[str, str],
    confidence: str,
) -> list[dict[str, Any]]:
    return [
        asdict(nodes[key])
        | {
            "reachable": key in topology.reachable,
            "state": _node_state(key, topology.reachability),
            "runtime_observation": runtime_observations[key],
            "reachability": topology.reachability.explanations.get(
                key, _disconnected_explanation(confidence)
            ),
        }
        for key in sorted(nodes)
    ]


def _disconnected_explanation(confidence: str) -> dict[str, Any]:
    return {
        "state": "disconnected",
        "reason": "no load or executable path from a discovered entry point",
        "predecessor": None,
        "edge_kind": None,
        "confidence": confidence,
    }


def _source_roots(
    target: Path, configured: tuple[str, ...]
) -> tuple[list[Path], list[str]]:
    notes: list[str] = []
    if configured:
        roots = [
            _bounded_directory(target, value, "source root") for value in configured
        ]
        return _deduplicate_paths(roots), ["source roots supplied by configuration"]

    candidates: list[str] = []
    pyproject = _read_pyproject(target)
    setuptools = pyproject.get("tool", {}).get("setuptools", {})
    if isinstance(setuptools, dict):
        package_find = setuptools.get("packages", {}).get("find", {})
        if isinstance(package_find, dict):
            where = package_find.get("where", [])
            if isinstance(where, str):
                candidates.append(where)
            elif isinstance(where, list):
                candidates.extend(str(value) for value in where)
    if not candidates and (target / "src").is_dir():
        candidates.append("src")
        notes.append("inferred src-layout source root")
    if not candidates:
        candidates.append(".")
        notes.append("used repository root because no package source root was declared")
    roots = [
        _bounded_directory(target, value, "inferred source root")
        for value in candidates
    ]
    return _deduplicate_paths(roots), notes


def _bounded_directory(target: Path, value: str, label: str) -> Path:
    candidate = (target / value).resolve()
    if not candidate.is_relative_to(target):
        raise ValueError(f"{label} escapes the target: {value}")
    if not candidate.is_dir():
        raise ValueError(f"{label} is not a directory: {value}")
    return candidate


def _deduplicate_paths(paths: list[Path]) -> list[Path]:
    return sorted(set(paths), key=lambda item: (len(item.parts), item.as_posix()))


def _read_pyproject(target: Path) -> dict[str, Any]:
    path = target / "pyproject.toml"
    if not path.is_file() or path.is_symlink():
        return {}
    try:
        document = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError):
        return {}
    return document if isinstance(document, dict) else {}


def _load_modules(
    target: Path, source_roots: list[Path]
) -> tuple[dict[str, ModuleRecord], list[str]]:
    records: dict[str, ModuleRecord] = {}
    errors: list[str] = []
    total_bytes = 0
    paths: list[tuple[Path, Path]] = []
    for source_root in source_roots:
        for path in source_root.rglob("*.py"):
            if path.is_symlink() or any(part in _EXCLUDED_PARTS for part in path.parts):
                continue
            paths.append((source_root, path))
    paths.sort(key=lambda item: item[1].as_posix())
    if len(paths) > _MAX_FILES:
        errors.append(
            f"source file limit exceeded ({_MAX_FILES}); analysis is incomplete"
        )
        paths = paths[:_MAX_FILES]
    for source_root, path in paths:
        try:
            size = path.stat().st_size
        except OSError as exc:
            errors.append(f"{_relative(target, path)}: could not stat source: {exc}")
            continue
        if size > _MAX_FILE_BYTES:
            errors.append(
                f"{_relative(target, path)}: file exceeds {_MAX_FILE_BYTES} byte limit"
            )
            continue
        total_bytes += size
        if total_bytes > _MAX_SOURCE_BYTES:
            errors.append(
                f"source byte limit exceeded ({_MAX_SOURCE_BYTES}); analysis is incomplete"
            )
            break
        try:
            text = path.read_text(encoding="utf-8")
            tree = ast.parse(text, filename=_relative(target, path))
        except (OSError, UnicodeDecodeError, SyntaxError) as exc:
            line = getattr(exc, "lineno", None)
            suffix = f":{line}" if line else ""
            errors.append(f"{_relative(target, path)}{suffix}: {exc}")
            continue
        name = _module_name(source_root, path)
        if not name:
            continue
        if name in records:
            errors.append(
                f"duplicate module {name}: {records[name].relative_path} and {_relative(target, path)}"
            )
            continue
        record = ModuleRecord(
            name=name,
            path=path,
            relative_path=_relative(target, path),
            is_package=path.name == "__init__.py",
            tree=tree,
            lines_of_code=_lines_of_code(text),
        )
        _collect_framework_bindings(record)
        _collect_definitions(record)
        records[name] = record
    return records, errors


def _module_name(source_root: Path, path: Path) -> str:
    relative = path.relative_to(source_root)
    parts = list(relative.with_suffix("").parts)
    if parts and parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def _lines_of_code(text: str) -> int:
    return sum(
        1
        for line in text.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    )


def _collect_definitions(record: ModuleRecord) -> None:
    _walk_definitions(record, record.tree.body, "")


def _walk_definitions(record: ModuleRecord, body: list[ast.stmt], prefix: str) -> None:
    for statement in body:
        if not isinstance(
            statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
        ):
            continue
        qualname = f"{prefix}.{statement.name}" if prefix else statement.name
        record.definitions[qualname] = _symbol_id(record.name, qualname)
        if _framework_decorator(statement.decorator_list, record):
            record.framework_roots.append(
                (
                    qualname,
                    statement.lineno,
                    _decorator_name(statement.decorator_list),
                )
            )
        if isinstance(statement, ast.ClassDef):
            _collect_dispatch_members(record, statement, qualname)
            _walk_definitions(record, statement.body, qualname)


def _collect_dispatch_members(
    record: ModuleRecord, statement: ast.ClassDef, qualname: str
) -> None:
    node_visitor = any(
        _dotted_name(base).rpartition(".")[2] == "NodeVisitor"
        for base in statement.bases
    )
    framework_methods: set[str] = set()
    for base in statement.bases:
        framework_methods.update(
            _FRAMEWORK_CLASS_DISPATCH.get(
                _dotted_name(base).rpartition(".")[2], frozenset()
            )
        )
    if not node_visitor and not framework_methods:
        return
    for member in statement.body:
        if isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef)) and (
            (node_visitor and member.name.startswith("visit_"))
            or member.name in framework_methods
        ):
            record.dispatch_members.add(f"{qualname}.{member.name}")


def _collect_framework_bindings(record: ModuleRecord) -> None:
    for statement in record.tree.body:
        if isinstance(statement, ast.Import):
            for alias in statement.names:
                if alias.name.startswith(_FRAMEWORK_MODULE_PREFIXES):
                    record.framework_symbols.add(
                        alias.asname or alias.name.split(".")[0]
                    )
        elif isinstance(statement, ast.ImportFrom) and (
            statement.module or ""
        ).startswith(_FRAMEWORK_MODULE_PREFIXES):
            record.framework_symbols.update(
                alias.asname or alias.name
                for alias in statement.names
                if alias.name != "*"
            )
        elif isinstance(statement, (ast.Assign, ast.AnnAssign)):
            value = statement.value
            if not isinstance(value, ast.Call):
                continue
            constructor = _dotted_name(value.func).rpartition(".")[2]
            if constructor not in _FRAMEWORK_CONSTRUCTORS:
                continue
            targets = (
                statement.targets
                if isinstance(statement, ast.Assign)
                else [statement.target]
            )
            record.framework_receivers.update(
                name for target in targets if (name := _assignment_name(target))
            )


def _definition_nodes(
    modules: dict[str, ModuleRecord],
) -> tuple[dict[str, GraphNode], bool]:
    nodes: dict[str, GraphNode] = {}
    for record in modules.values():
        module_id = _module_id(record.name)
        nodes[module_id] = GraphNode(
            id=module_id,
            kind="module",
            module=record.name,
            name=record.name,
            path=record.relative_path,
            start_line=1,
            end_line=max(1, getattr(record.tree, "end_lineno", 1) or 1),
            lines_of_code=record.lines_of_code,
        )
    for record in modules.values():
        for statement, qualname, kind in _iter_definitions(record.tree.body):
            if len(nodes) >= _MAX_GRAPH_NODES:
                return nodes, True
            identifier = _symbol_id(record.name, qualname)
            nodes[identifier] = GraphNode(
                id=identifier,
                kind=kind,
                module=record.name,
                name=qualname,
                path=record.relative_path,
                start_line=statement.lineno,
                end_line=getattr(statement, "end_lineno", statement.lineno)
                or statement.lineno,
                lines_of_code=max(
                    1,
                    (
                        getattr(statement, "end_lineno", statement.lineno)
                        or statement.lineno
                    )
                    - statement.lineno
                    + 1,
                ),
            )
    return nodes, False


def _iter_definitions(
    body: list[ast.stmt], prefix: str = ""
) -> list[tuple[ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef, str, str]]:
    result: list[
        tuple[ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef, str, str]
    ] = []
    for statement in body:
        if not isinstance(
            statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
        ):
            continue
        qualname = f"{prefix}.{statement.name}" if prefix else statement.name
        kind = (
            "class"
            if isinstance(statement, ast.ClassDef)
            else ("method" if prefix else "function")
        )
        result.append((statement, qualname, kind))
        if isinstance(statement, ast.ClassDef):
            result.extend(_iter_definitions(statement.body, qualname))
    return result


class _GraphVisitor(ast.NodeVisitor):
    def __init__(
        self,
        record: ModuleRecord,
        modules: dict[str, ModuleRecord],
        nodes: dict[str, GraphNode],
    ) -> None:
        self.record = record
        self.modules = modules
        self.nodes = nodes
        self.edges: set[GraphEdge] = set()
        self.dynamic_features: set[str] = set()
        self.precision_features: set[str] = set()
        self._scope = [_module_id(record.name)]
        self._qualnames: list[str] = []
        self._aliases: list[dict[str, tuple[str, str]]] = [{}]
        self._instances: list[dict[str, str]] = [{}]

    @property
    def current(self) -> str:
        return self._scope[-1]

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            local = alias.asname or alias.name.split(".")[0]
            resolved = _nearest_internal_module(alias.name, self.modules)
            if resolved:
                self._aliases[-1][local] = ("module", alias.name)
                self._add_edge(_module_id(resolved), "import", node.lineno)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        base = _resolve_import_base(self.record, node.module, node.level)
        for alias in node.names:
            if alias.name == "*":
                self.dynamic_features.add("wildcard-import")
                continue
            local = alias.asname or alias.name
            candidate_module = f"{base}.{alias.name}" if base else alias.name
            if candidate_module in self.modules:
                self._aliases[-1][local] = ("module", candidate_module)
                self._add_edge(_module_id(candidate_module), "import", node.lineno)
                continue
            symbol = _find_symbol(self.nodes, base, alias.name)
            self._aliases[-1][local] = ("symbol", symbol or f"{base}:{alias.name}")
            resolved = _nearest_internal_module(base, self.modules)
            if resolved:
                self._add_edge(_module_id(resolved), "import", node.lineno)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_definition(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_definition(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._visit_definition(node)

    def _visit_definition(
        self, node: ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef
    ) -> None:
        qualname = ".".join([*self._qualnames, node.name])
        identifier = _symbol_id(self.record.name, qualname)
        for decorator in node.decorator_list:
            self.visit(decorator)
        for base in getattr(node, "bases", []):
            self.visit(base)
        for keyword in getattr(node, "keywords", []):
            self.visit(keyword.value)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for default in [*node.args.defaults, *node.args.kw_defaults]:
                if default is not None:
                    self.visit(default)
        if identifier not in self.nodes:
            for statement in node.body:
                self.visit(statement)
            return
        self._scope.append(identifier)
        self._qualnames.append(node.name)
        self._aliases.append(dict(self._aliases[-1]))
        self._instances.append({})
        for statement in node.body:
            self.visit(statement)
        self._instances.pop()
        self._aliases.pop()
        self._qualnames.pop()
        self._scope.pop()

    def visit_Assign(self, node: ast.Assign) -> None:
        self._record_framework_module_setting(node.targets, node.value, node.lineno)
        target_class = self._called_class(node.value)
        if target_class:
            for target in node.targets:
                name = _assignment_name(target)
                if name:
                    self._instances[-1][name] = target_class
                    self.precision_features.add("typed-receiver-resolution")
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None:
            self._record_framework_module_setting(
                [node.target], node.value, node.lineno
            )
            target_class = self._called_class(node.value)
            name = _assignment_name(node.target)
            if target_class:
                if name:
                    self._instances[-1][name] = target_class
                    self.precision_features.add("typed-receiver-resolution")
        self.generic_visit(node)

    def visit_If(self, node: ast.If) -> None:
        condition = _static_boolean(node.test)
        if condition is None:
            self.generic_visit(node)
            return
        self.precision_features.add("static-branch-pruning")
        for statement in node.body if condition else node.orelse:
            self.visit(statement)

    def visit_Call(self, node: ast.Call) -> None:
        dotted = _dotted_name(node.func)
        self._add_framework_environment_edge(node, dotted)
        dynamic_module = self._literal_dynamic_module(node, dotted)
        if dynamic_module:
            self.dynamic_features.add(
                f"resolved-literal-dynamic-import:{dynamic_module}"
            )
            self.precision_features.add("literal-dynamic-import-resolution")
            self._add_edge(
                _module_id(dynamic_module), "dynamic-import-literal", node.lineno
            )
        elif dotted in {"eval", "exec", "__import__", "importlib.import_module"}:
            self.dynamic_features.add(dotted)
        target = self._resolve_call(node.func)
        if target:
            self._add_edge(target, "call", node.lineno)
        self._add_framework_registration_edges(node, dotted)
        dispatch_targets = self._dispatch_targets(node.func, target)
        if dispatch_targets:
            self.dynamic_features.add("polymorphic-dispatch")
            for dispatch_target in dispatch_targets:
                self._add_edge(dispatch_target, "dispatch", node.lineno)
        self.generic_visit(node)

    def visit_Name(self, node: ast.Name) -> None:
        if not isinstance(node.ctx, ast.Load):
            return
        target = self._local_definition(node.id)
        if target is None:
            target = self._alias_target(self._lookup_alias(node.id))
        if target:
            self._add_edge(target, "reference", node.lineno)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        target = self._resolve_call(node)
        if target:
            self._add_edge(target, "reference", node.lineno)
        self.generic_visit(node)

    def _called_class(self, value: ast.expr) -> str | None:
        if not isinstance(value, ast.Call):
            return None
        identifier = self._resolve_call(value.func)
        definition = self.nodes.get(identifier) if identifier else None
        return identifier if definition and definition.kind == "class" else None

    def _literal_dynamic_module(self, node: ast.Call, dotted: str) -> str | None:
        if dotted not in {"__import__", "importlib.import_module"} or not node.args:
            return None
        value = node.args[0]
        if not isinstance(value, ast.Constant) or not isinstance(value.value, str):
            return None
        module = value.value.strip()
        if module.startswith("."):
            return None
        return module if module in self.modules else None

    def _record_framework_module_setting(
        self, targets: list[ast.expr], value: ast.expr, line: int
    ) -> None:
        if not isinstance(value, ast.Constant) or not isinstance(value.value, str):
            return
        setting = next(
            (
                target.id
                for target in targets
                if isinstance(target, ast.Name)
                and target.id in _FRAMEWORK_MODULE_SETTINGS
            ),
            None,
        )
        if setting is None:
            return
        module = (
            value.value
            if setting == "ROOT_URLCONF"
            else value.value.rpartition(".")[0] or value.value
        )
        if module in self.modules:
            self._add_edge(_module_id(module), "framework-config", line)
            self.precision_features.add("framework-configuration-resolution")

    def _add_framework_registration_edges(self, node: ast.Call, dotted: str) -> None:
        if dotted.rpartition(".")[2] not in _FRAMEWORK_REGISTRATION_CALLS:
            return
        for argument in [*node.args, *(keyword.value for keyword in node.keywords)]:
            target = self._resolve_call(argument)
            if (
                target is None
                and isinstance(argument, ast.Call)
                and isinstance(argument.func, ast.Attribute)
                and argument.func.attr == "as_view"
            ):
                target = self._resolve_call(argument.func.value)
            definition = self.nodes.get(target) if target else None
            if definition and definition.kind in {"function", "method", "class"}:
                self._add_edge(target, "registration-dispatch", node.lineno)
                self.precision_features.add("framework-registration-resolution")

    def _add_framework_environment_edge(self, node: ast.Call, dotted: str) -> None:
        if dotted.rpartition(".")[2] != "setdefault" or len(node.args) < 2:
            return
        key, value = node.args[:2]
        if not (
            isinstance(key, ast.Constant)
            and key.value == "DJANGO_SETTINGS_MODULE"
            and isinstance(value, ast.Constant)
            and isinstance(value.value, str)
            and value.value in self.modules
        ):
            return
        self._add_edge(_module_id(value.value), "framework-config", node.lineno)
        self.precision_features.add("framework-configuration-resolution")

    def _dispatch_targets(
        self, expression: ast.expr, direct_target: str | None
    ) -> list[str]:
        if not isinstance(expression, ast.Attribute):
            return []
        parts = _attribute_parts(expression)
        if not parts:
            return []
        receiver_is_polymorphic_self = parts[0] in {"self", "cls"}
        if direct_target is not None and not receiver_is_polymorphic_self:
            return []
        method_name = parts[-1]
        matches = sorted(
            identifier
            for identifier, node in self.nodes.items()
            if node.kind == "method" and node.name.rpartition(".")[2] == method_name
        )
        if len(matches) < 2:
            return []
        if len(matches) > _MAX_DISPATCH_TARGETS:
            self.dynamic_features.add(f"unbounded-polymorphic-dispatch:{method_name}")
            return []
        return [identifier for identifier in matches if identifier != direct_target]

    def _resolve_call(self, expression: ast.expr) -> str | None:
        if isinstance(expression, ast.Name):
            local = self._local_definition(expression.id)
            if local:
                return local
            alias = self._lookup_alias(expression.id)
            return self._alias_target(alias)
        if not isinstance(expression, ast.Attribute):
            return None
        parts = _attribute_parts(expression)
        if not parts:
            if isinstance(expression.value, ast.Call):
                class_id = self._called_class(expression.value)
                if class_id:
                    return self._method_on_class(class_id, expression.attr)
            return None
        receiver = ".".join(parts[:-1])
        instance_class = self._lookup_instance(receiver)
        if instance_class:
            return self._method_on_class(instance_class, parts[-1])
        if parts[0] in {"self", "cls"} and self._qualnames:
            class_name = self._qualnames[0]
            return _find_symbol(
                self.nodes, self.record.name, f"{class_name}.{parts[-1]}"
            )
        alias = self._lookup_alias(parts[0])
        if alias and alias[0] == "module":
            module = alias[1]
            suffix = ".".join(parts[1:])
            return _find_symbol(self.nodes, module, suffix) or _module_target(
                module, self.modules
            )
        local_class = self.record.definitions.get(parts[0])
        if local_class:
            return _find_symbol(self.nodes, self.record.name, ".".join(parts))
        return None

    def _method_on_class(self, class_id: str, method: str) -> str | None:
        definition = self.nodes.get(class_id)
        if definition is None or definition.kind != "class":
            return None
        return _find_symbol(
            self.nodes, definition.module, f"{definition.name}.{method}"
        )

    def _local_definition(self, name: str) -> str | None:
        if self._qualnames:
            class_candidate = f"{self._qualnames[0]}.{name}"
            value = self.record.definitions.get(class_candidate)
            if value:
                return value
        return self.record.definitions.get(name)

    def _lookup_alias(self, name: str) -> tuple[str, str] | None:
        for aliases in reversed(self._aliases):
            if name in aliases:
                return aliases[name]
        return None

    def _lookup_instance(self, name: str) -> str | None:
        for instances in reversed(self._instances):
            if name in instances:
                return instances[name]
        return None

    def _alias_target(self, alias: tuple[str, str] | None) -> str | None:
        if not alias:
            return None
        kind, value = alias
        if kind == "module":
            return _module_target(value, self.modules)
        if value.startswith("symbol:"):
            return value if value in self.nodes else None
        module, _, name = value.partition(":")
        return _find_symbol(self.nodes, module, name)

    def _add_edge(self, target: str | None, kind: str, line: int) -> None:
        if target and target in self.nodes and target != self.current:
            self.edges.add(
                _graph_edge(
                    source=self.current,
                    target=target,
                    kind=kind,
                    line=line,
                )
            )


def _resolve_import_base(record: ModuleRecord, module: str | None, level: int) -> str:
    if level == 0:
        return module or ""
    package = record.name if record.is_package else record.name.rpartition(".")[0]
    parts = package.split(".") if package else []
    keep = max(0, len(parts) - level + 1)
    base = parts[:keep]
    if module:
        base.extend(module.split("."))
    return ".".join(base)


def _nearest_internal_module(name: str, modules: dict[str, ModuleRecord]) -> str | None:
    candidate = name
    while candidate:
        if candidate in modules:
            return candidate
        candidate = candidate.rpartition(".")[0]
    return None


def _module_target(name: str, modules: dict[str, ModuleRecord]) -> str | None:
    module = _nearest_internal_module(name, modules)
    return _module_id(module) if module else None


def _find_symbol(nodes: dict[str, GraphNode], module: str, name: str) -> str | None:
    identifier = _symbol_id(module, name)
    return identifier if identifier in nodes else None


def _discover_entry_points(
    target: Path,
    modules: dict[str, ModuleRecord],
    nodes: dict[str, GraphNode],
    configured: tuple[str, ...],
    framework_roots: bool,
) -> tuple[list[EntryPoint], list[str]]:
    declarations = _entry_point_declarations(target, configured)
    entries, errors, seen = _resolve_entry_points(declarations, modules, nodes)
    entries.extend(_implicit_entry_points(modules, nodes, framework_roots, seen))
    entries.sort(key=lambda item: item.id)
    if len(entries) > _MAX_ENTRY_POINTS:
        errors.append(
            f"entry point limit exceeded ({_MAX_ENTRY_POINTS}); analysis is incomplete"
        )
        entries = entries[:_MAX_ENTRY_POINTS]
    return entries, errors


def _entry_point_declarations(
    target: Path, configured: tuple[str, ...]
) -> list[tuple[str, str, str]]:
    declarations: list[tuple[str, str, str]] = []
    pyproject = _read_pyproject(target)
    project = pyproject.get("project", {})
    if isinstance(project, dict):
        for table_name in ("scripts", "gui-scripts"):
            table = project.get(table_name, {})
            if isinstance(table, dict):
                for name, value in sorted(table.items()):
                    declarations.append(
                        (f"project-{table_name}", str(name), str(value))
                    )
        groups = project.get("entry-points", {})
        if isinstance(groups, dict):
            for group, table in sorted(groups.items()):
                if isinstance(table, dict):
                    for name, value in sorted(table.items()):
                        declarations.append(
                            (f"entry-point:{group}", str(name), str(value))
                        )
    poetry = pyproject.get("tool", {}).get("poetry", {})
    if isinstance(poetry, dict) and isinstance(poetry.get("scripts"), dict):
        for name, value in sorted(poetry["scripts"].items()):
            declaration = (
                value.get("reference", "") if isinstance(value, dict) else value
            )
            declarations.append(("poetry-script", str(name), str(declaration)))
    declarations.extend(("configured", value, value) for value in configured)
    return declarations


def _resolve_entry_points(
    declarations: list[tuple[str, str, str]],
    modules: dict[str, ModuleRecord],
    nodes: dict[str, GraphNode],
) -> tuple[list[EntryPoint], list[str], set[tuple[str, str]]]:
    entries: list[EntryPoint] = []
    errors: list[str] = []
    seen: set[tuple[str, str]] = set()
    for kind, name, declaration in declarations:
        target_id = _resolve_declaration(declaration, modules, nodes)
        if target_id is None:
            errors.append(f"entry point {name!r} could not be resolved: {declaration}")
            continue
        key = (kind, target_id)
        if key in seen:
            continue
        seen.add(key)
        node = nodes[target_id]
        entries.append(
            EntryPoint(
                id=f"entry:{kind}:{name}",
                kind=kind,
                target=target_id,
                declared_as=declaration,
                path=node.path,
                line=node.start_line,
            )
        )
    return entries, errors, seen


def _implicit_entry_points(
    modules: dict[str, ModuleRecord],
    nodes: dict[str, GraphNode],
    framework_roots: bool,
    seen: set[tuple[str, str]],
) -> list[EntryPoint]:
    entries: list[EntryPoint] = []
    for record in modules.values():
        module_id = _module_id(record.name)
        if record.path.name == "__main__.py" or _has_main_guard(record.tree):
            key = ("python-main", module_id)
            if key not in seen:
                seen.add(key)
                entries.append(
                    EntryPoint(
                        id=f"entry:python-main:{record.name}",
                        kind="python-main",
                        target=module_id,
                        declared_as=record.relative_path,
                        path=record.relative_path,
                        line=1,
                    )
                )
        if framework_roots:
            framework_line = _framework_runtime_module_line(record)
            if framework_line is not None:
                key = ("framework-runtime-module", module_id)
                if key not in seen:
                    seen.add(key)
                    entries.append(
                        EntryPoint(
                            id=f"entry:framework-runtime:{record.name}",
                            kind="framework-runtime-module",
                            target=module_id,
                            declared_as=f"{record.path.name}:application",
                            path=record.relative_path,
                            line=framework_line,
                        )
                    )
            for qualname, line, decorator in record.framework_roots:
                symbol = _symbol_id(record.name, qualname)
                key = ("framework-decorator", symbol)
                if symbol in nodes and key not in seen:
                    seen.add(key)
                    entries.append(
                        EntryPoint(
                            id=f"entry:framework:{record.name}:{qualname}",
                            kind="framework-decorator",
                            target=symbol,
                            declared_as=decorator,
                            path=record.relative_path,
                            line=line,
                        )
                    )
    return entries


def _framework_runtime_module_line(record: ModuleRecord) -> int | None:
    if record.path.name not in {"asgi.py", "wsgi.py"}:
        return None
    for statement in record.tree.body:
        targets: list[ast.expr] = []
        if isinstance(statement, ast.Assign):
            targets = statement.targets
        elif isinstance(statement, ast.AnnAssign):
            targets = [statement.target]
        if any(
            isinstance(target, ast.Name) and target.id == "application"
            for target in targets
        ):
            return statement.lineno
    return None


def _resolve_declaration(
    declaration: str,
    modules: dict[str, ModuleRecord],
    nodes: dict[str, GraphNode],
) -> str | None:
    value = declaration.strip().split("[", 1)[0].strip()
    module, separator, attribute = value.partition(":")
    if module not in modules:
        return None
    if not separator or not attribute:
        return _module_id(module)
    attribute = attribute.strip().replace(":", ".")
    return _find_symbol(nodes, module, attribute)


def _has_main_guard(tree: ast.Module) -> bool:
    for node in ast.walk(tree):
        if not isinstance(node, ast.If):
            continue
        comparison = node.test
        if not isinstance(comparison, ast.Compare) or len(comparison.ops) != 1:
            continue
        values = [comparison.left, *comparison.comparators]
        has_name = any(
            isinstance(value, ast.Name) and value.id == "__name__" for value in values
        )
        has_main = any(
            isinstance(value, ast.Constant) and value.value == "__main__"
            for value in values
        )
        if has_name and has_main:
            return True
    return False


def _framework_decorator(decorators: list[ast.expr], record: ModuleRecord) -> bool:
    for item in decorators:
        name = (
            _dotted_name(item.func)
            if isinstance(item, ast.Call)
            else _dotted_name(item)
        )
        parts = name.split(".")
        if not parts or parts[-1] not in _FRAMEWORK_DECORATORS | {"listens_for"}:
            continue
        if (
            len(parts) == 1
            and parts[0] in record.framework_symbols
            or len(parts) > 1
            and parts[0] in record.framework_receivers | record.framework_symbols
        ):
            return True
    return False


def _decorator_name(decorators: list[ast.expr]) -> str:
    for item in decorators:
        name = (
            _dotted_name(item.func)
            if isinstance(item, ast.Call)
            else _dotted_name(item)
        )
        if name.split(".")[-1] in _FRAMEWORK_DECORATORS | {"listens_for"}:
            return f"@{name}"
    return "@framework-handler"


def _dotted_name(node: ast.expr) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _dotted_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def _attribute_parts(node: ast.Attribute) -> list[str]:
    dotted = _dotted_name(node)
    return dotted.split(".") if dotted else []


def _assignment_name(node: ast.expr) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        dotted = _dotted_name(node)
        return dotted or None
    return None


def _static_boolean(node: ast.expr) -> bool | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, bool):
        return node.value
    if isinstance(node, ast.Name) and node.id == "TYPE_CHECKING":
        return False
    if isinstance(node, ast.Attribute) and _dotted_name(node) == "typing.TYPE_CHECKING":
        return False
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        value = _static_boolean(node.operand)
        return None if value is None else not value
    return None


def _edge_adjacency(edges: set[GraphEdge]) -> dict[str, list[GraphEdge]]:
    result: dict[str, list[GraphEdge]] = defaultdict(list)
    for edge in sorted(edges, key=_edge_key):
        result[edge.source].append(edge)
    return dict(result)


def _reachability_states(
    entry_points: list[EntryPoint],
    edges: set[GraphEdge],
    nodes: dict[str, GraphNode],
) -> ReachabilityResult:
    adjacency = _edge_adjacency(edges)
    executable: set[str] = set()
    load_only: set[str] = set()
    explanations: dict[str, dict[str, Any]] = {}
    executable_queue: deque[str] = deque()
    load_queue: deque[str] = deque()

    def mark_executable(
        identifier: str,
        *,
        reason: str,
        predecessor: str | None,
        edge_kind: str | None,
        confidence: str,
    ) -> None:
        if identifier not in nodes or identifier in executable:
            return
        load_only.discard(identifier)
        executable.add(identifier)
        explanations[identifier] = {
            "state": "executable",
            "reason": reason,
            "predecessor": predecessor,
            "edge_kind": edge_kind,
            "confidence": confidence,
        }
        executable_queue.append(identifier)

    def mark_loaded(
        identifier: str,
        *,
        reason: str,
        predecessor: str | None,
        edge_kind: str | None,
        confidence: str,
    ) -> None:
        if (
            identifier not in nodes
            or identifier in executable
            or identifier in load_only
        ):
            return
        load_only.add(identifier)
        explanations[identifier] = {
            "state": "load-only",
            "reason": reason,
            "predecessor": predecessor,
            "edge_kind": edge_kind,
            "confidence": confidence,
        }
        load_queue.append(identifier)

    for entry in entry_points:
        mark_executable(
            entry.target,
            reason=f"declared reachability root ({entry.kind}: {entry.declared_as})",
            predecessor=None,
            edge_kind="entry-point",
            confidence="high",
        )
        node = nodes.get(entry.target)
        if node and node.kind != "module":
            mark_loaded(
                _module_id(node.module),
                reason="the module containing an executable entry point must be loaded",
                predecessor=entry.target,
                edge_kind="entry-module",
                confidence="high",
            )

    while executable_queue or load_queue:
        if executable_queue:
            source = executable_queue.popleft()
            if source not in executable:
                continue
            for edge in adjacency.get(source, []):
                if edge.kind in {
                    "call",
                    "constructor-dispatch",
                    "dispatch",
                    "framework-dispatch",
                    "owner",
                    "registration-dispatch",
                }:
                    mark_executable(
                        edge.target,
                        reason=edge.reason,
                        predecessor=source,
                        edge_kind=edge.kind,
                        confidence=edge.confidence,
                    )
                elif edge.kind == "reference" and nodes[edge.target].kind in {
                    "function",
                    "method",
                    "class",
                }:
                    mark_executable(
                        edge.target,
                        reason=(
                            "callable referenced from an executable scope; it may be "
                            "used as a callback or dispatch target"
                        ),
                        predecessor=source,
                        edge_kind="dispatch-reference",
                        confidence="medium",
                    )
                else:
                    mark_loaded(
                        edge.target,
                        reason=edge.reason,
                        predecessor=source,
                        edge_kind=edge.kind,
                        confidence=edge.confidence,
                    )
            continue

        source = load_queue.popleft()
        if source not in load_only:
            continue
        source_node = nodes.get(source)
        if source_node is None or source_node.kind not in {"module", "class"}:
            continue
        for edge in adjacency.get(source, []):
            if edge.kind in {"call", "registration-dispatch"}:
                activity = (
                    "registration occurs"
                    if edge.kind == "registration-dispatch"
                    else "call occurs"
                )
                mark_executable(
                    edge.target,
                    reason=(
                        f"{edge.reason}; the {activity} while a "
                        f"{source_node.kind} body is loaded"
                    ),
                    predecessor=source,
                    edge_kind=edge.kind,
                    confidence=edge.confidence,
                )
            else:
                mark_loaded(
                    edge.target,
                    reason=edge.reason,
                    predecessor=source,
                    edge_kind=edge.kind,
                    confidence=edge.confidence,
                )

    return ReachabilityResult(
        executable=executable,
        load_only=load_only,
        explanations=explanations,
    )


def _node_state(identifier: str, result: ReachabilityResult) -> str:
    if identifier in result.executable:
        return "executable"
    if identifier in result.load_only:
        return "load-only"
    return "disconnected"


def _load_coverage_evidence(
    target: Path, coverage_path: Path | None
) -> tuple[dict[str, set[int]], dict[str, Any], list[str]]:
    if coverage_path is None:
        return {}, {"configured": False}, []
    candidate = coverage_path.expanduser()
    if not candidate.is_absolute():
        candidate = target / candidate
    try:
        resolved = resolve_regular_file(candidate, "reachability coverage evidence")
        size = resolved.stat().st_size
        if size > _MAX_COVERAGE_BYTES:
            raise ValueError(f"coverage evidence exceeds {_MAX_COVERAGE_BYTES} bytes")
        payload = resolved.read_bytes()
        document = strict_json_loads(payload)
        if not isinstance(document, dict) or not isinstance(
            document.get("files"), dict
        ):
            raise TypeError("coverage evidence requires a files object")
        files = document["files"]
        if len(files) > _MAX_FILES:
            raise ValueError(f"coverage evidence exceeds {_MAX_FILES} files")
        observations: dict[str, set[int]] = {}
        total_lines = 0
        for raw_path, value in files.items():
            if not isinstance(raw_path, str) or not isinstance(value, dict):
                raise TypeError("coverage file entries must map paths to objects")
            path = Path(raw_path.replace("\\", "/"))
            source = path if path.is_absolute() else target / path
            source = source.resolve()
            try:
                relative = source.relative_to(target).as_posix()
            except ValueError as exc:
                raise ValueError(
                    f"coverage source path escapes the target: {raw_path}"
                ) from exc
            executed = value.get("executed_lines", [])
            if not isinstance(executed, list):
                raise TypeError(f"coverage executed_lines must be an array: {raw_path}")
            lines: set[int] = set()
            for raw_line in executed:
                if isinstance(raw_line, bool):
                    raise TypeError(f"coverage line must be an integer: {raw_path}")
                try:
                    line = int(raw_line)
                except (TypeError, ValueError) as exc:
                    raise TypeError(
                        f"coverage line must be an integer: {raw_path}"
                    ) from exc
                if line < 1:
                    raise ValueError(f"coverage line must be positive: {raw_path}")
                lines.add(line)
            total_lines += len(lines)
            if total_lines > _MAX_COVERAGE_LINES:
                raise ValueError(
                    f"coverage evidence exceeds {_MAX_COVERAGE_LINES} executed lines"
                )
            observations[relative] = lines
        return (
            observations,
            {
                "configured": True,
                "valid": True,
                "path": str(resolved),
                "sha256": hashlib.sha256(payload).hexdigest(),
                "size_bytes": size,
                "files": len(observations),
                "executed_lines": total_lines,
            },
            [],
        )
    except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
        return (
            {},
            {"configured": True, "valid": False},
            [f"coverage evidence is invalid: {exc}"],
        )


def _runtime_observation(node: GraphNode, coverage: dict[str, set[int]]) -> str:
    executed = coverage.get(node.path)
    if executed is None:
        return "not-measured"
    if any(node.start_line <= line <= node.end_line for line in executed):
        return "observed"
    return "not-observed"


def _component_observation(identifiers: list[str], observations: dict[str, str]) -> str:
    states = {
        observations.get(identifier, "not-measured") for identifier in identifiers
    }
    if "observed" in states:
        return "observed"
    if "not-observed" in states:
        return "not-observed"
    return "not-measured"


def _unreachable_islands(
    modules: dict[str, ModuleRecord],
    nodes: dict[str, GraphNode],
    edges: set[GraphEdge],
    unreachable: set[str],
    minimum_loc: int,
    runtime_observations: dict[str, str],
) -> list[dict[str, Any]]:
    neighbors: dict[str, set[str]] = {name: set() for name in unreachable}
    for edge in edges:
        source = nodes.get(edge.source)
        target = nodes.get(edge.target)
        if not source or not target or source.module == target.module:
            continue
        if source.module in unreachable and target.module in unreachable:
            neighbors[source.module].add(target.module)
            neighbors[target.module].add(source.module)
    islands: list[dict[str, Any]] = []
    remaining = set(unreachable)
    while remaining:
        seed = min(remaining)
        component: set[str] = set()
        queue = deque([seed])
        remaining.remove(seed)
        while queue:
            module = queue.popleft()
            component.add(module)
            for neighbor in sorted(neighbors[module]):
                if neighbor in remaining:
                    remaining.remove(neighbor)
                    queue.append(neighbor)
        module_names = sorted(component)
        loc = sum(modules[name].lines_of_code for name in module_names)
        symbol_count = sum(
            1
            for node in nodes.values()
            if node.module in component and node.kind != "module"
        )
        material = "\n".join(module_names).encode("utf-8")
        primary_module = max(
            module_names,
            key=lambda name: (modules[name].lines_of_code, name),
        )
        component_node_ids = [
            identifier for identifier, node in nodes.items() if node.module in component
        ]
        islands.append(
            {
                "id": f"island-{hashlib.sha256(material).hexdigest()[:12]}",
                "kind": "module-island",
                "state": "disconnected",
                "primary_module": primary_module,
                "primary_path": modules[primary_module].relative_path,
                "primary_start_line": 1,
                "primary_end_line": max(
                    1, getattr(modules[primary_module].tree, "end_lineno", 1) or 1
                ),
                "modules": module_names,
                "module_count": len(module_names),
                "symbol_count": symbol_count,
                "lines_of_code": loc,
                "paths": [modules[name].relative_path for name in module_names],
                "reportable": loc >= minimum_loc,
                "runtime_observation": _component_observation(
                    component_node_ids, runtime_observations
                ),
                "reason": "no static path from any discovered entry point",
            }
        )
    return sorted(
        islands,
        key=lambda item: (-int(item["lines_of_code"]), str(item["id"])),
    )


def _load_only_symbol_islands(
    nodes: dict[str, GraphNode],
    edges: set[GraphEdge],
    reachability: ReachabilityResult,
    loaded_modules: set[str],
    minimum_loc: int,
    runtime_observations: dict[str, str],
) -> list[dict[str, Any]]:
    candidates = {
        identifier
        for identifier, node in nodes.items()
        if node.kind != "module"
        and node.module in loaded_modules
        and identifier in reachability.load_only
    }
    neighbors: dict[str, set[str]] = {identifier: set() for identifier in candidates}
    for edge in edges:
        if edge.source in candidates and edge.target in candidates:
            neighbors[edge.source].add(edge.target)
            neighbors[edge.target].add(edge.source)
    islands: list[dict[str, Any]] = []
    remaining = set(candidates)
    while remaining:
        seed = min(remaining)
        component: set[str] = set()
        queue = deque([seed])
        remaining.remove(seed)
        while queue:
            identifier = queue.popleft()
            component.add(identifier)
            for neighbor in sorted(neighbors[identifier]):
                if neighbor in remaining:
                    remaining.remove(neighbor)
                    queue.append(neighbor)
        component_nodes = [nodes[identifier] for identifier in sorted(component)]
        lines_of_code = _covered_lines(component_nodes)
        module_names = sorted({node.module for node in component_nodes})
        paths = sorted({node.path for node in component_nodes})
        primary = max(
            component_nodes,
            key=lambda node: (node.lines_of_code, node.module, node.name),
        )
        material = "\n".join(sorted(component)).encode("utf-8")
        static_confidence = _lowest_confidence(
            str(reachability.explanations.get(identifier, {}).get("confidence", "low"))
            for identifier in component
        )
        islands.append(
            {
                "id": f"symbol-island-{hashlib.sha256(material).hexdigest()[:12]}",
                "kind": "load-only-symbol-island",
                "state": "load-only",
                "primary_module": primary.module,
                "primary_symbol": primary.name,
                "primary_path": primary.path,
                "primary_start_line": primary.start_line,
                "primary_end_line": primary.end_line,
                "modules": module_names,
                "module_count": len(module_names),
                "symbol_count": len(component_nodes),
                "symbols": [f"{node.module}:{node.name}" for node in component_nodes],
                "lines_of_code": lines_of_code,
                "paths": paths,
                "reportable": lines_of_code >= minimum_loc,
                "runtime_observation": _component_observation(
                    sorted(component), runtime_observations
                ),
                "reason": (
                    "the definitions are loaded or referenced, but no direct executable "
                    "call path from a discovered entry point was established"
                ),
                "static_confidence": static_confidence,
            }
        )
    return islands


def _add_island_triage(
    islands: list[dict[str, Any]],
    dynamic_features: set[str],
    coverage_metadata: dict[str, Any],
    *,
    analysis_confidence: str,
) -> None:
    uncertain_features = sorted(_uncertain_dynamic_features(dynamic_features))
    coverage_valid = bool(coverage_metadata.get("valid"))
    coverage_configured = bool(coverage_metadata.get("configured"))
    for island in islands:
        state = str(island.get("state") or "disconnected")
        observation = str(island.get("runtime_observation") or "not-measured")
        lines_of_code = int(island.get("lines_of_code") or 0)
        blockers: list[str] = []
        actions: list[str] = []

        if observation == "observed":
            evidence_strength = "static-runtime-conflict"
            removal_readiness = "blocked-runtime-observed"
            priority = "review-first"
            blockers.append("runtime coverage executed code in this candidate")
            actions.append(
                "Identify the observed test or runtime lane and model its production entry point."
            )
        elif coverage_valid and observation == "not-observed":
            evidence_strength = "static-plus-not-observed-coverage"
            removal_readiness = "candidate-after-validation"
            priority = (
                "high"
                if state == "disconnected" and lines_of_code >= 1000
                else "normal"
            )
            actions.append(
                "Confirm the supplied coverage includes every production-relevant execution lane."
            )
        else:
            evidence_strength = "static-only"
            removal_readiness = "manual-validation-required"
            priority = (
                "high"
                if state == "disconnected" and lines_of_code >= 1000
                else "normal"
            )
            blockers.append(
                "no valid runtime coverage corroborates the static classification"
            )
            if coverage_configured:
                actions.append(
                    "Repair the configured coverage evidence and rerun the scan."
                )
            else:
                actions.append(
                    "Attach coverage.py JSON from representative production-like tests."
                )

        if state == "load-only":
            blockers.append("the code is loaded or referenced by a reachable scope")
            if removal_readiness == "candidate-after-validation":
                removal_readiness = "manual-validation-required"
            actions.append(
                "Inspect callback, registry, plugin, dependency-injection, and reflection usage."
            )
        if uncertain_features:
            blockers.append(
                "unresolved dynamic behavior exists in the analyzed project"
            )
            if removal_readiness == "candidate-after-validation":
                removal_readiness = "manual-validation-required"
            actions.append(
                "Resolve or configure the reported dynamic roots before deleting code."
            )
        static_confidence = str(island.get("static_confidence") or analysis_confidence)
        confidence_factors = [f"static graph: {static_confidence}"]
        island_confidence = static_confidence
        if observation == "observed":
            island_confidence = "high"
            confidence_factors.append("runtime coverage observed this candidate")
        elif coverage_valid and observation == "not-observed":
            confidence_factors.append(
                "configured runtime coverage did not observe this candidate"
            )
        else:
            confidence_factors.append("representative runtime coverage is unavailable")
        if uncertain_features:
            island_confidence = _lowest_confidence((island_confidence, "medium"))
            confidence_factors.append(
                "unresolved dynamic behavior caps candidate confidence at medium"
            )
        island["confidence"] = island_confidence
        island["confidence_factors"] = confidence_factors
        actions.append(
            "Add a missing entry point when intentional; otherwise remove in a focused change with regression tests."
        )
        island["triage"] = {
            "priority": priority,
            "evidence_strength": evidence_strength,
            "removal_readiness": removal_readiness,
            "blocking_factors": blockers,
            "recommended_actions": actions,
        }


def _lowest_confidence(values: Any) -> str:
    ranks = {"low": 0, "medium": 1, "high": 2}
    normalized = [value if value in ranks else "low" for value in values]
    return min(normalized, key=ranks.__getitem__, default="low")


def _covered_lines(nodes: list[GraphNode]) -> int:
    covered: dict[str, set[int]] = defaultdict(set)
    for node in nodes:
        covered[node.path].update(range(node.start_line, node.end_line + 1))
    return sum(len(lines) for lines in covered.values())


def _representative_sequences(
    entries: list[EntryPoint],
    edges: set[GraphEdge],
    nodes: dict[str, GraphNode],
) -> list[dict[str, Any]]:
    execution_edges = {
        edge
        for edge in edges
        if edge.kind
        in {
            "call",
            "constructor-dispatch",
            "dispatch",
            "framework-dispatch",
            "registration-dispatch",
        }
    }
    edge_adjacency = _edge_adjacency(execution_edges)
    adjacency = {
        source: [edge.target for edge in outgoing]
        for source, outgoing in edge_adjacency.items()
    }
    edge_lookup = {(edge.source, edge.target): edge for edge in execution_edges}
    result: list[dict[str, Any]] = []
    for entry in entries[:_MAX_TRACED_ENTRY_POINTS]:
        predecessor: dict[str, str | None] = {entry.target: None}
        queue = deque([entry.target])
        while queue:
            source = queue.popleft()
            for target in adjacency.get(source, []):
                if target not in predecessor:
                    predecessor[target] = source
                    queue.append(target)
        leaves = [
            node
            for node in predecessor
            if node in nodes
            and not any(child in predecessor for child in adjacency.get(node, []))
        ]
        if not leaves:
            leaves = [node for node in predecessor if node != entry.target]
        leaves.sort(key=lambda node: (-_path_depth(node, predecessor), node))
        paths = []
        for leaf in leaves[:_MAX_REPRESENTATIVE_SEQUENCES]:
            complete_path = _reconstruct_path(leaf, predecessor)
            path = complete_path[:_MAX_SEQUENCE_DEPTH]
            paths.append(
                {
                    "node_ids": path,
                    "sequence": [
                        _node_label(nodes[node]) for node in path if node in nodes
                    ],
                    "edges": [
                        {
                            "kind": edge_lookup[(source, destination)].kind,
                            "line": edge_lookup[(source, destination)].line,
                            "confidence": edge_lookup[(source, destination)].confidence,
                            "reason": edge_lookup[(source, destination)].reason,
                        }
                        for source, destination in pairwise(path)
                    ],
                    "truncated": len(complete_path) > len(path),
                }
            )
        result.append(
            {
                "entry_point_id": entry.id,
                "path_type": "direct-static-call",
                "executable_nodes": len(predecessor),
                "reachable_nodes": len(predecessor),
                "representative_paths": paths,
            }
        )
    return result


def _path_depth(node: str, predecessor: dict[str, str | None]) -> int:
    depth = 0
    while predecessor.get(node) is not None:
        depth += 1
        node = predecessor[node] or node
    return depth


def _reconstruct_path(node: str, predecessor: dict[str, str | None]) -> list[str]:
    result = [node]
    while predecessor.get(node) is not None:
        node = predecessor[node] or node
        result.append(node)
    result.reverse()
    return result


def _node_label(node: GraphNode) -> str:
    return node.module if node.kind == "module" else f"{node.module}:{node.name}"


def _analysis_confidence(
    entries: list[EntryPoint], errors: list[str], dynamic_features: set[str]
) -> str:
    if not entries or errors:
        return "low"
    if _uncertain_dynamic_features(dynamic_features):
        return "medium"
    return "high"


def _warnings(
    entries: list[EntryPoint], dynamic_features: set[str], errors: list[str]
) -> list[str]:
    warnings = []
    if not entries:
        warnings.append(
            "No resolvable entry points were discovered; unreachable-code conclusions are disabled."
        )
    if _uncertain_dynamic_features(dynamic_features):
        warnings.append(
            "Dynamic loading or execution was detected; configure every legitimate dynamic root before removing candidates."
        )
    if errors:
        warnings.append(
            "One or more sources or configured roots could not be analyzed; reachability evidence is incomplete."
        )
    warnings.append(
        "Static reachability is conservative and cannot prove runtime behavior involving reflection, dependency injection, generated code, or external plugin loaders."
    )
    return warnings


def _uncertain_dynamic_features(dynamic_features: set[str]) -> set[str]:
    return {
        feature
        for feature in dynamic_features
        if not feature.startswith("resolved-literal-dynamic-import:")
    }


def _graph_edge(*, source: str, target: str, kind: str, line: int) -> GraphEdge:
    confidence, reason = {
        "call": ("high", "direct AST-resolved call"),
        "dispatch": (
            "medium",
            "bounded polymorphic method-name match may dispatch to this implementation",
        ),
        "framework-dispatch": (
            "high",
            "a recognized framework convention dispatches to this hook",
        ),
        "constructor-dispatch": (
            "high",
            "constructing the class invokes this lifecycle method",
        ),
        "registration-dispatch": (
            "medium",
            "a recognized registration API may dispatch to this callable",
        ),
        "dynamic-import-literal": (
            "high",
            "a literal dynamic import loads this internal module",
        ),
        "framework-config": (
            "high",
            "a recognized framework setting loads this internal module",
        ),
        "import": ("high", "static internal import loads the target module"),
        "package-init": (
            "high",
            "loading a package member also loads its package initializer",
        ),
        "definition": (
            "high",
            "loading the module creates this top-level definition without invoking it",
        ),
        "member": (
            "high",
            "loading the class creates this member definition without invoking it",
        ),
        "owner": (
            "high",
            "an executable method makes its owning class executable",
        ),
        "reference": (
            "medium",
            "static symbol reference establishes availability but does not prove invocation",
        ),
    }.get(kind, ("medium", "static graph relationship"))
    return GraphEdge(
        source=source,
        target=target,
        kind=kind,
        line=line,
        confidence=confidence,
        reason=reason,
    )


def _graph_digest(
    nodes: dict[str, GraphNode], edges: set[GraphEdge], entries: list[EntryPoint]
) -> str:
    material = [f"node:{key}" for key in sorted(nodes)]
    material.extend(
        f"edge:{edge.source}:{edge.target}:{edge.kind}:{edge.line}:"
        f"{edge.confidence}:{edge.reason}"
        for edge in sorted(edges, key=_edge_key)
    )
    material.extend(
        f"entry:{entry.kind}:{entry.target}:{entry.declared_as}" for entry in entries
    )
    return hashlib.sha256("\n".join(material).encode("utf-8")).hexdigest()


def _edge_key(edge: GraphEdge) -> tuple[str, str, str, int, str, str]:
    return (
        edge.source,
        edge.target,
        edge.kind,
        edge.line,
        edge.confidence,
        edge.reason,
    )


def _module_id(module: str) -> str:
    return f"module:{module}"


def _symbol_id(module: str, name: str) -> str:
    return f"symbol:{module}:{name}"


def _relative(target: Path, path: Path) -> str:
    return path.resolve().relative_to(target).as_posix()
