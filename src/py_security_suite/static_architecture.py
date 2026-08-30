from __future__ import annotations

import ast
import tomllib
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any

from .models import Confidence, Finding, Location, Severity, Source, finding_identity
from .path_safety import read_regular_file
from .strict_json import loads as strict_loads


_SKIP = frozenset(
    {
        ".artifacts",
        ".git",
        ".pysec-tools",
        ".venv",
        "build",
        "dist",
        "node_modules",
        "tests",
    }
)
_MAX_FILES = 50_000
_MAX_EDGES = 250_000
_MAX_SYMBOL_EDGES = 250_000
_MAX_DYNAMIC_IMPORTS = 10_000
_MAX_ENTRYPOINTS = 50_000
_MAX_FINDINGS = 500
_MAX_POLICY_VIOLATIONS = 1000
_MAX_REFACTORING_TARGETS = 1_000
_FAN_OUT_THRESHOLD = 12
_HUB_THRESHOLD = 20
_INSTABILITY_DELTA = 0.5
_BASELINE_PATH = "security/baselines/architecture-edges.json"
_POLICY_PATH = "security/architecture-policy.json"
_TACH_POLICY_PATH = "tach.toml"


def analyze_static_architecture(
    target: Path, reachability_artifact: object | None = None
) -> tuple[list[Finding], dict[str, Any]]:
    policy, policy_present, policy_path, policy_error = _architecture_policy(target)
    thresholds = policy["thresholds"]
    files = sorted(
        path
        for path in target.rglob("*.py")
        if not any(part in _SKIP for part in path.relative_to(target).parts)
    )
    file_truncated = len(files) > _MAX_FILES
    roots = _source_roots(target)
    modules: dict[str, Path] = {}
    for path in files[:_MAX_FILES]:
        module = _module_name(path, roots)
        if module:
            modules[module] = path
    edges: set[tuple[str, str]] = set()
    symbol_edges: set[tuple[str, str, str, int]] = set()
    dynamic_imports: list[dict[str, Any]] = []
    entrypoint_symbols: list[dict[str, Any]] = []
    parse_errors: list[str] = []
    for module, path in sorted(modules.items()):
        relative = path.relative_to(target).as_posix()
        try:
            _, payload = read_regular_file(
                path,
                "static architecture source",
                maximum_bytes=4 * 1024 * 1024,
                boundary=target,
            )
            tree = ast.parse(payload, filename=relative)
        except (OSError, SyntaxError, UnicodeError, ValueError) as exc:
            parse_errors.append(f"{relative}: {type(exc).__name__}")
            continue
        for imported in _imports(module, path.name == "__init__.py", tree):
            destination = _local_destination(imported, modules)
            if destination and destination != module:
                edges.add((module, destination))
                if len(edges) >= _MAX_EDGES:
                    break
        module_dynamic = _dynamic_imports(
            module, relative, path.name == "__init__.py", tree, modules
        )
        for record in module_dynamic:
            destination = record.get("resolved_module")
            if isinstance(destination, str) and len(edges) < _MAX_EDGES:
                edges.add((module, destination))
        dynamic_remaining = _MAX_DYNAMIC_IMPORTS + 1 - len(dynamic_imports)
        if dynamic_remaining > 0:
            dynamic_imports.extend(module_dynamic[:dynamic_remaining])
        local_symbol_edges, local_entrypoints = _symbol_graph(
            module, relative, tree, modules
        )
        if len(symbol_edges) <= _MAX_SYMBOL_EDGES:
            for edge in sorted(local_symbol_edges):
                symbol_edges.add(edge)
                if len(symbol_edges) > _MAX_SYMBOL_EDGES:
                    break
        entrypoint_remaining = _MAX_ENTRYPOINTS + 1 - len(entrypoint_symbols)
        if entrypoint_remaining > 0:
            entrypoint_symbols.extend(local_entrypoints[:entrypoint_remaining])
        if len(edges) >= _MAX_EDGES:
            break
    symbol_truncated = len(symbol_edges) > _MAX_SYMBOL_EDGES
    dynamic_truncated = len(dynamic_imports) > _MAX_DYNAMIC_IMPORTS
    entrypoint_truncated = len(entrypoint_symbols) > _MAX_ENTRYPOINTS
    declared_entrypoints, entrypoint_error = _declared_entrypoints(target, modules)
    if entrypoint_error:
        parse_errors.append(entrypoint_error)
    entrypoint_symbols = _merge_entrypoints(
        [*entrypoint_symbols[:_MAX_ENTRYPOINTS], *declared_entrypoints]
    )
    entrypoint_truncated = (
        entrypoint_truncated or len(entrypoint_symbols) > _MAX_ENTRYPOINTS
    )
    if symbol_truncated:
        parse_errors.append(
            f"symbol dependency graph exceeded {_MAX_SYMBOL_EDGES} edges"
        )
    if dynamic_truncated:
        parse_errors.append(
            f"dynamic import inventory exceeded {_MAX_DYNAMIC_IMPORTS} records"
        )
    if entrypoint_truncated:
        parse_errors.append(f"entrypoint inventory exceeded {_MAX_ENTRYPOINTS} records")
    adjacency: dict[str, set[str]] = {module: set() for module in modules}
    incoming: dict[str, set[str]] = {module: set() for module in modules}
    for source, destination in edges:
        adjacency[source].add(destination)
        incoming[destination].add(source)
    try:
        cycles = [
            component
            for component in _strong_components(adjacency)
            if len(component) > 1
        ]
    except RecursionError:
        cycles = []
        parse_errors.append(
            "dependency graph traversal exceeded the Python recursion limit"
        )
    cycles.sort(key=lambda value: (-len(value), value))
    fan_out: list[dict[str, Any]] = [
        {
            "module": module,
            "dependencies": sorted(dependencies),
            "count": len(dependencies),
        }
        for module, dependencies in adjacency.items()
        if len(dependencies) > thresholds["module_fan_out"]
    ]
    fan_out.sort(key=lambda item: (-int(item["count"]), str(item["module"])))
    module_metrics: list[dict[str, Any]] = [
        {
            "module": module,
            "fan_in": len(incoming[module]),
            "fan_out": len(adjacency[module]),
            "instability": _instability(len(incoming[module]), len(adjacency[module])),
        }
        for module in sorted(modules)
    ]
    metrics_by_module = {str(item["module"]): item for item in module_metrics}
    hubs: list[dict[str, Any]] = [
        item
        for item in module_metrics
        if int(item["fan_in"]) + int(item["fan_out"]) > thresholds["hub_total_degree"]
    ]
    hubs.sort(
        key=lambda item: (
            -(int(item["fan_in"]) + int(item["fan_out"])),
            str(item["module"]),
        )
    )
    unstable_edges: list[dict[str, Any]] = [
        {
            "source": source,
            "destination": destination,
            "source_instability": metrics_by_module[source]["instability"],
            "destination_instability": metrics_by_module[destination]["instability"],
        }
        for source, destination in sorted(edges)
        if float(metrics_by_module[destination]["instability"])
        - float(metrics_by_module[source]["instability"])
        >= thresholds["instability_delta"]
    ]
    baseline_edges, baseline_present, baseline_error = _baseline_edges(target)
    if baseline_error:
        parse_errors.append(baseline_error)
    if policy_error:
        parse_errors.append(policy_error)
    new_edges = (
        sorted(
            f"{source} -> {destination}"
            for source, destination in edges - baseline_edges
        )
        if baseline_present
        else []
    )
    cycle_records = [
        {
            "modules": component,
            "edges": [
                f"{source} -> {destination}"
                for source, destination in sorted(edges)
                if source in component and destination in component
            ],
        }
        for component in cycles
    ]
    policy_violations, policy_truncated = _policy_violations(edges, policy)
    if policy_truncated:
        parse_errors.append(
            f"architecture policy violations exceeded {_MAX_POLICY_VIOLATIONS} records"
        )
    refactoring_targets_detected, refactoring_targets = _refactoring_targets(
        cycle_records=cycle_records,
        fan_out=fan_out,
        hubs=hubs,
        unstable_edges=unstable_edges,
        new_edges=new_edges,
        baseline_present=baseline_present,
        policy_violations=policy_violations,
        thresholds=thresholds,
    )
    semantic_graph = _semantic_graph_summary(reachability_artifact)
    findings = [_cycle_finding(item, modules, target) for item in cycle_records]
    findings.extend(
        _fan_out_finding(item, modules, target, thresholds["module_fan_out"])
        for item in fan_out
    )
    findings.extend(
        _hub_finding(item, modules, target, thresholds["hub_total_degree"])
        for item in hubs
    )
    findings.extend(
        _unstable_edge_finding(item, modules, target, thresholds["instability_delta"])
        for item in unstable_edges
    )
    findings.extend(
        _new_edge_finding(item, modules, target) for item in new_edges[:500]
    )
    findings.extend(
        _policy_finding(item, modules, target) for item in policy_violations
    )
    findings_detected = len(findings)
    findings = findings[:_MAX_FINDINGS]
    complete = (
        not parse_errors
        and not file_truncated
        and len(edges) < _MAX_EDGES
        and findings_detected <= _MAX_FINDINGS
        and not symbol_truncated
        and not dynamic_truncated
        and not entrypoint_truncated
    )
    return findings, {
        "schema_version": "1.4",
        "analysis": "python-local-module-dependency-graph",
        "complete": complete,
        "files_analyzed": len(modules),
        "modules_detected": len(modules),
        "edges_detected": len(edges),
        "cycles_detected": len(cycle_records),
        "fan_out_hotspots_detected": len(fan_out),
        "hub_modules_detected": len(hubs),
        "unstable_dependency_edges_detected": len(unstable_edges),
        "symbol_edges_detected": len(symbol_edges),
        "symbol_edges": [
            {
                "source": source,
                "destination": destination,
                "path": path,
                "line": line,
            }
            for source, destination, path, line in sorted(symbol_edges)[
                :_MAX_SYMBOL_EDGES
            ]
        ],
        "dynamic_imports_detected": len(dynamic_imports),
        "unresolved_dynamic_imports": sum(
            item["resolved_module"] is None for item in dynamic_imports
        ),
        "dynamic_imports": sorted(
            dynamic_imports,
            key=lambda item: (str(item["path"]), int(item["line"])),
        )[:_MAX_DYNAMIC_IMPORTS],
        "entrypoint_symbols_detected": len(entrypoint_symbols),
        "entrypoint_symbols": sorted(
            entrypoint_symbols,
            key=lambda item: (str(item["path"]), int(item["line"])),
        )[:_MAX_ENTRYPOINTS],
        "cycles": cycle_records[:500],
        "fan_out_hotspots": fan_out[:500],
        "module_metrics": module_metrics,
        "hub_modules": hubs[:500],
        "unstable_dependency_edges": unstable_edges[:1000],
        "baseline_path": _BASELINE_PATH if baseline_present else None,
        "baseline_present": baseline_present,
        "new_dependency_edges": new_edges[:1000],
        "policy_path": policy_path,
        "policy_present": policy_present,
        "policy_format": policy.get("format") if policy_present else None,
        "policy_violations_detected": len(policy_violations) + int(policy_truncated),
        "policy_violations": policy_violations,
        "refactoring_targets_detected": refactoring_targets_detected,
        "refactoring_targets_retained": len(refactoring_targets),
        "refactoring_targets_omitted": max(
            0, refactoring_targets_detected - len(refactoring_targets)
        ),
        "refactoring_targets": refactoring_targets,
        "semantic_graph": semantic_graph,
        "parse_errors": parse_errors[:1000],
        "truncated": file_truncated
        or len(edges) >= _MAX_EDGES
        or findings_detected > _MAX_FINDINGS
        or policy_truncated
        or symbol_truncated
        or dynamic_truncated
        or entrypoint_truncated,
        "thresholds": thresholds,
        "claim_boundary": (
            "The graph resolves statically recognizable imports among Python modules in the "
            "repository. Literal dynamic imports plus decorator, packaging-script, module-main, "
            "and main-guard entry points are retained, "
            "but non-literal imports, generated modules, and runtime dependency injection "
            "may add or remove effective coupling. Symbol edges are syntactic call "
            "relationships rather than runtime dispatch proof. When supplied, semantic_graph "
            "summarizes the separately governed reachability graph; its confidence and "
            "precision controls are preserved rather than promoted to runtime proof."
        ),
    }


def _semantic_graph_summary(value: object | None) -> dict[str, Any]:
    unavailable: dict[str, Any] = {
        "available": False,
        "schema_version": None,
        "confidence": None,
        "complete": False,
        "nodes": 0,
        "edges": 0,
        "entry_points": 0,
        "islands": 0,
        "precision_features": [],
        "type_aware": False,
        "framework_aware": False,
        "dynamic_features_detected": 0,
        "errors_detected": 0,
    }
    if not isinstance(value, dict) or value.get("schema_version") not in {"1.1", "1.2"}:
        return unavailable
    analysis = value.get("analysis")
    summary = value.get("summary")
    nodes = value.get("nodes")
    edges = value.get("edges")
    entry_points = value.get("entry_points")
    islands = value.get("islands")
    precision = value.get("precision_features")
    dynamic = value.get("dynamic_features")
    errors = value.get("errors")
    if (
        not isinstance(nodes, list)
        or not isinstance(edges, list)
        or not isinstance(entry_points, list)
        or not isinstance(islands, list)
        or not isinstance(precision, list)
        or not isinstance(dynamic, list)
        or not isinstance(errors, list)
        or not isinstance(analysis, dict)
        or not isinstance(summary, dict)
    ):
        return unavailable
    confidence = analysis.get("confidence")
    if confidence not in {"low", "medium", "high"}:
        confidence = "low"
    precision_features = sorted(
        {item[:200] for item in precision[:100_000] if isinstance(item, str) and item}
    )[:100]
    return {
        "available": True,
        "schema_version": str(value["schema_version"]),
        "confidence": confidence,
        "complete": bool(analysis.get("complete")) and not errors,
        "nodes": min(len(nodes), 750_000),
        "edges": min(len(edges), 2_000_000),
        "entry_points": min(len(entry_points), 10_000),
        "islands": min(len(islands), 250_000),
        "precision_features": precision_features,
        "type_aware": "typed-receiver-resolution" in precision_features,
        "framework_aware": any(
            feature
            in {
                "framework-configuration-resolution",
                "framework-registration-resolution",
            }
            for feature in precision_features
        ),
        "dynamic_features_detected": min(len(dynamic), 100_000),
        "errors_detected": min(len(errors), 100_000),
    }


def _refactoring_targets(
    *,
    cycle_records: list[dict[str, Any]],
    fan_out: list[dict[str, Any]],
    hubs: list[dict[str, Any]],
    unstable_edges: list[dict[str, Any]],
    new_edges: list[str],
    baseline_present: bool,
    policy_violations: list[dict[str, Any]],
    thresholds: dict[str, Any],
) -> tuple[int, list[dict[str, Any]]]:
    """Rank architectural change targets while preserving exact evidence classes."""

    targets: list[dict[str, Any]] = []
    policy_cycle_pairs = {
        (str(item["source"]), str(item["destination"]))
        for item in policy_violations
        if item["kind"] == "circular-dependency"
    }
    for record in cycle_records:
        modules = [str(item) for item in record["modules"]]
        governed = any(
            source in modules and destination in modules
            for source, destination in policy_cycle_pairs
        )
        score = min(100, (92 if governed else 78) + min(8, len(modules) - 2))
        targets.append(
            _refactoring_target(
                kind="dependency-cycle",
                subject=" <-> ".join(modules[:4]),
                modules=modules,
                evidence=[str(item) for item in record["edges"][:100]],
                score=score,
                exact=governed,
                reason=(
                    "The cycle violates the declared architecture policy."
                    if governed
                    else "The static module graph contains a strongly connected component."
                ),
                remediation="Extract the smallest stable contract that reverses or removes one dependency edge, then enforce the new direction in policy.",
            )
        )
    violations_by_source: dict[str, list[dict[str, Any]]] = {}
    for violation in policy_violations:
        if violation["kind"] == "circular-dependency":
            continue
        violations_by_source.setdefault(str(violation["source"]), []).append(violation)
    for source, violations in violations_by_source.items():
        modules = sorted({source, *(str(item["destination"]) for item in violations)})
        targets.append(
            _refactoring_target(
                kind="policy-boundary",
                subject=source,
                modules=modules,
                evidence=[
                    f"{item['kind']}: {item['source']} -> {item['destination']} ({item['rule']})"
                    for item in violations[:100]
                ],
                score=min(100, 88 + len(violations)),
                exact=True,
                reason="One source module violates one or more declared dependency contracts.",
                remediation="Route the dependency through an allowed port or move ownership to the declared layer; update policy only after design review.",
            )
        )
    fanout_threshold = int(thresholds["module_fan_out"])
    for item in fan_out:
        count = int(item["count"])
        targets.append(
            _refactoring_target(
                kind="fan-out",
                subject=str(item["module"]),
                modules=[str(item["module"]), *map(str, item["dependencies"][:99])],
                evidence=[f"fan_out={count}", f"threshold={fanout_threshold}"],
                score=min(84, 55 + round(25 * count / max(1, fanout_threshold))),
                exact=False,
                reason="The module coordinates more direct dependencies than the governed review threshold.",
                remediation="Split orchestration by capability and depend on narrower ports rather than concrete subsystems.",
            )
        )
    hub_threshold = int(thresholds["hub_total_degree"])
    for item in hubs:
        degree = int(item["fan_in"]) + int(item["fan_out"])
        targets.append(
            _refactoring_target(
                kind="hub",
                subject=str(item["module"]),
                modules=[str(item["module"])],
                evidence=[
                    f"fan_in={item['fan_in']}",
                    f"fan_out={item['fan_out']}",
                    f"degree_threshold={hub_threshold}",
                ],
                score=min(82, 52 + round(25 * degree / max(1, hub_threshold))),
                exact=False,
                reason="The module is a high-degree change and failure propagation hub.",
                remediation="Separate stable shared contracts from volatile coordination and reduce consumers of the concrete module.",
            )
        )
    unstable_by_source: dict[str, list[dict[str, Any]]] = {}
    for edge in unstable_edges:
        unstable_by_source.setdefault(str(edge["source"]), []).append(edge)
    for source, instability_records in unstable_by_source.items():
        targets.append(
            _refactoring_target(
                kind="instability-direction",
                subject=source,
                modules=sorted(
                    {
                        source,
                        *(str(item["destination"]) for item in instability_records),
                    }
                ),
                evidence=[
                    f"{item['source']} -> {item['destination']}: {item['source_instability']} -> {item['destination_instability']}"
                    for item in instability_records[:100]
                ],
                score=min(72, 48 + len(instability_records) * 3),
                exact=False,
                reason="Stable code depends on comparatively volatile modules.",
                remediation="Invert the dependency around a stable interface owned by the consuming boundary.",
            )
        )
    if baseline_present:
        new_by_source: dict[str, list[str]] = {}
        for dependency_edge in new_edges:
            source, _, _ = dependency_edge.partition(" -> ")
            new_by_source.setdefault(source, []).append(dependency_edge)
        for source, regression_edges in new_by_source.items():
            regression_modules = {source}
            for dependency_edge in regression_edges:
                _, _, destination = dependency_edge.partition(" -> ")
                regression_modules.add(destination)
            targets.append(
                _refactoring_target(
                    kind="dependency-regression",
                    subject=source,
                    modules=sorted(regression_modules),
                    evidence=regression_edges[:100],
                    score=min(90, 72 + len(regression_edges) * 2),
                    exact=True,
                    reason="New dependency edges are absent from the approved baseline.",
                    remediation="Remove or explicitly review each new edge before regenerating the signed-off baseline.",
                )
            )
    targets.sort(
        key=lambda item: (
            -int(item["priority_score"]),
            not bool(item["exact_contract_failure"]),
            str(item["kind"]),
            str(item["subject"]),
        )
    )
    return len(targets), targets[:_MAX_REFACTORING_TARGETS]


def _refactoring_target(
    *,
    kind: str,
    subject: str,
    modules: list[str],
    evidence: list[str],
    score: int,
    exact: bool,
    reason: str,
    remediation: str,
) -> dict[str, Any]:
    return {
        "kind": kind,
        "subject": subject[:1000],
        "modules": sorted(set(modules))[:100],
        "evidence": evidence[:100],
        "priority": "p0" if score >= 85 else "p1" if score >= 60 else "p2",
        "priority_score": score,
        "exact_contract_failure": exact,
        "reason": reason,
        "remediation": remediation,
    }


def _instability(fan_in: int, fan_out: int) -> float:
    denominator = fan_in + fan_out
    return round(fan_out / denominator, 4) if denominator else 0.0


def _architecture_policy(
    target: Path,
) -> tuple[dict[str, Any], bool, str | None, str | None]:
    default: dict[str, object] = {
        "thresholds": {
            "module_fan_out": _FAN_OUT_THRESHOLD,
            "hub_total_degree": _HUB_THRESHOLD,
            "instability_delta": _INSTABILITY_DELTA,
        },
        "layers": [],
        "forbidden_edges": [],
        "declared_dependencies": {},
        "forbid_circular_dependencies": False,
        "format": None,
    }
    path = target / Path(_POLICY_PATH)
    if not path.is_file():
        return _tach_policy(target, default)
    try:
        _, payload = read_regular_file(
            path, "architecture policy", maximum_bytes=256 * 1024, boundary=target
        )
        document = strict_loads(payload)
        if (
            not isinstance(document, dict)
            or document.get("schema_version") != "1.0"
            or not set(document).issubset(
                {"schema_version", "thresholds", "layers", "forbidden_edges"}
            )
        ):
            raise ValueError("invalid policy fields")
        thresholds: dict[str, int | float] = {
            "module_fan_out": _FAN_OUT_THRESHOLD,
            "hub_total_degree": _HUB_THRESHOLD,
            "instability_delta": _INSTABILITY_DELTA,
        }
        raw_thresholds = document.get("thresholds", {})
        if not isinstance(raw_thresholds, dict) or not set(raw_thresholds).issubset(
            thresholds
        ):
            raise ValueError("invalid architecture thresholds")
        for name, value in raw_thresholds.items():
            if name == "instability_delta":
                if (
                    isinstance(value, bool)
                    or not isinstance(value, (int, float))
                    or not 0 <= value <= 1
                ):
                    raise ValueError("invalid instability delta")
                thresholds[name] = float(value)
            elif (
                isinstance(value, bool)
                or not isinstance(value, int)
                or not 1 <= value <= 50000
            ):
                raise ValueError(f"invalid architecture threshold: {name}")
            else:
                thresholds[name] = value
        layers = _validated_layers(document.get("layers", []))
        forbidden = _validated_forbidden_edges(document.get("forbidden_edges", []))
        return (
            {
                "thresholds": thresholds,
                "layers": layers,
                "forbidden_edges": forbidden,
                "declared_dependencies": {},
                "forbid_circular_dependencies": False,
                "format": "native-json",
            },
            True,
            _POLICY_PATH,
            None,
        )
    except (OSError, TypeError, ValueError) as exc:
        return default, True, _POLICY_PATH, f"{_POLICY_PATH}: {type(exc).__name__}"


def _tach_policy(
    target: Path, default: dict[str, Any]
) -> tuple[dict[str, Any], bool, str | None, str | None]:
    path = target / _TACH_POLICY_PATH
    if not path.is_file():
        return default, False, None, None
    try:
        _, payload = read_regular_file(
            path, "Tach architecture policy", maximum_bytes=512 * 1024, boundary=target
        )
        document = tomllib.loads(payload.decode("utf-8"))
        modules = document.get("modules", [])
        if not isinstance(modules, list) or len(modules) > 50_000:
            raise ValueError("invalid Tach modules")
        declared: dict[str, list[str]] = {}
        for item in modules:
            if (
                not isinstance(item, dict)
                or not isinstance(item.get("path"), str)
                or not item["path"]
                or not isinstance(item.get("depends_on", []), list)
                or not all(
                    isinstance(value, str) and value
                    for value in item.get("depends_on", [])
                )
            ):
                raise ValueError("invalid Tach module declaration")
            if item["path"] in declared:
                raise ValueError("duplicate Tach module declaration")
            declared[item["path"]] = sorted(set(item.get("depends_on", [])))
        policy = dict(default)
        policy["declared_dependencies"] = declared
        forbid_cycles = document.get("forbid_circular_dependencies", False)
        if not isinstance(forbid_cycles, bool):
            raise ValueError("invalid Tach circular dependency setting")
        policy["forbid_circular_dependencies"] = forbid_cycles
        policy["format"] = "tach"
        return policy, True, _TACH_POLICY_PATH, None
    except (
        OSError,
        TypeError,
        UnicodeError,
        ValueError,
        tomllib.TOMLDecodeError,
    ) as exc:
        return (
            default,
            True,
            _TACH_POLICY_PATH,
            f"{_TACH_POLICY_PATH}: {type(exc).__name__}",
        )


def _validated_layers(value: object) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) > 1000:
        raise ValueError("invalid architecture layers")
    result: list[dict[str, Any]] = []
    names: set[str] = set()
    for item in value:
        if (
            not isinstance(item, dict)
            or set(item) != {"name", "modules", "may_depend_on"}
            or not isinstance(item.get("name"), str)
            or not item["name"]
            or item["name"] in names
            or not _patterns(item.get("modules"))
            or not _patterns(item.get("may_depend_on"), allow_empty=True)
        ):
            raise ValueError("invalid architecture layer")
        names.add(item["name"])
        result.append(dict(item))
    if any(
        dependency not in names
        for item in result
        for dependency in item["may_depend_on"]
    ):
        raise ValueError("architecture layer references an unknown dependency layer")
    return result


def _validated_forbidden_edges(value: object) -> list[dict[str, str]]:
    if not isinstance(value, list) or len(value) > 1000:
        raise ValueError("invalid forbidden edges")
    result: list[dict[str, str]] = []
    for item in value:
        if (
            not isinstance(item, dict)
            or set(item) != {"source", "destination", "reason"}
            or not all(
                isinstance(item.get(name), str) and item[name]
                for name in ("source", "destination", "reason")
            )
        ):
            raise ValueError("invalid forbidden edge")
        result.append(dict(item))
    return result


def _patterns(value: object, *, allow_empty: bool = False) -> bool:
    return bool(
        isinstance(value, list)
        and (allow_empty or value)
        and len(value) <= 1000
        and len(value) == len(set(value))
        and all(isinstance(item, str) and item and len(item) <= 1000 for item in value)
    )


def _policy_violations(
    edges: set[tuple[str, str]], policy: dict[str, Any]
) -> tuple[list[dict[str, str]], bool]:
    violations: dict[tuple[str, str, str], dict[str, str]] = {}
    layers = policy["layers"]
    for source, destination in sorted(edges):
        declared = policy.get("declared_dependencies", {})
        source_boundary = (
            _tach_boundary(source, declared) if isinstance(declared, dict) else None
        )
        destination_boundary = (
            _tach_boundary(destination, declared)
            if isinstance(declared, dict)
            else None
        )
        allowed = (
            declared.get(source_boundary)
            if isinstance(declared, dict) and source_boundary
            else None
        )
        destination_allowed = bool(
            isinstance(allowed, list)
            and (
                destination_boundary == source_boundary
                or any(
                    destination_boundary is not None
                    and fnmatchcase(destination_boundary, dependency)
                    for dependency in allowed
                )
            )
        )
        if isinstance(allowed, list) and not destination_allowed:
            key = (source, destination, "undeclared-dependency")
            violations[key] = {
                "kind": "undeclared-dependency",
                "source": source,
                "destination": destination,
                "rule": f"Tach module {source} declares only {allowed}",
            }
            if len(violations) > _MAX_POLICY_VIOLATIONS:
                ordered = [violations[key] for key in sorted(violations)]
                return ordered[:_MAX_POLICY_VIOLATIONS], True
        for rule in policy["forbidden_edges"]:
            if fnmatchcase(source, rule["source"]) and fnmatchcase(
                destination, rule["destination"]
            ):
                key = (source, destination, "forbidden-edge")
                violations[key] = {
                    "kind": "forbidden-edge",
                    "source": source,
                    "destination": destination,
                    "rule": rule["reason"],
                }
                if len(violations) > _MAX_POLICY_VIOLATIONS:
                    ordered = [violations[key] for key in sorted(violations)]
                    return ordered[:_MAX_POLICY_VIOLATIONS], True
        source_layers = [
            layer
            for layer in layers
            if any(fnmatchcase(source, pattern) for pattern in layer["modules"])
        ]
        destination_layers = [
            layer
            for layer in layers
            if any(fnmatchcase(destination, pattern) for pattern in layer["modules"])
        ]
        for source_layer in source_layers:
            for destination_layer in destination_layers:
                if (
                    destination_layer["name"] == source_layer["name"]
                    or destination_layer["name"] in source_layer["may_depend_on"]
                ):
                    continue
                key = (source, destination, "layer-dependency")
                violations[key] = {
                    "kind": "layer-dependency",
                    "source": source,
                    "destination": destination,
                    "rule": f"layer {source_layer['name']} may depend only on {source_layer['may_depend_on']}",
                }
                if len(violations) > _MAX_POLICY_VIOLATIONS:
                    ordered = [violations[key] for key in sorted(violations)]
                    return ordered[:_MAX_POLICY_VIOLATIONS], True
    declared = policy.get("declared_dependencies", {})
    if policy.get("forbid_circular_dependencies") and isinstance(declared, dict):
        boundary_adjacency: dict[str, set[str]] = {
            boundary: set() for boundary in declared
        }
        for source, destination in edges:
            source_boundary = _tach_boundary(source, declared)
            destination_boundary = _tach_boundary(destination, declared)
            if (
                source_boundary
                and destination_boundary
                and source_boundary != destination_boundary
            ):
                boundary_adjacency[source_boundary].add(destination_boundary)
        for component in _strong_components(boundary_adjacency):
            if len(component) < 2:
                continue
            source, destination = component[:2]
            key = (source, destination, "circular-dependency")
            violations[key] = {
                "kind": "circular-dependency",
                "source": source,
                "destination": destination,
                "rule": "Tach forbids circular dependencies among: "
                + ", ".join(component),
            }
            if len(violations) > _MAX_POLICY_VIOLATIONS:
                ordered = [violations[key] for key in sorted(violations)]
                return ordered[:_MAX_POLICY_VIOLATIONS], True
    return [violations[key] for key in sorted(violations)], False


def _tach_boundary(module: str, declared: dict[str, list[str]]) -> str | None:
    candidates = [
        pattern
        for pattern in declared
        if fnmatchcase(module, pattern)
        or ("*" not in pattern and module.startswith(f"{pattern}."))
    ]
    return max(candidates, key=len) if candidates else None


def _baseline_edges(target: Path) -> tuple[set[tuple[str, str]], bool, str | None]:
    path = target / Path(_BASELINE_PATH)
    if not path.is_file():
        return set(), False, None
    try:
        _, payload = read_regular_file(
            path,
            "architecture edge baseline",
            maximum_bytes=8 * 1024 * 1024,
            boundary=target,
        )
        document = strict_loads(payload)
        if (
            not isinstance(document, dict)
            or set(document) != {"schema_version", "edges"}
            or document.get("schema_version") != "1.0"
            or not isinstance(document.get("edges"), list)
            or len(document["edges"]) > _MAX_EDGES
        ):
            raise ValueError("invalid fields")
        edges: set[tuple[str, str]] = set()
        for item in document["edges"]:
            if not isinstance(item, str) or " -> " not in item:
                raise ValueError("invalid edge")
            source, destination = item.split(" -> ", 1)
            if not source or not destination:
                raise ValueError("invalid edge")
            edges.add((source, destination))
        return edges, True, None
    except (OSError, TypeError, ValueError) as exc:
        return set(), True, f"{_BASELINE_PATH}: {type(exc).__name__}"


def _source_roots(target: Path) -> list[Path]:
    roots = [target]
    source = target / "src"
    if source.is_dir():
        roots.insert(0, source)
    return roots


def _module_name(path: Path, roots: list[Path]) -> str | None:
    relative: Path | None = None
    for root in roots:
        try:
            relative = path.relative_to(root)
            break
        except ValueError:
            continue
    if relative is None:
        return None
    parts = list(relative.with_suffix("").parts)
    if parts and parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts) or None


def _imports(module: str, is_package: bool, tree: ast.AST) -> set[str]:
    values: set[str] = set()
    package = module if is_package else module.rpartition(".")[0]
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            values.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                parent_parts = package.split(".") if package else []
                trim = max(0, node.level - 1)
                base_parts = (
                    parent_parts[: len(parent_parts) - trim] if trim else parent_parts
                )
                base = ".".join([*base_parts, *(node.module or "").split(".")]).strip(
                    "."
                )
            else:
                base = node.module or ""
            if base:
                values.add(base)
                values.update(
                    f"{base}.{alias.name}" for alias in node.names if alias.name != "*"
                )
    return values


def _local_destination(imported: str, modules: dict[str, Path]) -> str | None:
    candidate = imported
    while candidate:
        if candidate in modules:
            return candidate
        candidate = candidate.rpartition(".")[0]
    return None


def _dynamic_imports(
    module: str,
    path: str,
    is_package: bool,
    tree: ast.AST,
    modules: dict[str, Path],
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    package = module if is_package else module.rpartition(".")[0]
    aliases = _architecture_aliases(tree, module, is_package)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _architecture_name(node.func, aliases)
        if name not in {"__import__", "importlib.import_module"}:
            continue
        target = (
            node.args[0].value
            if node.args
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
            else None
        )
        normalized = target
        if target and target.startswith("."):
            levels = len(target) - len(target.lstrip("."))
            parent = package.split(".") if package else []
            trim = max(0, levels - 1)
            prefix = parent[: len(parent) - trim] if trim else parent
            normalized = ".".join([*prefix, target.lstrip(".")]).strip(".")
        records.append(
            {
                "caller_module": module,
                "target": target,
                "literal": target is not None,
                "resolved_module": (
                    _local_destination(normalized, modules) if normalized else None
                ),
                "path": path,
                "line": int(getattr(node, "lineno", 1)),
            }
        )
    return records


def _symbol_graph(
    module: str,
    path: str,
    tree: ast.Module,
    modules: dict[str, Path],
) -> tuple[set[tuple[str, str, str, int]], list[dict[str, Any]]]:
    aliases = _architecture_aliases(
        tree, module, module in modules and path.endswith("__init__.py")
    )
    functions: list[tuple[ast.FunctionDef | ast.AsyncFunctionDef, str, str | None]] = []
    definitions: dict[str, str] = {}
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            symbol = f"{module}.{node.name}"
            functions.append((node, symbol, None))
            definitions[node.name] = symbol
        elif isinstance(node, ast.ClassDef):
            definitions[node.name] = f"{module}.{node.name}"
            for child in node.body:
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    functions.append(
                        (child, f"{module}.{node.name}.{child.name}", node.name)
                    )
    edges: set[tuple[str, str, str, int]] = set()
    entrypoints: list[dict[str, Any]] = []
    for function, source, owner in functions:
        decorators = sorted(
            {
                name
                for decorator in function.decorator_list
                if (name := _decorator_name(decorator, aliases))
            }
        )
        recognized = [
            name
            for name in decorators
            if name.rsplit(".", 1)[-1].casefold()
            in {
                "api_route",
                "command",
                "consumer",
                "delete",
                "get",
                "handler",
                "listener",
                "patch",
                "post",
                "put",
                "receiver",
                "route",
                "subscribe",
                "task",
            }
        ]
        if recognized:
            entrypoints.append(
                {
                    "symbol": source,
                    "kind": "decorator",
                    "evidence": recognized,
                    "path": path,
                    "line": int(function.lineno),
                }
            )
        for call in _owned_calls(function):
            destination = _architecture_name(
                call.func,
                aliases,
                module=module,
                owner_class=owner,
            )
            if destination in definitions:
                destination = definitions[destination]
            if not destination or not _local_symbol(destination, modules):
                continue
            edges.add((source, destination, path, int(getattr(call, "lineno", 1))))
    for node in tree.body:
        if not isinstance(node, ast.If) or not _is_main_guard(node.test):
            continue
        for call in (child for child in ast.walk(node) if isinstance(child, ast.Call)):
            destination = _architecture_name(call.func, aliases, module=module)
            if destination in definitions:
                destination = definitions[destination]
            if destination and _local_symbol(destination, modules):
                entrypoints.append(
                    {
                        "symbol": destination,
                        "kind": "main-guard",
                        "evidence": ["if __name__ == __main__"],
                        "path": path,
                        "line": int(getattr(call, "lineno", node.lineno)),
                    }
                )
    return edges, entrypoints


def _is_main_guard(node: ast.expr) -> bool:
    if not isinstance(node, ast.Compare) or len(node.ops) != 1:
        return False
    values = [node.left, *node.comparators]
    return any(
        isinstance(value, ast.Name) and value.id == "__name__" for value in values
    ) and any(
        isinstance(value, ast.Constant) and value.value == "__main__"
        for value in values
    )


def _declared_entrypoints(
    target: Path, modules: dict[str, Path]
) -> tuple[list[dict[str, Any]], str | None]:
    records: list[dict[str, Any]] = []
    for module, path in sorted(modules.items()):
        if path.name == "__main__.py":
            records.append(
                {
                    "symbol": module,
                    "kind": "module-main",
                    "evidence": [f"python -m {module.rpartition('.')[0] or module}"],
                    "path": path.relative_to(target).as_posix(),
                    "line": 1,
                }
            )
    pyproject = target / "pyproject.toml"
    if not pyproject.is_file():
        return records, None
    try:
        _, payload = read_regular_file(
            pyproject,
            "packaging entry points",
            maximum_bytes=2 * 1024 * 1024,
            boundary=target,
        )
        document = tomllib.loads(payload.decode("utf-8"))
        project = document.get("project", {})
        scripts = project.get("scripts", {}) if isinstance(project, dict) else {}
        if not isinstance(scripts, dict) or len(scripts) > 10_000:
            raise ValueError("invalid project scripts")
        for name, value in sorted(scripts.items()):
            if (
                not isinstance(name, str)
                or not isinstance(value, str)
                or ":" not in value
            ):
                raise ValueError("invalid project script")
            module, function = value.split(":", 1)
            function = function.split("[", 1)[0]
            script_path = modules.get(module)
            if not script_path or not function:
                continue
            records.append(
                {
                    "symbol": f"{module}.{function}",
                    "kind": "packaging-script",
                    "evidence": [name],
                    "path": script_path.relative_to(target).as_posix(),
                    "line": _symbol_line(script_path, function),
                }
            )
        return records, None
    except (
        OSError,
        TypeError,
        UnicodeError,
        ValueError,
        tomllib.TOMLDecodeError,
    ) as exc:
        return records, f"pyproject.toml entry points: {type(exc).__name__}"


def _symbol_line(path: Path, function: str) -> int:
    try:
        _, payload = read_regular_file(
            path,
            "entry point source",
            maximum_bytes=4 * 1024 * 1024,
            boundary=path.parent,
        )
        tree = ast.parse(payload)
    except (OSError, SyntaxError, UnicodeError, ValueError):
        return 1
    target = function.rsplit(".", 1)[-1]
    return next(
        (
            int(node.lineno)
            for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name == target
        ),
        1,
    )


def _merge_entrypoints(values: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: dict[tuple[str, str, int], dict[str, Any]] = {}
    for value in values:
        key = (str(value["symbol"]), str(value["path"]), int(value["line"]))
        existing = merged.get(key)
        if existing is None:
            merged[key] = {
                **value,
                "evidence": sorted(set(str(item) for item in value["evidence"])),
            }
            continue
        existing["evidence"] = sorted(
            set(existing["evidence"]) | {str(item) for item in value["evidence"]}
        )
        if existing["kind"] != value["kind"]:
            existing["kind"] = "multiple"
    return [merged[key] for key in sorted(merged)]


def _architecture_aliases(
    tree: ast.AST, module: str, is_package: bool
) -> dict[str, str]:
    aliases: dict[str, str] = {}
    package = module if is_package else module.rpartition(".")[0]
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                aliases[alias.asname or alias.name.split(".", 1)[0]] = alias.name
        elif isinstance(node, ast.ImportFrom):
            base = node.module or ""
            if node.level:
                parent = package.split(".") if package else []
                trim = max(0, node.level - 1)
                prefix = parent[: len(parent) - trim] if trim else parent
                base = ".".join([*prefix, *base.split(".")]).strip(".")
            for alias in node.names:
                if alias.name != "*":
                    aliases[alias.asname or alias.name] = ".".join(
                        part for part in (base, alias.name) if part
                    )
    return aliases


def _architecture_name(
    node: ast.expr,
    aliases: dict[str, str],
    *,
    module: str = "",
    owner_class: str | None = None,
) -> str | None:
    if isinstance(node, ast.Name):
        if owner_class and node.id in {"self", "cls"}:
            return f"{module}.{owner_class}"
        return aliases.get(node.id, node.id)
    if isinstance(node, ast.Attribute):
        parent = _architecture_name(
            node.value,
            aliases,
            module=module,
            owner_class=owner_class,
        )
        return f"{parent}.{node.attr}" if parent else None
    return None


def _decorator_name(node: ast.expr, aliases: dict[str, str]) -> str | None:
    target = node.func if isinstance(node, ast.Call) else node
    return _architecture_name(target, aliases)


def _owned_calls(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
) -> list[ast.Call]:
    calls: list[ast.Call] = []
    pending: list[ast.AST] = list(reversed(function.body))
    while pending:
        node = pending.pop()
        if isinstance(
            node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)
        ):
            continue
        if isinstance(node, ast.Call):
            calls.append(node)
        pending.extend(reversed(list(ast.iter_child_nodes(node))))
    return calls


def _local_symbol(symbol: str, modules: dict[str, Path]) -> bool:
    candidate = symbol
    while candidate:
        if candidate in modules:
            return True
        candidate = candidate.rpartition(".")[0]
    return False


def _strong_components(adjacency: dict[str, set[str]]) -> list[list[str]]:
    index = 0
    indices: dict[str, int] = {}
    lowlinks: dict[str, int] = {}
    stack: list[str] = []
    on_stack: set[str] = set()
    result: list[list[str]] = []

    def visit(node: str) -> None:
        nonlocal index
        indices[node] = index
        lowlinks[node] = index
        index += 1
        stack.append(node)
        on_stack.add(node)
        for neighbor in sorted(adjacency[node]):
            if neighbor not in indices:
                visit(neighbor)
                lowlinks[node] = min(lowlinks[node], lowlinks[neighbor])
            elif neighbor in on_stack:
                lowlinks[node] = min(lowlinks[node], indices[neighbor])
        if lowlinks[node] != indices[node]:
            return
        component: list[str] = []
        while stack:
            member = stack.pop()
            on_stack.remove(member)
            component.append(member)
            if member == node:
                break
        result.append(sorted(component))

    for node in sorted(adjacency):
        if node not in indices:
            visit(node)
    return result


def _cycle_finding(
    record: dict[str, Any], modules: dict[str, Path], target: Path
) -> Finding:
    module = str(record["modules"][0])
    path = modules[module].relative_to(target).as_posix()
    description = "Circular local-module dependency: " + ", ".join(record["modules"])
    return _finding(
        rule="ARCH-DEPENDENCY-CYCLE",
        title="Circular Python module dependency",
        description=description,
        impact="Circular ownership makes initialization order fragile, obscures dependency direction, and increases the blast radius of security-sensitive changes.",
        remediation="Extract the shared contract or invert the dependency so the modules form an acyclic direction of ownership.",
        severity=Severity.MEDIUM,
        path=path,
        evidence=record,
    )


def _fan_out_finding(
    record: dict[str, Any], modules: dict[str, Path], target: Path, threshold: int
) -> Finding:
    module = str(record["module"])
    path = modules[module].relative_to(target).as_posix()
    description = (
        f"{module} directly depends on {record['count']} local modules, above the "
        f"governed threshold {threshold}."
    )
    return _finding(
        rule="ARCH-EXCESSIVE-MODULE-FANOUT",
        title="Module coordinates too many local dependencies",
        description=description,
        impact="High fan-out often indicates mixed responsibilities and makes review, testing, and safe replacement of collaborators harder.",
        remediation="Split orchestration from domain behavior, introduce narrow interfaces, and move cohesive responsibilities behind smaller modules.",
        severity=Severity.LOW,
        path=path,
        evidence=record,
    )


def _hub_finding(
    record: dict[str, Any], modules: dict[str, Path], target: Path, threshold: int
) -> Finding:
    module = str(record["module"])
    path = modules[module].relative_to(target).as_posix()
    total = int(record["fan_in"]) + int(record["fan_out"])
    return _finding(
        rule="ARCH-HIGH-DEGREE-HUB",
        title="Module is a high-degree dependency hub",
        description=(
            f"{module} has fan-in {record['fan_in']} and fan-out {record['fan_out']} "
            f"for total degree {total}, above {threshold}."
        ),
        impact="A high-degree hub concentrates change and failure blast radius and can conceal mixed responsibilities behind one module boundary.",
        remediation="Separate stable interfaces from orchestration and move cohesive responsibilities into independently owned modules.",
        severity=Severity.MEDIUM,
        path=path,
        evidence=record,
    )


def _unstable_edge_finding(
    record: dict[str, Any],
    modules: dict[str, Path],
    target: Path,
    threshold: float,
) -> Finding:
    source = str(record["source"])
    path = modules[source].relative_to(target).as_posix()
    return _finding(
        rule="ARCH-STABLE-DEPENDS-ON-UNSTABLE",
        title="Stable module depends on a substantially less stable module",
        description=(
            f"{source} (instability {record['source_instability']}) depends on "
            f"{record['destination']} (instability {record['destination_instability']}), "
            f"meeting the configured delta {threshold}."
        ),
        impact="A widely depended-on stable module inherits churn and implementation detail from a less stable dependency.",
        remediation="Invert the dependency through a stable contract or move the volatile behavior behind an adapter.",
        severity=Severity.LOW,
        path=path,
        evidence=record,
    )


def _new_edge_finding(edge: str, modules: dict[str, Path], target: Path) -> Finding:
    source, destination = edge.split(" -> ", 1)
    path = modules[source].relative_to(target).as_posix()
    return _finding(
        rule="ARCH-NEW-DEPENDENCY-EDGE",
        title="New local dependency edge relative to architecture baseline",
        description=f"{source} now depends on {destination}.",
        impact="A new dependency can bypass intended ownership or layering even when it does not immediately form a cycle.",
        remediation="Review the edge against the architecture contract and update the baseline only after explicit approval.",
        severity=Severity.LOW,
        path=path,
        evidence={"source": source, "destination": destination},
    )


def _policy_finding(
    record: dict[str, str], modules: dict[str, Path], target: Path
) -> Finding:
    source = record["source"]
    source_path = modules.get(source)
    if source_path is None:
        candidates = [
            path for module, path in modules.items() if module.startswith(f"{source}.")
        ]
        source_path = min(candidates, default=min(modules.values()))
    path = source_path.relative_to(target).as_posix()
    description = (
        record["rule"]
        if record["kind"] == "circular-dependency"
        else (
            f"{source} depends on {record['destination']}, violating "
            f"{record['kind']}: {record['rule']}."
        )
    )
    return _finding(
        rule="ARCH-POLICY-VIOLATION",
        title="Declared architecture policy is violated",
        description=description,
        impact="The implemented dependency direction conflicts with the repository's reviewed ownership and layering contract.",
        remediation="Remove or invert the dependency, introduce an allowed interface, or update the architecture policy through explicit review.",
        severity=Severity.HIGH,
        path=path,
        evidence=record,
    )


def _finding(
    *,
    rule: str,
    title: str,
    description: str,
    impact: str,
    remediation: str,
    severity: Severity,
    path: str,
    evidence: dict[str, Any],
) -> Finding:
    finding_id, fingerprint = finding_identity(
        tool="static-architecture", rule_id=rule, path=path
    )
    return Finding(
        finding_id=finding_id,
        fingerprint=fingerprint,
        title=title,
        description=description,
        impact=impact,
        remediation=remediation,
        severity=severity,
        confidence=Confidence.HIGH,
        area="architecture",
        domain="quality",
        classifications=[rule],
        locations=[Location(path=path, start_line=1)],
        sources=[Source(tool="static-architecture", rule_id=rule, message=description)],
        evidence={"static_architecture": evidence},
    )
