from __future__ import annotations

import ast
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
_MAX_FINDINGS = 500
_MAX_POLICY_VIOLATIONS = 1000
_FAN_OUT_THRESHOLD = 12
_HUB_THRESHOLD = 20
_INSTABILITY_DELTA = 0.5
_BASELINE_PATH = "security/baselines/architecture-edges.json"
_POLICY_PATH = "security/architecture-policy.json"


def analyze_static_architecture(target: Path) -> tuple[list[Finding], dict[str, Any]]:
    policy, policy_present, policy_error = _architecture_policy(target)
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
        if len(edges) >= _MAX_EDGES:
            break
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
    )
    return findings, {
        "schema_version": "1.1",
        "analysis": "python-local-module-dependency-graph",
        "complete": complete,
        "files_analyzed": len(modules),
        "modules_detected": len(modules),
        "edges_detected": len(edges),
        "cycles_detected": len(cycle_records),
        "fan_out_hotspots_detected": len(fan_out),
        "hub_modules_detected": len(hubs),
        "unstable_dependency_edges_detected": len(unstable_edges),
        "cycles": cycle_records[:500],
        "fan_out_hotspots": fan_out[:500],
        "module_metrics": module_metrics,
        "hub_modules": hubs[:500],
        "unstable_dependency_edges": unstable_edges[:1000],
        "baseline_path": _BASELINE_PATH if baseline_present else None,
        "baseline_present": baseline_present,
        "new_dependency_edges": new_edges[:1000],
        "policy_path": _POLICY_PATH if policy_present else None,
        "policy_present": policy_present,
        "policy_violations_detected": len(policy_violations) + int(policy_truncated),
        "policy_violations": policy_violations,
        "parse_errors": parse_errors[:1000],
        "truncated": file_truncated
        or len(edges) >= _MAX_EDGES
        or findings_detected > _MAX_FINDINGS
        or policy_truncated,
        "thresholds": thresholds,
        "claim_boundary": (
            "The graph resolves statically recognizable imports among Python modules in the "
            "repository. Dynamic imports, plugin registration, generated modules, and runtime "
            "dependency injection may add or remove effective coupling."
        ),
    }


def _instability(fan_in: int, fan_out: int) -> float:
    denominator = fan_in + fan_out
    return round(fan_out / denominator, 4) if denominator else 0.0


def _architecture_policy(
    target: Path,
) -> tuple[dict[str, Any], bool, str | None]:
    default: dict[str, object] = {
        "thresholds": {
            "module_fan_out": _FAN_OUT_THRESHOLD,
            "hub_total_degree": _HUB_THRESHOLD,
            "instability_delta": _INSTABILITY_DELTA,
        },
        "layers": [],
        "forbidden_edges": [],
    }
    path = target / Path(_POLICY_PATH)
    if not path.is_file():
        return default, False, None
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
            },
            True,
            None,
        )
    except (OSError, TypeError, ValueError) as exc:
        return default, True, f"{_POLICY_PATH}: {type(exc).__name__}"


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
    return [violations[key] for key in sorted(violations)], False


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
    path = modules[source].relative_to(target).as_posix()
    return _finding(
        rule="ARCH-POLICY-VIOLATION",
        title="Declared architecture policy is violated",
        description=(
            f"{source} depends on {record['destination']}, violating "
            f"{record['kind']}: {record['rule']}."
        ),
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
