from __future__ import annotations

import ast
import copy
import hashlib
from collections import defaultdict
from pathlib import Path
from typing import Any

from .models import (
    Citation,
    Confidence,
    Finding,
    Location,
    Severity,
    Source,
    finding_identity,
)
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
_MAX_ISSUES = 500
_POLICY_PATH = "security/code-health-policy.json"
_DEFAULT_THRESHOLDS = {
    "cognitive_complexity": 15,
    "function_lines": 100,
    "parameters": 8,
    "class_lines": 800,
    "duplicate_function_lines": 12,
    "semantic_clone_lines": 20,
    "nesting_depth": 5,
    "function_call_targets": 20,
    "class_methods": 30,
    "class_lack_of_cohesion_percent": 80,
    "swallowed_broad_exceptions": 0,
    "async_blocking_calls": 0,
    "module_mutable_globals": 0,
}

_BLOCKING_CALLS = frozenset(
    {
        "os.system",
        "subprocess.call",
        "subprocess.check_call",
        "subprocess.check_output",
        "subprocess.run",
        "time.sleep",
        "urllib.request.urlopen",
    }
)


def analyze_code_health(target: Path) -> tuple[list[Finding], dict[str, Any]]:
    issues: list[dict[str, Any]] = []
    parse_errors: list[str] = []
    thresholds, policy_present, policy_error = _load_policy(target)
    if policy_error:
        parse_errors.append(policy_error)
    bodies: dict[str, list[dict[str, Any]]] = defaultdict(list)
    semantic_bodies: dict[str, list[dict[str, Any]]] = defaultdict(list)
    eligible_paths = [
        path
        for path in target.rglob("*.py")
        if not any(part in _SKIP for part in path.relative_to(target).parts)
    ]
    eligible_paths.sort()
    file_limit_exceeded = len(eligible_paths) > _MAX_FILES
    files_analyzed = 0
    for path in eligible_paths[:_MAX_FILES]:
        relative = path.relative_to(target)
        try:
            _, payload = read_regular_file(
                path,
                "code health source",
                maximum_bytes=4 * 1024 * 1024,
                boundary=target,
            )
            tree = ast.parse(payload, filename=relative.as_posix())
        except (OSError, SyntaxError, UnicodeError, ValueError) as exc:
            parse_errors.append(f"{relative.as_posix()}: {type(exc).__name__}")
            continue
        files_analyzed += 1
        mutable_globals = _mutable_module_globals(tree)
        if len(mutable_globals) > thresholds["module_mutable_globals"]:
            issues.append(
                _issue(
                    "module-mutable-globals",
                    relative,
                    mutable_globals[0][1],
                    len(mutable_globals),
                    thresholds["module_mutable_globals"],
                    symbol=", ".join(name for name, _ in mutable_globals[:5]),
                )
            )
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                end = int(node.end_lineno or node.lineno)
                length = end - int(node.lineno) + 1
                complexity = _cognitive_complexity(node)
                parameters = (
                    len(node.args.posonlyargs)
                    + len(node.args.args)
                    + len(node.args.kwonlyargs)
                )
                if node.args.vararg:
                    parameters += 1
                if node.args.kwarg:
                    parameters += 1
                nesting = _maximum_nesting(node)
                call_targets = _call_target_count(node)
                swallowed = _swallowed_broad_exceptions(node)
                blocking_calls = (
                    _async_blocking_calls(node)
                    if isinstance(node, ast.AsyncFunctionDef)
                    else []
                )
                if complexity > thresholds["cognitive_complexity"]:
                    issues.append(
                        _issue(
                            "cognitive-complexity",
                            relative,
                            node,
                            complexity,
                            thresholds["cognitive_complexity"],
                        )
                    )
                if length > thresholds["function_lines"]:
                    issues.append(
                        _issue(
                            "long-function",
                            relative,
                            node,
                            length,
                            thresholds["function_lines"],
                        )
                    )
                if parameters > thresholds["parameters"]:
                    issues.append(
                        _issue(
                            "parameter-coupling",
                            relative,
                            node,
                            parameters,
                            thresholds["parameters"],
                        )
                    )
                if nesting > thresholds["nesting_depth"]:
                    issues.append(
                        _issue(
                            "deep-nesting",
                            relative,
                            node,
                            nesting,
                            thresholds["nesting_depth"],
                        )
                    )
                if call_targets > thresholds["function_call_targets"]:
                    issues.append(
                        _issue(
                            "excessive-call-coupling",
                            relative,
                            node,
                            call_targets,
                            thresholds["function_call_targets"],
                        )
                    )
                if swallowed > thresholds["swallowed_broad_exceptions"]:
                    issues.append(
                        _issue(
                            "swallowed-broad-exception",
                            relative,
                            node,
                            swallowed,
                            thresholds["swallowed_broad_exceptions"],
                        )
                    )
                if len(blocking_calls) > thresholds["async_blocking_calls"]:
                    issues.append(
                        _issue(
                            "async-blocking-call",
                            relative,
                            node,
                            len(blocking_calls),
                            thresholds["async_blocking_calls"],
                            symbol=f"{node.name}: {', '.join(blocking_calls[:5])}",
                        )
                    )
                if length >= thresholds["duplicate_function_lines"]:
                    normalized_body = ast.Module(body=node.body, type_ignores=[])
                    digest = hashlib.sha256(
                        (
                            ast.dump(node.args, include_attributes=False)
                            + ast.dump(normalized_body, include_attributes=False)
                        ).encode()
                    ).hexdigest()
                    record = {
                        "path": relative.as_posix(),
                        "line": int(node.lineno),
                        "end_line": end,
                        "name": node.name,
                        "exact_digest": digest,
                    }
                    bodies[digest].append(record)
                    if length >= thresholds["semantic_clone_lines"]:
                        semantic_bodies[_semantic_digest(node)].append(record)
            elif isinstance(node, ast.ClassDef):
                end = int(node.end_lineno or node.lineno)
                length = end - int(node.lineno) + 1
                methods = sum(
                    isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
                    for child in node.body
                )
                if length > thresholds["class_lines"]:
                    issues.append(
                        _issue(
                            "large-class",
                            relative,
                            node,
                            length,
                            thresholds["class_lines"],
                        )
                    )
                if methods > thresholds["class_methods"]:
                    issues.append(
                        _issue(
                            "excessive-class-responsibilities",
                            relative,
                            node,
                            methods,
                            thresholds["class_methods"],
                        )
                    )
                lack_of_cohesion = _class_lack_of_cohesion_percent(node)
                if (
                    lack_of_cohesion is not None
                    and lack_of_cohesion > thresholds["class_lack_of_cohesion_percent"]
                ):
                    issues.append(
                        _issue(
                            "low-class-cohesion",
                            relative,
                            node,
                            lack_of_cohesion,
                            thresholds["class_lack_of_cohesion_percent"],
                        )
                    )
    for group in bodies.values():
        distinct_paths = {str(item["path"]) for item in group}
        if len(group) < 2 or len(distinct_paths) < 2:
            continue
        ordered = sorted(group, key=lambda item: (str(item["path"]), int(item["line"])))
        issues.append(
            {
                "kind": "duplicate-function",
                "path": ordered[0]["path"],
                "line": ordered[0]["line"],
                "end_line": ordered[0]["end_line"],
                "symbol": ordered[0]["name"],
                "value": len(ordered),
                "threshold": 1,
                "duplicates": [
                    {key: value for key, value in item.items() if key != "exact_digest"}
                    for item in ordered[1:20]
                ],
            }
        )
    for group in semantic_bodies.values():
        distinct_paths = {str(item["path"]) for item in group}
        exact_digests = {str(item["exact_digest"]) for item in group}
        if len(group) < 2 or len(distinct_paths) < 2 or len(exact_digests) < 2:
            continue
        ordered = sorted(group, key=lambda item: (str(item["path"]), int(item["line"])))
        issues.append(
            {
                "kind": "semantic-clone",
                "path": ordered[0]["path"],
                "line": ordered[0]["line"],
                "end_line": ordered[0]["end_line"],
                "symbol": ordered[0]["name"],
                "value": len(ordered),
                "threshold": 1,
                "duplicates": [
                    {key: value for key, value in item.items() if key != "exact_digest"}
                    for item in ordered[1:20]
                ],
            }
        )
    issues.sort(
        key=lambda item: (str(item["path"]), int(item["line"]), str(item["kind"]))
    )
    issues_detected = len(issues)
    issue_limit_exceeded = issues_detected > _MAX_ISSUES
    issues = issues[:_MAX_ISSUES]
    findings = [_finding(item) for item in issues]
    return findings, {
        "schema_version": "1.2",
        "analysis": "python-cognitive-complexity-size-coupling-and-duplication",
        "files_analyzed": files_analyzed,
        "complete": not parse_errors
        and not file_limit_exceeded
        and not issue_limit_exceeded,
        "truncated": file_limit_exceeded or issue_limit_exceeded,
        "issues_detected": issues_detected,
        "issues": issues,
        "parse_errors_detected": len(parse_errors),
        "parse_errors_omitted": max(0, len(parse_errors) - 100),
        "parse_errors": parse_errors[:100],
        "policy_path": _POLICY_PATH if policy_present else None,
        "policy_present": policy_present,
        "thresholds": thresholds,
        "limitations": [
            "Structural metrics prioritize review; they do not prove incorrect behavior or an architectural defect.",
            *(
                ["Analysis output was truncated at a governed resource limit."]
                if file_limit_exceeded or issue_limit_exceeded
                else []
            ),
        ],
    }


def _load_policy(target: Path) -> tuple[dict[str, int], bool, str | None]:
    thresholds = dict(_DEFAULT_THRESHOLDS)
    path = target / Path(_POLICY_PATH)
    if not path.is_file():
        return thresholds, False, None
    try:
        _, payload = read_regular_file(
            path, "code health policy", maximum_bytes=64 * 1024, boundary=target
        )
        document = strict_loads(payload)
        if (
            not isinstance(document, dict)
            or set(document) != {"schema_version", "thresholds"}
            or document.get("schema_version") != "1.0"
            or not isinstance(document.get("thresholds"), dict)
            or not set(document["thresholds"]).issubset(thresholds)
        ):
            raise ValueError("invalid policy fields")
        for name, value in document["thresholds"].items():
            minimum = (
                0
                if name
                in {
                    "swallowed_broad_exceptions",
                    "async_blocking_calls",
                    "module_mutable_globals",
                }
                else 1
            )
            maximum = 100 if name == "class_lack_of_cohesion_percent" else 10000
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or not minimum <= value <= maximum
            ):
                raise ValueError(f"invalid threshold: {name}")
            thresholds[name] = value
        return thresholds, True, None
    except (OSError, TypeError, ValueError) as exc:
        return thresholds, True, f"{_POLICY_PATH}: {type(exc).__name__}"


class _SemanticNormalizer(ast.NodeTransformer):
    def visit_Name(self, node: ast.Name) -> ast.AST:  # noqa: N802
        return ast.copy_location(ast.Name(id="_name", ctx=node.ctx), node)

    def visit_arg(self, node: ast.arg) -> ast.AST:  # noqa: N802
        replacement = ast.arg(
            arg="_arg", annotation=node.annotation, type_comment=node.type_comment
        )
        return ast.copy_location(replacement, node)

    def visit_Constant(self, node: ast.Constant) -> ast.AST:  # noqa: N802
        if node.value is None or isinstance(node.value, bool):
            return node
        value: str | int = "_string" if isinstance(node.value, str) else 0
        return ast.copy_location(ast.Constant(value=value), node)


def _semantic_digest(node: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
    normalized = copy.deepcopy(node)
    normalized.name = "_function"
    transformed = _SemanticNormalizer().visit(normalized)
    ast.fix_missing_locations(transformed)
    return hashlib.sha256(
        ast.dump(transformed, include_attributes=False).encode()
    ).hexdigest()


def _cognitive_complexity(function: ast.AST) -> int:
    score = 0

    def walk(node: ast.AST, nesting: int) -> None:
        nonlocal score
        branching = isinstance(
            node,
            (
                ast.If,
                ast.For,
                ast.AsyncFor,
                ast.While,
                ast.Try,
                ast.TryStar,
                ast.With,
                ast.AsyncWith,
                ast.Match,
            ),
        )
        if branching:
            score += 1 + nesting
            nesting += 1
        elif isinstance(node, (ast.Break, ast.Continue)):
            score += 1
        elif isinstance(node, ast.BoolOp):
            score += max(1, len(node.values) - 1)
        for child in ast.iter_child_nodes(node):
            if child is not function and isinstance(
                child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)
            ):
                continue
            walk(child, nesting)

    walk(function, 0)
    return score


def _maximum_nesting(function: ast.AST) -> int:
    maximum = 0

    def walk(node: ast.AST, depth: int) -> None:
        nonlocal maximum
        nested = isinstance(
            node,
            (
                ast.If,
                ast.For,
                ast.AsyncFor,
                ast.While,
                ast.Try,
                ast.TryStar,
                ast.With,
                ast.AsyncWith,
                ast.Match,
            ),
        )
        next_depth = depth + 1 if nested else depth
        maximum = max(maximum, next_depth)
        for child in ast.iter_child_nodes(node):
            if child is not function and isinstance(
                child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)
            ):
                continue
            walk(child, next_depth)

    walk(function, 0)
    return maximum


def _call_target_count(function: ast.AST) -> int:
    targets: set[str] = set()

    def walk(node: ast.AST) -> None:
        if isinstance(node, ast.Call):
            current: ast.expr = node.func
            parts: list[str] = []
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
            if parts:
                targets.add(".".join(reversed(parts)))
        for child in ast.iter_child_nodes(node):
            if child is not function and isinstance(
                child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)
            ):
                continue
            walk(child)

    walk(function)
    return len(targets)


def _call_name(node: ast.expr) -> str | None:
    parts: list[str] = []
    current = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
    return ".".join(reversed(parts)) if parts else None


def _swallowed_broad_exceptions(function: ast.AST) -> int:
    count = 0
    pending = list(ast.iter_child_nodes(function))
    while pending:
        node = pending.pop()
        if node is not function and isinstance(
            node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)
        ):
            continue
        if not isinstance(node, ast.ExceptHandler):
            pending.extend(ast.iter_child_nodes(node))
            continue
        broad = node.type is None or (
            isinstance(node.type, ast.Name)
            and node.type.id in {"BaseException", "Exception"}
        )
        raises = any(
            isinstance(descendant, ast.Raise)
            for child in node.body
            for descendant in ast.walk(child)
        )
        if broad and not raises:
            calls = {
                name
                for child in node.body
                for call in ast.walk(child)
                if isinstance(call, ast.Call)
                if (name := _call_name(call.func))
            }
            if not any(
                name.casefold().endswith(
                    (".debug", ".error", ".exception", ".info", ".log", ".warning")
                )
                for name in calls
            ):
                count += 1
        pending.extend(ast.iter_child_nodes(node))
    return count


def _async_blocking_calls(function: ast.AST) -> list[str]:
    found: set[str] = set()

    def walk(node: ast.AST, suppressed: bool = False) -> None:
        if node is not function and isinstance(
            node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)
        ):
            return
        if isinstance(node, ast.Call):
            name = _call_name(node.func)
            offloaded = bool(
                name == "asyncio.to_thread" or (name or "").endswith(".run_in_executor")
            )
            if (
                not suppressed
                and name
                and (name in _BLOCKING_CALLS or name.startswith("requests."))
            ):
                found.add(name)
            suppressed = suppressed or offloaded
        for child in ast.iter_child_nodes(node):
            walk(child, suppressed)

    walk(function)
    return sorted(found)


def _mutable_module_globals(tree: ast.Module) -> list[tuple[str, ast.AST]]:
    candidates: dict[str, ast.AST] = {}
    for node in tree.body:
        name: str | None = None
        value: ast.AST | None = None
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            if isinstance(node.targets[0], ast.Name):
                name, value = node.targets[0].id, node.value
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            name, value = node.target.id, node.value
        if not name or value is None or name.isupper():
            continue
        mutable = isinstance(value, (ast.List, ast.Dict, ast.Set)) or (
            isinstance(value, ast.Call)
            and _call_name(value.func)
            in {"collections.defaultdict", "defaultdict", "dict", "list", "set"}
        )
        if mutable:
            candidates[name] = node
    mutated: set[str] = set()
    mutators = {
        "add",
        "append",
        "clear",
        "discard",
        "extend",
        "insert",
        "pop",
        "popitem",
        "remove",
        "reverse",
        "setdefault",
        "sort",
        "update",
    }
    for current in ast.walk(tree):
        if (
            isinstance(current, ast.Call)
            and isinstance(current.func, ast.Attribute)
            and current.func.attr in mutators
            and isinstance(current.func.value, ast.Name)
            and current.func.value.id in candidates
        ):
            mutated.add(current.func.value.id)
        targets: list[ast.AST] = []
        if isinstance(current, (ast.Assign, ast.Delete)):
            targets.extend(current.targets)
        elif isinstance(current, (ast.AnnAssign, ast.AugAssign)):
            targets.append(current.target)
        for target in targets:
            if (
                isinstance(target, ast.Subscript)
                and isinstance(target.value, ast.Name)
                and target.value.id in candidates
            ):
                mutated.add(target.value.id)
    return [(name, candidates[name]) for name in sorted(mutated)]


def _class_lack_of_cohesion_percent(node: ast.ClassDef) -> int | None:
    fields: list[set[str]] = []
    for method in node.body:
        if not isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        parents = {
            child: parent
            for parent in ast.walk(method)
            for child in ast.iter_child_nodes(parent)
        }
        used = {
            child.attr
            for child in ast.walk(method)
            if isinstance(child, ast.Attribute)
            and isinstance(child.value, ast.Name)
            and child.value.id in {"self", "cls"}
            and not _is_call_target(child, parents)
        }
        fields.append(used)
    if len(fields) < 4:
        return None
    pairs = [
        (left, right)
        for index, left in enumerate(fields)
        for right in fields[index + 1 :]
    ]
    if not pairs or not any(left or right for left, right in pairs):
        return None
    disjoint = sum(not (left & right) for left, right in pairs)
    return round(disjoint * 100 / len(pairs))


def _is_call_target(node: ast.Attribute, parents: dict[ast.AST, ast.AST]) -> bool:
    parent = parents.get(node)
    return isinstance(parent, ast.Call) and parent.func is node


def _issue(
    kind: str,
    path: Path,
    node: ast.AST,
    value: int,
    threshold: int,
    *,
    symbol: str | None = None,
) -> dict[str, Any]:
    return {
        "kind": kind,
        "path": path.as_posix(),
        "line": int(getattr(node, "lineno", 1)),
        "end_line": int(getattr(node, "end_lineno", getattr(node, "lineno", 1))),
        "symbol": symbol or str(getattr(node, "name", "<block>")),
        "value": value,
        "threshold": threshold,
        "duplicates": [],
    }


def _finding(issue: dict[str, Any]) -> Finding:
    kind = str(issue["kind"])
    metadata = {
        "cognitive-complexity": (
            "Excessive cognitive complexity",
            Severity.MEDIUM,
            "CODE-COGNITIVE-COMPLEXITY",
        ),
        "long-function": ("Oversized function", Severity.LOW, "CODE-LONG-FUNCTION"),
        "parameter-coupling": (
            "High parameter coupling",
            Severity.LOW,
            "CODE-PARAMETER-COUPLING",
        ),
        "large-class": ("Oversized class", Severity.MEDIUM, "CODE-LARGE-CLASS"),
        "duplicate-function": (
            "Duplicated function implementation",
            Severity.MEDIUM,
            "CODE-DUPLICATE-FUNCTION",
        ),
        "semantic-clone": (
            "Structurally duplicated function implementation",
            Severity.LOW,
            "CODE-SEMANTIC-CLONE",
        ),
        "deep-nesting": (
            "Deeply nested control flow",
            Severity.MEDIUM,
            "CODE-DEEP-NESTING",
        ),
        "excessive-call-coupling": (
            "Excessive function call coupling",
            Severity.LOW,
            "CODE-EXCESSIVE-CALL-COUPLING",
        ),
        "excessive-class-responsibilities": (
            "Class has excessive responsibilities",
            Severity.MEDIUM,
            "CODE-EXCESSIVE-CLASS-RESPONSIBILITIES",
        ),
        "low-class-cohesion": (
            "Class methods have low state cohesion",
            Severity.MEDIUM,
            "CODE-LOW-CLASS-COHESION",
        ),
        "swallowed-broad-exception": (
            "Broad exception is swallowed",
            Severity.MEDIUM,
            "CODE-SWALLOWED-BROAD-EXCEPTION",
        ),
        "async-blocking-call": (
            "Blocking call is made from async code",
            Severity.MEDIUM,
            "CODE-ASYNC-BLOCKING-CALL",
        ),
        "module-mutable-globals": (
            "Module exposes mutable global state",
            Severity.LOW,
            "CODE-MUTABLE-GLOBAL-STATE",
        ),
    }
    title, severity, rule_id = metadata[kind]
    path, line = str(issue["path"]), int(issue["line"])
    finding_id, fingerprint = finding_identity(
        tool="code-health", rule_id=rule_id, path=path, start_line=line
    )
    description = f"{issue['symbol']} has {kind} value {issue['value']} above the governed threshold {issue['threshold']}."
    if issue["duplicates"]:
        description += " Matching implementations: " + ", ".join(
            f"{item['path']}:{item['line']}" for item in issue["duplicates"][:5]
        )
    return Finding(
        finding_id=finding_id,
        fingerprint=fingerprint,
        title=title,
        description=description,
        impact="The structure increases review cost, regression probability, hidden coupling, or the chance that security-relevant branches receive incomplete tests.",
        remediation="Split responsibilities behind explicit contracts, remove duplication, and add focused branch and mutation tests before accepting an exception.",
        severity=severity,
        confidence=Confidence.HIGH,
        area="maintainability",
        domain="quality",
        classifications=[rule_id],
        locations=[
            Location(path=path, start_line=line, end_line=int(issue["end_line"]))
        ],
        sources=[
            Source(
                tool="code-health",
                rule_id=rule_id,
                message=description,
                native_severity=severity.value,
            )
        ],
        citations=[
            Citation(
                kind="tool_rule",
                identifier=rule_id,
                title="Cognitive complexity and duplication review",
                uri="https://github.com/rohaquinlop/complexipy",
            )
        ],
        evidence={"code_health": issue},
    )
