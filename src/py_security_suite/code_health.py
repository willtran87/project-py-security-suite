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


def analyze_code_health(target: Path) -> tuple[list[Finding], dict[str, Any]]:
    issues: list[dict[str, Any]] = []
    parse_errors: list[str] = []
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
                if complexity > 15:
                    issues.append(
                        _issue("cognitive-complexity", relative, node, complexity, 15)
                    )
                if length > 100:
                    issues.append(_issue("long-function", relative, node, length, 100))
                if parameters > 8:
                    issues.append(
                        _issue("parameter-coupling", relative, node, parameters, 8)
                    )
                if length >= 12:
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
                    if length >= 20:
                        semantic_bodies[_semantic_digest(node)].append(record)
            elif isinstance(node, ast.ClassDef):
                end = int(node.end_lineno or node.lineno)
                length = end - int(node.lineno) + 1
                if length > 800:
                    issues.append(_issue("large-class", relative, node, length, 800))
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
        "schema_version": "1.0",
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
        "thresholds": {
            "cognitive_complexity": 15,
            "function_lines": 100,
            "parameters": 8,
            "class_lines": 800,
            "duplicate_function_lines": 12,
            "semantic_clone_lines": 20,
        },
        "limitations": [
            "Structural metrics prioritize review; they do not prove incorrect behavior or an architectural defect.",
            *(
                ["Analysis output was truncated at a governed resource limit."]
                if file_limit_exceeded or issue_limit_exceeded
                else []
            ),
        ],
    }


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


def _issue(
    kind: str, path: Path, node: ast.AST, value: int, threshold: int
) -> dict[str, Any]:
    return {
        "kind": kind,
        "path": path.as_posix(),
        "line": int(getattr(node, "lineno", 1)),
        "end_line": int(getattr(node, "end_lineno", getattr(node, "lineno", 1))),
        "symbol": str(getattr(node, "name", "<block>")),
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
