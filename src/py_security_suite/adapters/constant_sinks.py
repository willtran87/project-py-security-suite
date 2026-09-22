"""Bounded local constant evidence for reviewing native injection alerts.

An entirely constant string argument is a triage hint, not grounds for removing
an alert: local syntax cannot establish the native query's complete sink or
Python's runtime binding. No source execution, sanitizer names, import values,
or benchmark labels are used. Every native finding remains actionable.
"""

from __future__ import annotations

import ast
import hashlib
import operator
from collections.abc import Callable
from pathlib import Path
from typing import Any

from ..models import Finding
from ..source_index import parse_python, read_python_source

_UNKNOWN = object()
_RULES = {"py/xpath-injection": {"xpath", "XPath"}, "py/path-injection": {"open"}}
_BINARY = {ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul}
_COMPARE = {
    ast.Eq: operator.eq,
    ast.NotEq: operator.ne,
    ast.Lt: operator.lt,
    ast.LtE: operator.le,
    ast.Gt: operator.gt,
    ast.GtE: operator.ge,
    ast.In: lambda a, b: a in b,
    ast.NotIn: lambda a, b: a not in b,
}


class _Evaluator:
    def __init__(self) -> None:
        self.remaining = 2000

    def tick(self) -> None:
        self.remaining -= 1
        if self.remaining < 0:
            raise ValueError("constant proof budget exhausted")

    def value(self, node: ast.AST, env: dict[str, Any], depth: int = 0) -> Any:
        self.tick()
        if depth > 24:
            return _UNKNOWN

        def child(expr: ast.AST) -> Any:
            return self.value(expr, env, depth + 1)

        if isinstance(node, ast.Constant):
            result = node.value
        elif isinstance(node, ast.Name):
            result = env.get(node.id, _UNKNOWN)
        elif isinstance(node, ast.BinOp) and type(node.op) in _BINARY:
            left, right = child(node.left), child(node.right)
            if type(left) is int and type(right) is int:
                result = _BINARY[type(node.op)](left, right)
            elif (
                isinstance(node.op, ast.Add)
                and type(left) is str
                and type(right) is str
            ):
                result = left + right
            else:
                return _UNKNOWN
        elif isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            operand = child(node.operand)
            result = not operand if operand is not _UNKNOWN else _UNKNOWN
        elif (
            isinstance(node, ast.Compare)
            and len(node.ops) == 1
            and type(node.ops[0]) in _COMPARE
        ):
            left, right = child(node.left), child(node.comparators[0])
            if left is _UNKNOWN or right is _UNKNOWN:
                return _UNKNOWN
            try:
                result = _COMPARE[type(node.ops[0])](left, right)
            except (TypeError, ValueError):
                return _UNKNOWN
        elif isinstance(node, ast.IfExp):
            condition = child(node.test)
            result = (
                child(node.body if condition else node.orelse)
                if condition is not _UNKNOWN
                else _UNKNOWN
            )
        elif isinstance(node, ast.Subscript):
            value, index = child(node.value), child(node.slice)
            if type(value) is not str or type(index) is not int:
                return _UNKNOWN
            try:
                result = value[index]
            except IndexError:
                return _UNKNOWN
        elif isinstance(node, ast.JoinedStr):
            parts = []
            for part in node.values:
                if isinstance(part, ast.FormattedValue):
                    value = child(part.value)
                    if (
                        part.format_spec is not None
                        or part.conversion != -1
                        or value is _UNKNOWN
                    ):
                        return _UNKNOWN
                    parts.append(str(value))
                elif isinstance(part, ast.Constant) and type(part.value) is str:
                    parts.append(part.value)
                else:
                    return _UNKNOWN
            result = "".join(parts)
        else:
            return _UNKNOWN
        if type(result) is str and len(result) <= 4096:
            return result
        if type(result) is int and result.bit_length() <= 63:
            return result
        return result if result is None or type(result) is bool else _UNKNOWN

    def before(
        self, statements: list[ast.stmt], line: int, env: dict[str, Any]
    ) -> dict[str, Any] | None:
        for statement in statements:
            self.tick()
            if statement.lineno > line:
                return None
            if statement.lineno <= line <= (statement.end_lineno or statement.lineno):
                if isinstance(statement, ast.If):
                    condition = self.value(statement.test, env)
                    for branch, allowed in (
                        (statement.body, condition is _UNKNOWN or bool(condition)),
                        (statement.orelse, condition is _UNKNOWN or not condition),
                    ):
                        if allowed and any(
                            item.lineno <= line <= (item.end_lineno or item.lineno)
                            for item in branch
                        ):
                            found = self.before(branch, line, dict(env))
                            if found is not None:
                                return found
                    return None
                if isinstance(statement, ast.Try):
                    return self.before(statement.body, line, dict(env))
                if isinstance(
                    statement,
                    (ast.For, ast.While, ast.With, ast.AsyncFor, ast.AsyncWith),
                ):
                    return None
                return env
            if isinstance(statement, ast.Assign):
                value = self.value(statement.value, env)
                self.invalidate(statement, env)
                for target in statement.targets:
                    if isinstance(target, ast.Name):
                        env[target.id] = value
            elif isinstance(statement, ast.AnnAssign) and isinstance(
                statement.target, ast.Name
            ):
                env[statement.target.id] = (
                    self.value(statement.value, env)
                    if statement.value is not None
                    else _UNKNOWN
                )
            elif isinstance(statement, ast.If):
                condition = self.value(statement.test, env)
                branches = (
                    [statement.body, statement.orelse]
                    if condition is _UNKNOWN
                    else [statement.body if condition else statement.orelse]
                )
                states = [self.before(branch, line, dict(env)) for branch in branches]
                # before() returns the exit environment for a completed block.
                reaching = [state for state in states if state is not None]
                if not reaching:
                    return None
                env = {
                    key: value
                    for key, value in reaching[0].items()
                    if value is not _UNKNOWN
                    and all(
                        type(state.get(key, _UNKNOWN)) is type(value)
                        and state.get(key, _UNKNOWN) == value
                        for state in reaching
                    )
                }
            elif isinstance(
                statement, (ast.Return, ast.Raise, ast.Break, ast.Continue)
            ):
                return None
            else:
                self.invalidate(statement, env)
        return env

    @staticmethod
    def invalidate(statement: ast.stmt, env: dict[str, Any]) -> None:
        for node in ast.walk(statement):
            if isinstance(node, ast.Name) and isinstance(
                node.ctx, (ast.Store, ast.Del)
            ):
                env.pop(node.id, None)
            elif isinstance(node, (ast.Import, ast.ImportFrom)):
                for alias in node.names:
                    env.pop(alias.asname or alias.name.split(".")[0], None)
            elif isinstance(
                node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
            ):
                env.pop(node.name, None)


def constant_argument(tree: ast.Module, line: int, rule: str) -> bool:
    """Prove a single sink's entire string argument, within one lexical function."""
    functions = [
        node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.lineno <= line <= (node.end_lineno or node.lineno)
    ]
    if not functions or rule not in _RULES:
        return False
    function = max(functions, key=lambda node: node.lineno)
    # These constructs can change bindings beyond the local assignment model.
    if any(
        isinstance(
            node,
            (
                ast.Global,
                ast.Nonlocal,
                ast.Yield,
                ast.YieldFrom,
                ast.Await,
                ast.NamedExpr,
                ast.Lambda,
                ast.ListComp,
                ast.SetComp,
                ast.DictComp,
                ast.GeneratorExp,
                ast.ClassDef,
                ast.Match,
                ast.For,
                ast.AsyncFor,
                ast.While,
                ast.With,
                ast.AsyncWith,
                ast.TryStar,
            ),
        )
        or (
            isinstance(node, ast.Name)
            and node.id
            in {"exec", "eval", "locals", "globals", "_getframe", "currentframe"}
        )
        or (
            isinstance(node, ast.Attribute)
            and node.attr
            in {"exec", "eval", "locals", "globals", "_getframe", "currentframe"}
        )
        or (
            isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node is not function
        )
        for node in ast.walk(function)
        if getattr(node, "lineno", line) <= line
        or isinstance(node, (ast.Global, ast.Nonlocal))
    ):
        return False
    # Native alerts supply a line, which cannot disambiguate semicolon-separated
    # statements or an assignment and sink on the same line.
    statement_lines = [
        node.lineno
        for node in ast.walk(function)
        if isinstance(node, ast.stmt) and node.lineno <= line
    ]
    if len(set(statement_lines)) != len(statement_lines):
        return False
    calls = [
        node
        for node in ast.walk(function)
        if isinstance(node, ast.Call)
        and node.lineno == line
        and (
            node.func.id
            if isinstance(node.func, ast.Name)
            else node.func.attr
            if isinstance(node.func, ast.Attribute)
            else ""
        )
        in _RULES[rule]
    ]
    if len(calls) != 1:
        return False
    call = calls[0]
    if any(keyword.arg is None for keyword in call.keywords):
        return False
    keyword_name = "file" if rule == "py/path-injection" else "path"
    arguments = ([call.args[0]] if call.args else []) + [
        kw.value for kw in call.keywords if kw.arg == keyword_name
    ]
    if len(arguments) != 1:
        return False
    evaluator = _Evaluator()
    env = evaluator.before(function.body, line, {})
    return env is not None and type(evaluator.value(arguments[0], env)) is str


def annotate_constant_sinks(
    findings: list[Finding], root: Path, *, check: Callable[[], object]
) -> tuple[list[Finding], list[dict[str, object]]]:
    retained, reviewed = [], []
    cache: dict[str, tuple[ast.Module, str] | None] = {}
    for finding in findings:
        check()
        rules = {source.rule_id for source in finding.sources}
        if len(rules) != 1 or not rules <= _RULES.keys() or len(finding.locations) != 1:
            retained.append(finding)
            continue
        location, rule = finding.locations[0], next(iter(rules))
        try:
            if location.path not in cache:
                if len(cache) >= 4:
                    cache.clear()
                text = read_python_source(root / location.path, root)
                cache[location.path] = (
                    parse_python(text, location.path),
                    hashlib.sha256(text.encode()).hexdigest(),
                )
            entry = cache[location.path]
            if (
                entry is None
                or location.start_line is None
                or not constant_argument(entry[0], location.start_line, rule)
            ):
                retained.append(finding)
                continue
            check()
            review = {
                "finding_id": finding.finding_id,
                "rule_id": rule,
                "path": location.path,
                "line": location.start_line,
                "source_sha256": entry[1],
                "reason": "entire-sink-argument-is-a-local-constant-string",
                "native_finding_retained": True,
                "limitation": "local syntax does not establish runtime callee binding or native sink semantics",
            }
            finding.evidence["constant_sink_review"] = dict(review)
            reviewed.append(review)
            retained.append(finding)
        except TimeoutError:
            raise
        except (OSError, SyntaxError, TypeError, ValueError, RecursionError):
            cache[location.path] = None
            retained.append(finding)
    return retained, reviewed
