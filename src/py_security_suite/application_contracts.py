from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

from .models import (
    Confidence,
    Finding,
    Location,
    Severity,
    Source,
    finding_identity,
)
from .path_safety import read_regular_file
from .strict_json import canonical_bytes, loads as strict_loads


_HTTP_METHODS = frozenset(
    {"DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT", "TRACE"}
)
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
_CURRENT_OPENAPI = ("openapi.json", "docs/openapi.json", "security/openapi.json")
_BASELINE_OPENAPI = "security/baselines/openapi.json"
_CONTRACT_PATH = "security/application-contracts.json"
_MAX_FILES = 50_000


def analyze_application_contracts(
    target: Path, artifacts: dict[str, Any]
) -> tuple[list[Finding], dict[str, Any]]:
    routes, calls, parse_errors = _discover_python_surface(target)
    current_path, current_operations, current_error = _load_openapi_candidates(
        target, _CURRENT_OPENAPI
    )
    baseline_path, baseline_operations, baseline_error = _load_openapi_candidates(
        target, (_BASELINE_OPENAPI,)
    )
    contract, contract_error = _load_contract(target)
    test_cases = _test_case_observations(artifacts)
    passed_test_ids = {
        str(item["id"])
        for item in test_cases
        if item["result"] == "passed" and item["source_bound"] is True
    }
    errors = [
        value
        for value in (*parse_errors, current_error, baseline_error, contract_error)
        if value
    ]

    route_keys = {f"{item['method']} {item['path']}" for item in routes}
    current_keys = set(current_operations)
    undocumented = sorted(route_keys - current_keys) if current_path else []
    unimplemented = sorted(current_keys - route_keys) if current_path else []
    auth_regressions = sorted(
        key
        for key in set(baseline_operations) & current_keys
        if baseline_operations[key]["security_required"]
        and not current_operations[key]["security_required"]
    )
    contract_regressions = _operation_regressions(
        baseline_operations, current_operations
    )

    business_records = _business_records(contract["endpoints"], passed_test_ids)
    vulnerable_matches = _vulnerable_matches(
        contract["vulnerable_functions"], calls, routes
    )
    findings: list[Finding] = []
    findings.extend(_route_findings(routes, undocumented))
    findings.extend(_unimplemented_spec_findings(current_path, unimplemented))
    findings.extend(_auth_regression_findings(routes, auth_regressions))
    findings.extend(_contract_regression_findings(routes, contract_regressions))
    findings.extend(_business_findings(routes, business_records))
    findings.extend(_vulnerable_call_findings(vulnerable_matches))
    complete = not errors and not (
        undocumented
        or unimplemented
        or auth_regressions
        or contract_regressions
        or any(item["gaps"] for item in business_records)
        or vulnerable_matches
    )
    artifact = {
        "schema_version": "1.0",
        "analysis": "application-contract-and-vulnerable-call-analysis",
        "complete": complete,
        "routes": routes,
        "openapi": {
            "current_path": current_path,
            "baseline_path": baseline_path,
            "current_operations": sorted(current_keys),
            "baseline_operations": sorted(baseline_operations),
            "undocumented_code_routes": undocumented,
            "unimplemented_spec_operations": unimplemented,
            "authorization_regressions": auth_regressions,
            "contract_regressions": contract_regressions,
        },
        "contract_path": _CONTRACT_PATH if contract["present"] else None,
        "contract_present": contract["present"],
        "observed_test_ids": sorted({str(item["id"]) for item in test_cases})[:10_000],
        "observed_test_cases": test_cases,
        "business_logic": business_records,
        "vulnerable_call_matches": vulnerable_matches,
        "errors": errors[:1000],
        "claim_boundary": (
            "Route reconciliation is limited to statically recognizable Python decorators. "
            "Business-logic coverage proves only that declared test identities passed in "
            "source-bound retained evidence. "
            "Vulnerable-call matches prove an exact syntactic call to a manifest-listed symbol, "
            "not that the call executes in production or that exploit preconditions hold."
        ),
    }
    return findings, artifact


def _discover_python_surface(
    target: Path,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[str]]:
    routes: list[dict[str, Any]] = []
    calls: list[dict[str, Any]] = []
    errors: list[str] = []
    analyzed = 0
    for path in sorted(target.rglob("*.py")):
        relative = path.relative_to(target)
        if any(part in _SKIP for part in relative.parts):
            continue
        if analyzed >= _MAX_FILES:
            errors.append(
                f"application contract analysis exceeded {_MAX_FILES} Python files"
            )
            break
        analyzed += 1
        try:
            _, payload = read_regular_file(
                path,
                "application contract source",
                maximum_bytes=4 * 1024 * 1024,
                boundary=target,
            )
            tree = ast.parse(payload, filename=relative.as_posix())
        except (OSError, SyntaxError, UnicodeError, ValueError) as exc:
            errors.append(f"{relative.as_posix()}: {type(exc).__name__}")
            continue
        aliases = _import_aliases(tree)
        module = _source_module(relative)
        local_functions = {
            node.name
            for node in tree.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                routes.extend(_routes_for_function(relative.as_posix(), module, node))
                caller = f"{module}.{node.name}"
                for call in _calls_in_function(node):
                    name = _qualified_name(call.func, aliases)
                    if name in local_functions:
                        name = f"{module}.{name}"
                    if name:
                        calls.append(
                            {
                                "symbol": name,
                                "caller": caller,
                                "path": relative.as_posix(),
                                "line": int(getattr(call, "lineno", 1)),
                            }
                        )
    return _unique_dicts(routes), _unique_dicts(calls), errors[:1000]


def _routes_for_function(
    path: str, module: str, node: ast.FunctionDef | ast.AsyncFunctionDef
) -> list[dict[str, Any]]:
    routes: list[dict[str, Any]] = []
    for decorator in node.decorator_list:
        if not isinstance(decorator, ast.Call) or not isinstance(
            decorator.func, ast.Attribute
        ):
            continue
        attribute = decorator.func.attr.casefold()
        route_path = _literal_string(decorator.args[0]) if decorator.args else None
        if not route_path:
            continue
        methods: list[str] = []
        if attribute.upper() in _HTTP_METHODS:
            methods = [attribute.upper()]
        elif attribute in {"route", "api_route"}:
            for keyword in decorator.keywords:
                if keyword.arg == "methods" and isinstance(
                    keyword.value, (ast.List, ast.Tuple, ast.Set)
                ):
                    methods = [
                        value.upper()
                        for element in keyword.value.elts
                        if (value := _literal_string(element))
                        and value.upper() in _HTTP_METHODS
                    ]
            if not methods:
                methods = ["GET"]
        for method in sorted(set(methods)):
            routes.append(
                {
                    "method": method,
                    "path": route_path,
                    "source_path": path,
                    "line": int(
                        getattr(decorator, "lineno", getattr(node, "lineno", 1))
                    ),
                    "handler": node.name,
                    "handler_symbol": f"{module}.{node.name}",
                }
            )
    return routes


def _source_module(relative: Path) -> str:
    parts = list(relative.with_suffix("").parts)
    if parts and parts[0] == "src":
        parts.pop(0)
    if parts and parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts) or "<module>"


def _calls_in_function(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> list[ast.Call]:
    """Return calls owned by *node*, excluding nested callable scopes."""

    calls: list[ast.Call] = []
    pending: list[ast.AST] = list(reversed(node.body))
    while pending:
        current = pending.pop()
        if isinstance(
            current,
            (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda),
        ):
            continue
        if isinstance(current, ast.Call):
            calls.append(current)
        pending.extend(reversed(list(ast.iter_child_nodes(current))))
    return calls


def _import_aliases(tree: ast.AST) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                aliases[alias.asname or alias.name.split(".", 1)[0]] = alias.name
        elif isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"
    return aliases


def _qualified_name(node: ast.expr, aliases: dict[str, str]) -> str | None:
    if isinstance(node, ast.Name):
        return aliases.get(node.id, node.id)
    if isinstance(node, ast.Attribute):
        parent = _qualified_name(node.value, aliases)
        return f"{parent}.{node.attr}" if parent else None
    return None


def _literal_string(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str) and node.value:
        return node.value
    return None


def _load_openapi_candidates(
    target: Path, candidates: tuple[str, ...]
) -> tuple[str | None, dict[str, dict[str, Any]], str | None]:
    for relative in candidates:
        path = target / Path(relative)
        if not path.is_file():
            continue
        try:
            _, payload = read_regular_file(
                path, "OpenAPI contract", maximum_bytes=8 * 1024 * 1024, boundary=target
            )
            document = strict_loads(payload)
            if not isinstance(document, dict) or not isinstance(
                document.get("paths"), dict
            ):
                raise ValueError("OpenAPI paths are missing")
            root_security = document.get("security")
            operations: dict[str, dict[str, Any]] = {}
            for route, path_item in document["paths"].items():
                if not isinstance(route, str) or not isinstance(path_item, dict):
                    continue
                for method, operation in path_item.items():
                    upper = str(method).upper()
                    if upper not in _HTTP_METHODS or not isinstance(operation, dict):
                        continue
                    security = operation.get("security", root_security)
                    parameters = [
                        *(
                            path_item.get("parameters", [])
                            if isinstance(path_item.get("parameters"), list)
                            else []
                        ),
                        *(
                            operation.get("parameters", [])
                            if isinstance(operation.get("parameters"), list)
                            else []
                        ),
                    ]
                    request_body = operation.get("requestBody")
                    operations[f"{upper} {route}"] = {
                        "security_required": isinstance(security, list)
                        and bool(security),
                        "security": _security_requirements(security),
                        "required_inputs": _required_inputs(
                            parameters, request_body, document
                        ),
                        "constraints": _request_constraints(
                            parameters, request_body, document
                        ),
                    }
            return relative, operations, None
        except (OSError, TypeError, ValueError) as exc:
            return relative, {}, f"{relative}: {type(exc).__name__}"
    return None, {}, None


def _security_requirements(value: object) -> dict[str, list[str]]:
    result: dict[str, set[str]] = {}
    if not isinstance(value, list):
        return {}
    for alternative in value:
        if not isinstance(alternative, dict):
            continue
        for scheme, scopes in alternative.items():
            bucket = result.setdefault(str(scheme), set())
            if isinstance(scopes, list):
                bucket.update(str(scope) for scope in scopes)
    return {scheme: sorted(scopes) for scheme, scopes in sorted(result.items())}


def _required_inputs(
    parameters: list[object], request_body: object, document: dict[str, Any]
) -> list[str]:
    required: set[str] = set()
    for raw in parameters[:10_000]:
        parameter = _resolve_schema(raw, document)
        if not isinstance(parameter, dict) or parameter.get("required") is not True:
            continue
        location = str(parameter.get("in") or "parameter")
        name = str(parameter.get("name") or "")
        if name:
            required.add(f"{location}:{name}")
    body = _resolve_schema(request_body, document)
    if isinstance(body, dict):
        if body.get("required") is True:
            required.add("body:<request>")
        for media_type, schema in _content_schemas(body):
            resolved = _resolve_schema(schema, document)
            if not isinstance(resolved, dict):
                continue
            raw_required = resolved.get("required", [])
            if isinstance(raw_required, list):
                required.update(
                    f"body:{media_type}:{name}"
                    for name in raw_required
                    if isinstance(name, str) and name
                )
    return sorted(required)


def _request_constraints(
    parameters: list[object], request_body: object, document: dict[str, Any]
) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for raw in parameters[:10_000]:
        parameter = _resolve_schema(raw, document)
        if not isinstance(parameter, dict):
            continue
        name = str(parameter.get("name") or "")
        location = str(parameter.get("in") or "parameter")
        schema = _resolve_schema(parameter.get("schema"), document)
        if name and isinstance(schema, dict):
            _collect_constraints(schema, f"{location}:{name}", document, result, 0)
    body = _resolve_schema(request_body, document)
    if isinstance(body, dict):
        for media_type, schema in _content_schemas(body):
            resolved = _resolve_schema(schema, document)
            if isinstance(resolved, dict):
                _collect_constraints(
                    resolved, f"body:{media_type}", document, result, 0
                )
    return dict(sorted(result.items()))


def _content_schemas(body: dict[str, Any]) -> list[tuple[str, object]]:
    content = body.get("content")
    if not isinstance(content, dict):
        return []
    return [
        (str(media_type), value.get("schema"))
        for media_type, value in content.items()
        if isinstance(value, dict)
    ][:100]


def _resolve_schema(value: object, document: dict[str, Any]) -> object:
    current = value
    seen: set[str] = set()
    for _ in range(20):
        if not isinstance(current, dict) or not isinstance(current.get("$ref"), str):
            return current
        reference = str(current["$ref"])
        if not reference.startswith("#/") or reference in seen:
            return current
        seen.add(reference)
        resolved: object = document
        for part in reference[2:].split("/"):
            if not isinstance(resolved, dict):
                return current
            resolved = resolved.get(part.replace("~1", "/").replace("~0", "~"))
        current = resolved
    return current


def _collect_constraints(
    schema: dict[str, Any],
    path: str,
    document: dict[str, Any],
    result: dict[str, dict[str, Any]],
    depth: int,
) -> None:
    if depth > 20 or len(result) >= 10_000:
        return
    resolved = _resolve_schema(schema, document)
    if not isinstance(resolved, dict):
        return
    constraint_keys = (
        "minLength",
        "maxLength",
        "minimum",
        "maximum",
        "pattern",
        "enum",
    )
    constraints = {key: resolved[key] for key in constraint_keys if key in resolved}
    if constraints:
        result[path] = constraints
    properties = resolved.get("properties")
    if isinstance(properties, dict):
        for name, child in list(properties.items())[:1000]:
            if isinstance(child, dict):
                _collect_constraints(
                    child, f"{path}.{name}", document, result, depth + 1
                )
    items = resolved.get("items")
    if isinstance(items, dict):
        _collect_constraints(items, f"{path}[]", document, result, depth + 1)


def _operation_regressions(
    baseline: dict[str, dict[str, Any]], current: dict[str, dict[str, Any]]
) -> list[dict[str, str]]:
    regressions: list[dict[str, str]] = []
    for operation in sorted(set(baseline) & set(current)):
        before, after = baseline[operation], current[operation]
        for value in sorted(
            set(before.get("required_inputs", []))
            - set(after.get("required_inputs", []))
        ):
            regressions.append(
                {
                    "operation": operation,
                    "kind": "required-input-removed",
                    "subject": value,
                }
            )
        before_security = before.get("security", {})
        after_security = after.get("security", {})
        if isinstance(before_security, dict) and isinstance(after_security, dict):
            for scheme, scopes in before_security.items():
                removed = set(scopes) - set(after_security.get(scheme, []))
                for scope in sorted(removed):
                    regressions.append(
                        {
                            "operation": operation,
                            "kind": "security-scope-removed",
                            "subject": f"{scheme}:{scope}",
                        }
                    )
        before_constraints = before.get("constraints", {})
        after_constraints = after.get("constraints", {})
        if isinstance(before_constraints, dict) and isinstance(after_constraints, dict):
            for subject, old in before_constraints.items():
                new = after_constraints.get(subject, {})
                if not isinstance(old, dict) or not isinstance(new, dict):
                    continue
                for reason in _weakened_constraints(old, new):
                    regressions.append(
                        {
                            "operation": operation,
                            "kind": "request-constraint-weakened",
                            "subject": f"{subject}:{reason}",
                        }
                    )
    return regressions[:10_000]


def _weakened_constraints(old: dict[str, Any], new: dict[str, Any]) -> list[str]:
    result: list[str] = []
    if "pattern" in old and "pattern" not in new:
        result.append("pattern-removed")
    if "enum" in old and isinstance(old["enum"], list):
        new_enum = new.get("enum")
        old_values = {canonical_bytes(value) for value in old["enum"]}
        new_values = (
            {canonical_bytes(value) for value in new_enum}
            if isinstance(new_enum, list)
            else set()
        )
        if not isinstance(new_enum, list) or not new_values.issubset(old_values):
            result.append("enum-expanded-or-removed")
    for key, direction in (
        ("minLength", "lower"),
        ("minimum", "lower"),
        ("maxLength", "higher"),
        ("maximum", "higher"),
    ):
        if key not in old:
            continue
        if key not in new:
            result.append(f"{key}-removed")
            continue
        try:
            weakened = (
                float(new[key]) < float(old[key])
                if direction == "lower"
                else float(new[key]) > float(old[key])
            )
        except (TypeError, ValueError):
            weakened = True
        if weakened:
            result.append(f"{key}-weakened")
    return result


def _load_contract(target: Path) -> tuple[dict[str, Any], str | None]:
    empty = {"present": False, "endpoints": [], "vulnerable_functions": []}
    path = target / Path(_CONTRACT_PATH)
    if not path.is_file():
        return empty, None
    try:
        _, payload = read_regular_file(
            path,
            "application contracts",
            maximum_bytes=4 * 1024 * 1024,
            boundary=target,
        )
        document = strict_loads(payload)
    except (OSError, TypeError, ValueError) as exc:
        return {**empty, "present": True}, f"{_CONTRACT_PATH}: {type(exc).__name__}"
    if (
        not isinstance(document, dict)
        or set(document) != {"schema_version", "endpoints", "vulnerable_functions"}
        or document.get("schema_version") != "1.0"
        or not isinstance(document.get("endpoints"), list)
        or not isinstance(document.get("vulnerable_functions"), list)
        or len(document["endpoints"]) > 10_000
        or len(document["vulnerable_functions"]) > 10_000
    ):
        return {**empty, "present": True}, f"{_CONTRACT_PATH}: invalid root fields"
    endpoints: list[dict[str, Any]] = []
    endpoint_fields = {
        "method",
        "path",
        "tenant_scoped",
        "allow_test_ids",
        "deny_test_ids",
        "cross_tenant_test_ids",
    }
    for index, item in enumerate(document["endpoints"]):
        if (
            not isinstance(item, dict)
            or set(item) != endpoint_fields
            or str(item.get("method", "")).upper() not in _HTTP_METHODS
            or not _strings(item.get("allow_test_ids"))
            or not _strings(item.get("deny_test_ids"))
            or not _strings(item.get("cross_tenant_test_ids"), allow_empty=True)
            or not isinstance(item.get("tenant_scoped"), bool)
            or not isinstance(item.get("path"), str)
            or not item["path"]
        ):
            return {
                **empty,
                "present": True,
            }, f"{_CONTRACT_PATH}: endpoint {index} is invalid"
        endpoints.append({**item, "method": str(item["method"]).upper()})
    vulnerable: list[dict[str, Any]] = []
    vulnerable_fields = {"package", "advisory_id", "symbols"}
    for index, item in enumerate(document["vulnerable_functions"]):
        if (
            not isinstance(item, dict)
            or set(item) != vulnerable_fields
            or not isinstance(item.get("package"), str)
            or not item["package"]
            or not isinstance(item.get("advisory_id"), str)
            or not item["advisory_id"]
            or not _strings(item.get("symbols"))
        ):
            return {
                **empty,
                "present": True,
            }, f"{_CONTRACT_PATH}: vulnerable function {index} is invalid"
        vulnerable.append(dict(item))
    return {
        "present": True,
        "endpoints": endpoints,
        "vulnerable_functions": vulnerable,
    }, None


def _strings(value: object, *, allow_empty: bool = False) -> bool:
    return (
        isinstance(value, list)
        and (allow_empty or bool(value))
        and len(value) <= 10_000
        and all(isinstance(item, str) and item.strip() for item in value)
        and len(value) == len(set(value))
    )


def _test_case_observations(artifacts: dict[str, Any]) -> list[dict[str, Any]]:
    inventory = artifacts.get("source-inventory.json")
    source_sha256 = (
        str(inventory.get("source_sha256") or "") if isinstance(inventory, dict) else ""
    )
    result: dict[tuple[str, str], dict[str, Any]] = {}
    budget = 100_000
    stack: list[tuple[str, object, bool]] = [
        (
            name,
            value,
            isinstance(value, dict)
            and bool(source_sha256)
            and value.get("source_sha256") == source_sha256,
        )
        for name, value in artifacts.items()
        if any(
            token in name
            for token in (
                "test",
                "junit",
                "hypothesis",
                "schemathesis",
                "authorization",
            )
        )
    ]
    while stack and budget > 0:
        budget -= 1
        source, value, source_bound = stack.pop()
        if isinstance(value, dict):
            identifier = next(
                (
                    value[key]
                    for key in ("id", "name", "nodeid", "test_case_id")
                    if isinstance(value.get(key), str) and value[key]
                ),
                None,
            )
            raw_result = next(
                (
                    value[key]
                    for key in ("result", "outcome", "status")
                    if isinstance(value.get(key), str)
                ),
                "unknown",
            )
            normalized_result = {
                "pass": "passed",
                "passed": "passed",
                "success": "passed",
                "ok": "passed",
                "failure": "failed",
                "failed": "failed",
                "error": "failed",
                "skipped": "skipped",
            }.get(str(raw_result).casefold(), "unknown")
            if identifier:
                key = (source, str(identifier))
                result[key] = {
                    "id": str(identifier),
                    "source": source,
                    "result": normalized_result,
                    "source_bound": source_bound,
                }
            for child in value.values():
                if isinstance(child, (dict, list)):
                    stack.append((source, child, source_bound))
        elif isinstance(value, list):
            stack.extend(
                (source, item, source_bound)
                for item in value
                if isinstance(item, (dict, list))
            )
    return sorted(
        result.values(), key=lambda item: (str(item["id"]), str(item["source"]))
    )[:10_000]


def _business_records(
    endpoints: list[dict[str, Any]], test_ids: set[str]
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for endpoint in endpoints:
        required = {
            "allow": list(endpoint["allow_test_ids"]),
            "deny": list(endpoint["deny_test_ids"]),
            "cross_tenant": list(endpoint["cross_tenant_test_ids"]),
        }
        missing = {kind: sorted(set(ids) - test_ids) for kind, ids in required.items()}
        gaps: list[str] = []
        for kind in ("allow", "deny", "cross_tenant"):
            if missing[kind]:
                gaps.append(
                    f"missing {kind.replace('_', '-')} evidence: {', '.join(missing[kind])}"
                )
        if endpoint["tenant_scoped"] and not required["cross_tenant"]:
            gaps.append("tenant-scoped endpoint has no cross-tenant denial obligation")
        records.append(
            {
                "method": endpoint["method"],
                "path": endpoint["path"],
                "tenant_scoped": endpoint["tenant_scoped"],
                "required_test_ids": required,
                "missing_test_ids": missing,
                "gaps": gaps,
                "complete": not gaps,
            }
        )
    return records


def _vulnerable_matches(
    declarations: list[dict[str, Any]],
    calls: list[dict[str, Any]],
    routes: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    matches: list[dict[str, Any]] = []
    by_symbol: dict[str, list[dict[str, Any]]] = {}
    for call in calls:
        by_symbol.setdefault(str(call["symbol"]), []).append(call)
    callers_by_callee: dict[str, set[str]] = {}
    for call in calls:
        caller = str(call.get("caller") or "")
        if caller:
            callers_by_callee.setdefault(str(call["symbol"]), set()).add(caller)
    entrypoints = {
        str(route["handler_symbol"]): f"{route['method']} {route['path']}"
        for route in routes
    }
    for declaration in declarations:
        for symbol in declaration["symbols"]:
            for call in by_symbol.get(symbol, []):
                caller = str(call.get("caller") or "")
                chain, entrypoint = _entrypoint_chain(
                    caller, symbol, callers_by_callee, entrypoints
                )
                matches.append(
                    {
                        "package": declaration["package"],
                        "advisory_id": declaration["advisory_id"],
                        "symbol": symbol,
                        "path": call["path"],
                        "line": call["line"],
                        "direct_caller": caller or None,
                        "call_chain": chain,
                        "entrypoint": entrypoint,
                        "entrypoint_reachable": entrypoint is not None,
                    }
                )
    return _unique_dicts(matches)[:10_000]


def _entrypoint_chain(
    direct_caller: str,
    vulnerable_symbol: str,
    callers_by_callee: dict[str, set[str]],
    entrypoints: dict[str, str],
) -> tuple[list[str], str | None]:
    if not direct_caller:
        return [vulnerable_symbol], None
    queue: list[tuple[str, list[str]]] = [(direct_caller, [direct_caller])]
    seen: set[str] = set()
    while queue and len(seen) < 10_000:
        current, reverse_chain = queue.pop(0)
        if current in seen:
            continue
        seen.add(current)
        if current in entrypoints:
            return [*reverse_chain, vulnerable_symbol], entrypoints[current]
        for caller in sorted(callers_by_callee.get(current, set())):
            queue.append((caller, [caller, *reverse_chain]))
    return [direct_caller, vulnerable_symbol], None


def _route_findings(
    routes: list[dict[str, Any]], undocumented: list[str]
) -> list[Finding]:
    by_key = {f"{item['method']} {item['path']}": item for item in routes}
    return [
        _finding(
            rule="API-UNDOCUMENTED-ROUTE",
            title=f"Code route is absent from OpenAPI: {key}",
            description="A statically discovered route is not declared by the retained OpenAPI document.",
            impact="Undocumented attack surface can escape contract testing, authorization review, and gateway policy.",
            remediation="Add the route to OpenAPI or remove the unintended handler, then rerun contract and authorization tests.",
            severity=Severity.MEDIUM,
            classification="CWE-1059",
            path=str(by_key[key]["source_path"]),
            line=int(by_key[key]["line"]),
            evidence={"operation": key},
        )
        for key in undocumented
        if key in by_key
    ]


def _auth_regression_findings(
    routes: list[dict[str, Any]], regressions: list[str]
) -> list[Finding]:
    by_key = {f"{item['method']} {item['path']}": item for item in routes}
    return [
        _finding(
            rule="API-AUTHORIZATION-REGRESSION",
            title=f"OpenAPI authorization requirement was removed: {key}",
            description="The baseline required security for this operation, but the current contract does not.",
            impact="Clients or gateways generated from the current contract may expose the operation without the prior authentication requirement.",
            remediation="Restore the security requirement or retain a reviewed, tested authorization-change decision.",
            severity=Severity.HIGH,
            classification="CWE-862",
            path=str(by_key.get(key, {}).get("source_path") or "openapi.json"),
            line=int(by_key.get(key, {}).get("line") or 1),
            evidence={"operation": key},
        )
        for key in regressions
    ]


def _unimplemented_spec_findings(
    current_path: str | None, operations: list[str]
) -> list[Finding]:
    if current_path is None:
        return []
    return [
        _finding(
            rule="API-SPEC-OPERATION-WITHOUT-HANDLER",
            title=f"OpenAPI operation has no recognizable code route: {operation}",
            description="The retained OpenAPI document declares this operation, but no matching Python route decorator was discovered.",
            impact="The contract may be stale, the handler may be dynamically registered outside analyzable boundaries, or an intended control path may be missing.",
            remediation="Implement or remove the operation, or retain the dynamic route registration as governed semantic evidence.",
            severity=Severity.LOW,
            classification="CWE-1059",
            path=current_path,
            line=1,
            evidence={"operation": operation},
        )
        for operation in operations
    ]


def _contract_regression_findings(
    routes: list[dict[str, Any]], regressions: list[dict[str, str]]
) -> list[Finding]:
    by_key = {f"{item['method']} {item['path']}": item for item in routes}
    findings: list[Finding] = []
    for regression in regressions:
        operation = regression["operation"]
        route = by_key.get(operation, {})
        authorization = regression["kind"] == "security-scope-removed"
        findings.append(
            _finding(
                rule=(
                    "API-AUTHORIZATION-SCOPE-REGRESSION"
                    if authorization
                    else "API-REQUEST-CONTRACT-WEAKENED"
                ),
                title=f"API input protection regressed: {operation}",
                description=(
                    f"{regression['kind']} for {regression['subject']} relative to "
                    "the retained OpenAPI baseline."
                ),
                impact=(
                    "A broader request or authorization contract can admit inputs or "
                    "permissions that the prior security boundary rejected."
                ),
                remediation=(
                    "Restore the requirement or retain a reviewed change with passing "
                    "negative, boundary, and authorization tests."
                ),
                severity=Severity.HIGH if authorization else Severity.MEDIUM,
                classification="CWE-863" if authorization else "CWE-20",
                path=str(route.get("source_path") or "openapi.json"),
                line=int(route.get("line") or 1),
                evidence=regression,
            )
        )
    return findings


def _business_findings(
    routes: list[dict[str, Any]], records: list[dict[str, Any]]
) -> list[Finding]:
    by_key = {f"{item['method']} {item['path']}": item for item in routes}
    findings: list[Finding] = []
    for record in records:
        if not record["gaps"]:
            continue
        key = f"{record['method']} {record['path']}"
        route = by_key.get(key, {})
        findings.append(
            _finding(
                rule="BUSINESS-LOGIC-EVIDENCE-GAP",
                title=f"Authorization behavior lacks retained tests: {key}",
                description="; ".join(record["gaps"]),
                impact="Allow, deny, or tenant-isolation behavior can regress without a source-bound executable oracle.",
                remediation="Run and retain the declared positive, negative, and cross-tenant test identities for this endpoint.",
                severity=Severity.HIGH if record["tenant_scoped"] else Severity.MEDIUM,
                classification="CWE-284",
                path=str(route.get("source_path") or _CONTRACT_PATH),
                line=int(route.get("line") or 1),
                evidence=record,
            )
        )
    return findings


def _vulnerable_call_findings(matches: list[dict[str, Any]]) -> list[Finding]:
    return [
        _finding(
            rule="VULNERABLE-FUNCTION-CALL",
            title=f"Call to advisory-listed function {item['symbol']}",
            description=(
                f"The exact symbol is listed for {item['package']} under "
                f"{item['advisory_id']} and is called in source"
                + (
                    f" from API entry point {item['entrypoint']}."
                    if item["entrypoint_reachable"]
                    else "."
                )
            ),
            impact=(
                "The vulnerable dependency surface is statically reachable from an "
                "application entry point; exploitability still depends on inputs and "
                "runtime preconditions."
                if item["entrypoint_reachable"]
                else "The vulnerable dependency surface is syntactically used; runtime "
                "entry-point reachability and exploit preconditions remain unproven."
            ),
            remediation="Upgrade or remove the affected dependency, or prove the call is unreachable or outside the advisory's affected preconditions.",
            severity=(
                Severity.HIGH if item["entrypoint_reachable"] else Severity.MEDIUM
            ),
            classification="CWE-1104",
            path=str(item["path"]),
            line=int(item["line"]),
            evidence=item,
        )
        for item in matches
    ]


def _finding(
    *,
    rule: str,
    title: str,
    description: str,
    impact: str,
    remediation: str,
    severity: Severity,
    classification: str,
    path: str,
    line: int,
    evidence: dict[str, Any],
) -> Finding:
    finding_id, fingerprint = finding_identity(
        tool="application-contracts", rule_id=rule, path=path, start_line=line
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
        area="application-contracts",
        domain="security",
        classifications=[rule, classification],
        locations=[Location(path=path, start_line=line)],
        sources=[
            Source(tool="application-contracts", rule_id=rule, message=description)
        ],
        evidence={"application_contracts": evidence},
    )


def _unique_dicts(values: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    seen: set[tuple[tuple[str, str], ...]] = set()
    for value in values:
        identity = tuple(sorted((str(key), repr(item)) for key, item in value.items()))
        if identity not in seen:
            seen.add(identity)
            result.append(value)
    return result
