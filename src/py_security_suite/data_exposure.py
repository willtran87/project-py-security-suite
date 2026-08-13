from __future__ import annotations

import ast
import re
import tomllib
from pathlib import Path
from typing import Any

from .models import Citation, Finding


_MAX_FILES = 5000
_MAX_SURFACES = 500
_MAX_SDK_OBSERVATIONS = 500
_SKIP_DIRECTORIES = frozenset(
    {
        ".artifacts",
        ".git",
        ".hg",
        ".pysec-tools",
        ".svn",
        ".tox",
        ".venv",
        "__pycache__",
        "build",
        "dist",
        "node_modules",
        "venv",
    }
)
_EXPOSURE_CWES = frozenset(
    {"CWE-200", "CWE-201", "CWE-209", "CWE-215", "CWE-359", "CWE-532", "CWE-598"}
)
_SDK_CATALOG: dict[str, tuple[str, str]] = {
    "amplitude": ("Amplitude", "analytics"),
    "analytics": ("Segment/Analytics", "analytics"),
    "aiohttp": ("aiohttp", "network-egress"),
    "datadog": ("Datadog", "observability"),
    "ddtrace": ("Datadog APM", "observability"),
    "elasticapm": ("Elastic APM", "observability"),
    "httpx": ("HTTPX", "network-egress"),
    "honeycomb": ("Honeycomb", "observability"),
    "loguru": ("Loguru", "logging"),
    "logfire": ("Pydantic Logfire", "observability"),
    "mixpanel": ("Mixpanel", "analytics"),
    "newrelic": ("New Relic", "observability"),
    "opencensus": ("OpenCensus", "telemetry"),
    "opentelemetry": ("OpenTelemetry", "telemetry"),
    "prometheus_client": ("Prometheus client", "metrics"),
    "requests": ("Requests", "network-egress"),
    "raygun4py": ("Raygun", "error-monitoring"),
    "rollbar": ("Rollbar", "error-monitoring"),
    "sentry_sdk": ("Sentry SDK", "error-monitoring"),
    "statsd": ("StatsD", "metrics"),
    "structlog": ("structlog", "logging"),
    "aws_xray_sdk": ("AWS X-Ray SDK", "telemetry"),
    "posthog": ("PostHog", "analytics"),
    "bugsnag": ("Bugsnag", "error-monitoring"),
}
_DEPENDENCY_TO_IMPORT = {
    "amplitude-analytics": "amplitude",
    "analytics-python": "analytics",
    "datadog": "datadog",
    "ddtrace": "ddtrace",
    "elastic-apm": "elasticapm",
    "httpx": "httpx",
    "honeycomb-beeline": "honeycomb",
    "loguru": "loguru",
    "logfire": "logfire",
    "mixpanel": "mixpanel",
    "newrelic": "newrelic",
    "opencensus": "opencensus",
    "opentelemetry-api": "opentelemetry",
    "opentelemetry-sdk": "opentelemetry",
    "prometheus-client": "prometheus_client",
    "requests": "requests",
    "raygun4py": "raygun4py",
    "rollbar": "rollbar",
    "sentry-sdk": "sentry_sdk",
    "statsd": "statsd",
    "structlog": "structlog",
    "posthog": "posthog",
    "bugsnag": "bugsnag",
    "aws-xray-sdk": "aws_xray_sdk",
}
_LOG_METHODS = frozenset(
    {"critical", "debug", "error", "exception", "info", "log", "warning", "warn"}
)
_TELEMETRY_METHODS = {
    "add_custom_attribute": ("observability", "custom telemetry attribute"),
    "add_custom_attributes": ("observability", "custom telemetry attributes"),
    "add_breadcrumb": ("error-monitoring", "Sentry breadcrumb"),
    "add_event": ("telemetry", "trace event"),
    "capture_event": ("error-monitoring", "captured event"),
    "capture_exception": ("error-monitoring", "captured exception"),
    "capture_message": ("error-monitoring", "captured message"),
    "capture": ("analytics", "analytics event"),
    "identify": ("analytics", "analytics identity"),
    "notify": ("error-monitoring", "error notification"),
    "record_custom_event": ("observability", "custom telemetry event"),
    "record_exception": ("telemetry", "recorded exception"),
    "report_exc_info": ("error-monitoring", "reported exception"),
    "report_message": ("error-monitoring", "reported message"),
    "set_attribute": ("telemetry", "trace attribute"),
    "set_attributes": ("telemetry", "trace attributes"),
    "set_context": ("error-monitoring", "diagnostic context"),
    "set_extra": ("error-monitoring", "diagnostic extra"),
    "set_tag": ("observability", "trace tag"),
    "set_tags": ("observability", "trace tags"),
    "set_user": ("error-monitoring", "user context"),
    "track": ("analytics", "analytics event"),
}
_NETWORK_METHODS = frozenset(
    {"delete", "get", "head", "options", "patch", "post", "put", "request"}
)
_SANITIZER_HINT = re.compile(r"(?i)(?:hash|hmac|mask|redact|sanitize|scrub|tokenize)")
_SENSITIVE_HINT = re.compile(
    r"(?i)(?:account.?id|address|api.?key|auth(?:entication|orization|_?(?:header|token))|birth|card|connection.?string|cookie|credential|cvv|database.?url|diagnosis|dsn|email|health|ip.?address|medical|national.?id|otp|passw(?:or)?d|patient|phone|pin|private.?key|secret|session|social.?security|ssn|token|user.?id|username)"
)
_REQUEST_DATA_HINT = re.compile(
    r"(?i)(?:body|data|form|json|payload|post|query_params|request|response)"
)
_EXCEPTION_HINT = re.compile(r"(?i)(?:error|exception|exc|traceback)")
_RESPONSE_SINKS = frozenset(
    {"abort", "HTTPException", "HttpResponse", "JSONResponse", "JsonResponse"}
)


def build_data_exposure_synthesis(
    target: Path,
    findings: list[Finding],
    artifacts: dict[str, Any],
) -> dict[str, Any]:
    """Inventory disclosure sinks and enrich supported source-to-sink findings.

    The inventory is deliberately non-authoritative: a sink call is a review
    surface, not proof that sensitive data reaches it. Confirmed assessments
    require a normalized finding carrying an exposure CWE or an explicit
    data-exposure rule classification.
    """
    inventory = _inventory(target)
    assessments: list[dict[str, Any]] = []
    for finding in findings:
        if not _is_exposure_finding(finding):
            continue
        assessment = _assessment(finding, inventory, artifacts)
        finding.evidence["data_exposure"] = {
            key: value for key, value in assessment.items() if key != "finding_id"
        }
        _attach_citations(finding, assessment)
        assessments.append(assessment)

    production_surfaces = [
        item for item in inventory["sink_surfaces"] if item["scope"] == "production"
    ]
    observed_sdk_families = sorted(
        {
            str(item["family"])
            for item in inventory["sdk_observations"]
            if item.get("family")
        }
    )
    return {
        "schema_version": "1.0",
        "schema_id": "urn:project-py-security-suite:data-exposure:1.0",
        "authoritative": False,
        "purpose": (
            "bounded sensitive-data disclosure analysis across normalized taint "
            "findings, Python sink surfaces, SDK presence, and structural evidence"
        ),
        "summary": {
            "exposure_findings": len(assessments),
            "logging_findings": sum(
                item["sink_family"] == "logging" for item in assessments
            ),
            "telemetry_findings": sum(
                item["sink_family"]
                in {
                    "analytics",
                    "error-monitoring",
                    "metrics",
                    "observability",
                    "telemetry",
                }
                for item in assessments
            ),
            "production_sink_surfaces": len(production_surfaces),
            "test_sink_surfaces": len(inventory["sink_surfaces"])
            - len(production_surfaces),
            "sdk_families_observed": len(observed_sdk_families),
            "files_analyzed": inventory["files_analyzed"],
            "parse_errors": inventory["parse_errors"],
        },
        "finding_assessments": sorted(
            assessments,
            key=lambda item: (
                {"high": 0, "medium": 1, "low": 2}[str(item["confidence"])],
                str(item["finding_id"]),
            ),
        ),
        "sink_surfaces": inventory["sink_surfaces"][:_MAX_SURFACES],
        "sdk_observations": inventory["sdk_observations"][:_MAX_SDK_OBSERVATIONS],
        "standards": [
            {
                "identifier": "CWE-532",
                "title": "Insertion of Sensitive Information into Log File",
                "uri": "https://cwe.mitre.org/data/definitions/532.html",
            },
            {
                "identifier": "CWE-201",
                "title": "Insertion of Sensitive Information Into Sent Data",
                "uri": "https://cwe.mitre.org/data/definitions/201.html",
            },
            {
                "identifier": "CWE-209",
                "title": "Generation of Error Message Containing Sensitive Information",
                "uri": "https://cwe.mitre.org/data/definitions/209.html",
            },
            {
                "identifier": "CWE-598",
                "title": "Use of HTTP Request With Sensitive Query String",
                "uri": "https://cwe.mitre.org/data/definitions/598.html",
            },
            {
                "identifier": "OWASP-LOGGING",
                "title": "OWASP Logging Cheat Sheet",
                "uri": "https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html",
            },
            {
                "identifier": "OTEL-SENSITIVE-DATA",
                "title": "OpenTelemetry handling sensitive data",
                "uri": "https://opentelemetry.io/docs/security/handling-sensitive-data/",
            },
        ],
        "limits": {
            "maximum_python_files": _MAX_FILES,
            "maximum_sink_surfaces": _MAX_SURFACES,
            "maximum_sdk_observations": _MAX_SDK_OBSERVATIONS,
            "files_omitted": inventory["files_omitted"],
            "sink_surfaces_omitted": max(
                0, len(inventory["sink_surfaces"]) - _MAX_SURFACES
            ),
            "sdk_observations_omitted": max(
                0, len(inventory["sdk_observations"]) - _MAX_SDK_OBSERVATIONS
            ),
        },
        "limitations": [
            "A sink surface is an inventory item, not proof of sensitive-data flow.",
            "Confirmed assessments require scanner evidence; naming alone does not classify data as sensitive.",
            "Static analysis may miss reflection, generated code, dynamic SDK wrappers, and runtime serialization.",
            "Hashing, masking, and redaction must be reviewed for data type, reversibility, and organizational policy.",
            "Absence of findings does not prove logs or telemetry are free of sensitive data.",
        ],
    }


def _inventory(target: Path) -> dict[str, Any]:
    python_files = [
        path
        for path in target.rglob("*.py")
        if not any(part in _SKIP_DIRECTORIES for part in path.relative_to(target).parts)
        and not path.is_symlink()
    ]
    python_files.sort(key=lambda path: path.relative_to(target).as_posix())
    selected = python_files[:_MAX_FILES]
    sink_surfaces: list[dict[str, Any]] = []
    sdk_observations: list[dict[str, Any]] = []
    parse_errors = 0
    for path in selected:
        relative = path.relative_to(target).as_posix()
        try:
            tree = ast.parse(path.read_text(encoding="utf-8-sig"), filename=relative)
        except (OSError, SyntaxError, UnicodeError):
            parse_errors += 1
            continue
        visitor = _ExposureVisitor(relative)
        visitor.visit(tree)
        sink_surfaces.extend(visitor.sinks)
        sdk_observations.extend(visitor.sdks)
    sdk_observations.extend(_declared_sdk_observations(target))
    return {
        "files_analyzed": len(selected),
        "files_omitted": max(0, len(python_files) - _MAX_FILES),
        "parse_errors": parse_errors,
        "sink_surfaces": _deduplicate(sink_surfaces),
        "sdk_observations": _deduplicate(sdk_observations),
    }


class _ExposureVisitor(ast.NodeVisitor):
    def __init__(self, path: str) -> None:
        self.path = path
        self.scope = "test" if _is_test_path(path) else "production"
        self.aliases: dict[str, str] = {}
        self.sdk_families: set[str] = set()
        self.sinks: list[dict[str, Any]] = []
        self.sdks: list[dict[str, Any]] = []

    def visit_Import(self, node: ast.Import) -> None:
        for item in node.names:
            root = item.name.split(".", 1)[0]
            self.aliases[item.asname or root] = item.name
            self._sdk(root, node.lineno, "import")
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module:
            root = node.module.split(".", 1)[0]
            self._sdk(root, node.lineno, "import")
            for item in node.names:
                self.aliases[item.asname or item.name] = f"{node.module}.{item.name}"
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        self._remember_assignment(node.targets, node.value)
        self._configuration_assignment(node.targets, node.value, node.lineno)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None:
            self._remember_assignment([node.target], node.value)
            self._configuration_assignment([node.target], node.value, node.lineno)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        qualified = _qualified_name(node.func, self.aliases)
        method = qualified.rsplit(".", 1)[-1]
        family: str | None = None
        label = method
        if method in _LOG_METHODS and _looks_like_logger(qualified):
            family = "logging"
            label = (
                "request data in structured log"
                if _call_has_request_data(node)
                else f"log.{method}"
            )
        elif qualified == "print" and _call_has_sensitive_hint(node):
            family, label = "logging", "standard output"
        elif qualified in {"sys.stderr.write", "sys.stdout.write"} and (
            _call_has_sensitive_hint(node) or _call_has_request_data(node)
        ):
            family, label = "logging", "process output stream"
        elif qualified == "logging.LoggerAdapter" and _call_has_sensitive_hint(node):
            family, label = "logging", "persistent structured-log context"
        elif method == "bind" and _looks_like_logger(qualified):
            family, label = "logging", "bound structured-log context"
        elif _looks_like_response_sink(qualified) and _call_has_exception_data(node):
            family, label = "client-response", "raw exception in HTTP response"
        elif _is_sentry_pii_configuration(qualified, node):
            family, label = "error-monitoring", "automatic PII collection enabled"
        elif _has_header_capture_configuration(node):
            family, label = "telemetry", "HTTP header capture configured"
        elif method in _TELEMETRY_METHODS and self.sdk_families & {
            "analytics",
            "error-monitoring",
            "metrics",
            "observability",
            "telemetry",
        }:
            family, label = _TELEMETRY_METHODS[method]
        elif method == "labels" and "metrics" in self.sdk_families:
            family, label = "metrics", "metric labels"
        elif (
            method in _NETWORK_METHODS
            and _looks_like_network(qualified)
            and (params := _call_keyword(node, "params")) is not None
            and (
                _node_has_sensitive_hint(params) or _node_has_private_data_hint(params)
            )
        ):
            family, label = "url-query", "sensitive HTTP query parameters"
        elif method in _NETWORK_METHODS and _looks_like_network(qualified):
            family, label = "network-egress", f"HTTP {method}"
        if family:
            self.sinks.append(
                {
                    "path": self.path,
                    "line": node.lineno,
                    "scope": self.scope,
                    "sink_family": family,
                    "sink": qualified[:300],
                    "label": label,
                    "sdk": _sdk_for_qualified_name(qualified),
                    "sanitizer_visible": _call_has_protective_configuration(node)
                    or any(
                        _SANITIZER_HINT.search(
                            _qualified_name(item, self.aliases) or ""
                        )
                        for item in ast.walk(node)
                        if isinstance(item, ast.Call)
                    ),
                }
            )
        self.generic_visit(node)

    def _remember_assignment(self, targets: list[ast.expr], value: ast.expr) -> None:
        qualified = _qualified_name(value, self.aliases)
        if not (
            qualified.endswith((".bind", ".getLogger", ".get_logger"))
            or qualified in {"logging.LoggerAdapter", "loguru.logger"}
        ):
            return
        for target in targets:
            if isinstance(target, ast.Name):
                self.aliases[target.id] = "logger"

    def _configuration_assignment(
        self, targets: list[ast.expr], value: ast.expr, line: int
    ) -> None:
        names = {_assignment_name(target, self.aliases).upper() for target in targets}
        capture_names = {
            name
            for name in names
            if "OTEL_INSTRUMENTATION_HTTP_CAPTURE_HEADERS_" in name
            and not name.endswith("SANITIZE_FIELDS")
        }
        if not capture_names or not _is_broad_capture(value):
            return
        self.sinks.append(
            {
                "path": self.path,
                "line": line,
                "scope": self.scope,
                "sink_family": "telemetry",
                "sink": sorted(capture_names)[0][:300],
                "label": "broad OpenTelemetry HTTP header capture",
                "sdk": "OpenTelemetry",
                "sanitizer_visible": False,
            }
        )

    def _sdk(self, root: str, line: int, evidence: str) -> None:
        record = _SDK_CATALOG.get(root)
        if record is None:
            return
        sdk, family = record
        self.sdk_families.add(family)
        self.sdks.append(
            {
                "sdk": sdk,
                "family": family,
                "module": root,
                "evidence": evidence,
                "path": self.path,
                "line": line,
                "scope": self.scope,
            }
        )


def _declared_sdk_observations(target: Path) -> list[dict[str, Any]]:
    path = target / "pyproject.toml"
    if not path.is_file():
        return []
    try:
        document = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError, UnicodeError):
        return []
    dependencies: list[str] = []
    project = document.get("project")
    if isinstance(project, dict) and isinstance(project.get("dependencies"), list):
        dependencies.extend(str(item) for item in project["dependencies"])
    groups = document.get("dependency-groups")
    if isinstance(groups, dict):
        for values in groups.values():
            if isinstance(values, list):
                dependencies.extend(str(item) for item in values)
    result: list[dict[str, Any]] = []
    for dependency in dependencies:
        name = re.split(r"[<>=!~;\[\s]", dependency, maxsplit=1)[0]
        normalized = re.sub(r"[-_.]+", "-", name).casefold()
        module = _DEPENDENCY_TO_IMPORT.get(normalized)
        if not module:
            continue
        sdk, family = _SDK_CATALOG[module]
        result.append(
            {
                "sdk": sdk,
                "family": family,
                "module": module,
                "evidence": "declared-dependency",
                "path": "pyproject.toml",
                "line": None,
                "scope": "repository",
            }
        )
    return result


def _assessment(
    finding: Finding,
    inventory: dict[str, Any],
    artifacts: dict[str, Any],
) -> dict[str, Any]:
    location = finding.locations[0] if finding.locations else None
    path = location.path if location else "<repository>"
    line = location.start_line if location else None
    candidates = [
        item
        for item in inventory["sink_surfaces"]
        if item["path"] == path and (line is None or abs(int(item["line"]) - line) <= 5)
    ]
    nearest = min(
        candidates,
        key=lambda item: abs(int(item["line"]) - int(line or item["line"])),
        default=None,
    )
    sink_family = (
        str(nearest["sink_family"]) if nearest else _finding_sink_family(finding)
    )
    sdk = str(nearest.get("sdk") or "") if nearest else ""
    if not sdk:
        compatible = {
            str(item["sdk"])
            for item in inventory["sdk_observations"]
            if item.get("path") == path
            and _sdk_family_matches_sink(str(item.get("family") or ""), sink_family)
        }
        sdk = next(iter(sorted(compatible)), "") if len(compatible) == 1 else ""
    structural = finding.evidence.get("structural_synthesis")
    graph = finding.evidence.get("graph_context")
    relevance = _relevance(structural, graph)
    confidence = _assessment_confidence(finding, nearest, relevance)
    return {
        "finding_id": finding.finding_id,
        "concern": _concern(finding, sink_family),
        "sink_family": sink_family,
        "sink": nearest.get("sink") if nearest else None,
        "sdk": sdk or None,
        "path": path,
        "line": line,
        "scope": nearest.get("scope") if nearest else _scope(path),
        "confidence": confidence,
        "structural_relevance": relevance,
        "sanitizer_visible": nearest.get("sanitizer_visible") if nearest else None,
        "classifications": sorted(set(finding.classifications)),
        "source_tools": sorted({source.tool for source in finding.sources}),
        "recommended_action": _recommended_action(sink_family, sdk),
        "evidence_artifacts": sorted(
            name
            for name in (
                "graphify.json",
                "reachability.json",
                "coverage-summary.json",
                "diff-coverage.json",
            )
            if name in artifacts
        ),
    }


def _is_exposure_finding(finding: Finding) -> bool:
    classifications = {
        value.upper().split(":", 1)[0] for value in finding.classifications
    }
    if classifications & _EXPOSURE_CWES:
        return True
    if finding.area == "data-exposure":
        return True
    return any(
        source.rule_id.startswith("python.sensitive-data-")
        for source in finding.sources
    )


def _finding_sink_family(finding: Finding) -> str:
    value = " ".join(
        [finding.title, finding.description, finding.area]
        + [source.rule_id for source in finding.sources]
    ).casefold()
    if "url-query" in value or "query string" in value or "url query" in value:
        return "url-query"
    if "http-response" in value or "http response" in value:
        return "client-response"
    if "telemetry" in value or "sentry" in value or "trace" in value:
        return "telemetry"
    if "exception" in value or "error message" in value:
        return "exception"
    if "log" in value:
        return "logging"
    return "external-disclosure"


def _concern(finding: Finding, family: str) -> str:
    classes = {value.upper().split(":", 1)[0] for value in finding.classifications}
    if "CWE-598" in classes or family == "url-query":
        return (
            "private-data-in-url-query"
            if "CWE-359" in classes
            else "sensitive-data-in-url-query"
        )
    if "CWE-209" in classes or family in {"client-response", "exception"}:
        return "sensitive-error-detail"
    if "CWE-532" in classes or family == "logging":
        return "sensitive-information-in-logs"
    if "CWE-359" in classes:
        return "private-data-exposure"
    if "CWE-201" in classes or family != "external-disclosure":
        return "sensitive-information-in-sent-data"
    return "unauthorized-information-exposure"


def _relevance(structural: Any, graph: Any) -> str:
    if isinstance(structural, dict):
        island = structural.get("island")
        if isinstance(island, dict):
            classification = island.get("classification")
            if classification == "likely-dynamic":
                return "runtime-observed"
            if classification == "likely-removable":
                return "disconnected-review"
        if isinstance(structural.get("change_impact"), dict):
            return "changed-code"
    if isinstance(graph, dict) and int(graph.get("degree") or 0) > 0:
        return "statically-connected"
    return "unknown"


def _assessment_confidence(
    finding: Finding, nearest: dict[str, Any] | None, relevance: str
) -> str:
    scanner_confidence = finding.confidence.value
    if nearest and scanner_confidence == "high" and relevance != "disconnected-review":
        return "high"
    if nearest or scanner_confidence in {"high", "medium"}:
        return "medium"
    return "low"


def _recommended_action(family: str, sdk: str) -> str:
    target = f" through {sdk}" if sdk else ""
    if family == "url-query":
        return (
            "Remove sensitive values from the URL and send them in an appropriate "
            "protected header or body; rotate exposed credentials and review access "
            "logs, proxies, telemetry, caches, browser history, and Referer propagation."
        )
    if family in {"client-response", "exception"}:
        return (
            "Return a stable public error code and generic message; keep the exception "
            "only in protected server-side diagnostics after redaction."
        )
    if family == "logging":
        return (
            "Remove the sensitive field from the log event or apply an approved, "
            "tested minimization/redaction boundary before logging; verify exception "
            "and structured-log serialization as well. Treat pseudonyms and hashes "
            "as sensitive until their re-identification risk is approved."
        )
    if family in {
        "analytics",
        "error-monitoring",
        "metrics",
        "observability",
        "telemetry",
    }:
        return (
            f"Minimize the data sent{target}, disable default PII collection where "
            "supported, allowlist attributes, and test the configured exporter with "
            "synthetic canary data before production approval."
        )
    return (
        "Confirm the recipient and purpose, minimize the payload, enforce transport "
        "protection, and prevent credentials or personal data from crossing an "
        "unauthorized trust boundary."
    )


def _attach_citations(finding: Finding, assessment: dict[str, Any]) -> None:
    classes = {value.upper().split(":", 1)[0] for value in finding.classifications}
    mapping = {
        "CWE-200": "Exposure of Sensitive Information to an Unauthorized Actor",
        "CWE-201": "Insertion of Sensitive Information Into Sent Data",
        "CWE-209": "Generation of Error Message Containing Sensitive Information",
        "CWE-359": "Exposure of Private Personal Information to an Unauthorized Actor",
        "CWE-532": "Insertion of Sensitive Information into Log File",
        "CWE-598": "Use of HTTP Request With Sensitive Query String",
    }
    for identifier in sorted(classes & mapping.keys()):
        _add_citation(
            finding,
            identifier,
            mapping[identifier],
            f"https://cwe.mitre.org/data/definitions/{identifier.removeprefix('CWE-')}.html",
        )
    if assessment["sink_family"] == "logging":
        _add_citation(
            finding,
            "OWASP-LOGGING",
            "OWASP Logging Cheat Sheet",
            "https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html",
        )
    if assessment["sink_family"] in {
        "analytics",
        "error-monitoring",
        "metrics",
        "observability",
        "telemetry",
    }:
        _add_citation(
            finding,
            "OTEL-SENSITIVE-DATA",
            "OpenTelemetry handling sensitive data",
            "https://opentelemetry.io/docs/security/handling-sensitive-data/",
        )


def _add_citation(finding: Finding, identifier: str, title: str, uri: str) -> None:
    if any(item.identifier == identifier for item in finding.citations):
        return
    finding.citations.append(
        Citation(kind="standard", identifier=identifier, title=title, uri=uri)
    )


def _qualified_name(node: ast.AST, aliases: dict[str, str]) -> str:
    if isinstance(node, ast.Name):
        return aliases.get(node.id, node.id)
    if isinstance(node, ast.Attribute):
        parent = _qualified_name(node.value, aliases)
        return f"{parent}.{node.attr}" if parent else node.attr
    if isinstance(node, ast.Call):
        return _qualified_name(node.func, aliases)
    return ""


def _assignment_name(node: ast.AST, aliases: dict[str, str]) -> str:
    qualified = _qualified_name(node, aliases)
    if qualified:
        return qualified
    if isinstance(node, ast.Subscript):
        parent = _qualified_name(node.value, aliases)
        key = node.slice
        if isinstance(key, ast.Constant) and isinstance(key.value, str):
            return f"{parent}[{key.value}]"
    return ""


def _looks_like_logger(value: str) -> bool:
    root = value.split(".", 1)[0].casefold()
    return root in {"logging", "log", "logger", "loguru", "structlog"} or any(
        token in value.casefold() for token in (".logger.", ".log.")
    )


def _looks_like_network(value: str) -> bool:
    root = value.split(".", 1)[0].casefold()
    return root in {"aiohttp", "httpx", "requests"}


def _looks_like_response_sink(value: str) -> bool:
    return value.rsplit(".", 1)[-1] in _RESPONSE_SINKS


def _call_keyword(node: ast.Call, name: str) -> ast.expr | None:
    return next(
        (item.value for item in node.keywords if item.arg == name),
        None,
    )


def _is_sentry_pii_configuration(qualified: str, node: ast.Call) -> bool:
    value = _call_keyword(node, "send_default_pii")
    return (
        qualified == "sentry_sdk.init"
        and isinstance(value, ast.Constant)
        and value.value is True
    )


def _has_header_capture_configuration(node: ast.Call) -> bool:
    return any(
        item.arg is not None
        and item.arg.startswith("http_capture_headers_")
        and item.arg != "http_capture_headers_sanitize_fields"
        for item in node.keywords
    )


def _call_has_protective_configuration(node: ast.Call) -> bool:
    return any(
        item.arg
        in {
            "before_breadcrumb",
            "before_send",
            "before_send_log",
            "event_scrubber",
            "http_capture_headers_sanitize_fields",
            "sensitive_headers",
        }
        and not (isinstance(item.value, ast.Constant) and item.value.value is None)
        for item in node.keywords
    )


def _is_broad_capture(node: ast.AST) -> bool:
    return any(
        isinstance(item, ast.Constant)
        and isinstance(item.value, str)
        and item.value.strip() in {"*", ".*"}
        for item in ast.walk(node)
    )


def _call_has_sensitive_hint(node: ast.Call) -> bool:
    return _node_has_sensitive_hint(node)


def _call_has_request_data(node: ast.Call) -> bool:
    return _node_matches_hint(node, _REQUEST_DATA_HINT)


def _call_has_exception_data(node: ast.Call) -> bool:
    return _node_matches_hint(node, _EXCEPTION_HINT) or any(
        isinstance(item, ast.Call)
        and _qualified_name(item.func, {}).rsplit(".", 1)[-1] == "format_exc"
        for item in ast.walk(node)
    )


def _node_has_sensitive_hint(node: ast.AST) -> bool:
    return _node_matches_hint(node, _SENSITIVE_HINT)


def _node_has_private_data_hint(node: ast.AST) -> bool:
    return _node_matches_hint(
        node,
        re.compile(
            r"(?i)(?:account.?id|address|birth|card|cvv|diagnosis|email|health|ip.?address|medical|national.?id|patient|phone|social.?security|ssn|user.?id|username)"
        ),
    )


def _node_matches_hint(node: ast.AST, hint: re.Pattern[str]) -> bool:
    return any(hint.search(value) for value in _node_text(node))


def _node_text(node: ast.AST) -> list[str]:
    return [
        item.id
        if isinstance(item, ast.Name)
        else item.attr
        if isinstance(item, ast.Attribute)
        else str(item.value)
        if isinstance(item, ast.Constant) and isinstance(item.value, str)
        else ""
        for item in ast.walk(node)
    ]


def _sdk_for_qualified_name(value: str) -> str | None:
    root = value.split(".", 1)[0]
    record = _SDK_CATALOG.get(root)
    return record[0] if record else None


def _sdk_family_matches_sink(sdk_family: str, sink_family: str) -> bool:
    if sdk_family == sink_family:
        return True
    telemetry = {
        "analytics",
        "error-monitoring",
        "metrics",
        "observability",
        "telemetry",
    }
    return sdk_family in telemetry and sink_family in telemetry


def _deduplicate(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[Any, ...]] = set()
    result: list[dict[str, Any]] = []
    for item in sorted(
        items,
        key=lambda value: (
            str(value.get("path")),
            int(value.get("line") or 0),
            str(value.get("sdk")),
            str(value.get("sink")),
        ),
    ):
        key = tuple(sorted(item.items()))
        if key not in seen:
            seen.add(key)
            result.append(item)
    return result


def _scope(path: str) -> str:
    return "test" if _is_test_path(path) else "production"


def _is_test_path(path: str) -> bool:
    normalized = path.replace("\\", "/").casefold()
    name = normalized.rsplit("/", 1)[-1]
    return (
        normalized.startswith("tests/")
        or "/tests/" in normalized
        or name.startswith("test_")
        or name.endswith("_test.py")
    )
