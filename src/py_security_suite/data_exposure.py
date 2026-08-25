from __future__ import annotations

import ast
import json
import re
import tomllib
from pathlib import Path
from typing import Any

from .advisory_fusion import build_advisory_clusters
from .models import Citation, Finding


_MAX_FILES = 5000
_MAX_CONFIGURATION_FILES = 1000
_MAX_CONFIGURATION_BYTES = 2 * 1024 * 1024
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
    "azure.monitor.opentelemetry": ("Azure Monitor OpenTelemetry", "observability"),
    "google.cloud.error_reporting": (
        "Google Cloud Error Reporting",
        "error-monitoring",
    ),
    "google.cloud.logging": ("Google Cloud Logging", "logging"),
    "langfuse": ("Langfuse", "observability"),
    "mlflow": ("MLflow", "observability"),
    "openinference": ("OpenInference", "observability"),
    "phoenix": ("Arize Phoenix", "observability"),
    "splunk_otel": ("Splunk OpenTelemetry", "observability"),
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
    "arize-phoenix": "phoenix",
    "azure-monitor-opentelemetry": "azure.monitor.opentelemetry",
    "google-cloud-error-reporting": "google.cloud.error_reporting",
    "google-cloud-logging": "google.cloud.logging",
    "langfuse": "langfuse",
    "mlflow": "mlflow",
    "openinference-instrumentation": "openinference",
    "splunk-opentelemetry": "splunk_otel",
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
    "add_attribute": ("telemetry", "trace attribute"),
    "add_field": ("observability", "telemetry field"),
    "notice_error": ("observability", "reported exception"),
    "put_annotation": ("telemetry", "trace annotation"),
    "put_metadata": ("telemetry", "trace metadata"),
    "set_custom_context": ("observability", "custom telemetry context"),
    "set_extra_context": ("observability", "extra telemetry context"),
}
_NETWORK_METHODS = frozenset(
    {"delete", "get", "head", "options", "patch", "post", "put", "request"}
)
_SANITIZER_HINT = re.compile(r"(?i)(?:hash|hmac|mask|redact|sanitize|scrub|tokenize)")
_MINIMIZER_HINT = re.compile(
    r"(?i)(?:allowlist|drop_sensitive|minimize|remove_sensitive|select_safe)"
)
_REDACTOR_HINT = re.compile(r"(?i)(?:mask|redact|sanitize|scrub)")
_PSEUDONYMIZER_HINT = re.compile(r"(?i)(?:hash|hmac|tokenize)")
_SENSITIVE_HINT = re.compile(
    r"(?i)(?:account.?id|address|api.?key|auth(?:entication|orization|_?(?:header|token))|birth|card|connection.?string|cookie|credential|cvv|database.?url|diagnosis|dsn|email|health|ip.?address|medical|national.?id|otp|passw(?:or)?d|patient|phone|pin|private.?key|secret|session|social.?security|ssn|token(?!ize|ization)|user.?id|username)"
)
_REQUEST_DATA_HINT = re.compile(
    r"(?i)(?:body|form|json|payload|post|query_params|request|request_data)"
)
_REQUEST_OBJECT_HINT = re.compile(
    r"(?i)^(?!.*response)(?:[a-z][a-z0-9]*_)*(?:req|request)$"
)
_EXCEPTION_HINT = re.compile(r"(?i)(?:error|exception|exc|traceback)")
_DATA_CLASS_HINTS: dict[str, re.Pattern[str]] = {
    "credentials": re.compile(
        r"(?i)(?:api.?key|auth(?:entication|orization|_?(?:header|token))|connection.?string|cookie|credential|database.?url|dsn|encryption.?key|otp|passcode|passw(?:or)?d|pin|private.?key|secret|session|token(?!ize|ization))"
    ),
    "financial": re.compile(
        r"(?i)(?:bank|card.?number|credit.?card|cvv|iban|payment|routing.?number)"
    ),
    "health": re.compile(
        r"(?i)(?:diagnosis|health|medical|patient|prescription|treatment)"
    ),
    "personal": re.compile(
        r"(?i)(?:account.?id|address|birth|date.?of.?birth|dob|email|ip.?address|national.?id|phone|social.?security|ssn|user.?id|username)"
    ),
    "request-content": re.compile(
        r"(?i)(?:body|form|json|payload|post|query_params|request_data)"
    ),
}
_RESPONSE_SINKS = frozenset(
    {"abort", "HTTPException", "HttpResponse", "JSONResponse", "JsonResponse"}
)
_CONFIGURATION_SUFFIXES = frozenset(
    {".cfg", ".conf", ".env", ".ini", ".properties", ".toml", ".yaml", ".yml"}
)
_GENAI_CAPTURE_NAME = "OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT"
_GENAI_CAPTURE_ENABLED = frozenset({"EVENT_ONLY", "SPAN_AND_EVENT", "SPAN_ONLY"})
_GENAI_CAPTURE_LEGACY = frozenset({"0", "1", "FALSE", "NO", "OFF", "ON", "TRUE", "YES"})
_CONFIG_ASSIGNMENT = re.compile(
    r"^\s*[\"']?(?P<name>[A-Za-z_][A-Za-z0-9_]*)[\"']?\s*(?:=|:)\s*"
    r"[\"']?(?P<value>[^\"'#\s,}]+)",
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
    _enrich_sink_surfaces(inventory["sink_surfaces"], artifacts, findings)
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
        "schema_version": "1.5",
        "schema_id": "urn:project-py-security-suite:data-exposure:1.5",
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
            "configuration_review_surfaces": sum(
                str(item.get("label") or "").startswith(
                    ("GenAI ", "invalid GenAI ", "broad OpenTelemetry ")
                )
                for item in inventory["sink_surfaces"]
            ),
            "high_priority_review_surfaces": sum(
                item.get("scope") == "production"
                and item.get("review_priority") == "high"
                for item in inventory["sink_surfaces"]
            ),
            "sensitive_context_surfaces": sum(
                bool(item.get("data_classes")) for item in inventory["sink_surfaces"]
            ),
            "protected_surfaces": sum(
                item.get("protection_status") != "not-observed"
                for item in inventory["sink_surfaces"]
            ),
            "fusion_enriched_findings": 0,
            "urgent_cross_referenced_findings": 0,
            "changed_exposure_findings": 0,
            "uncovered_exposure_findings": 0,
            "runtime_observed_exposure_findings": 0,
            "broad_blast_radius_findings": 0,
            "owned_exposure_findings": 0,
            "exposure_findings_with_mapped_tests": 0,
            "exposure_findings_with_validation_mismatch": 0,
            "high_change_risk_exposure_findings": 0,
            "exposure_findings_with_sdk_package_risk": 0,
            "structurally_enriched_surfaces": sum(
                bool(item.get("structural_context", {}).get("context_available"))
                for item in inventory["sink_surfaces"]
            ),
            "changed_sink_surfaces": sum(
                item.get("structural_context", {}).get("changed_line") is True
                for item in inventory["sink_surfaces"]
            ),
            "uncovered_sink_surfaces": sum(
                item.get("structural_context", {}).get("line_covered") is False
                for item in inventory["sink_surfaces"]
            ),
            "runtime_observed_sink_surfaces": sum(
                "observed"
                in item.get("structural_context", {}).get("runtime_observations", [])
                for item in inventory["sink_surfaces"]
            ),
            "disconnected_sink_surfaces": sum(
                "disconnected"
                in item.get("structural_context", {}).get("reachability_states", [])
                for item in inventory["sink_surfaces"]
            ),
            "compound_sink_surfaces": sum(
                bool(item.get("structural_context", {}).get("related_finding_ids"))
                for item in inventory["sink_surfaces"]
            ),
            "owned_sink_surfaces": sum(
                bool(item.get("structural_context", {}).get("owners"))
                for item in inventory["sink_surfaces"]
            ),
            "sink_surfaces_with_mapped_tests": sum(
                bool(item.get("structural_context", {}).get("mapped_test_files"))
                for item in inventory["sink_surfaces"]
            ),
            "sink_surfaces_with_validation_mismatch": sum(
                item.get("structural_context", {}).get("test_coverage_alignment")
                == "coverage-gap"
                for item in inventory["sink_surfaces"]
            ),
            "high_change_risk_sink_surfaces": sum(
                item.get("structural_context", {}).get("change_risk_priority") == "high"
                for item in inventory["sink_surfaces"]
            ),
            "sink_surfaces_in_structural_hotspots": sum(
                bool(item.get("structural_context", {}).get("structural_risk_ids"))
                for item in inventory["sink_surfaces"]
            ),
            "sink_surfaces_with_sdk_package_risk": 0,
            "sdk_packages_correlated": 0,
            "sdk_packages_with_findings": 0,
            "sdk_packages_with_version_drift": 0,
            "sdk_distinct_advisories": 0,
            "sdk_advisory_observations": 0,
            "sdk_advisories_with_import_evidence": 0,
            "sdk_advisories_in_executable_imports": 0,
            "sdk_advisories_flagged_unused": 0,
            "sdk_known_exploited_advisories": 0,
            "sdk_high_epss_advisories": 0,
            "sdk_advisories_with_fixed_versions": 0,
            "sdk_p0_advisories": 0,
            "sdk_advisories_requiring_vex_validation": 0,
            "sdk_advisories_with_focused_tests": 0,
            "sdk_advisories_with_passing_focused_test_evidence": 0,
            "sdk_advisories_with_failing_focused_test_evidence": 0,
            "sdk_advisories_with_unobserved_focused_tests": 0,
            "sdk_advisories_with_import_path_owners": 0,
            "sdk_advisories_with_uncovered_import_paths": 0,
            "sdk_advisories_with_test_coverage_mismatch": 0,
            "sdk_advisories_with_introducing_dependency_paths": 0,
            "sdk_advisories_with_dependency_environment_gaps": 0,
            "sdk_transitive_advisories_without_dependency_paths": 0,
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
            "maximum_configuration_files": _MAX_CONFIGURATION_FILES,
            "maximum_sink_surfaces": _MAX_SURFACES,
            "maximum_sdk_observations": _MAX_SDK_OBSERVATIONS,
            "files_omitted": inventory["files_omitted"],
            "configuration_files_omitted": inventory["configuration_files_omitted"],
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
            "Data classes and review priorities are heuristic context for triage, not regulatory classification or proof of disclosure.",
            "Static analysis may miss reflection, generated code, dynamic SDK wrappers, and runtime serialization.",
            "Hashing, masking, and redaction must be reviewed for data type, reversibility, and organizational policy.",
            "Absence of findings does not prove logs or telemetry are free of sensitive data.",
        ],
    }


def apply_data_exposure_fusion(
    document: dict[str, Any],
    findings: list[Finding],
    fusion: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Join finalized fusion context back into exposure assessments in place."""
    assessments = document.get("finding_assessments")
    summary = document.get("summary")
    if not isinstance(assessments, list) or not isinstance(summary, dict):
        return document
    dependency_contexts = _sdk_dependency_contexts(document, findings, fusion)
    _apply_sdk_dependency_context(document, dependency_contexts)
    by_id = {
        str(item.get("finding_id")): item
        for item in assessments
        if isinstance(item, dict) and item.get("finding_id")
    }
    fusion_enriched = 0
    urgent = 0
    changed = 0
    uncovered = 0
    runtime_observed = 0
    broad_blast_radius = 0
    owned = 0
    mapped_tests = 0
    validation_mismatch = 0
    high_change_risk = 0
    for finding in findings:
        assessment = by_id.get(finding.finding_id)
        if assessment is None:
            continue
        cross_references = _fusion_cross_references(finding)
        assessment["cross_references"] = cross_references
        assessment["triage_tier"] = _exposure_triage_tier(assessment, cross_references)
        dependency_context = assessment["sdk_dependency_context"]
        if dependency_context["context_available"]:
            evidence_artifacts = assessment.get("evidence_artifacts")
            if not isinstance(evidence_artifacts, list):
                evidence_artifacts = []
            assessment["evidence_artifacts"] = sorted(
                set(evidence_artifacts)
                | {"findings.json"}
                | ({"evidence-fusion.json"} if isinstance(fusion, dict) else set())
            )
        assessment["verification_steps"] = _exposure_verification_steps(
            assessment, cross_references
        )
        exposure = finding.evidence.get("data_exposure")
        if isinstance(exposure, dict):
            exposure["cross_references"] = cross_references
            exposure["triage_tier"] = assessment["triage_tier"]
            exposure["verification_steps"] = assessment["verification_steps"]
            exposure["sdk_dependency_context"] = assessment["sdk_dependency_context"]
            exposure["evidence_artifacts"] = assessment["evidence_artifacts"]
        if cross_references["fusion_available"]:
            fusion_enriched += 1
        urgent += assessment["triage_tier"] == "urgent"
        changed += cross_references["changed_line"] is True
        uncovered += cross_references["line_covered"] is False
        runtime_observed += _runtime_observed(cross_references)
        broad_blast_radius += int(cross_references["graph_upstream_files"] or 0) >= 10
        owned += bool(cross_references["owners"])
        mapped_tests += bool(cross_references["mapped_test_files"])
        validation_mismatch += (
            cross_references["test_coverage_alignment"] == "coverage-gap"
        )
        high_change_risk += cross_references["change_risk_priority"] == "high"
    summary.update(
        {
            "fusion_enriched_findings": fusion_enriched,
            "urgent_cross_referenced_findings": urgent,
            "changed_exposure_findings": changed,
            "uncovered_exposure_findings": uncovered,
            "runtime_observed_exposure_findings": runtime_observed,
            "broad_blast_radius_findings": broad_blast_radius,
            "owned_exposure_findings": owned,
            "exposure_findings_with_mapped_tests": mapped_tests,
            "exposure_findings_with_validation_mismatch": validation_mismatch,
            "high_change_risk_exposure_findings": high_change_risk,
            "exposure_findings_with_sdk_package_risk": sum(
                bool(item.get("sdk_dependency_context", {}).get("risk_present"))
                for item in assessments
                if isinstance(item, dict)
            ),
            "sink_surfaces_with_sdk_package_risk": sum(
                bool(item.get("sdk_dependency_context", {}).get("risk_present"))
                for item in document.get("sink_surfaces", [])
                if isinstance(item, dict)
            ),
            "sdk_packages_correlated": len(
                {
                    package
                    for context in dependency_contexts.values()
                    for package in context["packages"]
                }
            ),
            "sdk_packages_with_findings": len(
                {
                    package
                    for context in dependency_contexts.values()
                    for package in context["packages_with_findings"]
                }
            ),
            "sdk_packages_with_version_drift": len(
                {
                    str(item["package"])
                    for context in dependency_contexts.values()
                    for item in context["lineage"]
                    if item["status"] == "version-drift"
                }
            ),
            "sdk_distinct_advisories": len(
                {
                    str(item["cluster_id"])
                    for context in dependency_contexts.values()
                    for item in context["advisory_clusters"]
                }
            ),
            "sdk_advisory_observations": sum(
                int(item["observation_count"])
                for item in {
                    str(cluster["cluster_id"]): cluster
                    for context in dependency_contexts.values()
                    for cluster in context["advisory_clusters"]
                }.values()
            ),
            "sdk_advisories_with_import_evidence": sum(
                cluster["dependency_usage"]["import_observed"] is True
                for cluster in {
                    str(cluster["cluster_id"]): cluster
                    for context in dependency_contexts.values()
                    for cluster in context["advisory_clusters"]
                }.values()
            ),
            "sdk_advisories_in_executable_imports": sum(
                cluster["dependency_usage"]["assessment"]
                in {"runtime-observed-import", "executable-import"}
                for cluster in {
                    str(cluster["cluster_id"]): cluster
                    for context in dependency_contexts.values()
                    for cluster in context["advisory_clusters"]
                }.values()
            ),
            "sdk_advisories_flagged_unused": sum(
                "unused-declaration" in cluster["dependency_usage"]["deptry_statuses"]
                for cluster in {
                    str(cluster["cluster_id"]): cluster
                    for context in dependency_contexts.values()
                    for cluster in context["advisory_clusters"]
                }.values()
            ),
            "sdk_known_exploited_advisories": sum(
                cluster["threat_context"]["known_exploited"]
                for cluster in {
                    str(cluster["cluster_id"]): cluster
                    for context in dependency_contexts.values()
                    for cluster in context["advisory_clusters"]
                }.values()
            ),
            "sdk_high_epss_advisories": sum(
                cluster["threat_context"]["epss_high"]
                for cluster in {
                    str(cluster["cluster_id"]): cluster
                    for context in dependency_contexts.values()
                    for cluster in context["advisory_clusters"]
                }.values()
            ),
            "sdk_advisories_with_fixed_versions": sum(
                cluster["remediation_context"]["fix_available"]
                for cluster in {
                    str(cluster["cluster_id"]): cluster
                    for context in dependency_contexts.values()
                    for cluster in context["advisory_clusters"]
                }.values()
            ),
            "sdk_p0_advisories": sum(
                cluster["remediation_context"]["priority"] == "P0"
                for cluster in {
                    str(cluster["cluster_id"]): cluster
                    for context in dependency_contexts.values()
                    for cluster in context["advisory_clusters"]
                }.values()
            ),
            "sdk_advisories_requiring_vex_validation": sum(
                cluster["threat_context"]["vex_disposition"]
                in {"bounded-or-resolved-claim", "mixed"}
                for cluster in {
                    str(cluster["cluster_id"]): cluster
                    for context in dependency_contexts.values()
                    for cluster in context["advisory_clusters"]
                }.values()
            ),
            "sdk_advisories_with_focused_tests": sum(
                bool(cluster["dependency_usage"]["recommended_test_files"])
                for cluster in {
                    str(cluster["cluster_id"]): cluster
                    for context in dependency_contexts.values()
                    for cluster in context["advisory_clusters"]
                }.values()
            ),
            "sdk_advisories_with_passing_focused_test_evidence": sum(
                cluster["dependency_usage"]["focused_test_validation_status"]
                == "passed"
                for cluster in {
                    str(cluster["cluster_id"]): cluster
                    for context in dependency_contexts.values()
                    for cluster in context["advisory_clusters"]
                }.values()
            ),
            "sdk_advisories_with_failing_focused_test_evidence": sum(
                cluster["dependency_usage"]["focused_test_validation_status"]
                == "failed"
                for cluster in {
                    str(cluster["cluster_id"]): cluster
                    for context in dependency_contexts.values()
                    for cluster in context["advisory_clusters"]
                }.values()
            ),
            "sdk_advisories_with_unobserved_focused_tests": sum(
                bool(cluster["dependency_usage"]["unobserved_recommended_test_files"])
                for cluster in {
                    str(cluster["cluster_id"]): cluster
                    for context in dependency_contexts.values()
                    for cluster in context["advisory_clusters"]
                }.values()
            ),
            "sdk_advisories_with_import_path_owners": sum(
                bool(cluster["dependency_usage"]["import_path_owners"])
                for cluster in {
                    str(cluster["cluster_id"]): cluster
                    for context in dependency_contexts.values()
                    for cluster in context["advisory_clusters"]
                }.values()
            ),
            "sdk_advisories_with_uncovered_import_paths": sum(
                bool(cluster["dependency_usage"]["uncovered_import_paths"])
                for cluster in {
                    str(cluster["cluster_id"]): cluster
                    for context in dependency_contexts.values()
                    for cluster in context["advisory_clusters"]
                }.values()
            ),
            "sdk_advisories_with_test_coverage_mismatch": sum(
                cluster["dependency_usage"]["test_coverage_alignment"] == "coverage-gap"
                for cluster in {
                    str(cluster["cluster_id"]): cluster
                    for context in dependency_contexts.values()
                    for cluster in context["advisory_clusters"]
                }.values()
            ),
            "sdk_advisories_with_introducing_dependency_paths": sum(
                bool(cluster["dependency_usage"]["dependency_paths"])
                for cluster in {
                    str(cluster["cluster_id"]): cluster
                    for context in dependency_contexts.values()
                    for cluster in context["advisory_clusters"]
                }.values()
            ),
            "sdk_advisories_with_dependency_environment_gaps": sum(
                cluster["dependency_usage"]["dependency_environment_warning"]
                for cluster in {
                    str(cluster["cluster_id"]): cluster
                    for context in dependency_contexts.values()
                    for cluster in context["advisory_clusters"]
                }.values()
            ),
            "sdk_transitive_advisories_without_dependency_paths": sum(
                cluster["dependency_usage"]["source_relationship"] == "transitive"
                and not cluster["dependency_usage"]["dependency_paths"]
                for cluster in {
                    str(cluster["cluster_id"]): cluster
                    for context in dependency_contexts.values()
                    for cluster in context["advisory_clusters"]
                }.values()
            ),
        }
    )
    assessments.sort(
        key=lambda item: (
            {"urgent": 0, "elevated": 1, "standard": 2}.get(
                str(item.get("triage_tier")), 3
            ),
            {"high": 0, "medium": 1, "none": 2}.get(
                str(item.get("sdk_dependency_context", {}).get("risk_tier")), 3
            ),
            {"high": 0, "medium": 1, "low": 2}.get(str(item.get("review_priority")), 3),
            str(item.get("finding_id")),
        )
    )
    return document


def _empty_sdk_dependency_context() -> dict[str, Any]:
    return {
        "context_available": False,
        "risk_present": False,
        "risk_tier": "none",
        "packages": [],
        "packages_with_findings": [],
        "package_finding_ids": [],
        "package_finding_tools": [],
        "package_classifications": [],
        "distinct_advisory_count": 0,
        "advisory_observation_count": 0,
        "advisory_clusters": [],
        "advisories_with_import_evidence": 0,
        "advisories_in_executable_imports": 0,
        "advisories_flagged_unused": 0,
        "known_exploited_advisories": 0,
        "high_epss_advisories": 0,
        "advisories_with_fixed_versions": 0,
        "p0_advisories": 0,
        "advisories_requiring_vex_validation": 0,
        "advisories_with_focused_tests": 0,
        "advisories_with_import_path_owners": 0,
        "advisories_with_uncovered_import_paths": 0,
        "advisories_with_test_coverage_mismatch": 0,
        "highest_severity": None,
        "lineage": [],
        "risk_reasons": [],
        "citations": [],
    }


def _sdk_dependency_contexts(
    document: dict[str, Any],
    findings: list[Finding],
    fusion: dict[str, Any] | None,
) -> dict[str, dict[str, Any]]:
    packages_by_sdk: dict[str, set[str]] = {}
    observations = document.get("sdk_observations")
    if isinstance(observations, list):
        for item in observations:
            if not isinstance(item, dict) or not isinstance(item.get("sdk"), str):
                continue
            package = _normalized_package(item.get("package"))
            packages_by_sdk.setdefault(item["sdk"], set())
            if package:
                packages_by_sdk[item["sdk"]].add(package)

    raw_lineage = fusion.get("package_lineage") if isinstance(fusion, dict) else None
    lineage_by_package: dict[str, dict[str, Any]] = {}
    if isinstance(raw_lineage, list):
        for item in raw_lineage:
            if not isinstance(item, dict):
                continue
            package = _normalized_package(item.get("package"))
            status = str(item.get("status") or "")
            if not package or status not in {
                "matched",
                "version-drift",
                "source-only",
                "artifact-only",
            }:
                continue
            lineage_by_package[package] = {
                "package": package,
                "status": status,
                "source_versions": _bounded_strings(item.get("source_versions"), 20),
                "artifact_versions": _bounded_strings(
                    item.get("artifact_versions"), 20
                ),
            }
            module = _DEPENDENCY_TO_IMPORT.get(package)
            catalog = _SDK_CATALOG.get(module or "")
            if catalog:
                packages_by_sdk.setdefault(catalog[0], set()).add(package)

    package_findings = _sdk_package_finding_index(findings)
    raw_clusters = fusion.get("advisory_clusters") if isinstance(fusion, dict) else None
    if not isinstance(raw_clusters, list):
        raw_clusters = build_advisory_clusters(findings)
    clusters_by_package: dict[str, list[dict[str, Any]]] = {}
    for raw_cluster in raw_clusters:
        cluster = _sdk_advisory_cluster(raw_cluster)
        if cluster is not None:
            clusters_by_package.setdefault(cluster["package"], []).append(cluster)
    contexts: dict[str, dict[str, Any]] = {}
    for sdk, package_values in sorted(packages_by_sdk.items()):
        packages = sorted(package_values)[:50]
        records = [
            record
            for package in packages
            for record in package_findings.get(package, [])
        ]
        finding_ids = sorted({str(item["finding_id"]) for item in records})[:50]
        packages_with_findings = sorted(
            {package for package in packages if package_findings.get(package)}
        )
        advisory_clusters = sorted(
            {
                str(cluster["cluster_id"]): cluster
                for package in packages
                for cluster in clusters_by_package.get(package, [])
            }.values(),
            key=lambda item: (str(item["package"]), str(item["primary_identifier"])),
        )[:50]
        lineage = [
            lineage_by_package[pkg] for pkg in packages if pkg in lineage_by_package
        ]
        risky_lineage = [
            item
            for item in lineage
            if item["status"] in {"version-drift", "artifact-only"}
        ]
        highest_severity = _highest_sdk_package_severity(records)
        risk_present = bool(finding_ids or risky_lineage)
        risk_tier = (
            "high"
            if highest_severity in {"critical", "high"} or risky_lineage
            else "medium"
            if risk_present
            else "none"
        )
        reasons = []
        for package in packages_with_findings:
            package_clusters = clusters_by_package.get(package, [])
            if package_clusters:
                observations = sum(
                    int(item["observation_count"]) for item in package_clusters
                )
                reasons.append(
                    f"{package} has {len(package_clusters)} distinct advisory risk(s) "
                    f"across {observations} retained scanner observation(s)"
                )
            else:
                observations = len(package_findings[package])
                reasons.append(
                    f"{package} has {observations} normalized package finding(s)"
                )
        reasons.extend(
            f"{item['package']} has {item['status']} source/artifact lineage"
            for item in risky_lineage
        )
        import_count = sum(
            item["dependency_usage"]["import_observed"] is True
            for item in advisory_clusters
        )
        executable_count = sum(
            item["dependency_usage"]["assessment"]
            in {"runtime-observed-import", "executable-import"}
            for item in advisory_clusters
        )
        unused_count = sum(
            "unused-declaration" in item["dependency_usage"]["deptry_statuses"]
            for item in advisory_clusters
        )
        known_exploited_count = sum(
            item["threat_context"]["known_exploited"] for item in advisory_clusters
        )
        high_epss_count = sum(
            item["threat_context"]["epss_high"] for item in advisory_clusters
        )
        fixed_count = sum(
            item["remediation_context"]["fix_available"] for item in advisory_clusters
        )
        p0_count = sum(
            item["remediation_context"]["priority"] == "P0"
            for item in advisory_clusters
        )
        vex_validation_count = sum(
            item["threat_context"]["vex_disposition"]
            in {"bounded-or-resolved-claim", "mixed"}
            for item in advisory_clusters
        )
        focused_test_count = sum(
            bool(item["dependency_usage"]["recommended_test_files"])
            for item in advisory_clusters
        )
        passing_test_count = sum(
            item["dependency_usage"]["focused_test_validation_status"] == "passed"
            for item in advisory_clusters
        )
        failing_test_count = sum(
            item["dependency_usage"]["focused_test_validation_status"] == "failed"
            for item in advisory_clusters
        )
        unobserved_test_count = sum(
            bool(item["dependency_usage"]["unobserved_recommended_test_files"])
            for item in advisory_clusters
        )
        dependency_path_count = sum(
            bool(item["dependency_usage"]["dependency_paths"])
            for item in advisory_clusters
        )
        dependency_environment_gap_count = sum(
            item["dependency_usage"]["dependency_environment_warning"]
            for item in advisory_clusters
        )
        missing_transitive_path_count = sum(
            item["dependency_usage"]["source_relationship"] == "transitive"
            and not item["dependency_usage"]["dependency_paths"]
            for item in advisory_clusters
        )
        owner_count = sum(
            bool(item["dependency_usage"]["import_path_owners"])
            for item in advisory_clusters
        )
        uncovered_import_count = sum(
            bool(item["dependency_usage"]["uncovered_import_paths"])
            for item in advisory_clusters
        )
        test_coverage_mismatch_count = sum(
            item["dependency_usage"]["test_coverage_alignment"] == "coverage-gap"
            for item in advisory_clusters
        )
        if import_count:
            reasons.append(
                f"{import_count} distinct advisory risk(s) have exact static import evidence"
            )
        if executable_count:
            reasons.append(
                f"{executable_count} distinct advisory risk(s) map to executable or runtime-observed imports"
            )
        if unused_count:
            reasons.append(
                f"deptry flags the declaration for {unused_count} distinct advisory risk(s) as unused"
            )
        if known_exploited_count:
            reasons.append(
                f"{known_exploited_count} distinct advisory risk(s) match the approved offline CISA KEV snapshot"
            )
        if fixed_count:
            reasons.append(
                f"{fixed_count} distinct advisory risk(s) have scanner-reported fixed-version candidates"
            )
        if vex_validation_count:
            reasons.append(
                f"{vex_validation_count} distinct advisory risk(s) require VEX scope and justification validation"
            )
        if focused_test_count:
            reasons.append(
                f"{focused_test_count} distinct advisory risk(s) have graph-selected focused tests"
            )
        if passing_test_count:
            reasons.append(
                f"{passing_test_count} distinct advisory risk(s) have retained passing cases for every graph-selected focused test file"
            )
        if failing_test_count:
            reasons.append(
                f"{failing_test_count} distinct advisory risk(s) have retained failures or errors in graph-selected focused tests"
            )
        if unobserved_test_count:
            reasons.append(
                f"{unobserved_test_count} distinct advisory risk(s) have graph-selected focused test files absent from retained case-level evidence"
            )
        if dependency_path_count:
            roots = sorted(
                {
                    root
                    for item in advisory_clusters
                    for root in item["dependency_usage"]["introducing_packages"]
                }
            )
            reasons.append(
                f"{dependency_path_count} distinct advisory risk(s) have bounded CycloneDX introducing paths"
                + (f" via {', '.join(roots[:5])}" if roots else "")
            )
        if dependency_environment_gap_count:
            reasons.append(
                f"{dependency_environment_gap_count} distinct advisory risk(s) are qualified by pipdeptree environment health gaps"
            )
        if missing_transitive_path_count:
            reasons.append(
                f"{missing_transitive_path_count} transitive advisory risk(s) lack a bounded introducing path"
            )
        if owner_count:
            reasons.append(
                f"{owner_count} distinct advisory risk(s) have import-path owners"
            )
        if uncovered_import_count:
            reasons.append(
                f"{uncovered_import_count} distinct advisory risk(s) map to import paths below 80% coverage"
            )
        if test_coverage_mismatch_count:
            reasons.append(
                f"{test_coverage_mismatch_count} distinct advisory risk(s) have passing focused tests but affected import paths below 80% coverage"
            )
        citation_sources = advisory_clusters if advisory_clusters else records
        citations = {
            (str(citation["identifier"]), str(citation.get("uri") or "")): citation
            for source in citation_sources
            for citation in source["citations"]
        }
        contexts[sdk] = {
            "context_available": bool(packages),
            "risk_present": risk_present,
            "risk_tier": risk_tier,
            "packages": packages,
            "packages_with_findings": packages_with_findings,
            "package_finding_ids": finding_ids,
            "package_finding_tools": sorted(
                {tool for item in records for tool in item["tools"]}
            )[:20],
            "package_classifications": sorted(
                {
                    classification
                    for item in records
                    for raw_classification in item["classifications"]
                    if (
                        classification := _normalized_package_classification(
                            raw_classification
                        )
                    )
                }
            )[:50],
            "distinct_advisory_count": len(advisory_clusters),
            "advisory_observation_count": sum(
                int(item["observation_count"]) for item in advisory_clusters
            ),
            "advisory_clusters": advisory_clusters,
            "advisories_with_import_evidence": import_count,
            "advisories_in_executable_imports": executable_count,
            "advisories_flagged_unused": unused_count,
            "known_exploited_advisories": known_exploited_count,
            "high_epss_advisories": high_epss_count,
            "advisories_with_fixed_versions": fixed_count,
            "p0_advisories": p0_count,
            "advisories_requiring_vex_validation": vex_validation_count,
            "advisories_with_focused_tests": focused_test_count,
            "advisories_with_import_path_owners": owner_count,
            "advisories_with_uncovered_import_paths": uncovered_import_count,
            "advisories_with_test_coverage_mismatch": test_coverage_mismatch_count,
            "highest_severity": highest_severity,
            "lineage": lineage[:50],
            "risk_reasons": reasons[:20],
            "citations": [citations[key] for key in sorted(citations)[:25]],
        }
    return contexts


def _sdk_advisory_cluster(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    package = _normalized_package(value.get("package"))
    cluster_id = str(value.get("cluster_id") or "")[:100]
    primary = str(value.get("primary_identifier") or "")[:100]
    if not package or not cluster_id or not primary:
        return None
    observation_count = value.get("observation_count")
    alias_count = value.get("alias_count")
    raw_citations = value.get("citations")
    citations = raw_citations if isinstance(raw_citations, list) else []
    highest_severity = str(value.get("highest_severity") or "unknown")
    if highest_severity not in {
        "critical",
        "high",
        "medium",
        "low",
        "informational",
        "unknown",
    }:
        highest_severity = "unknown"
    return {
        "cluster_id": cluster_id,
        "package": package,
        "versions": _bounded_strings(value.get("versions"), 50),
        "primary_identifier": primary,
        "identifiers": _bounded_strings(value.get("identifiers"), 100),
        "finding_ids": _bounded_strings(value.get("finding_ids"), 100),
        "tools": _bounded_strings(value.get("tools"), 25),
        "highest_severity": highest_severity,
        "observation_count": (
            observation_count
            if isinstance(observation_count, int) and observation_count > 0
            else 1
        ),
        "alias_count": (
            alias_count if isinstance(alias_count, int) and alias_count >= 0 else 0
        ),
        "cross_tool": value.get("cross_tool") is True,
        "dependency_usage": _sdk_dependency_usage(value.get("dependency_usage")),
        "threat_context": _sdk_threat_context(value.get("threat_context")),
        "remediation_context": _sdk_remediation_context(
            value.get("remediation_context")
        ),
        "citations": [
            {
                "identifier": str(item.get("identifier") or "")[:200],
                "title": str(item.get("title") or "")[:500],
                "uri": item.get("uri") if isinstance(item.get("uri"), str) else None,
            }
            for item in citations[:25]
            if isinstance(item, dict) and item.get("identifier") and item.get("title")
        ],
    }


def _sdk_threat_context(value: Any) -> dict[str, Any]:
    raw = value if isinstance(value, dict) else {}
    disposition = str(raw.get("vex_disposition") or "unassessed")
    allowed = {
        "unassessed",
        "exploitable",
        "bounded-or-resolved-claim",
        "mixed",
        "in_triage",
    }
    return {
        "intelligence_available": raw.get("intelligence_available") is True,
        "intelligence_sources": _bounded_strings(raw.get("intelligence_sources"), 10),
        "cves": _bounded_strings(raw.get("cves"), 100),
        "known_exploited": raw.get("known_exploited") is True,
        "known_exploited_cves": _bounded_strings(raw.get("known_exploited_cves"), 100),
        "known_exploited_records": _sdk_kev_records(raw.get("known_exploited_records")),
        "epss_probability": _bounded_probability(raw.get("epss_probability")),
        "epss_percentile": _bounded_probability(raw.get("epss_percentile")),
        "epss_high": raw.get("epss_high") is True,
        "epss_records": _sdk_epss_records(raw.get("epss_records")),
        "vex_states": _bounded_strings(raw.get("vex_states"), 20),
        "vex_disposition": disposition if disposition in allowed else "unassessed",
        "vex_records": _sdk_vex_records(raw.get("vex_records")),
    }


def _sdk_kev_records(value: Any) -> list[dict[str, Any]]:
    raw = value if isinstance(value, list) else []
    return [
        {
            "cve": str(item.get("cve") or "")[:100],
            "date_added": str(item.get("date_added") or "")[:30],
            "due_date": str(item.get("due_date") or "")[:30],
            "known_ransomware_campaign_use": str(
                item.get("known_ransomware_campaign_use") or ""
            )[:30],
            "required_action": str(item.get("required_action") or "")[:500],
        }
        for item in raw[:100]
        if isinstance(item, dict) and item.get("cve")
    ]


def _sdk_epss_records(value: Any) -> list[dict[str, Any]]:
    raw = value if isinstance(value, list) else []
    return [
        {
            "cve": str(item.get("cve") or "")[:100],
            "probability": _bounded_probability(item.get("probability")),
            "percentile": _bounded_probability(item.get("percentile")),
        }
        for item in raw[:100]
        if isinstance(item, dict)
        and item.get("cve")
        and _bounded_probability(item.get("probability")) is not None
        and _bounded_probability(item.get("percentile")) is not None
    ]


def _sdk_vex_records(value: Any) -> list[dict[str, Any]]:
    raw = value if isinstance(value, list) else []
    return [
        {
            "cve": str(item.get("cve") or "")[:100],
            "state": str(item.get("state") or "")[:100],
            "justification": str(item.get("justification") or "")[:100],
            "detail": str(item.get("detail") or "")[:500],
            "response": _bounded_strings(item.get("response"), 20),
        }
        for item in raw[:100]
        if isinstance(item, dict) and item.get("state")
    ]


def _sdk_remediation_context(value: Any) -> dict[str, Any]:
    raw = value if isinstance(value, dict) else {}
    priority = str(raw.get("priority") or "P4")
    action_kind = str(raw.get("action_kind") or "mitigate-or-replace")
    allowed_actions = {
        "upgrade",
        "remove-or-upgrade",
        "mitigate-or-replace",
        "resolve-evidence-conflict",
        "validate-vex",
    }
    raw_sources = raw.get("fixed_version_sources")
    sources = raw_sources if isinstance(raw_sources, list) else []
    return {
        "priority": priority if priority in {"P0", "P1", "P2", "P3", "P4"} else "P4",
        "action_kind": (
            action_kind if action_kind in allowed_actions else "mitigate-or-replace"
        ),
        "fix_available": raw.get("fix_available") is True,
        "fixed_version_candidates": _bounded_strings(
            raw.get("fixed_version_candidates"), 100
        ),
        "fixed_version_sources": [
            {
                "tool": str(item.get("tool") or "unknown")[:100],
                "versions": _bounded_strings(item.get("versions"), 50),
            }
            for item in sources[:25]
            if isinstance(item, dict)
        ],
        "owners": _bounded_strings(raw.get("owners"), 20),
        "recommended_test_files": _bounded_strings(
            raw.get("recommended_test_files"), 50
        ),
        "test_selection_confidence": (
            str(raw.get("test_selection_confidence"))
            if str(raw.get("test_selection_confidence"))
            in {"high", "medium", "low", "not-available"}
            else "not-available"
        ),
        "focused_test_validation_status": (
            str(raw.get("focused_test_validation_status"))
            if str(raw.get("focused_test_validation_status"))
            in {
                "passed",
                "failed",
                "incomplete",
                "not-observed",
                "not-available",
                "not-selected",
            }
            else "not-available"
        ),
        "test_coverage_alignment": _sdk_test_coverage_alignment(
            raw.get("test_coverage_alignment")
        ),
        "introducing_packages": _bounded_strings(raw.get("introducing_packages"), 25),
        "dependency_paths": _sdk_dependency_paths(raw.get("dependency_paths")),
        "dependency_path_confidence": (
            str(raw.get("dependency_path_confidence"))
            if str(raw.get("dependency_path_confidence"))
            in {"high", "qualified", "not-available"}
            else "not-available"
        ),
        "recommended_action": str(
            raw.get("recommended_action")
            or "Review and remediate the native advisory evidence."
        )[:2000],
        "verification_steps": _bounded_strings(raw.get("verification_steps"), 6),
        "evidence_basis": _bounded_strings(raw.get("evidence_basis"), 20),
        "uncertainties": _bounded_strings(raw.get("uncertainties"), 20),
    }


def _bounded_probability(value: Any) -> float | None:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        return None
    return round(float(value), 6) if 0 <= float(value) <= 1 else None


def _sdk_dependency_usage(value: Any) -> dict[str, Any]:
    raw = value if isinstance(value, dict) else {}
    assessment = str(raw.get("assessment") or "unknown")
    allowed_assessments = {
        "runtime-observed-import",
        "executable-import",
        "load-only-import",
        "disconnected-import",
        "imported-reachability-incomplete",
        "import-observed",
        "declared-unused",
        "import-not-observed",
        "import-vs-unused-conflict",
        "unknown",
    }
    relationship = str(raw.get("source_relationship") or "unknown")
    return {
        "assessment": assessment if assessment in allowed_assessments else "unknown",
        "source_relationship": (
            relationship
            if relationship in {"direct", "transitive", "unknown"}
            else "unknown"
        ),
        "relationship_evidence_available": raw.get("relationship_evidence_available")
        is True,
        "dependency_path_evidence_available": raw.get(
            "dependency_path_evidence_available"
        )
        is True,
        "dependency_paths": _sdk_dependency_paths(raw.get("dependency_paths")),
        "dependency_paths_truncated": raw.get("dependency_paths_truncated") is True,
        "introducing_packages": _bounded_strings(raw.get("introducing_packages"), 25),
        "dependency_path_confidence": (
            str(raw.get("dependency_path_confidence"))
            if str(raw.get("dependency_path_confidence"))
            in {"high", "qualified", "not-available"}
            else "not-available"
        ),
        "environment_health_evidence_available": raw.get(
            "environment_health_evidence_available"
        )
        is True,
        "dependency_environment_health": _sdk_dependency_environment_health(
            raw.get("dependency_environment_health")
        ),
        "dependency_environment_warning": raw.get("dependency_environment_warning")
        is True,
        "import_evidence_available": raw.get("import_evidence_available") is True,
        "import_observed": (
            raw.get("import_observed")
            if isinstance(raw.get("import_observed"), bool)
            else None
        ),
        "import_modules": _bounded_strings(raw.get("import_modules"), 50),
        "import_paths": _bounded_strings(raw.get("import_paths"), 50),
        "reachability_evidence_available": raw.get("reachability_evidence_available")
        is True,
        "reachability_complete": (
            raw.get("reachability_complete")
            if isinstance(raw.get("reachability_complete"), bool)
            else None
        ),
        "reachability_confidence": (
            str(raw["reachability_confidence"])[:50]
            if raw.get("reachability_confidence")
            else None
        ),
        "reachability_states": _bounded_strings(raw.get("reachability_states"), 10),
        "runtime_observations": _bounded_strings(raw.get("runtime_observations"), 10),
        "deptry_statuses": _bounded_strings(raw.get("deptry_statuses"), 10),
        "deptry_finding_ids": _bounded_strings(raw.get("deptry_finding_ids"), 50),
        "signals_conflict": raw.get("signals_conflict") is True,
        "test_mapping_evidence_available": raw.get("test_mapping_evidence_available")
        is True,
        "recommended_test_files": _bounded_strings(
            raw.get("recommended_test_files"), 50
        ),
        "direct_test_files": _bounded_strings(raw.get("direct_test_files"), 50),
        "transitive_test_files": _bounded_strings(raw.get("transitive_test_files"), 50),
        "test_selection_confidence": (
            str(raw.get("test_selection_confidence"))
            if str(raw.get("test_selection_confidence"))
            in {"high", "medium", "low", "not-available"}
            else "not-available"
        ),
        "test_execution_evidence_available": raw.get(
            "test_execution_evidence_available"
        )
        is True,
        "test_case_inventory_available": raw.get("test_case_inventory_available")
        is True,
        "test_case_inventory_complete": (
            raw.get("test_case_inventory_complete")
            if isinstance(raw.get("test_case_inventory_complete"), bool)
            else None
        ),
        "test_execution_sources": _bounded_strings(
            raw.get("test_execution_sources"), 10
        ),
        "focused_test_execution": _sdk_focused_test_execution(
            raw.get("focused_test_execution")
        ),
        "focused_test_validation_status": (
            str(raw.get("focused_test_validation_status"))
            if str(raw.get("focused_test_validation_status"))
            in {
                "passed",
                "failed",
                "incomplete",
                "not-observed",
                "not-available",
                "not-selected",
            }
            else "not-available"
        ),
        "unobserved_recommended_test_files": _bounded_strings(
            raw.get("unobserved_recommended_test_files"), 50
        ),
        "test_coverage_alignment": _sdk_test_coverage_alignment(
            raw.get("test_coverage_alignment")
        ),
        "validation_gap_reasons": _bounded_strings(
            raw.get("validation_gap_reasons"), 10
        ),
        "ownership_evidence_available": raw.get("ownership_evidence_available") is True,
        "import_path_owners": _bounded_strings(raw.get("import_path_owners"), 20),
        "import_path_ownership": _sdk_import_path_ownership(
            raw.get("import_path_ownership")
        ),
        "coverage_evidence_available": raw.get("coverage_evidence_available") is True,
        "import_path_coverage": _sdk_import_path_coverage(
            raw.get("import_path_coverage")
        ),
        "import_path_assessments": _sdk_import_path_assessments(
            raw.get("import_path_assessments")
        ),
        "uncovered_import_paths": _bounded_strings(
            raw.get("uncovered_import_paths"), 50
        ),
        "evidence_artifacts": _bounded_strings(raw.get("evidence_artifacts"), 10),
    }


def _sdk_test_coverage_alignment(value: Any) -> str:
    text = str(value or "not-selected")
    allowed = {
        "aligned-current-evidence",
        "coverage-gap",
        "coverage-not-available",
        "test-evidence-not-available",
        "tests-failing",
        "tests-incomplete",
        "tests-not-observed",
        "not-selected",
    }
    return text if text in allowed else "test-evidence-not-available"


def _sdk_import_path_coverage(value: Any) -> list[dict[str, Any]]:
    raw = value if isinstance(value, list) else []
    return [
        {
            "path": str(item.get("path") or "")[:4096],
            "coverage_percent": (
                round(float(percent), 3)
                if isinstance(percent := item.get("coverage_percent"), (int, float))
                and not isinstance(percent, bool)
                and 0 <= float(percent) <= 100
                else None
            ),
        }
        for item in raw[:50]
        if isinstance(item, dict) and item.get("path")
    ]


def _sdk_import_path_ownership(value: Any) -> list[dict[str, Any]]:
    raw = value if isinstance(value, list) else []
    return [
        {
            "path": str(item.get("path") or "")[:4096],
            "owners": _bounded_strings(item.get("owners"), 20),
        }
        for item in raw[:50]
        if isinstance(item, dict) and item.get("path")
    ]


def _sdk_import_path_assessments(value: Any) -> list[dict[str, Any]]:
    raw = value if isinstance(value, list) else []
    result: list[dict[str, Any]] = []
    for item in raw[:50]:
        if not isinstance(item, dict) or not item.get("path"):
            continue
        percent = item.get("coverage_percent")
        coverage_percent = (
            round(float(percent), 3)
            if isinstance(percent, (int, float))
            and not isinstance(percent, bool)
            and 0 <= float(percent) <= 100
            else None
        )
        coverage_gap = item.get("coverage_gap")
        result.append(
            {
                "path": str(item.get("path"))[:4096],
                "import_modules": _bounded_strings(item.get("import_modules"), 50),
                "import_lines": sorted(
                    {
                        line
                        for line in item.get("import_lines", [])[:100]
                        if isinstance(line, int)
                        and not isinstance(line, bool)
                        and line > 0
                    }
                )
                if isinstance(item.get("import_lines"), list)
                else [],
                "assessment": str(item.get("assessment") or "import-observed"),
                "reachability_states": _bounded_strings(
                    item.get("reachability_states"), 10
                ),
                "runtime_observations": _bounded_strings(
                    item.get("runtime_observations"), 10
                ),
                "owners": _bounded_strings(item.get("owners"), 20),
                "ownership_evidence_available": item.get("ownership_evidence_available")
                is True,
                "direct_test_files": _bounded_strings(
                    item.get("direct_test_files"), 50
                ),
                "transitive_test_files": _bounded_strings(
                    item.get("transitive_test_files"), 50
                ),
                "recommended_test_files": _bounded_strings(
                    item.get("recommended_test_files"), 50
                ),
                "test_selection_confidence": str(
                    item.get("test_selection_confidence") or "not-available"
                ),
                "test_execution_evidence_available": item.get(
                    "test_execution_evidence_available"
                )
                is True,
                "test_case_inventory_available": item.get(
                    "test_case_inventory_available"
                )
                is True,
                "test_case_inventory_complete": (
                    item.get("test_case_inventory_complete")
                    if isinstance(item.get("test_case_inventory_complete"), bool)
                    else None
                ),
                "test_execution_sources": _bounded_strings(
                    item.get("test_execution_sources"), 10
                ),
                "focused_test_execution": _sdk_focused_test_execution(
                    item.get("focused_test_execution")
                ),
                "focused_test_validation_status": str(
                    item.get("focused_test_validation_status") or "not-selected"
                ),
                "unobserved_recommended_test_files": _bounded_strings(
                    item.get("unobserved_recommended_test_files"), 50
                ),
                "coverage_evidence_available": item.get("coverage_evidence_available")
                is True,
                "coverage_percent": coverage_percent,
                "coverage_gap": coverage_gap
                if isinstance(coverage_gap, bool)
                else None,
                "test_coverage_alignment": _sdk_test_coverage_alignment(
                    item.get("test_coverage_alignment")
                ),
                "validation_gap_reasons": _bounded_strings(
                    item.get("validation_gap_reasons"), 10
                ),
                "evidence_artifacts": _bounded_strings(
                    item.get("evidence_artifacts"), 10
                ),
            }
        )
    return result


def _sdk_dependency_paths(value: Any) -> list[dict[str, Any]]:
    raw = value if isinstance(value, list) else []
    return [
        {
            "introducing_package": str(item.get("introducing_package") or "")[:300],
            "path": _bounded_strings(item.get("path"), 12),
            "depth": _bounded_nonnegative_integer(item.get("depth")),
        }
        for item in raw[:25]
        if isinstance(item, dict) and item.get("introducing_package")
    ]


def _sdk_dependency_environment_health(value: Any) -> dict[str, Any]:
    raw = value if isinstance(value, dict) else {}
    if not raw:
        return {}
    return {
        "total_packages": _bounded_nonnegative_integer(raw.get("total_packages")),
        "direct_dependencies": _bounded_nonnegative_integer(
            raw.get("direct_dependencies")
        ),
        "transitive_dependencies": _bounded_nonnegative_integer(
            raw.get("transitive_dependencies")
        ),
        "max_depth": _bounded_nonnegative_integer(raw.get("max_depth")),
        "missing_dependencies": _bounded_nonnegative_integer(
            raw.get("missing_dependencies")
        ),
        "cyclic_dependencies": _bounded_nonnegative_integer(
            raw.get("cyclic_dependencies")
        ),
        "conflicting_dependency_packages": _bounded_nonnegative_integer(
            raw.get("conflicting_dependency_packages")
        ),
        "conflicting_dependency_edges": _bounded_nonnegative_integer(
            raw.get("conflicting_dependency_edges")
        ),
        "healthy": raw.get("healthy") is True,
    }


def _sdk_focused_test_execution(value: Any) -> list[dict[str, Any]]:
    raw = value if isinstance(value, list) else []
    allowed_statuses = {"passed", "failed", "partial", "skipped", "not-observed"}
    return [
        {
            "path": str(item.get("path") or "")[:4096],
            "status": (
                str(item.get("status"))
                if str(item.get("status")) in allowed_statuses
                else "not-observed"
            ),
            "tests": _bounded_nonnegative_integer(item.get("tests")),
            "passed": _bounded_nonnegative_integer(item.get("passed")),
            "failures": _bounded_nonnegative_integer(item.get("failures")),
            "errors": _bounded_nonnegative_integer(item.get("errors")),
            "skipped": _bounded_nonnegative_integer(item.get("skipped")),
            "sources": _bounded_strings(item.get("sources"), 10),
            "path_attributions": [
                attribution
                for attribution in _bounded_strings(item.get("path_attributions"), 2)
                if attribution in {"producer", "classname-module"}
            ],
        }
        for item in raw[:50]
        if isinstance(item, dict) and item.get("path")
    ]


def _bounded_nonnegative_integer(value: Any) -> int:
    return (
        min(value, 1_000_000)
        if isinstance(value, int) and not isinstance(value, bool) and value >= 0
        else 0
    )


def _sdk_package_finding_index(
    findings: list[Finding],
) -> dict[str, list[dict[str, Any]]]:
    result: dict[str, list[dict[str, Any]]] = {}
    for finding in findings:
        packages = {
            package
            for location in finding.locations
            if (package := _normalized_package(location.package))
        }
        if not packages:
            continue
        record = {
            "finding_id": finding.finding_id,
            "severity": finding.severity.value,
            "tools": sorted({source.tool for source in finding.sources}),
            "classifications": sorted(set(finding.classifications)),
            "citations": [
                {
                    "identifier": citation.identifier,
                    "title": citation.title,
                    "uri": citation.uri,
                }
                for citation in finding.citations[:10]
                if citation.kind != "supporting_evidence"
            ],
        }
        for package in packages:
            result.setdefault(package, []).append(record)
    return result


def _highest_sdk_package_severity(records: list[dict[str, Any]]) -> str | None:
    order = {
        "critical": 5,
        "high": 4,
        "medium": 3,
        "low": 2,
        "informational": 1,
        "unknown": 0,
    }
    values = [str(item.get("severity") or "unknown") for item in records]
    return max(values, key=lambda item: order.get(item, 0), default=None)


def _apply_sdk_dependency_context(
    document: dict[str, Any], contexts: dict[str, dict[str, Any]]
) -> None:
    assessments = document.get("finding_assessments")
    if isinstance(assessments, list):
        for item in assessments:
            if isinstance(item, dict):
                item["sdk_dependency_context"] = _sdk_context_for(
                    item.get("sdk"), contexts
                )
    surfaces = document.get("sink_surfaces")
    if isinstance(surfaces, list):
        for item in surfaces:
            if not isinstance(item, dict):
                continue
            context = _sdk_context_for(item.get("sdk"), contexts)
            item["sdk_dependency_context"] = context
            if context["risk_tier"] == "high" and item.get("scope") == "production":
                item["review_priority"] = "high"
            steps = _sdk_dependency_verification_steps(context)
            existing = item.get("verification_steps")
            if not isinstance(existing, list):
                existing = []
            item["verification_steps"] = list(
                dict.fromkeys([*steps, *(str(value) for value in existing)])
            )[:6]


def _sdk_context_for(sdk: Any, contexts: dict[str, dict[str, Any]]) -> dict[str, Any]:
    raw = contexts.get(str(sdk)) if isinstance(sdk, str) else None
    if raw is None:
        return _empty_sdk_dependency_context()
    return {
        key: [dict(item) if isinstance(item, dict) else item for item in value]
        if isinstance(value, list)
        else value
        for key, value in raw.items()
    }


def _sdk_dependency_verification_steps(context: Any) -> list[str]:
    if not isinstance(context, dict) or not context.get("risk_present"):
        return []
    steps: list[str] = []
    advisory_clusters = context.get("advisory_clusters")
    tools = context.get("package_finding_tools")
    if isinstance(advisory_clusters, list) and advisory_clusters:
        primary_identifiers = [
            str(item.get("primary_identifier"))
            for item in advisory_clusters
            if isinstance(item, dict) and item.get("primary_identifier")
        ]
        attribution = (
            " from " + ", ".join(str(item) for item in tools[:5])
            if isinstance(tools, list) and tools
            else ""
        )
        prioritized = sorted(
            (item for item in advisory_clusters if isinstance(item, dict)),
            key=lambda item: {
                "P0": 0,
                "P1": 1,
                "P2": 2,
                "P3": 3,
                "P4": 4,
            }.get(
                str(item.get("remediation_context", {}).get("priority") or "P4"),
                5,
            ),
        )
        leading: dict[str, Any] = prioritized[0] if prioritized else {}
        raw_remediation = leading.get("remediation_context")
        remediation = raw_remediation if isinstance(raw_remediation, dict) else {}
        action = str(remediation.get("recommended_action") or "")
        if action:
            identifier = str(
                leading.get("primary_identifier") or leading.get("cluster_id")
            )
            steps.append(
                f"{remediation.get('priority', 'P4')} SDK advisory {identifier}: {action}"
            )
        else:
            steps.append(
                "Review distinct SDK advisories "
                + ", ".join(primary_identifiers[:5])
                + attribution
                + "; upgrade, replace, or govern the affected package before approving this data path."
            )
        usage: list[dict[str, Any]] = []
        for item in advisory_clusters:
            if not isinstance(item, dict):
                continue
            raw_usage = item.get("dependency_usage")
            if isinstance(raw_usage, dict):
                usage.append(raw_usage)
        if any(item.get("signals_conflict") is True for item in usage):
            steps.append(
                "Resolve the Graphify-import versus deptry-unused contradiction before disposition; confirm dependency-to-import mapping and dynamic/plugin loading."
            )
        elif any(item.get("assessment") == "declared-unused" for item in usage):
            steps.append(
                "Confirm deptry's unused-declaration evidence against dynamic and plugin loading; remove the package when unused, otherwise upgrade and document the hidden load path."
            )
        elif any(item.get("import_observed") is True for item in usage):
            import_paths = sorted(
                {
                    str(path)
                    for item in usage
                    for path in item.get("import_paths", [])[:10]
                }
            )
            steps.append(
                "Trace vulnerable API use from the exact importing files"
                + (": " + ", ".join(import_paths[:5]) if import_paths else "")
                + "; static import evidence alone does not establish vulnerable-function reachability."
            )
    finding_ids = context.get("package_finding_ids")
    if not advisory_clusters and isinstance(finding_ids, list) and finding_ids:
        attribution = (
            " from " + ", ".join(str(item) for item in tools[:5])
            if isinstance(tools, list) and tools
            else ""
        )
        steps.append(
            "Review SDK package findings "
            + ", ".join(str(item) for item in finding_ids[:5])
            + attribution
            + "; upgrade, replace, or govern the affected package before approving this data path."
        )
    lineage = context.get("lineage")
    if isinstance(lineage, list):
        drift = [
            str(item.get("package"))
            for item in lineage
            if isinstance(item, dict) and item.get("status") == "version-drift"
        ]
        artifact_only = [
            str(item.get("package"))
            for item in lineage
            if isinstance(item, dict) and item.get("status") == "artifact-only"
        ]
        if drift:
            steps.append(
                "Reconcile source and built-artifact versions for "
                + ", ".join(drift[:5])
                + " before release."
            )
        if artifact_only:
            steps.append(
                "Explain or remove artifact-only SDK packages: "
                + ", ".join(artifact_only[:5])
                + "."
            )
    return steps[:3]


def _normalized_package(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    return re.sub(r"[-_.]+", "-", value.strip()).casefold()[:300]


def _normalized_package_classification(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    result = value.strip()[:300]
    return (
        result.upper()
        if re.match(r"^(?:CVE|GHSA|OSV|PYSEC)-", result, re.IGNORECASE)
        else result
    )


def _enrich_sink_surfaces(
    surfaces: list[dict[str, Any]],
    artifacts: dict[str, Any],
    findings: list[Finding],
) -> None:
    coverage = _surface_coverage_index(artifacts.get("coverage-summary.json"))
    changes = _surface_change_index(artifacts.get("diff-coverage.json"))
    reachability = _surface_reachability_index(artifacts.get("reachability.json"))
    graph = _surface_graph_index(artifacts.get("graphify.json"))
    structural = _surface_structural_index(artifacts.get("structural-synthesis.json"))
    findings_by_path = _surface_finding_index(findings)
    for surface in surfaces:
        path = str(surface.get("path") or "").replace("\\", "/")
        line = int(surface.get("line") or 0)
        coverage_record = coverage.get(path, {})
        change_record = changes.get(path, {})
        reachability_record = _surface_reachability_record(
            reachability.get(path, []), line
        )
        graph_record = graph.get(path, {})
        structural_record = structural.get(path, {})
        path_findings = findings_by_path.get(path, [])
        related = _surface_related_findings(path_findings, line)
        line_covered = _surface_line_covered(coverage_record, change_record, line)
        changed_line = (
            line in change_record.get("changed_lines", set()) if change_record else None
        )
        context = {
            "context_available": bool(
                coverage_record
                or change_record
                or reachability_record["states"]
                or graph_record
                or structural_record
                or related
            ),
            "changed_line": changed_line,
            "line_covered": line_covered,
            "coverage_percent": coverage_record.get("percent"),
            "diff_coverage_percent": change_record.get("percent"),
            "reachability_states": reachability_record["states"],
            "runtime_observations": reachability_record["observations"],
            "graph_upstream_files": graph_record.get("upstream"),
            "graph_downstream_files": graph_record.get("downstream"),
            "graph_degree": graph_record.get("degree"),
            "related_finding_ids": [item["finding_id"] for item in related],
            "related_tools": sorted(
                {tool for item in related for tool in item["tools"]}
            ),
            "owners": sorted(
                {owner for item in path_findings for owner in item["owners"]}
                | set(structural_record.get("owners", []))
            )[:20],
            "change_risk_score": structural_record.get("change_risk_score"),
            "change_risk_priority": structural_record.get("change_risk_priority"),
            "change_classification": structural_record.get("change_classification"),
            "mapped_test_files": structural_record.get("mapped_test_files", []),
            "test_selection_confidence": structural_record.get(
                "test_selection_confidence"
            ),
            "focused_test_validation_status": structural_record.get(
                "focused_test_validation_status"
            ),
            "test_coverage_alignment": structural_record.get("test_coverage_alignment"),
            "validation_gap_reasons": structural_record.get(
                "validation_gap_reasons", []
            ),
            "validation_action": structural_record.get("validation_action"),
            "structural_risk_ids": structural_record.get("risk_ids", []),
            "structural_risk_kinds": structural_record.get("risk_kinds", []),
            "structural_recommendation": structural_record.get("recommendation"),
        }
        surface["structural_context"] = context
        surface["sdk_dependency_context"] = _empty_sdk_dependency_context()
        surface["review_priority"] = _surface_context_priority(surface, context)
        surface["verification_steps"] = _surface_verification_steps(surface, context)


def _surface_coverage_index(value: Any) -> dict[str, dict[str, Any]]:
    if not isinstance(value, dict) or not isinstance(value.get("files"), list):
        return {}
    result: dict[str, dict[str, Any]] = {}
    for item in value["files"]:
        if not isinstance(item, dict) or not isinstance(item.get("path"), str):
            continue
        summary = item.get("summary")
        percent = summary.get("percent_covered") if isinstance(summary, dict) else None
        result[item["path"].replace("\\", "/")] = {
            "percent": _optional_number(percent),
            "missing_lines": _integer_set(item.get("missing_lines")),
            "covered_lines": _integer_set(
                item.get("covered_lines") or item.get("executed_lines")
            ),
        }
    return result


def _surface_change_index(value: Any) -> dict[str, dict[str, Any]]:
    if not isinstance(value, dict) or not isinstance(value.get("src_stats"), dict):
        return {}
    result: dict[str, dict[str, Any]] = {}
    for path, item in value["src_stats"].items():
        if not isinstance(item, dict):
            continue
        covered = _integer_set(item.get("covered_lines"))
        violations = _integer_set(item.get("violation_lines"))
        result[str(path).replace("\\", "/")] = {
            "changed_lines": covered | violations,
            "covered_lines": covered,
            "violation_lines": violations,
            "percent": _optional_number(item.get("percent_covered")),
        }
    return result


def _surface_reachability_index(value: Any) -> dict[str, list[dict[str, Any]]]:
    result: dict[str, list[dict[str, Any]]] = {}
    if not isinstance(value, dict) or not isinstance(value.get("nodes"), list):
        return result
    for item in value["nodes"]:
        if not isinstance(item, dict) or not isinstance(item.get("path"), str):
            continue
        path = item["path"].replace("\\", "/")
        result.setdefault(path, []).append(item)
    return result


def _surface_reachability_record(
    nodes: list[dict[str, Any]], line: int
) -> dict[str, list[str]]:
    containing = [
        item
        for item in nodes
        if isinstance(item.get("start_line"), int)
        and isinstance(item.get("end_line"), int)
        and int(item["start_line"]) <= line <= int(item["end_line"])
    ]
    selected = containing or [
        item
        for item in nodes
        if not isinstance(item.get("start_line"), int)
        or not isinstance(item.get("end_line"), int)
    ]
    return {
        "states": sorted(
            {
                str(item["state"])
                for item in selected
                if isinstance(item.get("state"), str)
            }
        ),
        "observations": sorted(
            {
                str(item["runtime_observation"])
                for item in selected
                if isinstance(item.get("runtime_observation"), str)
            }
        ),
    }


def _surface_graph_index(value: Any) -> dict[str, dict[str, int]]:
    if not isinstance(value, dict):
        return {}
    topology = value.get("topology")
    if not isinstance(topology, dict) or not isinstance(
        topology.get("file_edges"), list
    ):
        return {}
    incoming: dict[str, set[str]] = {}
    outgoing: dict[str, set[str]] = {}
    for item in topology["file_edges"]:
        if not isinstance(item, dict):
            continue
        source = item.get("source")
        target = item.get("target")
        if not isinstance(source, str) or not isinstance(target, str):
            continue
        source = source.replace("\\", "/")
        target = target.replace("\\", "/")
        outgoing.setdefault(source, set()).add(target)
        incoming.setdefault(target, set()).add(source)
    paths = set(incoming) | set(outgoing)
    return {
        path: {
            "upstream": len(_surface_walk(incoming, path)),
            "downstream": len(_surface_walk(outgoing, path)),
            "degree": len(incoming.get(path, set()) | outgoing.get(path, set())),
        }
        for path in paths
    }


def _surface_structural_index(value: Any) -> dict[str, dict[str, Any]]:
    if not isinstance(value, dict):
        return {}
    result: dict[str, dict[str, Any]] = {}
    changes = value.get("change_impact_assessments")
    if isinstance(changes, list):
        for item in changes:
            if not isinstance(item, dict) or not isinstance(item.get("path"), str):
                continue
            path = item["path"].replace("\\", "/")
            tests: set[str] = set()
            for key in (
                "direct_test_files",
                "transitive_test_files",
                "associated_test_files",
            ):
                values = item.get(key)
                if isinstance(values, list):
                    tests.update(
                        str(test).replace("\\", "/")
                        for test in values
                        if isinstance(test, str) and test
                    )
            record = result.setdefault(path, {"risk_ids": [], "risk_kinds": []})
            record.update(
                {
                    "change_risk_score": _optional_count(item.get("risk_score")),
                    "change_risk_priority": _optional_string(
                        item.get("priority"), {"high", "medium", "low"}
                    ),
                    "change_classification": _optional_string(
                        item.get("classification")
                    ),
                    "mapped_test_files": sorted(tests)[:25],
                    "test_selection_confidence": _optional_string(
                        item.get("test_selection_confidence"),
                        {"high", "medium", "low"},
                    ),
                    "focused_test_validation_status": _optional_string(
                        item.get("focused_test_validation_status")
                    ),
                    "test_coverage_alignment": _optional_string(
                        item.get("test_coverage_alignment")
                    ),
                    "validation_gap_reasons": _bounded_strings(
                        item.get("validation_gap_reasons"), 10
                    ),
                    "validation_action": _optional_string(
                        item.get("validation_action")
                    ),
                    "recommendation": _optional_string(item.get("recommended_action")),
                }
            )
    islands = value.get("island_assessments")
    if isinstance(islands, list):
        for item in islands:
            if not isinstance(item, dict) or not isinstance(item.get("paths"), list):
                continue
            island_id = _optional_string(item.get("island_id"))
            classification = _optional_string(item.get("classification"))
            priority = _optional_string(item.get("priority"))
            for raw_path in item["paths"]:
                if not isinstance(raw_path, str):
                    continue
                record = result.setdefault(
                    raw_path.replace("\\", "/"),
                    {"risk_ids": [], "risk_kinds": []},
                )
                if island_id:
                    record["risk_ids"].append(island_id)
                if classification:
                    record["risk_kinds"].append(
                        f"island:{classification}"
                        + (f":{priority}" if priority else "")
                    )
                owners = item.get("owners")
                if isinstance(owners, list):
                    record.setdefault("owners", []).extend(
                        str(owner)
                        for owner in owners
                        if isinstance(owner, str) and owner
                    )
                if not record.get("recommendation"):
                    record["recommendation"] = _optional_string(
                        item.get("recommended_action")
                    )
    cycles = value.get("import_cycles")
    if isinstance(cycles, list):
        for item in cycles:
            if not isinstance(item, dict) or not isinstance(item.get("paths"), list):
                continue
            cycle_id = _optional_string(item.get("cycle_id"))
            priority = _optional_string(item.get("priority"))
            for raw_path in item["paths"]:
                if not isinstance(raw_path, str):
                    continue
                record = result.setdefault(
                    raw_path.replace("\\", "/"),
                    {"risk_ids": [], "risk_kinds": []},
                )
                if cycle_id:
                    record["risk_ids"].append(cycle_id)
                record["risk_kinds"].append(
                    "import-cycle" + (f":{priority}" if priority else "")
                )
                if not record.get("recommendation"):
                    record["recommendation"] = _optional_string(
                        item.get("recommended_action")
                    )
    for record in result.values():
        record["risk_ids"] = sorted(set(record.get("risk_ids", [])))[:20]
        record["risk_kinds"] = sorted(set(record.get("risk_kinds", [])))[:20]
        record["owners"] = sorted(set(record.get("owners", [])))[:20]
        record.setdefault("mapped_test_files", [])
        record.setdefault("change_risk_score", None)
        record.setdefault("change_risk_priority", None)
        record.setdefault("change_classification", None)
        record.setdefault("test_selection_confidence", None)
        record.setdefault("focused_test_validation_status", None)
        record.setdefault("test_coverage_alignment", None)
        record.setdefault("validation_gap_reasons", [])
        record.setdefault("validation_action", None)
        record.setdefault("recommendation", None)
    return result


def _surface_walk(edges: dict[str, set[str]], start: str) -> set[str]:
    seen: set[str] = set()
    pending = list(edges.get(start, set()))
    while pending and len(seen) < 10000:
        current = pending.pop()
        if current in seen or current == start:
            continue
        seen.add(current)
        pending.extend(edges.get(current, set()) - seen)
    return seen


def _surface_finding_index(findings: list[Finding]) -> dict[str, list[dict[str, Any]]]:
    result: dict[str, list[dict[str, Any]]] = {}
    for finding in findings:
        for location in finding.locations[:5]:
            path = location.path.replace("\\", "/")
            result.setdefault(path, []).append(
                {
                    "finding_id": finding.finding_id,
                    "line": location.start_line,
                    "tools": sorted({source.tool for source in finding.sources}),
                    "owners": _bounded_strings(finding.evidence.get("owners"), 20),
                }
            )
    return result


def _surface_related_findings(
    candidates: list[dict[str, Any]], line: int
) -> list[dict[str, Any]]:
    return sorted(
        (
            item
            for item in candidates
            if item.get("line") is None or abs(int(item["line"]) - line) <= 10
        ),
        key=lambda item: (
            abs(int(item.get("line") or line) - line),
            item["finding_id"],
        ),
    )[:20]


def _surface_line_covered(
    coverage: dict[str, Any], change: dict[str, Any], line: int
) -> bool | None:
    if line in change.get("violation_lines", set()):
        return False
    if line in change.get("covered_lines", set()):
        return True
    if line in coverage.get("missing_lines", set()):
        return False
    if line in coverage.get("covered_lines", set()):
        return True
    return None


def _surface_context_priority(surface: dict[str, Any], context: dict[str, Any]) -> str:
    current = str(surface.get("review_priority") or "medium")
    if current == "high":
        return current
    if context["changed_line"] is True and context["line_covered"] is False:
        return "high"
    if "observed" in context["runtime_observations"] and surface.get("data_classes"):
        return "high"
    if int(context.get("graph_upstream_files") or 0) >= 10:
        return "high"
    if context.get("change_risk_priority") == "high":
        return "high"
    if any(
        str(kind).startswith(("island:latent-attack-surface", "import-cycle:high"))
        for kind in context.get("structural_risk_kinds", [])
    ):
        return "high"
    if context["related_finding_ids"] or context["context_available"]:
        return "medium"
    return current


def _surface_verification_steps(
    surface: dict[str, Any], context: dict[str, Any]
) -> list[str]:
    steps: list[str] = []
    if context["changed_line"] is True:
        steps.append("Review the change that introduced or modified this sink surface.")
    if context["line_covered"] is False:
        steps.append(
            "Add a focused test that exercises the sink with synthetic sensitive-data canaries."
        )
    validation_action = context.get("validation_action")
    if isinstance(validation_action, str) and validation_action:
        steps.append(validation_action)
    if "observed" in context["runtime_observations"]:
        steps.append(
            "Inspect locally captured runtime output and assert that canary values are absent."
        )
    if "disconnected" in context["reachability_states"]:
        steps.append(
            "Validate dynamic registration and configured entry points; remove the sink if the path is truly disconnected."
        )
    if int(context.get("graph_upstream_files") or 0) >= 10:
        steps.append(
            "Run graph-guided tests for upstream dependents before changing the sink."
        )
    mapped_tests = context.get("mapped_test_files")
    if isinstance(mapped_tests, list) and mapped_tests:
        steps.append(
            "Run the graph-selected tests for this sink: "
            + ", ".join(str(item) for item in mapped_tests[:5])
            + "."
        )
    recommendation = context.get("structural_recommendation")
    if isinstance(recommendation, str) and recommendation:
        steps.append(recommendation)
    if context["related_finding_ids"]:
        steps.append(
            "Review nearby normalized findings together with this surface before disposition."
        )
    owners = context.get("owners")
    if isinstance(owners, list) and owners:
        steps.append(
            "Route disposition and closure evidence to "
            + ", ".join(str(item) for item in owners[:5])
            + "."
        )
    data_classes = [str(item) for item in surface.get("data_classes", [])]
    if data_classes:
        steps.append(
            "Exercise this sink with synthetic "
            + ", ".join(data_classes)
            + " canaries and assert raw values are absent from captured output."
        )
    protection = str(surface.get("protection_status") or "not-observed")
    if protection != "not-observed":
        steps.append(
            f"Test the visible {protection} control and verify the emitted value cannot reconstruct the source data."
        )
    elif surface.get("trust_boundary") in {
        "client-response",
        "external-observability",
        "external-service",
    }:
        steps.append(
            "Confirm the destination, approved field allowlist, access controls, and retention for this trust-boundary crossing."
        )
    if not steps:
        steps.append(
            "Document the approved fields for this sink and test that unexpected sensitive fields are excluded."
        )
    return steps[:6]


def _integer_set(value: Any) -> set[int]:
    if not isinstance(value, list):
        return set()
    return {
        int(item)
        for item in value
        if isinstance(item, int) and not isinstance(item, bool) and item > 0
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
    configuration_surfaces, configuration_files_omitted = _configuration_surfaces(
        target
    )
    sink_surfaces.extend(configuration_surfaces)
    sdk_observations.extend(_declared_sdk_observations(target))
    return {
        "files_analyzed": len(selected),
        "files_omitted": max(0, len(python_files) - _MAX_FILES),
        "configuration_files_omitted": configuration_files_omitted,
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
        self.value_classes: dict[str, set[str]] = {}
        self.value_protection: dict[str, str] = {}
        self.sinks: list[dict[str, Any]] = []
        self.sdks: list[dict[str, Any]] = []

    def visit_Import(self, node: ast.Import) -> None:
        for item in node.names:
            root = item.name.split(".", 1)[0]
            self.aliases[item.asname or root] = item.name
            self._sdk(item.name, node.lineno, "import")
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module:
            self._sdk(node.module, node.lineno, "import")
            for item in node.names:
                imported = f"{node.module}.{item.name}"
                self.aliases[item.asname or item.name] = imported
                self._sdk(imported, node.lineno, "import")
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_lexical_scope(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_lexical_scope(node)

    def visit_Lambda(self, node: ast.Lambda) -> None:
        self._visit_lexical_scope(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._visit_lexical_scope(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        self._remember_assignment(node.targets, node.value)
        self._remember_value_context(node.targets, node.value)
        self._configuration_assignment(node.targets, node.value, node.lineno)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None:
            self._remember_assignment([node.target], node.value)
            self._remember_value_context([node.target], node.value)
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
            family = "telemetry"
            label = (
                "broad OpenTelemetry HTTP header capture"
                if _has_broad_header_capture_configuration(node)
                else "OpenTelemetry HTTP header capture"
            )
        elif (mode := _genai_capture_call_mode(qualified, node)) is not None and (
            capture_label := _genai_capture_label(mode)
        ) is not None:
            family = "telemetry"
            label = capture_label
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
            and node.args
            and self._has_dynamic_sensitive_context(node.args[0])
        ):
            family, label = "url", "sensitive data in outbound URL"
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
            data_classes = self._classes_for_node(node)
            protection = self._protection_for_node(node)
            risk_factors = _surface_risk_factors(node, family, data_classes, protection)
            self.sinks.append(
                {
                    "path": self.path,
                    "line": node.lineno,
                    "scope": self.scope,
                    "sink_family": family,
                    "sink": qualified[:300],
                    "label": label,
                    "sdk": _sdk_for_qualified_name(qualified),
                    "sanitizer_visible": protection != "not-observed",
                    "protection_status": protection,
                    "data_classes": sorted(data_classes),
                    "trust_boundary": _trust_boundary(family),
                    "risk_factors": risk_factors,
                    "review_priority": _surface_priority(
                        self.scope,
                        family,
                        data_classes,
                        protection,
                        risk_factors,
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

    def _visit_lexical_scope(
        self, node: ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda | ast.ClassDef
    ) -> None:
        outer_aliases = self.aliases
        outer_classes = self.value_classes
        outer_protection = self.value_protection
        self.aliases = dict(outer_aliases)
        self.value_classes = {
            name: set(classes) for name, classes in outer_classes.items()
        }
        self.value_protection = dict(outer_protection)
        try:
            self.generic_visit(node)
        finally:
            self.aliases = outer_aliases
            self.value_classes = outer_classes
            self.value_protection = outer_protection

    def _remember_value_context(self, targets: list[ast.expr], value: ast.expr) -> None:
        classes = self._classes_for_node(value)
        protection = self._protection_for_node(value)
        for name in _target_names(targets):
            if classes:
                self.value_classes[name] = classes
            else:
                self.value_classes.pop(name, None)
            if protection != "not-observed":
                self.value_protection[name] = protection
            else:
                self.value_protection.pop(name, None)

    def _classes_for_node(self, node: ast.AST) -> set[str]:
        classes = _data_classes(node)
        for item in ast.walk(node):
            if isinstance(item, ast.Name):
                classes.update(self.value_classes.get(item.id, set()))
        return classes

    def _protection_for_node(self, node: ast.AST) -> str:
        kinds = {
            self.value_protection[item.id]
            for item in ast.walk(node)
            if isinstance(item, ast.Name) and item.id in self.value_protection
        }
        for item in ast.walk(node):
            if isinstance(item, ast.Call):
                kind = _protective_call_kind(item, self.aliases)
                if kind != "not-observed":
                    kinds.add(kind)
        if isinstance(node, ast.Call) and _call_has_protective_configuration(node):
            kinds.add("configured-hook")
        return _strongest_protection(kinds)

    def _has_dynamic_sensitive_context(self, node: ast.AST) -> bool:
        for item in ast.walk(node):
            if isinstance(item, ast.Name):
                if self.value_classes.get(item.id) or _SENSITIVE_HINT.search(item.id):
                    return True
            elif isinstance(item, ast.Attribute) and _SENSITIVE_HINT.search(item.attr):
                return True
        return False

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
        if capture_names and _is_broad_capture(value):
            self.sinks.append(
                _configuration_surface(
                    path=self.path,
                    line=line,
                    name=sorted(capture_names)[0],
                    label="broad OpenTelemetry HTTP header capture",
                    scope=self.scope,
                )
            )
        if _GENAI_CAPTURE_NAME in names and (mode := _constant_text(value)) is not None:
            label = _genai_capture_label(mode)
            if label:
                self.sinks.append(
                    _configuration_surface(
                        path=self.path,
                        line=line,
                        name=_GENAI_CAPTURE_NAME,
                        label=label,
                        scope=self.scope,
                    )
                )

    def _sdk(self, module: str, line: int, evidence: str) -> None:
        matched = _sdk_catalog_key(module)
        record = _SDK_CATALOG.get(matched or "")
        if record is None:
            return
        sdk, family = record
        self.sdk_families.add(family)
        self.sdks.append(
            {
                "sdk": sdk,
                "family": family,
                "module": matched,
                "package": None,
                "evidence": evidence,
                "path": self.path,
                "line": line,
                "scope": self.scope,
            }
        )


def _declared_sdk_observations(target: Path) -> list[dict[str, Any]]:
    declarations: list[tuple[str, str, int | None]] = []
    manifests = sorted(
        (
            path
            for path in target.rglob("pyproject.toml")
            if not path.is_symlink()
            and not any(
                part in _SKIP_DIRECTORIES for part in path.relative_to(target).parts
            )
        ),
        key=lambda path: path.relative_to(target).as_posix(),
    )
    for path in manifests[:_MAX_CONFIGURATION_FILES]:
        try:
            document = tomllib.loads(path.read_text(encoding="utf-8"))
        except (OSError, tomllib.TOMLDecodeError, UnicodeError):
            continue
        relative = path.relative_to(target).as_posix()
        declarations.extend(
            (dependency, relative, None)
            for dependency in _pyproject_dependencies(document)
        )

    requirement_files = sorted(
        (
            path
            for path in target.rglob("*.txt")
            if path.name.casefold().startswith(("requirements", "constraints"))
            and not path.is_symlink()
            and not any(
                part in _SKIP_DIRECTORIES for part in path.relative_to(target).parts
            )
        ),
        key=lambda path: path.relative_to(target).as_posix(),
    )
    for path in requirement_files[:_MAX_CONFIGURATION_FILES]:
        try:
            lines = path.read_text(encoding="utf-8-sig").splitlines()
        except (OSError, UnicodeError):
            continue
        relative = path.relative_to(target).as_posix()
        declarations.extend(
            (line.split("#", 1)[0].strip(), relative, number)
            for number, line in enumerate(lines, start=1)
            if line.split("#", 1)[0].strip()
            and not line.lstrip().startswith(("-", "#"))
        )

    result: list[dict[str, Any]] = []
    for dependency, declaration_path, line in declarations:
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
                "package": normalized,
                "evidence": "declared-dependency",
                "path": declaration_path,
                "line": line,
                "scope": "repository",
            }
        )
    return result


def _pyproject_dependencies(document: dict[str, Any]) -> list[str]:
    dependencies: list[str] = []
    project = document.get("project")
    if isinstance(project, dict):
        if isinstance(project.get("dependencies"), list):
            dependencies.extend(str(item) for item in project["dependencies"])
        optional = project.get("optional-dependencies")
        if isinstance(optional, dict):
            for values in optional.values():
                if isinstance(values, list):
                    dependencies.extend(str(item) for item in values)
    groups = document.get("dependency-groups")
    if isinstance(groups, dict):
        for values in groups.values():
            if isinstance(values, list):
                dependencies.extend(str(item) for item in values)
    tool = document.get("tool")
    poetry = tool.get("poetry") if isinstance(tool, dict) else None
    if isinstance(poetry, dict):
        dependencies.extend(_mapping_dependency_names(poetry.get("dependencies")))
        poetry_groups = poetry.get("group")
        if isinstance(poetry_groups, dict):
            for group in poetry_groups.values():
                if isinstance(group, dict):
                    dependencies.extend(
                        _mapping_dependency_names(group.get("dependencies"))
                    )
    return dependencies


def _mapping_dependency_names(value: Any) -> list[str]:
    if not isinstance(value, dict):
        return []
    return [str(name) for name in value if str(name).casefold() != "python"]


def _configuration_surfaces(target: Path) -> tuple[list[dict[str, Any]], int]:
    candidates = sorted(
        (
            path
            for path in target.rglob("*")
            if path.is_file()
            and not path.is_symlink()
            and _is_configuration_path(path)
            and not any(
                part in _SKIP_DIRECTORIES for part in path.relative_to(target).parts
            )
        ),
        key=lambda path: path.relative_to(target).as_posix(),
    )
    result: list[dict[str, Any]] = []
    for path in candidates[:_MAX_CONFIGURATION_FILES]:
        try:
            if path.stat().st_size > _MAX_CONFIGURATION_BYTES:
                continue
            lines = path.read_text(encoding="utf-8-sig").splitlines()
        except (OSError, UnicodeError):
            continue
        relative = path.relative_to(target).as_posix()
        for number, line in enumerate(lines, start=1):
            match = _CONFIG_ASSIGNMENT.match(line)
            if not match:
                continue
            name = match.group("name").upper()
            value = match.group("value").strip().upper()
            label: str | None = None
            if name == _GENAI_CAPTURE_NAME:
                label = _genai_capture_label(value)
            elif (
                "OTEL_INSTRUMENTATION_HTTP_CAPTURE_HEADERS_" in name
                and not name.endswith("SANITIZE_FIELDS")
                and value in {"*", ".*"}
            ):
                label = "broad OpenTelemetry HTTP header capture"
            if label:
                result.append(
                    _configuration_surface(
                        path=relative,
                        line=number,
                        name=name,
                        label=label,
                        scope=_scope(relative),
                    )
                )
    return result, max(0, len(candidates) - _MAX_CONFIGURATION_FILES)


def _is_configuration_path(path: Path) -> bool:
    name = path.name.casefold()
    return (
        path.suffix.casefold() in _CONFIGURATION_SUFFIXES
        or name == ".env"
        or name.endswith(".env")
    )


def _configuration_surface(
    *, path: str, line: int, name: str, label: str, scope: str
) -> dict[str, Any]:
    risk_factors = ["external-trust-boundary", "capture-configuration"]
    if "broad" in label.casefold():
        risk_factors.append("broad-data-capture")
    if "content capture enabled" in label.casefold():
        risk_factors.extend(["full-content-capture", "long-lived-operational-copy"])
    if "invalid" in label.casefold():
        risk_factors.append("ambiguous-protection-configuration")
    return {
        "path": path,
        "line": line,
        "scope": scope,
        "sink_family": "telemetry",
        "sink": name[:300],
        "label": label,
        "sdk": "OpenTelemetry",
        "sanitizer_visible": False,
        "protection_status": "not-observed",
        "data_classes": ["credentials", "personal", "request-content"],
        "trust_boundary": "external-observability",
        "risk_factors": sorted(set(risk_factors)),
        "review_priority": "high" if scope == "production" else "low",
    }


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
    expected_family = _finding_sink_family(finding)
    nearest = min(
        candidates,
        key=lambda item: (
            0 if _sink_families_match(str(item["sink_family"]), expected_family) else 1,
            abs(int(item["line"]) - int(line or item["line"])),
        ),
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
    data_classes = set(_finding_data_classes(finding))
    if nearest:
        data_classes.update(str(value) for value in nearest.get("data_classes") or [])
    protection = (
        str(nearest.get("protection_status") or "not-observed")
        if nearest
        else "unknown"
    )
    risk_factors = (
        list(nearest.get("risk_factors") or [])
        if nearest
        else ["scanner-confirmed-source-to-sink"]
    )
    if "scanner-confirmed-source-to-sink" not in risk_factors:
        risk_factors.append("scanner-confirmed-source-to-sink")
    assessment = {
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
        "protection_status": protection,
        "data_classes": sorted(data_classes),
        "trust_boundary": (
            str(nearest.get("trust_boundary"))
            if nearest
            else _trust_boundary(sink_family)
        ),
        "risk_factors": sorted(set(risk_factors)),
        "review_priority": _assessment_priority(finding, nearest, relevance),
        "sdk_dependency_context": _empty_sdk_dependency_context(),
        "evidence_basis": "normalized-scanner-source-to-sink",
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
    cross_references = _fusion_cross_references(finding)
    assessment["cross_references"] = cross_references
    assessment["triage_tier"] = _exposure_triage_tier(assessment, cross_references)
    assessment["verification_steps"] = _exposure_verification_steps(
        assessment, cross_references
    )
    return assessment


def _finding_data_classes(finding: Finding) -> list[str]:
    rule_value = " ".join(source.rule_id for source in finding.sources).casefold()
    value = " ".join(
        [finding.title, finding.description, *finding.classifications]
    ).casefold()
    result: set[str] = set()
    if "sensitive-data" in rule_value or (
        "credential" in value
        and "private-data" not in rule_value
        and "request-data" not in rule_value
    ):
        result.add("credentials")
    if "private-data" in rule_value or "cwe-359" in value:
        result.add("personal")
    if "request-data" in rule_value or "request payload" in value:
        result.add("request-content")
    if "runtime-state" in rule_value:
        result.add("unclassified-sensitive")
    return sorted(result)


def _assessment_priority(
    finding: Finding, nearest: dict[str, Any] | None, relevance: str
) -> str:
    if nearest and nearest.get("scope") == "test":
        return "low"
    if finding.severity.value in {"critical", "high"}:
        return "high"
    if nearest and nearest.get("review_priority") == "high":
        return "high"
    if relevance == "disconnected-review":
        return "low"
    return "medium"


def _fusion_cross_references(finding: Finding) -> dict[str, Any]:
    fusion = finding.evidence.get("fusion")
    if not isinstance(fusion, dict):
        fusion = {}
    source = fusion.get("source_context")
    if not isinstance(source, dict):
        source = {}
    structural = fusion.get("structural_context")
    if not isinstance(structural, dict):
        structural = {}
    change = structural.get("change_impact")
    if not isinstance(change, dict):
        change = {}
    mapped_tests = _mapped_tests_from_change(change)
    structural_ids: list[str] = []
    structural_kinds: list[str] = []
    island = structural.get("island")
    if isinstance(island, dict):
        if island.get("island_id"):
            structural_ids.append(str(island["island_id"]))
        if island.get("classification"):
            structural_kinds.append(f"island:{island['classification']}")
    cycle = structural.get("import_cycle")
    if isinstance(cycle, dict):
        if cycle.get("cycle_id"):
            structural_ids.append(str(cycle["cycle_id"]))
        structural_kinds.append(
            "import-cycle" + (f":{cycle['priority']}" if cycle.get("priority") else "")
        )
    boundary = structural.get("island_boundary")
    if isinstance(boundary, dict) and boundary.get("boundary_classification"):
        structural_kinds.append(f"boundary:{boundary['boundary_classification']}")
    return {
        "fusion_available": bool(fusion),
        "fusion_review_tier": str(fusion.get("review_tier") or "not-available"),
        "corroboration": str(fusion.get("corroboration") or "not-available"),
        "review_reasons": _bounded_strings(fusion.get("review_reasons"), 10),
        "related_finding_ids": _bounded_strings(fusion.get("related_finding_ids"), 20),
        "related_tools": _bounded_strings(fusion.get("related_tools"), 20),
        "changed_line": _optional_bool(source.get("changed_line")),
        "line_covered": _optional_bool(source.get("line_covered")),
        "coverage_percent": _optional_number(source.get("coverage_percent")),
        "diff_coverage_percent": _optional_number(source.get("diff_coverage_percent")),
        "reachability_states": _bounded_strings(source.get("reachability_states"), 10),
        "runtime_observations": _bounded_strings(
            source.get("runtime_observations"), 10
        ),
        "graph_upstream_files": _optional_count(source.get("graph_upstream_files")),
        "graph_downstream_files": _optional_count(source.get("graph_downstream_files")),
        "graph_degree": _optional_count(source.get("graph_degree")),
        "owners": _bounded_strings(finding.evidence.get("owners"), 20),
        "change_risk_score": _optional_count(change.get("risk_score")),
        "change_risk_priority": _optional_string(
            change.get("priority"), {"high", "medium", "low"}
        ),
        "change_classification": _optional_string(change.get("classification")),
        "mapped_test_files": mapped_tests,
        "test_selection_confidence": _optional_string(
            change.get("test_selection_confidence"), {"high", "medium", "low"}
        ),
        "focused_test_validation_status": _optional_string(
            change.get("focused_test_validation_status")
        ),
        "test_coverage_alignment": _optional_string(
            change.get("test_coverage_alignment")
        ),
        "validation_gap_reasons": _bounded_strings(
            change.get("validation_gap_reasons"), 10
        ),
        "validation_action": _optional_string(change.get("validation_action")),
        "structural_risk_ids": sorted(set(structural_ids))[:20],
        "structural_risk_kinds": sorted(set(structural_kinds))[:20],
        "structural_recommendation": _optional_string(change.get("recommended_action")),
    }


def _exposure_triage_tier(
    assessment: dict[str, Any], cross_references: dict[str, Any]
) -> str:
    fusion_tier = str(cross_references.get("fusion_review_tier") or "")
    if fusion_tier == "urgent":
        return "urgent"
    dependency = assessment.get("sdk_dependency_context")
    dependency_tier = (
        str(dependency.get("risk_tier")) if isinstance(dependency, dict) else "none"
    )
    if (
        fusion_tier == "elevated"
        or assessment.get("review_priority") == "high"
        or dependency_tier == "high"
    ):
        return "elevated"
    return "standard"


def _exposure_verification_steps(
    assessment: dict[str, Any], cross_references: dict[str, Any]
) -> list[str]:
    steps = [
        "Confirm the scanner source-to-sink trace and the field's authoritative data classification."
    ]
    steps.extend(
        _sdk_dependency_verification_steps(assessment.get("sdk_dependency_context"))
    )
    if cross_references.get("changed_line") is True:
        steps.append(
            "Review the introducing change and require a focused regression test before merge or release."
        )
    if cross_references.get("line_covered") is False:
        steps.append(
            "Add a test that exercises the finding line with synthetic credential and privacy canaries."
        )
    validation_action = cross_references.get("validation_action")
    if isinstance(validation_action, str) and validation_action:
        steps.append(validation_action)
    mapped_tests = cross_references.get("mapped_test_files")
    if isinstance(mapped_tests, list) and mapped_tests:
        steps.append(
            "Run the graph-guided, graph-selected tests: "
            + ", ".join(str(item) for item in mapped_tests[:5])
            + "."
        )
    observations = set(cross_references.get("runtime_observations") or [])
    states = set(cross_references.get("reachability_states") or [])
    if "observed" in observations:
        steps.append(
            "Exercise the observed path against a local capture exporter and assert that canary values are absent."
        )
    elif "executable" in states or "load-only" in states:
        steps.append(
            "Exercise the modeled entry-point path with a local capture exporter and inspect serialized output."
        )
    elif "disconnected" in states:
        steps.append(
            "Validate configured entry points and dynamic registration; if truly disconnected, remove or disable the sink path."
        )
    if int(cross_references.get("graph_upstream_files") or 0) >= 10:
        steps.append(
            "Run graph-guided regression tests for upstream dependents before changing the shared sink path."
        )
    recommendation = cross_references.get("structural_recommendation")
    if isinstance(recommendation, str) and recommendation:
        steps.append(recommendation)
    owners = cross_references.get("owners")
    if isinstance(owners, list) and owners:
        steps.append(
            "Route disposition and closure evidence to "
            + ", ".join(str(item) for item in owners[:5])
            + "."
        )
    if assessment.get("protection_status") not in {"not-observed", "unknown"}:
        steps.append(
            "Verify the visible protection with data-class-specific canaries; do not accept its name as proof of effectiveness."
        )
    if assessment.get("trust_boundary") in {
        "external-network",
        "external-observability",
        "untrusted-client",
    }:
        steps.append(
            "Verify recipient, exporter, region, access, retention, and deletion controls at the identified trust boundary."
        )
    return steps[:6]


def _bounded_strings(value: Any, limit: int) -> list[str]:
    if not isinstance(value, list):
        return []
    return sorted({str(item)[:500] for item in value if str(item)})[:limit]


def _mapped_tests_from_change(change: dict[str, Any]) -> list[str]:
    values: list[str] = []
    for key in (
        "direct_test_files",
        "transitive_test_files",
        "associated_test_files",
    ):
        candidates = change.get(key)
        if isinstance(candidates, list):
            values.extend(str(item) for item in candidates if isinstance(item, str))
    return _bounded_strings(values, 25)


def _optional_bool(value: Any) -> bool | None:
    return value if isinstance(value, bool) else None


def _optional_number(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return round(float(value), 2)


def _optional_string(value: Any, allowed: set[str] | None = None) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    result = value[:500]
    return result if allowed is None or result in allowed else None


def _optional_count(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value


def _runtime_observed(cross_references: dict[str, Any]) -> bool:
    return "observed" in set(cross_references.get("runtime_observations") or [])


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
    if "sensitive-data-in-url" in value or "outbound url" in value:
        return "url"
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
    if "CWE-598" in classes or family in {"url", "url-query"}:
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
    if family in {"url", "url-query"}:
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


def _has_broad_header_capture_configuration(node: ast.Call) -> bool:
    return any(
        item.arg is not None
        and item.arg.startswith("http_capture_headers_")
        and item.arg != "http_capture_headers_sanitize_fields"
        and _is_broad_capture(item.value)
        for item in node.keywords
    )


def _genai_capture_call_mode(qualified: str, node: ast.Call) -> str | None:
    if qualified == "os.environ.setdefault" and len(node.args) >= 2:
        name = _constant_text(node.args[0])
        return _constant_text(node.args[1]) if name == _GENAI_CAPTURE_NAME else None
    if qualified == "os.putenv" and len(node.args) >= 2:
        name = _constant_text(node.args[0])
        return _constant_text(node.args[1]) if name == _GENAI_CAPTURE_NAME else None
    return None


def _genai_capture_label(value: str) -> str | None:
    normalized = value.strip().upper()
    if normalized in _GENAI_CAPTURE_ENABLED:
        return "GenAI message content capture enabled"
    if normalized in _GENAI_CAPTURE_LEGACY:
        return "invalid GenAI content-capture mode"
    return None


def _constant_text(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value.strip().upper()
    return None


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


def _target_names(targets: list[ast.expr]) -> set[str]:
    names: set[str] = set()
    for target in targets:
        for item in ast.walk(target):
            if isinstance(item, ast.Name):
                names.add(item.id)
    return names


def _data_classes(node: ast.AST) -> set[str]:
    values = _node_text(node)
    result = {
        label
        for label, hint in _DATA_CLASS_HINTS.items()
        if any(hint.search(value) for value in values)
    }
    if any(
        isinstance(item, ast.Attribute)
        and item.attr in {"body", "data", "form", "GET", "POST", "query_params"}
        and _request_receiver(item.value)
        for item in ast.walk(node)
    ):
        result.add("request-content")
    if any(
        isinstance(item, ast.Call)
        and _qualified_name(item.func, {}).rsplit(".", 1)[-1] in {"get_json", "json"}
        and isinstance(item.func, ast.Attribute)
        and _request_receiver(item.func.value)
        for item in ast.walk(node)
    ):
        result.add("request-content")
    return result


def _protective_call_kind(node: ast.Call, aliases: dict[str, str]) -> str:
    name = _qualified_name(node.func, aliases)
    if _MINIMIZER_HINT.search(name):
        return "minimized-or-allowlisted"
    if _REDACTOR_HINT.search(name):
        return "redacted-or-masked"
    if _PSEUDONYMIZER_HINT.search(name):
        return "pseudonymized"
    return "not-observed"


def _strongest_protection(kinds: set[str]) -> str:
    for value in (
        "minimized-or-allowlisted",
        "redacted-or-masked",
        "configured-hook",
        "pseudonymized",
    ):
        if value in kinds:
            return value
    return "not-observed"


def _trust_boundary(family: str) -> str:
    if family in {"analytics", "error-monitoring", "observability", "telemetry"}:
        return "external-observability"
    if family in {"network-egress", "url", "url-query"}:
        return "external-network"
    if family == "client-response":
        return "untrusted-client"
    if family in {"logging", "metrics"}:
        return "operational-data-plane"
    return "unknown"


def _surface_risk_factors(
    node: ast.Call,
    family: str,
    data_classes: set[str],
    protection: str,
) -> list[str]:
    factors: set[str] = set()
    if data_classes:
        factors.add("sensitive-context")
    if "request-content" in data_classes:
        factors.add("full-request-content")
    if family in {
        "analytics",
        "error-monitoring",
        "network-egress",
        "observability",
        "telemetry",
        "url",
        "url-query",
    }:
        factors.add("external-trust-boundary")
    if family in {
        "analytics",
        "error-monitoring",
        "logging",
        "metrics",
        "observability",
        "telemetry",
        "url",
        "url-query",
    }:
        factors.add("long-lived-operational-copy")
    if family in {"url", "url-query"}:
        factors.add("url-propagation")
    if family == "client-response":
        factors.add("untrusted-client-disclosure")
    if family == "metrics" and data_classes:
        factors.add("high-cardinality-label-disclosure")
    if _call_has_exception_data(node):
        factors.add("exception-details")
    call_names = {
        _qualified_name(item.func, {}).casefold()
        for item in ast.walk(node)
        if isinstance(item, ast.Call)
    }
    text = {value.casefold() for value in _node_text(node)}
    has_environment = any(
        isinstance(item, ast.Attribute)
        and _qualified_name(item, {}).casefold() == "os.environ"
        for item in ast.walk(node)
    )
    if call_names & {"locals", "vars"} or "__dict__" in text or has_environment:
        factors.add("broad-runtime-state")
    if data_classes and any(
        value.rsplit(".", 1)[-1]
        in {"asdict", "dict", "json", "model_dump", "model_dump_json"}
        for value in call_names
    ):
        factors.add("full-object-serialization")
    if protection == "not-observed" and data_classes:
        factors.add("no-protection-observed")
    if protection == "pseudonymized":
        factors.add("pseudonymized-data-remains-sensitive")
    return sorted(factors)


def _surface_priority(
    scope: str,
    family: str,
    data_classes: set[str],
    protection: str,
    risk_factors: list[str],
) -> str:
    if scope == "test":
        return "low"
    if family in {"client-response", "url", "url-query"} and data_classes:
        return "high"
    if (
        data_classes
        and protection == "not-observed"
        and family
        in {
            "analytics",
            "error-monitoring",
            "logging",
            "metrics",
            "observability",
            "telemetry",
        }
    ):
        return "high"
    if "broad-runtime-state" in risk_factors or "full-request-content" in risk_factors:
        return "high"
    return "medium"


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
    if _node_matches_hint(node, _REQUEST_DATA_HINT):
        return True
    return any(
        isinstance(item, ast.Attribute)
        and item.attr == "data"
        and _request_receiver(item.value)
        for item in ast.walk(node)
    )


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


def _request_receiver(node: ast.AST) -> bool:
    value = _qualified_name(node, {})
    return bool(
        value and _REQUEST_OBJECT_HINT.fullmatch(value.rsplit(".", 1)[-1]) is not None
    )


def _sdk_catalog_key(module: str) -> str | None:
    normalized = module.casefold()
    matches = [
        key
        for key in _SDK_CATALOG
        if normalized == key or normalized.startswith(f"{key}.")
    ]
    return max(matches, key=len, default=None)


def _sdk_for_qualified_name(value: str) -> str | None:
    key = _sdk_catalog_key(value)
    record = _SDK_CATALOG.get(key or "")
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


def _sink_families_match(observed: str, expected: str) -> bool:
    if observed == expected:
        return True
    if {observed, expected} <= {"url", "url-query"}:
        return True
    telemetry = {
        "analytics",
        "error-monitoring",
        "metrics",
        "observability",
        "telemetry",
    }
    return observed in telemetry and expected in telemetry


def _deduplicate(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
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
        key = json.dumps(item, sort_keys=True, separators=(",", ":"))
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
