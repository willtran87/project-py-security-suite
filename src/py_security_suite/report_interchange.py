"""SARIF and SonarQube external-issue report rendering."""

from __future__ import annotations

from typing import Any

from .report_markdown import _markdown_text
from .report_sarif import (
    SARIF_FINGERPRINT_KEY,
    _sarif_artifact_uri,
    _sarif_code_flow_summary,
    _sarif_level,
    _sarif_message_text,
    _sarif_name,
    _sarif_security_score,
    _sarif_suppression,
)
from .models import Finding, Location, Severity, json_ready
from .report_common import (
    _classification_uri,
    _finding_priority,
    _line_is_highlighted,
    _owner_values,
    _reference_uri,
)


__all__ = [
    "render_sarif",
    "render_sonarqube_external_issues",
]


def render_sarif(findings: list[Finding]) -> dict[str, Any]:
    """Render SARIF 2.1.0 for code-scanning platforms.

    Rules are keyed by ``(scanner rule, severity)`` because GitHub reads
    ``security-severity`` only from the rule descriptor: one descriptor per
    source rule would show every result at the first finding's severity.
    Findings suppressed by governed risk acceptance are emitted with an
    accepted external suppression instead of being dropped, so platforms keep
    them dismissed rather than closing them as fixed.
    """

    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for finding in findings:
        source = finding.sources[0] if finding.sources else None
        base_rule_id = (
            f"{source.tool}/{source.rule_id}" if source else finding.finding_id
        )
        rule_id = f"{base_rule_id}/{finding.severity.value}"
        security_severity = str(_sarif_security_score(finding.severity))
        rule = {
            "id": rule_id,
            "name": _sarif_name(rule_id),
            "shortDescription": {"text": finding.title},
            "fullDescription": {"text": finding.description},
            "defaultConfiguration": {"level": _sarif_level(finding.severity)},
            "help": {
                "text": (
                    f"Why it matters: {finding.impact}\n\n"
                    f"Recommended action: {finding.remediation}"
                ),
                "markdown": (
                    f"**Why it matters:** {_markdown_text(finding.impact)}\n\n"
                    "**Recommended action:** "
                    f"{_markdown_text(finding.remediation)}"
                ),
            },
            "properties": {
                "security-severity": security_severity,
                "severity": finding.severity.value,
                "source_rule_id": base_rule_id,
                "tags": list(
                    dict.fromkeys(
                        [finding.domain, finding.area, *finding.classifications]
                    )
                ),
            },
        }
        help_uri = _first_reference_uri(finding)
        if help_uri:
            rule["helpUri"] = help_uri
        rules.setdefault(rule_id, rule)
        result: dict[str, Any] = {
            "ruleId": rule_id,
            "level": _sarif_level(finding.severity),
            "message": {"text": _sarif_message_text(finding.description)},
            "partialFingerprints": {SARIF_FINGERPRINT_KEY: finding.fingerprint},
            "properties": {
                "security-severity": security_severity,
                "severity": finding.severity.value,
                "finding_id": finding.finding_id,
                "priority": _finding_priority(finding),
                "domain": finding.domain,
                "area": finding.area,
                "blocking": finding.blocking,
                "confidence": finding.confidence.value,
                "lifecycle": finding.status.value,
                "owners": _owner_values(finding),
                "classifications": finding.classifications,
                "impact": finding.impact,
                "recommended_action": finding.remediation,
                "source_tools": [item.tool for item in finding.sources],
                "source_rules": [
                    {
                        "tool": item.tool,
                        "version": item.version,
                        "rule_id": item.rule_id,
                        "native_severity": item.native_severity,
                    }
                    for item in finding.sources
                ],
                "citations": [
                    {
                        "kind": item.kind,
                        "identifier": item.identifier,
                        "title": item.title,
                        "uri": _reference_uri(item),
                    }
                    for item in finding.citations
                ],
            },
        }
        graph_context = finding.evidence.get("graph_context")
        if isinstance(graph_context, dict):
            result["properties"]["graph_context"] = json_ready(graph_context)
        risk_path = finding.evidence.get("risk_path")
        if isinstance(risk_path, dict):
            result["properties"]["risk_path"] = json_ready(risk_path)
        secret_provenance = finding.evidence.get("secret_provenance")
        if isinstance(secret_provenance, dict):
            result["properties"]["secret_provenance"] = json_ready(secret_provenance)
        structural = finding.evidence.get("structural_synthesis")
        if isinstance(structural, dict):
            result["properties"]["structural_synthesis"] = json_ready(structural)
        data_exposure = finding.evidence.get("data_exposure")
        if isinstance(data_exposure, dict):
            result["properties"]["data_exposure"] = json_ready(data_exposure)
        fusion = finding.evidence.get("fusion")
        if isinstance(fusion, dict):
            result["properties"]["evidence_fusion"] = json_ready(fusion)
        location_summary = finding.evidence.get("sarif_location_summary")
        if isinstance(location_summary, dict):
            result["properties"]["sarif_location_summary"] = json_ready(
                location_summary
            )
        result_semantics = finding.evidence.get("sarif_result_semantics")
        if isinstance(result_semantics, dict):
            result["properties"]["sarif_result_semantics"] = json_ready(
                result_semantics
            )
        rule_reference = finding.evidence.get("sarif_rule_reference")
        if isinstance(rule_reference, dict):
            result["properties"]["sarif_rule_reference"] = json_ready(rule_reference)
        message_reference = finding.evidence.get("sarif_message_reference")
        if isinstance(message_reference, dict):
            result["properties"]["sarif_message_reference"] = json_ready(
                message_reference
            )
        severity_decision = finding.evidence.get("sarif_severity_decision")
        if isinstance(severity_decision, dict):
            result["properties"]["sarif_severity_decision"] = json_ready(
                severity_decision
            )
        code_flows = finding.evidence.get("sarif_code_flows")
        if isinstance(code_flows, list):
            flow_summary = _sarif_code_flow_summary(code_flows)
            if flow_summary:
                result["properties"]["sarif_code_flow_summary"] = flow_summary
        suppression = _sarif_suppression(finding)
        if suppression is not None:
            result["suppressions"] = [suppression]
        locations = [
            physical
            for physical in map(_sarif_result_location, finding.locations)
            if physical is not None
        ]
        if locations:
            result["locations"] = locations
        results.append(result)
    return {
        "$schema": ("https://json.schemastore.org/sarif-2.1.0.json"),
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Python Security Suite",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }


def _sarif_result_location(location: Location) -> dict[str, Any] | None:
    uri = _sarif_artifact_uri(location.path)
    if uri is None:
        return None
    physical: dict[str, Any] = {"artifactLocation": {"uri": uri}}
    if location.start_line:
        region: dict[str, Any] = {
            "startLine": location.start_line,
            "endLine": location.end_line or location.start_line,
        }
        if location.snippet and not location.snippet_redacted:
            highlighted = _highlighted_snippet(location)
            if highlighted:
                region["snippet"] = {"text": highlighted}
            snippet_start = location.snippet_start_line or location.start_line
            physical["contextRegion"] = {
                "startLine": snippet_start,
                "endLine": snippet_start + len(location.snippet.splitlines()) - 1,
                "snippet": {"text": location.snippet},
            }
        physical["region"] = region
    return {"physicalLocation": physical}


def render_sonarqube_external_issues(findings: list[Finding]) -> dict[str, Any]:
    """Render SonarQube's portable generic external-issue format."""

    issues: list[dict[str, Any]] = []
    for finding in findings:
        source = finding.sources[0] if finding.sources else None
        location = (
            finding.locations[0] if finding.locations else Location(path="<repository>")
        )
        issue: dict[str, Any] = {
            "engineId": "py-security-suite",
            "ruleId": f"{source.tool}/{source.rule_id}"
            if source
            else finding.finding_id,
            "severity": {
                Severity.CRITICAL: "BLOCKER",
                Severity.HIGH: "CRITICAL",
                Severity.MEDIUM: "MAJOR",
                Severity.LOW: "MINOR",
                Severity.INFORMATIONAL: "INFO",
                Severity.UNKNOWN: "INFO",
            }[finding.severity],
            "type": "VULNERABILITY"
            if finding.domain in {"security", "supply-chain"}
            else "CODE_SMELL",
            "primaryLocation": {
                "message": f"{finding.title}. Recommended action: {finding.remediation}",
                "filePath": location.path,
            },
        }
        graph_context = finding.evidence.get("graph_context")
        if isinstance(graph_context, dict):
            issue["primaryLocation"]["message"] += (
                f" Graph impact: {int(graph_context.get('two_hop_upstream_count', 0))} "
                "upstream and "
                f"{int(graph_context.get('two_hop_downstream_count', 0))} "
                "downstream files within two hops."
            )
        structural = finding.evidence.get("structural_synthesis")
        if isinstance(structural, dict):
            disposition = structural.get("disposition")
            island = structural.get("island")
            cycle = structural.get("import_cycle")
            change = structural.get("change_impact")
            boundary = structural.get("island_boundary")
            labels = []
            if disposition:
                labels.append(f"dead-code disposition {disposition}")
            if isinstance(island, dict):
                labels.append(
                    f"island classification {island.get('classification', 'review')}"
                )
            if isinstance(cycle, dict):
                labels.append(
                    f"import cycle across {int(cycle.get('file_count', 0))} files"
                )
            if isinstance(change, dict):
                labels.append(
                    "change impact "
                    f"{change.get('classification', 'review')} with risk "
                    f"{int(change.get('risk_score', 0))}"
                )
            if isinstance(boundary, dict):
                labels.append(
                    "island boundary "
                    f"{boundary.get('boundary_classification', 'review')}"
                )
            if labels:
                issue["primaryLocation"]["message"] += (
                    " Structural synthesis: " + "; ".join(labels) + "."
                )
        data_exposure = finding.evidence.get("data_exposure")
        if isinstance(data_exposure, dict):
            issue["primaryLocation"]["message"] += (
                " Sensitive-data path: "
                f"{data_exposure.get('concern', 'review')} to "
                f"{data_exposure.get('sink_family', 'unknown')}"
                + (
                    f" through {data_exposure['sdk']}"
                    if data_exposure.get("sdk")
                    else ""
                )
                + "."
            )
        fusion = finding.evidence.get("fusion")
        if isinstance(fusion, dict):
            issue["primaryLocation"]["message"] += (
                " Evidence fusion: "
                f"{fusion.get('review_tier', 'standard')} review tier, "
                f"{fusion.get('corroboration', 'single-tool')} corroboration."
            )
        if location.start_line:
            issue["primaryLocation"]["textRange"] = {
                "startLine": location.start_line,
                "endLine": location.end_line or location.start_line,
            }
        issues.append(issue)
    return {"issues": issues}


def _highlighted_snippet(location: Location) -> str:
    if location.snippet is None:
        return ""
    snippet_start = location.snippet_start_line or location.start_line or 1
    return "\n".join(
        value
        for offset, value in enumerate(location.snippet.splitlines())
        if _line_is_highlighted(location, snippet_start + offset)
    )


def _first_reference_uri(finding: Finding) -> str | None:
    for citation in finding.citations:
        uri = _reference_uri(citation)
        if uri:
            return uri
    for classification in finding.classifications:
        uri = _classification_uri(classification)
        if uri:
            return uri
    return None
