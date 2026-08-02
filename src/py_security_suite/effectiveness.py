from __future__ import annotations

from collections import Counter
from typing import Any

from .models import Finding, ToolRun, ToolStatus


def effectiveness_artifact(
    findings: list[Finding], tool_runs: list[ToolRun]
) -> dict[str, Any]:
    attributed = [finding for finding in findings if finding.sources]
    complete = [finding for finding in findings if _actionable(finding)]
    by_tool: Counter[str] = Counter()
    unique_by_tool: Counter[str] = Counter()
    for finding in findings:
        tools = {source.tool for source in finding.sources}
        by_tool.update(tools)
        if len(tools) == 1:
            unique_by_tool.update(tools)
    completed = [run for run in tool_runs if run.status is ToolStatus.COMPLETED]
    applicable = [run for run in tool_runs if run.applicable]
    corroborated = sum(
        len({source.tool for source in finding.sources}) > 1 for finding in findings
    )
    total = len(findings)
    return {
        "schema_version": "1.0",
        "scope": (
            "observed scan normalization and tool contribution; precision and "
            "recall require a separately labeled detection corpus"
        ),
        "tool_health": {
            "selected": len(tool_runs),
            "applicable": len(applicable),
            "completed": len(completed),
            "completion_percent": _percent(len(completed), len(applicable)),
        },
        "normalization": {
            "findings": total,
            "attributed": len(attributed),
            "actionable_and_cited": len(complete),
            "attribution_percent": _percent(len(attributed), total),
            "actionability_percent": _percent(len(complete), total),
        },
        "independence": {
            "corroborated_findings": corroborated,
            "single_tool_findings": total - corroborated,
        },
        "tool_contribution": [
            {
                "tool": tool,
                "findings": count,
                "unique_findings": unique_by_tool[tool],
            }
            for tool, count in sorted(
                by_tool.items(), key=lambda item: (-item[1], item[0])
            )
        ],
    }


def assurance_claims_artifact(
    findings: list[Finding], tool_runs: list[ToolRun], *, source_integrity: bool
) -> dict[str, Any]:
    statuses = {run.tool: run.status.value for run in tool_runs}
    active_domains = Counter(finding.domain for finding in findings)
    return {
        "schema_version": "1.0",
        "framework": {
            "name": "NIST Secure Software Development Framework",
            "version": "1.1",
            "reference": "https://csrc.nist.gov/pubs/sp/800/218/final",
        },
        "claims": [
            _claim(
                "PS.1",
                "Protect code from tampering",
                source_integrity,
                ["scan-manifest.json#inventory.source_integrity_verified"],
            ),
            _claim(
                "PW.7",
                "Review and analyze human-readable code",
                _completed(statuses, "bandit", "semgrep", "codeql"),
                ["scan-manifest.json#tools", "results.sarif"],
            ),
            _claim(
                "PW.4",
                "Reuse well-secured software components",
                _completed(statuses, "osv-scanner", "cyclonedx-py"),
                ["sbom.cdx.json", "risk-intelligence.json"],
            ),
            _claim(
                "PS.3",
                "Archive and protect release provenance",
                source_integrity and _completed(statuses, "cosign"),
                ["security-passport.json", "checksums.sha256"],
            ),
            _claim(
                "RV.1",
                "Identify and confirm vulnerabilities continuously",
                not active_domains.get("security")
                and not active_domains.get("supply-chain"),
                ["findings.json", "finding-delta.json"],
            ),
        ],
    }


def _actionable(finding: Finding) -> bool:
    return bool(
        finding.sources
        and finding.classifications
        and finding.citations
        and finding.impact.strip()
        and finding.remediation.strip()
        and finding.locations
    )


def _completed(statuses: dict[str, str], *tools: str) -> bool:
    return any(statuses.get(tool) == ToolStatus.COMPLETED.value for tool in tools)


def _claim(
    identifier: str, title: str, satisfied: bool, evidence: list[str]
) -> dict[str, Any]:
    return {
        "control": identifier,
        "claim": title,
        "result": "satisfied" if satisfied else "not_satisfied",
        "evidence": evidence,
    }


def _percent(numerator: int, denominator: int) -> float:
    return round(numerator * 100.0 / denominator, 2) if denominator else 100.0
