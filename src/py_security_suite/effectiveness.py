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
    findings: list[Finding],
    tool_runs: list[ToolRun],
    *,
    source_integrity: bool,
    context_errors: list[str] | None = None,
    network_isolation_attested: bool = False,
) -> dict[str, Any]:
    statuses = {run.tool: run.status.value for run in tool_runs}
    active_domains = Counter(finding.domain for finding in findings)
    errors = list(context_errors or [])
    intelligence_errors = [
        error
        for error in errors
        if any(
            label in error.casefold()
            for label in ("kev", "epss", "vex", "intelligence")
        )
    ]
    provenance_findings = [
        finding
        for finding in findings
        if finding.area in {"artifact-provenance", "build-provenance"}
        or (finding.domain == "supply-chain" and "provenance" in finding.area)
    ]
    security_findings = active_domains.get("security", 0) + active_domains.get(
        "supply-chain", 0
    )
    return {
        "schema_version": "1.1",
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
                []
                if source_integrity
                else ["target content integrity was not verified"],
            ),
            _claim(
                "PW.7",
                "Review and analyze human-readable code",
                _completed(statuses, "bandit", "semgrep", "codeql"),
                ["scan-manifest.json#tools", "results.sarif"],
                (
                    []
                    if _completed(statuses, "bandit", "semgrep", "codeql")
                    else ["no required human-readable code analysis completed"]
                ),
            ),
            _claim(
                "PW.4",
                "Reuse well-secured software components",
                _completed(statuses, "osv-scanner", "cyclonedx-py")
                and not intelligence_errors,
                ["sbom.cdx.json", "risk-intelligence.json"],
                intelligence_errors
                or (
                    []
                    if _completed(statuses, "osv-scanner", "cyclonedx-py")
                    else [
                        "component inventory or vulnerability analysis did not complete"
                    ]
                ),
            ),
            _claim(
                "PS.3",
                "Archive and protect release provenance",
                source_integrity
                and _completed(statuses, "cosign")
                and not provenance_findings,
                ["security-passport.json", "checksums.sha256"],
                [
                    *(
                        []
                        if source_integrity
                        else ["source integrity was not verified"]
                    ),
                    *(
                        []
                        if _completed(statuses, "cosign")
                        else ["artifact provenance verification did not complete"]
                    ),
                    *[
                        f"active provenance finding: {finding.finding_id}"
                        for finding in provenance_findings
                    ],
                ],
            ),
            _claim(
                "RV.1",
                "Identify and confirm vulnerabilities continuously",
                _completed(statuses, "bandit", "semgrep", "codeql")
                and _completed(statuses, "osv-scanner", "grype", "trivy")
                and not security_findings
                and not errors,
                ["findings.json", "finding-delta.json"],
                [
                    *errors,
                    *(
                        []
                        if security_findings == 0
                        else [
                            f"{security_findings} active security or supply-chain finding(s)"
                        ]
                    ),
                    *(
                        []
                        if _completed(statuses, "bandit", "semgrep", "codeql")
                        else ["static vulnerability identification did not complete"]
                    ),
                    *(
                        []
                        if _completed(statuses, "osv-scanner", "grype", "trivy")
                        else ["component vulnerability confirmation did not complete"]
                    ),
                ],
            ),
            _claim(
                "PO.5",
                "Implement and maintain secure environments for software development",
                network_isolation_attested,
                ["scan-manifest.json#network_isolation_attested"],
                (
                    []
                    if network_isolation_attested
                    else ["an external network-isolation boundary was not attested"]
                ),
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
    identifier: str,
    title: str,
    satisfied: bool,
    evidence: list[str],
    blocking_reasons: list[str],
) -> dict[str, Any]:
    return {
        "control": identifier,
        "claim": title,
        "result": "satisfied" if satisfied else "not_satisfied",
        "evidence": evidence,
        "blocking_reasons": blocking_reasons,
    }


def _percent(numerator: int, denominator: int) -> float:
    return round(numerator * 100.0 / denominator, 2) if denominator else 100.0
