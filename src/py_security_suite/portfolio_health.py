from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .models import Finding, ToolRun, ToolStatus


@dataclass(slots=True, frozen=True)
class CoverageDomain:
    name: str
    purpose: str
    tools: frozenset[str]


DOMAINS = (
    CoverageDomain(
        "python-source-security",
        "Security patterns, semantic analysis, and source-to-sink data flow",
        frozenset(
            {"bandit", "semgrep", "ruff", "pysa", "codeql", "devskim", "flawfinder"}
        ),
    ),
    CoverageDomain(
        "secrets",
        "Working-tree, archive, and history credential detection",
        frozenset({"detect-secrets", "gitleaks", "trufflehog"}),
    ),
    CoverageDomain(
        "dependencies",
        "Dependency inventory, vulnerabilities, conflicts, and malicious-package signals",
        frozenset({"osv-scanner", "cyclonedx-py", "grype", "guarddog", "pipdeptree"}),
    ),
    CoverageDomain(
        "release-supply-chain",
        "Artifact inventory, structure, malware, provenance, signatures, and reproducibility",
        frozenset(
            {
                "syft",
                "grype",
                "check-wheel-contents",
                "twine",
                "pypi-attestations",
                "cosign",
                "in-toto",
                "reproducible-build",
                "check-manifest",
                "clamav",
                "github-attestation",
                "yara",
            }
        ),
    ),
    CoverageDomain(
        "iac-containers",
        "Infrastructure, container, Kubernetes, and deployment hardening",
        frozenset({"trivy", "checkov", "kics", "kube-linter", "hadolint", "oci-image"}),
    ),
    CoverageDomain(
        "delivery-governance",
        "Workflow integrity, policy as code, licensing, and repository governance",
        frozenset({"zizmor", "actionlint", "scorecard", "conftest", "reuse"}),
    ),
    CoverageDomain(
        "python-quality",
        "Correctness, formatting, type contracts, dependency hygiene, and complexity",
        frozenset(
            {
                "ruff-quality",
                "ruff-format",
                "pylint",
                "mypy",
                "pyright",
                "deptry",
                "radon",
            }
        ),
    ),
    CoverageDomain(
        "architecture-reachability",
        "Boundaries, cycles, repository scale, unused code, and entry-point reachability",
        frozenset({"tach", "vulture", "reachability", "git-sizer"}),
    ),
    CoverageDomain(
        "test-assurance",
        "Test results, coverage, contracts, properties, fuzzing, and mutation sensitivity",
        frozenset(
            {
                "coverage",
                "junit",
                "diff-cover",
                "hypothesis",
                "schemathesis",
                "crosshair",
                "atheris",
                "mutmut",
            }
        ),
    ),
    CoverageDomain(
        "dynamic-threat-modeling",
        "Runtime web testing and reviewed threat-model evidence",
        frozenset({"zap", "pytm"}),
    ),
    CoverageDomain(
        "metadata-documentation",
        "Package metadata, distribution completeness, and documentation quality",
        frozenset({"validate-pyproject", "check-manifest", "vale"}),
    ),
    CoverageDomain(
        "automation-scripts",
        "PowerShell and shell correctness, safety, and portability",
        frozenset({"psscriptanalyzer", "shellcheck"}),
    ),
)


def portfolio_health_artifact(
    findings: list[Finding], tool_runs: list[ToolRun]
) -> dict[str, Any]:
    rows = [_domain_health(domain, findings, tool_runs) for domain in DOMAINS]
    applicable = sum(int(row["applicable_tools"]) for row in rows)
    completed = sum(int(row["completed_tools"]) for row in rows)
    return {
        "schema_version": "1.0",
        "scope": (
            "Operational coverage of selected controls. Grades measure applicable "
            "scanner completion, not absence of vulnerabilities or product certification."
        ),
        "overall": {
            "grade": _grade(completed, applicable),
            "applicable_control_slots": applicable,
            "completed_control_slots": completed,
            "completion_percent": _percent(completed, applicable),
            "domains_with_execution_gaps": sum(
                bool(row["execution_gaps"]) for row in rows
            ),
            "domains_not_selected": sum(
                row["status"] == "not_selected" for row in rows
            ),
        },
        "domains": rows,
    }


def _domain_health(
    domain: CoverageDomain, findings: list[Finding], tool_runs: list[ToolRun]
) -> dict[str, Any]:
    selected = [run for run in tool_runs if run.tool in domain.tools]
    applicable = [run for run in selected if run.applicable]
    completed = [run for run in applicable if run.status is ToolStatus.COMPLETED]
    gaps = sorted(
        run.tool for run in applicable if run.status is not ToolStatus.COMPLETED
    )
    domain_findings = [
        finding
        for finding in findings
        if any(source.tool in domain.tools for source in finding.sources)
    ]
    status = (
        "not_selected"
        if not selected
        else "conditional_only"
        if not applicable
        else "gap"
        if gaps
        else "complete"
    )
    return {
        "domain": domain.name,
        "purpose": domain.purpose,
        "status": status,
        "grade": _grade(len(completed), len(applicable)),
        "selected_tools": len(selected),
        "applicable_tools": len(applicable),
        "completed_tools": len(completed),
        "completion_percent": _percent(len(completed), len(applicable)),
        "execution_gaps": gaps,
        "active_findings": len(domain_findings),
        "blocking_findings": sum(finding.blocking for finding in domain_findings),
    }


def _grade(completed: int, applicable: int) -> str:
    if not applicable:
        return "N/A"
    percent = completed * 100.0 / applicable
    if percent >= 90:
        return "A"
    if percent >= 75:
        return "B"
    if percent >= 50:
        return "C"
    if percent > 0:
        return "D"
    return "F"


def _percent(numerator: int, denominator: int) -> float | None:
    return round(numerator * 100.0 / denominator, 2) if denominator else None
