from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .models import Finding, FindingStatus, Outcome, Severity, ToolRun, ToolStatus
from .readiness_guidance import activation_guidance


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
        "Boundaries, cycles, repository scale, unused code, entry-point reachability, and code-graph impact",
        frozenset({"tach", "vulture", "reachability", "graphify", "git-sizer"}),
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
    findings: list[Finding],
    tool_runs: list[ToolRun],
    *,
    outcome: Outcome | None = None,
    policy_reasons: tuple[str, ...] | list[str] = (),
) -> dict[str, Any]:
    active_findings = [
        finding
        for finding in findings
        if finding.status is not FindingStatus.SUPPRESSED
    ]
    rows = [_domain_health(domain, active_findings, tool_runs) for domain in DOMAINS]
    applicable = sum(int(row["applicable_tools"]) for row in rows)
    completed = sum(int(row["completed_tools"]) for row in rows)
    execution_grade = _execution_grade(completed, applicable)
    risk_grade, risk_status, highest = _risk_grade(active_findings)
    evidence_grade, evidence_status, evidence_gaps = _evidence_grade(
        tool_runs,
        outcome=outcome,
        policy_reasons=policy_reasons,
    )
    recipes = [
        activation_recipe(run)
        for run in sorted(tool_runs, key=lambda item: item.tool)
        if not run.applicable
    ]
    return {
        "schema_version": "1.1",
        "scope": (
            "Distinct execution, observed-risk, and evidence grades for selected "
            "controls. None of these grades constitutes product certification or "
            "independent release approval."
        ),
        "overall": {
            "execution_grade": execution_grade,
            "risk_grade": risk_grade,
            "risk_status": risk_status,
            "evidence_grade": evidence_grade,
            "evidence_status": evidence_status,
            "release_decision": _release_decision(outcome),
            "highest_active_severity": highest,
            "active_findings": len(active_findings),
            "blocking_findings": sum(finding.blocking for finding in active_findings),
            "applicable_control_slots": applicable,
            "completed_control_slots": completed,
            "completion_percent": _percent(completed, applicable),
            "domains_with_execution_gaps": sum(
                bool(row["execution_gaps"]) for row in rows
            ),
            "domains_not_selected": sum(
                row["status"] == "not_selected" for row in rows
            ),
            "policy_gap_count": len(policy_reasons),
            "evidence_gaps": evidence_gaps,
        },
        "domains": rows,
        "activation_recipes": recipes,
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
        "execution_grade": _execution_grade(len(completed), len(applicable)),
        "risk_grade": _risk_grade(domain_findings)[0],
        "selected_tools": len(selected),
        "applicable_tools": len(applicable),
        "completed_tools": len(completed),
        "completion_percent": _percent(len(completed), len(applicable)),
        "execution_gaps": gaps,
        "active_findings": len(domain_findings),
        "blocking_findings": sum(finding.blocking for finding in domain_findings),
    }


def _execution_grade(completed: int, applicable: int) -> str:
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


def _risk_grade(findings: list[Finding]) -> tuple[str, str, str | None]:
    severities = {finding.severity for finding in findings}
    if Severity.CRITICAL in severities:
        return "F", "critical", Severity.CRITICAL.value
    if Severity.HIGH in severities:
        return "D", "high", Severity.HIGH.value
    if Severity.MEDIUM in severities or Severity.UNKNOWN in severities:
        highest = (
            Severity.MEDIUM.value
            if Severity.MEDIUM in severities
            else Severity.UNKNOWN.value
        )
        return "C", "moderate", highest
    if Severity.LOW in severities:
        return "B", "low", Severity.LOW.value
    if Severity.INFORMATIONAL in severities:
        return "A", "minimal", Severity.INFORMATIONAL.value
    return "A", "none_observed", None


def _evidence_grade(
    tool_runs: list[ToolRun],
    *,
    outcome: Outcome | None,
    policy_reasons: tuple[str, ...] | list[str],
) -> tuple[str, str, list[str]]:
    applicable_gaps = sorted(
        run.tool
        for run in tool_runs
        if run.applicable and run.status is not ToolStatus.COMPLETED
    )
    changed = sorted(
        run.tool
        for run in tool_runs
        if run.applicable
        and (
            run.executable_unchanged is False
            or run.auxiliary_executable_unchanged is False
        )
    )
    approval_gaps = sorted(
        run.tool
        for run in tool_runs
        if run.applicable
        and run.status is ToolStatus.COMPLETED
        and run.executable_sha256 is not None
        and not run.executable_organization_approved
    )
    gaps = [str(reason) for reason in policy_reasons]
    if applicable_gaps:
        gaps.append("applicable scanner gaps: " + ", ".join(applicable_gaps))
    if changed:
        gaps.append("scanner entry points changed: " + ", ".join(changed))
    if approval_gaps:
        gaps.append(
            f"{len(approval_gaps)} completed scanner entry point(s) lack "
            "organization approval"
        )
    if outcome is Outcome.INCOMPLETE or applicable_gaps or changed:
        return "F", "incomplete", _bounded_gaps(gaps)
    if approval_gaps:
        return "C", "observed_not_approved", _bounded_gaps(gaps)
    if outcome is None:
        return "N/A", "not_evaluated", _bounded_gaps(gaps)
    return "A", "complete_for_scan_scope", _bounded_gaps(gaps)


def _release_decision(outcome: Outcome | None) -> str:
    if outcome in {Outcome.FAIL, Outcome.INCOMPLETE}:
        return "blocked"
    if outcome is Outcome.WARN:
        return "review_required"
    if outcome is Outcome.PASS:
        return "eligible_for_external_approval"
    return "not_evaluated"


def _bounded_gaps(gaps: list[str]) -> list[str]:
    """Keep strict evidence artifacts bounded without hiding the source count."""
    unique: list[str] = []
    seen: set[str] = set()
    for gap in gaps:
        value = gap.strip()[:16_000]
        if value and value not in seen:
            unique.append(value)
            seen.add(value)
        if len(unique) == 256:
            break
    return unique


def activation_recipe(run: ToolRun) -> dict[str, str]:
    """Return deterministic ownership and evidence guidance for an N/A control."""
    reason = run.error or "No applicability diagnostic was supplied."
    guidance = activation_guidance(run.tool, reason)
    return {
        "tool": run.tool,
        "category": guidance.category,
        "owner": guidance.owner,
        "reason": reason,
        "activation_trigger": guidance.activation_trigger,
        "required_action": guidance.required_action,
        "evidence_required": guidance.evidence_required,
    }


def _percent(numerator: int, denominator: int) -> float | None:
    return round(numerator * 100.0 / denominator, 2) if denominator else None
