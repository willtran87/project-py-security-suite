from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .models import Finding, FindingStatus, ToolRun, ToolStatus


@dataclass(frozen=True, slots=True)
class AdmissionAxis:
    key: str
    label: str
    purpose: str
    tools: frozenset[str]


AXES = (
    AdmissionAxis(
        "source",
        "Source and architecture",
        "Python security, secrets, correctness, architecture, and reachability",
        frozenset(
            {
                "bandit",
                "semgrep",
                "ruff",
                "pysa",
                "codeql",
                "iast",
                "devskim",
                "flawfinder",
                "polyglot",
                "detect-secrets",
                "gitleaks",
                "trufflehog",
                "ruff-quality",
                "ruff-format",
                "pylint",
                "mypy",
                "pyright",
                "deptry",
                "radon",
                "tach",
                "graphify",
                "vulture",
                "reachability",
                "git-sizer",
            }
        ),
    ),
    AdmissionAxis(
        "tests",
        "Test assurance",
        "Results, coverage, contracts, properties, fuzzing, and mutation sensitivity",
        frozenset(
            {
                "coverage",
                "junit",
                "diff-cover",
                "hypothesis",
                "schemathesis",
                "crosshair",
                "atheris",
                "clusterfuzzlite",
                "mutmut",
                "browser-security",
                "authorization-security",
                "native-sanitizers",
                "mobsf",
                "fuzz-introspector",
                "restler",
                "protocol-security",
            }
        ),
    ),
    AdmissionAxis(
        "dependencies",
        "Dependencies",
        "Inventory, known vulnerabilities, conflicts, and malicious-package signals",
        frozenset({"osv-scanner", "cyclonedx-py", "grype", "guarddog", "pipdeptree"}),
    ),
    AdmissionAxis(
        "artifacts",
        "Built artifacts",
        "Distribution structure, malware, provenance, signatures, and reproducibility",
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
    AdmissionAxis(
        "governance",
        "Delivery and governance",
        "Isolation, scanner trust, workflows, policy, deployment, and metadata controls",
        frozenset(
            {
                "zizmor",
                "actionlint",
                "scorecard",
                "conftest",
                "reuse",
                "trivy",
                "checkov",
                "kics",
                "kube-linter",
                "kubescape",
                "prowler",
                "cloud-attack-path",
                "hadolint",
                "oci-image",
                "validate-pyproject",
                "vale",
                "psscriptanalyzer",
                "shellcheck",
                "pytm",
                "zap",
                "nuclei",
                "oast",
                "falco",
                "rasp",
                "tls-scan",
                "secret-verification",
            }
        ),
    ),
)


def admission_decisions(
    findings: list[Finding],
    tool_runs: list[ToolRun],
    *,
    network_isolation_attested: bool,
    source_integrity_verified: bool,
) -> dict[str, Any]:
    """Separate admission evidence so one failing axis cannot obscure another."""
    active = [item for item in findings if item.status is not FindingStatus.SUPPRESSED]
    rows = [
        _axis_decision(
            axis,
            active,
            tool_runs,
            network_isolation_attested=network_isolation_attested,
            source_integrity_verified=source_integrity_verified,
        )
        for axis in AXES
    ]
    return {
        "schema_version": "1.0",
        "schema_id": "urn:project-py-security-suite:schema:admission-decisions:1.0",
        "scope": (
            "Evidence decomposition for triage. Axis decisions do not replace the "
            "scan policy result or governed release approval."
        ),
        "counts": {
            state: sum(row["decision"] == state for row in rows)
            for state in ("allow", "block", "incomplete", "not_applicable")
        },
        "axes": rows,
    }


def _axis_decision(
    axis: AdmissionAxis,
    findings: list[Finding],
    runs: list[ToolRun],
    *,
    network_isolation_attested: bool,
    source_integrity_verified: bool,
) -> dict[str, Any]:
    selected = [run for run in runs if run.tool in axis.tools]
    applicable = [run for run in selected if run.applicable]
    completed = [run for run in applicable if run.status is ToolStatus.COMPLETED]
    gaps = sorted(
        run.tool for run in applicable if run.status is not ToolStatus.COMPLETED
    )
    axis_findings = [
        finding
        for finding in findings
        if any(source.tool in axis.tools for source in finding.sources)
    ]
    blockers = [finding for finding in axis_findings if finding.blocking]
    integrity_gaps: list[str] = []
    if axis.key == "governance":
        if not network_isolation_attested:
            integrity_gaps.append("external network-isolation attestation is absent")
        if not source_integrity_verified:
            integrity_gaps.append("target source integrity was not verified unchanged")
        unapproved = sorted(
            run.tool
            for run in runs
            if run.applicable
            and run.executable_sha256
            and not run.executable_organization_approved
        )
        if unapproved:
            integrity_gaps.append(
                f"{len(unapproved)} scanner entry point(s) lack organization approval"
            )
    if blockers:
        decision = "block"
        action = "Resolve or formally govern the blocking findings on this axis."
    elif gaps or integrity_gaps:
        decision = "incomplete"
        action = (
            "Restore the listed execution or integrity evidence and rerun the suite."
        )
    elif not applicable:
        decision = "not_applicable"
        action = "No applicable selected control; review scope when repository content changes."
    else:
        decision = "allow"
        action = "No axis-specific action from this scan."
    return {
        "axis": axis.key,
        "label": axis.label,
        "purpose": axis.purpose,
        "decision": decision,
        "selected_tools": len(selected),
        "applicable_tools": len(applicable),
        "completed_tools": len(completed),
        "execution_gaps": gaps,
        "active_findings": len(axis_findings),
        "blocking_findings": len(blockers),
        "integrity_gaps": integrity_gaps,
        "required_action": action,
    }
