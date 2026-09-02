"""Coordinated, source-only assurance stages for one sealed project snapshot."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .application_contracts import analyze_application_contracts
from .architecture_history import architecture_history
from .code_health import analyze_code_health
from .framework_coverage import framework_model_coverage
from .models import Finding, ToolRun
from .static_architecture import analyze_static_architecture


STRUCTURAL_QUALITY_PROFILES = frozenset(
    {
        "standard",
        "audit",
        "quality",
        "repo",
        "comprehensive",
        "production",
        "release",
    }
)
_RELEASE_PROFILES = frozenset({"production", "release"})


def apply_source_assurance(
    *,
    target: Path,
    profile: str,
    findings: list[Finding],
    tool_runs: list[ToolRun],
    artifacts: dict[str, Any],
) -> list[str]:
    """Populate missing source-analysis artifacts and return release gate errors."""

    errors: list[str] = []
    if "framework-model-coverage.json" not in artifacts:
        framework_findings, coverage = framework_model_coverage(
            target, tool_runs, findings
        )
        qualified_canary_ids = set(coverage["qualified_canary_finding_ids"])
        findings[:] = [
            finding
            for finding in findings
            if finding.finding_id not in qualified_canary_ids
        ]
        findings.extend(framework_findings)
        artifacts["framework-model-coverage.json"] = coverage
        if (
            profile in _RELEASE_PROFILES
            and not coverage["complete"]
            and (coverage["frameworks_detected"] or coverage["parse_errors"])
        ):
            errors.append(
                "detected Python frameworks lack digest-bound semantic models, "
                "positive/negative canaries, or a completed model engine"
            )

    if "application-contract-analysis.json" not in artifacts:
        contract_findings, contract = analyze_application_contracts(target, artifacts)
        findings.extend(contract_findings)
        artifacts["application-contract-analysis.json"] = contract
        if (
            profile in _RELEASE_PROFILES
            and not contract["complete"]
            and (contract["contract_present"] or contract["openapi"]["current_path"])
        ):
            errors.append(
                "application contracts contain API drift, missing authorization test "
                "evidence, vulnerable-function calls, or analysis errors"
            )

    if profile not in STRUCTURAL_QUALITY_PROFILES:
        return errors
    if "code-health.json" not in artifacts:
        code_findings, code_health = analyze_code_health(target)
        findings.extend(code_findings)
        artifacts["code-health.json"] = code_health
    if "static-architecture.json" not in artifacts:
        architecture_findings, static_architecture = analyze_static_architecture(
            target, artifacts.get("reachability.json")
        )
        findings.extend(architecture_findings)
        artifacts["static-architecture.json"] = static_architecture
    if "architecture-history.json" not in artifacts:
        history_findings, history = architecture_history(target, findings)
        findings.extend(history_findings)
        artifacts["architecture-history.json"] = history
    return errors
