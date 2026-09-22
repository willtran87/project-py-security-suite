"""Optional industry enrichment, separated from evidence finalization."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .models import Finding
from .scan_control import analysis_checkpoint
from .industry_assurance import build_industry_assurance
from .industry_receipt_trust import load_industry_receipt_trust


def industry_assurance_errors(
    target: Path,
    findings: list[Finding],
    derived_artifacts: dict[str, Any],
    profile: str,
) -> list[str]:
    analysis_checkpoint()
    context_errors: list[str] = []
    receipt_trust_policy, receipt_trust_errors = load_industry_receipt_trust(target)
    analysis_checkpoint()
    industry_artifacts, industry_errors = build_industry_assurance(
        target,
        derived_artifacts,
        findings,
        receipt_trust_policy=receipt_trust_policy,
    )
    industry_errors = [*receipt_trust_errors, *industry_errors]
    derived_artifacts.update(industry_artifacts)
    control_assessment = industry_artifacts["control-assessment.json"]
    benchmark_scorecard = industry_artifacts["benchmark-scorecard.json"]
    if profile in {"production", "release"} and industry_errors:
        context_errors.extend(
            f"industry assurance: {error}" for error in industry_errors
        )
    if (
        profile in {"production", "release"}
        and control_assessment["enforced"] is True
        and control_assessment["complete"] is not True
    ):
        context_errors.append(
            "enforced industry control assessment contains unsatisfied controls"
        )
    if (
        profile in {"production", "release"}
        and benchmark_scorecard["benchmarks_enabled"]
        and (
            benchmark_scorecard["complete"] is not True
            or benchmark_scorecard["passed"] is not True
        )
    ):
        context_errors.append(
            "enabled industry benchmarks lack valid passing governed evidence"
        )
    return context_errors
