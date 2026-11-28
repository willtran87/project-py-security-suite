"""Sensitive-data route validation hand-off and readiness assessment."""

from __future__ import annotations

from typing import Any

from .risk_path_values import _object, _strings
from .risk_path_common import _MAX_CAMPAIGN_TESTS, _objects


__all__ = [
    "_sensitive_route_validation_handoff",
]


def _sensitive_route_validation_handoff(
    route: dict[str, Any],
    campaigns_by_id: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    campaign_ids = _strings(route.get("validation_campaign_ids"), 50)
    campaigns = [
        campaigns_by_id[campaign_id]
        for campaign_id in campaign_ids
        if campaign_id in campaigns_by_id
    ]
    selected_all = list(
        dict.fromkeys(
            test_file
            for campaign in campaigns
            for test_file in _strings(campaign.get("selected_test_files"), 50)
        )
    )
    selected = selected_all[:_MAX_CAMPAIGN_TESTS]
    execution_by_path: dict[str, dict[str, Any]] = {}
    for campaign in campaigns:
        for execution in _objects(campaign.get("focused_test_execution"), 50):
            path = str(execution.get("path") or "")
            if path and path not in execution_by_path:
                execution_by_path[path] = execution
    executions_all = [execution_by_path[path] for path in sorted(execution_by_path)]
    executions = executions_all[:_MAX_CAMPAIGN_TESTS]
    focused_statuses = sorted(
        {
            str(campaign.get("focused_test_validation_status") or "not-selected")
            for campaign in campaigns
        }
    )
    coverage_statuses = sorted(
        {
            str(campaign.get("coverage_status") or "not-available")
            for campaign in campaigns
        }
    )
    alignments = sorted(
        {
            str(campaign.get("test_coverage_alignment") or "not-selected")
            for campaign in campaigns
        }
    )
    revision_bindings = sorted(
        {
            str(
                _object(campaign.get("source_snapshot")).get(
                    "evidence_revision_binding"
                )
                or "not-established"
            )
            for campaign in campaigns
        }
    )
    campaign_assurance = sorted(
        {
            str(
                _object(campaign.get("route_evidence_assurance")).get("assessment")
                or "not-assessed"
            )
            for campaign in campaigns
        }
    )
    shared_test_quality = sorted(
        {
            str(
                _object(campaign.get("shared_test_evidence_quality")).get("assessment")
                or "not-established"
            )
            for campaign in campaigns
        }
    )
    route_validation_status = str(
        _object(route.get("validation")).get("assessment_status") or "not-assessed"
    )
    execution_complete = bool(campaigns) and all(
        campaign.get("test_execution_evidence_available") is True
        for campaign in campaigns
    )
    case_inventory_complete = (
        all(
            campaign.get("test_case_inventory_complete") is True
            for campaign in campaigns
        )
        if campaigns
        else None
    )
    campaign_assurance_prerequisite_met = bool(campaigns) and all(
        _object(campaign.get("route_evidence_assurance")).get(
            "tool_assurance_prerequisite_met"
        )
        is True
        for campaign in campaigns
    )
    source_revision_aligned = bool(campaigns) and all(
        _object(campaign.get("source_snapshot")).get("evidence_revision_binding")
        == "aligned"
        for campaign in campaigns
    )
    readiness = _sensitive_validation_readiness(
        campaigns=campaigns,
        selected=selected,
        route_validation_status=route_validation_status,
        focused_statuses=focused_statuses,
        alignments=alignments,
        revision_bindings=revision_bindings,
        campaign_assurance_prerequisite_met=campaign_assurance_prerequisite_met,
        execution_complete=execution_complete,
        case_inventory_complete=case_inventory_complete,
    )
    gap_reasons = _sensitive_validation_gap_reasons(
        campaigns=campaigns,
        selected=selected,
        route_validation_status=route_validation_status,
        focused_statuses=focused_statuses,
        coverage_statuses=coverage_statuses,
        alignments=alignments,
        revision_bindings=revision_bindings,
        campaign_assurance_prerequisite_met=campaign_assurance_prerequisite_met,
        execution_complete=execution_complete,
        case_inventory_complete=case_inventory_complete,
    )
    hotspot_ids = sorted(
        {
            *_strings(route.get("validation_test_hotspot_ids"), 100),
            *(
                hotspot_id
                for campaign in campaigns
                for hotspot_id in _strings(campaign.get("shared_test_hotspot_ids"), 100)
            ),
        }
    )[:100]
    test_file_finding_ids = sorted(
        {
            finding_id
            for campaign in campaigns
            for finding_id in _strings(
                _object(campaign.get("shared_test_evidence_quality")).get(
                    "test_file_finding_ids"
                ),
                100,
            )
        }
    )[:100]
    cross_owner_tests = sorted(
        {
            path
            for campaign in campaigns
            for path in _strings(
                _object(campaign.get("shared_test_evidence_quality")).get(
                    "cross_owner_test_files"
                ),
                50,
            )
        }
    )[:50]
    unowned_tests = sorted(
        {
            path
            for campaign in campaigns
            for path in _strings(
                _object(campaign.get("shared_test_evidence_quality")).get(
                    "unowned_test_files"
                ),
                50,
            )
        }
    )[:50]
    evidence_artifacts = sorted(
        {
            "risk-paths.json",
            *(
                artifact
                for campaign in campaigns
                for artifact in _strings(campaign.get("evidence_artifacts"), 25)
            ),
        }
    )
    campaign_records = [
        {
            "campaign_id": str(campaign["campaign_id"]),
            "path": str(campaign["path"]),
            "selected_test_files": _strings(campaign.get("selected_test_files"), 50),
            "focused_test_validation_status": str(
                campaign.get("focused_test_validation_status") or "not-selected"
            ),
            "coverage_status": str(campaign.get("coverage_status") or "not-available"),
            "test_coverage_alignment": str(
                campaign.get("test_coverage_alignment") or "not-selected"
            ),
            "source_revision_binding": str(
                _object(campaign.get("source_snapshot")).get(
                    "evidence_revision_binding"
                )
                or "not-established"
            ),
            "route_assurance_status": str(
                _object(campaign.get("route_evidence_assurance")).get("assessment")
                or "not-assessed"
            ),
            "route_assurance_prerequisite_met": _object(
                campaign.get("route_evidence_assurance")
            ).get("tool_assurance_prerequisite_met")
            is True,
            "shared_test_evidence_quality": str(
                _object(campaign.get("shared_test_evidence_quality")).get("assessment")
                or "not-established"
            ),
            "review_tier": str(campaign.get("review_tier") or "low"),
            "evidence_artifacts": _strings(campaign.get("evidence_artifacts"), 25),
        }
        for campaign in campaigns[:25]
    ]
    return {
        "supporting_evidence_readiness": readiness,
        "canary_assertion_status": "not-established",
        "route_validation_status": route_validation_status,
        "campaign_ids": [str(campaign["campaign_id"]) for campaign in campaigns],
        "campaigns_omitted": max(0, len(campaigns) - 25),
        "campaign_records": campaign_records,
        "test_hotspot_ids": hotspot_ids,
        "candidate_test_files": selected,
        "candidate_test_files_omitted": max(0, len(selected_all) - _MAX_CAMPAIGN_TESTS),
        "test_selection_confidence": _combined_test_selection_confidence(campaigns),
        "focused_test_statuses": focused_statuses,
        "focused_test_execution": executions,
        "focused_test_execution_omitted": max(
            0, len(executions_all) - _MAX_CAMPAIGN_TESTS
        ),
        "test_execution_evidence_complete": execution_complete,
        "test_case_inventory_complete": case_inventory_complete,
        "coverage_statuses": coverage_statuses,
        "coverage_attribution": "not-established",
        "test_coverage_alignments": alignments,
        "source_revision_bindings": revision_bindings,
        "source_revision_aligned": source_revision_aligned,
        "campaign_assurance_statuses": campaign_assurance,
        "campaign_assurance_prerequisite_met": campaign_assurance_prerequisite_met,
        "shared_test_quality_statuses": shared_test_quality,
        "test_file_finding_ids": test_file_finding_ids,
        "cross_owner_test_files": cross_owner_tests,
        "unowned_test_files": unowned_tests,
        "gap_reasons": gap_reasons,
        "evidence_artifacts": evidence_artifacts,
        "recommended_action": _sensitive_validation_action(
            readiness, selected, gap_reasons
        ),
        "interpretation": (
            "Candidate tests and retained execution, coverage, source-binding, and "
            "assurance evidence form a validation handoff only. Aggregate file "
            "coverage is not attributed solely to these tests, and no retained "
            "evidence proves that a synthetic credential canary assertion exists."
        ),
    }


def _combined_test_selection_confidence(campaigns: list[dict[str, Any]]) -> str:
    values = {
        str(campaign.get("test_selection_confidence") or "not-available")
        for campaign in campaigns
    }
    if not values:
        return "not-available"
    if len(values) == 1:
        return next(iter(values))
    return "mixed"


def _sensitive_validation_readiness(
    *,
    campaigns: list[dict[str, Any]],
    selected: list[str],
    route_validation_status: str,
    focused_statuses: list[str],
    alignments: list[str],
    revision_bindings: list[str],
    campaign_assurance_prerequisite_met: bool,
    execution_complete: bool,
    case_inventory_complete: bool | None,
) -> str:
    if not campaigns or not selected:
        return "not-established"
    if (
        route_validation_status == "gap"
        or set(focused_statuses) & {"failed", "incomplete"}
        or set(alignments) & {"tests-failing", "coverage-gap"}
        or "mismatch" in revision_bindings
        or not campaign_assurance_prerequisite_met
    ):
        return "evidence-gap"
    if (
        route_validation_status == "aligned"
        and focused_statuses == ["passed"]
        and alignments == ["aligned-current-evidence"]
        and revision_bindings == ["aligned"]
        and execution_complete
        and case_inventory_complete is True
    ):
        return "supporting-evidence-ready"
    return "partial"


def _sensitive_validation_gap_reasons(
    *,
    campaigns: list[dict[str, Any]],
    selected: list[str],
    route_validation_status: str,
    focused_statuses: list[str],
    coverage_statuses: list[str],
    alignments: list[str],
    revision_bindings: list[str],
    campaign_assurance_prerequisite_met: bool,
    execution_complete: bool,
    case_inventory_complete: bool | None,
) -> list[str]:
    reasons: list[str] = []
    if not campaigns:
        reasons.append("No shared validation campaign is linked to the sink route.")
    if not selected:
        reasons.append("No graph-selected or route-mapped candidate test is retained.")
    if route_validation_status != "aligned":
        reasons.append(
            f"The sink route validation status is {route_validation_status}."
        )
    if focused_statuses and focused_statuses != ["passed"]:
        reasons.append(
            "Focused test status is not uniformly passed: "
            + ", ".join(focused_statuses)
            + "."
        )
    if coverage_statuses and coverage_statuses != ["covered"]:
        reasons.append(
            "Campaign control-point coverage is not uniformly complete: "
            + ", ".join(coverage_statuses)
            + "."
        )
    if alignments and alignments != ["aligned-current-evidence"]:
        reasons.append(
            "Test/coverage alignment is not current and complete: "
            + ", ".join(alignments)
            + "."
        )
    if revision_bindings and revision_bindings != ["aligned"]:
        reasons.append(
            "Campaign source-revision binding is not uniformly aligned: "
            + ", ".join(revision_bindings)
            + "."
        )
    if campaigns and not campaign_assurance_prerequisite_met:
        reasons.append(
            "At least one campaign lacks completed, integrity-verified, approved route evidence."
        )
    if campaigns and not execution_complete:
        reasons.append("Test execution evidence is incomplete for linked campaigns.")
    if campaigns and case_inventory_complete is not True:
        reasons.append("The retained test-case inventory is incomplete or unavailable.")
    reasons.append(
        "A synthetic credential-canary assertion has not been established by retained evidence."
    )
    return reasons[:20]


def _sensitive_validation_action(
    readiness: str,
    selected: list[str],
    gap_reasons: list[str],
) -> str:
    tests = ", ".join(selected[:5]) if selected else "a focused sink-boundary test"
    action = (
        f"Use {tests} as candidate validation scope. Add an explicit synthetic "
        "credential canary and assert minimization, masking, or rejection before the "
        "sink boundary; then regenerate source-bound JUnit and coverage evidence."
    )
    if readiness != "supporting-evidence-ready" and gap_reasons:
        action += " Resolve the retained execution, coverage, revision, and assurance gaps first."
    return action[:2000]
