"""Per-target evidence assurance and finding correlation context."""

from __future__ import annotations

from typing import Any

from .risk_path_values import _object, _strings, _nonnegative_integer
from .models import Finding
from .risk_path_common import (
    _MAX_SENSITIVE_ROUTE_CITATIONS,
    _citation_records,
    _optional_boolean,
    _optional_string,
)


__all__ = [
    "_empty_evidence_assurance",
    "_finding_correlations",
    "_finding_evidence_artifacts",
    "_target_evidence_assurance",
    "_tool_posture_index",
]


_TOOL_RUN_STATUSES = frozenset(
    {"completed", "unavailable", "failed", "timed_out", "parse_error", "skipped"}
)


_TOOL_ASSURANCE_STATUSES = frozenset(
    {
        "approved",
        "approval-gap",
        "integrity-gap",
        "not-established",
        "execution-gap",
        "not-applicable",
    }
)


def _tool_posture_index(value: Any) -> dict[str, dict[str, Any]]:
    raw = value.get("tool_posture") if isinstance(value, dict) else None
    records = raw if isinstance(raw, list) else []
    result: dict[str, dict[str, Any]] = {}
    for item in records[:500]:
        if not isinstance(item, dict):
            continue
        tool = _optional_string(item.get("tool"))
        status = _optional_string(item.get("status"))
        assurance = _optional_string(item.get("assurance_status"))
        if (
            not tool
            or status not in _TOOL_RUN_STATUSES
            or assurance not in _TOOL_ASSURANCE_STATUSES
        ):
            continue
        result[tool] = {
            "tool": tool,
            "status": status,
            "applicable": item.get("applicable") is True,
            "evidence_lane": str(item.get("evidence_lane") or "other")[:100],
            "normalized_findings": _nonnegative_integer(item.get("normalized_findings"))
            or 0,
            "unique_normalized_findings": _nonnegative_integer(
                item.get("unique_normalized_findings")
            )
            or 0,
            "executable_integrity_verified": _optional_boolean(
                item.get("executable_integrity_verified")
            ),
            "executable_organization_approved": (
                item.get("executable_organization_approved") is True
            ),
            "executable_unchanged": _optional_boolean(item.get("executable_unchanged")),
            "auxiliary_executable_present": (
                item.get("auxiliary_executable_present") is True
            ),
            "auxiliary_executable_integrity_verified": _optional_boolean(
                item.get("auxiliary_executable_integrity_verified")
            ),
            "auxiliary_executable_organization_approved": _optional_boolean(
                item.get("auxiliary_executable_organization_approved")
            ),
            "auxiliary_executable_unchanged": _optional_boolean(
                item.get("auxiliary_executable_unchanged")
            ),
            "assurance_status": assurance,
        }
    return result


def _target_evidence_assurance(
    target: dict[str, Any], posture: dict[str, dict[str, Any]]
) -> dict[str, Any]:
    origin = {
        "finding": "scanner-finding",
        "dependency-advisory-import": "dependency-advisory-fusion",
        "sink-surface": "derived-analysis",
    }.get(str(target.get("kind")), "derived-analysis")
    contributing = sorted(set(_strings(target.get("tools"), 25)))
    correlations = _object(target.get("correlations"))
    supporting = sorted(
        set(_strings(correlations.get("related_tools"), 25)) - set(contributing)
    )
    external_contributors = [
        tool for tool in contributing if not tool.startswith("pysec-")
    ]
    assessed_tools = (
        sorted(set(supporting)) if origin == "derived-analysis" else contributing
    )
    records = [posture[tool] for tool in assessed_tools if tool in posture]
    unassessed = sorted(set(assessed_tools) - set(posture))
    completed = sorted(
        str(record["tool"]) for record in records if record["status"] == "completed"
    )
    approved = sorted(
        str(record["tool"])
        for record in records
        if record["assurance_status"] == "approved"
    )
    execution_gaps = sorted(
        str(record["tool"])
        for record in records
        if record["assurance_status"] in {"execution-gap", "not-applicable"}
    )
    trust_gaps = sorted(
        str(record["tool"])
        for record in records
        if record["assurance_status"]
        in {"approval-gap", "integrity-gap", "not-established"}
    )
    corroboration = _optional_string(correlations.get("corroboration"))
    perspective = _perspective_assessment(origin, external_contributors, corroboration)
    review_status = _evidence_review_status(
        origin=origin,
        perspective=perspective,
        assessed_tools=assessed_tools,
        unassessed=unassessed,
        execution_gaps=execution_gaps,
        trust_gaps=trust_gaps,
    )
    return {
        "review_status": review_status,
        "origin": origin,
        "perspective_assessment": perspective,
        "corroboration": corroboration,
        "contributing_tools": contributing,
        "supporting_tools": supporting,
        "evidence_lanes": sorted({str(record["evidence_lane"]) for record in records}),
        "tool_records": records,
        "completed_tools": completed,
        "approved_tools": approved,
        "trust_gap_tools": trust_gaps,
        "execution_gap_tools": execution_gaps,
        "unassessed_tools": unassessed,
        "recommended_action": _evidence_assurance_action(
            review_status, trust_gaps, execution_gaps, unassessed
        ),
        "evidence_artifacts": (
            ["effectiveness.json", "scanner-trust.json"] if records else []
        ),
    }


def _perspective_assessment(
    origin: str, contributing_tools: list[str], corroboration: str | None
) -> str:
    if corroboration in {"independent", "cross-stage"}:
        return "independent-corroboration"
    if len(contributing_tools) > 1:
        return "multi-tool"
    if len(contributing_tools) == 1:
        return "single-tool"
    if origin == "derived-analysis":
        return "derived-analysis"
    return "not-established"


def _evidence_review_status(
    *,
    origin: str,
    perspective: str,
    assessed_tools: list[str],
    unassessed: list[str],
    execution_gaps: list[str],
    trust_gaps: list[str],
) -> str:
    if unassessed or (origin != "derived-analysis" and not assessed_tools):
        return "not-assessed"
    if execution_gaps:
        return "execution-gap"
    if trust_gaps:
        return "trust-gap"
    if origin == "derived-analysis":
        return "derived-analysis"
    if perspective in {"single-tool", "not-established"}:
        return "perspective-gap"
    return "assured"


def _evidence_assurance_action(
    status: str,
    trust_gaps: list[str],
    execution_gaps: list[str],
    unassessed: list[str],
) -> str:
    if status == "execution-gap":
        return (
            "Complete the contributing scanner run(s) and retain normalized evidence: "
            + ", ".join(execution_gaps[:10])
            + "."
        )
    if status == "trust-gap":
        return (
            "Verify executable integrity and obtain organization approval for the "
            "contributing scanner binding(s): " + ", ".join(trust_gaps[:10]) + "."
        )
    if status == "not-assessed":
        return (
            "Retain completion and scanner-identity evidence for the contributing "
            "tool(s): " + ", ".join(unassessed[:10] or ["unknown"]) + "."
        )
    if status == "perspective-gap":
        return (
            "Validate the target with an independent applicable technique or record "
            "why the single retained scanner perspective is sufficient."
        )
    if status == "derived-analysis":
        return (
            "Review the suite-derived correlation against its cited source evidence; "
            "do not treat derived analysis as an independent scanner observation."
        )
    return "Preserve the approved multi-perspective evidence and rerun it after remediation."


def _empty_evidence_assurance(target: dict[str, Any]) -> dict[str, Any]:
    return _target_evidence_assurance(target, {})


def _finding_correlations(
    finding: Finding,
    fusion: dict[str, Any],
    structural: dict[str, Any],
    exposure: dict[str, Any],
) -> dict[str, Any]:
    island = _object(structural.get("island"))
    cycle = _object(structural.get("import_cycle"))
    advisory = _object(fusion.get("advisory_context"))
    result: dict[str, Any] = {
        "related_finding_ids": _strings(fusion.get("related_finding_ids"), 50),
        "related_tools": _strings(fusion.get("related_tools"), 25),
        "review_tier": _optional_string(fusion.get("review_tier")),
        "review_reasons": _strings(fusion.get("review_reasons"), 20),
        "corroboration": _optional_string(fusion.get("corroboration")),
        "island_id": _optional_string(island.get("island_id")),
        "import_cycle_id": _optional_string(cycle.get("cycle_id")),
        "advisory_cluster_id": _optional_string(advisory.get("cluster_id")),
        "known_exploited": bool(
            _object(finding.evidence.get("risk_intelligence")).get("known_exploited")
        ),
    }
    if exposure:
        result["sensitive_data_context"] = {
            "concern": str(exposure.get("concern") or "sensitive-data-exposure")[:200],
            "sink_family": str(exposure.get("sink_family") or "unknown")[:100],
            "sink": _optional_string(exposure.get("sink")),
            "sdk": _optional_string(exposure.get("sdk")),
            "confidence": _optional_string(exposure.get("confidence")),
            "data_classes": _strings(exposure.get("data_classes"), 25),
            "trust_boundary": str(exposure.get("trust_boundary") or "unknown")[:100],
            "protection_status": str(exposure.get("protection_status") or "unknown")[
                :100
            ],
            "risk_factors": _strings(exposure.get("risk_factors"), 25),
            "review_priority": _optional_string(exposure.get("review_priority")),
            "citations": _citation_records(
                finding.citations,
                limit=_MAX_SENSITIVE_ROUTE_CITATIONS,
                default_kind="reference",
            ),
        }
    return result


def _finding_evidence_artifacts(
    finding: Finding,
    fusion: dict[str, Any],
    structural: dict[str, Any],
    exposure: dict[str, Any],
) -> list[str]:
    names = {"findings.json"}
    if fusion:
        names.add("evidence-fusion.json")
    if structural:
        names.add("structural-synthesis.json")
    if exposure:
        names.add("data-exposure.json")
    graph = finding.evidence.get("graph_context")
    if isinstance(graph, dict):
        names.add("graph-analysis.json")
    return sorted(names)
