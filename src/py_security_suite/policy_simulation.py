from __future__ import annotations


from .strict_json import loads as strict_json_loads
from collections import Counter
from pathlib import Path
from typing import Any

from .passport import verify_report
from .path_safety import resolve_regular_file

_MAX_JSON_BYTES = 128 * 1024 * 1024
_SEVERITIES = {"critical", "high", "medium", "low", "info", "unknown"}
_CONFIDENCE = {"unknown": 0, "low": 1, "medium": 2, "high": 3}


def simulate_policy(
    report: Path,
    *,
    block_severities: tuple[str, ...] = ("critical", "high"),
    required_tools: tuple[str, ...] = (),
    minimum_confidence: str = "unknown",
    maximum_blocking_findings: int = 0,
) -> dict[str, Any]:
    """Evaluate a hypothetical policy against sealed evidence without changing it."""
    severities, tools_required, confidence = _validated_policy(
        block_severities,
        required_tools,
        minimum_confidence,
        maximum_blocking_findings,
    )
    verification = verify_report(report)
    findings, tools = _report_evidence(report)
    active = [value for value in findings if value.get("status") != "suppressed"]
    severity_blockers = _severity_blockers(active, severities)
    low_confidence = _low_confidence(active, confidence)
    tool_gaps = _tool_gaps(tools, tools_required)
    reasons = _reasons(
        severity_blockers,
        low_confidence,
        tool_gaps,
        confidence=confidence,
        maximum_blocking_findings=maximum_blocking_findings,
    )
    disposition = "block" if reasons else "allow"
    return {
        "schema_version": "1.0",
        "authoritative": False,
        "scope": "Deterministic what-if policy evaluation over a verified report; it does not alter evidence or grant admission.",
        "report": {
            "scan_id": verification["scan_id"],
            "checksums_sha256": verification["checksums_sha256"],
            "actual_outcome": verification["outcome"],
        },
        "policy": {
            "block_severities": sorted(severities),
            "required_tools": sorted(tools_required),
            "minimum_confidence": confidence,
            "maximum_blocking_findings": maximum_blocking_findings,
        },
        "result": {
            "disposition": disposition,
            "reasons": reasons,
            "differs_from_actual": disposition
            != _actual_disposition(verification["outcome"]),
        },
        "metrics": {
            "active_findings": len(active),
            "matching_blocking_findings": len(severity_blockers),
            "below_confidence_floor": len(low_confidence),
            "required_tool_gaps": len(tool_gaps),
            "active_by_severity": dict(
                sorted(
                    Counter(
                        str(value.get("severity") or "unknown").casefold()
                        for value in active
                    ).items()
                )
            ),
        },
    }


def _validated_policy(
    block_severities: tuple[str, ...],
    required_tools: tuple[str, ...],
    minimum_confidence: str,
    maximum_blocking_findings: int,
) -> tuple[tuple[str, ...], tuple[str, ...], str]:
    if maximum_blocking_findings < 0:
        raise ValueError("maximum blocking findings cannot be negative")
    severities = tuple(value.casefold() for value in block_severities)
    if (
        not severities
        or len(set(severities)) != len(severities)
        or any(value not in _SEVERITIES for value in severities)
    ):
        raise ValueError("block severities must be unique supported severity names")
    tools = tuple(value.strip() for value in required_tools)
    if "" in tools or len(set(tools)) != len(tools):
        raise ValueError("required tools must be non-empty and unique")
    confidence = minimum_confidence.casefold()
    if confidence not in _CONFIDENCE:
        raise ValueError("minimum confidence must be unknown, low, medium, or high")
    return severities, tools, confidence


def _report_evidence(report: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    root = report.expanduser().resolve()
    findings = _read(root / "findings.json")
    manifest = _read(root / "scan-manifest.json")
    return (
        _objects(findings.get("findings"), "findings"),
        _objects(manifest.get("tools"), "tools"),
    )


def _severity_blockers(
    active: list[dict[str, Any]], severities: tuple[str, ...]
) -> list[dict[str, Any]]:
    return [
        value
        for value in active
        if str(value.get("severity") or "unknown").casefold() in severities
    ]


def _low_confidence(
    active: list[dict[str, Any]], confidence: str
) -> list[dict[str, Any]]:
    return [
        value
        for value in active
        if _CONFIDENCE.get(str(value.get("confidence") or "unknown").casefold(), 0)
        < _CONFIDENCE[confidence]
    ]


def _tool_gaps(tools: list[dict[str, Any]], required: tuple[str, ...]) -> list[str]:
    by_name = {str(value.get("tool") or ""): value for value in tools}
    return [
        name
        for name in required
        if name not in by_name
        or by_name[name].get("applicable") is False
        or by_name[name].get("status") != "completed"
    ]


def _reasons(
    severity_blockers: list[dict[str, Any]],
    low_confidence: list[dict[str, Any]],
    tool_gaps: list[str],
    *,
    confidence: str,
    maximum_blocking_findings: int,
) -> list[dict[str, Any]]:
    values: list[dict[str, Any]] = []
    if len(severity_blockers) > maximum_blocking_findings:
        values.append(
            {
                "id": "finding-threshold",
                "message": f"{len(severity_blockers)} active findings match blocking severities; maximum is {maximum_blocking_findings}",
                "finding_ids": sorted(
                    _finding_id(value) for value in severity_blockers
                ),
            }
        )
    if low_confidence:
        values.append(
            {
                "id": "evidence-confidence",
                "message": f"{len(low_confidence)} active findings are below the {confidence} confidence floor",
                "finding_ids": sorted(_finding_id(value) for value in low_confidence),
            }
        )
    if tool_gaps:
        values.append(
            {
                "id": "required-tools",
                "message": "required scanners did not complete: "
                + ", ".join(sorted(tool_gaps)),
                "tools": sorted(tool_gaps),
            }
        )
    return values


def _actual_disposition(outcome: str) -> str:
    return "allow" if outcome == "pass" else "review" if outcome == "warn" else "block"


def _finding_id(value: dict[str, Any]) -> str:
    return str(value.get("finding_id") or value.get("id") or "unknown")


def _read(path: Path) -> dict[str, Any]:
    source = resolve_regular_file(path, "policy simulation input")
    if source.stat().st_size > _MAX_JSON_BYTES:
        raise ValueError("policy simulation input exceeds 128 MiB")
    value = strict_json_loads(source.read_bytes())
    if not isinstance(value, dict):
        raise TypeError("policy simulation input root must be an object")
    return value


def _objects(value: object, label: str) -> list[dict[str, Any]]:
    if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
        raise TypeError(f"{label} must be an array of objects")
    return value
