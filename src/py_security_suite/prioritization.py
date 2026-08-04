from __future__ import annotations


_PRIORITY_RANK = {"P0": 0, "P1": 1, "P2": 2, "P3": 3, "P4": 4}
_SEVERITY_RANK = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "informational": 4,
    "unknown": 5,
}


def finding_priority(
    *, severity: object, classifications: object, evidence: object
) -> str:
    """Return the normalized operational priority for a finding."""
    if isinstance(evidence, dict):
        intelligence = evidence.get("risk_intelligence")
        if isinstance(intelligence, dict) and intelligence.get("known_exploited"):
            return "P0"
    severity_value = str(severity or "unknown")
    if (
        isinstance(classifications, list)
        and "EPSS-HIGH" in classifications
        and severity_value in {"critical", "high", "medium"}
    ):
        return "P1"
    return {
        "critical": "P0",
        "high": "P1",
        "medium": "P2",
        "low": "P3",
        "informational": "P4",
        "unknown": "P4",
    }.get(severity_value, "P4")


def finding_order_key(
    *,
    finding_id: object,
    severity: object,
    classifications: object,
    evidence: object,
    blocking: object,
    status: object,
) -> tuple[int, int, int, int, str]:
    """Order findings by derived priority, then operational urgency."""
    severity_value = str(severity or "unknown")
    priority = finding_priority(
        severity=severity_value,
        classifications=classifications,
        evidence=evidence,
    )
    return (
        _PRIORITY_RANK[priority],
        0 if blocking is True else 1,
        0 if str(status or "unknown") in {"new", "regression"} else 1,
        _SEVERITY_RANK.get(severity_value, 5),
        str(finding_id or ""),
    )
