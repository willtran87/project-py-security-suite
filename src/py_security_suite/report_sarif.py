"""SARIF 2.1.0 rendering helpers for code-scanning platforms."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import quote

from .models import Finding, FindingStatus, Severity


SARIF_FINGERPRINT_KEY = "pysecFingerprint/v1"
"""Suite-owned ``partialFingerprints`` key.

``primaryLocationLineHash`` is reserved for GitHub's own line-content hash;
publishing the suite fingerprint under it would make GitHub compare unrelated
hash schemes. A versioned custom key keeps alert identity stable and lets
code scanning compute its own line hash alongside it.
"""


def _sarif_code_flow_summary(value: list[Any]) -> list[dict[str, Any]]:
    allowed_semantics = {
        "native-source-sink-kinds",
        "security-path-problem",
        "unclassified-code-flow",
    }
    summaries: list[dict[str, Any]] = []
    for flow_index, flow in enumerate(value[:10]):
        if not isinstance(flow, dict):
            continue
        raw_semantic_basis = flow.get("semantic_basis")
        semantic_basis = (
            raw_semantic_basis
            if isinstance(raw_semantic_basis, str)
            and raw_semantic_basis in allowed_semantics
            else "unclassified-code-flow"
        )
        raw_counts = flow.get("thread_flow_location_resolution_counts")
        counts: dict[object, object] = (
            raw_counts if isinstance(raw_counts, dict) else {}
        )
        count_items: list[tuple[str, object]] = [
            (key, count) for key, count in counts.items() if isinstance(key, str)
        ]
        bounded_counts = sorted(
            count_items,
            key=lambda item: item[0],
        )[:20]
        summaries.append(
            {
                "flow_index": flow_index,
                "code_flow_index": _sarif_summary_count(flow.get("code_flow_index")),
                "code_flow_thread_count": _sarif_summary_count(
                    flow.get("code_flow_thread_count")
                ),
                "represented_thread_count": _sarif_summary_count(
                    flow.get("represented_thread_count")
                ),
                "thread_flows_omitted": _sarif_summary_count(
                    flow.get("thread_flows_omitted")
                ),
                "cross_thread_combined": flow.get("cross_thread_combined") is True,
                "execution_order_complete": (
                    flow.get("execution_order_complete") is True
                ),
                "invalid_execution_order_count": _sarif_summary_count(
                    flow.get("invalid_execution_order_count")
                ),
                "duplicate_execution_order_count": _sarif_summary_count(
                    flow.get("duplicate_execution_order_count")
                ),
                "simultaneous_execution_order_count": _sarif_summary_count(
                    flow.get("simultaneous_execution_order_count")
                ),
                "semantic_basis": semantic_basis,
                "reported_step_count": _sarif_summary_count(flow.get("step_count")),
                "steps_omitted": _sarif_summary_count(flow.get("steps_omitted")),
                "thread_flow_location_resolution_counts": {
                    key[:100]: _sarif_summary_count(count)
                    for key, count in bounded_counts
                },
            }
        )
    return summaries


def _sarif_summary_count(value: Any) -> int:
    return (
        value
        if isinstance(value, int) and not isinstance(value, bool) and value >= 0
        else 0
    )


def _sarif_message_text(value: str) -> str:
    """Escape SARIF 3.11.6 embedded-link syntax in plain-text messages.

    SARIF viewers render ``[text](uri)`` in ``message.text`` as a link, so
    literal brackets from scanner output are backslash-escaped, as are any
    backslashes that would otherwise escape a bracket.
    """

    return re.sub(
        r"(\\*)([\[\]])",
        lambda match: match.group(1) * 2 + "\\" + match.group(2),
        value,
    )


def _sarif_suppression(finding: Finding) -> dict[str, Any] | None:
    if finding.status is not FindingStatus.SUPPRESSED:
        return None
    acceptance = finding.evidence.get("risk_acceptance")
    justification = "Suppressed by governed risk acceptance."
    if isinstance(acceptance, dict):
        details = [
            f"{label}: {acceptance[key]}"
            for key, label in (
                ("disposition", "disposition"),
                ("rationale", "rationale"),
                ("owner", "owner"),
                ("expires", "expires"),
            )
            if isinstance(acceptance.get(key), str) and acceptance[key]
        ]
        if details:
            justification = "; ".join(details)
    return {
        "kind": "external",
        "status": "accepted",
        "justification": justification[:2000],
    }


def _sarif_artifact_uri(path: str) -> str | None:
    """Return an RFC 3986 relative reference for an in-target path, or None.

    Placeholders such as ``<outside-target>`` or ``<repository>``, absolute
    paths, and parent traversal are not valid artifact locations, so the
    location is omitted rather than published as a misleading URI.
    """

    normalized = path.replace("\\", "/")
    if (
        not normalized
        or normalized in {".", "./"}
        or (normalized.startswith("<") and normalized.endswith(">"))
        or normalized.startswith("/")
        or re.match(r"^[A-Za-z]:", normalized)
        or ".." in normalized.split("/")
        or any(ord(character) < 32 or ord(character) == 127 for character in path)
    ):
        return None
    if normalized.startswith("./"):
        normalized = normalized[2:]
    return quote(normalized, safe="/")


def _sarif_name(rule_id: str) -> str:
    return "".join(character if character.isalnum() else "_" for character in rule_id)[
        :120
    ]


def _sarif_level(severity: Severity) -> str:
    if severity in {Severity.CRITICAL, Severity.HIGH}:
        return "error"
    if severity is Severity.MEDIUM:
        return "warning"
    return "note"


def _sarif_security_score(severity: Severity) -> float:
    return {
        Severity.CRITICAL: 9.5,
        Severity.HIGH: 8.0,
        Severity.MEDIUM: 5.5,
        Severity.LOW: 3.0,
        Severity.INFORMATIONAL: 1.0,
        Severity.UNKNOWN: 0.0,
    }[severity]
