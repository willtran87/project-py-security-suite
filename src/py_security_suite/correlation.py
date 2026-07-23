from __future__ import annotations

from collections import defaultdict

from .models import (
    Confidence,
    Finding,
    Severity,
    finding_identity,
)


_SEVERITY_ORDER = {
    Severity.UNKNOWN: 0,
    Severity.INFORMATIONAL: 1,
    Severity.LOW: 2,
    Severity.MEDIUM: 3,
    Severity.HIGH: 4,
    Severity.CRITICAL: 5,
}
_CONFIDENCE_ORDER = {
    Confidence.UNKNOWN: 0,
    Confidence.LOW: 1,
    Confidence.MEDIUM: 2,
    Confidence.HIGH: 3,
}


def correlate_findings(findings: list[Finding]) -> list[Finding]:
    grouped: dict[tuple[str, int | None, str], list[Finding]] = defaultdict(list)
    for finding in findings:
        location = finding.locations[0] if finding.locations else None
        path = location.path if location else "<unknown>"
        line = location.start_line if location else None
        logical_rule = _logical_rule(finding)
        grouped[(path, line, logical_rule)].append(finding)

    correlated: list[Finding] = []
    for (path, line, logical_rule), observations in grouped.items():
        primary = observations[0]
        if len(observations) == 1:
            correlated.append(primary)
            continue
        finding_id, fingerprint = finding_identity(
            tool="suite",
            rule_id=logical_rule,
            path=path,
            start_line=line,
        )
        primary.finding_id = finding_id
        primary.fingerprint = fingerprint
        primary.severity = max(
            (item.severity for item in observations),
            key=lambda value: _SEVERITY_ORDER[value],
        )
        primary.confidence = max(
            (item.confidence for item in observations),
            key=lambda value: _CONFIDENCE_ORDER[value],
        )
        primary.sources = _unique(
            [source for item in observations for source in item.sources],
            key=lambda source: (source.tool, source.rule_id),
        )
        primary.citations = _unique(
            [citation for item in observations for citation in item.citations],
            key=lambda citation: (citation.kind, citation.identifier),
        )
        primary.classifications = list(
            dict.fromkeys(
                value
                for item in observations
                for value in item.classifications
            )
        )
        correlated.append(primary)

    return sorted(correlated, key=_sort_key)


def _logical_rule(finding: Finding) -> str:
    for classification in finding.classifications:
        normalized = classification.upper().split(":", 1)[0]
        if normalized.startswith("CWE-"):
            return normalized
    if finding.sources:
        return finding.sources[0].rule_id
    return finding.title.casefold()


def _unique(values: list, *, key):
    seen = set()
    result = []
    for value in values:
        identity = key(value)
        if identity not in seen:
            seen.add(identity)
            result.append(value)
    return result


def _sort_key(finding: Finding) -> tuple[int, str, int, str]:
    location = finding.locations[0] if finding.locations else None
    return (
        -_SEVERITY_ORDER[finding.severity],
        location.path if location else "",
        location.start_line or 0 if location else 0,
        finding.finding_id,
    )

