from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse

from ..models import (
    Citation,
    Finding,
    Location,
    Severity,
    Source,
    finding_identity,
    normalize_repo_path,
)
from .common import map_confidence, map_severity, string_list


def parse_sarif_findings(
    payload: str,
    target: Path,
    *,
    tool_name: str,
    default_area: str,
    default_impact: str,
    default_remediation: str,
) -> list[Finding]:
    document = json.loads(payload)
    runs = document.get("runs", [])
    if not isinstance(runs, list):
        raise TypeError("SARIF runs must be a list")
    findings: list[Finding] = []
    for run in runs:
        if not isinstance(run, dict):
            raise TypeError("SARIF run must be an object")
        tool = run.get("tool") or {}
        driver = tool.get("driver") if isinstance(tool, dict) else {}
        rules = _rule_index(driver)
        results = run.get("results") or []
        if not isinstance(results, list):
            raise TypeError("SARIF results must be a list")
        for result in results:
            if not isinstance(result, dict):
                raise TypeError("SARIF result must be an object")
            rule_id = str(result.get("ruleId") or "unknown")
            rule = rules.get(rule_id, {})
            message = _message(result.get("message")) or rule_id
            title = (
                _message(rule.get("shortDescription"))
                or _message(rule.get("fullDescription"))
                or message
            )
            location = _location(result, target)
            properties = result.get("properties") or {}
            if not isinstance(properties, dict):
                properties = {}
            rule_properties = rule.get("properties") or {}
            if not isinstance(rule_properties, dict):
                rule_properties = {}
            severity = _sarif_severity(
                result.get("level"), properties, rule_properties
            )
            classifications = _classifications(properties, rule_properties)
            finding_id, fingerprint = finding_identity(
                tool=tool_name,
                rule_id=rule_id,
                path=location.path,
                start_line=location.start_line,
            )
            help_text = _message(rule.get("help"))
            help_uri = _safe_uri(rule.get("helpUri"))
            findings.append(
                Finding(
                    finding_id=finding_id,
                    fingerprint=fingerprint,
                    title=title,
                    description=message,
                    impact=(
                        str(properties.get("impact") or "").strip()
                        or help_text
                        or default_impact
                    ),
                    remediation=(
                        str(
                            properties.get("recommended_action")
                            or properties.get("remediation")
                            or ""
                        ).strip()
                        or default_remediation
                    ),
                    severity=severity,
                    confidence=map_confidence(
                        properties.get("confidence")
                        or rule_properties.get("confidence")
                    ),
                    area=str(
                        properties.get("area")
                        or rule_properties.get("category")
                        or default_area
                    ),
                    classifications=classifications,
                    locations=[location],
                    sources=[
                        Source(
                            tool=tool_name,
                            rule_id=rule_id,
                            message=message,
                            native_severity=str(
                                result.get("level") or severity.value
                            ),
                        )
                    ],
                    citations=[
                        Citation(
                            kind="tool_rule",
                            identifier=rule_id,
                            title=title,
                            uri=help_uri,
                        )
                    ],
                )
            )
    return findings


def _rule_index(driver: Any) -> dict[str, dict[str, Any]]:
    if not isinstance(driver, dict):
        return {}
    rules = driver.get("rules") or []
    if not isinstance(rules, list):
        return {}
    return {
        str(rule.get("id")): rule
        for rule in rules
        if isinstance(rule, dict) and rule.get("id")
    }


def _message(value: Any) -> str:
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, dict):
        return str(value.get("text") or value.get("markdown") or "").strip()
    return ""


def _location(result: dict[str, Any], target: Path) -> Location:
    locations = result.get("locations") or []
    if not isinstance(locations, list) or not locations:
        return Location(path="<repository>")
    location = locations[0]
    physical = location.get("physicalLocation") if isinstance(location, dict) else {}
    if not isinstance(physical, dict):
        physical = {}
    artifact = physical.get("artifactLocation") or {}
    uri = str(artifact.get("uri") or "<repository>") if isinstance(artifact, dict) else "<repository>"
    path = _uri_path(uri)
    region = physical.get("region") or {}
    if not isinstance(region, dict):
        region = {}
    return Location(
        path=normalize_repo_path(target, path),
        start_line=_integer(region.get("startLine")),
        end_line=_integer(region.get("endLine")),
    )


def _uri_path(value: str) -> str:
    if not value.startswith("file:"):
        return unquote(value)
    parsed = urlparse(value)
    path = unquote(parsed.path)
    if len(path) >= 3 and path[0] == "/" and path[2] == ":":
        path = path[1:]
    return path


def _sarif_severity(
    level: Any,
    properties: dict[str, Any],
    rule_properties: dict[str, Any],
) -> Severity:
    raw_score = (
        properties.get("security-severity")
        or rule_properties.get("security-severity")
    )
    try:
        score = float(raw_score)
    except (TypeError, ValueError):
        score = -1
    if score >= 9:
        return Severity.CRITICAL
    if score >= 7:
        return Severity.HIGH
    if score >= 4:
        return Severity.MEDIUM
    if score >= 0:
        return Severity.LOW
    return map_severity(level)


def _classifications(
    properties: dict[str, Any], rule_properties: dict[str, Any]
) -> list[str]:
    values = (
        string_list(properties.get("classifications"))
        + string_list(properties.get("tags"))
        + string_list(rule_properties.get("tags"))
    )
    return list(
        dict.fromkeys(
            value
            for value in values
            if value.upper().startswith(("CWE-", "OWASP", "MITRE"))
        )
    )


def _integer(value: Any) -> int | None:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _safe_uri(value: Any) -> str | None:
    text = str(value or "")
    return text if text.startswith(("https://", "http://")) else None
