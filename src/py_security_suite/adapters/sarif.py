from __future__ import annotations

import json
import re
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
    findings: list[Finding] = []
    for run in _object_list(document.get("runs", []), "runs"):
        driver = _object(_object(run.get("tool")).get("driver"))
        rules = _rule_index(driver)
        findings.extend(
            _finding(
                result,
                rules,
                target,
                tool_name=tool_name,
                default_area=default_area,
                default_impact=default_impact,
                default_remediation=default_remediation,
            )
            for result in _object_list(run.get("results") or [], "results")
        )
    return findings


def _finding(
    result: dict[str, Any],
    rules: dict[str, dict[str, Any]],
    target: Path,
    *,
    tool_name: str,
    default_area: str,
    default_impact: str,
    default_remediation: str,
) -> Finding:
    rule_id = str(result.get("ruleId") or "unknown")
    rule = rules.get(rule_id, {})
    message = _message(result.get("message")) or rule_id
    title = (
        _message(rule.get("shortDescription"))
        or _message(rule.get("fullDescription"))
        or message
    )
    location = _location(result, target)
    properties = _object(result.get("properties"))
    rule_properties = _object(rule.get("properties"))
    severity = _sarif_severity(result.get("level"), properties, rule_properties)
    tags = _tags(properties, rule_properties)
    domain = _domain(tags)
    finding_id, fingerprint = finding_identity(
        tool=tool_name,
        rule_id=rule_id,
        path=location.path,
        start_line=location.start_line,
    )
    help_text = _message(rule.get("help"))
    help_uri = _safe_uri(rule.get("helpUri")) or _derived_help_uri(tool_name, rule_id)
    impact = str(properties.get("impact") or "").strip() or help_text
    remediation = str(
        properties.get("recommended_action") or properties.get("remediation") or ""
    ).strip()
    if domain == "quality":
        impact = impact or (
            "The code pattern can conceal an implementation mistake or make future "
            "maintenance and review less reliable."
        )
        remediation = remediation or (
            "Make the intent explicit using the cited CodeQL guidance, add or update "
            "a focused test, and rerun the quality profile."
        )
    classifications = _classifications(properties, rule_properties) or [
        _rule_classification(tool_name, rule_id)
    ]
    code_flows = _code_flows(result, target, tool_name)
    return Finding(
        finding_id=finding_id,
        fingerprint=fingerprint,
        title=title,
        description=message,
        impact=impact or default_impact,
        remediation=remediation or default_remediation,
        severity=severity,
        confidence=map_confidence(
            properties.get("confidence")
            or rule_properties.get("confidence")
            or properties.get("precision")
            or rule_properties.get("precision")
        ),
        area=str(
            properties.get("area")
            or rule_properties.get("category")
            or _area(tags, default_area)
        ),
        domain=domain,
        classifications=classifications,
        locations=[location],
        sources=[
            Source(
                tool=tool_name,
                rule_id=rule_id,
                message=message,
                native_severity=str(result.get("level") or severity.value),
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
        evidence={"sarif_code_flows": code_flows} if code_flows else {},
    )


def _code_flows(
    result: dict[str, Any], target: Path, tool_name: str
) -> list[dict[str, Any]]:
    """Retain bounded SARIF path steps without snippets or sensitive state."""
    raw_code_flows = result.get("codeFlows") or []
    if not isinstance(raw_code_flows, list):
        raise TypeError("SARIF codeFlows must be a list")
    flows: list[dict[str, Any]] = []
    for code_flow in raw_code_flows[:5]:
        if not isinstance(code_flow, dict):
            raise TypeError("SARIF codeFlow must be an object")
        thread_flows = code_flow.get("threadFlows") or []
        if not isinstance(thread_flows, list):
            raise TypeError("SARIF threadFlows must be a list")
        for thread_flow in thread_flows[:5]:
            if not isinstance(thread_flow, dict):
                raise TypeError("SARIF threadFlow must be an object")
            raw_locations = thread_flow.get("locations") or []
            if not isinstance(raw_locations, list):
                raise TypeError("SARIF threadFlow locations must be a list")
            steps: list[dict[str, Any]] = []
            for raw in raw_locations[:100]:
                if not isinstance(raw, dict):
                    raise TypeError("SARIF threadFlow location must be an object")
                nested = raw.get("location")
                location = nested if isinstance(nested, dict) else raw
                physical = location.get("physicalLocation")
                physical = physical if isinstance(physical, dict) else {}
                artifact = physical.get("artifactLocation")
                artifact = artifact if isinstance(artifact, dict) else {}
                region = physical.get("region")
                region = region if isinstance(region, dict) else {}
                message = _message(location.get("message")) or _message(
                    raw.get("message")
                )
                steps.append(
                    {
                        "path": normalize_repo_path(
                            target,
                            _uri_path(str(artifact.get("uri") or "<repository>")),
                        ),
                        "line": _integer(region.get("startLine")),
                        "message": message[:500],
                    }
                )
            if steps:
                flows.append(
                    {
                        "tool": tool_name,
                        "steps": steps,
                        "step_count": len(raw_locations),
                        "steps_omitted": max(0, len(raw_locations) - len(steps)),
                    }
                )
            if len(flows) >= 10:
                return flows
    return flows


def _object(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _object_list(value: Any, label: str) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise TypeError(f"SARIF {label} must be a list of objects")
    return [item for item in value if isinstance(item, dict)]


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
    uri = (
        str(artifact.get("uri") or "<repository>")
        if isinstance(artifact, dict)
        else "<repository>"
    )
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
    raw_score = properties.get("security-severity") or rule_properties.get(
        "security-severity"
    )
    try:
        score = float(str(raw_score))
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
    effective_level = (
        level
        or properties.get("problem.severity")
        or rule_properties.get("problem.severity")
    )
    return map_severity(effective_level, default=Severity.INFORMATIONAL)


def _classifications(
    properties: dict[str, Any], rule_properties: dict[str, Any]
) -> list[str]:
    values = (
        string_list(properties.get("classifications"))
        + string_list(properties.get("tags"))
        + string_list(rule_properties.get("tags"))
    )
    normalized: list[str] = []
    for value in values:
        lowered = value.casefold()
        if "cwe-" in lowered:
            suffix = lowered.rsplit("cwe-", maxsplit=1)[-1]
            if suffix.isdigit():
                normalized.append(f"CWE-{suffix}")
        elif value.upper().startswith(("OWASP", "MITRE")):
            normalized.append(value)
    return list(dict.fromkeys(normalized))


def _rule_classification(tool_name: str, rule_id: str) -> str:
    value = f"{tool_name}-{rule_id}".upper()
    return re.sub(r"[^A-Z0-9]+", "-", value).strip("-") or "SARIF-UNKNOWN"


def _tags(properties: dict[str, Any], rule_properties: dict[str, Any]) -> list[str]:
    return [
        value.casefold()
        for value in (
            string_list(properties.get("tags"))
            + string_list(rule_properties.get("tags"))
        )
    ]


def _domain(tags: list[str]) -> str:
    if any(
        tag == "quality"
        or tag.startswith(("maintainability", "readability", "correctness"))
        for tag in tags
    ) and not any(tag == "security" for tag in tags):
        return "quality"
    return "security"


def _area(tags: list[str], default: str) -> str:
    for candidate in ("reliability", "correctness", "maintainability", "readability"):
        if candidate in tags:
            return "code-quality"
    return default


def _derived_help_uri(tool_name: str, rule_id: str) -> str | None:
    if tool_name != "codeql" or not rule_id.startswith("py/"):
        return None
    slug = rule_id.replace("/", "-")
    return f"https://codeql.github.com/codeql-query-help/python/{slug}/"


def _integer(value: Any) -> int | None:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _safe_uri(value: Any) -> str | None:
    text = str(value or "")
    return text if text.startswith(("https://", "http://")) else None
