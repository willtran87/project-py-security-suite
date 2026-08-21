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
from ..source_context import is_secret_bearing_scan, redact_sensitive_text
from .common import map_confidence, map_severity, string_list


_MAX_RESULT_LOCATIONS = 25
_RESULT_KINDS = {
    "fail": "fail",
    "informational": "informational",
    "notapplicable": "not-applicable",
    "open": "open",
    "pass": "pass",
    "review": "review",
}
_BASELINE_STATES = {
    "absent": "absent",
    "new": "new",
    "unchanged": "unchanged",
    "updated": "updated",
}
_SUPPRESSION_STATUSES = {
    "accepted": "accepted",
    "rejected": "rejected",
    "underreview": "under-review",
}


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
        for result in _object_list(run.get("results") or [], "results"):
            result_semantics = _result_semantics(result)
            if not result_semantics["normalized_as_finding"]:
                continue
            findings.append(
                _finding(
                    result,
                    rules,
                    target,
                    tool_name=tool_name,
                    default_area=default_area,
                    default_impact=default_impact,
                    default_remediation=default_remediation,
                    result_semantics=result_semantics,
                )
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
    result_semantics: dict[str, Any],
) -> Finding:
    rule_id = str(result.get("ruleId") or "unknown")
    rule = rules.get(rule_id, {})
    properties = _object(result.get("properties"))
    rule_properties = _object(rule.get("properties"))
    tags = _tags(properties, rule_properties)
    area = str(
        properties.get("area")
        or rule_properties.get("category")
        or _area(tags, default_area)
    )
    secret_bearing = is_secret_bearing_scan(area=area, tool_name=tool_name)
    raw_message = _message(result.get("message")) or rule_id
    message = redact_sensitive_text(raw_message, secret_bearing=secret_bearing)
    raw_title = (
        _message(rule.get("shortDescription"))
        or _message(rule.get("fullDescription"))
        or message
    )
    title = redact_sensitive_text(raw_title, secret_bearing=secret_bearing)
    locations, location_summary = _locations(result, target)
    location = locations[0]
    severity = _sarif_severity(result.get("level"), properties, rule_properties)
    domain = _domain(tags)
    finding_id, fingerprint = finding_identity(
        tool=tool_name,
        rule_id=rule_id,
        path=location.path,
        start_line=location.start_line,
    )
    help_text = redact_sensitive_text(
        _message(rule.get("help")), secret_bearing=secret_bearing
    )
    help_uri = _safe_uri(rule.get("helpUri")) or _derived_help_uri(tool_name, rule_id)
    impact = (
        redact_sensitive_text(
            str(properties.get("impact") or "").strip(),
            secret_bearing=secret_bearing,
        )
        or help_text
    )
    remediation = redact_sensitive_text(
        str(
            properties.get("recommended_action") or properties.get("remediation") or ""
        ).strip(),
        secret_bearing=secret_bearing,
    )
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
    code_flows = _code_flows(
        result,
        target,
        tool_name,
        security_domain=domain == "security",
        rule_kind=str(rule_properties.get("kind") or properties.get("kind") or ""),
        secret_bearing_messages=secret_bearing,
    )
    evidence: dict[str, Any] = {"sarif_result_semantics": result_semantics}
    if code_flows:
        evidence["sarif_code_flows"] = code_flows
    if location_summary:
        evidence["sarif_location_summary"] = location_summary
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
        area=area,
        domain=domain,
        classifications=classifications,
        locations=locations,
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
        evidence=evidence,
    )


def _code_flows(
    result: dict[str, Any],
    target: Path,
    tool_name: str,
    *,
    security_domain: bool,
    rule_kind: str,
    secret_bearing_messages: bool,
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
            native_steps: list[tuple[int, dict[str, Any]]] = []
            for native_index, raw in enumerate(raw_locations[:100]):
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
                message = redact_sensitive_text(
                    message, secret_bearing=secret_bearing_messages
                )
                native_steps.append(
                    (
                        native_index,
                        {
                            "path": normalize_repo_path(
                                target,
                                _uri_path(str(artifact.get("uri") or "<repository>")),
                            ),
                            "line": _positive_integer(region.get("startLine")),
                            "message": message[:500],
                            "execution_order": _nonnegative_integer(
                                raw.get("executionOrder")
                            ),
                            "nesting_level": _nonnegative_integer(
                                raw.get("nestingLevel")
                            ),
                            "importance": str(raw.get("importance") or "")[:100],
                            "kinds": _flow_kinds(raw.get("kinds")),
                        },
                    )
                )
            if native_steps and all(
                isinstance(step.get("execution_order"), int) for _, step in native_steps
            ):
                native_steps.sort(
                    key=lambda item: (int(item[1]["execution_order"]), item[0])
                )
            steps = [
                {**step, "sequence": sequence}
                for sequence, (_, step) in enumerate(native_steps)
            ]
            if steps:
                semantic_basis = _flow_semantic_basis(
                    steps,
                    security_domain=security_domain,
                    rule_kind=rule_kind,
                )
                flows.append(
                    {
                        "tool": tool_name,
                        "semantic_basis": semantic_basis,
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


def _result_semantics(result: dict[str, Any]) -> dict[str, Any]:
    kind = _enum_value(result.get("kind"), _RESULT_KINDS, default="fail")
    baseline_state = _enum_value(
        result.get("baselineState"), _BASELINE_STATES, default="unspecified"
    )
    raw_suppressions = result.get("suppressions")
    malformed_container = raw_suppressions is not None and not isinstance(
        raw_suppressions, list
    )
    suppressions = raw_suppressions if isinstance(raw_suppressions, list) else []
    status_counts: dict[str, int] = {}
    invalid_count = 0
    for suppression in suppressions:
        if not isinstance(suppression, dict):
            invalid_count += 1
            continue
        status = _enum_value(
            suppression.get("status"),
            _SUPPRESSION_STATUSES,
            default="unspecified",
        )
        status_counts[status] = status_counts.get(status, 0) + 1
    normalized_as_finding = kind not in {"pass", "not-applicable"} and (
        baseline_state != "absent"
    )
    return {
        "kind": kind,
        "baseline_state": baseline_state,
        "normalized_as_finding": normalized_as_finding,
        "native_suppression_count": len(suppressions),
        "native_suppression_status_counts": dict(sorted(status_counts.items())),
        "accepted_native_suppression_count": status_counts.get("accepted", 0),
        "invalid_native_suppression_count": invalid_count,
        "malformed_native_suppression_container": malformed_container,
        "native_suppression_authority": (
            "informational-only; suite policy acceptance is still required"
        ),
    }


def _enum_value(value: Any, allowed: dict[str, str], *, default: str) -> str:
    if value is None:
        return default
    if not isinstance(value, str):
        return "unknown"
    return allowed.get(value.strip().casefold(), "unknown")


def _location(result: dict[str, Any], target: Path) -> Location:
    """Return the stable primary result location for compatibility."""
    return _locations(result, target)[0][0]


def _locations(
    result: dict[str, Any], target: Path
) -> tuple[list[Location], dict[str, Any]]:
    """Retain bounded, ordered, distinct native result locations."""
    raw_locations = result.get("locations") or []
    if not isinstance(raw_locations, list) or not raw_locations:
        return [Location(path="<repository>")], {}
    retained: list[Location] = []
    seen: set[tuple[str, int | None, int | None]] = set()
    duplicate_count = 0
    invalid_count = 0
    limit_count = 0
    for raw_location in raw_locations:
        if not isinstance(raw_location, dict) or not _valid_location_shape(
            raw_location
        ):
            invalid_count += 1
            continue
        location = _physical_location(raw_location, target)
        identity = (location.path, location.start_line, location.end_line)
        if identity in seen:
            duplicate_count += 1
            continue
        seen.add(identity)
        if len(retained) >= _MAX_RESULT_LOCATIONS:
            limit_count += 1
            continue
        retained.append(location)
    native_retained_count = len(retained)
    if not retained:
        retained.append(Location(path="<repository>"))
    summary = {
        "reported_count": len(raw_locations),
        "retained_count": native_retained_count,
        "duplicate_count": duplicate_count,
        "invalid_count": invalid_count,
        "limit_omitted_count": limit_count,
        "omitted_count": duplicate_count + invalid_count + limit_count,
        "truncated": limit_count > 0,
    }
    return retained, summary


def _physical_location(location: dict[str, Any], target: Path) -> Location:
    physical = location.get("physicalLocation")
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
        start_line=_positive_integer(region.get("startLine")),
        end_line=_positive_integer(region.get("endLine")),
    )


def _valid_location_shape(location: dict[str, Any]) -> bool:
    physical = location.get("physicalLocation")
    if physical is None:
        return True
    if not isinstance(physical, dict):
        return False
    artifact = physical.get("artifactLocation")
    if artifact is not None:
        if not isinstance(artifact, dict):
            return False
        uri = artifact.get("uri")
        if uri is not None and not isinstance(uri, str):
            return False
    region = physical.get("region")
    if region is None:
        return True
    if not isinstance(region, dict):
        return False
    start = _positive_integer(region.get("startLine"))
    end = _positive_integer(region.get("endLine"))
    if region.get("startLine") is not None and start is None:
        return False
    if region.get("endLine") is not None and end is None:
        return False
    return start is None or end is None or end >= start


def _uri_path(value: str) -> str:
    value = value.strip()
    if not value:
        return "<repository>"
    if re.match(r"^[A-Za-z]:[\\/]", value):
        return unquote(value)
    parsed = urlparse(value)
    if not parsed.scheme:
        return unquote(value)
    if parsed.scheme.casefold() != "file":
        return "<external-artifact>"
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


def _positive_integer(value: Any) -> int | None:
    return (
        value
        if isinstance(value, int) and not isinstance(value, bool) and value > 0
        else None
    )


def _nonnegative_integer(value: Any) -> int | None:
    return (
        value
        if isinstance(value, int) and not isinstance(value, bool) and value >= 0
        else None
    )


def _flow_kinds(value: Any) -> list[str]:
    return sorted(
        {
            normalized
            for item in string_list(value)[:25]
            if (normalized := item.strip().casefold())
        }
    )[:10]


def _flow_semantic_basis(
    steps: list[dict[str, Any]], *, security_domain: bool, rule_kind: str
) -> str:
    if not security_domain:
        return "unclassified-code-flow"
    source_positions = [
        index for index, step in enumerate(steps) if "source" in step.get("kinds", [])
    ]
    sink_positions = [
        index for index, step in enumerate(steps) if "sink" in step.get("kinds", [])
    ]
    if source_positions and sink_positions and source_positions[0] < sink_positions[-1]:
        return "native-source-sink-kinds"
    if rule_kind.strip().casefold().replace("_", "-") == "path-problem":
        return "security-path-problem"
    return "unclassified-code-flow"


def _safe_uri(value: Any) -> str | None:
    text = str(value or "")
    return text if text.startswith(("https://", "http://")) else None
