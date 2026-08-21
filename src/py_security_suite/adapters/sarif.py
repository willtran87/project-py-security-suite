from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urljoin, urlparse

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
_MAX_MESSAGE_ARGUMENTS = 100
_MAX_MESSAGE_ARGUMENT_CHARACTERS = 500
_MAX_MESSAGE_TEMPLATE_CHARACTERS = 4_000
_MAX_RESOLVED_MESSAGE_CHARACTERS = 8_000
_MAX_ARTIFACT_INDEX_DEPTH = 20
_MAX_URI_BASE_DEPTH = 20
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
        ordered_rules = _ordered_rules(driver)
        global_message_strings = _object(driver.get("globalMessageStrings"))
        uri_bases = _object(run.get("originalUriBaseIds"))
        artifacts = _object_list(run.get("artifacts") or [], "artifacts")
        for result in _object_list(run.get("results") or [], "results"):
            result_semantics = _result_semantics(result)
            if not result_semantics["normalized_as_finding"]:
                continue
            findings.append(
                _finding(
                    result,
                    ordered_rules,
                    target,
                    tool_name=tool_name,
                    default_area=default_area,
                    default_impact=default_impact,
                    default_remediation=default_remediation,
                    result_semantics=result_semantics,
                    global_message_strings=global_message_strings,
                    uri_bases=uri_bases,
                    artifacts=artifacts,
                )
            )
    return findings


def _finding(
    result: dict[str, Any],
    ordered_rules: list[dict[str, Any]],
    target: Path,
    *,
    tool_name: str,
    default_area: str,
    default_impact: str,
    default_remediation: str,
    result_semantics: dict[str, Any],
    global_message_strings: dict[str, Any],
    uri_bases: dict[str, Any],
    artifacts: list[dict[str, Any]],
) -> Finding:
    rule_id, rule, rule_reference = _resolve_rule(result, ordered_rules)
    properties = _object(result.get("properties"))
    rule_properties = _object(rule.get("properties"))
    tags = _tags(properties, rule_properties)
    area = str(
        properties.get("area")
        or rule_properties.get("category")
        or _area(tags, default_area)
    )
    secret_bearing = is_secret_bearing_scan(area=area, tool_name=tool_name)
    raw_message, message_reference = _resolve_result_message(
        result.get("message"),
        rule=rule,
        global_message_strings=global_message_strings,
        secret_bearing=secret_bearing,
    )
    raw_message = raw_message or rule_id
    message = redact_sensitive_text(raw_message, secret_bearing=secret_bearing)
    raw_title = (
        _message(rule.get("shortDescription"))
        or _message(rule.get("fullDescription"))
        or message
    )
    title = redact_sensitive_text(raw_title, secret_bearing=secret_bearing)
    locations, location_summary = _locations(
        result, target, uri_bases=uri_bases, artifacts=artifacts
    )
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
        uri_bases=uri_bases,
        artifacts=artifacts,
    )
    evidence: dict[str, Any] = {
        "sarif_result_semantics": result_semantics,
        "sarif_rule_reference": rule_reference,
        "sarif_message_reference": message_reference,
    }
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
    uri_bases: dict[str, Any],
    artifacts: list[dict[str, Any]],
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
                path, path_resolution = _artifact_path(
                    artifact,
                    target,
                    uri_bases=uri_bases,
                    artifacts=artifacts,
                )
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
                            "path": path,
                            "path_resolution": path_resolution,
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


def _ordered_rules(driver: Any) -> list[dict[str, Any]]:
    if not isinstance(driver, dict):
        return []
    rules = driver.get("rules") or []
    if not isinstance(rules, list):
        return []
    return [rule if isinstance(rule, dict) else {} for rule in rules]


def _resolve_rule(
    result: dict[str, Any], ordered_rules: list[dict[str, Any]]
) -> tuple[str, dict[str, Any], dict[str, Any]]:
    raw_rule_id = result.get("ruleId")
    if raw_rule_id is None:
        declared_rule_id = ""
    elif not isinstance(raw_rule_id, str):
        raise TypeError("SARIF ruleId must be a string")
    else:
        declared_rule_id = raw_rule_id.strip()
        if not declared_rule_id:
            raise ValueError("SARIF ruleId must not be empty")

    raw_rule_index = result.get("ruleIndex")
    rule_index: int | None = None
    if raw_rule_index is not None:
        if not isinstance(raw_rule_index, int) or isinstance(raw_rule_index, bool):
            raise TypeError("SARIF ruleIndex must be an integer")
        if raw_rule_index < -1:
            raise ValueError("SARIF ruleIndex must be -1 or non-negative")
        if raw_rule_index >= 0:
            rule_index = raw_rule_index

    indexed_rule: dict[str, Any] | None = None
    indexed_rule_id = ""
    if rule_index is not None:
        if rule_index >= len(ordered_rules):
            raise ValueError("SARIF ruleIndex is outside the driver rule table")
        indexed_rule = ordered_rules[rule_index]
        raw_indexed_id = indexed_rule.get("id")
        if not isinstance(raw_indexed_id, str) or not raw_indexed_id.strip():
            raise ValueError("SARIF ruleIndex references a rule without an id")
        indexed_rule_id = raw_indexed_id.strip()
        if declared_rule_id and declared_rule_id != indexed_rule_id:
            raise ValueError("SARIF ruleId and ruleIndex reference different rules")

    rule_id = declared_rule_id or indexed_rule_id or "unknown"
    if indexed_rule is not None:
        rule = indexed_rule
        basis = "rule-id-and-index" if declared_rule_id else "rule-index"
    elif declared_rule_id:
        matches = [
            candidate
            for candidate in ordered_rules
            if isinstance(candidate.get("id"), str)
            and str(candidate["id"]).strip() == declared_rule_id
        ]
        if len(matches) > 1:
            raise ValueError("SARIF ruleId is ambiguous in the driver rule table")
        rule = matches[0] if matches else {}
        basis = "rule-id"
    else:
        rule = {}
        basis = "unresolved"
    return (
        rule_id,
        rule,
        {
            "basis": basis,
            "rule_index": rule_index,
            "metadata_resolved": bool(rule),
        },
    )


def _message(value: Any) -> str:
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, dict):
        return str(value.get("text") or value.get("markdown") or "").strip()
    return ""


def _resolve_result_message(
    value: Any,
    *,
    rule: dict[str, Any],
    global_message_strings: dict[str, Any],
    secret_bearing: bool,
) -> tuple[str, dict[str, Any]]:
    template = ""
    basis = "missing"
    message_id_present = False
    message_id_resolved = False
    if isinstance(value, str):
        template = value.strip()
        basis = "inline-text"
        raw_arguments: Any = None
    elif isinstance(value, dict):
        raw_arguments = value.get("arguments")
        inline_text = value.get("text")
        inline_markdown = value.get("markdown")
        if isinstance(inline_text, str) and inline_text.strip():
            template = inline_text.strip()
            basis = "inline-text"
        elif isinstance(inline_markdown, str) and inline_markdown.strip():
            template = inline_markdown.strip()
            basis = "inline-markdown"
        else:
            raw_message_id = value.get("id")
            message_id_present = raw_message_id is not None
            message_id = (
                raw_message_id.strip()
                if isinstance(raw_message_id, str) and raw_message_id.strip()
                else ""
            )
            if message_id:
                rule_messages = _object(rule.get("messageStrings"))
                template = _message_template(rule_messages.get(message_id))
                if template:
                    basis = "rule-message-string"
                    message_id_resolved = True
                else:
                    template = _message_template(global_message_strings.get(message_id))
                    if template:
                        basis = "global-message-string"
                        message_id_resolved = True
                    else:
                        basis = "unresolved-message-id"
            elif message_id_present:
                basis = "invalid-message-id"
    else:
        raw_arguments = None

    template = redact_sensitive_text(template, secret_bearing=secret_bearing)
    arguments, argument_summary = _message_arguments(
        raw_arguments, secret_bearing=secret_bearing
    )
    template_characters_omitted = max(
        0, len(template) - _MAX_MESSAGE_TEMPLATE_CHARACTERS
    )
    template_truncated = template_characters_omitted > 0
    template = template[:_MAX_MESSAGE_TEMPLATE_CHARACTERS]
    resolved, used_arguments, unresolved_placeholders = _substitute_message_arguments(
        template, arguments
    )
    resolved = redact_sensitive_text(resolved, secret_bearing=secret_bearing)
    resolved_message_characters_omitted = max(
        0, len(resolved) - _MAX_RESOLVED_MESSAGE_CHARACTERS
    )
    resolved_message_truncated = resolved_message_characters_omitted > 0
    resolved = resolved[:_MAX_RESOLVED_MESSAGE_CHARACTERS].strip()
    return (
        resolved,
        {
            "basis": basis,
            "message_id_present": message_id_present,
            "message_id_resolved": message_id_resolved,
            **argument_summary,
            "used_argument_count": len(used_arguments),
            "unused_retained_argument_count": max(
                0, len(arguments) - len(used_arguments)
            ),
            "unresolved_placeholder_count": unresolved_placeholders,
            "template_truncated": template_truncated,
            "template_characters_omitted": template_characters_omitted,
            "resolved_message_truncated": resolved_message_truncated,
            "resolved_message_characters_omitted": (
                resolved_message_characters_omitted
            ),
        },
    )


def _message_template(value: Any) -> str:
    if isinstance(value, str):
        return value.strip()
    if not isinstance(value, dict):
        return ""
    text = value.get("text")
    if isinstance(text, str) and text.strip():
        return text.strip()
    markdown = value.get("markdown")
    return markdown.strip() if isinstance(markdown, str) else ""


def _message_arguments(
    value: Any, *, secret_bearing: bool
) -> tuple[list[str], dict[str, Any]]:
    malformed_container = value is not None and not isinstance(value, list)
    raw_arguments = value if isinstance(value, list) else []
    retained: list[str] = []
    invalid_count = 0
    truncated_count = 0
    for argument in raw_arguments[:_MAX_MESSAGE_ARGUMENTS]:
        if not isinstance(argument, str):
            retained.append("<invalid-argument>")
            invalid_count += 1
            continue
        redacted = redact_sensitive_text(argument, secret_bearing=secret_bearing)
        if len(redacted) > _MAX_MESSAGE_ARGUMENT_CHARACTERS:
            truncated_count += 1
        retained.append(redacted[:_MAX_MESSAGE_ARGUMENT_CHARACTERS])
    return (
        retained,
        {
            "reported_argument_count": len(raw_arguments),
            "retained_argument_count": len(retained),
            "arguments_omitted_count": max(0, len(raw_arguments) - len(retained)),
            "invalid_argument_count": invalid_count,
            "truncated_argument_count": truncated_count,
            "malformed_argument_container": malformed_container,
        },
    )


def _substitute_message_arguments(
    template: str, arguments: list[str]
) -> tuple[str, set[int], int]:
    output: list[str] = []
    used: set[int] = set()
    unresolved = 0
    index = 0
    while index < len(template):
        if template.startswith("{{", index):
            output.append("{")
            index += 2
            continue
        if template.startswith("}}", index):
            output.append("}")
            index += 2
            continue
        if template[index] == "{":
            end = template.find("}", index + 1)
            placeholder = template[index + 1 : end] if end != -1 else ""
            if placeholder.isdigit():
                if len(placeholder) > 6:
                    output.append(template[index : end + 1])
                    unresolved += 1
                    index = end + 1
                    continue
                argument_index = int(placeholder)
                if argument_index < len(arguments):
                    output.append(arguments[argument_index])
                    used.add(argument_index)
                else:
                    output.append(template[index : end + 1])
                    unresolved += 1
                index = end + 1
                continue
        output.append(template[index])
        index += 1
    return "".join(output), used, unresolved


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
    result: dict[str, Any],
    target: Path,
    *,
    uri_bases: dict[str, Any] | None = None,
    artifacts: list[dict[str, Any]] | None = None,
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
    path_resolution_counts: dict[str, int] = {}
    for raw_location in raw_locations:
        if not isinstance(raw_location, dict) or not _valid_location_shape(
            raw_location
        ):
            invalid_count += 1
            continue
        location, path_resolution = _physical_location(
            raw_location,
            target,
            uri_bases=uri_bases or {},
            artifacts=artifacts or [],
        )
        identity = (location.path, location.start_line, location.end_line)
        if identity in seen:
            duplicate_count += 1
            continue
        seen.add(identity)
        path_resolution_counts[path_resolution] = (
            path_resolution_counts.get(path_resolution, 0) + 1
        )
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
        "path_resolution_counts": dict(sorted(path_resolution_counts.items())),
    }
    return retained, summary


def _physical_location(
    location: dict[str, Any],
    target: Path,
    *,
    uri_bases: dict[str, Any],
    artifacts: list[dict[str, Any]],
) -> tuple[Location, str]:
    physical = location.get("physicalLocation")
    if not isinstance(physical, dict):
        physical = {}
    artifact = physical.get("artifactLocation") or {}
    artifact = artifact if isinstance(artifact, dict) else {}
    path, path_resolution = _artifact_path(
        artifact, target, uri_bases=uri_bases, artifacts=artifacts
    )
    region = physical.get("region") or {}
    if not isinstance(region, dict):
        region = {}
    return (
        Location(
            path=path,
            start_line=_positive_integer(region.get("startLine")),
            end_line=_positive_integer(region.get("endLine")),
        ),
        path_resolution,
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
        if "uri" in artifact and not isinstance(uri, str):
            return False
        uri_base_id = artifact.get("uriBaseId")
        if "uriBaseId" in artifact and (
            not isinstance(uri_base_id, str) or not uri_base_id.strip()
        ):
            return False
        artifact_index = artifact.get("index")
        if (
            "index" in artifact
            and uri is None
            and uri_base_id is None
            and _nonnegative_integer(artifact_index) is None
        ):
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


def _artifact_path(
    artifact: dict[str, Any],
    target: Path,
    *,
    uri_bases: dict[str, Any],
    artifacts: list[dict[str, Any]] | None = None,
) -> tuple[str, str]:
    resolved_artifact, index_resolution = _resolve_artifact_index(
        artifact,
        artifacts or [],
        visited=(),
        depth=0,
    )
    if resolved_artifact is None:
        marker = (
            "<invalid-artifact-index>"
            if index_resolution == "invalid-artifact-index"
            else "<unresolved-artifact-index>"
        )
        return marker, index_resolution or "unresolved-artifact-index"
    artifact = resolved_artifact
    raw_uri = artifact.get("uri")
    raw_base_id = artifact.get("uriBaseId")
    if "uri" in artifact and not isinstance(raw_uri, str):
        return "<invalid-artifact-uri>", _indexed_path_resolution(
            index_resolution, "invalid-artifact-uri"
        )
    if isinstance(raw_uri, str):
        uri = raw_uri.strip()
    else:
        uri = "" if raw_base_id is not None else "<repository>"
    if not _valid_uri_reference(uri):
        return "<invalid-artifact-uri>", _indexed_path_resolution(
            index_resolution, "invalid-artifact-uri"
        )
    if "uriBaseId" not in artifact:
        path = _uri_path(uri)
        resolution = (
            "external-uri" if path == "<external-artifact>" else "target-relative"
        )
        if path == "<external-artifact>":
            return path, _indexed_path_resolution(index_resolution, resolution)
        normalized = normalize_repo_path(target, path)
        if normalized == "<outside-target>":
            return normalized, _indexed_path_resolution(
                index_resolution, "outside-target"
            )
        return normalized, _indexed_path_resolution(index_resolution, resolution)
    if not isinstance(raw_base_id, str) or not raw_base_id.strip():
        return "<unresolved-uri-base>", _indexed_path_resolution(
            index_resolution, "invalid-uri-base"
        )
    base_uri, resolution = _resolve_uri_base(
        raw_base_id.strip(), uri_bases, visited=(), depth=0
    )
    if base_uri is None:
        return "<unresolved-uri-base>", _indexed_path_resolution(
            index_resolution, resolution
        )
    try:
        resolved_uri = urljoin(base_uri, uri)
    except ValueError:
        return "<invalid-artifact-uri>", _indexed_path_resolution(
            index_resolution, "invalid-artifact-uri"
        )
    path = _uri_path(resolved_uri)
    if path == "<invalid-artifact-uri>":
        return path, _indexed_path_resolution(index_resolution, "invalid-artifact-uri")
    if path == "<external-artifact>":
        return path, _indexed_path_resolution(index_resolution, "external-uri-base")
    normalized = normalize_repo_path(target, path)
    if normalized == "<outside-target>":
        return normalized, _indexed_path_resolution(
            index_resolution, "uri-base-outside-target"
        )
    return normalized, _indexed_path_resolution(index_resolution, "uri-base-resolved")


def _indexed_path_resolution(index_resolution: str | None, resolution: str) -> str:
    if index_resolution is None:
        return resolution
    if resolution in {"target-relative", "uri-base-resolved"}:
        return index_resolution
    return f"artifact-index-{resolution}"


def _resolve_artifact_index(
    artifact: dict[str, Any],
    artifacts: list[dict[str, Any]],
    *,
    visited: tuple[int, ...],
    depth: int,
) -> tuple[dict[str, Any] | None, str | None]:
    if "uri" in artifact or "uriBaseId" in artifact or "index" not in artifact:
        return artifact, None
    raw_index = artifact.get("index")
    index = _nonnegative_integer(raw_index)
    if index is None:
        return None, "invalid-artifact-index"
    if depth >= _MAX_ARTIFACT_INDEX_DEPTH:
        return None, "artifact-index-depth-exceeded"
    if index in visited:
        return None, "cyclic-artifact-index"
    if index >= len(artifacts):
        return None, "unresolved-artifact-index"
    raw_location = artifacts[index].get("location")
    if raw_location is None:
        return None, "unresolved-artifact-index"
    if not isinstance(raw_location, dict):
        return None, "invalid-artifact-index"
    if not any(key in raw_location for key in ("uri", "uriBaseId", "index")):
        return None, "unresolved-artifact-index"
    resolved, resolution = _resolve_artifact_index(
        raw_location,
        artifacts,
        visited=(*visited, index),
        depth=depth + 1,
    )
    if resolved is None:
        return None, resolution
    return resolved, "artifact-index-resolved"


def _resolve_uri_base(
    base_id: str,
    uri_bases: dict[str, Any],
    *,
    visited: tuple[str, ...],
    depth: int,
) -> tuple[str | None, str]:
    if depth >= _MAX_URI_BASE_DEPTH:
        return None, "uri-base-depth-exceeded"
    if base_id in visited:
        return None, "cyclic-uri-base"
    raw_base = uri_bases.get(base_id)
    if not isinstance(raw_base, dict):
        return None, "unresolved-uri-base"
    raw_uri = raw_base.get("uri")
    if raw_uri is None:
        uri = ""
    elif isinstance(raw_uri, str):
        uri = raw_uri.strip()
    else:
        return None, "invalid-uri-base"
    if not _valid_uri_reference(uri):
        return None, "invalid-uri-base"
    raw_parent = raw_base.get("uriBaseId")
    if raw_parent is None:
        return uri, "uri-base-resolved"
    if not isinstance(raw_parent, str) or not raw_parent.strip():
        return None, "invalid-uri-base"
    parent_uri, resolution = _resolve_uri_base(
        raw_parent.strip(),
        uri_bases,
        visited=(*visited, base_id),
        depth=depth + 1,
    )
    if parent_uri is None:
        return None, resolution
    try:
        return urljoin(parent_uri, uri), "uri-base-resolved"
    except ValueError:
        return None, "invalid-uri-base"


def _valid_uri_reference(value: str) -> bool:
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        return False
    if re.search(r"%(?![0-9A-Fa-f]{2})", value):
        return False
    try:
        urlparse(value)
    except ValueError:
        return False
    return True


def _uri_path(value: str) -> str:
    value = value.strip()
    if not value:
        return "<repository>"
    if re.match(r"^[A-Za-z]:[\\/]", value):
        return unquote(value)
    try:
        parsed = urlparse(value)
    except ValueError:
        return "<invalid-artifact-uri>"
    if not parsed.scheme:
        if parsed.netloc:
            return "<external-artifact>"
        return unquote(parsed.path)
    if parsed.scheme.casefold() != "file":
        return "<external-artifact>"
    if parsed.username is not None or parsed.password is not None:
        return "<external-artifact>"
    if parsed.netloc and parsed.netloc.casefold() != "localhost":
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
