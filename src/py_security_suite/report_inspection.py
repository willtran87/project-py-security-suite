from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit

from .execution import sanitize_terminal_text
from .models import Outcome
from .passport import verify_report


_MAX_JSON_BYTES = 128 * 1024 * 1024
_SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "informational": 4,
    "unknown": 5,
}
_POLICY_DISPOSITIONS = {
    Outcome.PASS: "allow",
    Outcome.WARN: "review",
    Outcome.FAIL: "block",
    Outcome.INCOMPLETE: "block",
}


def inspect_report(report: Path, *, limit: int = 5) -> dict[str, Any]:
    """Verify and summarize a report without trusting its HTML or Markdown."""
    if limit < 0 or limit > 100:
        raise ValueError("inspection limit must be between 0 and 100")
    verification = verify_report(report)
    root = report.expanduser().absolute().resolve()
    manifest = _read_object(root / "scan-manifest.json")
    findings_document = _read_object(root / "findings.json")
    findings = _object_list(findings_document.get("findings"), "findings")
    tools = _object_list(manifest.get("tools"), "tools")
    outcome, policy_reasons = _policy_metadata(manifest)
    policy_reasons = [_safe_text(reason) for reason in policy_reasons]
    sorted_findings = sorted(findings, key=_finding_key)
    return {
        "schema_version": "1.0",
        "verified": True,
        "scan": _scan_summary(manifest, outcome),
        "findings": _findings_summary(findings),
        "tool_health": _tool_health(tools),
        "entrypoint_integrity": _entrypoint_integrity(tools),
        "scan_policy": {
            "disposition": _POLICY_DISPOSITIONS[Outcome(outcome)],
            "reasons": policy_reasons,
        },
        # Retain the original field for consumers of the 1.0 inspection shape.
        "policy_reasons": policy_reasons,
        "top_actions": [_action(item, root) for item in sorted_findings[:limit]],
        "integrity": {
            "status": "verified",
            "files_verified": verification["file_count"],
            "checksums_sha256": verification["checksums_sha256"],
        },
        "entrypoints": _entrypoints(root),
    }


def _object_list(value: object, name: str) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise ValueError(f"report {name} must be a list of objects")
    return value


def _policy_metadata(manifest: dict[str, Any]) -> tuple[str, list[str]]:
    outcome = str(manifest.get("outcome") or "")
    try:
        parsed_outcome = Outcome(outcome)
    except ValueError as exc:
        raise ValueError("report outcome is invalid") from exc
    reasons = manifest.get("policy_reasons") or []
    if not isinstance(reasons, list) or not all(
        isinstance(item, str) for item in reasons
    ):
        raise ValueError("report policy reasons must be a list of strings")
    return parsed_outcome.value, reasons


def _scan_summary(manifest: dict[str, Any], outcome: str) -> dict[str, Any]:
    return {
        "id": _safe_text(manifest.get("scan_id")),
        "target": _safe_text(manifest.get("target")),
        "profile": _safe_text(manifest.get("profile")),
        "outcome": outcome,
        "duration_seconds": manifest.get("duration_seconds"),
        "finished_at": _safe_text(manifest.get("finished_at")),
    }


def _findings_summary(findings: list[dict[str, Any]]) -> dict[str, Any]:
    severity = Counter(
        _safe_text(item.get("severity") or "unknown") for item in findings
    )
    domains = Counter(_safe_text(item.get("domain") or "unknown") for item in findings)
    lifecycle = Counter(
        _safe_text(item.get("status") or "unknown") for item in findings
    )
    return {
        "total": len(findings),
        "blocking": sum(bool(item.get("blocking")) for item in findings),
        "by_severity": dict(sorted(severity.items())),
        "by_domain": dict(sorted(domains.items())),
        "by_lifecycle": dict(sorted(lifecycle.items())),
    }


def _entrypoints(root: Path) -> dict[str, str]:
    return {
        "html": _safe_text(root / "index.html"),
        "summary": _safe_text(root / "summary.md"),
        "action_plan": _safe_text(root / "action-plan.md"),
    }


def render_inspection(document: dict[str, Any]) -> str:
    """Render a compact summary suited to terminals and release logs."""
    scan = document["scan"]
    findings = document["findings"]
    health = document["tool_health"]
    entrypoints = document["entrypoint_integrity"]
    integrity = document["integrity"]
    policy = document["scan_policy"]
    lines = [
        (
            f"{str(scan['outcome']).upper()}: {scan['target']} "
            f"({scan['profile']}; {scan['id']})"
        ),
        (
            f"Decision: {str(policy['disposition']).upper()}; report integrity: "
            f"{str(integrity['status']).upper()} ({integrity['files_verified']} files)"
        ),
        (
            f"Findings: {findings['total']} total, {findings['blocking']} blocking; "
            f"severity {_counts(findings['by_severity'])}"
        ),
        (
            f"Tools: {health['completed']}/{health['applicable']} applicable completed; "
            f"{health['not_applicable']} not applicable; "
            f"{health['execution_gaps']} execution gaps"
        ),
        (
            f"Entrypoints: {entrypoints['approved_and_unchanged']}/"
            f"{entrypoints['observed']} approved and unchanged; "
            f"{entrypoints['unchanged_after_execution']}/"
            f"{entrypoints['observed']} unchanged after execution"
        ),
        f"Domains: {_counts(findings['by_domain'])}",
        f"Lifecycle: {_counts(findings['by_lifecycle'])}",
    ]
    reasons = policy["reasons"]
    if reasons:
        lines.append("Policy reasons:")
        lines.extend(f"- {_safe_text(reason)}" for reason in reasons)
    actions = document["top_actions"]
    if actions:
        lines.append("Top actions:")
        for item in actions:
            lines.extend(_render_action(item))
    lines.extend(
        [
            f"Open: {document['entrypoints']['html']}",
            f"Actions: {document['entrypoints']['action_plan']}",
        ]
    )
    return "\n".join(lines)


def _render_action(item: dict[str, Any]) -> list[str]:
    lines = [
        f"- [{str(item['severity']).upper()}/{str(item['status']).upper()}] "
        f"{item['title']} | {_action_location(item)}",
        "  Evidence: " + "; ".join(_action_evidence(item)),
    ]
    lines.extend(
        f"  Reference: {_reference_text(citation)}" for citation in item["citations"]
    )
    if item["remediation"]:
        lines.append(f"  Action: {item['remediation']}")
    lines.append(f"  Review: {item['details']}")
    return lines


def _action_location(item: dict[str, Any]) -> str:
    location = str(item["path"])
    return f"{location}:{item['line']}" if item["line"] is not None else location


def _action_evidence(item: dict[str, Any]) -> list[str]:
    evidence = [f"finding {item['finding_id']}", *item["source_rules"]]
    if item["classifications"]:
        evidence.append("classification " + ", ".join(item["classifications"]))
    if item["owners"]:
        evidence.append("owner " + ", ".join(item["owners"]))
    return evidence


def _reference_text(citation: dict[str, str]) -> str:
    reference = citation["title"] or citation["identifier"]
    return f"{reference} - {citation['uri']}" if citation["uri"] else reference


def _read_object(path: Path) -> dict[str, Any]:
    if not path.is_file() or path.is_symlink() or path.stat().st_size > _MAX_JSON_BYTES:
        raise ValueError(f"report JSON is not a bounded regular file: {path}")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"report JSON root must be an object: {path}")
    return value


def _finding_key(item: dict[str, Any]) -> tuple[int, int, int, str]:
    status = str(item.get("status") or "unknown")
    return (
        0 if item.get("blocking") else 1,
        0 if status in {"new", "regression"} else 1,
        _SEVERITY_ORDER.get(str(item.get("severity") or "unknown"), 5),
        str(item.get("finding_id") or ""),
    )


def _action(item: dict[str, Any], root: Path) -> dict[str, Any]:
    location = _primary_location(item.get("locations"))
    sources = _sources(item.get("sources"))
    finding_id = _safe_text(item.get("finding_id") or "")
    return {
        "finding_id": finding_id,
        "title": _safe_text(item.get("title")),
        "severity": _safe_text(item.get("severity")),
        "status": _safe_text(item.get("status")),
        "domain": _safe_text(item.get("domain")),
        "path": _safe_text(location.get("path", "<repository>")),
        "line": _line_number(location.get("start_line")),
        "tools": sorted({_safe_text(source["tool"]) for source in sources}),
        "source_rules": sorted({_source_rule(source) for source in sources}),
        "classifications": _strings(item.get("classifications")),
        "citations": _citations(item.get("citations")),
        "owners": _owners(item.get("evidence")),
        "remediation": _safe_text(item.get("remediation") or ""),
        "details": f"{_safe_text(root / 'index.html')}#{quote(finding_id, safe='')}",
    }


def _primary_location(value: object) -> dict[str, Any]:
    if isinstance(value, list) and value and isinstance(value[0], dict):
        return value[0]
    return {}


def _line_number(value: object) -> int | None:
    if isinstance(value, int) and not isinstance(value, bool) and value > 0:
        return value
    return None


def _sources(value: object) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [
        source for source in value if isinstance(source, dict) and source.get("tool")
    ]


def _source_rule(source: dict[str, Any]) -> str:
    tool = _safe_text(source["tool"])
    rule = source.get("rule_id")
    return f"{tool}/{_safe_text(rule)}" if rule else tool


def _owners(value: object) -> list[str]:
    if not isinstance(value, dict) or not isinstance(value.get("owners"), list):
        return []
    return [_safe_text(owner) for owner in value["owners"]]


def _strings(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [_safe_text(item) for item in value]


def _citations(value: object) -> list[dict[str, str]]:
    if not isinstance(value, list):
        return []
    return [
        {
            "identifier": _safe_text(item.get("identifier") or ""),
            "title": _safe_text(item.get("title") or ""),
            "uri": _safe_web_uri(item.get("uri")),
        }
        for item in value
        if isinstance(item, dict)
    ]


def _counts(values: dict[str, int]) -> str:
    return (
        ", ".join(f"{_safe_text(name)}={count}" for name, count in values.items())
        or "none"
    )


def _tool_health(tools: list[dict[str, Any]]) -> dict[str, Any]:
    applicable = [item for item in tools if item.get("applicable", True) is not False]
    not_applicable = len(tools) - len(applicable)
    completed = sum(str(item.get("status")) == "completed" for item in applicable)
    by_status = Counter(_safe_text(item.get("status") or "unknown") for item in tools)
    return {
        "selected": len(tools),
        "applicable": len(applicable),
        "completed": completed,
        "not_applicable": not_applicable,
        "execution_gaps": len(applicable) - completed,
        "coverage_complete": completed == len(applicable),
        "by_status": dict(sorted(by_status.items())),
    }


def _entrypoint_integrity(tools: list[dict[str, Any]]) -> dict[str, Any]:
    states = [
        state
        for tool in tools
        for state in (
            (
                tool.get("executable_sha256"),
                tool.get("executable_integrity_verified"),
                tool.get("executable_unchanged"),
            ),
            (
                tool.get("auxiliary_executable_sha256"),
                tool.get("auxiliary_executable_integrity_verified"),
                tool.get("auxiliary_executable_unchanged"),
            ),
        )
        if isinstance(state[0], str) and state[0]
    ]
    observed = len(states)
    approved = sum(
        approval is True and unchanged is True for _, approval, unchanged in states
    )
    unchanged = sum(value is True for _, _, value in states)
    return {
        "observed": observed,
        "approved_and_unchanged": approved,
        "unchanged_after_execution": unchanged,
        "postcheck_gaps": observed - unchanged,
        "fully_approved": observed > 0 and approved == observed,
    }


def _safe_text(value: object) -> str:
    return sanitize_terminal_text(str(value))


def _safe_web_uri(value: object) -> str:
    uri = _safe_text(value or "").strip()
    try:
        parsed = urlsplit(uri)
    except ValueError:
        return ""
    return uri if parsed.scheme.lower() in {"http", "https"} and parsed.netloc else ""
