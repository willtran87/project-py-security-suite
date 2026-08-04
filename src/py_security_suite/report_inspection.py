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
_INSPECTION_SCHEMA_ID = "urn:project-py-security-suite:schema:report-inspection:1.0"
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
        "schema_id": _INSPECTION_SCHEMA_ID,
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
        "top_actions": [_action(item) for item in sorted_findings[:limit]],
        "integrity": {
            "status": "verified",
            "files_verified": verification["file_count"],
            "checksums_sha256": verification["checksums_sha256"],
        },
        "entrypoints": _entrypoints(),
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


def _entrypoints() -> dict[str, str]:
    return {
        "html": "index.html",
        "summary": "summary.md",
        "action_plan": "action-plan.md",
    }


def render_inspection(
    document: dict[str, Any], *, report_root: Path | None = None
) -> str:
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
    approval_gaps = entrypoints["approval_gap_entrypoints"]
    if approval_gaps:
        lines.append(
            "Trust action: approve digests for " + _bounded_names(approval_gaps)
        )
    postcheck_gaps = entrypoints["postcheck_gap_entrypoints"]
    if postcheck_gaps:
        lines.append(
            "Trust action: restore post-checks for " + _bounded_names(postcheck_gaps)
        )
    approval_candidates = entrypoints["approval_candidate_entrypoints"]
    if approval_candidates:
        binding_label = "binding" if approval_candidates == 1 else "bindings"
        unique_digests = entrypoints["approval_candidate_unique_digests"]
        digest_label = "digest" if unique_digests == 1 else "digests"
        lines.append(
            f"Approval workload: {approval_candidates} candidate {binding_label} "
            f"across {unique_digests} unique {digest_label}"
        )
    reasons = policy["reasons"]
    if reasons:
        lines.append("Policy reasons:")
        lines.extend(f"- {_safe_text(reason)}" for reason in reasons)
    actions = document["top_actions"]
    if actions:
        lines.append("Top actions:")
        for item in actions:
            lines.extend(_render_action(item, report_root=report_root))
    lines.extend(
        [
            "Open: "
            + _local_artifact_reference(document["entrypoints"]["html"], report_root),
            "Actions: "
            + _local_artifact_reference(
                document["entrypoints"]["action_plan"], report_root
            ),
        ]
    )
    return "\n".join(lines)


def _render_action(
    item: dict[str, Any], *, report_root: Path | None = None
) -> list[str]:
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
    lines.append("  Review: " + _local_artifact_reference(item["details"], report_root))
    return lines


def _local_artifact_reference(value: object, report_root: Path | None) -> str:
    reference = _safe_text(value)
    if report_root is None:
        return reference
    path_text, separator, fragment = reference.partition("#")
    relative = Path(path_text)
    if relative.is_absolute() or ".." in relative.parts:
        return reference
    root = report_root.expanduser().absolute().resolve()
    resolved = (root / relative).resolve()
    if not resolved.is_relative_to(root):
        return reference
    return f"{resolved}{separator}{fragment}"


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


def _action(item: dict[str, Any]) -> dict[str, Any]:
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
        "details": f"index.html#{quote(finding_id, safe='')}",
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
                _safe_text(tool.get("tool") or "unknown"),
                "primary",
                tool.get("executable_sha256"),
                tool.get("executable_integrity_verified"),
                tool.get("executable_unchanged"),
            ),
            (
                _safe_text(tool.get("tool") or "unknown"),
                "helper",
                tool.get("auxiliary_executable_sha256"),
                tool.get("auxiliary_executable_integrity_verified"),
                tool.get("auxiliary_executable_unchanged"),
            ),
        )
        if isinstance(state[2], str) and state[2]
    ]
    observed = len(states)
    approved = sum(
        approval is True and unchanged is True
        for _, _, _, approval, unchanged in states
    )
    unchanged = sum(value is True for _, _, _, _, value in states)
    actions = sorted(
        (
            _entrypoint_trust_action(state)
            for state in states
            if state[3] is not True or state[4] is not True
        ),
        key=lambda action: (
            _trust_priority_rank(action["priority"]),
            action["entrypoint"],
        ),
    )
    approval_candidates = [
        action for action in actions if action["approval_candidate"] is True
    ]
    return {
        "observed": observed,
        "approved_and_unchanged": approved,
        "unchanged_after_execution": unchanged,
        "postcheck_gaps": observed - unchanged,
        "fully_approved": observed > 0 and approved == observed,
        "approval_gap_entrypoints": sorted(
            _entrypoint_name(tool, role)
            for tool, role, _, approval, _ in states
            if approval is not True
        ),
        "postcheck_gap_entrypoints": sorted(
            _entrypoint_name(tool, role)
            for tool, role, _, _, postcheck in states
            if postcheck is not True
        ),
        "approval_candidate_entrypoints": len(approval_candidates),
        "approval_candidate_unique_digests": len(
            {action["sha256"] for action in approval_candidates}
        ),
        "actions": actions,
    }


def _entrypoint_trust_action(
    state: tuple[str, str, object, object, object],
) -> dict[str, Any]:
    tool, role, digest_value, approval, unchanged = state
    digest = _safe_text(digest_value)
    priority = "P0" if unchanged is False else "P1" if unchanged is not True else "P2"
    required_actions: list[str] = []
    if unchanged is False:
        required_actions.append("quarantine_changed_toolchain")
    elif unchanged is not True:
        required_actions.append("restore_post_execution_verification")
    if approval is not True:
        required_actions.extend(
            ["verify_provenance_before_approval", "approve_exact_digest"]
        )
    approval_candidate = approval is not True and unchanged is True
    field = "auxiliary_executable_sha256" if role == "helper" else "executable_sha256"
    return {
        "entrypoint": _entrypoint_name(tool, role),
        "tool": tool,
        "role": role,
        "sha256": digest,
        "priority": priority,
        "approval_status": "approved" if approval is True else "not_approved",
        "postcheck_status": (
            "unchanged"
            if unchanged is True
            else "changed"
            if unchanged is False
            else "unavailable"
        ),
        "approval_candidate": approval_candidate,
        "configuration_key": f"tools.{tool}.{field}" if approval_candidate else None,
        "required_actions": required_actions,
    }


def _entrypoint_name(tool: str, role: str) -> str:
    return f"{tool}:helper" if role == "helper" else tool


def _trust_priority_rank(priority: object) -> int:
    return {"P0": 0, "P1": 1, "P2": 2}.get(str(priority), 3)


def _bounded_names(values: list[str], *, limit: int = 5) -> str:
    displayed = values[:limit]
    summary = ", ".join(_safe_text(value) for value in displayed)
    omitted = len(values) - len(displayed)
    return f"{summary} (+{omitted} more)" if omitted else summary


def _safe_text(value: object) -> str:
    return sanitize_terminal_text(str(value))


def _safe_web_uri(value: object) -> str:
    uri = _safe_text(value or "").strip()
    try:
        parsed = urlsplit(uri)
    except ValueError:
        return ""
    return uri if parsed.scheme.lower() in {"http", "https"} and parsed.netloc else ""
