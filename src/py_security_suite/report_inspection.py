from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

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


def inspect_report(report: Path, *, limit: int = 5) -> dict[str, Any]:
    """Verify and summarize a report without trusting its HTML or Markdown."""
    if limit < 0 or limit > 100:
        raise ValueError("inspection limit must be between 0 and 100")
    root = report.expanduser().resolve()
    verification = verify_report(root)
    manifest = _read_object(root / "scan-manifest.json")
    findings_document = _read_object(root / "findings.json")
    findings = findings_document.get("findings")
    tools = manifest.get("tools")
    if not isinstance(findings, list) or not all(
        isinstance(item, dict) for item in findings
    ):
        raise ValueError("report findings must be a list of objects")
    if not isinstance(tools, list) or not all(isinstance(item, dict) for item in tools):
        raise ValueError("report tools must be a list of objects")

    severity = Counter(str(item.get("severity") or "unknown") for item in findings)
    domains = Counter(str(item.get("domain") or "unknown") for item in findings)
    lifecycle = Counter(str(item.get("status") or "unknown") for item in findings)
    tool_health = Counter(str(item.get("status") or "unknown") for item in tools)
    sorted_findings = sorted(findings, key=_finding_key)
    return {
        "schema_version": "1.0",
        "verified": True,
        "scan": {
            "id": manifest.get("scan_id"),
            "target": manifest.get("target"),
            "profile": manifest.get("profile"),
            "outcome": manifest.get("outcome"),
            "duration_seconds": manifest.get("duration_seconds"),
            "finished_at": manifest.get("finished_at"),
        },
        "findings": {
            "total": len(findings),
            "blocking": sum(bool(item.get("blocking")) for item in findings),
            "by_severity": dict(sorted(severity.items())),
            "by_domain": dict(sorted(domains.items())),
            "by_lifecycle": dict(sorted(lifecycle.items())),
        },
        "tool_health": {
            "selected": len(tools),
            "by_status": dict(sorted(tool_health.items())),
        },
        "policy_reasons": manifest.get("policy_reasons") or [],
        "top_actions": [_action(item) for item in sorted_findings[:limit]],
        "integrity": {
            "files_verified": verification["file_count"],
            "checksums_sha256": verification["checksums_sha256"],
        },
        "entrypoints": {
            "html": str(root / "index.html"),
            "summary": str(root / "summary.md"),
            "action_plan": str(root / "action-plan.md"),
        },
    }


def render_inspection(document: dict[str, Any]) -> str:
    """Render a compact summary suited to terminals and release logs."""
    scan = document["scan"]
    findings = document["findings"]
    health = document["tool_health"]
    status = health["by_status"]
    lines = [
        (
            f"{str(scan['outcome']).upper()}: {scan['target']} "
            f"({scan['profile']}; {scan['id']})"
        ),
        (
            f"Findings: {findings['total']} total, {findings['blocking']} blocking; "
            f"severity {_counts(findings['by_severity'])}"
        ),
        (
            f"Tools: {status.get('completed', 0)} completed, "
            f"{status.get('skipped', 0)} not applicable, "
            f"{_problem_tool_count(status)} with execution problems"
        ),
        f"Domains: {_counts(findings['by_domain'])}",
        f"Lifecycle: {_counts(findings['by_lifecycle'])}",
    ]
    actions = document["top_actions"]
    if actions:
        lines.append("Top actions:")
        for item in actions:
            location = item["path"]
            if item["line"] is not None:
                location = f"{location}:{item['line']}"
            lines.append(
                f"- [{str(item['severity']).upper()}] {item['title']} — "
                f"{location} — {', '.join(item['tools'])}"
            )
    lines.extend(
        [
            (
                f"Integrity: {document['integrity']['files_verified']} report files "
                "verified"
            ),
            f"Open: {document['entrypoints']['html']}",
        ]
    )
    return "\n".join(lines)


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
    locations = item.get("locations") or []
    location = locations[0] if locations and isinstance(locations[0], dict) else {}
    sources = item.get("sources") or []
    tools = sorted(
        {
            str(source.get("tool"))
            for source in sources
            if isinstance(source, dict) and source.get("tool")
        }
    )
    evidence = item.get("evidence") or {}
    owners = evidence.get("owners") if isinstance(evidence, dict) else []
    return {
        "finding_id": item.get("finding_id"),
        "title": item.get("title"),
        "severity": item.get("severity"),
        "status": item.get("status"),
        "domain": item.get("domain"),
        "path": location.get("path", "<repository>"),
        "line": location.get("start_line"),
        "tools": tools,
        "owners": owners if isinstance(owners, list) else [],
    }


def _counts(values: dict[str, int]) -> str:
    return ", ".join(f"{name}={count}" for name, count in values.items()) or "none"


def _problem_tool_count(values: dict[str, int]) -> int:
    return sum(
        count for name, count in values.items() if name not in {"completed", "skipped"}
    )
