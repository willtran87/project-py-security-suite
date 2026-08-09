from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

from .passport import verify_report
from .path_safety import resolve_regular_file

_MAX_REPORTS = 100
_MAX_JSON_BYTES = 128 * 1024 * 1024


def build_operational_trend(
    reports: list[Path],
    *,
    performance_regression_percent: float = 50.0,
    maximum_total_seconds: float | None = None,
    tool_budgets: dict[str, float] | None = None,
) -> dict[str, Any]:
    """Compare multiple independently sealed reports without modifying them."""
    if len(reports) < 2 or len(reports) > _MAX_REPORTS:
        raise ValueError("trend requires between 2 and 100 reports")
    if performance_regression_percent < 0 or performance_regression_percent > 10_000:
        raise ValueError("performance regression percent must be between 0 and 10000")
    if maximum_total_seconds is not None and maximum_total_seconds <= 0:
        raise ValueError("maximum total seconds must be greater than zero")
    budgets = tool_budgets or {}
    if any(not name or seconds <= 0 for name, seconds in budgets.items()):
        raise ValueError("tool budgets require a name and seconds greater than zero")
    timeline = [_snapshot(report) for report in reports]
    timeline.sort(key=lambda item: (str(item["finished_at"]), str(item["scan_id"])))
    seals = [_report_seal(item) for item in timeline]
    if len(set(seals)) != len(seals):
        raise ValueError("trend reports must have distinct checksum seals")
    first, last = timeline[0], timeline[-1]
    statuses = Counter(str(item["outcome"]) for item in timeline)
    scanner_history = _scanner_history(timeline)
    comparison = _comparison(first, last)
    anomalies = _anomalies(
        timeline,
        performance_regression_percent=performance_regression_percent,
        maximum_total_seconds=maximum_total_seconds,
        tool_budgets=budgets,
    )
    return {
        "schema_version": "1.1",
        "authoritative": False,
        "scope": "Longitudinal decision support derived from verified reports; each report remains the evidence authority.",
        "summary": {
            "reports": len(timeline),
            "first_scan": first["scan_id"],
            "last_scan": last["scan_id"],
            "latest_outcome": last["outcome"],
            "outcomes": dict(sorted(statuses.items())),
        },
        "delta": {
            key: int(last[key]) - int(first[key])
            for key in (
                "active_findings",
                "blocking_findings",
                "completed_tools",
                "execution_gaps",
                "unknown_versions",
                "changed_entrypoints",
            )
        },
        "comparison": comparison,
        "scanner_history": scanner_history,
        "anomalies": anomalies,
        "timeline": timeline,
    }


def _report_seal(snapshot: dict[str, Any]) -> str:
    return str(snapshot["checksums_sha256"])


def _snapshot(report: Path) -> dict[str, Any]:
    verification = verify_report(report)
    root = report.expanduser().resolve()
    manifest = _read(root / "scan-manifest.json")
    findings_document = _read(root / "findings.json")
    portfolio = _read(root / "portfolio-health.json")
    findings = findings_document.get("findings")
    tools = manifest.get("tools")
    if not isinstance(findings, list) or not isinstance(tools, list):
        raise TypeError("verified report findings and tools must be arrays")
    active = [
        value
        for value in findings
        if isinstance(value, dict) and value.get("status") != "suppressed"
    ]
    applicable = [
        value
        for value in tools
        if isinstance(value, dict) and value.get("applicable") is not False
    ]
    overall = portfolio.get("overall")
    overall = overall if isinstance(overall, dict) else {}
    identity = {
        "scan_id": verification["scan_id"],
        "checksums_sha256": verification["checksums_sha256"],
        "finished_at": str(
            manifest.get("finished_at") or manifest.get("started_at") or ""
        ),
        "outcome": verification["outcome"],
        "profile": str(manifest.get("profile") or ""),
        "source_sha256": str(findings_document.get("source_sha256") or ""),
        "vcs_revision": str(findings_document.get("vcs_revision") or ""),
    }
    return (
        identity
        | _snapshot_metrics(active, applicable, overall)
        | {
            "finding_ids": sorted(
                str(value.get("finding_id") or value.get("id") or "unknown")
                for value in active
            ),
            "tool_runs": _tool_run_snapshots(tools),
        }
    )


def _snapshot_metrics(
    active: list[dict[str, Any]],
    applicable: list[dict[str, Any]],
    overall: dict[str, Any],
) -> dict[str, Any]:
    return {
        "active_findings": len(active),
        "blocking_findings": sum(value.get("blocking") is True for value in active),
        "completed_tools": sum(
            value.get("status") == "completed" for value in applicable
        ),
        "applicable_tools": len(applicable),
        "execution_gaps": int(overall.get("domains_with_execution_gaps") or 0),
        "unknown_versions": sum(
            str(value.get("version") or "unknown") == "unknown" for value in applicable
        ),
        "changed_entrypoints": sum(
            value.get("executable_unchanged") is False for value in applicable
        ),
        "duration_seconds": round(
            sum(float(value.get("duration_seconds") or 0.0) for value in applicable), 3
        ),
    }


def _tool_run_snapshots(tools: list[object]) -> list[dict[str, Any]]:
    return [
        {
            "tool": str(value.get("tool") or "unknown"),
            "applicable": value.get("applicable") is not False,
            "status": str(value.get("status") or "unknown"),
            "version": str(value.get("version") or "unknown"),
            "duration_seconds": round(float(value.get("duration_seconds") or 0.0), 3),
        }
        for value in sorted(
            (item for item in tools if isinstance(item, dict)),
            key=lambda item: str(item.get("tool") or ""),
        )
    ]


def _comparison(first: dict[str, Any], last: dict[str, Any]) -> dict[str, Any]:
    first_ids = set(str(value) for value in first["finding_ids"])
    last_ids = set(str(value) for value in last["finding_ids"])
    return {
        "new_finding_ids": sorted(last_ids - first_ids),
        "resolved_finding_ids": sorted(first_ids - last_ids),
        "unchanged_finding_ids": sorted(first_ids & last_ids),
        "profile_changed": first["profile"] != last["profile"],
        "source_changed": first["source_sha256"] != last["source_sha256"],
        "revision_changed": first["vcs_revision"] != last["vcs_revision"],
    }


def _scanner_history(timeline: list[dict[str, Any]]) -> list[dict[str, Any]]:
    names = sorted(
        {str(run["tool"]) for snapshot in timeline for run in snapshot["tool_runs"]}
    )
    result: list[dict[str, Any]] = []
    for name in names:
        runs = [
            run
            for snapshot in timeline
            for run in snapshot["tool_runs"]
            if run["tool"] == name
        ]
        applicable = [run for run in runs if run["applicable"] is True]
        completed = sum(run["status"] == "completed" for run in applicable)
        first, last = runs[0], runs[-1]
        first_duration = float(first["duration_seconds"])
        last_duration = float(last["duration_seconds"])
        duration_delta_percent = (
            round((last_duration - first_duration) / first_duration * 100, 2)
            if first_duration > 0
            else None
        )
        result.append(
            {
                "tool": name,
                "observations": len(runs),
                "applicable_runs": len(applicable),
                "completed_runs": completed,
                "completion_percent": round(completed / len(applicable) * 100, 2)
                if applicable
                else None,
                "versions": sorted({str(run["version"]) for run in runs}),
                "first_status": first["status"],
                "last_status": last["status"],
                "first_applicable": first["applicable"],
                "last_applicable": last["applicable"],
                "first_duration_seconds": first_duration,
                "last_duration_seconds": last_duration,
                "duration_delta_percent": duration_delta_percent,
            }
        )
    return result


def _anomalies(
    timeline: list[dict[str, Any]],
    *,
    performance_regression_percent: float,
    maximum_total_seconds: float | None,
    tool_budgets: dict[str, float],
) -> list[dict[str, Any]]:
    previous, latest = timeline[-2], timeline[-1]
    result: list[dict[str, Any]] = []
    if (
        maximum_total_seconds is not None
        and float(latest["duration_seconds"]) > maximum_total_seconds
    ):
        result.append(
            {
                "kind": "scan-performance-budget-exceeded",
                "severity": "review",
                "detail": f"latest scan used {latest['duration_seconds']:.3f}s against a {maximum_total_seconds:.3f}s budget",
                "budget_seconds": maximum_total_seconds,
            }
        )
    if previous["profile"] != latest["profile"]:
        result.append(
            {
                "kind": "profile-change",
                "severity": "review",
                "detail": f"profile changed from {previous['profile']} to {latest['profile']}",
            }
        )
    previous_runs = {run["tool"]: run for run in previous["tool_runs"]}
    latest_runs = {run["tool"]: run for run in latest["tool_runs"]}
    for tool in sorted(set(previous_runs) & set(latest_runs)):
        before, after = previous_runs[tool], latest_runs[tool]
        if (
            before["status"] == "completed"
            and after["applicable"]
            and after["status"] != "completed"
        ):
            result.append(
                {
                    "kind": "scanner-status-regression",
                    "severity": "block",
                    "tool": tool,
                    "detail": f"status regressed from completed to {after['status']}",
                }
            )
        if before["version"] != after["version"]:
            result.append(
                {
                    "kind": "scanner-version-change",
                    "severity": "review",
                    "tool": tool,
                    "detail": f"version changed from {before['version']} to {after['version']}",
                }
            )
        if before["applicable"] != after["applicable"]:
            result.append(
                {
                    "kind": "scanner-applicability-change",
                    "severity": "review",
                    "tool": tool,
                    "detail": f"applicability changed from {before['applicable']} to {after['applicable']}",
                }
            )
        before_duration = float(before["duration_seconds"])
        after_duration = float(after["duration_seconds"])
        budget = tool_budgets.get(tool)
        if budget is not None and after_duration > budget:
            result.append(
                {
                    "kind": "scanner-performance-budget-exceeded",
                    "severity": "review",
                    "tool": tool,
                    "detail": f"duration {after_duration:.3f}s exceeded the {budget:.3f}s budget",
                    "budget_seconds": budget,
                }
            )
        change = (
            (after_duration - before_duration) / before_duration * 100
            if before_duration > 0
            else 0.0
        )
        if change > performance_regression_percent:
            result.append(
                {
                    "kind": "scanner-performance-regression",
                    "severity": "review",
                    "tool": tool,
                    "detail": f"duration increased {change:.2f}% ({before_duration:.3f}s to {after_duration:.3f}s)",
                    "change_percent": round(change, 2),
                }
            )
    return result


def _read(path: Path) -> dict[str, Any]:
    source = resolve_regular_file(path, "trend input")
    if source.stat().st_size > _MAX_JSON_BYTES:
        raise ValueError("trend input exceeds 128 MiB")
    value = json.loads(source.read_bytes())
    if not isinstance(value, dict):
        raise TypeError("trend input root must be an object")
    return value
