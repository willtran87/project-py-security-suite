from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

from .passport import verify_report
from .path_safety import resolve_regular_file

_MAX_REPORTS = 100
_MAX_JSON_BYTES = 128 * 1024 * 1024
_MAX_VALIDATION_SUBJECTS = 10_000
_VALIDATION_RISK = {
    "aligned-current-evidence": 0,
    "coverage-gap": 2,
    "tests-not-observed": 2,
    "test-evidence-not-available": 3,
    "coverage-not-available": 3,
    "tests-incomplete": 4,
    "tests-failing": 5,
    "assessment-truncated": 5,
}


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
        "schema_version": "1.3",
        "authoritative": False,
        "scope": "Longitudinal decision support derived from verified reports; each report remains the evidence authority.",
        "summary": {
            "reports": len(timeline),
            "first_scan": first["scan_id"],
            "last_scan": last["scan_id"],
            "latest_outcome": last["outcome"],
            "outcomes": dict(sorted(statuses.items())),
            "latest_validation_evidence_available": last[
                "validation_evidence_available"
            ],
            "latest_validation_ledger_available": last["validation_ledger_available"],
            "latest_validation_assessment_available": last[
                "validation_assessment_available"
            ],
            "latest_validation_alignment_items": last["validation_alignment_items"],
            "latest_codeowner_backed_validation_items": last[
                "codeowner_backed_validation_items"
            ],
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
                "validation_alignment_items",
                "codeowner_backed_validation_items",
                "validation_items_with_failing_tests",
                "validation_items_with_coverage_gaps",
            )
        },
        "comparison": comparison,
        "validation_owner_history": _validation_owner_history(timeline),
        "scanner_history": scanner_history,
        "anomalies": anomalies,
        "timeline": timeline,
    }


def render_operational_trend_markdown(trend: dict[str, Any]) -> str:
    """Render a bounded GitHub-readable view of the machine trend artifact."""
    summary = _object(trend.get("summary"))
    delta = _object(trend.get("delta"))
    comparison = _object(trend.get("comparison"))
    timeline = _object_list(trend.get("timeline"))
    first = timeline[0] if timeline else {}
    latest = timeline[-1] if timeline else {}
    comparable = comparison.get("validation_evidence_comparable") is True
    lines = [
        "# Operational assurance trend",
        "",
        "> Decision support from independently verified reports; each sealed report remains the evidence authority.",
        "",
        f"- **Reports:** {int(summary.get('reports') or 0)}",
        f"- **Window:** `{_md(summary.get('first_scan'))}` → `{_md(summary.get('last_scan'))}`",
        f"- **Latest outcome:** `{_md(summary.get('latest_outcome'))}`",
        f"- **Validation evidence comparable:** {'Yes' if comparable else 'No'}",
        "",
        "## First-to-latest movement",
        "",
        "| Measure | First | Latest | Delta |",
        "|---|---:|---:|---:|",
    ]
    for key, label in (
        ("active_findings", "Active findings"),
        ("blocking_findings", "Blocking findings"),
        ("validation_alignment_items", "Validation debt subjects"),
        ("codeowner_backed_validation_items", "CODEOWNERS-routed validation subjects"),
        (
            "validation_items_with_failing_tests",
            "Validation subjects with failing tests",
        ),
        (
            "validation_items_with_coverage_gaps",
            "Validation subjects with coverage gaps",
        ),
        ("completed_tools", "Completed tools"),
        ("execution_gaps", "Execution gaps"),
    ):
        delta_value = (
            "not comparable"
            if not comparable
            and key
            in {
                "validation_alignment_items",
                "codeowner_backed_validation_items",
                "validation_items_with_failing_tests",
                "validation_items_with_coverage_gaps",
            }
            else _signed(delta.get(key))
        )
        lines.append(
            f"| {label} | {int(first.get(key) or 0)} | {int(latest.get(key) or 0)} | {delta_value} |"
        )
    lines.extend(
        [
            "",
            "## Validation continuity",
            "",
            (
                "Closure-plan 1.2 ledgers and change-assessment scopes are comparable across the first and latest reports."
                if comparable
                else "**Comparability gap:** compatible closure ledgers and change-assessment scope are not present in both endpoint reports; no new or resolved debt claim is made."
            ),
            "",
            "| New subjects | Resolved subjects | Unchanged subjects | State/owner transitions |",
            "|---:|---:|---:|---:|",
            (
                f"| {len(_strings(comparison.get('new_validation_subject_ids')))} | "
                f"{len(_strings(comparison.get('resolved_validation_subject_ids')))} | "
                f"{len(_strings(comparison.get('unchanged_validation_subject_ids')))} | "
                f"{len(_object_list(comparison.get('validation_state_transitions')))} |"
            ),
            "",
        ]
    )
    reasons = _strings(comparison.get("validation_comparability_reasons"))
    if reasons:
        lines.extend(
            [
                "**Why comparison is unavailable:**",
                "",
                *(f"- {_md(reason)}" for reason in reasons),
                "",
            ]
        )
    owner_history = _object_list(trend.get("validation_owner_history"))
    if owner_history:
        lines.extend(
            [
                "### Validation owner queues",
                "",
                "| Owner | First subjects | Latest subjects | Delta |",
                "|---|---:|---:|---:|",
            ]
        )
        lines.extend(
            (
                f"| `{_md(item.get('owner'))}` | {int(item.get('first_subjects') or 0)} | "
                f"{int(item.get('latest_subjects') or 0)} | {_signed(item.get('delta'))} |"
            )
            for item in owner_history[:100]
        )
        if len(owner_history) > 100:
            lines.append(
                f"| … |  |  | {len(owner_history) - 100} owner queue(s) omitted |"
            )
        lines.append("")
    transitions = _object_list(comparison.get("validation_state_transitions"))
    if transitions:
        lines.extend(
            [
                "### Validation state and routing transitions",
                "",
                "| Subject | Path | State | Owner | Priority |",
                "|---|---|---|---|---|",
            ]
        )
        lines.extend(
            (
                f"| `{_md(item.get('id'))}` | `{_md(item.get('path'))}` | "
                f"`{_md(item.get('alignment_before'))}` → `{_md(item.get('alignment_after'))}` | "
                f"`{_md(item.get('owner_before'))}` → `{_md(item.get('owner_after'))}` | "
                f"`{_md(item.get('priority_before'))}` → `{_md(item.get('priority_after'))}` |"
            )
            for item in transitions[:100]
        )
        if len(transitions) > 100:
            lines.append(
                f"| … | {len(transitions) - 100} transition(s) omitted |  |  |  |"
            )
        lines.append("")
    lines.extend(_render_trend_anomalies(_object_list(trend.get("anomalies"))))
    lines.extend(_render_scanner_history(_object_list(trend.get("scanner_history"))))
    lines.extend(
        [
            "## Scan timeline",
            "",
            "| Scan | Finished | Outcome | Findings | Validation debt | Validation evidence | Duration (s) |",
            "|---|---|---|---:|---:|---|---:|",
        ]
    )
    lines.extend(
        (
            f"| `{_md(item.get('scan_id'))}` | {_md(item.get('finished_at'))} | "
            f"`{_md(item.get('outcome'))}` | {int(item.get('active_findings') or 0)} | "
            f"{int(item.get('validation_alignment_items') or 0)} | "
            f"{'available' if item.get('validation_evidence_available') is True else 'missing'} | "
            f"{float(item.get('duration_seconds') or 0.0):.3f} |"
        )
        for item in timeline
    )
    return "\n".join(lines).rstrip() + "\n"


def _report_seal(snapshot: dict[str, Any]) -> str:
    return str(snapshot["checksums_sha256"])


def _snapshot(report: Path) -> dict[str, Any]:
    verification = verify_report(report)
    root = report.expanduser().resolve()
    manifest = _read(root / "scan-manifest.json")
    findings_document = _read(root / "findings.json")
    portfolio = _read(root / "portfolio-health.json")
    closure = _optional_read(root / "closure-plan.json")
    diff_coverage = _optional_read(root / "diff-coverage.json")
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
    validation = _validation_snapshot(closure, diff_coverage)
    return (
        identity
        | _snapshot_metrics(active, applicable, overall)
        | validation
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


def _validation_snapshot(
    closure: dict[str, Any], diff_coverage: dict[str, Any]
) -> dict[str, Any]:
    summary = closure.get("summary")
    items = closure.get("items")
    assessment = _validation_assessment(diff_coverage)
    ledger_available = (
        closure.get("schema_version") == "1.2"
        and isinstance(summary, dict)
        and isinstance(items, list)
    )
    if (
        not ledger_available
        or not isinstance(summary, dict)
        or not isinstance(items, list)
    ):
        return {
            "validation_evidence_available": False,
            "validation_ledger_available": False,
            "validation_assessment_available": assessment["available"],
            "validation_assessment_reason": assessment["reason"],
            "validation_assessment_scope": assessment["scope"],
            "validation_alignment_items": 0,
            "codeowner_backed_validation_items": 0,
            "validation_items_with_failing_tests": 0,
            "validation_items_with_coverage_gaps": 0,
            "validation_subjects": [],
        }
    subjects: list[dict[str, Any]] = []
    for item in items[:_MAX_VALIDATION_SUBJECTS]:
        if not isinstance(item, dict):
            continue
        details = item.get("details")
        if not isinstance(details, dict) or not details.get("validation_alignment"):
            continue
        subject_id = str(item.get("id") or "")
        if not subject_id:
            continue
        owners = details.get("owners")
        owner_values = (
            [str(value) for value in owners[:20] if value]
            if isinstance(owners, list)
            else []
        )
        subjects.append(
            {
                "id": subject_id,
                "path": str(details.get("path") or ""),
                "owner": str(item.get("owner") or "Unassigned"),
                "owners": owner_values,
                "ownership_rule_matched": details.get("ownership_rule_matched") is True,
                "alignment": str(details.get("validation_alignment")),
                "priority": str(item.get("priority") or "P3"),
            }
        )
    subjects.sort(key=lambda value: str(value["id"]))
    return {
        "validation_evidence_available": assessment["available"],
        "validation_ledger_available": True,
        "validation_assessment_available": assessment["available"],
        "validation_assessment_reason": assessment["reason"],
        "validation_assessment_scope": assessment["scope"],
        "validation_alignment_items": int(
            summary.get("validation_alignment_items") or 0
        ),
        "codeowner_backed_validation_items": int(
            summary.get("codeowner_backed_validation_items") or 0
        ),
        "validation_items_with_failing_tests": int(
            summary.get("validation_items_with_failing_tests") or 0
        ),
        "validation_items_with_coverage_gaps": int(
            summary.get("validation_items_with_coverage_gaps") or 0
        ),
        "validation_subjects": subjects,
    }


def _validation_assessment(diff_coverage: dict[str, Any]) -> dict[str, Any]:
    stats = diff_coverage.get("src_stats")
    diff_name = diff_coverage.get("diff_name")
    changed_lines = diff_coverage.get("num_changed_lines")
    if (
        diff_coverage.get("schema_version") != "1.0"
        or not isinstance(stats, dict)
        or not isinstance(diff_name, str)
        or not diff_name.strip()
        or not isinstance(changed_lines, int)
        or isinstance(changed_lines, bool)
        or changed_lines < 0
    ):
        return {
            "available": False,
            "reason": "current diff-coverage change-assessment evidence is unavailable",
            "scope": None,
        }
    return {
        "available": True,
        "reason": "changed-file scope is backed by retained diff-coverage evidence",
        "scope": {
            "diff_name": diff_name.strip(),
            "changed_files": len(stats),
            "changed_lines": changed_lines,
            "minimum_percent": float(diff_coverage.get("minimum_percent") or 0.0),
        },
    }


def _validation_subject_changed(before: dict[str, Any], after: dict[str, Any]) -> bool:
    return any(
        before.get(field) != after.get(field)
        for field in ("owner", "alignment", "priority", "ownership_rule_matched")
    )


def _validation_owner_delta(
    before: dict[str, dict[str, Any]], after: dict[str, dict[str, Any]]
) -> list[dict[str, Any]]:
    before_counts = Counter(
        str(value.get("owner") or "Unassigned") for value in before.values()
    )
    after_counts = Counter(
        str(value.get("owner") or "Unassigned") for value in after.values()
    )
    return [
        {
            "owner": owner,
            "subjects_before": before_counts[owner],
            "subjects_after": after_counts[owner],
            "delta": after_counts[owner] - before_counts[owner],
        }
        for owner in sorted(set(before_counts) | set(after_counts))
    ]


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
    first_validation = {
        str(value["id"]): value for value in first["validation_subjects"]
    }
    last_validation = {str(value["id"]): value for value in last["validation_subjects"]}
    first_validation_ids = set(first_validation)
    last_validation_ids = set(last_validation)
    common_validation_ids = first_validation_ids & last_validation_ids
    transitions = [
        {
            "id": subject_id,
            "path": last_validation[subject_id].get("path")
            or first_validation[subject_id].get("path"),
            "owner_before": first_validation[subject_id].get("owner"),
            "owner_after": last_validation[subject_id].get("owner"),
            "alignment_before": first_validation[subject_id].get("alignment"),
            "alignment_after": last_validation[subject_id].get("alignment"),
            "priority_before": first_validation[subject_id].get("priority"),
            "priority_after": last_validation[subject_id].get("priority"),
        }
        for subject_id in sorted(common_validation_ids)
        if _validation_subject_changed(
            first_validation[subject_id], last_validation[subject_id]
        )
    ]
    validation_comparable = bool(first["validation_evidence_available"]) and bool(
        last["validation_evidence_available"]
    )
    comparability_reasons = _validation_comparability_reasons(first, last)
    return {
        "new_finding_ids": sorted(last_ids - first_ids),
        "resolved_finding_ids": sorted(first_ids - last_ids),
        "unchanged_finding_ids": sorted(first_ids & last_ids),
        "profile_changed": first["profile"] != last["profile"],
        "source_changed": first["source_sha256"] != last["source_sha256"],
        "revision_changed": first["vcs_revision"] != last["vcs_revision"],
        "validation_evidence_comparable": validation_comparable,
        "validation_comparability_reasons": comparability_reasons,
        "new_validation_subject_ids": (
            sorted(last_validation_ids - first_validation_ids)
            if validation_comparable
            else []
        ),
        "resolved_validation_subject_ids": (
            sorted(first_validation_ids - last_validation_ids)
            if validation_comparable
            else []
        ),
        "unchanged_validation_subject_ids": (
            sorted(common_validation_ids) if validation_comparable else []
        ),
        "validation_state_transitions": transitions if validation_comparable else [],
        "validation_owner_delta": (
            _validation_owner_delta(first_validation, last_validation)
            if validation_comparable
            else []
        ),
    }


def _validation_comparability_reasons(
    first: dict[str, Any], last: dict[str, Any]
) -> list[str]:
    reasons: list[str] = []
    for label, snapshot in (("first", first), ("latest", last)):
        if snapshot.get("validation_ledger_available") is not True:
            reasons.append(f"{label} report lacks a current closure-plan 1.2 ledger")
        if snapshot.get("validation_assessment_available") is not True:
            reasons.append(
                f"{label} report lacks retained diff-coverage change-assessment scope"
            )
    return reasons


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


def _validation_owner_history(
    timeline: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    owners = sorted(
        {
            str(subject.get("owner") or "Unassigned")
            for snapshot in timeline
            for subject in snapshot["validation_subjects"]
        }
    )
    result: list[dict[str, Any]] = []
    for owner in owners:
        observations = [
            {
                "scan_id": snapshot["scan_id"],
                "evidence_available": snapshot["validation_evidence_available"],
                "subjects": sum(
                    str(subject.get("owner") or "Unassigned") == owner
                    for subject in snapshot["validation_subjects"]
                ),
            }
            for snapshot in timeline
        ]
        result.append(
            {
                "owner": owner,
                "observations": observations,
                "first_subjects": observations[0]["subjects"],
                "latest_subjects": observations[-1]["subjects"],
                "comparable": all(
                    observation["evidence_available"] for observation in observations
                ),
                "delta": (
                    observations[-1]["subjects"] - observations[0]["subjects"]
                    if all(
                        observation["evidence_available"]
                        for observation in observations
                    )
                    else None
                ),
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
    result.extend(_validation_anomalies(previous, latest))
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


def _validation_anomalies(
    previous: dict[str, Any], latest: dict[str, Any]
) -> list[dict[str, Any]]:
    before_available = previous["validation_evidence_available"] is True
    after_available = latest["validation_evidence_available"] is True
    if not before_available or not after_available:
        reasons = _validation_comparability_reasons(previous, latest)
        return [
            {
                "kind": "validation-evidence-comparability-gap",
                "severity": "review",
                "detail": (
                    "validation comparison is unavailable: " + "; ".join(reasons)
                ),
                "reasons": reasons,
            }
        ]
    result: list[dict[str, Any]] = []
    before_total = int(previous["validation_alignment_items"])
    after_total = int(latest["validation_alignment_items"])
    if after_total > before_total:
        result.append(
            {
                "kind": "validation-debt-regression",
                "severity": "review",
                "detail": (
                    f"validation subjects increased from {before_total} to {after_total}"
                ),
                "subjects_before": before_total,
                "subjects_after": after_total,
            }
        )
    before_owned = int(previous["codeowner_backed_validation_items"])
    after_owned = int(latest["codeowner_backed_validation_items"])
    before_coverage = before_owned / before_total if before_total else 1.0
    after_coverage = after_owned / after_total if after_total else 1.0
    if after_coverage < before_coverage:
        result.append(
            {
                "kind": "validation-ownership-regression",
                "severity": "review",
                "detail": (
                    "CODEOWNERS-backed validation routing decreased from "
                    f"{before_coverage * 100:.2f}% to {after_coverage * 100:.2f}%"
                ),
                "coverage_before_percent": round(before_coverage * 100, 2),
                "coverage_after_percent": round(after_coverage * 100, 2),
            }
        )
    before_subjects = {
        str(value["id"]): value for value in previous["validation_subjects"]
    }
    after_subjects = {
        str(value["id"]): value for value in latest["validation_subjects"]
    }
    for subject_id in sorted(set(before_subjects) & set(after_subjects)):
        before = before_subjects[subject_id]
        after = after_subjects[subject_id]
        before_state = str(before.get("alignment") or "")
        after_state = str(after.get("alignment") or "")
        if _VALIDATION_RISK.get(after_state, 3) <= _VALIDATION_RISK.get(
            before_state, 3
        ):
            continue
        result.append(
            {
                "kind": "validation-state-regression",
                "severity": "block" if after_state == "tests-failing" else "review",
                "subject_id": subject_id,
                "path": after.get("path") or before.get("path"),
                "owner": after.get("owner"),
                "state_before": before_state,
                "state_after": after_state,
                "detail": (
                    f"validation state regressed from {before_state} to {after_state}"
                ),
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


def _optional_read(path: Path) -> dict[str, Any]:
    return _read(path) if path.is_file() else {}


def _render_trend_anomalies(anomalies: list[dict[str, Any]]) -> list[str]:
    lines = [
        "## Review anomalies",
        "",
        "| Severity | Kind | Subject | Detail |",
        "|---|---|---|---|",
    ]
    if not anomalies:
        lines.append(
            "| — | none | — | No configured regression anomaly was detected. |"
        )
        return [*lines, ""]
    for item in anomalies[:100]:
        subject = item.get("subject_id") or item.get("tool") or item.get("path") or "—"
        lines.append(
            f"| `{_md(item.get('severity'))}` | `{_md(item.get('kind'))}` | "
            f"`{_md(subject)}` | {_md(item.get('detail'))} |"
        )
    if len(anomalies) > 100:
        lines.append(
            f"| review | omitted | — | {len(anomalies) - 100} anomaly record(s) omitted. |"
        )
    return [*lines, ""]


def _render_scanner_history(history: list[dict[str, Any]]) -> list[str]:
    lines = [
        "## Scanner reliability",
        "",
        "| Tool | Applicable runs | Completed | Completion | First → latest status | Versions | Duration delta |",
        "|---|---:|---:|---:|---|---|---:|",
    ]
    if not history:
        lines.append("| — | 0 | 0 | — | — | — | — |")
        return [*lines, ""]
    for item in history[:200]:
        completion = item.get("completion_percent")
        duration = item.get("duration_delta_percent")
        completion_text = (
            f"{float(completion):.2f}%" if isinstance(completion, (int, float)) else "—"
        )
        duration_text = (
            f"{float(duration):+.2f}%" if isinstance(duration, (int, float)) else "—"
        )
        lines.append(
            f"| `{_md(item.get('tool'))}` | {int(item.get('applicable_runs') or 0)} | "
            f"{int(item.get('completed_runs') or 0)} | {completion_text} | "
            f"`{_md(item.get('first_status'))}` → `{_md(item.get('last_status'))}` | "
            f"{_md(', '.join(_strings(item.get('versions'))))} | {duration_text} |"
        )
    if len(history) > 200:
        lines.append(f"| … |  |  |  |  | {len(history) - 200} tool(s) omitted |  |")
    return [*lines, ""]


def _object(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _object_list(value: Any) -> list[dict[str, Any]]:
    return (
        [item for item in value if isinstance(item, dict)]
        if isinstance(value, list)
        else []
    )


def _strings(value: Any) -> list[str]:
    return [str(item) for item in value if item] if isinstance(value, list) else []


def _md(value: Any) -> str:
    return str(value or "").replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def _signed(value: Any) -> str:
    if value is None:
        return "not comparable"
    number = int(value or 0)
    return f"{number:+d}" if number else "0"
