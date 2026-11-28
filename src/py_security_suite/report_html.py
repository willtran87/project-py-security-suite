"""Self-contained HTML report (report.html) rendering."""

from __future__ import annotations

import html
from typing import Any

from .admission import admission_decisions
from .models import Citation, Finding, FindingStatus, ScanManifest, Severity, ToolRun
from .portfolio_health import activation_recipe, portfolio_health_artifact
from .report_references import TOOL_REFERENCES as _TOOL_REFERENCES
from .report_common import (
    _advanced_taint_alignment_counts,
    _applicable_scanner_gaps,
    _applicable_tools,
    _area_summary,
    _artifact_identity,
    _campaign_route_assurance_text,
    _campaign_shared_test_quality_text,
    _change_lifecycle_text,
    _classification_uri,
    _completed_tools,
    _coverage_action,
    _dependency_usage_summary,
    _entry_point_exposure_text,
    _entry_runtime_status_text,
    _entrypoint_integrity_counts,
    _evidence_assurance_text,
    _executable_integrity_label,
    _exposure_cross_reference_signals,
    _finding_priority,
    _finding_sort_key,
    _graph_corroboration_text,
    _line_is_highlighted,
    _location_text,
    _missing_source_evidence_text,
    _next_action_for_manifest,
    _not_applicable_scanners,
    _owner_values,
    _package_lifecycle_text,
    _policy_decision_value,
    _primary_snippet_location,
    _reference_uri,
    _remediation_context_summary,
    _report_release_status,
    _risk_campaign_control_text,
    _risk_campaign_factor_text,
    _risk_path_validation_signals,
    _route_applicability_text,
    _route_ownership_text,
    _safe_http_reference,
    _sdk_dependency_context_summary,
    _secret_membership_text,
    _source_version,
    _threat_intelligence_summary,
    _unrouted_structural_context_text,
)


__all__ = [
    "_html_risk_path_context",
    "_html_secret_provenance_context",
    "_html_unrouted_structural_summary",
    "render_html",
]


def _risk_advisory_citations_html(value: Any) -> str:
    if not isinstance(value, list):
        return ""
    citations: list[str] = []
    for item in value[:5]:
        if not isinstance(item, dict):
            continue
        identifier = html.escape(str(item.get("identifier") or "reference"))
        uri_value = item.get("uri")
        uri = _safe_http_reference(uri_value) if isinstance(uri_value, str) else None
        citations.append(
            f"<a href='{html.escape(uri, quote=True)}' rel='noreferrer'>{identifier}</a>"
            if uri
            else f"<code>{identifier}</code>"
        )
    return ", ".join(citations)


def _html_finding_cards(ordered: list[Finding], tool_versions: dict[str, str]) -> str:
    return "".join(
        _render_html_finding(finding, tool_versions) for finding in ordered
    ) or (
        "<section class='empty'><h3>No normalized findings</h3>"
        "<p>The selected scanners completed without reporting a finding.</p></section>"
    )


def _html_finding_rows(ordered: list[Finding]) -> str:
    return "".join(
        "<tr>"
        f"<td><span class='badge {html.escape(finding.severity.value)}'>"
        f"{html.escape(_finding_priority(finding))}</span></td>"
        f"<td>{html.escape(finding.severity.value.upper())}</td>"
        f"<td><a href='#{html.escape(finding.finding_id, quote=True)}'>"
        f"<strong>{html.escape(finding.title)}</strong></a><br>"
        f"<code>{html.escape(finding.finding_id)}</code></td>"
        f"<td><code>{html.escape(_location_text(finding))}</code></td>"
        f"<td>{html.escape(_finding_tools(finding))}</td>"
        f"<td>{html.escape(finding.remediation)}</td>"
        "</tr>"
        for finding in ordered
    ) or ("<tr><td colspan='6'>No normalized findings require review.</td></tr>")


def _html_policy_reasons(manifest: ScanManifest) -> str:
    return (
        "".join(f"<li>{html.escape(reason)}</li>" for reason in manifest.policy_reasons)
        or "<li>No policy reason was recorded.</li>"
    )


def _html_coverage_gap_rows(
    manifest: ScanManifest, coverage_gaps: list[ToolRun]
) -> str:
    return "".join(
        "<tr>"
        f"<td><strong>{html.escape(run.tool)}</strong></td>"
        f"<td>{'applicable' if run.applicable else 'not applicable'}</td>"
        f"<td><span class='status {html.escape(run.status.value)}'>"
        f"{html.escape(run.status.value)}</span></td>"
        f"<td>{html.escape(run.error or 'No diagnostic supplied')}</td>"
        f"<td>{html.escape(_coverage_action(run, manifest))}</td>"
        f"<td>{_html_tool_reference(run.tool)}</td>"
        "</tr>"
        for run in coverage_gaps
    ) or (
        "<tr><td>All applicable tools</td><td>applicable</td>"
        "<td>completed</td><td>-</td><td>No action</td><td>-</td></tr>"
    )


def _html_not_applicable_details(not_applicable: list[ToolRun]) -> str:
    if not not_applicable:
        return ""
    rows = "".join(_html_activation_recipe(run) for run in not_applicable)
    return (
        "<details class='coverage-details'><summary>"
        f"{len(not_applicable)} not-applicable controls (informational)"
        "</summary><table><thead><tr><th>Tool</th><th>Category</th>"
        "<th>Owner</th><th>Activation trigger</th><th>Required evidence</th>"
        "<th>Action</th><th>Reference</th></tr></thead>"
        f"<tbody>{rows}</tbody></table></details>"
    )


def _html_activation_recipe(run: ToolRun) -> str:
    recipe = activation_recipe(run)
    return (
        "<tr>"
        f"<td><strong>{html.escape(run.tool)}</strong></td>"
        f"<td>{html.escape(recipe['category'])}</td>"
        f"<td>{html.escape(recipe['owner'])}</td>"
        f"<td>{html.escape(recipe['activation_trigger'])}</td>"
        f"<td>{html.escape(recipe['evidence_required'])}</td>"
        f"<td>{html.escape(recipe['required_action'])}</td>"
        f"<td>{_html_tool_reference(run.tool)}</td>"
        "</tr>"
    )


def _html_tool_rows(tools: list[ToolRun]) -> str:
    return "".join(
        "<tr>"
        f"<td><strong>{html.escape(run.tool)}</strong></td>"
        f"<td>{html.escape(run.version)}</td>"
        f"<td>{'applicable' if run.applicable else 'not applicable'}</td>"
        f"<td><span class='status {html.escape(run.status.value)}'>"
        f"{html.escape(run.status.value)}</span></td>"
        f"<td>{html.escape(_executable_integrity_label(run))}</td>"
        f"<td>{run.finding_count}</td>"
        f"<td>{run.duration_seconds:.3f}s</td>"
        f"<td>{html.escape(run.error or 'None')}</td>"
        "</tr>"
        for run in tools
    )


def _html_area_rows(active_findings: list[Finding]) -> str:
    return (
        "".join(
            "<tr>"
            f"<td><strong>{html.escape(area)}</strong></td>"
            f"<td>{area_counts['critical']}</td>"
            f"<td>{area_counts['high']}</td>"
            f"<td>{area_counts['medium']}</td>"
            f"<td>{area_counts['low']}</td>"
            f"<td>{area_counts['informational'] + area_counts['unknown']}</td>"
            f"<td>{area_counts['total']}</td>"
            "</tr>"
            for area, area_counts in _area_summary(active_findings)
        )
        or "<tr><td>No findings</td><td colspan='6'>0</td></tr>"
    )


def _severity_counts(findings: list[Finding]) -> dict[str, int]:
    return {
        severity.value: sum(finding.severity is severity for finding in findings)
        for severity in Severity
    }


def _html_admission_cards(manifest: ScanManifest, findings: list[Finding]) -> str:
    decisions = admission_decisions(
        findings,
        manifest.tools,
        network_isolation_attested=manifest.network_isolation_attested,
        source_integrity_verified=manifest.inventory.source_integrity_verified,
    )
    cards: list[str] = []
    for row in decisions["axes"]:
        gaps = [*row["execution_gaps"], *row["integrity_gaps"]]
        gap_text = "; ".join(gaps) or "No axis-specific evidence gaps."
        cards.append(
            f'<article class="axis-card {html.escape(row["decision"])}">'
            f'<div class="axis-heading"><h3>{html.escape(row["label"])}</h3>'
            f'<span class="decision-badge {html.escape(row["decision"])}">'
            f"{html.escape(row['decision'].upper())}</span></div>"
            f"<p>{html.escape(row['purpose'])}</p>"
            f"<p><strong>Coverage:</strong> {row['completed_tools']}/"
            f"{row['applicable_tools']} applicable completed &middot; "
            f"{row['active_findings']} finding(s) &middot; "
            f"{row['blocking_findings']} blocking</p>"
            f"<p><strong>Evidence:</strong> {html.escape(gap_text)}</p>"
            f"<p><strong>Action:</strong> {html.escape(row['required_action'])}</p>"
            "</article>"
        )
    return "".join(cards)


def _html_unrouted_structural_summary(value: dict[str, Any] | None) -> str:
    if not isinstance(value, dict) or not isinstance(value.get("summary"), dict):
        return ""
    summary = value["summary"]
    raw = value.get("unrouted_structural_intersections")
    intersections = raw if isinstance(raw, list) else []
    availability = value.get("evidence_availability")
    availability = availability if isinstance(availability, dict) else {}
    rows: list[str] = []
    for item in intersections[:10]:
        if not isinstance(item, dict):
            continue
        owners = item.get("coordination_owners")
        owner_values = owners if isinstance(owners, list) else []
        candidate_entries = item.get("candidate_entry_paths")
        entry_values = candidate_entries if isinstance(candidate_entries, list) else []
        tests = item.get("direct_test_files")
        test_values = tests if isinstance(tests, list) else []
        validation = item.get("target_validation")
        validation = validation if isinstance(validation, dict) else {}
        location = str(item.get("path") or "unknown") + (
            f":{int(item['line'])}" if isinstance(item.get("line"), int) else ""
        )
        rows.append(
            "<tr><td><code>"
            + html.escape(str(item.get("priority") or "P4"))
            + "</code><br><code>"
            + html.escape(location)
            + "</code><br>"
            + html.escape(str(item.get("target_kind") or "unknown"))
            + "</td><td><code>"
            + html.escape(str(item.get("island_id") or "unknown"))
            + "</code><br>state <code>"
            + html.escape(str(item.get("island_state") or "unknown"))
            + "</code><br>boundary <code>"
            + html.escape(str(item.get("boundary_classification") or "not-established"))
            + "</code><br>membership <code>"
            + html.escape(str(item.get("evidence_basis") or "unknown"))
            + "</code></td><td><code>"
            + html.escape(str(item.get("risk_signal") or "unknown"))
            + "</code><br><strong>"
            + html.escape(str(item.get("decision") or "review"))
            + "</strong>"
            + (
                "<br>Candidate entry: "
                + ", ".join(
                    "<code>" + html.escape(str(path)) + "</code>"
                    for path in entry_values[:3]
                )
                if entry_values
                else ""
            )
            + "</td><td>Validation <code>"
            + html.escape(str(validation.get("assessment_status") or "not-assessed"))
            + "</code>"
            + (
                "<br>Tests: "
                + ", ".join(
                    "<code>" + html.escape(str(path)) + "</code>"
                    for path in test_values[:3]
                )
                if test_values
                else "<br>Tests: not mapped"
            )
            + "<br>Owner: "
            + html.escape(", ".join(map(str, owner_values)) or "unassigned")
            + "<br>"
            + html.escape(str(item.get("recommended_action") or "Review."))
            + "</td></tr>"
        )
    retained_note = (
        f" Showing the first {len(rows)} of {len(intersections)} retained intersections."
        if intersections
        else " No exact retained intersections were found."
    )
    evidence_state = (
        "available"
        if availability.get("structural_synthesis") is True
        else "not available"
    )
    table = (
        "<table><thead><tr><th>Priority / target</th><th>Island / evidence</th>"
        "<th>Decision</th><th>Validation / owner / action</th></tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table>"
        if rows
        else ""
    )
    return (
        "<section aria-labelledby='unrouted-structural-heading'>"
        "<h2 id='unrouted-structural-heading'>Unrouted target / structural-island decisions</h2>"
        "<p><strong>Intersections:</strong> "
        + str(int(summary.get("unrouted_structural_intersections") or 0))
        + "; <strong>disconnected targets:</strong> "
        + str(int(summary.get("unrouted_targets_in_disconnected_islands") or 0))
        + "; <strong>runtime counter-evidence:</strong> "
        + str(int(summary.get("unrouted_targets_with_runtime_counter_evidence") or 0))
        + "; <strong>dead-code corroboration:</strong> "
        + str(int(summary.get("unrouted_targets_with_dead_code_corroboration") or 0))
        + ". Structural synthesis is <strong>"
        + evidence_state
        + "</strong>."
        + html.escape(retained_note)
        + "</p><p>Exact retained island membership guides a missing-entry-path, "
        "test-scope, or dormant-capability decision. It does not prove dead code, "
        "safety, exploitability, or production inaccessibility.</p>"
        + table
        + "</section>"
    )


def _html_advanced_analysis_summary(value: dict[str, Any] | None) -> str:
    if not isinstance(value, dict) or not isinstance(value.get("summary"), dict):
        return ""
    summary = value["summary"]
    aligned_taint_paths, retained_taint_paths = _advanced_taint_alignment_counts(value)
    controls = value.get("control_topology")
    controls = controls if isinstance(controls, list) else []
    review = [
        item
        for item in controls
        if isinstance(item, dict)
        and (
            item.get("topology_status") in {"bypass-capable", "not-established"}
            or item.get("shared_mandatory_security_route_point") is True
        )
    ][:10]
    rows = "".join(
        "<tr><td><code>"
        + html.escape(str(item.get("topology_status") or "unknown"))
        + "</code>"
        + (
            "<br>shared mandatory security-route point"
            if item.get("shared_mandatory_security_route_point")
            else ""
        )
        + "</td><td><code>"
        + html.escape(str(item.get("path") or "unknown"))
        + "</code></td><td>"
        + str(len(item.get("entry_point_ids") or []))
        + " entries / "
        + str(len(item.get("target_ids") or []))
        + " targets</td><td>"
        + html.escape(str(item.get("recommended_action") or "Review."))
        + "</td></tr>"
        for item in review
    )
    table = (
        "<table><thead><tr><th>Status</th><th>Candidate control</th>"
        "<th>Scope</th><th>Action</th></tr></thead><tbody>" + rows + "</tbody></table>"
        if rows
        else "<p>No bypass-capable or shared mandatory control point was retained.</p>"
    )
    return (
        '<section aria-labelledby="advanced-analysis-heading">'
        '<h2 id="advanced-analysis-heading">Cross-evidence security leverage</h2>'
        "<p>Typed evidence relationships connect route topology, native taint paths, "
        "release entry points, threats, tests, mutations, telemetry, and dependencies. "
        "They guide review and do not prove exploitability or control effectiveness.</p>"
        '<div class="stats">'
        '<div class="stat"><strong>'
        + str(int(summary.get("bypass_capable_control_points") or 0))
        + "</strong><span>bypass-capable controls</span></div>"
        '<div class="stat"><strong>'
        + str(int(summary.get("shared_mandatory_security_route_points") or 0))
        + "</strong><span>shared mandatory security-route points</span></div>"
        '<div class="stat"><strong>'
        + f"{aligned_taint_paths} / {retained_taint_paths}"
        + "</strong><span>route-aligned / retained taint paths</span></div>"
        '<div class="stat"><strong>'
        + str(int(summary.get("unmodeled_published_entry_points") or 0))
        + "</strong><span>unmodeled artifact entries</span></div>"
        '<div class="stat"><strong>'
        + str(int(summary.get("telemetry_routes_without_observed_protection") or 0))
        + "</strong><span>telemetry protection gaps</span></div></div>"
        + table
        + '<p><a href="advanced-analysis.json">Download the complete typed evidence graph (JSON)</a></p>'
        "</section>"
    )


def render_html(
    manifest: ScanManifest,
    findings: list[Finding],
    *,
    risk_paths: dict[str, Any] | None = None,
    advanced_analysis: dict[str, Any] | None = None,
) -> str:
    tool_versions = {run.tool: run.version for run in manifest.tools}
    active_findings = [
        finding
        for finding in findings
        if finding.status is not FindingStatus.SUPPRESSED
    ]
    accepted = len(findings) - len(active_findings)
    ordered = sorted(active_findings, key=_finding_sort_key)
    coverage_gaps = _applicable_scanner_gaps(manifest.tools)
    not_applicable = _not_applicable_scanners(manifest.tools)
    finding_cards = _html_finding_cards(ordered, tool_versions)
    finding_rows = _html_finding_rows(ordered)
    reasons = _html_policy_reasons(manifest)
    gap_rows = _html_coverage_gap_rows(manifest, coverage_gaps)
    not_applicable_details = _html_not_applicable_details(not_applicable)
    tools = _html_tool_rows(manifest.tools)
    area_rows = _html_area_rows(active_findings)
    counts = _severity_counts(active_findings)
    entrypoints, approved_entrypoints, unchanged_entrypoints = (
        _entrypoint_integrity_counts(manifest.tools)
    )
    outcome = html.escape(manifest.outcome.value)
    decision = _policy_decision_value(manifest.outcome)
    completed = _completed_tools(manifest.tools)
    applicable = _applicable_tools(manifest.tools)
    health = portfolio_health_artifact(
        active_findings,
        manifest.tools,
        outcome=manifest.outcome,
        policy_reasons=manifest.policy_reasons,
    )["overall"]
    release_status = _report_release_status(manifest.outcome)
    admission_cards = _html_admission_cards(manifest, active_findings)
    unrouted_structural_html = _html_unrouted_structural_summary(risk_paths)
    advanced_analysis_html = _html_advanced_analysis_summary(advanced_analysis)
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy"
      content="default-src 'none'; style-src 'unsafe-inline'; img-src data:">
<title>Python Security Suite report</title>
<style>
:root {{ color-scheme: light; font-family: Inter, ui-sans-serif, system-ui,
  -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }}
* {{ box-sizing: border-box; }}
body {{ margin: 0; background: #f5f7fa; color: #172033; }}
.page {{ margin: 0 auto; max-width: 1180px; padding: 2rem; }}
h1, h2, h3 {{ color: #12365d; line-height: 1.25; }}
h2 {{ margin-top: 2.25rem; }}
p, li {{ line-height: 1.55; }}
a {{ color: #125d9c; overflow-wrap: anywhere; }}
code {{ overflow-wrap: anywhere; }}
.banner {{ border-left: .6rem solid #47627f; background: #fff;
  border-radius: .4rem; box-shadow: 0 1px 5px #17203318;
  padding: 1.25rem 1.5rem; }}
.banner.fail, .banner.incomplete {{ border-color: #a61b1b; }}
.banner.warn {{ border-color: #9a6e00; }}
.banner.pass {{ border-color: #247044; }}
.lede {{ color: #506074; margin-bottom: 0; }}
.stats {{ display: grid; grid-template-columns: repeat(5, minmax(0, 1fr));
  gap: .75rem; margin: 1rem 0 1.5rem; }}
.stat {{ background: #fff; border: 1px solid #d5dde7; border-radius: .4rem;
  padding: .85rem 1rem; }}
.stat strong {{ display: block; font-size: 1.45rem; }}
.stat span {{ color: #59677a; font-size: .9rem; }}
.decision {{ background: #eef3f8; border-radius: .4rem; padding: .75rem 1.1rem; }}
.decision h2 {{ display: flex; align-items: center; gap: .65rem; }}
.decision-badge {{ border-radius: 999px; font-size: .8rem; letter-spacing: .04em;
  padding: .25rem .65rem; }}
.decision-badge.block {{ background: #f8dddd; color: #8c1616; }}
.decision-badge.review {{ background: #fff0c7; color: #6e4e00; }}
.decision-badge.allow {{ background: #dcefe4; color: #185c36; }}
.decision-badge.incomplete, .decision-badge.not_applicable {{
  background: #fff0c7; color: #6e4e00; }}
.axis-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
  gap: .8rem; margin: 1rem 0 2rem; }}
.axis-card {{ background: #fff; border: 1px solid #d5dde7; border-left: .4rem solid #247044;
  border-radius: .4rem; padding: 1rem; }}
.axis-card.block {{ border-left-color: #a61b1b; }}
.axis-card.incomplete {{ border-left-color: #9a6e00; }}
.axis-card.not_applicable {{ border-left-color: #718096; }}
.axis-heading {{ display: flex; align-items: center; justify-content: space-between; gap: .75rem; }}
.axis-heading h3 {{ margin: 0; }}
.coverage-details {{ margin: 1rem 0 2rem; }}
.coverage-details summary {{ color: #17395f; cursor: pointer; font-weight: 700;
  padding: .65rem 0; }}
.coverage-details table {{ margin-bottom: 0; }}
table {{ width: 100%; border-collapse: collapse; margin: 1rem 0 2rem;
  background: #fff; }}
th, td {{ text-align: left; vertical-align: top; padding: .65rem;
  border: 1px solid #c7d0db; }}
th {{ background: #e8eef5; color: #17395f; }}
.finding {{ background: #fff; border: 1px solid #d5dde7;
  border-left: .45rem solid #47627f; border-radius: .4rem;
  box-shadow: 0 1px 4px #17203312; margin: 1rem 0; padding: 1.1rem 1.25rem; }}
.finding.critical, .finding.high {{ border-left-color: #a61b1b; }}
.finding.medium {{ border-left-color: #9a6e00; }}
.finding.low, .finding.informational {{ border-left-color: #315b7d; }}
.finding-header {{ display: flex; align-items: flex-start; gap: .75rem; }}
.finding-header h3 {{ margin: 0; flex: 1; }}
.finding-location {{ background: #eef3f8; border-left: .25rem solid #47627f;
  margin: 1rem 0; padding: .65rem .8rem; }}
.finding-location code {{ font-weight: 700; }}
.badge, .status {{ display: inline-block; border-radius: 999px; font-weight: 700;
  font-size: .78rem; letter-spacing: .02em; padding: .2rem .55rem; }}
.badge {{ background: #e8eef5; color: #17395f; white-space: nowrap; }}
.badge.critical, .badge.high {{ background: #f8dddd; color: #8c1616; }}
.badge.medium {{ background: #fff0c7; color: #6e4e00; }}
.badge.low, .badge.informational {{ background: #dfeaf4; color: #234f73; }}
.status.completed {{ background: #dcefe4; color: #185c36; }}
.status.failed, .status.unavailable, .status.timed_out,
.status.parse_error {{ background: #f8dddd; color: #8c1616; }}
.metadata {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(210px, 1fr));
  gap: .5rem 1rem; margin: .9rem 0; }}
.metadata div {{ color: #3d4d62; }}
.metadata strong {{ color: #172033; }}
.detail-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
  gap: 1rem; }}
.detail {{ background: #f7f9fb; border-radius: .35rem; padding: .75rem .9rem; }}
.detail h4 {{ margin: 0 0 .35rem; color: #17395f; }}
.detail p {{ margin: 0; }}
.detail.action {{ background: #e9f5ee; border: 1px solid #b9d8c5; }}
.source-context {{ margin: 1rem 0; }}
.source-context h4 {{ margin: 0 0 .45rem; color: #17395f; }}
.source-context pre {{ background: #111b2b; color: #e7edf5; border-radius: .4rem;
  margin: 0; overflow-x: auto; padding: .65rem 0; }}
.code-line {{ display: grid; grid-template-columns: 4.5rem 1fr;
  min-height: 1.55rem; padding: 0 .8rem; }}
.code-line.highlight {{ background: #5b4616; border-left: .3rem solid #f0c15b;
  padding-left: .5rem; }}
.line-number {{ color: #93a4ba; border-right: 1px solid #405067;
  margin-right: .85rem; padding-right: .65rem; text-align: right;
  user-select: none; }}
.code-text {{ white-space: pre; }}
.redaction-note {{ color: #59677a; font-size: .9rem; margin: .45rem 0 0; }}
.compact {{ margin: .35rem 0 0; padding-left: 1.25rem; }}
.empty {{ background: #fff; padding: 1rem; border-radius: .4rem; }}
.footer-note {{ color: #59677a; font-size: .9rem; }}
@media (max-width: 650px) {{
  .page {{ padding: 1rem; }}
  .stats {{ grid-template-columns: repeat(2, minmax(0, 1fr)); }}
  .finding-header {{ display: block; }}
  .finding-header .badge {{ margin-bottom: .5rem; }}
  table {{ display: block; overflow-x: auto; white-space: normal; }}
  .metadata {{ grid-template-columns: 1fr; }}
  .code-line {{ grid-template-columns: 3.5rem 1fr; }}
}}
</style>
</head>
<body>
<div class="page">
<header class="banner {outcome}">
<h1>Security result: {outcome.upper()}</h1>
<p class="lede">Scan <code>{html.escape(manifest.scan_id)}</code> &middot;
profile <code>{html.escape(manifest.profile)}</code> &middot;
target <code>{html.escape(manifest.target)}</code></p>
</header>
<section class="stats" aria-label="Scan summary">
<div class="stat"><strong>{
        len(active_findings)
    }</strong><span>Active findings</span></div>
<div class="stat"><strong>{accepted}</strong><span>Governed findings</span></div>
<div class="stat"><strong>{
        counts.get("critical", 0)
    }</strong><span>Critical</span></div>
<div class="stat"><strong>{counts.get("high", 0)}</strong><span>High</span></div>
<div class="stat"><strong>{counts.get("medium", 0)}</strong><span>Medium</span></div>
<div class="stat"><strong>{counts.get("low", 0)}</strong><span>Low</span></div>
<div class="stat"><strong>{completed}/{applicable}</strong>
<span>Applicable completed</span></div>
<div class="stat"><strong>{len(coverage_gaps)}</strong>
<span>Execution gaps</span></div>
<div class="stat"><strong>{len(not_applicable)}</strong>
<span>Not applicable</span></div>
<div class="stat"><strong>{approved_entrypoints}/{entrypoints}</strong>
<span>Entrypoints approved</span></div>
<div class="stat"><strong>{unchanged_entrypoints}/{entrypoints}</strong>
<span>Entrypoints unchanged</span></div>
<div class="stat"><strong>{health["execution_grade"]}</strong>
<span>Execution grade</span></div>
<div class="stat"><strong>{health["risk_grade"]}</strong>
<span>Observed-risk grade</span></div>
<div class="stat"><strong>{health["evidence_grade"]}</strong>
<span>Evidence grade</span></div>
<div class="stat"><strong>{html.escape(release_status)}</strong>
<span>Release readiness</span></div>
<div class="stat"><strong>{
        "yes" if manifest.inventory.source_integrity_verified else "no"
    }</strong><span>Target unchanged</span></div>
</section>
<section class="decision">
<h2>Decision: <span class="decision-badge {decision.lower()}">{decision}</span></h2>
<ul>{reasons}</ul>
<p><strong>Next action:</strong> {html.escape(_next_action_for_manifest(manifest))}</p>
<p><strong>Promotion:</strong> Run <code>pysec release-check</code> with the
required governed sidecars; this report alone does not authorize release.</p>
<p><a href="action-plan.md">Open the prioritized action plan</a></p>
<p><a href="closure-plan.json">Download the owned closure backlog (JSON)</a></p>
<p><a href="assurance-case.md">Open the production assurance case</a></p>
</section>
<section aria-labelledby="admission-heading">
<h2 id="admission-heading">Admission decisions by evidence axis</h2>
<p>Use these cards to route work quickly. The scan-policy decision remains authoritative.</p>
<div class="axis-grid">{admission_cards}</div>
</section>
{unrouted_structural_html}
{advanced_analysis_html}
<main>
<h2>Prioritized findings</h2>
<p>Start here. Each item links the security meaning to a precise source
location, scanner rule, and recommended action.</p>
<table>
<thead><tr><th>Priority</th><th>Severity</th><th>Finding</th>
<th>File and line</th><th>Found by</th><th>Recommended action</th></tr></thead>
<tbody>{finding_rows}</tbody>
</table>
<h2>Findings by area</h2>
<table>
<thead><tr><th>Area</th><th>Critical</th><th>High</th><th>Medium</th>
<th>Low</th><th>Info/Unknown</th><th>Total</th></tr></thead>
<tbody>{area_rows}</tbody>
</table>
<h2>Findings requiring review</h2>
{finding_cards}
<h2>Tool coverage</h2>
<table>
<thead><tr><th>Tool</th><th>Version</th><th>Applicability</th><th>Status</th>
<th>Entry-point integrity</th><th>Findings</th><th>Duration</th>
<th>Diagnostic</th></tr></thead>
<tbody>{tools}</tbody>
</table>
<h2>Coverage gaps and actions</h2>
<table>
<thead><tr><th>Tool</th><th>Applicability</th><th>Status</th>
<th>Reason</th><th>Required action</th><th>Reference</th></tr></thead>
<tbody>{gap_rows}</tbody>
</table>
{not_applicable_details}
<h2>Triage workflow</h2>
<ol>
<li>Open the cited location and validate the scanner premise in context.</li>
<li>Choose a disposition: fix, accepted risk, false positive, or approved suppression.</li>
<li>Record an owner and rationale in the repository's normal review system.</li>
<li>Rerun the isolated suite and confirm the stable finding ID is resolved or governed.</li>
</ol>
<h2>Scan integrity</h2>
<p>Network policy: <code>{html.escape(manifest.network_policy)}</code>;
isolation attested: <strong>{str(manifest.network_isolation_attested).lower()}</strong>;
unisolated diagnostic: <strong>{
        str(manifest.diagnostic_without_isolation).lower()
    }</strong>;
target code execution: <strong>{str(manifest.execute_target_code).lower()}</strong>.</p>
<p>Target source digest:
<code>sha256:{html.escape(manifest.inventory.source_sha256)}</code>;
after scan:
<code>sha256:{html.escape(manifest.inventory.source_sha256_after)}</code>;
unchanged: <strong>{
        str(manifest.inventory.source_integrity_verified).lower()
    }</strong>; scope: {manifest.inventory.hashed_files} files,
{manifest.inventory.hashed_bytes} bytes.</p>
<p class="footer-note">Detected secret values and raw scanner output are not retained.
Use <code>checksums.sha256</code> to verify the downloadable artifact.</p>
</main>
</div>
</body>
</html>
"""


def _html_tool_reference(tool: str) -> str:
    uri = _TOOL_REFERENCES.get(tool)
    if uri is None:
        return "-"
    return (
        f"<a href='{html.escape(uri, quote=True)}' rel='noreferrer'>"
        "Official documentation</a>"
    )


def _render_html_finding(finding: Finding, tool_versions: dict[str, str]) -> str:
    severity = html.escape(finding.severity.value)
    sources = (
        "".join(
            "<li>"
            f"<strong>{html.escape(source.tool)}</strong> "
            f"{html.escape(_source_version(source, tool_versions))} - "
            f"rule <code>{html.escape(source.rule_id)}</code>"
            "</li>"
            for source in finding.sources
        )
        or "<li>No scanner attribution recorded.</li>"
    )
    classifications = (
        " ".join(_html_classification(value) for value in finding.classifications)
        or "<span class='badge'>Unclassified</span>"
    )
    citations = (
        "".join(
            f"<li>{_html_citation(citation)}</li>" for citation in finding.citations
        )
        or "<li>No external reference.</li>"
    )
    source_context = _html_source_excerpt(finding)
    graph_context = _html_graph_context(finding)
    secret_provenance_context = _html_secret_provenance_context(finding)
    risk_path_context = _html_risk_path_context(finding)
    structural_context = _html_structural_context(finding)
    data_exposure_context = _html_data_exposure_context(finding)
    fusion_context = _html_fusion_context(finding)
    return (
        f"<article class='finding {severity}' "
        f"id='{html.escape(finding.finding_id, quote=True)}'>"
        "<div class='finding-header'>"
        f"<span class='badge {severity}'>"
        f"{html.escape(finding.severity.value.upper())}</span>"
        f"<h3>{html.escape(finding.title)}</h3>"
        "</div>"
        "<div class='metadata'>"
        f"<div><strong>Finding ID:</strong> "
        f"<code>{html.escape(finding.finding_id)}</code></div>"
        f"<div><strong>Priority:</strong> {_finding_priority(finding)}</div>"
        f"<div><strong>Lifecycle:</strong> {html.escape(finding.status.value)}</div>"
        f"<div><strong>Owners:</strong> {html.escape(', '.join(_owner_values(finding)) or 'Unassigned')}</div>"
        f"<div><strong>Threat intelligence:</strong> {html.escape(_threat_intelligence_summary(finding))}</div>"
        f"<div><strong>Domain:</strong> {html.escape(finding.domain)}</div>"
        f"<div><strong>Area:</strong> {html.escape(finding.area)}</div>"
        f"<div><strong>Confidence:</strong> "
        f"{html.escape(finding.confidence.value)}</div>"
        f"<div><strong>Classification:</strong> {classifications}</div>"
        "</div>"
        "<div class='finding-location'><strong>Review this location:</strong> "
        f"<code>{html.escape(_location_text(finding))}</code></div>"
        f"{source_context}"
        f"{graph_context}"
        f"{secret_provenance_context}"
        f"{risk_path_context}"
        f"{structural_context}"
        f"{data_exposure_context}"
        f"{fusion_context}"
        "<div class='detail-grid'>"
        "<section class='detail'><h4>What was detected</h4>"
        f"<p>{html.escape(finding.description)}</p></section>"
        "<section class='detail'><h4>Found by</h4>"
        f"<ul class='compact'>{sources}</ul></section>"
        "<section class='detail'><h4>References</h4>"
        f"<ul class='compact'>{citations}</ul></section>"
        "<section class='detail'><h4>Why it matters</h4>"
        f"<p>{html.escape(finding.impact)}</p></section>"
        "<section class='detail action'><h4>Recommended action</h4>"
        f"<p>{html.escape(finding.remediation)}</p></section>"
        "</div>"
        "</article>"
    )


def _finding_tools(finding: Finding) -> str:
    return (
        ", ".join(f"{source.tool}/{source.rule_id}" for source in finding.sources)
        or "unattributed"
    )


def _html_secret_provenance_context(finding: Finding) -> str:
    context = finding.evidence.get("secret_provenance")
    if not isinstance(context, dict):
        return ""
    membership = "; ".join(
        (
            _secret_membership_text(
                "source",
                context.get("source_inventory_available"),
                context.get("source_inventory_member"),
            ),
            _secret_membership_text(
                "graph",
                context.get("graph_available"),
                context.get("graph_path_member"),
            ),
            _secret_membership_text(
                "artifact",
                context.get("artifact_manifest_available"),
                context.get("artifact_manifest_member"),
            ),
        )
    )
    intersections = context.get("secret_exposure_intersections")
    values = intersections if isinstance(intersections, list) else []
    intersection_html = ""
    if values:
        items: list[str] = []
        for item in values[:3]:
            if not isinstance(item, dict):
                continue
            sink_path = str(item.get("sink_path") or "unknown")
            if item.get("sink_line"):
                sink_path += f":{item['sink_line']}"
            handoff = item.get("validation_handoff")
            handoff = handoff if isinstance(handoff, dict) else {}
            candidate_tests = handoff.get("candidate_test_files")
            candidate_tests = (
                candidate_tests if isinstance(candidate_tests, list) else []
            )
            compounds = item.get("secret_exposure_advisory_intersections")
            compound_values = compounds if isinstance(compounds, list) else []
            compound_html = ""
            if compound_values and isinstance(compound_values[0], dict):
                compound = compound_values[0]
                compound_html = (
                    " Compound scope <code>"
                    + html.escape(str(compound.get("intersection_id") or "unknown"))
                    + "</code> joins package <code>"
                    + html.escape(str(compound.get("package") or "unknown"))
                    + "</code> / advisory <code>"
                    + html.escape(str(compound.get("primary_identifier") or "unknown"))
                    + "</code>; canary <code>"
                    + html.escape(
                        str(
                            compound.get("canary_validation_status")
                            or "not-established"
                        )
                    )
                    + "</code>."
                )
            items.append(
                "<li><code>"
                + html.escape(str(item.get("intersection_id") or "unknown"))
                + "</code>: relationship <code>"
                + html.escape(str(item.get("association_kind") or "unknown"))
                + "</code>; sink <code>"
                + html.escape(sink_path)
                + "</code>; family <code>"
                + html.escape(str(item.get("sink_family") or "unknown"))
                + "</code>; boundary <code>"
                + html.escape(str(item.get("trust_boundary") or "unknown"))
                + "</code>; protection <code>"
                + html.escape(str(item.get("protection_status") or "unknown"))
                + "</code>; distance <code>"
                + html.escape(str(item.get("distance_to_sink") or 0))
                + "</code> file hop(s); temporal <code>"
                + html.escape(str(item.get("temporal_alignment") or "not-established"))
                + "</code>; validation handoff <code>"
                + html.escape(
                    str(
                        handoff.get("supporting_evidence_readiness")
                        or "not-established"
                    )
                )
                + "</code>; candidate tests <code>"
                + html.escape(
                    ", ".join(str(value) for value in candidate_tests[:3]) or "none"
                )
                + "</code>; combined assurance prerequisite <code>"
                + (
                    "met"
                    if item.get("combined_assurance_prerequisite_met") is True
                    else "not met"
                )
                + "</code>; canary <code>"
                + html.escape(
                    str(item.get("canary_validation_status") or "not-established")
                )
                + "</code>. <strong>Cross-reference action:</strong> "
                + html.escape(
                    str(
                        item.get("recommended_action") or "Trace and protect the route."
                    )
                )
                + " Static file-route co-location does not prove value flow, runtime "
                "execution, credential validity, or disclosure."
                + compound_html
                + "</li>"
            )
        if items:
            omitted = int(context.get("secret_exposure_intersections_omitted") or 0)
            omitted_text = (
                f"<p>{omitted} additional intersection(s) are retained in "
                "<code>risk-paths.json</code>.</p>"
                if omitted
                else ""
            )
            intersection_html = (
                "<section class='source-context'><h4>Secret-to-sensitive-sink "
                "intersections</h4><ul class='compact'>"
                + "".join(items)
                + "</ul>"
                + omitted_text
                + "</section>"
            )
    return (
        "<section class='source-context'><h4>Secret candidate provenance</h4><p>"
        "Context <code>"
        + html.escape(str(context.get("secret_context_id") or "unknown"))
        + "</code>; content <code>"
        + html.escape(str(context.get("content_lane") or "unknown"))
        + "</code>; disposition <code>"
        + html.escape(str(context.get("review_disposition") or "unknown"))
        + "</code>; verification <code>"
        + html.escape(str(context.get("verification_status") or "not-established"))
        + "</code>; history <code>"
        + html.escape(str(context.get("history_status") or "not-established"))
        + "</code>; "
        + html.escape(membership)
        + "; scanner <code>"
        + html.escape(str(context.get("scanner_perspective") or "single-scanner"))
        + "</code>; assurance <code>"
        + html.escape(str(context.get("evidence_assurance_status") or "not-assessed"))
        + "</code>; redacted <code>"
        + ("yes" if context.get("redacted") is True else "no")
        + "</code>. <strong>Lane-specific action:</strong> "
        + html.escape(
            str(context.get("recommended_action") or "Review the redacted candidate.")
        )
        + " This context does not establish that the candidate is a real, active, "
        "exploitable, or unique credential, and test/generated placement is not an "
        "automatic false-positive disposition.</p></section>" + intersection_html
    )


def _html_graph_context(finding: Finding) -> str:
    context = finding.evidence.get("graph_context")
    if not isinstance(context, dict):
        return ""
    degree = int(context.get("degree", 0))
    upstream = int(context.get("two_hop_upstream_count", 0))
    downstream = int(context.get("two_hop_downstream_count", 0))
    interpretation = html.escape(str(context.get("interpretation", "")))
    corroboration = html.escape(
        _graph_corroboration_text(context.get("corroborating_evidence", {}))
    )
    corroboration_html = f" Corroboration: {corroboration}." if corroboration else ""
    return (
        "<section class='source-context'><h4>Graph-aware impact context</h4>"
        f"<p>Degree <strong>{degree}</strong>; two-hop upstream "
        f"<strong>{upstream}</strong>; two-hop downstream "
        f"<strong>{downstream}</strong>. {interpretation}.{corroboration_html}</p></section>"
    )


def _html_risk_path_context(finding: Finding) -> str:
    context = finding.evidence.get("risk_path")
    if not isinstance(context, dict):
        return ""
    if context.get("status") != "routed":
        reason = html.escape(str(context.get("reason") or "review model coverage"))
        applicability = context.get("route_applicability")
        applicability = applicability if isinstance(applicability, dict) else {}
        applicability_text = html.escape(_route_applicability_text(applicability))
        action = html.escape(
            str(context.get("recommended_action") or "Review.").rstrip(".")
        )
        interpretation = (
            "This is a Python route-model evidence gap, not proof that the code is unreachable."
            if applicability.get("assessment") == "route-applicable"
            else "The finding remains actionable in its native evidence lane; a production Python route is not expected."
        )
        assurance = html.escape(
            _evidence_assurance_text(context.get("evidence_assurance"))
        )
        lifecycle = html.escape(
            _change_lifecycle_text(context.get("change_lifecycle_attribution"))
        )
        structural_text = html.escape(
            _unrouted_structural_context_text(
                context.get("unrouted_structural_intersections")
            )
        )
        return (
            "<section class='source-context'><h4>Static risk route</h4>"
            f"<p>{applicability_text}: {reason}. "
            f"<strong>Evidence assurance:</strong> {assurance}. "
            f"<strong>Change/lifecycle attribution:</strong> {lifecycle}. "
            f"<strong>Action:</strong> {action}. {html.escape(interpretation)}"
            f"{structural_text}</p></section>"
        )
    entry = context.get("entry_point")
    entry = entry if isinstance(entry, dict) else {}
    files = context.get("files")
    file_values = files if isinstance(files, list) else []
    route = " → ".join(str(item) for item in file_values[:6])
    if len(file_values) > 6:
        route += f" → … (+{len(file_values) - 6})"
    validation = context.get("validation")
    runtime = context.get("runtime_context")
    validation = validation if isinstance(validation, dict) else {}
    runtime = runtime if isinstance(runtime, dict) else {}
    hotspot_ids = context.get("convergence_hotspot_ids")
    hotspot_html = (
        " <strong>Shared control points:</strong> "
        + ", ".join(
            "<code>" + html.escape(str(value)) + "</code>" for value in hotspot_ids[:5]
        )
        + "."
        if isinstance(hotspot_ids, list) and hotspot_ids
        else ""
    )
    test_hotspot_ids = context.get("validation_test_hotspot_ids")
    test_hotspot_html = (
        " <strong>Shared validation tests:</strong> "
        + ", ".join(
            "<code>" + html.escape(str(value)) + "</code>"
            for value in test_hotspot_ids[:5]
        )
        + "."
        if isinstance(test_hotspot_ids, list) and test_hotspot_ids
        else ""
    )
    campaigns = context.get("validation_campaigns")
    campaign_values = campaigns if isinstance(campaigns, list) else []
    campaign_html = ""
    if campaign_values and isinstance(campaign_values[0], dict):
        campaign = campaign_values[0]
        campaign_ids = ", ".join(
            str(value.get("campaign_id") or "unknown")
            for value in campaign_values[:5]
            if isinstance(value, dict)
        )
        selected = campaign.get("selected_test_files")
        selected_values = selected if isinstance(selected, list) else []
        snapshot = campaign.get("source_snapshot")
        snapshot = snapshot if isinstance(snapshot, dict) else {}
        control_text = _risk_campaign_control_text(campaign)
        factor_text = _risk_campaign_factor_text(campaign)
        tests = ", ".join(str(value) for value in selected_values[:3]) or "none mapped"
        campaign_html = (
            " <strong>Shared validation campaign(s):</strong> <code>"
            + html.escape(campaign_ids)
            + "</code>; first campaign selected tests "
            + html.escape(tests)
            + "; execution <code>"
            + html.escape(
                str(campaign.get("focused_test_validation_status") or "not-available")
            )
            + "</code>; aggregate coverage <code>"
            + html.escape(str(campaign.get("coverage_status") or "not-available"))
            + "</code>; alignment <code>"
            + html.escape(
                str(campaign.get("test_coverage_alignment") or "not-selected")
            )
            + "</code>; review <code>"
            + html.escape(str(campaign.get("review_tier") or "low"))
            + "/"
            + str(int(campaign.get("review_score") or 0))
            + "</code>"
            + ("; factors " + html.escape(factor_text) if factor_text else "")
            + "; revision <code>"
            + html.escape(
                str(snapshot.get("evidence_revision_binding") or "not-established")
            )
            + "</code>; route evidence "
            + html.escape(_campaign_route_assurance_text(campaign))
            + "; shared tests "
            + html.escape(_campaign_shared_test_quality_text(campaign))
            + ("; " + html.escape(control_text) if control_text else "")
            + "."
        )
    advisory_routes = context.get("dependency_advisory_routes")
    advisory_values = advisory_routes if isinstance(advisory_routes, list) else []
    advisory_html = ""
    if advisory_values:
        first_advisory = (
            advisory_values[0] if isinstance(advisory_values[0], dict) else {}
        )
        identifiers = sorted(
            {
                str(item.get("primary_identifier") or item.get("advisory_cluster_id"))
                for item in advisory_values
                if isinstance(item, dict)
            }
        )
        import_paths = sorted(
            {
                str(item.get("import_path"))
                for item in advisory_values
                if isinstance(item, dict) and item.get("import_path")
            }
        )
        citation_html = _risk_advisory_citations_html(
            first_advisory.get("advisory_citations")
        )
        advisory_html = (
            " <strong>Dependency exposure routes:</strong> "
            + str(len(advisory_values))
            + " route(s) for <code>"
            + html.escape(", ".join(identifiers[:5]))
            + "</code> through importer(s) <code>"
            + html.escape(", ".join(import_paths[:5]))
            + "</code>"
            + "; "
            + html.escape(
                _package_lifecycle_text(first_advisory.get("package_lifecycle"))
            )
            + "; "
            + html.escape(_entry_point_exposure_text(first_advisory))
            + ("; citations " + citation_html if citation_html else "")
            + "."
        )
    raw_intersections = context.get("exposure_advisory_intersections")
    intersections = raw_intersections if isinstance(raw_intersections, list) else []
    intersection_html = ""
    if intersections:
        first_intersection = (
            intersections[0] if isinstance(intersections[0], dict) else {}
        )
        intersection_html = (
            " <strong>Sensitive-boundary dependency intersection(s):</strong> "
            + str(len(intersections))
            + "; exact path <code>"
            + html.escape(str(first_intersection.get("path") or "unknown"))
            + "</code>; SDK package <code>"
            + html.escape(str(first_intersection.get("package") or "unknown"))
            + "</code>; advisory <code>"
            + html.escape(
                str(first_intersection.get("primary_identifier") or "unknown")
            )
            + "</code>; protection <code>"
            + html.escape(str(first_intersection.get("protection_status") or "unknown"))
            + "</code>; "
            + html.escape(
                _package_lifecycle_text(first_intersection.get("package_lifecycle"))
            )
            + "; entry exposure <code>"
            + str(int(first_intersection.get("entry_point_exposure_count") or 0))
            + "</code> declared route(s); "
            + html.escape(
                _entry_runtime_status_text(
                    first_intersection.get("entry_point_runtime_statuses")
                )
            )
            + ". This is compound review context, not leakage or vulnerable-function proof."
        )
    compound_values = [
        compound
        for intersection in intersections
        if isinstance(intersection, dict)
        for compound in (
            intersection.get("secret_exposure_advisory_intersections") or []
        )
        if isinstance(compound, dict)
    ]
    compound_html = ""
    if compound_values:
        first_compound = compound_values[0]
        compound_html = (
            " <strong>Secret / sensitive-boundary / advisory intersection(s):</strong> "
            + str(len(compound_values))
            + "; secret <code>"
            + html.escape(str(first_compound.get("secret_path") or "unknown"))
            + "</code>; package <code>"
            + html.escape(str(first_compound.get("package") or "unknown"))
            + "</code>; advisory <code>"
            + html.escape(str(first_compound.get("primary_identifier") or "unknown"))
            + "</code>; canary <code>"
            + html.escape(
                str(first_compound.get("canary_validation_status") or "not-established")
            )
            + "</code>. The exact sensitive-route join does not prove value flow, disclosure, or vulnerable-function execution."
        )
    sensitive_route = context.get("sensitive_data_route")
    sensitive_route = sensitive_route if isinstance(sensitive_route, dict) else {}
    sensitive_route_html = ""
    if sensitive_route:
        sensitive_route_citations = _risk_advisory_citations_html(
            sensitive_route.get("citations")
        )
        sensitive_route_html = (
            " <strong>End-to-end sensitive-data route:</strong> <code>"
            + html.escape(str(sensitive_route.get("sensitive_route_id") or "unknown"))
            + "</code>; evidence <code>"
            + html.escape(str(sensitive_route.get("evidence_basis") or "unknown"))
            + "</code>; sink <code>"
            + html.escape(str(sensitive_route.get("sink_family") or "unknown"))
            + "</code>; boundary <code>"
            + html.escape(str(sensitive_route.get("trust_boundary") or "unknown"))
            + "</code>; protection <code>"
            + html.escape(str(sensitive_route.get("protection_status") or "unknown"))
            + "</code>; scanner assurance <code>"
            + html.escape(
                str(sensitive_route.get("evidence_assurance_status") or "not-assessed")
            )
            + "</code>; validation <code>"
            + html.escape(
                str(sensitive_route.get("validation_status") or "not-assessed")
            )
            + "</code>"
            + (
                "; guidance " + sensitive_route_citations
                if sensitive_route_citations
                else "; guidance citation unavailable"
            )
            + ". Citations support classification and remediation guidance; this "
            "static route is not proof of disclosure."
        )
    return (
        "<section class='source-context'><h4>Static risk route</h4><p>"
        "Route <code>"
        + html.escape(str(context.get("route_id") or "unknown"))
        + "</code> from <code>"
        + html.escape(str(entry.get("declared_as") or entry.get("id") or "unknown"))
        + "</code> in <strong>"
        + str(int(context.get("hop_count") or 0))
        + "</strong> file hop(s): "
        + html.escape(route or str(entry.get("path") or "same file"))
        + ". <strong>Entry exposure:</strong> "
        + html.escape(_entry_point_exposure_text(context))
        + ". <strong>Validation:</strong> "
        + html.escape(_risk_path_validation_signals(validation, runtime))
        + ". <strong>Evidence assurance:</strong> "
        + html.escape(_evidence_assurance_text(context.get("evidence_assurance")))
        + ". <strong>Change/lifecycle attribution:</strong> "
        + html.escape(
            _change_lifecycle_text(context.get("change_lifecycle_attribution"))
        )
        + ". <strong>Route ownership:</strong> "
        + html.escape(_route_ownership_text(context.get("ownership_context")))
        + "."
        + hotspot_html
        + test_hotspot_html
        + campaign_html
        + advisory_html
        + intersection_html
        + compound_html
        + sensitive_route_html
        + "</p></section>"
    )


def _html_fusion_context(finding: Finding) -> str:
    fusion = finding.evidence.get("fusion")
    if not isinstance(fusion, dict):
        return ""
    tier = html.escape(str(fusion.get("review_tier", "standard")))
    corroboration = html.escape(str(fusion.get("corroboration", "single-tool")))
    reasons = fusion.get("review_reasons", [])
    reason_text = "; ".join(str(value) for value in reasons[:5])
    advisory = fusion.get("advisory_context")
    advisory_text = ""
    if isinstance(advisory, dict) and advisory.get("cluster_id"):
        primary = str(advisory.get("primary_identifier") or advisory["cluster_id"])
        usage = _dependency_usage_summary(advisory.get("dependency_usage"))
        remediation = advisory.get("remediation_context")
        remediation_summary = _remediation_context_summary(remediation)
        action = (
            str(remediation.get("recommended_action") or "")
            if isinstance(remediation, dict)
            else ""
        )
        advisory_text = (
            " Advisory "
            + primary
            + ("; dependency use " + usage if usage else "")
            + ("; remediation " + remediation_summary if remediation_summary else "")
            + ("; action " + action if action else "")
            + "."
        )
    reason_html = f" {html.escape(reason_text)}." if reason_text else ""
    return (
        "<section class='source-context'><h4>Cross-referenced evidence</h4>"
        f"<p>Review tier <strong>{tier}</strong>; corroboration "
        f"<strong>{corroboration}</strong>.{reason_html}"
        f"{html.escape(advisory_text)}</p></section>"
    )


def _html_data_exposure_context(finding: Finding) -> str:
    context = finding.evidence.get("data_exposure")
    if not isinstance(context, dict):
        return ""
    concern = html.escape(str(context.get("concern", "review")))
    family = html.escape(str(context.get("sink_family", "unknown")))
    exact_sink = html.escape(str(context.get("sink") or family))
    sdk = html.escape(str(context.get("sdk") or "none identified"))
    relevance = html.escape(str(context.get("structural_relevance", "unknown")))
    priority = html.escape(str(context.get("review_priority", "medium")))
    data_classes = html.escape(
        ", ".join(str(value) for value in context.get("data_classes", []))
        or "unclassified"
    )
    trust_boundary = html.escape(str(context.get("trust_boundary", "unknown")))
    risk_factors = html.escape(
        ", ".join(str(value) for value in context.get("risk_factors", [])[:5])
        or "none recorded"
    )
    cross = context.get("cross_references")
    cross = cross if isinstance(cross, dict) else {}
    cross_signals = html.escape(_exposure_cross_reference_signals(cross))
    dependency = context.get("sdk_dependency_context")
    dependency_summary = _sdk_dependency_context_summary(dependency)
    dependency_html = ""
    if dependency_summary:
        citation_links: list[str] = []
        citations = (
            dependency.get("citations") if isinstance(dependency, dict) else None
        )
        if isinstance(citations, list):
            for item in citations[:5]:
                if not isinstance(item, dict):
                    continue
                identifier = html.escape(str(item.get("identifier") or "reference"))
                uri = item.get("uri")
                citation_links.append(
                    f"<a href='{html.escape(uri, quote=True)}' rel='noreferrer'>{identifier}</a>"
                    if isinstance(uri, str) and uri.startswith(("https://", "http://"))
                    else identifier
                )
        citations_html = (
            " Citations: " + ", ".join(citation_links) + "." if citation_links else ""
        )
        dependency_html = (
            "<h5>SDK dependency cross-reference</h5><p>"
            + html.escape(dependency_summary)
            + "."
            + citations_html
            + " This context raises review priority but does not prove SDK-mediated disclosure.</p>"
        )
    triage_tier = html.escape(str(context.get("triage_tier", "standard")))
    steps = context.get("verification_steps")
    steps_html = ""
    if isinstance(steps, list) and steps:
        steps_html = (
            "<h5>Verification plan</h5><ol>"
            + "".join(f"<li>{html.escape(str(step))}</li>" for step in steps)
            + "</ol>"
        )
    action = html.escape(str(context.get("recommended_action", "Review the path.")))
    return (
        "<section class='source-context'><h4>Sensitive-data exposure path</h4>"
        f"<p>Concern <strong>{concern}</strong>; sink <strong>{exact_sink}</strong> "
        f"(family <strong>{family}</strong>); "
        f"SDK <strong>{sdk}</strong>; structural relevance "
        f"<strong>{relevance}</strong>; priority <strong>{priority}</strong>; "
        f"cross-tool triage <strong>{triage_tier}</strong>; "
        f"data classes <strong>{data_classes}</strong>; trust boundary "
        f"<strong>{trust_boundary}</strong>; risk factors "
        f"<strong>{risk_factors}</strong>; joined evidence "
        f"<strong>{cross_signals}</strong>. {action}</p>{dependency_html}{steps_html}</section>"
    )


def _html_structural_context(finding: Finding) -> str:
    structural = finding.evidence.get("structural_synthesis")
    if not isinstance(structural, dict):
        return ""
    parts: list[str] = []
    disposition = structural.get("disposition")
    if disposition:
        parts.append(
            "Dead-code disposition <strong>"
            + html.escape(str(disposition))
            + "</strong>"
        )
    island = structural.get("island")
    if isinstance(island, dict):
        parts.append(
            "island <strong>"
            + html.escape(str(island.get("classification", "review")))
            + "</strong> ("
            + str(int(island.get("lines_of_code", 0)))
            + " LOC)"
        )
    cycle = structural.get("import_cycle")
    if isinstance(cycle, dict):
        parts.append(
            "import cycle across <strong>"
            + str(int(cycle.get("file_count", 0)))
            + "</strong> files"
        )
    change = structural.get("change_impact")
    if isinstance(change, dict):
        parts.append(
            "change impact <strong>"
            + html.escape(str(change.get("classification", "review")))
            + "</strong> (risk "
            + str(int(change.get("risk_score", 0)))
            + ")"
        )
    boundary = structural.get("island_boundary")
    if isinstance(boundary, dict):
        parts.append(
            "island boundary <strong>"
            + html.escape(str(boundary.get("boundary_classification", "review")))
            + "</strong>"
        )
    if not parts:
        return ""
    action = structural.get("recommended_action")
    if not action and isinstance(island, dict):
        action = island.get("recommended_action")
    if not action and isinstance(cycle, dict):
        action = cycle.get("recommended_action")
    if not action and isinstance(change, dict):
        action = change.get("recommended_action")
    if not action and isinstance(boundary, dict):
        action = boundary.get("recommended_action")
    action_html = f" {html.escape(str(action))}" if action else ""
    return (
        "<section class='source-context'><h4>Structural synthesis</h4><p>"
        + "; ".join(parts)
        + "."
        + action_html
        + "</p></section>"
    )


def _html_source_excerpt(finding: Finding) -> str:
    location = _primary_snippet_location(finding)
    if location is None or location.snippet is None:
        artifact = _artifact_identity(finding)
        if artifact is not None:
            path, digest, size = artifact
            size_line = f"\nsize: {size} bytes" if size is not None else ""
            return (
                "<section class='source-context'><h4>Artifact identity evidence "
                "&mdash; "
                f"<code>{html.escape(path)}</code></h4>"
                "<pre aria-label='Artifact identity'><code>"
                f"sha256:{html.escape(digest)}{size_line}</code></pre></section>"
            )
        return (
            "<section class='source-context'><h4>Source evidence</h4>"
            f"<p>{html.escape(_missing_source_evidence_text(finding))}</p></section>"
        )
    start = location.snippet_start_line or location.start_line or 1
    lines = location.snippet.splitlines() or [""]
    rendered = "".join(
        "<span class='code-line"
        f"{' highlight' if _line_is_highlighted(location, start + offset) else ''}'>"
        f"<span class='line-number'>{start + offset}</span>"
        f"<span class='code-text'>{html.escape(value)}</span></span>"
        for offset, value in enumerate(lines)
    )
    note = (
        "<p class='redaction-note'>The secret-bearing line is deliberately "
        "redacted. Inspect it only in the protected checkout.</p>"
        if location.snippet_redacted
        else ""
    )
    return (
        "<section class='source-context'><h4>Source evidence &mdash; "
        f"<code>{html.escape(_location_text(finding))}</code></h4>"
        f"<pre aria-label='Source excerpt'>{rendered}</pre>{note}</section>"
    )


def _html_classification(value: str) -> str:
    uri = _classification_uri(value)
    label = html.escape(value)
    if uri:
        return (
            f"<a class='badge' href='{html.escape(uri, quote=True)}' "
            f"rel='noreferrer'>{label}</a>"
        )
    return f"<span class='badge'>{label}</span>"


def _html_citation(citation: Citation) -> str:
    label = citation.identifier
    if citation.title and citation.title != citation.identifier:
        label += f" - {citation.title}"
    escaped = html.escape(label)
    uri = _reference_uri(citation)
    if uri:
        return (
            f"<a href='{html.escape(uri, quote=True)}' rel='noreferrer'>{escaped}</a>"
        )
    return escaped
