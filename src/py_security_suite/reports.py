from __future__ import annotations

import hashlib
import html
import json
from pathlib import Path
from typing import Any

from .models import (
    Citation,
    Finding,
    Outcome,
    ScanManifest,
    Severity,
    Source,
    ToolRun,
    json_ready,
)


REPORT_FILES = (
    "summary.md",
    "action-plan.md",
    "assurance-case.md",
    "index.html",
    "results.sarif",
    "findings.json",
    "scan-manifest.json",
    "checksums.sha256",
)

_SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFORMATIONAL: 4,
    Severity.UNKNOWN: 5,
}
_TOOL_REFERENCES = {
    "bandit": "https://bandit.readthedocs.io/",
    "semgrep": "https://semgrep.dev/docs/",
    "detect-secrets": "https://github.com/Yelp/detect-secrets",  # pragma: allowlist secret
    "osv-scanner": "https://google.github.io/osv-scanner/",
    "cyclonedx-py": "https://cyclonedx-bom-tool.readthedocs.io/",
    "ruff": "https://docs.astral.sh/ruff/rules/#flake8-bandit-s",
    "zizmor": "https://docs.zizmor.sh/",
    "pysa": "https://pyre-check.org/docs/pysa-basics/",
    "trivy": "https://trivy.dev/docs/latest/",
    "guarddog": "https://github.com/DataDog/guarddog",
    "scancode": "https://scancode-toolkit.readthedocs.io/",
    "gitleaks": "https://github.com/gitleaks/gitleaks",
    "trufflehog": "https://trufflesecurity.com/docs/",
    "codeql": "https://pypi.org/project/run-codeql/",
    "syft": "https://github.com/anchore/syft",
    "grype": "https://github.com/anchore/grype",
    "check-wheel-contents": "https://github.com/jwodder/check-wheel-contents",
    "twine": "https://twine.readthedocs.io/en/stable/#twine-check",
    "pypi-attestations": "https://docs.pypi.org/attestations/",
}


def write_reports(
    *,
    output: Path,
    findings: list[Finding],
    manifest: ScanManifest,
    diagnostics: dict[str, dict[str, Any]],
    include_evidence: bool,
    derived_artifacts: dict[str, Any] | None = None,
) -> None:
    output.mkdir(parents=True, exist_ok=False)
    manifest.artifacts = {
        "summary": "summary.md",
        "action_plan": "action-plan.md",
        "assurance_case": "assurance-case.md",
        "html": "index.html",
        "sarif": "results.sarif",
        "findings": "findings.json",
        "manifest": "scan-manifest.json",
        "checksums": "checksums.sha256",
    }
    for name in sorted(derived_artifacts or {}):
        if "/" in name or "\\" in name or name in REPORT_FILES:
            raise ValueError(f"unsafe or reserved derived artifact name: {name}")
        manifest.artifacts[name] = name
    _write_text(output / "summary.md", render_summary(manifest, findings))
    _write_text(output / "action-plan.md", render_action_plan(manifest, findings))
    _write_text(output / "assurance-case.md", render_assurance_case(manifest))
    _write_text(output / "index.html", render_html(manifest, findings))
    _write_json(output / "results.sarif", render_sarif(findings))
    _write_json(
        output / "findings.json",
        {
            "schema_version": "1.0",
            "scan_id": manifest.scan_id,
            "outcome": manifest.outcome,
            "findings": findings,
        },
    )
    if include_evidence:
        evidence = output / "evidence"
        evidence.mkdir()
        for tool, diagnostic in sorted(diagnostics.items()):
            _write_json(evidence / f"{tool}.json", diagnostic)
        manifest.artifacts["evidence"] = "evidence/"
    for name, value in sorted((derived_artifacts or {}).items()):
        _write_json(output / name, value)
    _write_json(output / "scan-manifest.json", manifest)
    _write_checksums(output)


def render_summary(manifest: ScanManifest, findings: list[Finding]) -> str:
    counts = manifest.finding_counts
    tool_versions = {run.tool: run.version for run in manifest.tools}
    lines = [
        f"# Security result: {manifest.outcome.value.upper()}",
        "",
        f"- **Scan:** `{_markdown_code(manifest.scan_id)}`",
        f"- **Profile:** `{_markdown_code(manifest.profile)}`",
        f"- **Target:** `{_markdown_code(manifest.target)}`",
        f"- **Findings:** {len(findings)} total; "
        f"{counts.get('critical', 0)} critical, {counts.get('high', 0)} high, "
        f"{counts.get('medium', 0)} medium, {counts.get('low', 0)} low",
        f"- **Applicable scanners completed:** "
        f"{_completed_tools(manifest.tools)}/{_applicable_tools(manifest.tools)}",
        f"- **Not applicable:** "
        f"{len(manifest.tools) - _applicable_tools(manifest.tools)} selected tool(s)",
        f"- **Network isolation attested:** "
        f"{'yes' if manifest.network_isolation_attested else 'no'}",
        f"- **Unisolated diagnostic execution:** "
        f"{'yes' if manifest.diagnostic_without_isolation else 'no'}",
        f"- **Immediate next step:** {_next_action(manifest.outcome)}",
        "",
        "## Decision",
        "",
    ]
    lines.extend(f"- {reason}" for reason in manifest.policy_reasons)

    lines.extend(["", "## Findings by area", ""])
    lines.append(
        "| Area | Critical | High | Medium | Low | Informational/Unknown | Total |"
    )
    lines.append("|---|---:|---:|---:|---:|---:|---:|")
    for area, area_counts in _area_summary(findings):
        lines.append(
            f"| {_markdown_table(area)} | {area_counts['critical']} | "
            f"{area_counts['high']} | {area_counts['medium']} | "
            f"{area_counts['low']} | "
            f"{area_counts['informational'] + area_counts['unknown']} | "
            f"{area_counts['total']} |"
        )
    if not findings:
        lines.append("| No findings | 0 | 0 | 0 | 0 | 0 | 0 |")

    lines.extend(["", "## Tool coverage", ""])
    lines.append("| Tool | Version | Applicability | Status | Findings | Duration |")
    lines.append("|---|---|---:|---:|---:|---:|")
    for run in manifest.tools:
        lines.append(
            f"| {_markdown_table(run.tool)} | {_markdown_table(run.version)} | "
            f"{'applicable' if run.applicable else 'not applicable'} | "
            f"{_markdown_table(run.status.value)} | {run.finding_count} | "
            f"{run.duration_seconds:.3f}s |"
        )

    gaps = [run for run in manifest.tools if run.status.value != "completed"]
    lines.extend(["", "## Coverage gaps and actions", ""])
    lines.append("| Tool | Status | Reason | Required action | Reference |")
    lines.append("|---|---|---|---|---|")
    for run in gaps:
        lines.append(
            f"| {_markdown_table(run.tool)} | "
            f"{_markdown_table(run.status.value)} | "
            f"{_markdown_table(run.error or 'No diagnostic supplied')} | "
            f"{_markdown_table(_coverage_action(run, manifest))} | "
            f"{_markdown_tool_reference(run.tool)} |"
        )
    if not gaps:
        lines.append("| All selected tools | completed | - | No action | - |")

    derived = [
        value
        for key, value in manifest.artifacts.items()
        if key
        not in {
            "summary",
            "html",
            "sarif",
            "findings",
            "manifest",
            "checksums",
            "evidence",
            "action_plan",
            "assurance_case",
        }
    ]
    if derived:
        lines.extend(["", "## Derived security evidence", ""])
        lines.extend(
            f"- [`{_markdown_code(value)}`]({_markdown_code(value)})"
            for value in derived
        )

    lines.extend(["", "## Findings requiring review", ""])
    if findings:
        ordered = sorted(findings, key=_finding_sort_key)
        for index, finding in enumerate(ordered[:20], start=1):
            sources = "; ".join(
                _markdown_source(source, tool_versions)
                for source in finding.sources
            ) or "No scanner attribution recorded"
            classifications = "; ".join(
                _markdown_classification(item)
                for item in finding.classifications
            ) or "Unclassified"
            references = "; ".join(
                _markdown_citation(item) for item in finding.citations
            ) or "No external reference"
            lines.extend(
                [
                    f"### {index}. {finding.severity.value.upper()} - "
                    f"{_markdown_text(finding.title)}",
                    "",
                    f"- **Finding ID:** `{_markdown_code(finding.finding_id)}`",
                    f"- **Priority:** `{_finding_priority(finding)}`",
                    f"- **Location:** `{_markdown_code(_location_text(finding))}`",
                    f"- **Found by:** {sources}",
                    f"- **Area / confidence:** "
                    f"`{_markdown_code(finding.area)}` / "
                    f"`{_markdown_code(finding.confidence.value)}`",
                    f"- **Classification:** {classifications}",
                    f"- **References:** {references}",
                    "",
                    f"**What was detected:** "
                    f"{_markdown_text(finding.description)}",
                    "",
                    f"**Why it matters:** {_markdown_text(finding.impact)}",
                    "",
                    f"**Recommended action:** "
                    f"{_markdown_text(finding.remediation)}",
                    "",
                ]
            )
        if len(ordered) > 20:
            lines.extend(
                [
                    f"{len(ordered) - 20} additional finding(s) are available in "
                    "`index.html`, `findings.json`, and `results.sarif`.",
                    "",
                ]
            )
    else:
        lines.extend(["- No normalized findings.", ""])

    lines.extend(
        [
            "## Triage workflow",
            "",
            _next_action(manifest.outcome),
            "",
            "1. Open the cited location and validate whether the scanner's premise "
            "is true in this execution context.",
            "2. Choose a disposition: fix, accepted risk, false positive, or "
            "approved suppression.",
            "3. Record the owner and rationale in the repository's normal review "
            "system.",
            "4. Rerun the isolated suite and confirm the finding ID is resolved or "
            "intentionally governed.",
            "",
            "The downloadable artifact contains detailed findings, citations, "
            "tool health, the scan manifest, sanitized diagnostics, and checksums.",
            "",
        ]
    )
    return "\n".join(lines)


def render_action_plan(manifest: ScanManifest, findings: list[Finding]) -> str:
    lines = [
        "# Security action plan",
        "",
        f"- **Scan:** `{_markdown_code(manifest.scan_id)}`",
        f"- **Outcome:** `{_markdown_code(manifest.outcome.value)}`",
        f"- **Profile:** `{_markdown_code(manifest.profile)}`",
        f"- **Immediate next step:** {_next_action(manifest.outcome)}",
        "",
        "## Finding actions",
        "",
        "| Priority | Severity | Finding | Area | Location | Sources | Action |",
        "|---|---|---|---|---|---|---|",
    ]
    for finding in sorted(findings, key=_finding_sort_key):
        sources = ", ".join(
            f"{source.tool}/{source.rule_id}" for source in finding.sources
        ) or "unattributed"
        lines.append(
            f"| {_finding_priority(finding)} | "
            f"{_markdown_table(finding.severity.value)} | "
            f"`{_markdown_code(finding.finding_id)}` "
            f"{_markdown_table(finding.title)} | "
            f"{_markdown_table(finding.area)} | "
            f"`{_markdown_code(_location_text(finding))}` | "
            f"{_markdown_table(sources)} | "
            f"{_markdown_table(finding.remediation)} |"
        )
    if not findings:
        lines.append("| - | - | No normalized findings | - | - | - | No action |")

    lines.extend(
        [
            "",
            "## Coverage actions",
            "",
            "| Tool | Applicability | Status | Reason | Action | Reference |",
            "|---|---|---|---|---|---|",
        ]
    )
    gaps = [run for run in manifest.tools if run.status.value != "completed"]
    for run in gaps:
        lines.append(
            f"| {_markdown_table(run.tool)} | "
            f"{'applicable' if run.applicable else 'not applicable'} | "
            f"{_markdown_table(run.status.value)} | "
            f"{_markdown_table(run.error or 'No diagnostic supplied')} | "
            f"{_markdown_table(_coverage_action(run, manifest))} | "
            f"{_markdown_tool_reference(run.tool)} |"
        )
    if not gaps:
        lines.append(
            "| All selected tools | applicable | completed | - | No action | - |"
        )
    lines.extend(
        [
            "",
            "## Policy and release-evidence actions",
            "",
            "| Requirement | Required action |",
            "|---|---|",
        ]
    )
    for reason in manifest.policy_reasons:
        lines.append(
            f"| {_markdown_table(reason)} | "
            f"{_markdown_table(_policy_action(reason))} |"
        )
    if not manifest.policy_reasons:
        lines.append("| All configured policy requirements | No action |")
    lines.extend(
        [
            "",
            "## Disposition record",
            "",
            "For each finding, record an owner and one disposition: fixed, accepted "
            "risk, false positive, or approved suppression. Preserve the finding ID "
            "and cited scanner rule in the review record, then rerun the suite.",
            "",
        ]
    )
    return "\n".join(lines)


def render_assurance_case(manifest: ScanManifest) -> str:
    rows = [
        _assurance_row(
            manifest,
            "Python source security",
            ("bandit", "semgrep", "ruff"),
            "Review and remediate cited source findings.",
            "https://csrc.nist.gov/pubs/sp/800/218/final",
        ),
        _assurance_row(
            manifest,
            "Deep data-flow analysis",
            ("pysa", "codeql"),
            "Configure and run at least one approved deep data-flow engine; "
            "production policy expects Pysa and the full profile requires CodeQL.",
            "https://owasp.org/www-project-application-security-verification-standard/",
        ),
        _assurance_row(
            manifest,
            "Secret exposure",
            ("detect-secrets", "gitleaks", "trufflehog"),
            "Scan a full VCS checkout and rotate any confirmed credential.",
            "https://csrc.nist.gov/pubs/sp/800/218/final",
        ),
        _assurance_row(
            manifest,
            "Dependency vulnerabilities and SBOM",
            ("osv-scanner", "cyclonedx-py", "guarddog", "syft", "grype"),
            "Use a reproducible lock, current approved offline advisory data, and "
            "retain the generated SBOM with the release.",
            "https://cyclonedx.org/capabilities/sbom/",
        ),
        _assurance_row(
            manifest,
            "Deployment, IaC, and CI configuration",
            ("trivy", "zizmor"),
            "Scan the final deployment definitions and CI workflows used for the "
            "release.",
            "https://csrc.nist.gov/pubs/sp/800/218/final",
        ),
        _assurance_row(
            manifest,
            "License and source inventory",
            ("scancode", "trivy"),
            "Review policy-disallowed licenses and preserve component inventory.",
            "https://spdx.dev/use/specifications/",
        ),
        _assurance_row(
            manifest,
            "Built artifact integrity and provenance",
            (
                "syft",
                "grype",
                "check-wheel-contents",
                "twine",
                "pypi-attestations",
            ),
            "Retain the verified artifact digest, SBOM, vulnerability result, "
            "metadata checks, and publisher provenance with the release.",
            "https://slsa.dev/spec/v1.0/levels",
        ),
    ]
    vcs_status = (
        "verified for scan scope"
        if manifest.inventory.vcs_history_available
        else "coverage gap"
    )
    vcs_evidence = (
        "VCS metadata was available to history-aware scanners."
        if manifest.inventory.vcs_history_available
        else "No VCS metadata was present; history and source provenance were not "
        "fully evaluated."
    )
    rows.extend(
        [
            (
                "Source provenance and history",
                vcs_status,
                vcs_evidence,
                "Run the production gate against a full, immutable VCS checkout.",
                "https://slsa.dev/spec/v1.0/levels",
            ),
            (
                "Dynamic, API, and runtime behavior",
                "external evidence required",
                "Target code execution is prohibited in this static scanning "
                "boundary.",
                "Run unit/integration, property, fuzz, and applicable DAST/API "
                "security tests in a separate disposable sandbox.",
                "https://owasp.org/www-project-application-security-verification-standard/",
            ),
            (
                "Threat model and security review",
                "external evidence required",
                "Automated scanners do not establish business-logic correctness, "
                "authorization design, abuse-case coverage, or accepted risk.",
                "Complete threat modeling and risk-owner review for material "
                "changes before production approval.",
                "https://csrc.nist.gov/pubs/sp/800/218/final",
            ),
        ]
    )
    lines = [
        "# Production security assurance case",
        "",
        f"- **Scan:** `{_markdown_code(manifest.scan_id)}`",
        f"- **Profile:** `{_markdown_code(manifest.profile)}`",
        f"- **Policy outcome:** `{_markdown_code(manifest.outcome.value)}`",
        "",
        "This document states what the scan demonstrated and what still requires "
        "separate release evidence. It is not a certification or a guarantee that "
        "the software is vulnerability-free.",
        "",
        "| Control area | Status | Evidence boundary | Required next action | Reference |",
        "|---|---|---|---|---|",
    ]
    for control, status, evidence, action, reference in rows:
        lines.append(
            f"| {_markdown_table(control)} | {_markdown_table(status)} | "
            f"{_markdown_table(evidence)} | {_markdown_table(action)} | "
            f"[Standard or guidance]({reference}) |"
        )
    lines.extend(
        [
            "",
            "## Production promotion rule",
            "",
            "Promote only when the suite outcome is `PASS`, all required external "
            "evidence above is attached to the same immutable artifact digest, "
            "and every accepted risk has an owner, rationale, and expiry date.",
            "",
        ]
    )
    return "\n".join(lines)


def render_html(manifest: ScanManifest, findings: list[Finding]) -> str:
    tool_versions = {run.tool: run.version for run in manifest.tools}
    ordered = sorted(findings, key=_finding_sort_key)
    finding_cards = "".join(
        _render_html_finding(finding, tool_versions) for finding in ordered
    ) or (
        "<section class='empty'><h3>No normalized findings</h3>"
        "<p>The selected scanners completed without reporting a finding.</p></section>"
    )
    reasons = "".join(
        f"<li>{html.escape(reason)}</li>" for reason in manifest.policy_reasons
    ) or "<li>No policy reason was recorded.</li>"
    gap_rows = "".join(
        "<tr>"
        f"<td><strong>{html.escape(run.tool)}</strong></td>"
        f"<td>{'applicable' if run.applicable else 'not applicable'}</td>"
        f"<td><span class='status {html.escape(run.status.value)}'>"
        f"{html.escape(run.status.value)}</span></td>"
        f"<td>{html.escape(run.error or 'No diagnostic supplied')}</td>"
        f"<td>{html.escape(_coverage_action(run, manifest))}</td>"
        f"<td>{_html_tool_reference(run.tool)}</td>"
        "</tr>"
        for run in manifest.tools
        if run.status.value != "completed"
    ) or (
        "<tr><td>All selected tools</td><td>applicable</td>"
        "<td>completed</td><td>-</td><td>No action</td><td>-</td></tr>"
    )
    tools = "".join(
        "<tr>"
        f"<td><strong>{html.escape(run.tool)}</strong></td>"
        f"<td>{html.escape(run.version)}</td>"
        f"<td>{'applicable' if run.applicable else 'not applicable'}</td>"
        f"<td><span class='status {html.escape(run.status.value)}'>"
        f"{html.escape(run.status.value)}</span></td>"
        f"<td>{run.finding_count}</td>"
        f"<td>{run.duration_seconds:.3f}s</td>"
        f"<td>{html.escape(run.error or 'None')}</td>"
        "</tr>"
        for run in manifest.tools
    )
    area_rows = "".join(
        "<tr>"
        f"<td><strong>{html.escape(area)}</strong></td>"
        f"<td>{area_counts['critical']}</td>"
        f"<td>{area_counts['high']}</td>"
        f"<td>{area_counts['medium']}</td>"
        f"<td>{area_counts['low']}</td>"
        f"<td>{area_counts['informational'] + area_counts['unknown']}</td>"
        f"<td>{area_counts['total']}</td>"
        "</tr>"
        for area, area_counts in _area_summary(findings)
    ) or "<tr><td>No findings</td><td colspan='6'>0</td></tr>"
    counts = manifest.finding_counts
    outcome = html.escape(manifest.outcome.value)
    completed = _completed_tools(manifest.tools)
    applicable = _applicable_tools(manifest.tools)
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
.stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(145px, 1fr));
  gap: .75rem; margin: 1rem 0 1.5rem; }}
.stat {{ background: #fff; border: 1px solid #d5dde7; border-radius: .4rem;
  padding: .85rem 1rem; }}
.stat strong {{ display: block; font-size: 1.45rem; }}
.stat span {{ color: #59677a; font-size: .9rem; }}
.decision {{ background: #eef3f8; border-radius: .4rem; padding: .75rem 1.1rem; }}
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
.compact {{ margin: .35rem 0 0; padding-left: 1.25rem; }}
.empty {{ background: #fff; padding: 1rem; border-radius: .4rem; }}
.footer-note {{ color: #59677a; font-size: .9rem; }}
@media (max-width: 650px) {{
  .page {{ padding: 1rem; }}
  .finding-header {{ display: block; }}
  .finding-header .badge {{ margin-bottom: .5rem; }}
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
<div class="stat"><strong>{len(findings)}</strong><span>Total findings</span></div>
<div class="stat"><strong>{counts.get('critical', 0)}</strong><span>Critical</span></div>
<div class="stat"><strong>{counts.get('high', 0)}</strong><span>High</span></div>
<div class="stat"><strong>{counts.get('medium', 0)}</strong><span>Medium</span></div>
<div class="stat"><strong>{counts.get('low', 0)}</strong><span>Low</span></div>
<div class="stat"><strong>{completed}/{applicable}</strong>
<span>Scanners completed</span></div>
</section>
<section class="decision">
<h2>Decision</h2><ul>{reasons}</ul>
<p><strong>Next action:</strong> {html.escape(_next_action(manifest.outcome))}</p>
<p><a href="action-plan.md">Open the prioritized action plan</a></p>
<p><a href="assurance-case.md">Open the production assurance case</a></p>
</section>
<main>
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
<thead><tr><th>Tool</th><th>Version</th><th>Applicability</th><th>Status</th><th>Findings</th>
<th>Duration</th><th>Diagnostic</th></tr></thead>
<tbody>{tools}</tbody>
</table>
<h2>Coverage gaps and actions</h2>
<table>
<thead><tr><th>Tool</th><th>Applicability</th><th>Status</th>
<th>Reason</th><th>Required action</th><th>Reference</th></tr></thead>
<tbody>{gap_rows}</tbody>
</table>
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
unisolated diagnostic: <strong>{str(manifest.diagnostic_without_isolation).lower()}</strong>;
target code execution: <strong>{str(manifest.execute_target_code).lower()}</strong>.</p>
<p class="footer-note">Detected secret values and raw scanner output are not retained.
Use <code>checksums.sha256</code> to verify the downloadable artifact.</p>
</main>
</div>
</body>
</html>
"""


def render_sarif(findings: list[Finding]) -> dict[str, Any]:
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for finding in findings:
        source = finding.sources[0] if finding.sources else None
        rule_id = (
            f"{source.tool}/{source.rule_id}" if source else finding.finding_id
        )
        rule = {
            "id": rule_id,
            "name": _sarif_name(rule_id),
            "shortDescription": {"text": finding.title},
            "fullDescription": {"text": finding.description},
            "help": {
                "text": (
                    f"Why it matters: {finding.impact}\n\n"
                    f"Recommended action: {finding.remediation}"
                ),
                "markdown": (
                    f"**Why it matters:** {finding.impact}\n\n"
                    f"**Recommended action:** {finding.remediation}"
                ),
            },
            "properties": {
                "security-severity": str(_sarif_security_score(finding.severity)),
                "tags": list(
                    dict.fromkeys(
                        ["security", finding.area, *finding.classifications]
                    )
                ),
            },
        }
        help_uri = _first_reference_uri(finding)
        if help_uri:
            rule["helpUri"] = help_uri
        rules.setdefault(rule_id, rule)
        result: dict[str, Any] = {
            "ruleId": rule_id,
            "level": _sarif_level(finding.severity),
            "message": {"text": finding.title},
            "partialFingerprints": {
                "primaryLocationLineHash": finding.fingerprint
            },
            "properties": {
                "finding_id": finding.finding_id,
                "priority": _finding_priority(finding),
                "area": finding.area,
                "blocking": finding.blocking,
                "confidence": finding.confidence.value,
                "classifications": finding.classifications,
                "impact": finding.impact,
                "recommended_action": finding.remediation,
                "source_tools": [item.tool for item in finding.sources],
                "source_rules": [
                    {
                        "tool": item.tool,
                        "version": item.version,
                        "rule_id": item.rule_id,
                        "native_severity": item.native_severity,
                    }
                    for item in finding.sources
                ],
                "citations": [
                    {
                        "kind": item.kind,
                        "identifier": item.identifier,
                        "title": item.title,
                        "uri": _reference_uri(item),
                    }
                    for item in finding.citations
                ],
            },
        }
        if finding.locations:
            location = finding.locations[0]
            physical: dict[str, Any] = {
                "artifactLocation": {"uri": location.path}
            }
            if location.start_line:
                physical["region"] = {
                    "startLine": location.start_line,
                    "endLine": location.end_line or location.start_line,
                }
            result["locations"] = [{"physicalLocation": physical}]
        results.append(result)
    return {
        "$schema": (
            "https://json.schemastore.org/sarif-2.1.0.json"
        ),
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Python Security Suite",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }


def _area_summary(
    findings: list[Finding],
) -> list[tuple[str, dict[str, int]]]:
    areas: dict[str, dict[str, int]] = {}
    severity_names = [item.value for item in Severity]
    for finding in findings:
        area = finding.area.strip() or "unclassified"
        counts = areas.setdefault(
            area,
            {name: 0 for name in [*severity_names, "total"]},
        )
        counts[finding.severity.value] += 1
        counts["total"] += 1
    return sorted(
        areas.items(),
        key=lambda item: (
            -item[1]["critical"],
            -item[1]["high"],
            -item[1]["medium"],
            -item[1]["low"],
            item[0],
        ),
    )


def _location_text(finding: Finding) -> str:
    if not finding.locations:
        return "<unknown>"
    location = finding.locations[0]
    value = location.path
    if location.start_line:
        value += f":{location.start_line}"
    if location.package:
        package = location.package
        if location.version:
            package += f" {location.version}"
        if location.ecosystem:
            package = f"{location.ecosystem}:{package}"
        value += f" ({package})"
    return value


def _markdown_source(
    source: Source, tool_versions: dict[str, str]
) -> str:
    version = _source_version(source, tool_versions)
    tool_label = source.tool if version == "unknown" else f"{source.tool} {version}"
    return (
        f"`{_markdown_code(tool_label)}` rule "
        f"`{_markdown_code(source.rule_id)}`"
    )


def _markdown_classification(value: str) -> str:
    uri = _classification_uri(value)
    label = _markdown_text(value)
    return f"[{label}]({uri})" if uri else f"`{_markdown_code(value)}`"


def _markdown_citation(citation: Citation) -> str:
    label = citation.identifier
    if citation.title and citation.title != citation.identifier:
        label += f" - {citation.title}"
    uri = _reference_uri(citation)
    escaped = _markdown_text(label)
    return f"[{escaped}]({uri})" if uri else f"`{_markdown_code(label)}`"


def _markdown_tool_reference(tool: str) -> str:
    uri = _TOOL_REFERENCES.get(tool)
    return f"[Official documentation]({uri})" if uri else "-"


def _html_tool_reference(tool: str) -> str:
    uri = _TOOL_REFERENCES.get(tool)
    if uri is None:
        return "-"
    return (
        f"<a href='{html.escape(uri, quote=True)}' rel='noreferrer'>"
        "Official documentation</a>"
    )


def _render_html_finding(
    finding: Finding, tool_versions: dict[str, str]
) -> str:
    severity = html.escape(finding.severity.value)
    sources = "".join(
        "<li>"
        f"<strong>{html.escape(source.tool)}</strong> "
        f"{html.escape(_source_version(source, tool_versions))} - "
        f"rule <code>{html.escape(source.rule_id)}</code>"
        "</li>"
        for source in finding.sources
    ) or "<li>No scanner attribution recorded.</li>"
    classifications = " ".join(
        _html_classification(value) for value in finding.classifications
    ) or "<span class='badge'>Unclassified</span>"
    citations = "".join(
        f"<li>{_html_citation(citation)}</li>"
        for citation in finding.citations
    ) or "<li>No external reference.</li>"
    return (
        f"<article class='finding {severity}'>"
        "<div class='finding-header'>"
        f"<span class='badge {severity}'>"
        f"{html.escape(finding.severity.value.upper())}</span>"
        f"<h3>{html.escape(finding.title)}</h3>"
        "</div>"
        "<div class='metadata'>"
        f"<div><strong>Finding ID:</strong> "
        f"<code>{html.escape(finding.finding_id)}</code></div>"
        f"<div><strong>Priority:</strong> {_finding_priority(finding)}</div>"
        f"<div><strong>Location:</strong> "
        f"<code>{html.escape(_location_text(finding))}</code></div>"
        f"<div><strong>Area:</strong> {html.escape(finding.area)}</div>"
        f"<div><strong>Confidence:</strong> "
        f"{html.escape(finding.confidence.value)}</div>"
        f"<div><strong>Classification:</strong> {classifications}</div>"
        "</div>"
        "<div class='detail-grid'>"
        "<section class='detail'><h4>What was detected</h4>"
        f"<p>{html.escape(finding.description)}</p></section>"
        "<section class='detail'><h4>Found by</h4>"
        f"<ul class='compact'>{sources}</ul></section>"
        "<section class='detail'><h4>References</h4>"
        f"<ul class='compact'>{citations}</ul></section>"
        "<section class='detail'><h4>Why it matters</h4>"
        f"<p>{html.escape(finding.impact)}</p></section>"
        "<section class='detail'><h4>Recommended action</h4>"
        f"<p>{html.escape(finding.remediation)}</p></section>"
        "</div>"
        "</article>"
    )


def _source_version(
    source: Source, tool_versions: dict[str, str]
) -> str:
    version = source.version
    if version == "unknown":
        version = tool_versions.get(source.tool, "unknown")
    if version == "unknown":
        return "unknown"
    lowered = version.casefold()
    tool = source.tool.casefold()
    for prefix in (f"{tool} version: ", f"{tool} "):
        if lowered.startswith(prefix):
            return version[len(prefix):]
    return version


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
            f"<a href='{html.escape(uri, quote=True)}' rel='noreferrer'>"
            f"{escaped}</a>"
        )
    return escaped


def _first_reference_uri(finding: Finding) -> str | None:
    for citation in finding.citations:
        uri = _reference_uri(citation)
        if uri:
            return uri
    for classification in finding.classifications:
        uri = _classification_uri(classification)
        if uri:
            return uri
    return None


def _reference_uri(citation: Citation) -> str | None:
    if citation.uri and citation.uri.startswith(("https://", "http://")):
        return citation.uri
    return _classification_uri(citation.identifier)


def _classification_uri(value: str) -> str | None:
    normalized = value.upper().split(":", 1)[0].strip()
    if normalized.startswith("CWE-") and normalized[4:].isdigit():
        return (
            "https://cwe.mitre.org/data/definitions/"
            f"{normalized[4:]}.html"
        )
    return None


def _write_json(path: Path, value: Any) -> None:
    _write_text(
        path,
        json.dumps(json_ready(value), indent=2, sort_keys=True, ensure_ascii=False)
        + "\n",
    )


def _write_text(path: Path, value: str) -> None:
    path.write_text(value, encoding="utf-8", newline="\n")


def _write_checksums(output: Path) -> None:
    entries = []
    for path in sorted(output.rglob("*")):
        if not path.is_file() or path.name == "checksums.sha256":
            continue
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        entries.append(f"{digest}  {path.relative_to(output).as_posix()}")
    _write_text(output / "checksums.sha256", "\n".join(entries) + "\n")


def _completed_tools(tools: list[ToolRun]) -> int:
    return sum(1 for tool in tools if tool.status.value == "completed")


def _applicable_tools(tools: list[ToolRun]) -> int:
    return sum(1 for tool in tools if tool.applicable)


def _finding_sort_key(finding: Finding) -> tuple[int, str]:
    return (_SEVERITY_ORDER[finding.severity], finding.finding_id)


def _next_action(outcome: Outcome) -> str:
    return {
        Outcome.PASS: "No policy-blocking action is required.",
        Outcome.WARN: "Review the non-blocking findings and record disposition.",
        Outcome.FAIL: "Remediate new blocking findings before merge.",
        Outcome.INCOMPLETE: (
            "Restore required scanner coverage or isolation evidence, then rerun; "
            "do not interpret this result as clean."
        ),
    }[outcome]


def _finding_priority(finding: Finding) -> str:
    return {
        Severity.CRITICAL: "P0",
        Severity.HIGH: "P1",
        Severity.MEDIUM: "P2",
        Severity.LOW: "P3",
        Severity.INFORMATIONAL: "P4",
        Severity.UNKNOWN: "P4",
    }[finding.severity]


def _coverage_action(run: ToolRun, manifest: ScanManifest) -> str:
    if not run.applicable:
        if (
            manifest.profile in {"production", "release"}
            and run.tool == "pysa"
            and manifest.inventory.python_files
        ):
            return (
                "Add a reviewed Pyre/Pysa configuration and models, stage Pysa "
                "on a supported native runner, and rerun."
            )
        if (
            manifest.profile in {"production", "release"}
            and manifest.inventory.declared_dependencies
            and run.tool in {"cyclonedx-py", "guarddog"}
        ):
            return (
                "Provide a supported reproducible dependency lock and run this "
                "control on a compatible native platform."
            )
        return (
            "No current action; rerun if the project gains content or a platform "
            "configuration that makes this scanner applicable."
        )
    actions = {
        "unavailable": (
            "Stage the approved executable and required offline data or rules, "
            "verify its checksum and version, then rerun."
        ),
        "failed": (
            "Inspect the sanitized evidence record, correct the scanner invocation "
            "or local assets, then rerun."
        ),
        "timed_out": (
            "Review the target scope and runner capacity, tune the scanner timeout "
            "under policy, then rerun."
        ),
        "parse_error": (
            "Verify the scanner version/output schema and update the adapter or pin "
            "a compatible version before rerunning."
        ),
        "skipped": "Confirm the skip reason is approved, then rerun if it changes.",
    }
    return actions.get(
        run.status.value,
        "Review the scanner diagnostic and restore completed coverage.",
    )


def _policy_action(reason: str) -> str:
    lowered = reason.casefold()
    if "network-isolation attestation" in lowered:
        return (
            "Run inside an independently enforced egress-denied boundary and pass "
            "--network-isolated only after the runner verifies that control."
        )
    if "full vcs checkout" in lowered:
        return (
            "Use a full immutable clone with history instead of an exported source "
            "directory, then rerun."
        )
    if "lock file" in lowered:
        return (
            "Generate and approve a reproducible lock file, preferably with artifact "
            "hashes, and rerun dependency and SBOM checks."
        )
    if "built wheel or source distribution" in lowered:
        return (
            "Build the immutable release distributions in the approved build lane, "
            "stage them under the configured artifacts path, and rerun."
        )
    if "data-flow" in lowered or "pysa" in lowered:
        return (
            "Add a reviewed Pyre/Pysa configuration and models, stage the approved "
            "scanner, and rerun."
        )
    if "scanner" in lowered:
        return (
            "Restore the named required scanner and its approved offline assets, "
            "then rerun."
        )
    return "Satisfy the stated policy requirement, attach evidence, and rerun."


def _assurance_row(
    manifest: ScanManifest,
    control: str,
    tools: tuple[str, ...],
    action: str,
    reference: str,
) -> tuple[str, str, str, str, str]:
    selected = [run for run in manifest.tools if run.tool in tools]
    applicable = [run for run in selected if run.applicable]
    completed = [run for run in applicable if run.status.value == "completed"]
    if not selected:
        status = "not assessed by profile"
    elif not applicable:
        status = "not applicable to detected content"
    elif len(completed) == len(applicable):
        status = "verified for scan scope"
    elif completed:
        status = "partial coverage"
    else:
        status = "coverage gap"
    evidence = ", ".join(
        f"{run.tool}: {'not applicable' if not run.applicable else run.status.value}"
        for run in selected
    ) or "No relevant scanner was selected."
    return control, status, evidence, action, reference


def _sarif_name(rule_id: str) -> str:
    return "".join(
        character if character.isalnum() else "_" for character in rule_id
    )[:120]


def _sarif_level(severity: Severity) -> str:
    if severity in {Severity.CRITICAL, Severity.HIGH}:
        return "error"
    if severity is Severity.MEDIUM:
        return "warning"
    return "note"


def _sarif_security_score(severity: Severity) -> float:
    return {
        Severity.CRITICAL: 9.5,
        Severity.HIGH: 8.0,
        Severity.MEDIUM: 5.5,
        Severity.LOW: 3.0,
        Severity.INFORMATIONAL: 1.0,
        Severity.UNKNOWN: 0.0,
    }[severity]


def _markdown_text(value: str) -> str:
    escaped = value.replace("\\", "\\\\")
    for character in ("`", "*", "_", "{", "}", "[", "]", "<", ">", "#"):
        escaped = escaped.replace(character, f"\\{character}")
    return escaped.replace("\r", " ").replace("\n", " ")


def _markdown_code(value: str) -> str:
    return value.replace("`", "'").replace("\r", " ").replace("\n", " ")


def _markdown_table(value: str) -> str:
    return _markdown_text(value).replace("|", "\\|")
