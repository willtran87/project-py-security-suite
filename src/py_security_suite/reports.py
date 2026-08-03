from __future__ import annotations

import hashlib
import html
import json
import re
import shutil
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit

from .models import (
    Citation,
    Finding,
    FindingStatus,
    Location,
    Outcome,
    ScanManifest,
    Severity,
    Source,
    ToolRun,
    json_ready,
)
from .source_context import source_language
from .passport import (
    REQUIRED_REPORT_ARTIFACTS,
    build_security_passport_statement,
    verify_report,
)


REPORT_FILES = tuple(REQUIRED_REPORT_ARTIFACTS.values())
_MAX_REFERENCE_URI = 2048
_UNSAFE_MARKDOWN_URI_CHARACTERS = frozenset("()<>\\")

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
    "ruff-quality": "https://docs.astral.sh/ruff/linter/",
    "ruff-format": "https://docs.astral.sh/ruff/formatter/",
    "pylint": "https://pylint.readthedocs.io/",
    "mypy": "https://mypy.readthedocs.io/",
    "vulture": "https://github.com/jendrikseipp/vulture",
    "radon": "https://radon.readthedocs.io/",
    "tach": "https://docs.gauge.sh/",
    "coverage": "https://coverage.readthedocs.io/",
    "junit": "https://github.com/testmoapp/junitxml",
    "hypothesis": "https://hypothesis.readthedocs.io/",
    "schemathesis": "https://schemathesis.readthedocs.io/",
    "actionlint": "https://github.com/rhysd/actionlint",
    "hadolint": "https://github.com/hadolint/hadolint",
    "devskim": "https://github.com/microsoft/DevSkim",
    "flawfinder": "https://dwheeler.com/flawfinder/",
    "reuse": "https://reuse.software/",
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
    "psscriptanalyzer": "https://learn.microsoft.com/powershell/utility-modules/psscriptanalyzer/overview",
    "shellcheck": "https://github.com/koalaman/shellcheck",
    "deptry": "https://deptry.com/",
    "diff-cover": "https://github.com/Bachmann1234/diff-cover",
    "checkov": "https://www.checkov.io/",
    "cosign": "https://docs.sigstore.dev/cosign/",
    "pyright": "https://microsoft.github.io/pyright/",
    "scorecard": "https://scorecard.dev/",
    "conftest": "https://www.conftest.dev/",
    "kics": "https://docs.kics.io/latest/",
    "pipdeptree": "https://pipdeptree.readthedocs.io/",
    "git-sizer": "https://github.com/github/git-sizer",
    "validate-pyproject": "https://validate-pyproject.readthedocs.io/",
    "vale": "https://vale.sh/",
    "kube-linter": "https://docs.kubelinter.io/",
    "crosshair": "https://crosshair.readthedocs.io/",
    "atheris": "https://github.com/google/atheris",
    "mutmut": "https://mutmut.readthedocs.io/",
    "check-manifest": "https://github.com/mgedmin/check-manifest",
    "clamav": "https://docs.clamav.net/",
    "github-attestation": "https://docs.github.com/en/actions/security-guides/using-artifact-attestations-to-establish-provenance-for-builds",
    "zap": "https://www.zaproxy.org/docs/automate/automation-framework/",
    "pytm": "https://owasp.org/www-project-pytm/",
    "in-toto": "https://in-toto.io/docs/getting-started/",
    "oci-image": "https://opencontainers.org/",
    "reproducible-build": "https://reproducible-builds.org/tools/",
    "yara": "https://yara.readthedocs.io/",
}


def write_reports(
    *,
    output: Path,
    findings: list[Finding],
    manifest: ScanManifest,
    diagnostics: dict[str, dict[str, Any]],
    include_evidence: bool,
    derived_artifacts: dict[str, Any] | None = None,
    replace_existing: bool = False,
) -> None:
    output = output.expanduser().absolute()
    if (output.exists() or output.is_symlink()) and not replace_existing:
        raise FileExistsError(f"report output already exists: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(
        tempfile.mkdtemp(prefix=f".{output.name}.staging-", dir=output.parent)
    )
    try:
        _write_report_contents(
            output=staging,
            findings=findings,
            manifest=manifest,
            diagnostics=diagnostics,
            include_evidence=include_evidence,
            derived_artifacts=derived_artifacts,
        )
        verify_report(staging)
        _publish_report(staging, output, replace_existing=replace_existing)
    finally:
        if staging.exists():
            shutil.rmtree(staging)


def is_complete_report(output: Path) -> bool:
    """Return whether an existing directory is a complete verified report."""
    try:
        verify_report(output)
    except (OSError, ValueError):
        return False
    return all((output / name).is_file() for name in REPORT_FILES)


def _publish_report(staging: Path, output: Path, *, replace_existing: bool) -> None:
    lock = output.parent / f".{output.name}.publish-lock"
    try:
        lock.mkdir()
    except FileExistsError as exc:
        raise FileExistsError(
            f"report publication is already active or requires recovery: {lock}"
        ) from exc
    try:
        _publish_report_locked(
            staging,
            output,
            replace_existing=replace_existing,
        )
    finally:
        lock.rmdir()


def _publish_report_locked(
    staging: Path,
    output: Path,
    *,
    replace_existing: bool,
) -> None:
    if not output.exists() and not output.is_symlink():
        staging.rename(output)
        return
    if not replace_existing:
        raise FileExistsError(f"report output appeared during generation: {output}")
    if output.is_symlink() or not output.is_dir():
        raise FileExistsError(f"report output is not a replaceable directory: {output}")
    if any(output.iterdir()) and not is_complete_report(output):
        raise FileExistsError(
            f"report output is not a complete verified suite report: {output}"
        )
    backup = Path(tempfile.mkdtemp(prefix=f".{output.name}.backup-", dir=output.parent))
    backup.rmdir()
    published = False
    output.rename(backup)
    try:
        staging.rename(output)
        published = True
    except BaseException:
        if not output.exists() and not output.is_symlink():
            backup.rename(output)
        raise
    finally:
        if published and backup.exists():
            shutil.rmtree(backup)


def _write_report_contents(
    *,
    output: Path,
    findings: list[Finding],
    manifest: ScanManifest,
    diagnostics: dict[str, dict[str, Any]],
    include_evidence: bool,
    derived_artifacts: dict[str, Any] | None,
) -> None:
    _register_report_artifacts(manifest, derived_artifacts)
    active_findings = [
        finding
        for finding in findings
        if finding.status is not FindingStatus.SUPPRESSED
    ]
    _write_primary_report_files(output, manifest, findings, active_findings)
    _write_evidence(output, manifest, diagnostics, include_evidence)
    _write_derived_artifacts(output, derived_artifacts)
    _write_json(output / "scan-manifest.json", manifest)
    _write_json(
        output / "security-passport.json",
        build_security_passport_statement(output, manifest),
    )
    _write_checksums(output)


def _register_report_artifacts(
    manifest: ScanManifest, derived_artifacts: dict[str, Any] | None
) -> None:
    manifest.artifacts = dict(REQUIRED_REPORT_ARTIFACTS)
    for name in sorted(derived_artifacts or {}):
        if (
            "/" in name
            or "\\" in name
            or name in REPORT_FILES
            or name in REQUIRED_REPORT_ARTIFACTS
        ):
            raise ValueError(f"unsafe or reserved derived artifact name: {name}")
        manifest.artifacts[name] = name


def _write_primary_report_files(
    output: Path,
    manifest: ScanManifest,
    findings: list[Finding],
    active_findings: list[Finding],
) -> None:
    _write_text(output / "summary.md", render_summary(manifest, findings))
    _write_text(
        output / "action-plan.md", render_action_plan(manifest, active_findings)
    )
    _write_text(output / "assurance-case.md", render_assurance_case(manifest))
    _write_text(output / "index.html", render_html(manifest, findings))
    _write_json(output / "results.sarif", render_sarif(active_findings))
    _write_json(
        output / "sonarqube-external-issues.json",
        render_sonarqube_external_issues(active_findings),
    )
    _write_json(
        output / "findings.json",
        {
            "schema_version": "1.0",
            "scan_id": manifest.scan_id,
            "outcome": manifest.outcome,
            "target": manifest.target,
            "profile": manifest.profile,
            "source_sha256": manifest.inventory.source_sha256,
            "findings": findings,
        },
    )


def _write_evidence(
    output: Path,
    manifest: ScanManifest,
    diagnostics: dict[str, dict[str, Any]],
    include_evidence: bool,
) -> None:
    if include_evidence:
        evidence = output / "evidence"
        evidence.mkdir()
        for tool, diagnostic in sorted(diagnostics.items()):
            _write_json(evidence / f"{tool}.json", diagnostic)
        manifest.artifacts["evidence"] = "evidence/"


def _write_derived_artifacts(
    output: Path, derived_artifacts: dict[str, Any] | None
) -> None:
    for name, value in sorted((derived_artifacts or {}).items()):
        _write_json(output / name, value)


def render_summary(manifest: ScanManifest, findings: list[Finding]) -> str:
    active_findings = [
        finding
        for finding in findings
        if finding.status is not FindingStatus.SUPPRESSED
    ]
    coverage_gaps = _applicable_scanner_gaps(manifest.tools)
    not_applicable = _not_applicable_scanners(manifest.tools)
    tool_versions = {run.tool: run.version for run in manifest.tools}
    lines = _render_summary_header(
        manifest,
        active_findings,
        governed_count=len(findings) - len(active_findings),
        coverage_gap_count=len(coverage_gaps),
    )
    lines.extend(["", "## Decision", ""])
    lines.extend(f"- {reason}" for reason in manifest.policy_reasons)
    lines.extend(_render_finding_lifecycle(manifest, active_findings))
    lines.extend(_render_finding_rollups(active_findings))
    lines.extend(_render_markdown_findings(active_findings, tool_versions))
    lines.extend(_render_tool_coverage(manifest.tools, coverage_gaps, not_applicable))
    lines.extend(_render_coverage_actions(manifest, coverage_gaps, not_applicable))
    lines.extend(_render_derived_evidence(manifest))
    lines.extend(_render_triage_workflow(manifest.outcome))
    return "\n".join(lines)


def _render_summary_header(
    manifest: ScanManifest,
    active_findings: list[Finding],
    *,
    governed_count: int,
    coverage_gap_count: int,
) -> list[str]:
    counts = {
        severity.value: sum(finding.severity is severity for finding in active_findings)
        for severity in Severity
    }
    return [
        f"# Security result: {manifest.outcome.value.upper()}",
        "",
        f"- **Scan:** `{_markdown_code(manifest.scan_id)}`",
        f"- **Profile:** `{_markdown_code(manifest.profile)}`",
        f"- **Target:** `{_markdown_code(manifest.target)}`",
        f"- **Scan-policy disposition:** {_policy_disposition(manifest.outcome)}",
        f"- **Findings:** {len(active_findings)} active, {governed_count} governed; "
        f"{counts.get('critical', 0)} critical, {counts.get('high', 0)} high, "
        f"{counts.get('medium', 0)} medium, {counts.get('low', 0)} low",
        f"- **Applicable scanners completed:** "
        f"{_completed_tools(manifest.tools)}/{_applicable_tools(manifest.tools)}",
        f"- **Not applicable:** "
        f"{len(manifest.tools) - _applicable_tools(manifest.tools)} selected tool(s)",
        f"- **Applicable scanner execution gaps:** {coverage_gap_count}",
        f"- **Network isolation attested:** "
        f"{'yes' if manifest.network_isolation_attested else 'no'}",
        f"- **Unisolated diagnostic execution:** "
        f"{'yes' if manifest.diagnostic_without_isolation else 'no'}",
        f"- **Target content integrity:** "
        f"{'verified unchanged' if manifest.inventory.source_integrity_verified else 'not verified'} "
        f"(`sha256:{_markdown_code(manifest.inventory.source_sha256)}`; "
        f"{manifest.inventory.hashed_files} files, "
        f"{manifest.inventory.hashed_bytes} bytes)",
        f"- **Immediate next step:** {_next_action(manifest.outcome)}",
    ]


def _render_finding_lifecycle(
    manifest: ScanManifest, active_findings: list[Finding]
) -> list[str]:
    lifecycle = {
        status.value: sum(finding.status is status for finding in active_findings)
        for status in (
            FindingStatus.NEW,
            FindingStatus.EXISTING,
            FindingStatus.REGRESSION,
        )
    }
    resolved = (
        int(manifest.baseline.get("counts", {}).get("resolved", 0))
        if isinstance(manifest.baseline.get("counts"), dict)
        else 0
    )
    return [
        "",
        "## Finding lifecycle",
        "",
        f"- New: {lifecycle['new']}",
        f"- Existing: {lifecycle['existing']}",
        f"- Regressed: {lifecycle['regression']}",
        f"- Resolved since baseline: {resolved}",
    ]


def _render_finding_rollups(active_findings: list[Finding]) -> list[str]:
    lines = ["", "## Findings by domain", ""]
    lines.append("| Domain | Findings | Blocking |")
    lines.append("|---|---:|---:|")
    for domain, domain_findings in _domain_summary(active_findings):
        lines.append(
            f"| {_markdown_table(domain)} | {len(domain_findings)} | "
            f"{sum(1 for finding in domain_findings if finding.blocking)} |"
        )
    if not active_findings:
        lines.append("| No findings | 0 | 0 |")

    lines.extend(["", "## Findings by area", ""])
    lines.append(
        "| Area | Critical | High | Medium | Low | Informational/Unknown | Total |"
    )
    lines.append("|---|---:|---:|---:|---:|---:|---:|")
    for area, area_counts in _area_summary(active_findings):
        lines.append(
            f"| {_markdown_table(area)} | {area_counts['critical']} | "
            f"{area_counts['high']} | {area_counts['medium']} | "
            f"{area_counts['low']} | "
            f"{area_counts['informational'] + area_counts['unknown']} | "
            f"{area_counts['total']} |"
        )
    if not active_findings:
        lines.append("| No findings | 0 | 0 | 0 | 0 | 0 | 0 |")
    return lines


def _render_tool_coverage(
    tools: list[ToolRun],
    coverage_gaps: list[ToolRun],
    not_applicable: list[ToolRun],
) -> list[str]:
    lines = [
        "",
        "## Tool coverage",
        "",
        f"- Applicable scanners: {_applicable_tools(tools)}",
        f"- Completed scanners: {_completed_tools(tools)}",
        f"- Applicable execution gaps: {len(coverage_gaps)}",
        f"- Conditional controls not applicable: {len(not_applicable)}",
        "",
        f"<details><summary>All {len(tools)} selected scanner results</summary>",
        "",
    ]
    lines.append(
        "| Tool | Version | Applicability | Status | Entry-point integrity | "
        "Findings | Duration |"
    )
    lines.append("|---|---|---:|---:|---|---:|---:|")
    lines.extend(
        (
            f"| {_markdown_table(run.tool)} | {_markdown_table(run.version)} | "
            f"{'applicable' if run.applicable else 'not applicable'} | "
            f"{_markdown_table(run.status.value)} | "
            f"{_markdown_table(_executable_integrity_label(run))} | "
            f"{run.finding_count} | {run.duration_seconds:.3f}s |"
        )
        for run in tools
    )
    lines.extend(["", "</details>"])
    return lines


def _render_coverage_actions(
    manifest: ScanManifest,
    coverage_gaps: list[ToolRun],
    not_applicable: list[ToolRun],
) -> list[str]:
    lines = ["", "## Coverage gaps and actions", ""]
    lines.append("| Tool | Status | Reason | Required action | Reference |")
    lines.append("|---|---|---|---|---|")
    lines.extend(
        (
            f"| {_markdown_table(run.tool)} | "
            f"{_markdown_table(run.status.value)} | "
            f"{_markdown_table(run.error or 'No diagnostic supplied')} | "
            f"{_markdown_table(_coverage_action(run, manifest))} | "
            f"{_markdown_tool_reference(run.tool)} |"
        )
        for run in coverage_gaps
    )
    if not coverage_gaps:
        lines.append("| All applicable tools | completed | - | No action | - |")

    if not_applicable:
        lines.extend(
            [
                "",
                f"<details><summary>{len(not_applicable)} not-applicable controls "
                "(informational)</summary>",
                "",
                "| Tool | Reason | Re-enable condition | Reference |",
                "|---|---|---|---|",
            ]
        )
        lines.extend(
            (
                f"| {_markdown_table(run.tool)} | "
                f"{_markdown_table(run.error or 'No diagnostic supplied')} | "
                f"{_markdown_table(_coverage_action(run, manifest))} | "
                f"{_markdown_tool_reference(run.tool)} |"
            )
            for run in not_applicable
        )
        lines.extend(["", "</details>"])
    return lines


def _render_derived_evidence(manifest: ScanManifest) -> list[str]:
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
    if not derived:
        return []
    return [
        "",
        "## Derived assurance evidence",
        "",
        *(
            f"- [`{_markdown_code(value)}`]({_markdown_code(value)})"
            for value in derived
        ),
    ]


def _render_triage_workflow(outcome: Outcome) -> list[str]:
    return [
        "## Triage workflow",
        "",
        _next_action(outcome),
        "",
        "1. Open the cited location and validate whether the scanner's premise "
        + "is true in this execution context.",
        "2. Choose a disposition: fix, accepted risk, false positive, or "
        + "approved suppression.",
        "3. Record the owner and rationale in the repository's normal review system.",
        "4. Rerun the isolated suite and confirm the finding ID is resolved or "
        + "intentionally governed.",
        "",
        "The downloadable artifact contains detailed findings, citations, tool "
        + "health, the scan manifest, sanitized diagnostics, and checksums.",
        "",
    ]


def _render_markdown_findings(
    findings: list[Finding],
    tool_versions: dict[str, str],
) -> list[str]:
    lines = ["", "## Findings requiring review", ""]
    if not findings:
        return [*lines, "- No normalized findings.", ""]
    ordered = sorted(findings, key=_finding_sort_key)
    for index, finding in enumerate(ordered[:20], start=1):
        sources = (
            "; ".join(
                _markdown_source(source, tool_versions) for source in finding.sources
            )
            or "No scanner attribution recorded"
        )
        classifications = (
            "; ".join(
                _markdown_classification(item) for item in finding.classifications
            )
            or "Unclassified"
        )
        references = (
            "; ".join(_markdown_citation(item) for item in finding.citations)
            or "No external reference"
        )
        lines.extend(
            [
                f"### {index}. {finding.severity.value.upper()} - "
                f"{_markdown_text(finding.title)}",
                "",
                f"- **Finding ID:** `{_markdown_code(finding.finding_id)}`",
                f"- **Priority:** `{_finding_priority(finding)}`",
                f"- **Lifecycle:** `{finding.status.value}`",
                f"- **Owners:** {_finding_owners(finding)}",
                f"- **Threat intelligence:** {_threat_intelligence_summary(finding)}",
                f"- **Location:** `{_markdown_code(_location_text(finding))}`",
                f"- **Found by:** {sources}",
                f"- **Domain / area / confidence:** "
                f"`{_markdown_code(finding.domain)}` / "
                f"`{_markdown_code(finding.area)}` / "
                f"`{_markdown_code(finding.confidence.value)}`",
                f"- **Classification:** {classifications}",
                f"- **References:** {references}",
                "",
                f"**What was detected:** {_markdown_text(finding.description)}",
                "",
                *_markdown_source_excerpt(finding),
                f"**Why it matters:** {_markdown_text(finding.impact)}",
                "",
                f"**Recommended action:** {_markdown_text(finding.remediation)}",
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
    return lines


def render_action_plan(manifest: ScanManifest, findings: list[Finding]) -> str:
    coverage_gaps = _applicable_scanner_gaps(manifest.tools)
    not_applicable = _not_applicable_scanners(manifest.tools)
    blocking = sum(1 for finding in findings if finding.blocking)
    lines = [
        "# Security action plan",
        "",
        f"- **Scan:** `{_markdown_code(manifest.scan_id)}`",
        f"- **Outcome:** `{_markdown_code(manifest.outcome.value)}`",
        f"- **Profile:** `{_markdown_code(manifest.profile)}`",
        f"- **Scan-policy disposition:** {_policy_disposition(manifest.outcome)}",
        f"- **Blocking findings:** {blocking}",
        f"- **Applicable scanner execution gaps:** {len(coverage_gaps)}",
        f"- **Conditional controls not applicable:** {len(not_applicable)}",
        f"- **Immediate next step:** {_next_action(manifest.outcome)}",
        "",
        "## Finding actions",
        "",
        "| Priority | Domain | Severity | Finding | Area | Location | Sources | Action |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for finding in sorted(findings, key=_finding_sort_key):
        sources = (
            ", ".join(f"{source.tool}/{source.rule_id}" for source in finding.sources)
            or "unattributed"
        )
        lines.append(
            f"| {_finding_priority(finding)} | "
            f"{_markdown_table(finding.domain)} | "
            f"{_markdown_table(finding.severity.value)} | "
            f"[`{_markdown_code(finding.finding_id)}` "
            f"{_markdown_table(finding.title)}]"
            f"(index.html#{quote(finding.finding_id, safe='')}) | "
            f"{_markdown_table(finding.area)} | "
            f"`{_markdown_code(_location_text(finding))}` | "
            f"{_markdown_table(sources)} | "
            f"{_markdown_table(finding.remediation)} |"
        )
    if not findings:
        lines.append("| - | - | - | No normalized findings | - | - | - | No action |")

    lines.extend(
        [
            "",
            "## Coverage actions",
            "",
            "| Tool | Applicability | Status | Reason | Action | Reference |",
            "|---|---|---|---|---|---|",
        ]
    )
    lines.extend(
        (
            f"| {_markdown_table(run.tool)} | "
            f"{'applicable' if run.applicable else 'not applicable'} | "
            f"{_markdown_table(run.status.value)} | "
            f"{_markdown_table(run.error or 'No diagnostic supplied')} | "
            f"{_markdown_table(_coverage_action(run, manifest))} | "
            f"{_markdown_tool_reference(run.tool)} |"
        )
        for run in coverage_gaps
    )
    if not coverage_gaps:
        lines.append(
            "| All applicable tools | applicable | completed | - | No action | - |"
        )
    if not_applicable:
        lines.extend(
            [
                "",
                f"<details><summary>{len(not_applicable)} not-applicable controls "
                "(informational)</summary>",
                "",
                "| Tool | Reason | Re-enable condition | Reference |",
                "|---|---|---|---|",
            ]
        )
        lines.extend(
            (
                f"| {_markdown_table(run.tool)} | "
                f"{_markdown_table(run.error or 'No diagnostic supplied')} | "
                f"{_markdown_table(_coverage_action(run, manifest))} | "
                f"{_markdown_tool_reference(run.tool)} |"
            )
            for run in not_applicable
        )
        lines.extend(["", "</details>"])
    lines.extend(
        [
            "",
            "## Policy and release-evidence actions",
            "",
            "| Requirement | Required action |",
            "|---|---|",
        ]
    )
    lines.extend(
        (f"| {_markdown_table(reason)} | {_markdown_table(_policy_action(reason))} |")
        for reason in manifest.policy_reasons
    )
    if not manifest.policy_reasons:
        lines.append("| All configured policy requirements | No action |")
    lines.extend(
        [
            "",
            "## Disposition record",
            "",
            "For each finding, record an owner and one disposition: fixed, accepted "
            + "risk, false positive, or approved suppression. Preserve the finding ID "
            + "and cited scanner rule in the review record, then rerun the suite.",
            "",
        ]
    )
    return "\n".join(lines)


def render_assurance_case(manifest: ScanManifest) -> str:
    executed = [run for run in manifest.tools if run.executable_sha256 is not None]
    verified = [
        run
        for run in executed
        if run.executable_integrity_verified and run.executable_unchanged
    ]
    auxiliary = [
        run for run in manifest.tools if run.auxiliary_executable_sha256 is not None
    ]
    auxiliary_verified = [
        run
        for run in auxiliary
        if run.auxiliary_executable_integrity_verified
        and run.auxiliary_executable_unchanged
    ]
    entrypoint_count = len(executed) + len(auxiliary)
    verified_entrypoint_count = len(verified) + len(auxiliary_verified)
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
            "Code quality and architecture",
            (
                "ruff-quality",
                "ruff-format",
                "pylint",
                "mypy",
                "vulture",
                "radon",
                "tach",
            ),
            "Resolve correctness, complexity, formatting, typing, dead-code, "
            "and architecture findings before promotion.",
            "https://docs.gauge.sh/",
        ),
        _assurance_row(
            manifest,
            "Automated test evidence",
            ("coverage", "junit"),
            "Generate branch-enabled coverage JSON and passing JUnit XML in a "
            "disposable test lane, then attach both reports to the scan.",
            "https://coverage.readthedocs.io/en/latest/commands/cmd_reporting.html",
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
            ("trivy", "zizmor", "actionlint", "hadolint"),
            "Scan the final deployment definitions and CI workflows used for the "
            "release.",
            "https://csrc.nist.gov/pubs/sp/800/218/final",
        ),
        _assurance_row(
            manifest,
            "License and source inventory",
            ("scancode", "trivy", "reuse"),
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
                "Target content integrity",
                (
                    "verified unchanged"
                    if manifest.inventory.source_integrity_verified
                    else "coverage gap"
                ),
                (
                    f"Before/after source snapshots covered "
                    f"{manifest.inventory.hashed_files} files and "
                    f"{manifest.inventory.hashed_bytes} bytes; initial digest "
                    f"sha256:{manifest.inventory.source_sha256}."
                ),
                (
                    "Investigate target writes or concurrent edits and rerun from "
                    "an immutable checkout."
                    if not manifest.inventory.source_integrity_verified
                    else "Preserve the scan manifest and checksums with the release."
                ),
                "https://slsa.dev/spec/v1.0/levels",
            ),
            (
                "Scanner entry-point integrity",
                (
                    "verified"
                    if entrypoint_count
                    and verified_entrypoint_count == entrypoint_count
                    else "coverage gap"
                ),
                (
                    f"{verified_entrypoint_count}/{entrypoint_count} resolved "
                    "scanner and helper entry points "
                    "matched an approved SHA-256 digest and remained unchanged "
                    "through execution."
                ),
                (
                    "Pin approved executable_sha256 values (and CodeQL auxiliary "
                    "CLI digest), then rerun."
                    if verified_entrypoint_count != entrypoint_count
                    else "Preserve the approved tool configuration with the release."
                ),
                "https://csrc.nist.gov/pubs/sp/800/218/final",
            ),
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
                "Target code execution is prohibited in this static scanning boundary.",
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
        + "separate release evidence. It is not a certification or a guarantee that "
        + "the software is vulnerability-free.",
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
            + "evidence above is attached to the same immutable artifact digest, "
            + "and every accepted risk has an owner, rationale, and expiry date.",
            "",
        ]
    )
    return "\n".join(lines)


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


def _html_not_applicable_details(
    manifest: ScanManifest, not_applicable: list[ToolRun]
) -> str:
    if not not_applicable:
        return ""
    rows = "".join(
        "<tr>"
        f"<td><strong>{html.escape(run.tool)}</strong></td>"
        f"<td>{html.escape(run.error or 'No diagnostic supplied')}</td>"
        f"<td>{html.escape(_coverage_action(run, manifest))}</td>"
        f"<td>{_html_tool_reference(run.tool)}</td>"
        "</tr>"
        for run in not_applicable
    )
    return (
        "<details class='coverage-details'><summary>"
        f"{len(not_applicable)} not-applicable controls (informational)"
        "</summary><table><thead><tr><th>Tool</th><th>Reason</th>"
        "<th>Re-enable condition</th><th>Reference</th></tr></thead>"
        f"<tbody>{rows}</tbody></table></details>"
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


def render_html(manifest: ScanManifest, findings: list[Finding]) -> str:
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
    not_applicable_details = _html_not_applicable_details(manifest, not_applicable)
    tools = _html_tool_rows(manifest.tools)
    area_rows = _html_area_rows(active_findings)
    counts = _severity_counts(active_findings)
    outcome = html.escape(manifest.outcome.value)
    decision = _policy_decision_value(manifest.outcome)
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
<div class="stat"><strong>{
        "yes" if manifest.inventory.source_integrity_verified else "no"
    }</strong><span>Target unchanged</span></div>
</section>
<section class="decision">
<h2>Decision: <span class="decision-badge {decision.lower()}">{decision}</span></h2>
<ul>{reasons}</ul>
<p><strong>Next action:</strong> {html.escape(_next_action(manifest.outcome))}</p>
<p><a href="action-plan.md">Open the prioritized action plan</a></p>
<p><a href="assurance-case.md">Open the production assurance case</a></p>
</section>
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


def render_sarif(findings: list[Finding]) -> dict[str, Any]:
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for finding in findings:
        source = finding.sources[0] if finding.sources else None
        rule_id = f"{source.tool}/{source.rule_id}" if source else finding.finding_id
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
                        [finding.domain, finding.area, *finding.classifications]
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
            "partialFingerprints": {"primaryLocationLineHash": finding.fingerprint},
            "properties": {
                "finding_id": finding.finding_id,
                "priority": _finding_priority(finding),
                "domain": finding.domain,
                "area": finding.area,
                "blocking": finding.blocking,
                "confidence": finding.confidence.value,
                "lifecycle": finding.status.value,
                "owners": _owner_values(finding),
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
            physical: dict[str, Any] = {"artifactLocation": {"uri": location.path}}
            if location.start_line:
                region: dict[str, Any] = {
                    "startLine": location.start_line,
                    "endLine": location.end_line or location.start_line,
                }
                if location.snippet and not location.snippet_redacted:
                    highlighted = _highlighted_snippet(location)
                    if highlighted:
                        region["snippet"] = {"text": highlighted}
                    snippet_start = location.snippet_start_line or location.start_line
                    physical["contextRegion"] = {
                        "startLine": snippet_start,
                        "endLine": (
                            snippet_start + len(location.snippet.splitlines()) - 1
                        ),
                        "snippet": {"text": location.snippet},
                    }
                physical["region"] = region
            result["locations"] = [{"physicalLocation": physical}]
        results.append(result)
    return {
        "$schema": ("https://json.schemastore.org/sarif-2.1.0.json"),
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


def render_sonarqube_external_issues(findings: list[Finding]) -> dict[str, Any]:
    """Render SonarQube's portable generic external-issue format."""

    issues: list[dict[str, Any]] = []
    for finding in findings:
        source = finding.sources[0] if finding.sources else None
        location = (
            finding.locations[0] if finding.locations else Location(path="<repository>")
        )
        issue: dict[str, Any] = {
            "engineId": "py-security-suite",
            "ruleId": f"{source.tool}/{source.rule_id}"
            if source
            else finding.finding_id,
            "severity": {
                Severity.CRITICAL: "BLOCKER",
                Severity.HIGH: "CRITICAL",
                Severity.MEDIUM: "MAJOR",
                Severity.LOW: "MINOR",
                Severity.INFORMATIONAL: "INFO",
                Severity.UNKNOWN: "INFO",
            }[finding.severity],
            "type": "VULNERABILITY"
            if finding.domain in {"security", "supply-chain"}
            else "CODE_SMELL",
            "primaryLocation": {
                "message": f"{finding.title}. Recommended action: {finding.remediation}",
                "filePath": location.path,
            },
        }
        if location.start_line:
            issue["primaryLocation"]["textRange"] = {
                "startLine": location.start_line,
                "endLine": location.end_line or location.start_line,
            }
        issues.append(issue)
    return {"issues": issues}


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


def _domain_summary(findings: list[Finding]) -> list[tuple[str, list[Finding]]]:
    domains: dict[str, list[Finding]] = {}
    for finding in findings:
        domain = finding.domain.strip() or "unclassified"
        domains.setdefault(domain, []).append(finding)
    return sorted(
        domains.items(),
        key=lambda item: (-len(item[1]), item[0].casefold()),
    )


def _location_text(finding: Finding) -> str:
    if not finding.locations:
        return "<unknown>"
    location = finding.locations[0]
    value = location.path
    if location.start_line:
        value += f":{location.start_line}"
        if location.end_line and location.end_line != location.start_line:
            value += f"-{location.end_line}"
    if location.package:
        package = location.package
        if location.version:
            package += f" {location.version}"
        if location.ecosystem:
            package = f"{location.ecosystem}:{package}"
        value += f" ({package})"
    return value


def _markdown_source(source: Source, tool_versions: dict[str, str]) -> str:
    version = _source_version(source, tool_versions)
    tool_label = source.tool if version == "unknown" else f"{source.tool} {version}"
    return f"`{_markdown_code(tool_label)}` rule `{_markdown_code(source.rule_id)}`"


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


def _markdown_source_excerpt(finding: Finding) -> list[str]:
    location = _primary_snippet_location(finding)
    if location is None or location.snippet is None:
        return [
            "**Source evidence:** No safe local source excerpt was available; "
            + "use the cited file and line above.",
            "",
        ]
    start = location.snippet_start_line or location.start_line or 1
    lines = location.snippet.splitlines() or [""]
    numbered = []
    for offset, value in enumerate(lines):
        number = start + offset
        marker = ">" if _line_is_highlighted(location, number) else " "
        numbered.append(f"{marker} {number:>5} | {value}")
    body = "\n".join(numbered)
    fence = "`" * max(3, _longest_backtick_run(body) + 1)
    language = source_language(location.path)
    result = [
        f"**Source evidence - `{_markdown_code(_location_text(finding))}`:**",
        "",
        f"{fence}{language}",
        body,
        fence,
        "",
    ]
    if location.snippet_redacted:
        result.extend(
            [
                "_The secret-bearing line is deliberately redacted from every "
                + "report format. Inspect it only in the protected checkout._",
                "",
            ]
        )
    return result


def _html_source_excerpt(finding: Finding) -> str:
    location = _primary_snippet_location(finding)
    if location is None or location.snippet is None:
        return (
            "<section class='source-context'><h4>Source evidence</h4>"
            "<p>No safe local source excerpt was available; use the cited file "
            "and line.</p></section>"
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


def _primary_snippet_location(finding: Finding) -> Location | None:
    return next(
        (location for location in finding.locations if location.snippet is not None),
        None,
    )


def _line_is_highlighted(location: Location, number: int) -> bool:
    start = location.start_line or number
    end = location.end_line or start
    return start <= number <= end


def _highlighted_snippet(location: Location) -> str:
    if location.snippet is None:
        return ""
    snippet_start = location.snippet_start_line or location.start_line or 1
    return "\n".join(
        value
        for offset, value in enumerate(location.snippet.splitlines())
        if _line_is_highlighted(location, snippet_start + offset)
    )


def _longest_backtick_run(value: str) -> int:
    return max((len(match.group(0)) for match in re.finditer(r"`+", value)), default=0)


def _source_version(source: Source, tool_versions: dict[str, str]) -> str:
    version = source.version
    if version == "unknown":
        version = tool_versions.get(source.tool, "unknown")
    if version == "unknown":
        return "unknown"
    lowered = version.casefold()
    tool = source.tool.casefold()
    for prefix in (f"{tool} version: ", f"{tool} "):
        if lowered.startswith(prefix):
            return version[len(prefix) :]
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
            f"<a href='{html.escape(uri, quote=True)}' rel='noreferrer'>{escaped}</a>"
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
    if citation.uri:
        uri = _safe_http_reference(citation.uri)
        if uri:
            return uri
    return _classification_uri(citation.identifier)


def _safe_http_reference(value: str) -> str | None:
    if len(value) > _MAX_REFERENCE_URI or _has_unsafe_reference_character(value):
        return None
    return value if _is_well_formed_http_reference(value) else None


def _has_unsafe_reference_character(value: str) -> bool:
    return any(
        not character.isprintable()
        or character.isspace()
        or character in _UNSAFE_MARKDOWN_URI_CHARACTERS
        for character in value
    )


def _is_well_formed_http_reference(value: str) -> bool:
    try:
        parsed = urlsplit(value)
        _ = parsed.port
    except ValueError:
        return False
    return (
        parsed.scheme.lower() in {"http", "https"}
        and bool(parsed.hostname)
        and parsed.username is None
        and parsed.password is None
    )


def _classification_uri(value: str) -> str | None:
    normalized = value.upper().split(":", 1)[0].strip()
    if normalized.startswith("CWE-") and normalized[4:].isdigit():
        return f"https://cwe.mitre.org/data/definitions/{normalized[4:]}.html"
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


def _applicable_scanner_gaps(tools: list[ToolRun]) -> list[ToolRun]:
    return [
        tool for tool in tools if tool.applicable and tool.status.value != "completed"
    ]


def _not_applicable_scanners(tools: list[ToolRun]) -> list[ToolRun]:
    return [tool for tool in tools if not tool.applicable]


def _executable_integrity_label(run: ToolRun) -> str:
    primary = _integrity_label(
        run.executable_sha256,
        run.executable_integrity_verified,
        run.executable_unchanged,
    )
    if run.auxiliary_executable_sha256 is None:
        return primary
    auxiliary = _integrity_label(
        run.auxiliary_executable_sha256,
        run.auxiliary_executable_integrity_verified,
        run.auxiliary_executable_unchanged,
    )
    return f"{primary}; helper: {auxiliary}"


def _integrity_label(
    digest: str | None,
    approved: bool | None,
    unchanged: bool | None,
) -> str:
    if digest is None:
        return "not checked"
    short_digest = digest[:12]
    if unchanged is False:
        return f"changed ({short_digest}...)"
    if approved and unchanged:
        return f"approved and unchanged ({short_digest}...)"
    if unchanged:
        return f"observed, not approved ({short_digest}...)"
    return f"observed, post-check unavailable ({short_digest}...)"


def _finding_sort_key(finding: Finding) -> tuple[int, str]:
    return (_SEVERITY_ORDER[finding.severity], finding.finding_id)


def _next_action(outcome: Outcome) -> str:
    return {
        Outcome.PASS: "No policy-blocking action is required.",
        Outcome.WARN: "Review the non-blocking findings and record disposition.",
        Outcome.FAIL: (
            "Remediate or govern blocking findings, then rerun before release or merge."
        ),
        Outcome.INCOMPLETE: (
            "Restore required scanner coverage or isolation evidence, then rerun; "
            "do not interpret this result as clean."
        ),
    }[outcome]


def _policy_disposition(outcome: Outcome) -> str:
    decision = _policy_decision_value(outcome)
    suffix = " (incomplete evidence)" if outcome is Outcome.INCOMPLETE else ""
    return f"`{decision}`{suffix}"


def _policy_decision_value(outcome: Outcome) -> str:
    return {
        Outcome.PASS: "ALLOW",
        Outcome.WARN: "REVIEW",
        Outcome.FAIL: "BLOCK",
        Outcome.INCOMPLETE: "BLOCK",
    }[outcome]


def _finding_priority(finding: Finding) -> str:
    intelligence = finding.evidence.get("risk_intelligence", {})
    if isinstance(intelligence, dict) and intelligence.get("known_exploited"):
        return "P0"
    if "EPSS-HIGH" in finding.classifications and finding.severity in {
        Severity.CRITICAL,
        Severity.HIGH,
        Severity.MEDIUM,
    }:
        return "P1"
    return {
        Severity.CRITICAL: "P0",
        Severity.HIGH: "P1",
        Severity.MEDIUM: "P2",
        Severity.LOW: "P3",
        Severity.INFORMATIONAL: "P4",
        Severity.UNKNOWN: "P4",
    }[finding.severity]


def _owner_values(finding: Finding) -> list[str]:
    owners = finding.evidence.get("owners", [])
    return [str(value) for value in owners[:20]] if isinstance(owners, list) else []


def _finding_owners(finding: Finding) -> str:
    owners = _owner_values(finding)
    return ", ".join(f"`{_markdown_code(value)}`" for value in owners) or "Unassigned"


def _threat_intelligence_summary(finding: Finding) -> str:
    intelligence = finding.evidence.get("risk_intelligence", {})
    if not isinstance(intelligence, dict):
        return "No matched offline intelligence"
    values: list[str] = []
    known = intelligence.get("known_exploited", [])
    if isinstance(known, list) and known:
        values.append("CISA KEV: known exploitation")
    epss = intelligence.get("epss", [])
    if isinstance(epss, list) and epss:
        highest = max(
            (value for value in epss if isinstance(value, dict)),
            key=lambda value: float(value.get("probability", 0.0)),
            default=None,
        )
        if highest is not None:
            values.append(
                f"EPSS {float(highest.get('probability', 0.0)):.1%} "
                f"(percentile {float(highest.get('percentile', 0.0)):.1%})"
            )
    vex = intelligence.get("vex", [])
    if isinstance(vex, list) and vex:
        states = sorted(
            {
                str(value.get("state") or "unknown")
                for value in vex
                if isinstance(value, dict)
            }
        )
        values.append("VEX: " + ", ".join(states))
    return "; ".join(values) or "No matched offline intelligence"


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
    evidence = (
        ", ".join(
            f"{run.tool}: {'not applicable' if not run.applicable else run.status.value}"
            for run in selected
        )
        or "No relevant scanner was selected."
    )
    return control, status, evidence, action, reference


def _sarif_name(rule_id: str) -> str:
    return "".join(character if character.isalnum() else "_" for character in rule_id)[
        :120
    ]


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
