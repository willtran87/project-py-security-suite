"""Markdown assurance case (assurance-case.md) rendering."""

from __future__ import annotations

from .report_markdown import _markdown_code
from .models import Finding, FindingStatus, ScanManifest
from .report_common import _entrypoint_integrity_counts, _markdown_table


__all__ = [
    "render_assurance_case",
]


def render_assurance_case(
    manifest: ScanManifest, findings: list[Finding] | None = None
) -> str:
    active_findings = [
        finding
        for finding in findings or []
        if finding.status is not FindingStatus.SUPPRESSED
    ]
    entrypoint_count, verified_entrypoint_count, _ = _entrypoint_integrity_counts(
        manifest.tools
    )
    rows = [
        _assurance_row(
            manifest,
            "Python source security",
            ("bandit", "semgrep", "ruff", "devskim", "flawfinder"),
            "Restore every incomplete source-security scanner and rerun before "
            "reviewing the result.",
            "No active source-security findings; retain this evidence and rerun "
            "for material source changes.",
            "https://csrc.nist.gov/pubs/sp/800/218/final",
            active_findings,
        ),
        _assurance_row(
            manifest,
            "Code quality and architecture",
            (
                "ruff-quality",
                "ruff-format",
                "pylint",
                "mypy",
                "pyright",
                "vulture",
                "radon",
                "tach",
                "reachability",
            ),
            "Restore incomplete correctness, formatting, typing, dead-code, "
            "complexity, architecture, and reachability controls, then rerun.",
            "Applicable quality and architecture controls completed without "
            "active findings; retain their evidence with the review.",
            "https://docs.gauge.sh/",
            active_findings,
        ),
        _assurance_row(
            manifest,
            "Automated test evidence",
            ("coverage", "junit", "diff-cover"),
            "Generate branch-enabled coverage JSON and passing JUnit XML in a "
            "disposable test lane, then attach both reports to the scan.",
            "Coverage, changed-line coverage, and JUnit evidence passed; retain "
            "all three reports with the same immutable source revision.",
            "https://coverage.readthedocs.io/en/latest/commands/cmd_reporting.html",
            active_findings,
        ),
        _assurance_row(
            manifest,
            "Deep data-flow analysis",
            ("pysa", "codeql"),
            "Configure and run at least one approved deep data-flow engine; "
            "production policy expects Pysa and the full profile requires CodeQL.",
            "At least one applicable deep data-flow engine completed without an "
            "active finding; retain its normalized result and tool-provenance "
            "evidence.",
            "https://owasp.org/www-project-application-security-verification-standard/",
            active_findings,
        ),
        _assurance_row(
            manifest,
            "Secret exposure",
            ("detect-secrets", "gitleaks", "trufflehog"),
            "Restore incomplete secret scanners, scan the full VCS checkout, and "
            "rerun before evaluating credential exposure.",
            "No active secret findings were reported; retain full-history scan "
            "evidence and rerun after credential-sensitive changes.",
            "https://csrc.nist.gov/pubs/sp/800/218/final",
            active_findings,
        ),
        _assurance_row(
            manifest,
            "Dependency vulnerabilities and SBOM",
            (
                "osv-scanner",
                "cyclonedx-py",
                "guarddog",
                "syft",
                "grype",
                "deptry",
                "pipdeptree",
            ),
            "Restore missing dependency scanners, a reproducible lock, and current "
            "approved offline advisory data, then regenerate the SBOM.",
            "Dependency and SBOM controls completed without active findings; "
            "retain the lock, SBOM, and advisory-snapshot digests.",
            "https://cyclonedx.org/capabilities/sbom/",
            active_findings,
            finding_areas=frozenset(
                {
                    "dependencies",
                    "package-integrity",
                    "artifact-vulnerability",
                    "dependency-health",
                    "dependency-hygiene",
                }
            ),
        ),
        _assurance_row(
            manifest,
            "Deployment, IaC, and CI configuration",
            (
                "trivy",
                "zizmor",
                "actionlint",
                "hadolint",
                "checkov",
                "conftest",
                "kics",
                "kube-linter",
                "kubescape",
                "psscriptanalyzer",
                "shellcheck",
            ),
            "Stage the final deployment and CI inputs, restore incomplete applicable "
            "controls, and rerun.",
            "Applicable deployment and CI controls completed without active "
            "findings; rerun when final deployment inputs change.",
            "https://csrc.nist.gov/pubs/sp/800/218/final",
            active_findings,
            finding_areas=frozenset(
                {
                    "deployment-configuration",
                    "ci-cd",
                    "ci-cd-correctness",
                    "container-hardening",
                    "infrastructure-as-code",
                    "kubernetes-security",
                    "powershell-safety",
                    "shell-safety",
                }
            ),
        ),
        _assurance_row(
            manifest,
            "License and source inventory",
            ("scancode", "trivy", "reuse"),
            "Restore incomplete license and origin controls, regenerate the component "
            "inventory, and rerun.",
            "No active license or inventory findings were reported; preserve the "
            "component inventory with the release.",
            "https://spdx.dev/use/specifications/",
            active_findings,
            finding_areas=frozenset({"license-governance", "license-compliance"}),
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
                "cosign",
            ),
            "Stage immutable artifacts and approved provenance inputs, restore every "
            "incomplete artifact control, and rerun.",
            "Artifact checks completed without active findings; retain digests, "
            "SBOMs, metadata checks, and provenance with the release.",
            "https://slsa.dev/spec/v1.0/levels",
            active_findings,
            finding_areas=frozenset(
                {
                    "artifact-provenance",
                    "artifact-vulnerability",
                    "artifact-integrity",
                    "artifact-source-parity",
                    "artifact-metadata",
                }
            ),
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
                (
                    "Preserve the immutable commit identity and VCS-aware evidence "
                    "with the release."
                    if manifest.inventory.vcs_history_available
                    else "Run the production gate against a full, immutable VCS "
                    "checkout."
                ),
                "https://slsa.dev/spec/v1.0/levels",
            ),
            _external_assurance_row(
                manifest,
                "Dynamic, API, and runtime behavior",
                (
                    "hypothesis",
                    "schemathesis",
                    "crosshair",
                    "atheris",
                    "clusterfuzzlite",
                    "mutmut",
                    "zap",
                    "browser-security",
                    "iast",
                    "falco",
                    "kubescape",
                ),
                "Run property, fuzz, mutation, applicable DAST/API/IAST checks, and "
                "runtime workload detection in separate disposable or deployed "
                "lanes, then attach source-bound evidence.",
                "Retain the attached companion evidence and rerun every applicable "
                "dynamic lane for material behavior or API changes.",
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


def _assurance_row(
    manifest: ScanManifest,
    control: str,
    tools: tuple[str, ...],
    gap_action: str,
    clean_action: str,
    reference: str,
    findings: list[Finding],
    *,
    finding_areas: frozenset[str] | None = None,
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
    coverage_status = status
    relevant_findings = [
        finding
        for finding in findings
        if any(source.tool in tools for source in finding.sources)
        and (finding_areas is None or finding.area in finding_areas)
    ]
    if relevant_findings:
        status = (
            "findings require action"
            if status == "verified for scan scope"
            else f"{status}; findings require action"
        )
        finding_tools = sorted(
            {
                source.tool
                for finding in relevant_findings
                for source in finding.sources
                if source.tool in tools
            }
        )
        count = len(relevant_findings)
        noun = "finding" if count == 1 else "findings"
        finding_action = (
            f"Open action-plan.md and resolve {count} active {noun} attributed to "
            f"{', '.join(finding_tools)} before promotion."
        )
        action = (
            finding_action
            if coverage_status == "verified for scan scope"
            else f"{gap_action} Also, {finding_action}"
        )
    elif status == "verified for scan scope":
        action = clean_action
    elif status == "not applicable to detected content":
        action = (
            "No current action; reevaluate this control when relevant repository "
            "content or release inputs are added."
        )
    else:
        action = gap_action
    evidence = (
        ", ".join(
            f"{run.tool}: {'not applicable' if not run.applicable else run.status.value}"
            for run in selected
        )
        or "No relevant scanner was selected."
    )
    return control, status, evidence, action, reference


def _external_assurance_row(
    manifest: ScanManifest,
    control: str,
    tools: tuple[str, ...],
    required_action: str,
    attached_action: str,
    reference: str,
) -> tuple[str, str, str, str, str]:
    selected = [run for run in manifest.tools if run.tool in tools]
    completed = [
        run for run in selected if run.applicable and run.status.value == "completed"
    ]
    evidence = (
        ", ".join(
            f"{run.tool}: {'not applicable' if not run.applicable else run.status.value}"
            for run in selected
        )
        or "No bounded companion evidence was attached."
    )
    if completed:
        status = "applicable external evidence attached"
        action = attached_action
        evidence += "; evidence was ingested, not executed in the scan boundary"
    else:
        status = "external evidence required"
        action = required_action
        evidence += "; target code execution is prohibited in the scan boundary"
    return control, status, evidence, action, reference
