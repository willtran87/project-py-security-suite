from __future__ import annotations

import hashlib
import os
import tempfile
from pathlib import Path
from typing import Any

from .artifact_validation import validate_governed_artifacts
from .models import Finding, FindingStatus, ScanManifest
from .passport import (
    REQUIRED_REPORT_ARTIFACTS,
    build_security_passport_statement,
    verify_report,
)
from .path_safety import HeldParentDirectory, hold_parent_directory
from .source_context import redact_sensitive_snippets
from .report_checkpoint import ReportInputs, load_report_inputs, preserve_report_inputs
from .report_cleanup import cleanup_directory
from .report_acl import _harden_report_tree, _verify_report_permissions
from .report_io import write_json as _write_json, write_text as _write_text
from .report_action_plan import (
    _render_entrypoint_trust_actions as _render_entrypoint_trust_actions,
    render_action_plan,
)
from .report_assurance_case import render_assurance_case
from .report_common import (
    _finding_priority as _finding_priority,
    _finding_sort_key as _finding_sort_key,
    _markdown_table as _markdown_table,
    _risk_advisory_citations_text as _risk_advisory_citations_text,
    _safe_http_reference as _safe_http_reference,
)
from .report_html import (
    _html_risk_path_context as _html_risk_path_context,
    _html_secret_provenance_context as _html_secret_provenance_context,
    _html_unrouted_structural_summary as _html_unrouted_structural_summary,
    render_html,
)
from .report_interchange import render_sarif, render_sonarqube_external_issues
from .report_markdown_findings import (
    _markdown_data_exposure_context as _markdown_data_exposure_context,
    _markdown_fusion_context as _markdown_fusion_context,
    _markdown_risk_path_context as _markdown_risk_path_context,
    _markdown_secret_provenance_context as _markdown_secret_provenance_context,
    _markdown_structural_context as _markdown_structural_context,
)
from .report_risk_path_summary import (
    _render_risk_path_summary as _render_risk_path_summary,
)
from .report_summary import (
    _render_data_exposure_summary as _render_data_exposure_summary,
    _render_domain_assurance_summary as _render_domain_assurance_summary,
    _render_fusion_summary as _render_fusion_summary,
    _render_llm_adversarial_summary as _render_llm_adversarial_summary,
    _render_structural_summary as _render_structural_summary,
    render_summary,
)


REPORT_FILES = tuple(REQUIRED_REPORT_ARTIFACTS.values())


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
    validate_governed_artifacts(derived_artifacts)
    if (output.exists() or output.is_symlink()) and not replace_existing:
        raise FileExistsError(f"report output already exists: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(
        tempfile.mkdtemp(prefix=f".{output.name}.staging-", dir=output.parent)
    )
    os.chmod(staging, 0o700)  # noqa: S103 - security artifact directory
    try:
        with preserve_report_inputs(
            output,
            ReportInputs(
                findings, manifest, diagnostics, include_evidence, derived_artifacts
            ),
            _harden_report_tree,
        ):
            _render_and_publish(
                staging,
                output,
                findings,
                manifest,
                diagnostics,
                include_evidence,
                derived_artifacts,
                replace_existing,
            )
    finally:
        if staging.exists():
            cleanup_directory(staging)


def _render_and_publish(
    staging: Path,
    output: Path,
    findings: list[Finding],
    manifest: ScanManifest,
    diagnostics: dict[str, dict[str, Any]],
    include_evidence: bool,
    derived_artifacts: dict[str, Any] | None,
    replace_existing: bool,
) -> None:
    _write_report_contents(
        output=staging,
        findings=findings,
        manifest=manifest,
        diagnostics=diagnostics,
        include_evidence=include_evidence,
        derived_artifacts=derived_artifacts,
    )
    _harden_report_tree(staging)
    verify_report(staging)
    _publish_report(staging, output, replace_existing=replace_existing)


def recover_reports(recovery: Path, output: Path) -> None:
    inputs = load_report_inputs(recovery)
    write_reports(
        output=output,
        findings=inputs.findings,
        manifest=inputs.manifest,
        diagnostics=inputs.diagnostics,
        include_evidence=inputs.include_evidence,
        derived_artifacts=inputs.derived_artifacts,
    )


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
        with hold_parent_directory(output, "report publication") as parent:
            _publish_report_locked(
                staging,
                output,
                replace_existing=replace_existing,
                held_parent=parent,
            )
    finally:
        cleanup_directory(lock, recursive=False)


def _publish_report_locked(
    staging: Path,
    output: Path,
    *,
    replace_existing: bool,
    held_parent: HeldParentDirectory,
) -> None:
    if not output.exists() and not output.is_symlink():
        held_parent.rename(staging, output)
        try:
            _verify_report_permissions(output)
        except BaseException:
            held_parent.rename(output, staging)
            raise
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
    held_parent.rename(output, backup)
    try:
        held_parent.rename(staging, output)
        _verify_report_permissions(output)
        published = True
    except BaseException:
        if output.exists() and not staging.exists():
            held_parent.rename(output, staging)
        if not output.exists() and not output.is_symlink():
            held_parent.rename(backup, output)
        raise
    finally:
        if published and backup.exists():
            # Holds the previous report's evidence: a failure is logged as an
            # error naming the retained path rather than being dropped.
            cleanup_directory(backup, contents="previous report backup")


def _write_report_contents(
    *,
    output: Path,
    findings: list[Finding],
    manifest: ScanManifest,
    diagnostics: dict[str, dict[str, Any]],
    include_evidence: bool,
    derived_artifacts: dict[str, Any] | None,
) -> None:
    redact_sensitive_snippets(findings)
    _register_report_artifacts(manifest, derived_artifacts)
    active_findings = [
        finding
        for finding in findings
        if finding.status is not FindingStatus.SUPPRESSED
    ]
    _write_primary_report_files(
        output, manifest, findings, active_findings, derived_artifacts
    )
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
        if name == "source-inventory.json":
            continue
        if (
            "/" in name
            or "\\" in name
            or name in REPORT_FILES
            or name in REQUIRED_REPORT_ARTIFACTS
        ):
            raise ValueError(f"unsafe or reserved derived artifact name: {name}")
        manifest.artifacts[name] = name
    if "source-inventory.json" not in (derived_artifacts or {}):
        raise ValueError("required source-inventory.json derived artifact is missing")


def _write_primary_report_files(
    output: Path,
    manifest: ScanManifest,
    findings: list[Finding],
    active_findings: list[Finding],
    derived_artifacts: dict[str, Any] | None,
) -> None:
    fusion = (derived_artifacts or {}).get("evidence-fusion.json")
    structural = (derived_artifacts or {}).get("structural-synthesis.json")
    data_exposure = (derived_artifacts or {}).get("data-exposure.json")
    risk_paths = (derived_artifacts or {}).get("risk-paths.json")
    advanced = (derived_artifacts or {}).get("advanced-analysis.json")
    application_contracts = (derived_artifacts or {}).get(
        "application-contract-analysis.json"
    )
    code_health = (derived_artifacts or {}).get("code-health.json")
    static_architecture = (derived_artifacts or {}).get("static-architecture.json")
    domain_assurance = (derived_artifacts or {}).get("domain-assurance.json")
    llm_adversarial = (derived_artifacts or {}).get("llm-adversarial-plan.json")
    industry_assurance = (derived_artifacts or {}).get("industry-assurance.json")
    _write_text(
        output / "summary.md",
        render_summary(
            manifest,
            findings,
            evidence_fusion=fusion if isinstance(fusion, dict) else None,
            structural_synthesis=structural if isinstance(structural, dict) else None,
            data_exposure=data_exposure if isinstance(data_exposure, dict) else None,
            risk_paths=risk_paths if isinstance(risk_paths, dict) else None,
            advanced_analysis=advanced if isinstance(advanced, dict) else None,
            application_contracts=(
                application_contracts
                if isinstance(application_contracts, dict)
                else None
            ),
            code_health=code_health if isinstance(code_health, dict) else None,
            static_architecture=(
                static_architecture if isinstance(static_architecture, dict) else None
            ),
            domain_assurance=(
                domain_assurance if isinstance(domain_assurance, dict) else None
            ),
            llm_adversarial=(
                llm_adversarial if isinstance(llm_adversarial, dict) else None
            ),
            industry_assurance=(
                industry_assurance if isinstance(industry_assurance, dict) else None
            ),
        ),
    )
    _write_text(
        output / "action-plan.md", render_action_plan(manifest, active_findings)
    )
    _write_text(
        output / "assurance-case.md",
        render_assurance_case(manifest, active_findings),
    )
    _write_text(
        output / "index.html",
        render_html(
            manifest,
            findings,
            risk_paths=risk_paths if isinstance(risk_paths, dict) else None,
            advanced_analysis=advanced if isinstance(advanced, dict) else None,
        ),
    )
    # Accepted findings stay in SARIF with a suppression so platforms keep
    # them dismissed instead of auto-closing them as fixed.
    _write_json(output / "results.sarif", render_sarif(findings))
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
            "vcs_revision": manifest.inventory.vcs_revision,
            "vcs_revision_verified": manifest.inventory.vcs_revision_verified,
            "selected_tools": sorted(run.tool for run in manifest.tools),
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


def _write_checksums(output: Path) -> None:
    entries = []
    for path in sorted(output.rglob("*")):
        if not path.is_file() or path.name == "checksums.sha256":
            continue
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        entries.append(f"{digest}  {path.relative_to(output).as_posix()}")
    _write_text(output / "checksums.sha256", "\n".join(entries) + "\n")
