from __future__ import annotations

import hashlib
import json
import time
import uuid
from collections.abc import Mapping
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

from . import __version__
from .adapters import ADAPTER_TYPES
from .adapters.base import AdapterResult, ScannerAdapter
from .config import SuiteConfig
from .closure_plan import closure_plan_artifact
from .correlation import correlate_findings
from .data_exposure import apply_data_exposure_fusion, build_data_exposure_synthesis
from .finding_delta import apply_finding_delta
from .governance import (
    validate_intelligence_approval,
    validate_isolation_evidence,
)
from .graph_analysis import apply_graph_context
from .effectiveness import assurance_claims_artifact, effectiveness_artifact
from .evidence_fusion import build_evidence_fusion
from .inventory import inventory_target_with_evidence, source_snapshot
from .models import (
    Finding,
    ScanManifest,
    ScanResult,
    ToolRun,
    ToolStatus,
    isoformat,
    utc_now,
    json_ready,
)
from .policy import evaluate_policy
from .admission import admission_decisions
from .advanced_analysis import build_advanced_analysis
from .portfolio_health import portfolio_health_artifact
from .path_safety import resolve_regular_directory, resolve_unlinked_path
from .reports import write_reports
from .risk_intelligence import enrich_findings
from .risk_paths import build_risk_paths
from .source_context import attach_source_context
from .structural_synthesis import build_structural_synthesis
from .trust_catalog import apply_trust_catalog


def scan_project(
    *,
    target: Path,
    output: Path,
    config: SuiteConfig,
    network_isolation_attested: bool,
    diagnostic_without_isolation: bool = False,
    adapter_types: Mapping[str, type[ScannerAdapter]] | None = None,
    replace_existing: bool = False,
) -> ScanResult:
    target = resolve_regular_directory(target, "scan target")
    output = resolve_unlinked_path(output, "report output")
    if not target.is_dir():
        raise ValueError(f"scan target is not a directory: {target}")
    if output.exists() and not replace_existing:
        raise ValueError(f"report output already exists: {output}")
    resolve_asset_paths(config, target)

    started_at = utc_now()
    started_clock = time.monotonic()
    selected = list(config.selected_tools)
    source_exclusions = (output, *_runtime_evidence_paths(config, selected))
    inventory, source_inventory = inventory_target_with_evidence(
        target, excluded_paths=source_exclusions
    )
    diagnostics: dict[str, dict[str, Any]] = {}
    derived_artifacts: dict[str, Any] = {}
    derived_artifacts["source-inventory.json"] = source_inventory
    context_errors: list[str] = []
    intelligence_artifact: dict[str, Any] = {}
    baseline_artifact: dict[str, Any] = {}
    trust = apply_trust_catalog(config)
    context_errors.extend(trust.errors)
    derived_artifacts["scanner-trust.json"] = trust.artifact
    isolation = validate_isolation_evidence(
        config.isolation,
        target_name=target.name,
        source_sha256=inventory.source_sha256,
        observed_at=started_at,
    )
    if network_isolation_attested:
        context_errors.extend(isolation.errors)
    elif config.isolation.require_evidence and not diagnostic_without_isolation:
        context_errors.append("approved external isolation evidence was not applied")
    derived_artifacts["isolation-attestation.json"] = isolation.artifact

    if (
        config.isolation.require_attestation
        and not network_isolation_attested
        and not diagnostic_without_isolation
    ):
        tool_runs = [
            ToolRun(
                tool=name,
                status=ToolStatus.SKIPPED,
                command=[config.tools[name].executable],
                duration_seconds=0.0,
                error="scan not started because network isolation was not attested",
            )
            for name in selected
        ]
        findings: list[Finding] = []
        diagnostics = {
            run.tool: {
                "tool": run.tool,
                "status": run.status,
                "error": run.error,
                "raw_output_retained": False,
            }
            for run in tool_runs
        }
    else:
        findings, tool_runs, diagnostics, adapter_artifacts = _run_adapters(
            target=target,
            config=config,
            selected=selected,
            adapter_types=adapter_types or ADAPTER_TYPES,
        )
        _annotate_tool_authority(tool_runs, diagnostics, config)
        derived_artifacts.update(adapter_artifacts)
        findings = correlate_findings(findings)
        intelligence = enrich_findings(findings, config.intelligence)
        context_errors.extend(intelligence.errors)
        intelligence_artifact = intelligence.artifact
        derived_artifacts["risk-intelligence.json"] = intelligence.artifact
        intelligence_approval = validate_intelligence_approval(
            config.intelligence,
            intelligence.artifact,
            observed_at=started_at,
        )
        context_errors.extend(intelligence_approval.errors)
        derived_artifacts["intelligence-approval.json"] = intelligence_approval.artifact
        delta = apply_finding_delta(
            findings,
            target=target,
            baseline_path=config.reports.baseline_path,
            baseline_sha256=config.reports.baseline_sha256,
            current_profile=config.profile,
            current_tools=tuple(selected),
            current_source_sha256=inventory.source_sha256,
            current_vcs_revision=inventory.vcs_revision,
        )
        context_errors.extend(delta.errors)
        baseline_artifact = delta.artifact
        derived_artifacts["finding-delta.json"] = delta.artifact
        attach_source_context(target, findings)
        graph_analysis = apply_graph_context(findings, derived_artifacts)
        if graph_analysis is not None:
            derived_artifacts["graph-analysis.json"] = graph_analysis
        structural_synthesis = build_structural_synthesis(findings, derived_artifacts)
        if structural_synthesis is not None:
            derived_artifacts["structural-synthesis.json"] = structural_synthesis
        derived_artifacts["data-exposure.json"] = build_data_exposure_synthesis(
            target, findings, derived_artifacts
        )
        fusion = build_evidence_fusion(findings, derived_artifacts, tool_runs)
        derived_artifacts["evidence-fusion.json"] = fusion
        apply_data_exposure_fusion(
            derived_artifacts["data-exposure.json"], findings, fusion
        )
        derived_artifacts["effectiveness.json"] = effectiveness_artifact(
            findings, tool_runs
        )
        derived_artifacts["risk-paths.json"] = build_risk_paths(
            findings, derived_artifacts
        )
        derived_artifacts["advanced-analysis.json"] = build_advanced_analysis(
            target, findings, derived_artifacts
        )
        context_errors.extend(
            (
                "evidence fusion contradiction for "
                f"{contradiction['finding_id']}: {contradiction['message']}"
            )
            for contradiction in fusion["contradictions"]
        )

    if "effectiveness.json" not in derived_artifacts:
        _annotate_tool_authority(tool_runs, diagnostics, config)
        derived_artifacts["effectiveness.json"] = effectiveness_artifact(
            findings, tool_runs
        )

    (
        inventory.source_sha256_after,
        inventory.hashed_files_after,
        inventory.hashed_bytes_after,
    ) = source_snapshot(target, excluded_paths=source_exclusions)
    inventory.source_integrity_verified = (
        inventory.source_sha256 == inventory.source_sha256_after
        and inventory.hashed_files == inventory.hashed_files_after
        and inventory.hashed_bytes == inventory.hashed_bytes_after
    )

    decision = evaluate_policy(
        config=config,
        findings=findings,
        tool_runs=tool_runs,
        network_isolation_attested=network_isolation_attested,
        inventory=inventory,
        context_errors=context_errors,
    )
    derived_artifacts["assurance-claims.json"] = assurance_claims_artifact(
        findings,
        tool_runs,
        source_integrity=inventory.source_integrity_verified,
        context_errors=context_errors,
        network_isolation_attested=network_isolation_attested,
    )
    derived_artifacts["portfolio-health.json"] = portfolio_health_artifact(
        findings,
        tool_runs,
        outcome=decision.outcome,
        policy_reasons=decision.reasons,
    )
    derived_artifacts["admission-decisions.json"] = admission_decisions(
        findings,
        tool_runs,
        network_isolation_attested=network_isolation_attested,
        source_integrity_verified=inventory.source_integrity_verified,
    )
    finished_at = utc_now()
    duration = round(time.monotonic() - started_clock, 3)
    counts = {
        severity: 0
        for severity in (
            "critical",
            "high",
            "medium",
            "low",
            "informational",
            "unknown",
        )
    }
    for finding in findings:
        counts[finding.severity.value] += 1

    manifest = ScanManifest(
        schema_version="1.0",
        suite_version=__version__,
        scan_id=f"scan-{uuid.uuid4()}",
        target=target.name,
        profile=config.profile,
        outcome=decision.outcome,
        started_at=isoformat(started_at),
        finished_at=isoformat(finished_at),
        duration_seconds=duration,
        network_policy=config.isolation.network,
        network_isolation_attested=network_isolation_attested,
        execute_target_code=config.isolation.execute_target_code,
        inventory=inventory,
        tools=tool_runs,
        finding_counts=counts,
        policy_reasons=decision.reasons,
        diagnostic_without_isolation=diagnostic_without_isolation,
        configuration_sha256=_configuration_digest(config),
        risk_acceptance_sha256=config.policy.risk_acceptance_sha256,
        intelligence=intelligence_artifact,
        baseline=baseline_artifact,
    )
    derived_artifacts["closure-plan.json"] = closure_plan_artifact(
        manifest,
        findings,
        derived_artifacts,
    )
    write_reports(
        output=output,
        findings=findings,
        manifest=manifest,
        diagnostics=diagnostics,
        include_evidence=config.reports.include_sanitized_evidence,
        derived_artifacts=derived_artifacts,
        replace_existing=replace_existing,
    )
    return ScanResult(
        outcome=decision.outcome,
        findings=findings,
        tool_runs=tool_runs,
        manifest=manifest,
    )


def _annotate_tool_authority(
    tool_runs: list[ToolRun],
    diagnostics: dict[str, dict[str, Any]],
    config: SuiteConfig,
) -> None:
    """Keep digest matching distinct from organization authorization."""
    for run in tool_runs:
        tool = config.tools[run.tool]
        run.executable_organization_approved = tool.executable_organization_approved
        run.auxiliary_executable_organization_approved = (
            tool.auxiliary_executable_organization_approved
        )
        diagnostic = diagnostics.get(run.tool)
        if diagnostic is not None:
            diagnostic["executable_organization_approved"] = (
                run.executable_organization_approved
            )
            diagnostic["auxiliary_executable_organization_approved"] = (
                run.auxiliary_executable_organization_approved
            )


def resolve_asset_paths(config: SuiteConfig, target: Path) -> None:
    """Resolve repository-relative offline assets against the scan target."""
    configured_bundle = config.paths.bundle_root
    bundle_candidate = (
        configured_bundle
        if configured_bundle.is_absolute()
        else target / configured_bundle
    )
    bundle_root = resolve_unlinked_path(
        bundle_candidate,
        "offline scanner bundle root",
        boundary=target if not configured_bundle.is_absolute() else None,
    )
    config.paths.bundle_root = bundle_root
    for tool_name, tool in config.tools.items():
        for setting in ("executable", "auxiliary_executable"):
            value = getattr(tool, setting)
            if _is_bundle_reference(value):
                setattr(
                    tool,
                    setting,
                    str(
                        _resolve_bundle_reference(
                            value,
                            bundle_root=bundle_root,
                            label=f"{tool_name} {setting}",
                        )
                    ),
                )
        for setting in (
            "rules_path",
            "database_path",
            "public_key_path",
            "artifacts_path",
            "provenance_path",
        ):
            value = getattr(tool, setting)
            if value is not None:
                serialized = str(value)
                if _is_bundle_reference(serialized):
                    resolved = _resolve_bundle_reference(
                        serialized,
                        bundle_root=bundle_root,
                        label=f"{tool_name} {setting}",
                    )
                    setattr(tool, setting, resolved)
                    continue
                setattr(
                    tool,
                    setting,
                    _resolve_configured_path(
                        value,
                        target=target,
                        bundle_root=bundle_root,
                        label=f"{tool_name} {setting}",
                    ),
                )
    acceptance = config.policy.risk_acceptance_path
    if acceptance is not None:
        config.policy.risk_acceptance_path = _resolve_configured_path(
            acceptance,
            target=target,
            bundle_root=bundle_root,
            label="risk-acceptance file",
        )
    baseline = config.reports.baseline_path
    if baseline is not None:
        config.reports.baseline_path = _resolve_configured_path(
            baseline,
            target=target,
            bundle_root=bundle_root,
            label="baseline",
        )
    for setting in ("kev_path", "epss_path", "vex_path"):
        value = getattr(config.intelligence, setting)
        if value is not None:
            setattr(
                config.intelligence,
                setting,
                _resolve_configured_path(
                    value,
                    target=target,
                    bundle_root=bundle_root,
                    label=f"{setting} snapshot",
                ),
            )
    approval = config.intelligence.approval_path
    if approval is not None:
        config.intelligence.approval_path = _resolve_configured_path(
            approval,
            target=target,
            bundle_root=bundle_root,
            label="intelligence approval",
        )
    isolation = config.isolation.evidence_path
    if isolation is not None:
        config.isolation.evidence_path = _resolve_configured_path(
            isolation,
            target=target,
            bundle_root=bundle_root,
            label="isolation evidence",
        )
    trust_catalog = config.trust.catalog_path
    if trust_catalog is not None:
        config.trust.catalog_path = _resolve_configured_path(
            trust_catalog,
            target=target,
            bundle_root=bundle_root,
            label="scanner trust catalog",
        )


def _runtime_evidence_paths(
    config: SuiteConfig, selected: list[str]
) -> tuple[Path, ...]:
    paths: set[Path] = set()
    for name in ("coverage", "junit", "hypothesis", "schemathesis", "diff-cover"):
        if name not in selected or name not in config.tools:
            continue
        path = config.tools[name].artifacts_path
        if path is None:
            continue
        resolved = path.resolve()
        paths.add(resolved)
        paths.add(resolved.with_name(resolved.name + ".pysec-binding.json"))
    reachability = config.tools.get("reachability")
    if "reachability" in selected and reachability is not None:
        path = reachability.coverage_path
        if path is not None:
            paths.add(path.resolve())
    return tuple(sorted(paths, key=str))


def _is_bundle_reference(value: str) -> bool:
    normalized = value.replace("\\", "/")
    return normalized == "@bundle" or normalized.startswith("@bundle/")


def _resolve_bundle_reference(
    value: str,
    *,
    bundle_root: Path,
    label: str,
) -> Path:
    normalized = value.replace("\\", "/")
    relative_text = normalized.removeprefix("@bundle/")
    if normalized == "@bundle" or not relative_text:
        raise ValueError(f"{label} must name a path below @bundle/")
    relative = Path(relative_text)
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError(f"{label} cannot traverse outside @bundle/")
    return resolve_unlinked_path(
        bundle_root / relative,
        label,
        boundary=bundle_root,
    )


def _resolve_configured_path(
    value: Path,
    *,
    target: Path,
    bundle_root: Path,
    label: str,
) -> Path:
    serialized = str(value)
    if _is_bundle_reference(serialized):
        return _resolve_bundle_reference(
            serialized,
            bundle_root=bundle_root,
            label=label,
        )
    candidate = value if value.is_absolute() else target / value
    return resolve_unlinked_path(candidate, label, boundary=target)


def _configuration_digest(config: SuiteConfig) -> str:
    payload = json.dumps(
        json_ready(config), sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _run_adapters(
    *,
    target: Path,
    config: SuiteConfig,
    selected: list[str],
    adapter_types: Mapping[str, type[ScannerAdapter]],
) -> tuple[
    list[Finding],
    list[ToolRun],
    dict[str, dict[str, Any]],
    dict[str, Any],
]:
    results: dict[str, AdapterResult] = {}
    skipped: dict[str, AdapterResult] = {}
    runnable: dict[str, ScannerAdapter] = {}
    for name in selected:
        tool_config = config.tools[name]
        if not tool_config.enabled:
            run = ToolRun(
                tool=name,
                status=ToolStatus.SKIPPED,
                command=[tool_config.executable],
                duration_seconds=0.0,
                error="scanner disabled by configuration",
            )
            skipped[name] = AdapterResult(
                findings=[],
                tool_run=run,
                diagnostic={
                    "tool": name,
                    "status": run.status,
                    "error": run.error,
                    "raw_output_retained": False,
                },
            )
            continue
        adapter_type = adapter_types.get(name)
        if adapter_type is None:
            run = ToolRun(
                tool=name,
                status=ToolStatus.UNAVAILABLE,
                command=[tool_config.executable],
                duration_seconds=0.0,
                error="adapter is not implemented",
            )
            skipped[name] = AdapterResult(
                findings=[],
                tool_run=run,
                diagnostic={
                    "tool": name,
                    "status": run.status,
                    "error": run.error,
                    "raw_output_retained": False,
                },
            )
            continue
        runnable[name] = adapter_type(tool_config, config.execution.max_output_bytes)

    with ThreadPoolExecutor(
        max_workers=min(config.execution.max_workers, max(len(runnable), 1)),
        thread_name_prefix="pysec",
    ) as executor:
        futures = {
            executor.submit(adapter.run, target): name
            for name, adapter in runnable.items()
        }
        for future in as_completed(futures):
            name = futures[future]
            try:
                results[name] = future.result()
            # Scanner adapters are an isolation boundary: convert every failure into
            # an explicit tool result so one adapter cannot abort the whole scan.
            except Exception as exc:  # noqa: BLE001  # pylint: disable=broad-exception-caught
                run = ToolRun(
                    tool=name,
                    status=ToolStatus.FAILED,
                    command=[config.tools[name].executable],
                    duration_seconds=0.0,
                    error=f"unhandled adapter failure: {type(exc).__name__}",
                )
                results[name] = AdapterResult(
                    findings=[],
                    tool_run=run,
                    diagnostic={
                        "tool": name,
                        "status": run.status,
                        "error": run.error,
                        "raw_output_retained": False,
                    },
                )

    results.update(skipped)
    ordered = [results[name] for name in selected]
    findings = [finding for result in ordered for finding in result.findings]
    tool_runs = [result.tool_run for result in ordered]
    diagnostics = {result.tool_run.tool: result.diagnostic for result in ordered}
    artifacts = {
        name: value for result in ordered for name, value in result.artifacts.items()
    }
    return findings, tool_runs, diagnostics, artifacts
