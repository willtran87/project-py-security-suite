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
from .correlation import correlate_findings
from .finding_delta import apply_finding_delta
from .governance import (
    validate_intelligence_approval,
    validate_isolation_evidence,
)
from .effectiveness import assurance_claims_artifact, effectiveness_artifact
from .inventory import inventory_target, source_snapshot
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
from .portfolio_health import portfolio_health_artifact
from .path_safety import resolve_regular_directory, resolve_unlinked_path
from .reports import write_reports
from .risk_intelligence import enrich_findings
from .source_context import attach_source_context
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
    inventory = inventory_target(target, excluded_paths=(output,))
    selected = list(config.selected_tools)
    diagnostics: dict[str, dict[str, Any]] = {}
    derived_artifacts: dict[str, Any] = {}
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
        )
        context_errors.extend(delta.errors)
        baseline_artifact = delta.artifact
        derived_artifacts["finding-delta.json"] = delta.artifact
        attach_source_context(target, findings)

    (
        inventory.source_sha256_after,
        inventory.hashed_files_after,
        inventory.hashed_bytes_after,
    ) = source_snapshot(target, excluded_paths=(output,))
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
    derived_artifacts["effectiveness.json"] = effectiveness_artifact(
        findings, tool_runs
    )
    derived_artifacts["assurance-claims.json"] = assurance_claims_artifact(
        findings,
        tool_runs,
        source_integrity=inventory.source_integrity_verified,
        context_errors=context_errors,
        network_isolation_attested=network_isolation_attested,
    )
    derived_artifacts["portfolio-health.json"] = portfolio_health_artifact(
        findings, tool_runs
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


def resolve_asset_paths(config: SuiteConfig, target: Path) -> None:
    """Resolve repository-relative offline assets against the scan target."""
    for tool_name, tool in config.tools.items():
        for setting in (
            "rules_path",
            "database_path",
            "public_key_path",
            "artifacts_path",
            "provenance_path",
        ):
            value = getattr(tool, setting)
            if value is not None:
                candidate = value if value.is_absolute() else target / value
                setattr(
                    tool,
                    setting,
                    resolve_unlinked_path(
                        candidate,
                        f"{tool_name} {setting}",
                        boundary=target,
                    ),
                )
    acceptance = config.policy.risk_acceptance_path
    if acceptance is not None:
        candidate = acceptance if acceptance.is_absolute() else target / acceptance
        config.policy.risk_acceptance_path = resolve_unlinked_path(
            candidate,
            "risk-acceptance file",
            boundary=target,
        )
    baseline = config.reports.baseline_path
    if baseline is not None:
        candidate = baseline if baseline.is_absolute() else target / baseline
        config.reports.baseline_path = resolve_unlinked_path(
            candidate,
            "baseline",
            boundary=target,
        )
    for setting in ("kev_path", "epss_path", "vex_path"):
        value = getattr(config.intelligence, setting)
        if value is not None:
            candidate = value if value.is_absolute() else target / value
            setattr(
                config.intelligence,
                setting,
                resolve_unlinked_path(
                    candidate,
                    f"{setting} snapshot",
                    boundary=target,
                ),
            )
    approval = config.intelligence.approval_path
    if approval is not None:
        candidate = approval if approval.is_absolute() else target / approval
        config.intelligence.approval_path = resolve_unlinked_path(
            candidate,
            "intelligence approval",
            boundary=target,
        )
    isolation = config.isolation.evidence_path
    if isolation is not None:
        candidate = isolation if isolation.is_absolute() else target / isolation
        config.isolation.evidence_path = resolve_unlinked_path(
            candidate,
            "isolation evidence",
            boundary=target,
        )
    trust_catalog = config.trust.catalog_path
    if trust_catalog is not None:
        candidate = (
            trust_catalog if trust_catalog.is_absolute() else target / trust_catalog
        )
        config.trust.catalog_path = resolve_unlinked_path(
            candidate,
            "scanner trust catalog",
            boundary=target,
        )


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
            except Exception as exc:  # pylint: disable=broad-exception-caught
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
