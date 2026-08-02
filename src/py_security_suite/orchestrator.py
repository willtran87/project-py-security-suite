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
from .reports import write_reports
from .risk_intelligence import enrich_findings
from .source_context import attach_source_context


def scan_project(
    *,
    target: Path,
    output: Path,
    config: SuiteConfig,
    network_isolation_attested: bool,
    diagnostic_without_isolation: bool = False,
    adapter_types: Mapping[str, type[ScannerAdapter]] | None = None,
) -> ScanResult:
    target = target.expanduser().resolve()
    output = output.expanduser().resolve()
    if not target.is_dir():
        raise ValueError(f"scan target is not a directory: {target}")
    if output.exists():
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
        findings, tool_runs, diagnostics, derived_artifacts = _run_adapters(
            target=target,
            config=config,
            selected=selected,
            adapter_types=adapter_types or ADAPTER_TYPES,
        )
        findings = correlate_findings(findings)
        intelligence = enrich_findings(findings, config.intelligence)
        context_errors.extend(intelligence.errors)
        intelligence_artifact = intelligence.artifact
        derived_artifacts["risk-intelligence.json"] = intelligence.artifact
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
    )
    return ScanResult(
        outcome=decision.outcome,
        findings=findings,
        tool_runs=tool_runs,
        manifest=manifest,
    )


def resolve_asset_paths(config: SuiteConfig, target: Path) -> None:
    """Resolve repository-relative offline assets against the scan target."""
    for tool in config.tools.values():
        if tool.rules_path is not None and not tool.rules_path.is_absolute():
            tool.rules_path = (target / tool.rules_path).resolve()
        if tool.database_path is not None and not tool.database_path.is_absolute():
            tool.database_path = (target / tool.database_path).resolve()
        if tool.public_key_path is not None and not tool.public_key_path.is_absolute():
            tool.public_key_path = (target / tool.public_key_path).resolve()
    acceptance = config.policy.risk_acceptance_path
    if acceptance is not None and not acceptance.is_absolute():
        config.policy.risk_acceptance_path = (target / acceptance).resolve()
    baseline = config.reports.baseline_path
    if baseline is not None and not baseline.is_absolute():
        config.reports.baseline_path = (target / baseline).resolve()
    for setting in ("kev_path", "epss_path", "vex_path"):
        value = getattr(config.intelligence, setting)
        if value is not None and not value.is_absolute():
            setattr(config.intelligence, setting, (target / value).resolve())


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
