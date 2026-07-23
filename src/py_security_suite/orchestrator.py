from __future__ import annotations

import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Mapping

from . import __version__
from .adapters import ADAPTER_TYPES
from .adapters.base import AdapterResult, ScannerAdapter
from .config import SuiteConfig
from .correlation import correlate_findings
from .inventory import inventory_target
from .models import (
    ScanManifest,
    ScanResult,
    ToolRun,
    ToolStatus,
    isoformat,
    utc_now,
)
from .policy import evaluate_policy
from .reports import write_reports


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
    _resolve_asset_paths(config, target)

    started_at = utc_now()
    started_clock = time.monotonic()
    inventory = inventory_target(target)
    selected = list(config.selected_tools)
    diagnostics: dict[str, dict[str, Any]] = {}
    derived_artifacts: dict[str, Any] = {}

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
        findings = []
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

    decision = evaluate_policy(
        config=config,
        findings=findings,
        tool_runs=tool_runs,
        network_isolation_attested=network_isolation_attested,
        inventory=inventory,
    )
    finished_at = utc_now()
    duration = round(time.monotonic() - started_clock, 3)
    counts = {severity: 0 for severity in (
        "critical",
        "high",
        "medium",
        "low",
        "informational",
        "unknown",
    )}
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


def _resolve_asset_paths(config: SuiteConfig, target: Path) -> None:
    """Resolve repository-relative offline assets against the scan target."""
    for tool in config.tools.values():
        if tool.rules_path is not None and not tool.rules_path.is_absolute():
            tool.rules_path = (target / tool.rules_path).resolve()
        if tool.database_path is not None and not tool.database_path.is_absolute():
            tool.database_path = (target / tool.database_path).resolve()


def _run_adapters(
    *,
    target: Path,
    config: SuiteConfig,
    selected: list[str],
    adapter_types: Mapping[str, type[ScannerAdapter]],
) -> tuple[
    list,
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
        runnable[name] = adapter_type(
            tool_config, config.execution.max_output_bytes
        )

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
            except Exception as exc:  # Defensive adapter boundary.
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
    findings = [
        finding for result in ordered for finding in result.findings
    ]
    tool_runs = [result.tool_run for result in ordered]
    diagnostics = {
        result.tool_run.tool: result.diagnostic for result in ordered
    }
    artifacts = {
        name: value
        for result in ordered
        for name, value in result.artifacts.items()
    }
    return findings, tool_runs, diagnostics, artifacts
