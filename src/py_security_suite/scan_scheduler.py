"""Scanner scheduling with deterministic output and explicit artifact ownership."""

from __future__ import annotations

from collections.abc import Mapping
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextvars import copy_context
from pathlib import Path
import time
from typing import Any, NamedTuple

from .adapters.base import AdapterResult, ScannerAdapter
from .config import SuiteConfig
from .models import Finding, ToolRun, ToolStatus
from .scan_artifacts import ArtifactRegistry
from .scan_control import ScanInterrupted, emit_progress, stop_reason


class AdapterStageResult(NamedTuple):
    findings: list[Finding]
    tool_runs: list[ToolRun]
    diagnostics: dict[str, dict[str, Any]]
    artifacts: dict[str, Any]


def _run_adapter(adapter: ScannerAdapter, target: Path) -> AdapterResult:
    reason = stop_reason()
    if reason:
        return AdapterResult(
            [],
            ToolRun(
                tool=adapter.name,
                status=ToolStatus.SKIPPED,
                command=[adapter.config.executable],
                duration_seconds=0.0,
                error=reason,
            ),
            {"tool": adapter.name, "status": "skipped", "error": reason},
        )
    emit_progress("scanners", "started", adapter.name)
    started = time.monotonic()
    try:
        return adapter.run(target)
    except Exception as exc:  # noqa: BLE001 - adapter failure becomes retained evidence
        error = (
            str(exc)
            if isinstance(exc, ScanInterrupted)
            else f"unhandled adapter failure: {type(exc).__name__}"
        )
        return AdapterResult(
            [],
            ToolRun(
                adapter.name,
                ToolStatus.FAILED,
                [adapter.config.executable],
                time.monotonic() - started,
                error=error,
            ),
            {"tool": adapter.name, "status": "failed", "error": error},
        )


def run_adapters(
    *,
    target: Path,
    config: SuiteConfig,
    selected: list[str],
    adapter_types: Mapping[str, type[ScannerAdapter]],
) -> AdapterStageResult:
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
            executor.submit(copy_context().run, _run_adapter, adapter, target): name
            for name, adapter in runnable.items()
        }
        for future in as_completed(futures):
            name = futures[future]
            try:
                results[name] = future.result()
                if results[name].tool_run.tool != name:
                    raise ValueError("adapter returned a different producer identity")
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
            result = results[name]
            emit_progress("scanners", result.tool_run.status.value, name)

    results.update(skipped)
    for name, result in skipped.items():
        emit_progress("scanners", result.tool_run.status.value, name)
    ordered = [results[name] for name in selected]
    findings = [finding for result in ordered for finding in result.findings]
    tool_runs = [result.tool_run for result in ordered]
    diagnostics = {result.tool_run.tool: result.diagnostic for result in ordered}
    registry = ArtifactRegistry()
    for result in ordered:
        registry.add(result.tool_run.tool, result.artifacts)
    artifacts = registry.values
    return AdapterStageResult(findings, tool_runs, diagnostics, artifacts)
