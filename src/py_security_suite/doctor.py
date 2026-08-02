from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any

from .adapters import ADAPTER_TYPES
from .config import SuiteConfig
from .finding_delta import apply_finding_delta
from .orchestrator import resolve_asset_paths
from .risk_acceptance import validate_risk_acceptances
from .risk_intelligence import enrich_findings


def assess_readiness(*, target: Path, config: SuiteConfig) -> dict[str, Any]:
    """Assess a configured scan without executing target code or scanners."""
    target = target.expanduser().resolve()
    if not target.is_dir():
        raise ValueError(f"scan target is not a directory: {target}")
    resolve_asset_paths(config, target)

    tools: list[dict[str, Any]] = []
    required = set(config.required_tools)
    for name in config.selected_tools:
        tool_config = config.tools[name]
        adapter_type = ADAPTER_TYPES.get(name)
        if adapter_type is None:
            tools.append(
                _tool_result(
                    name,
                    "unavailable",
                    "adapter is not implemented",
                    name in required,
                )
            )
            continue
        # The concrete-only registry is inferred at its ScannerAdapter base type.
        adapter = adapter_type(  # type: ignore[abstract]
            tool_config, config.execution.max_output_bytes
        )
        if not tool_config.enabled:
            reason = adapter.not_applicable_reason(target)
            tools.append(
                _tool_result(
                    name,
                    "not_applicable" if reason else "disabled",
                    reason or "scanner disabled by configuration",
                    name in required,
                )
            )
            continue
        readiness = adapter.preflight(target)
        tools.append(
            {
                **_tool_result(
                    name,
                    readiness.status,
                    readiness.reason,
                    name in required,
                ),
                "executable": readiness.executable,
                "executable_sha256": readiness.executable_sha256,
                "executable_integrity_verified": (
                    readiness.executable_integrity_verified
                ),
            }
        )

    context_errors: list[str] = []
    context_errors.extend(enrich_findings([], config.intelligence).errors)
    context_errors.extend(
        apply_finding_delta(
            [],
            target=target,
            baseline_path=config.reports.baseline_path,
            baseline_sha256=config.reports.baseline_sha256,
        ).errors
    )
    context_errors.extend(
        validate_risk_acceptances(
            config.policy.risk_acceptance_path,
            config.policy.risk_acceptance_sha256,
        )
    )

    counts = Counter(item["status"] for item in tools)
    blocking_tools = [
        item["tool"]
        for item in tools
        if item["required"] and item["status"] in {"disabled", "unavailable"}
    ]
    ready = not blocking_tools and not context_errors
    return {
        "schema_version": "1.0",
        "target": target.name,
        "profile": config.profile,
        "ready": ready,
        "scope": (
            "non-executing prerequisite assessment; a ready result does not "
            "replace a scan or its external network-isolation attestation"
        ),
        "summary": {
            "selected": len(tools),
            "ready": counts["ready"],
            "not_applicable": counts["not_applicable"],
            "disabled": counts["disabled"],
            "unavailable": counts["unavailable"],
        },
        "blocking_tools": blocking_tools,
        "context_errors": context_errors,
        "tools": tools,
    }


def render_readiness(document: dict[str, Any]) -> str:
    """Render a concise operator-facing readiness summary."""
    summary = document["summary"]
    state = "READY" if document["ready"] else "NOT READY"
    lines = [
        f"{state}: profile {document['profile']} for {document['target']}",
        (
            f"Tools: {summary['ready']} ready, "
            f"{summary['not_applicable']} not applicable, "
            f"{summary['disabled']} disabled, "
            f"{summary['unavailable']} unavailable"
        ),
    ]
    attention = [
        item
        for item in document["tools"]
        if item["status"] in {"disabled", "unavailable"}
    ]
    if attention or document["context_errors"]:
        lines.append("Attention:")
        lines.extend(
            f"- {item['tool']}: {item['status']} — {item['reason']}"
            for item in attention
        )
        lines.extend(f"- context: {error}" for error in document["context_errors"])
    lines.append(str(document["scope"]))
    return "\n".join(lines)


def _tool_result(
    tool: str, status: str, reason: str | None, required: bool
) -> dict[str, Any]:
    return {
        "tool": tool,
        "status": status,
        "required": required,
        "reason": reason,
    }
