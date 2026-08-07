from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any

from .adapters import ADAPTER_TYPES
from .config import SuiteConfig
from .finding_delta import apply_finding_delta
from .orchestrator import resolve_asset_paths
from .path_safety import resolve_regular_directory
from .risk_acceptance import validate_risk_acceptances
from .risk_intelligence import enrich_findings
from .trust_catalog import apply_trust_catalog


def assess_readiness(*, target: Path, config: SuiteConfig) -> dict[str, Any]:
    """Assess a configured scan without executing target code or scanners."""
    target = resolve_regular_directory(target, "scan target")
    resolve_asset_paths(config, target)
    trust = apply_trust_catalog(config)
    tools = _assess_tools(target, config)
    context_errors = _assess_context(target, config)
    context_errors.extend(trust.errors)
    document = _readiness_document(target, config, tools, context_errors)
    document["scanner_trust"] = trust.artifact
    return document


def _assess_tools(target: Path, config: SuiteConfig) -> list[dict[str, Any]]:
    required = set(config.required_tools)
    return [
        _assess_tool(name, target, config, name in required)
        for name in config.selected_tools
    ]


def _assess_tool(
    name: str, target: Path, config: SuiteConfig, required: bool
) -> dict[str, Any]:
    tool_config = config.tools[name]
    adapter_type = ADAPTER_TYPES.get(name)
    if adapter_type is None:
        return _tool_result(name, "unavailable", "adapter is not implemented", required)
    # The concrete-only registry is inferred at its ScannerAdapter base type.
    adapter = adapter_type(  # type: ignore[abstract]
        tool_config, config.execution.max_output_bytes
    )
    if not tool_config.enabled:
        reason = adapter.not_applicable_reason(target)
        return _tool_result(
            name,
            "not_applicable" if reason else "disabled",
            reason or "scanner disabled by configuration",
            required,
        )
    readiness = adapter.preflight(target)
    return {
        **_tool_result(name, readiness.status, readiness.reason, required),
        "executable": readiness.executable,
        "executable_sha256": readiness.executable_sha256,
        "executable_integrity_verified": readiness.executable_integrity_verified,
    }


def _assess_context(target: Path, config: SuiteConfig) -> list[str]:
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
    return context_errors


def _readiness_document(
    target: Path,
    config: SuiteConfig,
    tools: list[dict[str, Any]],
    context_errors: list[str],
) -> dict[str, Any]:
    summary = _summarize_tools(tools)
    blocking_tools, optional_attention_tools = _attention_tool_names(tools)
    ready = not blocking_tools and not context_errors
    blocking_reasons = _blocking_reasons(tools, blocking_tools, context_errors)
    conditional_actions = [
        {
            "tool": item["tool"],
            "category": item["category"],
            "reason": item["reason"],
            "required_action": item["required_action"],
        }
        for item in tools
        if item["category"]
        in {"missing_configuration", "missing_evidence", "platform_constraint"}
    ]
    return {
        "schema_version": "1.0",
        "target": target.name,
        "profile": config.profile,
        "ready": ready,
        "decision": {
            "disposition": "proceed" if ready else "block",
            "stage": "preflight",
            "release_approval": False,
            "blocking_reasons": blocking_reasons,
        },
        "scope": (
            "non-executing prerequisite assessment; a ready result does not "
            "replace a scan, its external network-isolation attestation, or "
            "release approval"
        ),
        "summary": summary,
        "blocking_tools": blocking_tools,
        "optional_attention_tools": optional_attention_tools,
        "conditional_actions": conditional_actions,
        "context_errors": context_errors,
        "tools": tools,
    }


def _attention_tool_names(
    tools: list[dict[str, Any]],
) -> tuple[list[str], list[str]]:
    attention = [
        item for item in tools if item["status"] in {"disabled", "unavailable"}
    ]
    blocking = [item["tool"] for item in attention if item["required"]]
    optional = [item["tool"] for item in attention if not item["required"]]
    return blocking, optional


def _blocking_reasons(
    tools: list[dict[str, Any]],
    blocking_tools: list[str],
    context_errors: list[str],
) -> list[dict[str, Any]]:
    reasons = [
        {
            "kind": "required_tool",
            "subject": item["tool"],
            "reason": item["reason"],
        }
        for item in tools
        if item["tool"] in blocking_tools
    ]
    reasons.extend(
        {"kind": "governed_context", "subject": "context", "reason": error}
        for error in context_errors
    )
    return reasons


def render_readiness(document: dict[str, Any]) -> str:
    """Render a concise operator-facing readiness summary."""
    summary = document["summary"]
    state = "READY" if document["ready"] else "NOT READY"
    decision = "PROCEED TO ISOLATED SCAN" if document["ready"] else "BLOCK PRE-FLIGHT"
    lines = [
        f"{state}: profile {document['profile']} for {document['target']}",
        f"Decision: {decision} (preflight only)",
        (
            f"Required: {summary['required_ready']}/"
            f"{summary['required_applicable']} applicable ready"
        ),
        (
            f"Tools: {summary['ready']}/{summary['applicable']} applicable ready; "
            f"{summary['not_applicable']} not applicable; "
            f"{summary['attention']} need attention"
        ),
    ]
    lines.extend(_render_attention(document))
    conditional = document.get("conditional_actions", [])
    if conditional:
        counts = Counter(item["category"] for item in conditional)
        lines.append(
            "Conditional evidence: "
            + ", ".join(
                f"{count} {category.replace('_', ' ')}"
                for category, count in sorted(counts.items())
            )
        )
    lines.append(f"Scope: {document['scope']}")
    return "\n".join(lines)


def _render_attention(document: dict[str, Any]) -> list[str]:
    attention = [
        item
        for item in document["tools"]
        if item["status"] in {"disabled", "unavailable"}
    ]
    if not attention and not document["context_errors"]:
        return []
    lines = ["Attention:"]
    lines.extend(
        f"- [{'required' if item['required'] else 'optional'}] "
        f"{item['tool']}: {item['status']} - {item['reason']}"
        for item in attention
    )
    lines.extend(
        f"- [required context] {error}" for error in document["context_errors"]
    )
    return lines


def _summarize_tools(tools: list[dict[str, Any]]) -> dict[str, int]:
    counts = Counter(item["status"] for item in tools)
    applicable = [item for item in tools if item["status"] != "not_applicable"]
    required_applicable = [item for item in applicable if item["required"]]
    categories = Counter(str(item["category"]) for item in tools)
    return {
        "selected": len(tools),
        "applicable": len(applicable),
        "ready": counts["ready"],
        "not_applicable": counts["not_applicable"],
        "disabled": counts["disabled"],
        "unavailable": counts["unavailable"],
        "attention": counts["disabled"] + counts["unavailable"],
        "required_applicable": len(required_applicable),
        "required_ready": sum(
            item["status"] == "ready" for item in required_applicable
        ),
        "content_absent": categories["content_absent"],
        "missing_evidence": categories["missing_evidence"],
        "missing_configuration": categories["missing_configuration"],
        "platform_constraints": categories["platform_constraint"],
    }


def _tool_result(
    tool: str, status: str, reason: str | None, required: bool
) -> dict[str, Any]:
    category, action = _readiness_guidance(status, reason)
    return {
        "tool": tool,
        "status": status,
        "required": required,
        "reason": reason,
        "category": category,
        "required_action": action,
    }


def _readiness_guidance(status: str, reason: str | None) -> tuple[str, str]:
    message = (reason or "").casefold()
    if status == "ready":
        return "ready", "No action; execute in the approved isolated scan lane."
    if status == "disabled":
        return (
            "disabled",
            "Enable the scanner or document an organization-approved exception.",
        )
    if status == "unavailable":
        return (
            "unavailable",
            "Install or restore the approved executable and required offline assets.",
        )
    if status != "not_applicable":
        return "attention", "Review the scanner prerequisite state."
    if any(
        value in message for value in ("pre-generated", "target python environment")
    ):
        return (
            "missing_evidence",
            "Generate the named evidence in its trusted companion lane, bind its digest, and rerun.",
        )
    if any(
        value in message
        for value in ("no approved local", "not configured", "no repository pysa")
    ):
        return (
            "missing_configuration",
            "Configure an approved local policy, environment, or evidence path and rerun preflight.",
        )
    if any(value in message for value in ("does not support", "run this profile on")):
        return (
            "platform_constraint",
            "Run this control on a supported companion platform and import its digest-bound evidence.",
        )
    return (
        "content_absent",
        "No current action; the control becomes applicable when supported repository content appears.",
    )
