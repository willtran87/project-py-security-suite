from __future__ import annotations

from collections import Counter
from html import escape
from pathlib import Path
from typing import Any

from .adapters import ADAPTER_TYPES
from .config import SuiteConfig
from .finding_delta import apply_finding_delta
from .inventory import inventory_target
from .orchestrator import resolve_asset_paths
from .path_safety import resolve_regular_directory
from .readiness_guidance import readiness_guidance
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
    authority_error = _production_authority_error(config, name)
    if readiness.status == "ready" and authority_error:
        return {
            **_tool_result(name, "unavailable", authority_error, required),
            "executable": readiness.executable,
            "executable_sha256": readiness.executable_sha256,
            "executable_integrity_verified": readiness.executable_integrity_verified,
            "executable_organization_approved": False,
        }
    return {
        **_tool_result(name, readiness.status, readiness.reason, required),
        "executable": readiness.executable,
        "executable_sha256": readiness.executable_sha256,
        "executable_integrity_verified": readiness.executable_integrity_verified,
        "executable_organization_approved": (
            tool_config.executable_organization_approved
        ),
    }


def _production_authority_error(config: SuiteConfig, name: str) -> str:
    if config.profile not in {"production", "release"}:
        return ""
    tool = config.tools[name]
    missing: list[str] = []
    if not tool.executable_organization_approved:
        missing.append("primary")
    if (
        tool.auxiliary_executable
        and not tool.auxiliary_executable_organization_approved
    ):
        missing.append("auxiliary")
    return (
        f"organization approval is missing for {name} " + " and ".join(missing)
        if missing
        else ""
    )


def _assess_context(target: Path, config: SuiteConfig) -> list[str]:
    context_errors: list[str] = []
    inventory = inventory_target(target)
    context_errors.extend(enrich_findings([], config.intelligence).errors)
    context_errors.extend(
        apply_finding_delta(
            [],
            target=target,
            baseline_path=config.reports.baseline_path,
            baseline_sha256=config.reports.baseline_sha256,
            current_profile=config.profile,
            current_tools=tuple(config.selected_tools),
            current_vcs_revision=inventory.vcs_revision,
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
    next_actions = _next_actions(tools, context_errors)
    return {
        "schema_version": "1.1",
        "schema_id": "urn:project-py-security-suite:schema:doctor-readiness:1.1",
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
        "action_groups": _action_groups(next_actions),
        "next_actions": next_actions,
        "context_errors": context_errors,
        "tools": tools,
    }


def _action_groups(actions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Collapse equivalent remediation without hiding per-control evidence."""
    grouped: dict[tuple[str, bool, str, str], set[str]] = {}
    for action in actions:
        key = (
            str(action["priority"]),
            bool(action["blocking"]),
            str(action["category"]),
            str(action["required_action"]),
        )
        grouped.setdefault(key, set()).add(str(action["subject"]))
    return [
        {
            "priority": priority,
            "blocking": blocking,
            "category": category,
            "subjects": sorted(subjects),
            "count": len(subjects),
            "required_action": required_action,
        }
        for (priority, blocking, category, required_action), subjects in sorted(
            grouped.items(),
            key=lambda item: (
                item[0][0],
                not item[0][1],
                item[0][2],
                sorted(item[1]),
            ),
        )
    ]


def _next_actions(
    tools: list[dict[str, Any]], context_errors: list[str]
) -> list[dict[str, Any]]:
    actions: list[dict[str, Any]] = []
    for item in tools:
        if item["status"] not in {"disabled", "unavailable"} and item[
            "category"
        ] not in {
            "missing_approval",
            "missing_configuration",
            "missing_evidence",
            "platform_constraint",
        }:
            continue
        blocking = bool(
            item["required"] and item["status"] in {"disabled", "unavailable"}
        )
        actions.append(
            {
                "priority": "P0" if blocking else "P2",
                "blocking": blocking,
                "subject": str(item["tool"]),
                "category": str(item["category"]),
                "reason": str(item["reason"] or ""),
                "required_action": str(item["required_action"]),
            }
        )
    actions.extend(
        {
            "priority": "P0",
            "blocking": True,
            "subject": "governed-context",
            "category": "governed_context",
            "reason": error,
            "required_action": (
                "Restore the configured digest-bound evidence or approval and rerun preflight."
            ),
        }
        for error in context_errors
    )
    return sorted(
        actions,
        key=lambda item: (
            item["priority"],
            not item["blocking"],
            item["category"],
            item["subject"],
        ),
    )


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


def render_readiness(document: dict[str, Any], *, explain: bool = False) -> str:
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
    if explain:
        lines.extend(_render_explanation(document))
    lines.append(f"Scope: {document['scope']}")
    return "\n".join(lines)


def _render_explanation(document: dict[str, Any]) -> list[str]:
    lines = ["Resolution batches:"]
    groups = document.get("action_groups", [])
    if not groups:
        lines.append("- No prerequisite actions remain.")
    for group in groups:
        disposition = "BLOCK" if group["blocking"] else "PREPARE"
        lines.extend(
            [
                f"- {group['priority']} {disposition} "
                f"[{str(group['category']).replace('_', ' ')}]: "
                f"{_subject_summary(group['subjects'])}",
                f"  Do: {group['required_action']}",
            ]
        )
    actions = document.get("next_actions", [])
    if actions:
        lines.append("Per-control evidence:")
        lines.extend(
            f"- {action['subject']}: {action['reason'] or 'prerequisite state requires review'}"
            for action in actions
        )
    lines.append("Selected controls:")
    for item in document["tools"]:
        digest = str(item.get("executable_sha256") or "")
        identity = f"; sha256:{digest[:12]}…" if digest else ""
        lines.append(
            f"- {item['tool']}: {item['status']} ({item['category']}; "
            f"{'required' if item['required'] else 'optional'}{identity})"
        )
    lines.extend(
        [
            "Next command:",
            "- Inside an externally enforced isolated boundary, run "
            f"`pysec scan . --profile {document['profile']} --network-isolated "
            "--output .artifacts/pysec-report`.",
        ]
    )
    return lines


def render_readiness_markdown(document: dict[str, Any]) -> str:
    """Render a GitHub-ready preflight artifact without remote dependencies."""
    summary = document["summary"]
    state = "READY" if document["ready"] else "NOT READY"
    lines = [
        "# Scan preflight",
        "",
        f"**Decision:** {state}  ",
        f"**Profile:** `{_md(document['profile'])}`  ",
        f"**Target:** `{_md(document['target'])}`",
        "",
        "## Summary",
        "",
        "| Measure | Value |",
        "|---|---:|",
        f"| Selected controls | {summary['selected']} |",
        f"| Applicable and ready | {summary['ready']} / {summary['applicable']} |",
        f"| Required and ready | {summary['required_ready']} / {summary['required_applicable']} |",
        f"| Not applicable | {summary['not_applicable']} |",
        f"| Need attention | {summary['attention']} |",
        f"| Missing organization approvals | {summary['missing_approvals']} |",
        "",
        "## Resolution batches",
        "",
        "| Priority | Disposition | Category | Controls | Required action |",
        "|---|---|---|---:|---|",
    ]
    groups = document.get("action_groups", [])
    if groups:
        lines.extend(
            (
                f"| {_md(group['priority'])} | "
                f"{'BLOCK' if group['blocking'] else 'PREPARE'} | "
                f"{_md(str(group['category']).replace('_', ' '))} | "
                f"{group['count']} ({_md(_subject_summary(group['subjects']))}) | "
                f"{_md(group['required_action'])} |"
            )
            for group in groups
        )
    else:
        lines.append(
            "| — | PROCEED | — | No prerequisite gaps detected. | Run the isolated scan. |"
        )
    actions = document.get("next_actions", [])
    lines.extend(
        [
            "",
            "<details>",
            f"<summary>Per-control actions ({len(actions)})</summary>",
            "",
            "| Priority | Disposition | Control | Reason |",
            "|---|---|---|---|",
        ]
    )
    lines.extend(
        f"| {_md(action['priority'])} | "
        f"{'BLOCK' if action['blocking'] else 'PREPARE'} | "
        f"`{_md(action['subject'])}` | {_md(action['reason'] or 'Review required.')} |"
        for action in actions
    )
    lines.extend(
        [
            "",
            "</details>",
            "",
            "<details>",
            "<summary>All selected controls</summary>",
            "",
            "| Control | Status | Category | Required |",
            "|---|---|---|---|",
        ]
    )
    lines.extend(
        f"| `{_md(item['tool'])}` | {_md(item['status'])} | "
        f"{_md(item['category'])} | {'yes' if item['required'] else 'no'} |"
        for item in document["tools"]
    )
    lines.extend(
        [
            "",
            "</details>",
            "",
            "> Preflight does not execute scanners or grant isolation, signing, trust, or release approval.",
        ]
    )
    return "\n".join(lines) + "\n"


def _md(value: Any) -> str:
    text = escape(" ".join(str(value).split()), quote=False).replace("\\", "\\\\")
    for character in ("`", "*", "_", "[", "]", "|"):
        text = text.replace(character, f"\\{character}")
    return text


def _subject_summary(subjects: list[str], *, limit: int = 6) -> str:
    shown = subjects[:limit]
    remainder = len(subjects) - len(shown)
    summary = ", ".join(shown)
    return f"{summary}, +{remainder} more" if remainder else summary


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
        "missing_approvals": categories["missing_approval"],
        "platform_constraints": categories["platform_constraint"],
    }


def _tool_result(
    tool: str, status: str, reason: str | None, required: bool
) -> dict[str, Any]:
    category, action = _readiness_guidance(status, reason, tool=tool)
    return {
        "tool": tool,
        "status": status,
        "required": required,
        "reason": reason,
        "category": category,
        "required_action": action,
    }


def _readiness_guidance(
    status: str, reason: str | None, *, tool: str = "scanner"
) -> tuple[str, str]:
    """Compatibility wrapper around the shared readiness classifier."""
    return readiness_guidance(tool=tool, status=status, reason=reason)
