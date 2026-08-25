from __future__ import annotations

import hashlib
import json
import platform
from html import escape
from pathlib import Path
from typing import Any

from .config import SuiteConfig
from .doctor import assess_readiness


_SCHEMA_ID = "urn:project-py-security-suite:schema:provision-plan:1.0"


def build_provision_plan(*, target: Path, config: SuiteConfig) -> dict[str, Any]:
    """Build a non-mutating, offline provisioning plan from doctor evidence."""
    readiness = assess_readiness(target=target, config=config)
    workflows = [
        {
            "order": index,
            "priority": group["priority"],
            "blocking": group["blocking"],
            "category": group["category"],
            "controls": group["subjects"],
            "objective": group["required_action"],
        }
        for index, group in enumerate(readiness["action_groups"], start=1)
    ]
    controls = [
        {
            "control": item["tool"],
            "required": item["required"],
            "status": item["status"],
            "category": item["category"],
            "reason": item["reason"] or "",
            "required_action": item["required_action"],
        }
        for item in readiness["tools"]
    ]
    root = config.paths.bundle_root
    try:
        root_hint = root.relative_to(target.expanduser().absolute()).as_posix()
    except ValueError:
        root_hint = "<externally-governed-root>"
    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "schema_id": _SCHEMA_ID,
        "authoritative": False,
        "target": readiness["target"],
        "profile": readiness["profile"],
        "platform": {
            "system": platform.system().casefold() or "unknown",
            "machine": platform.machine().casefold() or "unknown",
            "python": platform.python_version(),
        },
        "decision": readiness["decision"],
        "summary": {
            **readiness["summary"],
            "workflow_batches": len(workflows),
            "blocking_batches": sum(item["blocking"] for item in workflows),
        },
        "bundle": {
            "namespace": "@bundle/",
            "root_hint": root_hint,
            "network_acquisition_performed": False,
            "filesystem_mutation_performed": False,
        },
        "workflows": workflows,
        "controls": controls,
        "context_errors": readiness["context_errors"],
        "verification": {
            "preflight_argv": [
                "pysec",
                "doctor",
                ".",
                "--profile",
                readiness["profile"],
                "--explain",
            ],
            "scan_argv": [
                "pysec",
                "scan",
                ".",
                "--profile",
                readiness["profile"],
                "--network-isolated",
                "--output",
                ".artifacts/pysec-report",
            ],
        },
        "scope": (
            "Planning evidence only: no package was downloaded, no file was changed, "
            "and no trust, isolation, signing, or release approval was granted."
        ),
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    payload["plan_id"] = "plan-" + hashlib.sha256(canonical.encode()).hexdigest()[:24]
    return payload


def render_provision_plan(document: dict[str, Any]) -> str:
    """Render concise terminal guidance with shell-safe argv presentation."""
    state = "READY" if document["decision"]["disposition"] == "proceed" else "BLOCKED"
    lines = [
        f"{state}: offline provisioning plan {document['plan_id']}",
        f"Profile: {document['profile']} | Target: {document['target']}",
        (
            f"Controls: {document['summary']['ready']}/{document['summary']['applicable']} "
            f"applicable ready; {document['summary']['workflow_batches']} resolution batch(es)"
        ),
        "Resolution batches:",
    ]
    if not document["workflows"]:
        lines.append("- None. Run the isolated scan.")
    for item in document["workflows"]:
        controls = ", ".join(item["controls"][:6])
        if len(item["controls"]) > 6:
            controls += f", +{len(item['controls']) - 6} more"
        lines.append(
            f"- {item['priority']} {'BLOCK' if item['blocking'] else 'PREPARE'} "
            f"[{item['category'].replace('_', ' ')}] {controls}: {item['objective']}"
        )
    lines.append(f"Scope: {document['scope']}")
    return "\n".join(lines)


def render_provision_plan_markdown(document: dict[str, Any]) -> str:
    """Render a GitHub-ready offline provisioning artifact."""
    disposition = str(document["decision"]["disposition"]).upper()
    lines = [
        "# Offline provisioning plan",
        "",
        f"**Decision:** {disposition}  ",
        f"**Plan:** `{_md(document['plan_id'])}`  ",
        f"**Profile:** `{_md(document['profile'])}`  ",
        "**Bundle namespace:** `@bundle/`",
        "",
        "## Resolution batches",
        "",
        "| Order | Priority | Disposition | Category | Controls | Action |",
        "|---:|---|---|---|---|---|",
    ]
    if document["workflows"]:
        lines.extend(
            (
                f"| {item['order']} | {_md(item['priority'])} | "
                f"{'BLOCK' if item['blocking'] else 'PREPARE'} | "
                f"{_md(item['category'].replace('_', ' '))} | "
                f"{_md(', '.join(item['controls']))} | {_md(item['objective'])} |"
            )
            for item in document["workflows"]
        )
    else:
        lines.append(
            "| - | - | PROCEED | - | All selected controls | Run isolated scan. |"
        )
    lines.extend(
        [
            "",
            "## Safety boundary",
            "",
            f"> {_md(document['scope'])}",
            "",
            "## Verification commands",
            "",
            "```text",
            " ".join(document["verification"]["preflight_argv"]),
            " ".join(document["verification"]["scan_argv"]),
            "```",
        ]
    )
    return "\n".join(lines) + "\n"


def _md(value: object) -> str:
    text = escape(" ".join(str(value).split()), quote=False).replace("\\", "\\\\")
    for character in ("`", "*", "_", "[", "]", "|"):
        text = text.replace(character, f"\\{character}")
    return text
