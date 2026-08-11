from __future__ import annotations

import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any

from .execution import sanitize_terminal_text
from .models import Finding, ScanManifest, json_ready
from .passport import verify_report
from .path_safety import resolve_regular_file


_MAX_JSON_BYTES = 128 * 1024 * 1024
_SCHEMA_ID = "urn:project-py-security-suite:schema:closure-plan:1.0"
_PRIORITY_ORDER = {"P0": 0, "P1": 1, "P2": 2, "P3": 3, "P4": 4}
_SEVERITY_PRIORITY = {
    "critical": "P0",
    "high": "P1",
    "medium": "P2",
    "low": "P3",
    "informational": "P4",
    "unknown": "P3",
}


def build_closure_plan(
    report: Path,
    *,
    coverage_target: float = 90.0,
    hotspot_limit: int = 10,
) -> dict[str, Any]:
    """Build an owned closure backlog from one independently verified report."""
    _validate_options(coverage_target, hotspot_limit)
    verification = verify_report(report)
    root = report.expanduser().absolute().resolve()
    return _build(
        scan_id=str(verification["scan_id"]),
        outcome=str(verification["outcome"]),
        source_sha256=str(
            _read_object(root / "scan-manifest.json")
            .get("inventory", {})
            .get("source_sha256", "")
        ),
        findings=_object_list(
            _read_object(root / "findings.json").get("findings"), "findings"
        ),
        manifest=_read_object(root / "scan-manifest.json"),
        portfolio=_optional_object(root / "portfolio-health.json"),
        admission=_optional_object(root / "admission-decisions.json"),
        coverage=_optional_object(root / "coverage-summary.json"),
        reachability=_optional_object(root / "reachability.json"),
        coverage_target=coverage_target,
        hotspot_limit=hotspot_limit,
    )


def closure_plan_artifact(
    manifest: ScanManifest,
    findings: list[Finding],
    artifacts: dict[str, Any],
    *,
    coverage_target: float = 90.0,
    hotspot_limit: int = 10,
) -> dict[str, Any]:
    """Build the canonical closure plan while a report is being assembled."""
    _validate_options(coverage_target, hotspot_limit)
    manifest_document = json_ready(manifest)
    inventory = manifest_document.get("inventory", {})
    return _build(
        scan_id=manifest.scan_id,
        outcome=manifest.outcome.value,
        source_sha256=str(
            inventory.get("source_sha256", "") if isinstance(inventory, dict) else ""
        ),
        findings=[json_ready(finding) for finding in findings],
        manifest=manifest_document,
        portfolio=_as_object(artifacts.get("portfolio-health.json")),
        admission=_as_object(artifacts.get("admission-decisions.json")),
        coverage=_as_object(artifacts.get("coverage-summary.json")),
        reachability=_as_object(artifacts.get("reachability.json")),
        coverage_target=coverage_target,
        hotspot_limit=hotspot_limit,
    )


def render_closure_plan_markdown(plan: dict[str, Any]) -> str:
    """Render a GitHub-readable closure plan without weakening its JSON contract."""
    summary = _as_object(plan.get("summary"))
    authority_items = int(summary.get("authority_items") or 0)
    authority_line = (
        f"- **External or organization authority:** {authority_items} item(s)"
    )
    authority_notice = (
        "> This plan is non-authoritative. It prepares evidence and actions but "
        + "cannot approve scanner identities, attest isolation, or authorize a release."
    )
    lines = [
        "# Findings closure plan",
        "",
        f"- **Scan:** `{_md(plan.get('scan_id'))}`",
        f"- **Outcome:** `{_md(plan.get('outcome'))}`",
        f"- **Open work:** {int(summary.get('open_items') or 0)} item(s)",
        authority_line,
        "",
        authority_notice,
        "",
        "## Prioritized work",
        "",
        "| Priority | Authority | Status | Owner | Work item | Acceptance evidence |",
        "|---|---|---|---|---|---|",
    ]
    for item in _object_list(plan.get("items"), "closure plan items"):
        acceptance = item.get("acceptance_criteria")
        criteria = (
            str(acceptance[0])
            if isinstance(acceptance, list) and acceptance
            else "Rerun and seal the report."
        )
        lines.append(
            "| "
            + " | ".join(
                (
                    f"`{_md(item.get('priority'))}`",
                    _md(item.get("authority")),
                    _md(item.get("status")),
                    f"`{_md(item.get('owner'))}`",
                    f"**{_md(item.get('title'))}**<br>{_md(item.get('action'))}",
                    _md(criteria),
                )
            )
            + " |"
        )
    lines.extend(("", "## Safe command handoffs", ""))
    command_items = [
        item
        for item in _object_list(plan.get("items"), "closure plan items")
        if item.get("commands")
    ]
    if not command_items:
        lines.append("No command handoff is required for the current plan.")
    for item in command_items:
        lines.extend((f"### {_md(item.get('id'))} · {_md(item.get('title'))}", ""))
        for command in item["commands"]:
            rendered = " ".join(_shell_display(value) for value in command)
            lines.extend(("```text", rendered, "```", ""))
    return "\n".join(lines).rstrip() + "\n"


def _build(
    *,
    scan_id: str,
    outcome: str,
    source_sha256: str,
    findings: list[dict[str, Any]],
    manifest: dict[str, Any],
    portfolio: dict[str, Any],
    admission: dict[str, Any],
    coverage: dict[str, Any],
    reachability: dict[str, Any],
    coverage_target: float,
    hotspot_limit: int,
) -> dict[str, Any]:
    items: list[dict[str, Any]] = []
    items.extend(_finding_items(findings))
    items.extend(_governance_items(manifest, admission))
    items.extend(_activation_items(portfolio))
    items.extend(_coverage_items(coverage, coverage_target, hotspot_limit))
    items.extend(_reachability_items(reachability))
    items = _deduplicate(items)
    items.sort(
        key=lambda item: (
            _PRIORITY_ORDER[str(item["priority"])],
            str(item["authority"]),
            str(item["category"]),
            str(item["id"]),
        )
    )
    priorities = Counter(str(item["priority"]) for item in items)
    statuses = Counter(str(item["status"]) for item in items)
    authorities = Counter(str(item["authority"]) for item in items)
    return {
        "schema_version": "1.0",
        "schema_id": _SCHEMA_ID,
        "authoritative": False,
        "scope": (
            "Verified report findings and evidence gaps converted into owned closure "
            "work; independent authorities retain signing, isolation, trust, and "
            "release decisions."
        ),
        "scan_id": scan_id,
        "outcome": outcome,
        "source_sha256": source_sha256,
        "parameters": {
            "coverage_target_percent": coverage_target,
            "hotspot_limit": hotspot_limit,
        },
        "summary": {
            "open_items": len(items),
            "authority_items": sum(
                count
                for name, count in authorities.items()
                if name in {"organization", "external"}
            ),
            "by_priority": dict(sorted(priorities.items())),
            "by_status": dict(sorted(statuses.items())),
            "by_authority": dict(sorted(authorities.items())),
        },
        "items": items,
    }


def _finding_items(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    items = []
    for finding in findings:
        status = str(finding.get("status") or "new")
        if status in {"suppressed", "resolved", "accepted"}:
            continue
        finding_id = str(finding.get("finding_id") or "unknown")
        sources = _object_list(finding.get("sources"), "finding sources")
        tools = sorted(
            {str(source.get("tool")) for source in sources if source.get("tool")}
        )
        rules = {str(source.get("rule_id")) for source in sources}
        external = "COSIGN-BUNDLE-MISSING" in rules
        evidence = _as_object(finding.get("evidence"))
        owners = evidence.get("owners")
        owner = (
            str(owners[0])
            if isinstance(owners, list) and owners
            else "release-engineering"
            if external
            else "repository-maintainers"
        )
        location_paths = sorted(
            str(location.get("path"))
            for location in _object_list(finding.get("locations"), "locations")
            if location.get("path")
        )
        items.append(
            _item(
                key=f"finding:{finding_id}",
                priority=_SEVERITY_PRIORITY.get(
                    str(finding.get("severity") or "unknown"), "P3"
                ),
                category="finding",
                authority="external" if external else "repository",
                status="external_required" if external else "open",
                owner=owner,
                title=str(finding.get("title") or finding_id),
                why=str(finding.get("impact") or finding.get("description") or ""),
                action=str(
                    finding.get("remediation") or "Review and resolve the finding."
                ),
                acceptance=[
                    f"Finding {finding_id} is absent or governed in a newly sealed report.",
                    "The replacement report independently passes pysec verify-report.",
                ],
                evidence_refs=["findings.json", "action-plan.md", *location_paths],
                commands=(
                    [
                        [
                            "pysec",
                            "prepare-signing",
                            "<REPORT_DIRECTORY>",
                            "<ARTIFACT_DIRECTORY>",
                            "--output",
                            "<SIGNING_REQUEST_JSON>",
                        ]
                    ]
                    if external
                    else []
                ),
                related_findings=[finding_id],
                tools=tools,
            )
        )
    return items


def _governance_items(
    manifest: dict[str, Any], admission: dict[str, Any]
) -> list[dict[str, Any]]:
    gaps: set[str] = set()
    for axis in _object_list(admission.get("axes"), "admission axes"):
        if axis.get("axis") == "governance":
            value = axis.get("integrity_gaps")
            if isinstance(value, list):
                gaps.update(str(gap) for gap in value if str(gap).strip())
    items = []
    for gap in sorted(gaps):
        isolation = "isolation" in gap.lower()
        approval = "approval" in gap.lower()
        title = (
            "Provide external network-isolation evidence"
            if isolation
            else "Approve exact scanner entry-point identities"
            if approval
            else "Resolve governance evidence gap"
        )
        action = (
            "Capture and independently approve an isolation attestation bound to the "
            "target source identity and scan window."
            if isolation
            else "Review provenance for each unique executable digest, then record "
            "expiring organization approvals for every affected binding."
            if approval
            else gap
        )
        items.append(
            _item(
                key=f"governance:{gap}",
                priority="P1",
                category="governance",
                authority="organization",
                status="external_required",
                owner="platform-security" if isolation else "security-governance",
                title=title,
                why=gap,
                action=action,
                acceptance=[
                    "The governance admission axis is allow in a newly sealed report.",
                    "The evidence identity and approval remain independently verifiable.",
                ],
                evidence_refs=[
                    "admission-decisions.json",
                    "scanner-trust.json" if approval else "isolation-attestation.json",
                ],
                commands=[
                    [
                        "pysec",
                        "evidence-draft",
                        "<REPORT_DIRECTORY>",
                        "--format",
                        "json",
                        "--output",
                        "<GOVERNANCE_DRAFT_JSON>",
                    ]
                ],
            )
        )
    if manifest.get("network_isolation_attested") is False and not any(
        "isolation" in gap.lower() for gap in gaps
    ):
        # Older reports may not contain admission evidence; preserve fail-closed guidance.
        items.extend(
            _governance_items(
                manifest,
                {
                    "axes": [
                        {
                            "axis": "governance",
                            "integrity_gaps": [
                                "external network-isolation attestation is absent"
                            ],
                        }
                    ]
                },
            )
        )
    return items


def _activation_items(portfolio: dict[str, Any]) -> list[dict[str, Any]]:
    items = []
    for recipe in _object_list(
        portfolio.get("activation_recipes"), "activation recipes"
    ):
        tool = str(recipe.get("tool") or "unknown")
        category = str(recipe.get("category") or "conditional")
        authority = (
            "external"
            if category in {"companion_evidence", "platform_constraint"}
            else "organization"
            if category
            in {"missing_configuration", "target_environment", "release_configuration"}
            else "repository"
        )
        items.append(
            _item(
                key=f"activation:{tool}:{category}",
                priority="P2",
                category="conditional-control",
                authority=authority,
                status="conditional",
                owner=str(recipe.get("owner") or "repository-maintainers"),
                title=f"Activate {tool} when its trigger is satisfied",
                why=str(recipe.get("reason") or "Control is not currently applicable."),
                action=str(recipe.get("required_action") or "Reassess applicability."),
                acceptance=[
                    str(
                        recipe.get("evidence_required")
                        or "A completed control result in a newly sealed report."
                    ),
                    "Applicability is recalculated rather than manually overridden.",
                ],
                evidence_refs=["portfolio-health.json", "scan-manifest.json"],
                commands=_activation_commands(tool),
                tools=[tool],
            )
        )
    return items


def _coverage_items(
    coverage: dict[str, Any], target: float, limit: int
) -> list[dict[str, Any]]:
    candidates = []
    for record in _object_list(coverage.get("files"), "coverage files"):
        summary = _as_object(record.get("summary"))
        percent = summary.get("percent_covered")
        if not isinstance(percent, (int, float)) or isinstance(percent, bool):
            continue
        if float(percent) >= target:
            continue
        path = str(record.get("path") or "")
        if not path.startswith(("src/", "src\\")):
            continue
        candidates.append((float(percent), path, summary))
    candidates.sort(key=lambda value: (value[0], value[1]))
    items = []
    for percent, path, _summary in candidates[:limit]:
        items.append(
            _item(
                key=f"coverage:{path}:{target:.3f}",
                priority="P2",
                category="test-assurance",
                authority="repository",
                status="open",
                owner="quality-engineering",
                title=f"Raise decision coverage for {path}",
                why=(
                    f"Combined line/branch coverage is {percent:.2f}% versus the "
                    f"{target:.2f}% closure target."
                ),
                action=(
                    "Add behavior-focused tests for failure, boundary, rollback, and "
                    "security-relevant branches; do not add assertion-free execution."
                ),
                acceptance=[
                    f"The module reaches at least {target:.2f}% combined coverage.",
                    "New tests assert externally meaningful outcomes and failure behavior.",
                ],
                evidence_refs=["coverage-summary.json", path.replace("\\", "/")],
                tools=["coverage", "junit"],
            )
        )
    return items


def _activation_commands(tool: str) -> list[list[str]]:
    if tool == "reproducible-build":
        return [
            [
                "pysec",
                "normalize-sdist",
                "<FIRST_SDIST_TAR_GZ>",
                "--output",
                "<FIRST_SDIST_TAR_GZ>",
                "--source-date-epoch",
                "<REVIEWED_EPOCH>",
                "--overwrite",
            ],
            [
                "pysec",
                "normalize-sdist",
                "<SECOND_SDIST_TAR_GZ>",
                "--output",
                "<SECOND_SDIST_TAR_GZ>",
                "--source-date-epoch",
                "<REVIEWED_EPOCH>",
                "--overwrite",
            ],
            [
                "pysec",
                "compare-builds",
                "<FIRST_BUILD_DIRECTORY>",
                "<SECOND_BUILD_DIRECTORY>",
                "--format",
                "json",
                "--output",
                "<REPRODUCIBLE_BUILD_JSON>",
            ],
        ]
    return []


def _reachability_items(reachability: dict[str, Any]) -> list[dict[str, Any]]:
    warnings = reachability.get("warnings")
    if not isinstance(warnings, list) or not warnings:
        return []
    dynamic = [str(value) for value in warnings if "dynamic" in str(value).lower()]
    if not dynamic:
        return []
    summary = _as_object(reachability.get("summary"))
    return [
        _item(
            key="reachability:dynamic-roots",
            priority="P2",
            category="architecture",
            authority="repository",
            status="review",
            owner="architecture",
            title="Model legitimate dynamic reachability roots",
            why=" ".join(dynamic),
            action=(
                "Inventory plugin registries, callbacks, dependency injection, and "
                "reflection; configure reviewed roots and rerun reachability analysis."
            ),
            acceptance=[
                "Every legitimate dynamic root is configured or documented with an owner.",
                "No runtime-observed load-only candidate is removed without review.",
            ],
            evidence_refs=["reachability.json", "docs/reachability.md"],
            tools=["reachability"],
            details={
                "load_only_islands": int(summary.get("load_only_islands") or 0),
                "reportable_islands": int(summary.get("reportable_islands") or 0),
            },
        )
    ]


def _item(
    *,
    key: str,
    priority: str,
    category: str,
    authority: str,
    status: str,
    owner: str,
    title: str,
    why: str,
    action: str,
    acceptance: list[str],
    evidence_refs: list[str],
    commands: list[list[str]] | None = None,
    related_findings: list[str] | None = None,
    tools: list[str] | None = None,
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    digest = hashlib.sha256(key.encode("utf-8")).hexdigest()[:12].upper()
    return {
        "id": f"PYSEC-ACT-{digest}",
        "priority": priority,
        "category": category,
        "authority": authority,
        "status": status,
        "owner": owner[:256],
        "title": sanitize_terminal_text(title, maximum=1000),
        "why": sanitize_terminal_text(why, maximum=16_000),
        "action": sanitize_terminal_text(action, maximum=16_000),
        "acceptance_criteria": [
            sanitize_terminal_text(value, maximum=4000) for value in acceptance
        ],
        "evidence_refs": sorted({value[:4096] for value in evidence_refs if value}),
        "commands": commands or [],
        "related_findings": sorted(set(related_findings or [])),
        "tools": sorted(set(tools or [])),
        "details": details or {},
    }


def _deduplicate(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for item in items:
        result.setdefault(str(item["id"]), item)
    return list(result.values())


def _read_object(path: Path) -> dict[str, Any]:
    source = resolve_regular_file(path, "closure plan input")
    with source.open("rb") as handle:
        payload = handle.read(_MAX_JSON_BYTES + 1)
    if len(payload) > _MAX_JSON_BYTES:
        raise ValueError(f"closure plan input exceeds 128 MiB: {source.name}")
    try:
        value = json.loads(payload)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValueError(f"closure plan input is invalid JSON: {source.name}") from exc
    if not isinstance(value, dict):
        raise TypeError(f"closure plan input root must be an object: {source.name}")
    return value


def _optional_object(path: Path) -> dict[str, Any]:
    return _read_object(path) if path.is_file() else {}


def _as_object(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _object_list(value: Any, label: str) -> list[dict[str, Any]]:
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise TypeError(f"{label} must be an array of objects")
    return value


def _validate_options(coverage_target: float, hotspot_limit: int) -> None:
    if not 0.0 <= coverage_target <= 100.0:
        raise ValueError("coverage target must be between 0 and 100")
    if hotspot_limit < 0 or hotspot_limit > 100:
        raise ValueError("hotspot limit must be between 0 and 100")


def _md(value: Any) -> str:
    return str(value or "").replace("|", "\\|").replace("\n", " ")


def _shell_display(value: Any) -> str:
    text = str(value)
    if text.startswith("<") and text.endswith(">"):
        return text
    if not text or any(character.isspace() for character in text):
        return json.dumps(text)
    return text
