from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timedelta, timezone
from html import escape
from pathlib import Path
from typing import Any

from .execution import sha256_file
from .passport import verify_report
from .path_safety import resolve_regular_file

_MAX_JSON_BYTES = 128 * 1024 * 1024
_CLAIM_OWNERS = {
    "PS.1": "repository-owner",
    "PS.3": "release-engineering",
    "PW.4": "vulnerability-management",
    "PW.7": "application-security",
    "RV.1": "application-security",
    "PO.5": "platform-security",
}
_CLAIM_PREREQUISITES = {
    "PS.1": ["verified source snapshot before and after scanner execution"],
    "PS.3": [
        "exact release payload manifest",
        "verified Sigstore bundle for every release artifact",
        "signed Security Passport bound to the payload and report",
    ],
    "PW.4": [
        "complete dependency inventory and SBOM",
        "fresh vulnerability intelligence",
        "organization approval for the exact intelligence snapshot set",
    ],
    "PW.7": ["completed static analysis portfolio", "reviewable cited findings"],
    "RV.1": [
        "no active blocking security or supply-chain findings",
        "comparable approved baseline",
        "passing labeled detection corpus",
    ],
    "PO.5": [
        "externally enforced network isolation",
        "signed attestation bound to runner, source, policy, and validity window",
    ],
}


def build_promotion_plan(
    report: Path,
    *,
    release_readiness: Path | None = None,
    release_readiness_sha256: str = "",
) -> dict[str, Any]:
    """Build one decision-first, non-authoritative promotion plan."""
    _paired(release_readiness, release_readiness_sha256, "release readiness")
    verification = verify_report(report)
    root = report.expanduser().resolve()
    manifest = _read_object(root / "scan-manifest.json")
    findings_document = _read_object(root / "findings.json")
    claims_document = _read_object(root / "assurance-claims.json")
    portfolio = _read_object(root / "portfolio-health.json")
    delta = _read_object(root / "finding-delta.json")
    findings = _object_list(findings_document.get("findings"), "findings")
    claims = _object_list(claims_document.get("claims"), "assurance claims")
    tools = _object_list(manifest.get("tools"), "tools")
    readiness = (
        _digest_bound_object(
            release_readiness,
            release_readiness_sha256,
            "release readiness",
        )
        if release_readiness is not None
        else {}
    )
    if readiness:
        bound_report = readiness.get("report")
        if (
            not isinstance(bound_report, dict)
            or bound_report.get("checksums_sha256") != verification["checksums_sha256"]
        ):
            raise ValueError("release readiness is not bound to this report")
    active = [finding for finding in findings if finding.get("status") != "suppressed"]
    blocking = [finding for finding in active if finding.get("blocking") is True]
    claim_closure = [_claim_closure(claim) for claim in claims]
    evidence_quality = [_evidence_quality(finding) for finding in active]
    reliability = _scanner_reliability(tools)
    conditional = _conditional_domains(portfolio)
    baseline = _baseline_summary(delta)
    blockers = (
        [str(value) for value in readiness.get("blockers", [])]
        if isinstance(readiness.get("blockers"), list)
        else _derived_blockers(manifest, blocking, claim_closure)
    )
    lifecycle = _lifecycle(
        manifest,
        blocking=blocking,
        blockers=blockers,
        release_decision=str(readiness.get("decision") or "not_evaluated"),
    )
    blocker_graph = _blocker_graph(readiness, blockers)
    freshness = _evidence_freshness(root, manifest)
    actions = _next_actions(
        readiness=readiness,
        blockers=blockers,
        conditional=conditional,
        baseline=baseline,
    )
    actions = _with_service_levels(actions, manifest)
    return {
        "schema_version": "1.1",
        "status": "ready" if not blockers else "blocked",
        "authoritative": False,
        "scope": (
            "Decision-support plan derived from sealed evidence. Organization policy, "
            "signing authority, and deployment admission remain external."
        ),
        "report": {
            "scan_id": verification["scan_id"],
            "checksums_sha256": verification["checksums_sha256"],
            "files_verified": verification["file_count"],
            "outcome": verification["outcome"],
        },
        "summary": {
            "active_findings": len(active),
            "blocking_findings": len(blocking),
            "failed_claims": sum(
                item["result"] != "satisfied" for item in claim_closure
            ),
            "release_blockers": len(blockers),
            "conditional_domains": len(conditional),
            "evidence_quality_average": _average_quality(evidence_quality),
            "scanner_execution_complete": reliability["execution_gaps"] == 0,
        },
        "release_blockers": blockers,
        "blocker_graph": blocker_graph,
        "lifecycle": lifecycle,
        "assurance_closure": claim_closure,
        "finding_evidence_quality": evidence_quality,
        "detection_perspectives": _detection_perspectives(active),
        "baseline_comparability": baseline,
        "conditional_coverage": conditional,
        "scanner_reliability": reliability,
        "evidence_freshness": freshness,
        "configuration_provenance": _configuration_provenance(manifest, tools),
        "artifact_graph": _artifact_graph(manifest, findings),
        "audiences": _audience_views(
            blockers=blockers,
            blocking=blocking,
            claim_closure=claim_closure,
            conditional=conditional,
        ),
        "retention": _retention_plan(),
        "github_annotations": _github_annotations(blockers, blocking),
        "next_actions": actions,
    }


def render_promotion_markdown(plan: dict[str, Any]) -> str:
    """Render the decision-support plan for a GitHub artifact or job summary."""
    summary = plan["summary"]
    lines = [
        "# Release promotion plan",
        "",
        f"**Status:** {str(plan['status']).upper()}  ",
        f"**Scan:** `{plan['report']['scan_id']}`  ",
        f"**Evidence seal:** `{plan['report']['checksums_sha256']}`",
        "",
        "## Decision summary",
        "",
        "| Measure | Value |",
        "|---|---:|",
        f"| Active findings | {summary['active_findings']} |",
        f"| Blocking findings | {summary['blocking_findings']} |",
        f"| Release blockers | {summary['release_blockers']} |",
        f"| Evidence quality | {summary['evidence_quality_average']}% |",
        "",
        "## Lifecycle",
        "",
        "| Stage | Status | Detail |",
        "|---|---|---|",
    ]
    for item in plan["lifecycle"]:
        detail = str(item["detail"]).replace("|", "\\|").replace("\n", " ")
        lines.append(f"| {item['stage']} | {item['status']} | {detail} |")
    lines.extend(["", "## Next actions", ""])
    actions = plan["next_actions"]
    if not actions:
        lines.append(
            "No repository actions remain; continue with external admission policy."
        )
    for number, action in enumerate(actions, start=1):
        lines.extend(_render_markdown_action(action, number))
    lines.extend(
        [
            "",
            "## Evidence freshness",
            "",
            "| Evidence | Status | Valid until |",
            "|---|---|---|",
        ]
    )
    lines.extend(
        f"| {item['kind']} | {item['status']} | {item.get('valid_until') or 'not supplied'} |"
        for item in plan.get("evidence_freshness", [])
    )
    lines.extend(["", "## Blocker relationships", ""])
    graph = plan.get("blocker_graph", [])
    if graph:
        lines.extend(
            f"- `{item['derived_from']}` causes `{item['blocker']}`" for item in graph
        )
    else:
        lines.append("No causal blocker edges were reported.")
    lines.extend(
        [
            "",
            "> This is non-authoritative decision support. Verify the sealed report and apply organization admission policy.",
        ]
    )
    return "\n".join(lines) + "\n"


def render_promotion_html(plan: dict[str, Any]) -> str:
    """Render a standalone, dependency-free HTML promotion view."""
    markdown = render_promotion_markdown(plan)
    lifecycle_rows = "".join(
        f"<tr><td>{escape(str(item['stage']))}</td><td><span class='{escape(str(item['status']))}'>{escape(str(item['status']))}</span></td><td>{escape(str(item['detail']))}</td></tr>"
        for item in plan["lifecycle"]
    )
    actions = (
        "".join(
            _render_html_action(item, number)
            for number, item in enumerate(plan["next_actions"], start=1)
        )
        or "<p>No repository actions remain; continue with external admission policy.</p>"
    )
    summary = plan["summary"]
    freshness_rows = "".join(
        f"<tr><td>{escape(str(item['kind']))}</td><td>{escape(str(item['status']))}</td><td>{escape(str(item.get('valid_until') or 'not supplied'))}</td></tr>"
        for item in plan.get("evidence_freshness", [])
    )
    blocker_rows = (
        "".join(
            f"<li><code>{escape(str(item['derived_from']))}</code> causes <code>{escape(str(item['blocker']))}</code></li>"
            for item in plan.get("blocker_graph", [])
        )
        or "<li>No causal blocker edges were reported.</li>"
    )
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Release promotion plan</title><style>
body{{font:16px/1.5 system-ui,sans-serif;color:#172033;background:#f5f7fb;margin:0}}main{{max-width:1050px;margin:2rem auto;padding:2rem;background:white;border-radius:14px;box-shadow:0 8px 30px #1720331a}}h1{{margin-top:0}}code{{word-break:break-all}}pre{{margin:.75rem 0 0;padding:.75rem;overflow:auto;background:#172033;color:#f8fafc;border-radius:6px}}pre code{{word-break:normal}}.blocked,.fail{{color:#9f1239;font-weight:700}}.complete,.ready{{color:#166534;font-weight:700}}table{{border-collapse:collapse;width:100%;margin:1rem 0}}th,td{{text-align:left;padding:.65rem;border-bottom:1px solid #dbe2ee}}.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:.75rem}}.card{{background:#f5f7fb;padding:1rem;border-radius:8px}}.actions{{display:grid;gap:1rem}}.action{{border:1px solid #dbe2ee;border-left:5px solid #64748b;padding:1rem 1.15rem;border-radius:8px}}.action h3{{margin:0 0 .5rem}}.action p{{margin:.4rem 0}}.metadata{{display:flex;flex-wrap:wrap;gap:.4rem 1rem;color:#475569}}.priority{{display:inline-block;padding:.05rem .45rem;border-radius:999px;background:#fff1f2;color:#9f1239;font-size:.85rem}}footer{{margin-top:2rem;color:#5d677a}}
</style></head><body><main><h1>Release promotion plan</h1>
<p class="{escape(str(plan["status"]))}">{escape(str(plan["status"]).upper())}</p>
<p>Scan <code>{escape(str(plan["report"]["scan_id"]))}</code><br>Evidence seal <code>{escape(str(plan["report"]["checksums_sha256"]))}</code></p>
<section class="cards"><div class="card"><strong>{summary["active_findings"]}</strong><br>Active findings</div><div class="card"><strong>{summary["blocking_findings"]}</strong><br>Blocking findings</div><div class="card"><strong>{summary["release_blockers"]}</strong><br>Release blockers</div><div class="card"><strong>{summary["evidence_quality_average"]}%</strong><br>Evidence quality</div></section>
<h2>Lifecycle</h2><table><thead><tr><th>Stage</th><th>Status</th><th>Detail</th></tr></thead><tbody>{lifecycle_rows}</tbody></table>
<h2>Evidence freshness</h2><table><thead><tr><th>Evidence</th><th>Status</th><th>Valid until</th></tr></thead><tbody>{freshness_rows}</tbody></table>
<h2>Blocker relationships</h2><ul>{blocker_rows}</ul>
<h2>Next actions</h2><section class="actions">{actions}</section><footer>Non-authoritative decision support. Verify the sealed report and apply organization admission policy.</footer>
<!-- Markdown equivalent SHA-independent length: {len(markdown)} --></main></body></html>"""


def _render_markdown_action(action: dict[str, Any], number: int) -> list[str]:
    owner = action.get("owner") or action.get("authority") or "unassigned"
    priority = action.get("priority") or "P2"
    text = (
        action.get("action")
        or action.get("detail")
        or action.get("id")
        or "Review required"
    )
    lines = [
        f"### {number}. {_markdown_text(priority)} · {_markdown_text(owner)}",
        "",
        _markdown_text(text),
        "",
    ]
    metadata: list[str] = []
    if action.get("id"):
        metadata.append(f"- **Action ID:** {_markdown_code(action['id'])}")
    if action.get("authority"):
        metadata.append(
            f"- **Required authority:** {_markdown_code(action['authority'])}"
        )
    service_level = action.get("service_level")
    if isinstance(service_level, dict):
        due = service_level.get("due_at") or "not calculated"
        days = service_level.get("target_days")
        target = _markdown_code(due)
        if days is not None:
            target += f" ({_markdown_text(days)} days)"
        metadata.append(f"- **Target:** {target}")
    evidence = action.get("evidence")
    if isinstance(evidence, list) and evidence:
        subjects = ", ".join(_markdown_code(value) for value in evidence)
        metadata.append(f"- **Evidence subjects:** {subjects}")
    lines.extend(metadata)
    commands = action.get("commands")
    if isinstance(commands, list) and commands:
        command_text = "\n".join(_single_line(value) for value in commands)
        lines.extend(
            [
                "- **Suggested commands:**",
                "",
                f"  <pre><code>{escape(command_text, quote=False)}</code></pre>",
            ]
        )
    lines.append("")
    return lines


def _render_html_action(action: dict[str, Any], number: int) -> str:
    owner = action.get("owner") or action.get("authority") or "unassigned"
    priority = action.get("priority") or "P2"
    text = (
        action.get("action")
        or action.get("detail")
        or action.get("id")
        or "Review required"
    )
    metadata: list[str] = []
    if action.get("id"):
        metadata.append(
            f"<span><strong>Action ID:</strong> <code>{escape(_single_line(action['id']))}</code></span>"
        )
    if action.get("authority"):
        metadata.append(
            f"<span><strong>Authority:</strong> <code>{escape(_single_line(action['authority']))}</code></span>"
        )
    service_level = action.get("service_level")
    if isinstance(service_level, dict):
        due = service_level.get("due_at") or "not calculated"
        days = service_level.get("target_days")
        suffix = f" ({escape(_single_line(days))} days)" if days is not None else ""
        metadata.append(
            f"<span><strong>Target:</strong> <code>{escape(_single_line(due))}</code>{suffix}</span>"
        )
    evidence = action.get("evidence")
    evidence_html = ""
    if isinstance(evidence, list) and evidence:
        subjects = ", ".join(
            f"<code>{escape(_single_line(value))}</code>" for value in evidence
        )
        evidence_html = f"<p><strong>Evidence subjects:</strong> {subjects}</p>"
    commands = action.get("commands")
    commands_html = ""
    if isinstance(commands, list) and commands:
        command_text = "\n".join(_single_line(value) for value in commands)
        commands_html = f"<p><strong>Suggested commands:</strong></p><pre><code>{escape(command_text)}</code></pre>"
    return (
        '<article class="action">'
        f'<h3>{number}. <span class="priority">{escape(_single_line(priority))}</span> '
        f"{escape(_single_line(owner))}</h3>"
        f"<p>{escape(_single_line(text))}</p>"
        f'<div class="metadata">{"".join(metadata)}</div>'
        f"{evidence_html}{commands_html}</article>"
    )


def _single_line(value: Any) -> str:
    return " ".join(str(value).split())


def _markdown_text(value: Any) -> str:
    text = escape(_single_line(value), quote=False).replace("\\", "\\\\")
    for character in ("`", "*", "_", "[", "]", "|"):
        text = text.replace(character, f"\\{character}")
    return text


def _markdown_code(value: Any) -> str:
    return f"<code>{escape(_single_line(value), quote=False)}</code>"


def _claim_closure(claim: dict[str, Any]) -> dict[str, Any]:
    control = str(claim.get("control") or "unknown")
    reasons = claim.get("blocking_reasons")
    blockers = (
        [str(value) for value in reasons if isinstance(value, str)]
        if isinstance(reasons, list)
        else []
    )
    return {
        "control": control,
        "claim": str(claim.get("claim") or ""),
        "result": str(claim.get("result") or "unknown"),
        "owner": _CLAIM_OWNERS.get(control, "application-security"),
        "blocking_reasons": blockers,
        "prerequisites": _CLAIM_PREREQUISITES.get(
            control, ["review and supply checksum-bound evidence"]
        ),
        "evidence": [
            str(value) for value in claim.get("evidence", []) if isinstance(value, str)
        ]
        if isinstance(claim.get("evidence"), list)
        else [],
    }


def _evidence_quality(finding: dict[str, Any]) -> dict[str, Any]:
    sources = finding.get("sources")
    locations = finding.get("locations")
    citations = finding.get("citations")
    classifications = finding.get("classifications")
    evidence = finding.get("evidence")
    source = sources[0] if isinstance(sources, list) and sources else {}
    location = locations[0] if isinstance(locations, list) and locations else {}
    checks = {
        "tool": isinstance(source, dict) and bool(source.get("tool")),
        "rule": isinstance(source, dict) and bool(source.get("rule_id")),
        "classification": isinstance(classifications, list) and bool(classifications),
        "citation": isinstance(citations, list) and bool(citations),
        "location": isinstance(location, dict) and bool(location.get("path")),
        "line_or_artifact_identity": (
            isinstance(location, dict) and location.get("start_line") is not None
        )
        or (isinstance(evidence, dict) and bool(evidence.get("artifact_sha256"))),
        "owner": isinstance(evidence, dict)
        and isinstance(evidence.get("owners"), list)
        and bool(evidence["owners"]),
        "remediation": bool(finding.get("remediation")),
        "confidence": str(finding.get("confidence") or "unknown") != "unknown",
        "impact": bool(finding.get("impact")),
    }
    missing = [name for name, passed in checks.items() if not passed]
    return {
        "finding_id": str(finding.get("finding_id") or "unknown"),
        "score": sum(checks.values()),
        "maximum": len(checks),
        "percent": round(sum(checks.values()) / len(checks) * 100, 2),
        "missing": missing,
        "action": (
            "Evidence is complete."
            if not missing
            else "Add missing evidence fields: " + ", ".join(missing) + "."
        ),
    }


def _detection_perspectives(findings: list[dict[str, Any]]) -> dict[str, Any]:
    records: list[dict[str, Any]] = []
    yield_by_tool: Counter[str] = Counter()
    for finding in findings:
        sources = finding.get("sources")
        tools = (
            sorted(
                {
                    str(source.get("tool"))
                    for source in sources
                    if isinstance(source, dict) and source.get("tool")
                }
            )
            if isinstance(sources, list)
            else []
        )
        yield_by_tool.update(tools)
        records.append(
            {
                "finding_id": str(finding.get("finding_id") or "unknown"),
                "tools": tools,
                "perspective_count": len(tools),
                "corroboration": "multi-tool"
                if len(tools) > 1
                else "single-tool"
                if tools
                else "unattributed",
                "review": "Review unique scanner yield for false positives or blind spots."
                if len(tools) <= 1
                else "Independent tools corroborated this normalized finding.",
            }
        )
    return {
        "tool_yield": dict(sorted(yield_by_tool.items())),
        "single_tool_findings": sum(
            value["perspective_count"] == 1 for value in records
        ),
        "multi_tool_findings": sum(value["perspective_count"] > 1 for value in records),
        "unattributed_findings": sum(
            value["perspective_count"] == 0 for value in records
        ),
        "findings": records,
    }


def _scanner_reliability(tools: list[dict[str, Any]]) -> dict[str, Any]:
    applicable = [tool for tool in tools if tool.get("applicable") is not False]
    statuses = Counter(str(tool.get("status") or "unknown") for tool in tools)
    gaps = [
        str(tool.get("tool") or "unknown")
        for tool in applicable
        if tool.get("status") != "completed"
    ]
    unknown_versions = [
        str(tool.get("tool") or "unknown")
        for tool in applicable
        if str(tool.get("version") or "unknown").casefold() == "unknown"
    ]
    changed = [
        str(tool.get("tool") or "unknown")
        for tool in applicable
        if tool.get("executable_unchanged") is False
        or tool.get("auxiliary_executable_unchanged") is False
    ]
    slowest_values = sorted(
        (
            (
                float(tool.get("duration_seconds") or 0.0),
                str(tool.get("tool") or "unknown"),
            )
            for tool in applicable
        ),
        key=lambda item: (-item[0], item[1]),
    )[:10]
    slowest = [
        {"tool": tool, "duration_seconds": duration}
        for duration, tool in slowest_values
    ]
    return {
        "scope": "Single-scan execution health; longitudinal reliability requires retained trend evidence.",
        "selected": len(tools),
        "applicable": len(applicable),
        "statuses": dict(sorted(statuses.items())),
        "execution_gaps": len(gaps),
        "gap_tools": gaps,
        "unknown_version_tools": unknown_versions,
        "changed_entrypoint_tools": changed,
        "slowest": slowest,
    }


def _conditional_domains(portfolio: dict[str, Any]) -> list[dict[str, str]]:
    domains = portfolio.get("domains")
    if not isinstance(domains, list):
        return []
    return [
        {
            "domain": str(domain.get("domain") or "unknown"),
            "purpose": str(domain.get("purpose") or ""),
            "status": str(domain.get("status") or "unknown"),
            "activation": _activation(str(domain.get("domain") or "")),
        }
        for domain in domains
        if isinstance(domain, dict) and domain.get("status") == "conditional_only"
    ]


def _activation(domain: str) -> str:
    return {
        "delivery-governance": (
            "Add real workflow, policy, license, or repository-governance inputs and "
            "run the production or release profile."
        ),
        "dynamic-threat-modeling": (
            "Supply reviewed, digest-bound DAST and threat-model evidence produced "
            "inside a disposable isolated companion lane."
        ),
    }.get(
        domain, "Supply the domain-specific input declared by the compatibility matrix."
    )


def _baseline_summary(delta: dict[str, Any]) -> dict[str, Any]:
    comparison = delta.get("comparison")
    if isinstance(comparison, dict):
        return comparison
    return {
        "comparable": False,
        "reasons": [
            "legacy or absent baseline lacks profile, scanner-set, and ancestry metadata"
        ],
        "source": {"ancestry_verified": False},
    }


def _derived_blockers(
    manifest: dict[str, Any],
    blocking: list[dict[str, Any]],
    claims: list[dict[str, Any]],
) -> list[str]:
    blockers: list[str] = []
    if manifest.get("outcome") != "pass":
        blockers.append("scan-policy")
    if blocking:
        blockers.append("blocking-findings")
    if any(claim["result"] != "satisfied" for claim in claims):
        blockers.append("assurance-claims")
    return blockers


def _lifecycle(
    manifest: dict[str, Any],
    *,
    blocking: list[dict[str, Any]],
    blockers: list[str],
    release_decision: str,
) -> list[dict[str, str]]:
    unsigned = any(
        "COSIGN-BUNDLE-MISSING" in finding.get("classifications", [])
        for finding in blocking
        if isinstance(finding.get("classifications"), list)
    )
    scan_passed = manifest.get("outcome") == "pass"
    states = (
        ("built", "complete", "release distributions were inventoried"),
        ("scanned", "complete", "sealed report integrity verified"),
        (
            "reviewed",
            "complete" if not blockers else "blocked",
            "all release controls reviewed"
            if not blockers
            else "release blockers remain",
        ),
        (
            "signed",
            "blocked" if unsigned else "not_evaluated",
            "Sigstore bundles are missing" if unsigned else "verify signer policy",
        ),
        (
            "verified",
            "blocked" if unsigned or not scan_passed else "not_evaluated",
            "requires valid signatures and a passing scan",
        ),
        (
            "approved",
            "complete" if release_decision == "approved" else "blocked",
            "organization release decision is required",
        ),
        ("published", "not_evaluated", "publication is external to this suite"),
    )
    return [
        {"stage": stage, "status": status, "detail": detail}
        for stage, status, detail in states
    ]


def _artifact_graph(
    manifest: dict[str, Any], findings: list[dict[str, Any]]
) -> dict[str, Any]:
    inventory = manifest.get("inventory")
    source_sha256 = (
        str(inventory.get("source_sha256") or "") if isinstance(inventory, dict) else ""
    )
    nodes: list[dict[str, str]] = [
        {"id": "source", "kind": "source", "identity": source_sha256},
        {
            "id": "report",
            "kind": "report",
            "identity": str(manifest.get("scan_id") or ""),
        },
        {"id": "sbom", "kind": "sbom", "identity": "sbom.cdx.json"},
        {
            "id": "passport",
            "kind": "passport",
            "identity": "security-passport.json",
        },
    ]
    edges = [
        {"from": "source", "to": "report", "relation": "scanned-as"},
        {"from": "source", "to": "sbom", "relation": "described-by"},
        {"from": "report", "to": "passport", "relation": "attested-by"},
    ]
    artifacts: dict[str, str] = {}
    for finding in findings:
        evidence = finding.get("evidence")
        if not isinstance(evidence, dict):
            continue
        path = evidence.get("artifact_path")
        digest = evidence.get("artifact_sha256")
        if isinstance(path, str) and path and isinstance(digest, str) and digest:
            artifacts[path] = digest
    for index, (path, digest) in enumerate(sorted(artifacts.items()), start=1):
        identifier = f"artifact-{index}"
        nodes.append(
            {
                "id": identifier,
                "kind": "release-artifact",
                "name": path,
                "identity": digest,
            }
        )
        edges.extend(
            [
                {"from": "source", "to": identifier, "relation": "built-into"},
                {"from": identifier, "to": "passport", "relation": "subject-of"},
            ]
        )
    return {"nodes": nodes, "edges": edges}


def _audience_views(
    *,
    blockers: list[str],
    blocking: list[dict[str, Any]],
    claim_closure: list[dict[str, Any]],
    conditional: list[dict[str, str]],
) -> dict[str, Any]:
    return {
        "executive": {
            "decision": "blocked" if blockers else "ready",
            "material_risks": len(blocking),
            "message": (
                "Release is blocked pending controlled assurance work."
                if blockers
                else "No promotion blocker was derived from the supplied evidence."
            ),
        },
        "developer": {
            "blocking_finding_ids": [
                str(finding.get("finding_id") or "unknown") for finding in blocking
            ]
        },
        "security": {
            "failed_controls": [
                claim["control"]
                for claim in claim_closure
                if claim["result"] != "satisfied"
            ],
            "conditional_domains": [item["domain"] for item in conditional],
        },
        "release_engineering": {"blockers": blockers},
        "auditor": {
            "required_chain": [
                "source digest",
                "sealed report",
                "payload manifest",
                "provenance and signatures",
                "approved Passport",
            ]
        },
    }


def _retention_plan() -> list[dict[str, str]]:
    return [
        {
            "class": "release-record",
            "content": "report seal, payload manifest, provenance, signatures, Passport",
            "guidance": "retain immutably for the supported life of the release plus organization audit requirements",
        },
        {
            "class": "security-evidence",
            "content": "normalized findings, SBOMs, approvals, effectiveness evaluation",
            "guidance": "encrypt, restrict access, and retain for investigation and trend policy",
        },
        {
            "class": "ephemeral-sensitive",
            "content": "raw scanner output, temporary workspaces, credentials",
            "guidance": "minimize collection and securely dispose after bounded troubleshooting retention",
        },
    ]


def _next_actions(
    *,
    readiness: dict[str, Any],
    blockers: list[str],
    conditional: list[dict[str, str]],
    baseline: dict[str, Any],
) -> list[dict[str, Any]]:
    remediation = readiness.get("remediation")
    actions = (
        [value for value in remediation if isinstance(value, dict)]
        if isinstance(remediation, list)
        else [
            {
                "id": f"control:{blocker}",
                "priority": "P1",
                "action": "Resolve the failed control and regenerate sealed evidence.",
            }
            for blocker in blockers
        ]
    )
    if baseline.get("comparable") is not True:
        actions.append(
            {
                "id": "evidence:comparable-baseline",
                "priority": "P1",
                "action": "Use an approved baseline with the same profile and scanner set; verify source ancestry externally.",
            }
        )
    actions.extend(
        {
            "id": f"coverage:{item['domain']}",
            "priority": "P2",
            "action": item["activation"],
        }
        for item in conditional
    )
    return sorted(
        actions, key=lambda item: (str(item.get("priority")), str(item.get("id")))
    )


def _with_service_levels(
    actions: list[dict[str, Any]], manifest: dict[str, Any]
) -> list[dict[str, Any]]:
    observed = _timestamp(
        str(manifest.get("finished_at") or manifest.get("started_at") or "")
    )
    days = {"P0": 1, "P1": 7, "P2": 30}
    result: list[dict[str, Any]] = []
    for action in actions:
        value = dict(action)
        priority = str(value.get("priority") or "P2")
        target_days = days.get(priority, 30)
        value.setdefault("owner", str(value.get("authority") or "repository-owner"))
        value["service_level"] = {
            "target_days": target_days,
            "due_at": (observed + timedelta(days=target_days))
            .isoformat()
            .replace("+00:00", "Z")
            if observed
            else None,
            "status": "open",
        }
        result.append(value)
    return result


def _blocker_graph(
    readiness: dict[str, Any], blockers: list[str]
) -> list[dict[str, str]]:
    raw = readiness.get("blocker_graph")
    if isinstance(raw, list):
        values = [
            {
                "blocker": str(value.get("blocker")),
                "derived_from": str(value.get("derived_from")),
            }
            for value in raw
            if isinstance(value, dict)
            and value.get("blocker")
            and value.get("derived_from")
        ]
        if values:
            return values
    return [
        {"blocker": "scan-policy", "derived_from": blocker}
        for blocker in blockers
        if blocker != "scan-policy"
    ]


def _evidence_freshness(root: Path, manifest: dict[str, Any]) -> list[dict[str, Any]]:
    observed = _timestamp(
        str(manifest.get("finished_at") or manifest.get("started_at") or "")
    )
    records: list[dict[str, Any]] = []
    for kind, filename in (
        ("external-isolation", "isolation-attestation.json"),
        ("intelligence-approval", "intelligence-approval.json"),
    ):
        document = _read_optional_object(root / filename)
        configured = document.get("configured") is True
        approved = document.get("organization_approved") is True
        valid_until = str(document.get("valid_until") or "")
        expiry = _timestamp(valid_until)
        status = (
            "missing"
            if not configured
            else "unapproved"
            if not approved
            else "expired"
            if observed and expiry and expiry < observed
            else "current"
        )
        records.append(
            {
                "kind": kind,
                "status": status,
                "configured": configured,
                "organization_approved": approved,
                "valid_until": valid_until or None,
                "evidence": filename,
            }
        )
    trust = _read_optional_object(root / "scanner-trust.json")
    applied = trust.get("applied")
    applied_values = (
        [value for value in applied if isinstance(value, dict)]
        if isinstance(applied, list)
        else []
    )
    expiries = [
        str(value.get("expires")) for value in applied_values if value.get("expires")
    ]
    expired = bool(
        observed and any(_date_expired(value, observed) for value in expiries)
    )
    trust_configured = trust.get("configured") is True
    records.append(
        {
            "kind": "scanner-trust",
            "status": "missing"
            if not trust_configured
            else "expired"
            if expired
            else "current"
            if applied_values
            else "unapproved",
            "configured": trust_configured,
            "organization_approved": trust_configured
            and bool(applied_values)
            and not expired,
            "valid_until": min(expiries) if expiries else None,
            "evidence": "scanner-trust.json",
        }
    )
    return records


def _configuration_provenance(
    manifest: dict[str, Any], tools: list[dict[str, Any]]
) -> dict[str, Any]:
    selected = sorted(str(tool.get("tool") or "unknown") for tool in tools)
    approved_primary = sum(
        tool.get("executable_organization_approved") is True for tool in tools
    )
    auxiliary = [tool for tool in tools if tool.get("auxiliary_executable_sha256")]
    approved_auxiliary = sum(
        tool.get("auxiliary_executable_organization_approved") is True
        for tool in auxiliary
    )
    return {
        "configuration_sha256": str(manifest.get("configuration_sha256") or ""),
        "profile": str(manifest.get("profile") or ""),
        "selected_tools": selected,
        "selected_tool_count": len(selected),
        "organization_approved_primary_entrypoints": approved_primary,
        "organization_approved_auxiliary_entrypoints": approved_auxiliary,
        "auxiliary_entrypoint_count": len(auxiliary),
        "interpretation": "The digest identifies the effective merged configuration; organization-controlled approvals remain explicit per scanner entry point.",
    }


def _github_annotations(
    blockers: list[str], blocking: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    values: list[dict[str, Any]] = []
    for finding in blocking:
        locations = finding.get("locations")
        location = (
            locations[0]
            if isinstance(locations, list)
            and locations
            and isinstance(locations[0], dict)
            else {}
        )
        values.append(
            {
                "level": "error",
                "title": str(
                    finding.get("title")
                    or finding.get("finding_id")
                    or "Blocking security finding"
                ),
                "message": str(
                    finding.get("summary")
                    or finding.get("description")
                    or "Resolve the cited blocking finding."
                ),
                "file": str(location.get("path") or "findings.json"),
                "line": int(location.get("start_line") or 1),
                "finding_id": str(finding.get("finding_id") or "unknown"),
            }
        )
    if not values:
        values.extend(
            {
                "level": "error",
                "title": f"Release blocker: {blocker}",
                "message": "Resolve the blocker and regenerate sealed evidence.",
                "file": "scan-manifest.json",
                "line": 1,
                "finding_id": "",
            }
            for blocker in blockers
        )
    return values


def _timestamp(value: str) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _date_expired(value: str, observed: datetime) -> bool:
    try:
        expiry = datetime.fromisoformat(value).replace(tzinfo=timezone.utc) + timedelta(
            days=1
        )
    except ValueError:
        return True
    return expiry <= observed


def _average_quality(values: list[dict[str, Any]]) -> float | None:
    if not values:
        return None
    return round(sum(float(value["percent"]) for value in values) / len(values), 2)


def _paired(path: Path | None, digest: str, label: str) -> None:
    if bool(path) != bool(digest):
        raise ValueError(f"{label} path and SHA-256 must be supplied together")


def _digest_bound_object(path: Path, expected: str, label: str) -> dict[str, Any]:
    source = resolve_regular_file(path, label)
    if sha256_file(source) != expected.strip().casefold():
        raise ValueError(f"{label} does not match the approved SHA-256")
    return _read_object(source)


def _read_object(path: Path) -> dict[str, Any]:
    source = resolve_regular_file(path, "promotion evidence")
    if source.stat().st_size > _MAX_JSON_BYTES:
        raise ValueError("promotion evidence exceeds the size limit")
    value = json.loads(source.read_bytes())
    if not isinstance(value, dict):
        raise TypeError("promotion evidence root must be an object")
    return value


def _read_optional_object(path: Path) -> dict[str, Any]:
    return _read_object(path) if path.is_file() else {}


def _object_list(value: object, label: str) -> list[dict[str, Any]]:
    if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
        raise TypeError(f"{label} must be an array of objects")
    return value
