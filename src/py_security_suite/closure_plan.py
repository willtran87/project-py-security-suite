from __future__ import annotations

import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any

from .execution import sanitize_terminal_text
from .models import Finding, ScanManifest, json_ready
from .ownership import owners_for_path, ownership_rules_from_artifact
from .passport import verify_report
from .path_safety import resolve_regular_file


_MAX_JSON_BYTES = 128 * 1024 * 1024
_SCHEMA_ID = "urn:project-py-security-suite:schema:closure-plan:1.2"
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
        structural=_optional_object(root / "structural-synthesis.json"),
        finding_delta=_optional_object(root / "finding-delta.json"),
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
        structural=_as_object(artifacts.get("structural-synthesis.json")),
        finding_delta=_as_object(artifacts.get("finding-delta.json")),
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
    items = _object_list(plan.get("items"), "closure plan items")
    lines = [
        "# Findings closure plan",
        "",
        f"- **Scan:** `{_md(plan.get('scan_id'))}`",
        f"- **Outcome:** `{_md(plan.get('outcome'))}`",
        f"- **Open work:** {int(summary.get('open_items') or 0)} item(s)",
        f"- **Distinct advisory work:** {int(summary.get('advisory_items') or 0)} item(s) from {int(summary.get('advisory_observations') or 0)} retained scanner observation(s)",
        f"- **Changed-file validation work:** {int(summary.get('validation_alignment_items') or 0)} item(s); {int(summary.get('codeowner_backed_validation_items') or 0)} assigned by repository ownership rules",
        authority_line,
        "",
        authority_notice,
        "",
    ]
    lines.extend(_render_validation_queues(items))
    lines.extend(
        [
            "## Prioritized work",
            "",
            "| Priority | Category | Authority | Status | Owner | Work item | Acceptance evidence |",
            "|---|---|---|---|---|---|---|",
        ]
    )
    for item in items:
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
                    _md(item.get("category")),
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
    command_items = [item for item in items if item.get("commands")]
    if not command_items:
        lines.append("No command handoff is required for the current plan.")
    for item in command_items:
        lines.extend((f"### {_md(item.get('id'))} · {_md(item.get('title'))}", ""))
        for command in item["commands"]:
            rendered = " ".join(_shell_display(value) for value in command)
            lines.extend(("```text", rendered, "```", ""))
    return "\n".join(lines).rstrip() + "\n"


def _render_validation_queues(items: list[dict[str, Any]]) -> list[str]:
    validation = [
        item
        for item in items
        if _as_object(item.get("details")).get("validation_alignment")
    ]
    if not validation:
        return []
    counts = Counter(
        (
            str(item.get("owner") or "Unassigned"),
            str(_as_object(item.get("details")).get("validation_alignment")),
            str(item.get("priority") or "P3"),
        )
        for item in validation
    )
    actions: dict[tuple[str, str], str] = {}
    for item in validation:
        key = (
            str(item.get("owner") or "Unassigned"),
            str(_as_object(item.get("details")).get("validation_alignment")),
        )
        actions.setdefault(key, str(item.get("action") or "Review the work items."))
    lines = [
        "## Validation work queues",
        "",
        "File-level evidence remains in the prioritized ledger below; this rollup shows shared owner and evidence conditions.",
        "",
        "| Owner | Evidence condition | P1 | P2 | P3/P4 | Subjects | Shared next action |",
        "|---|---|---:|---:|---:|---:|---|",
    ]
    for owner, alignment in sorted(actions):
        p1 = counts[(owner, alignment, "P1")]
        p2 = counts[(owner, alignment, "P2")]
        lower = counts[(owner, alignment, "P3")] + counts[(owner, alignment, "P4")]
        lines.append(
            f"| `{_md(owner)}` | `{_md(alignment)}` | {p1} | {p2} | {lower} | "
            f"{p1 + p2 + lower} | {_md(actions[(owner, alignment)])} |"
        )
    return [*lines, ""]


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
    structural: dict[str, Any],
    finding_delta: dict[str, Any],
    coverage_target: float,
    hotspot_limit: int,
) -> dict[str, Any]:
    items: list[dict[str, Any]] = []
    items.extend(_finding_items(findings))
    items.extend(_governance_items(manifest, admission))
    items.extend(_activation_items(portfolio))
    items.extend(
        _test_assurance_items(
            structural,
            finding_delta,
            coverage,
            coverage_target,
            hotspot_limit,
        )
    )
    items.extend(_reachability_items(reachability))
    items = _consolidate_test_assurance(items)
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
    advisory_items = [
        item
        for item in items
        if _as_object(item.get("details")).get("advisory_cluster_id")
    ]
    validation_items = [
        item
        for item in items
        if _as_object(item.get("details")).get("validation_alignment")
    ]
    return {
        "schema_version": "1.2",
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
            "advisory_items": len(advisory_items),
            "advisory_observations": sum(
                len(item.get("related_findings", [])) for item in advisory_items
            ),
            "alias_observations_consolidated": sum(
                max(0, len(item.get("related_findings", [])) - 1)
                for item in advisory_items
            ),
            "validation_alignment_items": len(validation_items),
            "codeowner_backed_validation_items": sum(
                bool(_as_object(item.get("details")).get("ownership_rule_matched"))
                for item in validation_items
            ),
            "validation_items_with_failing_tests": sum(
                _as_object(item.get("details")).get("validation_alignment")
                == "tests-failing"
                for item in validation_items
            ),
            "validation_items_with_coverage_gaps": sum(
                _as_object(item.get("details")).get("validation_alignment")
                == "coverage-gap"
                for item in validation_items
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
        risk_refs, risk_acceptance, risk_details = _risk_path_closure_context(evidence)
        advisory = _as_object(
            _as_object(evidence.get("fusion")).get("advisory_context")
        )
        remediation = _as_object(advisory.get("remediation_context"))
        cluster_id = str(advisory.get("cluster_id") or "")
        if cluster_id and remediation:
            usage = _as_object(advisory.get("dependency_usage"))
            advisory_owners = remediation.get("owners")
            finding_owners = evidence.get("owners")
            owner = (
                str(advisory_owners[0])
                if isinstance(advisory_owners, list) and advisory_owners
                else str(finding_owners[0])
                if isinstance(finding_owners, list) and finding_owners
                else "repository-maintainers"
            )
            verification_steps = remediation.get("verification_steps")
            acceptance = (
                [str(item) for item in verification_steps[:6]]
                if isinstance(verification_steps, list)
                else []
            )
            acceptance.extend(
                [
                    f"Advisory cluster {cluster_id} is absent or explicitly governed in a newly sealed report.",
                    "The replacement report independently passes pysec verify-report.",
                    *risk_acceptance,
                ]
            )
            evidence_basis = remediation.get("evidence_basis")
            import_paths = _string_values(usage.get("import_paths"), 50)
            test_files = _string_values(remediation.get("recommended_test_files"), 50)
            test_execution_sources = _string_values(
                usage.get("test_execution_sources"), 10
            )
            dependency_evidence_refs = [
                item
                for item in _string_values(usage.get("evidence_artifacts"), 20)
                if item in {"sbom.cdx.json", "pipdeptree-summary.json"}
            ]
            cluster_findings = _string_values(advisory.get("finding_ids"), 100)
            raw_priority = str(remediation.get("priority") or "")
            priority = (
                raw_priority
                if raw_priority in _PRIORITY_ORDER
                else _SEVERITY_PRIORITY.get(
                    str(finding.get("severity") or "unknown"), "P3"
                )
            )
            items.append(
                _item(
                    key=f"advisory:{cluster_id}",
                    priority=priority,
                    category="finding",
                    authority="repository",
                    status="open",
                    owner=owner,
                    title=(
                        f"Remediate {advisory.get('primary_identifier') or cluster_id} "
                        f"in {advisory.get('package') or 'the affected package'}"
                    ),
                    why=(
                        "; ".join(str(item) for item in evidence_basis[:20])
                        if isinstance(evidence_basis, list) and evidence_basis
                        else str(
                            finding.get("impact") or finding.get("description") or ""
                        )
                    ),
                    action=str(
                        remediation.get("recommended_action")
                        or finding.get("remediation")
                        or "Review and resolve the advisory."
                    ),
                    acceptance=acceptance,
                    evidence_refs=[
                        "evidence-fusion.json",
                        "findings.json",
                        *import_paths,
                        *test_files,
                        *test_execution_sources,
                        *dependency_evidence_refs,
                        *risk_refs,
                    ],
                    related_findings=cluster_findings or [finding_id],
                    tools=_string_values(advisory.get("tools"), 25),
                    details={
                        "advisory_cluster_id": cluster_id,
                        "primary_identifier": advisory.get("primary_identifier"),
                        "identifiers": advisory.get("identifiers", []),
                        "package": advisory.get("package"),
                        "affected_versions": advisory.get("versions", []),
                        "action_kind": remediation.get("action_kind"),
                        "fixed_version_candidates": remediation.get(
                            "fixed_version_candidates", []
                        ),
                        "dependency_use_assessment": usage.get("assessment"),
                        "import_paths": import_paths,
                        "recommended_test_files": test_files,
                        "test_selection_confidence": remediation.get(
                            "test_selection_confidence"
                        ),
                        "focused_test_validation_status": remediation.get(
                            "focused_test_validation_status"
                        ),
                        "focused_test_execution": usage.get(
                            "focused_test_execution", []
                        ),
                        "introducing_packages": remediation.get(
                            "introducing_packages", []
                        ),
                        "dependency_paths": remediation.get("dependency_paths", []),
                        "dependency_path_confidence": remediation.get(
                            "dependency_path_confidence"
                        ),
                        "dependency_environment_health": usage.get(
                            "dependency_environment_health", {}
                        ),
                        "dependency_environment_warning": usage.get(
                            "dependency_environment_warning", False
                        ),
                        "owners": remediation.get("owners", []),
                        "uncertainties": remediation.get("uncertainties", []),
                        "risk_path": risk_details,
                    },
                )
            )
            continue
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
                    *risk_acceptance,
                ],
                evidence_refs=[
                    "findings.json",
                    "action-plan.md",
                    *location_paths,
                    *risk_refs,
                ],
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
                details={"risk_path": risk_details} if risk_details else {},
            )
        )
    return items


def _risk_path_closure_context(
    evidence: dict[str, Any],
) -> tuple[list[str], list[str], dict[str, Any]]:
    risk_path = _as_object(evidence.get("risk_path"))
    if not risk_path:
        return [], [], {}
    status = str(risk_path.get("status") or "unknown")
    refs = ["risk-paths.json"]
    details: dict[str, Any] = {"status": status}
    if status == "routed":
        route_id = str(risk_path.get("route_id") or "unknown")
        files = _string_values(risk_path.get("files"), 9)
        refs.extend(files)
        validation = _as_object(risk_path.get("validation"))
        assessment = str(validation.get("assessment_status") or "not-assessed")
        campaign_ids = _string_values(risk_path.get("validation_campaign_ids"), 50)
        raw_campaigns = risk_path.get("validation_campaigns")
        campaigns: list[dict[str, Any]] = (
            [
                {
                    "campaign_id": str(campaign.get("campaign_id") or "unknown"),
                    "hotspot_id": str(campaign.get("hotspot_id") or "unknown"),
                    "path": str(campaign.get("path") or "unknown"),
                    "selected_test_files": _string_values(
                        campaign.get("selected_test_files"), 50
                    ),
                    "shared_test_hotspot_ids": _string_values(
                        campaign.get("shared_test_hotspot_ids"), 100
                    ),
                    "focused_test_validation_status": campaign.get(
                        "focused_test_validation_status"
                    ),
                    "coverage_status": campaign.get("coverage_status"),
                    "coverage_evidence_scope": campaign.get("coverage_evidence_scope"),
                    "coverage_attribution": campaign.get("coverage_attribution"),
                    "coverage_percent": campaign.get("coverage_percent"),
                    "test_coverage_alignment": campaign.get("test_coverage_alignment"),
                    "review_score_model": campaign.get("review_score_model"),
                    "review_score": campaign.get("review_score"),
                    "review_tier": campaign.get("review_tier"),
                    "review_factors": [
                        _as_object(factor)
                        for factor in _object_list(
                            campaign.get("review_factors"),
                            "campaign review factors",
                        )[:20]
                    ],
                    "control_point_context": _as_object(
                        campaign.get("control_point_context")
                    ),
                    "source_snapshot": {
                        "source_sha256": _as_object(
                            campaign.get("source_snapshot")
                        ).get("source_sha256"),
                        "control_point_binding": _as_object(
                            _as_object(campaign.get("source_snapshot")).get(
                                "control_point_binding"
                            )
                        ),
                        "selected_test_files_bound": _as_object(
                            campaign.get("source_snapshot")
                        ).get("selected_test_files_bound"),
                        "selected_test_files_missing": _string_values(
                            _as_object(campaign.get("source_snapshot")).get(
                                "selected_test_files_missing"
                            ),
                            50,
                        ),
                        "evidence_revision_binding": _as_object(
                            campaign.get("source_snapshot")
                        ).get("evidence_revision_binding"),
                        "evidence_revision_binding_reason": _as_object(
                            campaign.get("source_snapshot")
                        ).get("evidence_revision_binding_reason"),
                    },
                    "recommended_action": campaign.get("recommended_action"),
                }
                for campaign in raw_campaigns[:50]
                if isinstance(campaign, dict)
            ]
            if isinstance(raw_campaigns, list)
            else []
        )
        refs.extend(
            test for campaign in campaigns for test in campaign["selected_test_files"]
        )
        raw_dependency_routes = risk_path.get("dependency_advisory_routes")
        dependency_routes = (
            [
                {
                    "route_id": str(item.get("route_id") or "unknown"),
                    "target_id": str(item.get("target_id") or "unknown"),
                    "priority": str(item.get("priority") or "P4"),
                    "advisory_cluster_id": str(
                        item.get("advisory_cluster_id") or "unknown"
                    ),
                    "primary_identifier": str(
                        item.get("primary_identifier") or "unknown"
                    ),
                    "package": str(item.get("package") or "unknown"),
                    "versions": _string_values(item.get("versions"), 25),
                    "import_path": str(item.get("import_path") or "unknown"),
                    "import_modules": _string_values(item.get("import_modules"), 50),
                    "import_lines": [
                        line
                        for line in item.get("import_lines", [])[:100]
                        if isinstance(line, int)
                        and not isinstance(line, bool)
                        and line > 0
                    ]
                    if isinstance(item.get("import_lines"), list)
                    else [],
                    "dependency_usage_assessment": item.get(
                        "dependency_usage_assessment"
                    ),
                    "import_path_assessment": _as_object(
                        item.get("import_path_assessment")
                    ),
                    "entry_point": _as_object(item.get("entry_point")),
                    "hop_count": item.get("hop_count"),
                    "files": _string_values(item.get("files"), 9),
                    "runtime_context": _as_object(item.get("runtime_context")),
                    "validation": _as_object(item.get("validation")),
                    "validation_campaign_ids": _string_values(
                        item.get("validation_campaign_ids"), 50
                    ),
                    "exposure_advisory_intersection_ids": _string_values(
                        item.get("exposure_advisory_intersection_ids"), 100
                    ),
                    "known_exploited": item.get("known_exploited") is True,
                    "epss_probability": item.get("epss_probability"),
                    "fix_available": item.get("fix_available") is True,
                    "fixed_version_candidates": _string_values(
                        item.get("fixed_version_candidates"), 25
                    ),
                    "package_lifecycle": _as_object(item.get("package_lifecycle")),
                    "change_risk_score": item.get("change_risk_score"),
                    "change_priority": item.get("change_priority"),
                    "uncovered_changed_lines": [
                        line
                        for line in item.get("uncovered_changed_lines", [])[:100]
                        if isinstance(line, int)
                        and not isinstance(line, bool)
                        and line > 0
                    ]
                    if isinstance(item.get("uncovered_changed_lines"), list)
                    else [],
                    "advisory_citations": [
                        _as_object(citation)
                        for citation in _object_list(
                            item.get("advisory_citations"),
                            "dependency advisory citations",
                        )[:25]
                    ],
                    "recommended_action": str(
                        item.get("recommended_action") or "Review dependency use."
                    ),
                }
                for item in raw_dependency_routes[:25]
                if isinstance(item, dict)
            ]
            if isinstance(raw_dependency_routes, list)
            else []
        )
        if dependency_routes:
            refs.append("evidence-fusion.json")
            refs.extend(str(item["import_path"]) for item in dependency_routes)
        raw_intersections = risk_path.get("exposure_advisory_intersections")
        exposure_advisory_intersections = (
            [
                {
                    "intersection_id": str(item.get("intersection_id") or "unknown"),
                    "priority": str(item.get("priority") or "P4"),
                    "path": str(item.get("path") or "unknown"),
                    "line": item.get("line"),
                    "sink_route_id": str(item.get("sink_route_id") or "unknown"),
                    "dependency_route_id": str(
                        item.get("dependency_route_id") or "unknown"
                    ),
                    "advisory_cluster_id": str(
                        item.get("advisory_cluster_id") or "unknown"
                    ),
                    "primary_identifier": str(
                        item.get("primary_identifier") or "unknown"
                    ),
                    "package": str(item.get("package") or "unknown"),
                    "sdk": item.get("sdk"),
                    "sink_family": str(item.get("sink_family") or "unknown"),
                    "trust_boundary": str(item.get("trust_boundary") or "unknown"),
                    "data_classes": _string_values(item.get("data_classes"), 25),
                    "protection_status": str(
                        item.get("protection_status") or "unknown"
                    ),
                    "known_exploited": item.get("known_exploited") is True,
                    "epss_high": item.get("epss_high") is True,
                    "fix_available": item.get("fix_available") is True,
                    "package_lifecycle": _as_object(item.get("package_lifecycle")),
                    "validation_statuses": _as_object(item.get("validation_statuses")),
                    "advisory_citations": [
                        _as_object(citation)
                        for citation in _object_list(
                            item.get("advisory_citations"),
                            "exposure advisory citations",
                        )[:25]
                    ],
                    "recommended_action": str(
                        item.get("recommended_action")
                        or "Review the exposure-advisory intersection."
                    ),
                }
                for item in raw_intersections[:25]
                if isinstance(item, dict)
            ]
            if isinstance(raw_intersections, list)
            else []
        )
        if exposure_advisory_intersections:
            refs.extend(["data-exposure.json", "evidence-fusion.json"])
            refs.extend(str(item["path"]) for item in exposure_advisory_intersections)
        if any(
            _as_object(campaign.get("source_snapshot")).get("source_sha256")
            for campaign in campaigns
        ):
            refs.append("source-inventory.json")
        details.update(
            {
                "route_id": route_id,
                "entry_point": _as_object(risk_path.get("entry_point")),
                "hop_count": risk_path.get("hop_count"),
                "files": files,
                "convergence_hotspot_ids": _string_values(
                    risk_path.get("convergence_hotspot_ids"), 50
                ),
                "validation_campaign_ids": campaign_ids,
                "validation_test_hotspot_ids": _string_values(
                    risk_path.get("validation_test_hotspot_ids"), 100
                ),
                "exposure_advisory_intersection_ids": _string_values(
                    risk_path.get("exposure_advisory_intersection_ids"), 100
                ),
                "exposure_advisory_intersections": exposure_advisory_intersections,
                "validation_campaigns": campaigns,
                "target_kind": risk_path.get("target_kind"),
                "target_id": risk_path.get("target_id"),
                "dependency_advisory_route_ids": _string_values(
                    risk_path.get("dependency_advisory_route_ids"), 25
                ),
                "dependency_advisory_import_paths": _string_values(
                    risk_path.get("dependency_advisory_import_paths"), 50
                ),
                "dependency_advisory_cluster_ids": _string_values(
                    risk_path.get("dependency_advisory_cluster_ids"), 50
                ),
                "dependency_advisory_routes": dependency_routes,
                "validation_assessment": assessment,
                "validation_action": validation.get("action"),
            }
        )
        acceptance = [
            f"Static route {route_id} is reviewed with its owner and retained in the replacement report."
        ]
        if assessment == "gap":
            acceptance.append(
                "The route validation assessment no longer reports a coverage or focused-test gap."
            )
        elif assessment in {"partial", "not-assessed"}:
            acceptance.append(
                "The route has retained change-scope, line-coverage, and focused-test evidence sufficient for an aligned or explicit-gap assessment."
            )
        campaign_gaps = [
            campaign
            for campaign in campaigns
            if campaign.get("test_coverage_alignment") != "aligned-current-evidence"
        ]
        if campaign_gaps:
            acceptance.append(
                "Every linked shared validation campaign has passing observed tests and retained hotspot coverage, or an approved evidence-gap disposition."
            )
        elif campaigns:
            acceptance.append(
                "Linked shared validation campaigns are rerun after remediation and retain their case-level and hotspot-coverage evidence."
            )
        revision_gaps = [
            campaign
            for campaign in campaigns
            if _as_object(campaign.get("source_snapshot")).get(
                "evidence_revision_binding"
            )
            in {"mismatch", "not-established"}
        ]
        if revision_gaps:
            acceptance.append(
                "Every linked campaign's retained test and coverage evidence declares the replacement report's sealed source-inventory digest."
            )
        if any(
            _as_object(campaign.get("control_point_context")).get(
                "uncovered_changed_lines"
            )
            for campaign in campaigns
        ):
            acceptance.append(
                "Every linked campaign covers its retained uncovered changed lines or records an approved risk disposition."
            )
        if any(
            any(
                factor.get("id") == "runtime-observation-gap"
                for factor in campaign.get("review_factors", [])
            )
            for campaign in campaigns
        ):
            acceptance.append(
                "Runtime evidence observes each linked changed control point, or the replacement report records an approved runtime-evidence gap."
            )
        if any(campaign["shared_test_hotspot_ids"] for campaign in campaigns):
            acceptance.append(
                "Shared validation-test hotspots have coordinated assertions and an independent-test or approved concentration-risk disposition."
            )
        if dependency_routes:
            acceptance.extend(
                [
                    "Every linked dependency-advisory importer is reviewed for vulnerable-function invocation from its declared entry-point route; static import reachability alone is not used as exploitability proof.",
                    "The affected dependency is upgraded, removed, mitigated, or covered by a governed VEX disposition, and focused importer tests are rerun with replacement evidence.",
                ]
            )
            if any(item["fix_available"] for item in dependency_routes):
                acceptance.append(
                    "A retained fixed-version candidate is applied or an explicit exception records why it is not applicable."
                )
            if any(item["uncovered_changed_lines"] for item in dependency_routes):
                acceptance.append(
                    "Focused importer validation covers every retained uncovered changed line, or the replacement report records an approved coverage disposition."
                )
            acceptance.extend(_package_lifecycle_acceptance(dependency_routes))
        if exposure_advisory_intersections:
            acceptance.extend(
                [
                    "Every exact-path sensitive-boundary/dependency intersection is reviewed for data minimization, redaction, recipient, retention, and access controls without treating path coincidence as proof of disclosure.",
                    "Vulnerable-function use is established or ruled out independently, the dependency remediation or governed VEX disposition is recorded, and both sink and importer validation are rerun.",
                ]
            )
            if any(
                item["protection_status"] == "not-observed"
                for item in exposure_advisory_intersections
            ):
                acceptance.append(
                    "A tested protection control is retained at every intersection that previously reported no observed minimization, masking, hashing, or redaction."
                )
        return refs, acceptance, details
    reason = str(risk_path.get("reason") or "bounded static route unavailable")
    details["reason"] = reason
    return (
        refs,
        [
            "The target has a governed entry-point route or a documented dynamic/external-entry rationale in the replacement report."
        ],
        details,
    )


def _package_lifecycle_acceptance(
    dependency_routes: list[dict[str, Any]],
) -> list[str]:
    assessments = {
        str(_as_object(item["package_lifecycle"]).get("assessment") or "")
        for item in dependency_routes
    }
    result: list[str] = []
    criteria = (
        (
            "version-drift" in assessments,
            "Source and built-artifact package versions agree in replacement composition inventories, or an approved drift disposition verifies remediation against the exact shipped component.",
        ),
        (
            "artifact-only" in assessments,
            "Every artifact-only package introduction is identified, removed, or governed with its build and packaging origin.",
        ),
        (
            "source-only" in assessments,
            "Complete replacement artifact inventory proves each source-only package is intentionally excluded; source-only status alone is not treated as safety evidence.",
        ),
        (
            bool(
                assessments
                & {
                    "source-inventory-unavailable",
                    "artifact-inventory-unavailable",
                    "composition-inventories-unavailable",
                    "package-not-observed",
                }
            ),
            "Complete source and built-artifact composition inventories establish the affected package lifecycle before disposition.",
        ),
        (
            any(
                _as_object(item["package_lifecycle"]).get(
                    "artifact_fixed_version_exact_match"
                )
                is False
                for item in dependency_routes
            ),
            "The replacement built-artifact inventory contains an approved remediated version, or an explicit exception explains the retained artifact version.",
        ),
    )
    result.extend(text for applies, text in criteria if applies)
    return result


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


def _test_assurance_items(
    structural: dict[str, Any],
    finding_delta: dict[str, Any],
    coverage: dict[str, Any],
    target: float,
    limit: int,
) -> list[dict[str, Any]]:
    """Join change impact, tests, coverage, and CODEOWNERS into closure work."""
    coverage_candidates = _coverage_candidates(coverage, target)
    coverage_by_path = {
        path: (percent, summary) for percent, path, summary in coverage_candidates
    }
    rules = ownership_rules_from_artifact(finding_delta)
    items: list[dict[str, Any]] = []
    handled_paths: set[str] = set()
    impacts = _object_list(
        structural.get("change_impact_assessments"),
        "structural change impact assessments",
    )
    for impact in impacts[:100]:
        path = str(impact.get("path") or "").replace("\\", "/")
        alignment = str(impact.get("test_coverage_alignment") or "")
        if not path or alignment in {"", "aligned-current-evidence", "not-selected"}:
            continue
        owners = owners_for_path(path, rules)
        owner = owners[0] if owners else "quality-engineering"
        coverage_hotspot = coverage_by_path.get(path)
        acceptance = _validation_acceptance(alignment, path)
        if coverage_hotspot is not None:
            acceptance.append(
                f"The module reaches at least {target:.2f}% combined coverage."
            )
        test_files = _string_values(
            [
                *(_string_values(impact.get("direct_test_files"), 25)),
                *(_string_values(impact.get("transitive_test_files"), 25)),
                *(_string_values(impact.get("associated_test_files"), 25)),
            ],
            50,
        )
        execution_sources = _string_values(impact.get("test_execution_sources"), 10)
        uncovered = _integer_values(impact.get("uncovered_changed_lines"), 100)
        why_parts = [
            _validation_why(alignment),
            f"{int(impact.get('changed_lines') or 0)} changed executable line(s) were analyzed",
        ]
        if uncovered:
            why_parts.append(f"{len(uncovered)} retained changed line(s) lack coverage")
        if coverage_hotspot is not None:
            why_parts.append(
                f"whole-file combined coverage is {coverage_hotspot[0]:.2f}% versus the {target:.2f}% target"
            )
        items.append(
            _item(
                key=f"test-assurance:{path}",
                priority=_validation_priority(
                    alignment, str(impact.get("priority") or "")
                ),
                category="test-assurance",
                authority="repository",
                status="open",
                owner=owner,
                title=_validation_title(alignment, path),
                why="; ".join(why_parts) + ".",
                action=str(
                    impact.get("validation_action")
                    or impact.get("recommended_action")
                    or "Regenerate focused-test and changed-line coverage evidence."
                ),
                acceptance=acceptance,
                evidence_refs=[
                    "structural-synthesis.json",
                    "diff-coverage.json",
                    "coverage-summary.json",
                    "finding-delta.json",
                    path,
                    *test_files,
                    *execution_sources,
                ],
                tools=_validation_tools(execution_sources),
                related_findings=_string_values(impact.get("finding_ids"), 25),
                details={
                    "path": path,
                    "validation_alignment": alignment,
                    "validation_gap_reasons": _string_values(
                        impact.get("validation_gap_reasons"), 20
                    ),
                    "ownership_rule_matched": bool(owners),
                    "owners": owners,
                    "change_priority": impact.get("priority"),
                    "change_risk_score": impact.get("risk_score"),
                    "changed_lines": int(impact.get("changed_lines") or 0),
                    "uncovered_changed_lines": uncovered,
                    "changed_line_coverage_percent": impact.get(
                        "changed_line_coverage_percent"
                    ),
                    "file_coverage_percent": (
                        coverage_hotspot[0]
                        if coverage_hotspot is not None
                        else impact.get("file_coverage_percent")
                    ),
                    "focused_test_validation_status": impact.get(
                        "focused_test_validation_status"
                    ),
                    "focused_test_execution": impact.get("focused_test_execution", []),
                    "recommended_test_files": test_files,
                    "test_selection_confidence": impact.get(
                        "test_selection_confidence"
                    ),
                },
            )
        )
        handled_paths.add(path)

    truncation = _as_object(structural.get("truncation"))
    omitted = int(truncation.get("change_impact_assessments_omitted") or 0)
    if omitted > 0:
        items.append(
            _item(
                key="test-assurance:omitted-change-impacts",
                priority="P1",
                category="test-assurance",
                authority="repository",
                status="open",
                owner="quality-engineering",
                title="Resolve omitted changed-file validation assessments",
                why=(
                    f"{omitted} changed-file assessment(s) exceeded the bounded "
                    "structural detail ledger; their validation alignment cannot be "
                    "established from this report."
                ),
                action=(
                    "Split the change into reviewable units or otherwise reduce the "
                    "changed-file set, then regenerate complete structural, focused-test, "
                    "and changed-line coverage evidence."
                ),
                acceptance=[
                    "No change impact assessments are omitted in the replacement report.",
                    "Every retained changed file reports aligned-current-evidence.",
                    "The replacement report independently passes pysec verify-report.",
                ],
                evidence_refs=[
                    "structural-synthesis.json#truncation.change_impact_assessments_omitted"
                ],
                tools=["coverage", "diff-cover", "graphify", "junit"],
                details={
                    "validation_alignment": "assessment-truncated",
                    "validation_gap_reasons": [
                        "changed-file validation detail was omitted by the bounded artifact"
                    ],
                    "ownership_rule_matched": False,
                    "owners": [],
                    "omitted_change_impact_assessments": omitted,
                },
            )
        )

    remaining = [
        candidate
        for candidate in coverage_candidates
        if candidate[1] not in handled_paths
    ]
    for percent, path, _summary in remaining[:limit]:
        owners = owners_for_path(path, rules)
        items.append(
            _item(
                key=f"test-assurance:{path}",
                priority="P2",
                category="test-assurance",
                authority="repository",
                status="open",
                owner=owners[0] if owners else "quality-engineering",
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
                evidence_refs=[
                    "coverage-summary.json",
                    "finding-delta.json",
                    path,
                ],
                tools=["coverage", "junit"],
                details={
                    "path": path,
                    "ownership_rule_matched": bool(owners),
                    "owners": owners,
                    "file_coverage_percent": percent,
                },
            )
        )
    return items


def _consolidate_test_assurance(
    items: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Fold native coverage observations into the richer per-file closure item."""
    assurance_by_path = {
        str(_as_object(item.get("details")).get("path")): item
        for item in items
        if item.get("category") == "test-assurance"
        and _as_object(item.get("details")).get("path")
    }
    result: list[dict[str, Any]] = []
    for item in items:
        tools = {str(value) for value in item.get("tools", [])}
        if item.get("category") != "finding" or not tools.intersection(
            {"coverage", "diff-cover"}
        ):
            result.append(item)
            continue
        path = next(
            (
                str(value).replace("\\", "/")
                for value in item.get("evidence_refs", [])
                if str(value).replace("\\", "/").startswith("src/")
                and str(value).endswith(".py")
            ),
            "",
        )
        assurance = assurance_by_path.get(path)
        if assurance is None:
            result.append(item)
            continue
        for field in (
            "acceptance_criteria",
            "evidence_refs",
            "related_findings",
            "tools",
        ):
            assurance[field] = _unique_values(
                [*assurance.get(field, []), *item.get(field, [])]
            )
        if (
            _PRIORITY_ORDER[str(item["priority"])]
            < _PRIORITY_ORDER[str(assurance["priority"])]
        ):
            assurance["priority"] = item["priority"]
        details = _as_object(assurance.get("details"))
        observations = details.setdefault("consolidated_coverage_findings", [])
        if isinstance(observations, list):
            observations.append(
                {
                    "closure_item_id": item["id"],
                    "finding_ids": item.get("related_findings", []),
                    "title": item.get("title"),
                    "tools": item.get("tools", []),
                }
            )
    return result


def _coverage_candidates(
    coverage: dict[str, Any], target: float
) -> list[tuple[float, str, dict[str, Any]]]:
    candidates: list[tuple[float, str, dict[str, Any]]] = []
    for record in _object_list(coverage.get("files"), "coverage files"):
        summary = _as_object(record.get("summary"))
        percent = summary.get("percent_covered")
        if not isinstance(percent, (int, float)) or isinstance(percent, bool):
            continue
        if float(percent) >= target:
            continue
        path = str(record.get("path") or "").replace("\\", "/")
        if not path.startswith(("src/", "src\\")):
            continue
        candidates.append((float(percent), path, summary))
    candidates.sort(key=lambda value: (value[0], value[1]))
    return candidates


def _validation_priority(alignment: str, change_priority: str) -> str:
    if alignment in {"tests-failing", "tests-incomplete"}:
        return "P1"
    if change_priority == "high" or alignment in {
        "coverage-gap",
        "test-evidence-not-available",
        "coverage-not-available",
    }:
        return "P2"
    return "P3"


def _validation_title(alignment: str, path: str) -> str:
    prefix = {
        "coverage-gap": "Cover changed executable lines in",
        "tests-failing": "Resolve failing focused tests for",
        "tests-incomplete": "Complete focused test execution for",
        "tests-not-observed": "Run graph-selected tests for",
        "test-evidence-not-available": "Produce focused test evidence for",
        "coverage-not-available": "Produce changed-line coverage for",
        "assessment-truncated": "Restore complete validation evidence for",
    }.get(alignment, "Align validation evidence for")
    return f"{prefix} {path}"


def _validation_why(alignment: str) -> str:
    return {
        "coverage-gap": "Focused tests passed, but changed-line coverage contradicts complete validation",
        "tests-failing": "At least one graph-selected focused test failed",
        "tests-incomplete": "Focused test execution did not complete cleanly",
        "tests-not-observed": "Mapped focused tests were not observed in retained case evidence",
        "test-evidence-not-available": "No supported case-level test artifact was retained",
        "coverage-not-available": "Changed-line coverage evidence was unavailable",
    }.get(alignment, "Focused-test and coverage evidence are not aligned")


def _validation_acceptance(alignment: str, path: str) -> list[str]:
    criteria = [
        f"The change impact for {path} reports aligned-current-evidence in a newly sealed report.",
        "The replacement report independently passes pysec verify-report.",
    ]
    if alignment in {"tests-failing", "tests-incomplete", "tests-not-observed"}:
        criteria.insert(0, "Every graph-selected focused test completes and passes.")
    if alignment in {"coverage-gap", "coverage-not-available"}:
        criteria.insert(0, "Every cited changed executable line is covered.")
    return criteria


def _validation_tools(execution_sources: list[str]) -> list[str]:
    tools = {"coverage", "diff-cover", "graphify"}
    for source in execution_sources:
        normalized = source.lower()
        tool = (
            "junit"
            if "junit" in normalized
            else "hypothesis"
            if "hypothesis" in normalized
            else "schemathesis"
            if "schemathesis" in normalized
            else source
        )
        tools.add(tool)
    return sorted(tools)


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
        key = str(item["id"])
        current = result.get(key)
        if current is None:
            result[key] = item
            continue
        for field in (
            "acceptance_criteria",
            "evidence_refs",
            "commands",
            "related_findings",
            "tools",
        ):
            combined = [*current.get(field, []), *item.get(field, [])]
            current[field] = _unique_values(combined)
    return list(result.values())


def _unique_values(values: list[Any]) -> list[Any]:
    result: list[Any] = []
    seen: set[Any] = set()
    for value in values:
        marker = tuple(value) if isinstance(value, list) else value
        if marker in seen:
            continue
        seen.add(marker)
        result.append(value)
    return result


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


def _string_values(value: Any, limit: int) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value[:limit] if isinstance(item, str) and item]


def _integer_values(value: Any, limit: int) -> list[int]:
    if not isinstance(value, list):
        return []
    return [
        item
        for item in value[:limit]
        if isinstance(item, int) and not isinstance(item, bool) and item > 0
    ]


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
