from __future__ import annotations

import hashlib
import json

from .strict_json import loads as strict_json_loads
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
        advanced=_optional_object(root / "advanced-analysis.json"),
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
        advanced=_as_object(artifacts.get("advanced-analysis.json")),
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
    advanced: dict[str, Any],
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
    items.extend(_advanced_analysis_items(advanced))
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
        secret_details = _closure_secret_provenance(evidence.get("secret_provenance"))
        secret_refs, secret_acceptance = _secret_provenance_closure_context(
            secret_details
        )
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
                    secret_details.get("recommended_action")
                    or finding.get("remediation")
                    or "Review and resolve the finding."
                ),
                acceptance=[
                    f"Finding {finding_id} is absent or governed in a newly sealed report.",
                    "The replacement report independently passes pysec verify-report.",
                    *risk_acceptance,
                    *secret_acceptance,
                ],
                evidence_refs=[
                    "findings.json",
                    "action-plan.md",
                    *location_paths,
                    *risk_refs,
                    *secret_refs,
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
                details={
                    **({"risk_path": risk_details} if risk_details else {}),
                    **({"secret_provenance": secret_details} if secret_details else {}),
                },
            )
        )
    return items


def _closure_secret_provenance(value: Any) -> dict[str, Any]:
    item = _as_object(value)
    if not item:
        return {}
    return {
        "secret_context_id": str(item.get("secret_context_id") or "unknown"),
        "content_lane": str(item.get("content_lane") or "unknown"),
        "review_disposition": str(item.get("review_disposition") or "unknown"),
        "path": str(item.get("path") or "unknown"),
        "line": item.get("line"),
        "redacted": item.get("redacted") is True,
        "verification_status": str(
            item.get("verification_status") or "not-established"
        ),
        "history_status": str(item.get("history_status") or "not-established"),
        "history_commit": item.get("history_commit"),
        "scanner_tools": _string_values(item.get("scanner_tools"), 25),
        "scanner_rules": _string_values(item.get("scanner_rules"), 50),
        "scanner_perspective": str(item.get("scanner_perspective") or "single-scanner"),
        "evidence_assurance_status": str(
            item.get("evidence_assurance_status") or "not-assessed"
        ),
        "source_inventory_member": item.get("source_inventory_member"),
        "graph_path_member": item.get("graph_path_member"),
        "artifact_manifest_member": item.get("artifact_manifest_member"),
        "owners": _string_values(item.get("owners"), 100),
        "secret_exposure_intersection_ids": _string_values(
            item.get("secret_exposure_intersection_ids"), 100
        ),
        "secret_exposure_intersections": _closure_secret_exposure_intersections(
            item.get("secret_exposure_intersections")
        ),
        "secret_exposure_intersections_omitted": int(
            item.get("secret_exposure_intersections_omitted") or 0
        ),
        "citations": _closure_citations(item.get("citations")),
        "evidence_artifacts": _string_values(item.get("evidence_artifacts"), 25),
        "recommended_action": str(
            item.get("recommended_action") or "Review the redacted secret candidate."
        ),
    }


def _secret_provenance_closure_context(
    item: dict[str, Any],
) -> tuple[list[str], list[str]]:
    if not item:
        return [], []
    acceptance = [
        "The redacted candidate is validated only in a protected workspace and no secret value is copied into reports, tickets, logs, or telemetry."
    ]
    lane = item.get("content_lane")
    if lane == "generated-evidence":
        acceptance.append(
            "The candidate is proven to be either a real credential or deterministic evidence: real credentials are rotated and purged with the producer sanitized; proven digests use only a narrow artifact/rule exclusion that preserves other secret scanning."
        )
    elif lane == "test-validation-source":
        acceptance.append(
            "Any retained test value is proven synthetic and nonfunctional, its fixture purpose is documented, and any allowlist is limited to the exact rule and path."
        )
    elif lane == "python-runtime-source":
        acceptance.append(
            "Any real credential is revoked and rotated, removed from maintained source and applicable history, and replaced by an approved secret-store reference."
        )
    elif lane == "artifact-control":
        acceptance.append(
            "Any real credential is removed from build and release material, caches are purged as required, and the producing build is corrected before promotion."
        )
    else:
        acceptance.append(
            "The candidate is resolved or narrowly governed in its native repository or configuration evidence lane without weakening unrelated secret scanning."
        )
    if item.get("history_status") == "history-evidence":
        acceptance.append(
            "The cited commit and reachable history are reviewed; a real credential is rotated and the governed history-remediation decision is retained."
        )
    if item.get("verification_status") != "verified":
        acceptance.append(
            "Credential validity is established or explicitly ruled out without treating scanner shape matching as proof of an active credential."
        )
    if item.get("redacted") is not True:
        acceptance.append(
            "Every report and export path is verified to redact secret material before artifacts leave the protected boundary."
        )
    intersections = _bounded_objects(item.get("secret_exposure_intersections"), 25)
    if intersections:
        acceptance.extend(
            [
                "Each retained secret-to-sensitive-sink intersection has a symbol-level review that either proves and remediates the value flow or records bounded counter-evidence; file-route co-location alone is not used as a disclosure claim.",
                "Synthetic-canary tests prove credential-shaped values are minimized, masked, or rejected before every cited sink boundary, and the newly sealed report retains the resulting validation evidence.",
            ]
        )
        if any(
            str(candidate.get("temporal_alignment")) == "history-to-current-route"
            for candidate in intersections
        ):
            acceptance.append(
                "Historical candidate and current sink evidence are revision-aligned before they are related; reachable history is remediated when the candidate was real."
            )
        if any(
            str(candidate.get("secret_assurance_status")) != "assured"
            or str(candidate.get("sensitive_assurance_status")) != "assured"
            for candidate in intersections
        ):
            acceptance.append(
                "Contributing secret and sensitive-sink scanners complete with approved, integrity-verified evidence or a governed assurance limitation remains explicit."
            )
        if any(
            _as_object(candidate.get("validation_handoff")).get(
                "source_revision_aligned"
            )
            is not True
            for candidate in intersections
        ):
            acceptance.append(
                "Candidate sink tests, coverage, and scanner evidence are regenerated against and cryptographically bound to the replacement source revision before they are accepted as supporting evidence."
            )
        if any(
            candidate.get("combined_assurance_prerequisite_met") is not True
            for candidate in intersections
        ):
            acceptance.append(
                "Secret, sink, and linked campaign evidence all meet completed, integrity-verified, organization-approved assurance prerequisites before the validation handoff is used for closure."
            )
        if any(
            _as_object(candidate.get("validation_handoff")).get("test_file_finding_ids")
            for candidate in intersections
        ):
            acceptance.append(
                "Active findings in every candidate validation-test file are resolved or governed before its assertions are trusted as closure evidence."
            )
        if any(
            _as_object(candidate.get("validation_handoff")).get(
                "cross_owner_test_files"
            )
            or _as_object(candidate.get("validation_handoff")).get("unowned_test_files")
            for candidate in intersections
        ):
            acceptance.append(
                "Candidate validation tests have accountable ownership and coordinated review across secret, sink, and test owners."
            )
        compounds = [
            compound
            for candidate in intersections
            for compound in _bounded_objects(
                candidate.get("secret_exposure_advisory_intersections"), 25
            )
        ]
        if compounds:
            acceptance.extend(
                [
                    "Every exact sensitive-route secret/sink/advisory intersection is reviewed as one protected remediation scope while credential flow and vulnerable-function execution are established independently.",
                    "Dependency remediation or a governed VEX disposition is completed alongside credential rotation when applicable, pre-sink protection, and explicit synthetic-canary validation against the same sealed source revision.",
                ]
            )
    references = {
        *_string_values(item.get("evidence_artifacts"), 25),
        *(
            reference
            for candidate in intersections
            for reference in _string_values(candidate.get("evidence_artifacts"), 25)
        ),
        *(
            reference
            for candidate in intersections
            for compound in _bounded_objects(
                candidate.get("secret_exposure_advisory_intersections"), 25
            )
            for reference in _string_values(compound.get("evidence_artifacts"), 25)
        ),
    }
    return sorted(references), acceptance


def _closure_secret_exposure_intersections(value: Any) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for item in _bounded_objects(value, 25):
        result.append(
            {
                "intersection_id": str(item.get("intersection_id") or "unknown"),
                "priority": str(item.get("priority") or "P4"),
                "association_kind": str(item.get("association_kind") or "unknown"),
                "temporal_alignment": str(
                    item.get("temporal_alignment") or "not-established"
                ),
                "secret_path": str(item.get("secret_path") or "unknown"),
                "secret_line": item.get("secret_line"),
                "secret_verification_status": str(
                    item.get("secret_verification_status") or "not-established"
                ),
                "secret_assurance_status": str(
                    item.get("secret_assurance_status") or "not-assessed"
                ),
                "sensitive_route_id": str(item.get("sensitive_route_id") or "unknown"),
                "sink_path": str(item.get("sink_path") or "unknown"),
                "sink_line": item.get("sink_line"),
                "sink_family": str(item.get("sink_family") or "unknown"),
                "trust_boundary": str(item.get("trust_boundary") or "unknown"),
                "protection_status": str(item.get("protection_status") or "unknown"),
                "sensitive_assurance_status": str(
                    item.get("sensitive_assurance_status") or "not-assessed"
                ),
                "validation_status": str(
                    item.get("validation_status") or "not-assessed"
                ),
                "validation_handoff": _closure_sensitive_validation_handoff(
                    item.get("validation_handoff")
                ),
                "combined_assurance_prerequisite_met": item.get(
                    "combined_assurance_prerequisite_met"
                )
                is True,
                "canary_validation_status": str(
                    item.get("canary_validation_status") or "not-established"
                ),
                "recommended_test_files": _string_values(
                    item.get("recommended_test_files"), 50
                ),
                "intersection_validation_gap_reasons": _string_values(
                    item.get("intersection_validation_gap_reasons"), 25
                ),
                "secret_exposure_advisory_intersection_ids": _string_values(
                    item.get("secret_exposure_advisory_intersection_ids"), 100
                ),
                "secret_exposure_advisory_intersections": (
                    _closure_secret_exposure_advisory_intersections(
                        item.get("secret_exposure_advisory_intersections")
                    )
                ),
                "secret_exposure_advisory_intersections_omitted": (
                    _nonnegative_integer(
                        item.get("secret_exposure_advisory_intersections_omitted")
                    )
                ),
                "distance_to_sink": int(item.get("distance_to_sink") or 0),
                "owners": _string_values(item.get("owners"), 100),
                "finding_ids": _string_values(item.get("finding_ids"), 100),
                "risk_factors": _string_values(item.get("risk_factors"), 25),
                "citations": _closure_citations(item.get("citations")),
                "evidence_artifacts": _string_values(
                    item.get("evidence_artifacts"), 25
                ),
                "recommended_action": str(
                    item.get("recommended_action") or "Trace and protect the route."
                ),
                "interpretation": str(item.get("interpretation") or ""),
            }
        )
    return result


def _closure_secret_exposure_advisory_intersections(
    value: Any,
) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for item in _bounded_objects(value, 25):
        result.append(
            {
                "intersection_id": str(item.get("intersection_id") or "unknown"),
                "priority": str(item.get("priority") or "P4"),
                "evidence_basis": str(item.get("evidence_basis") or "unknown"),
                "secret_exposure_intersection_id": str(
                    item.get("secret_exposure_intersection_id") or "unknown"
                ),
                "exposure_advisory_intersection_id": str(
                    item.get("exposure_advisory_intersection_id") or "unknown"
                ),
                "secret_path": str(item.get("secret_path") or "unknown"),
                "secret_line": item.get("secret_line"),
                "secret_verification_status": str(
                    item.get("secret_verification_status") or "not-established"
                ),
                "temporal_alignment": str(
                    item.get("temporal_alignment") or "not-established"
                ),
                "sink_path": str(item.get("sink_path") or "unknown"),
                "sink_line": item.get("sink_line"),
                "sink_family": str(item.get("sink_family") or "unknown"),
                "trust_boundary": str(item.get("trust_boundary") or "unknown"),
                "protection_status": str(item.get("protection_status") or "unknown"),
                "dependency_route_id": str(
                    item.get("dependency_route_id") or "unknown"
                ),
                "advisory_cluster_id": str(
                    item.get("advisory_cluster_id") or "unknown"
                ),
                "primary_identifier": str(item.get("primary_identifier") or "unknown"),
                "package": str(item.get("package") or "unknown"),
                "known_exploited": item.get("known_exploited") is True,
                "epss_high": item.get("epss_high") is True,
                "fix_available": item.get("fix_available") is True,
                "package_lifecycle": _as_object(item.get("package_lifecycle")),
                "entry_point_ids": _string_values(item.get("entry_point_ids"), 100),
                "entry_point_runtime_statuses": _as_object(
                    item.get("entry_point_runtime_statuses")
                ),
                "validation_statuses": _as_object(item.get("validation_statuses")),
                "validation_handoff": _closure_sensitive_validation_handoff(
                    item.get("validation_handoff")
                ),
                "combined_assurance_prerequisite_met": item.get(
                    "combined_assurance_prerequisite_met"
                )
                is True,
                "canary_validation_status": str(
                    item.get("canary_validation_status") or "not-established"
                ),
                "recommended_test_files": _string_values(
                    item.get("recommended_test_files"), 50
                ),
                "owners": _string_values(item.get("owners"), 100),
                "finding_ids": _string_values(item.get("finding_ids"), 100),
                "risk_factors": _string_values(item.get("risk_factors"), 25),
                "citations": _closure_citations(item.get("citations")),
                "evidence_artifacts": _string_values(
                    item.get("evidence_artifacts"), 25
                ),
                "recommended_action": str(
                    item.get("recommended_action")
                    or "Review and remediate the compound exposure scope."
                ),
                "interpretation": str(item.get("interpretation") or ""),
            }
        )
    return result


def _closure_sensitive_validation_handoff(value: Any) -> dict[str, Any]:
    handoff = _as_object(value)
    if not handoff:
        return {}
    return {
        "supporting_evidence_readiness": str(
            handoff.get("supporting_evidence_readiness") or "not-established"
        ),
        "canary_assertion_status": str(
            handoff.get("canary_assertion_status") or "not-established"
        ),
        "route_validation_status": str(
            handoff.get("route_validation_status") or "not-assessed"
        ),
        "campaign_ids": _string_values(handoff.get("campaign_ids"), 50),
        "campaigns_omitted": _nonnegative_integer(handoff.get("campaigns_omitted")),
        "campaign_records": _bounded_objects(handoff.get("campaign_records"), 25),
        "test_hotspot_ids": _string_values(handoff.get("test_hotspot_ids"), 100),
        "candidate_test_files": _string_values(handoff.get("candidate_test_files"), 50),
        "candidate_test_files_omitted": _nonnegative_integer(
            handoff.get("candidate_test_files_omitted")
        ),
        "test_selection_confidence": str(
            handoff.get("test_selection_confidence") or "not-available"
        ),
        "focused_test_statuses": _string_values(
            handoff.get("focused_test_statuses"), 25
        ),
        "focused_test_execution": _bounded_objects(
            handoff.get("focused_test_execution"), 50
        ),
        "focused_test_execution_omitted": _nonnegative_integer(
            handoff.get("focused_test_execution_omitted")
        ),
        "test_execution_evidence_complete": handoff.get(
            "test_execution_evidence_complete"
        )
        is True,
        "test_case_inventory_complete": handoff.get("test_case_inventory_complete"),
        "coverage_statuses": _string_values(handoff.get("coverage_statuses"), 25),
        "coverage_attribution": str(
            handoff.get("coverage_attribution") or "not-established"
        ),
        "test_coverage_alignments": _string_values(
            handoff.get("test_coverage_alignments"), 25
        ),
        "source_revision_bindings": _string_values(
            handoff.get("source_revision_bindings"), 25
        ),
        "source_revision_aligned": handoff.get("source_revision_aligned") is True,
        "campaign_assurance_statuses": _string_values(
            handoff.get("campaign_assurance_statuses"), 25
        ),
        "campaign_assurance_prerequisite_met": handoff.get(
            "campaign_assurance_prerequisite_met"
        )
        is True,
        "shared_test_quality_statuses": _string_values(
            handoff.get("shared_test_quality_statuses"), 25
        ),
        "test_file_finding_ids": _string_values(
            handoff.get("test_file_finding_ids"), 100
        ),
        "cross_owner_test_files": _string_values(
            handoff.get("cross_owner_test_files"), 50
        ),
        "unowned_test_files": _string_values(handoff.get("unowned_test_files"), 50),
        "gap_reasons": _string_values(handoff.get("gap_reasons"), 20),
        "evidence_artifacts": _string_values(handoff.get("evidence_artifacts"), 25),
        "recommended_action": str(
            handoff.get("recommended_action")
            or "Establish source-bound sink validation evidence."
        ),
        "interpretation": str(handoff.get("interpretation") or ""),
    }


def _closure_validation_campaigns(value: Any) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for campaign in _bounded_objects(value, 50):
        snapshot = _as_object(campaign.get("source_snapshot"))
        result.append(
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
                "review_factors": _bounded_objects(campaign.get("review_factors"), 20),
                "control_point_context": _as_object(
                    campaign.get("control_point_context")
                ),
                "route_evidence_assurance": _as_object(
                    campaign.get("route_evidence_assurance")
                ),
                "shared_test_evidence_quality": _as_object(
                    campaign.get("shared_test_evidence_quality")
                ),
                "source_snapshot": {
                    "source_sha256": snapshot.get("source_sha256"),
                    "control_point_binding": _as_object(
                        snapshot.get("control_point_binding")
                    ),
                    "selected_test_files_bound": snapshot.get(
                        "selected_test_files_bound"
                    ),
                    "selected_test_files_missing": _string_values(
                        snapshot.get("selected_test_files_missing"), 50
                    ),
                    "evidence_revision_binding": snapshot.get(
                        "evidence_revision_binding"
                    ),
                    "evidence_revision_binding_reason": snapshot.get(
                        "evidence_revision_binding_reason"
                    ),
                    "evidence_source_bindings": _bounded_objects(
                        snapshot.get("evidence_source_bindings"), 4
                    ),
                },
                "recommended_action": campaign.get("recommended_action"),
            }
        )
    return result


def _closure_dependency_advisory_routes(value: Any) -> list[dict[str, Any]]:
    return [
        _closure_dependency_advisory_route(item) for item in _bounded_objects(value, 25)
    ]


def _closure_dependency_advisory_route(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "route_id": str(item.get("route_id") or "unknown"),
        "target_id": str(item.get("target_id") or "unknown"),
        "priority": str(item.get("priority") or "P4"),
        "advisory_cluster_id": str(item.get("advisory_cluster_id") or "unknown"),
        "primary_identifier": str(item.get("primary_identifier") or "unknown"),
        "package": str(item.get("package") or "unknown"),
        "versions": _string_values(item.get("versions"), 25),
        "import_path": str(item.get("import_path") or "unknown"),
        "import_modules": _string_values(item.get("import_modules"), 50),
        "import_lines": _integer_values(item.get("import_lines"), 100),
        "dependency_usage_assessment": item.get("dependency_usage_assessment"),
        "import_path_assessment": _as_object(item.get("import_path_assessment")),
        "entry_point": _as_object(item.get("entry_point")),
        "entry_point_exposure_count": item.get("entry_point_exposure_count"),
        "entry_point_exposures": _closure_entry_point_exposures(
            item.get("entry_point_exposures")
        ),
        "entry_point_exposures_omitted": item.get("entry_point_exposures_omitted"),
        "entry_point_runtime_statuses": _as_object(
            item.get("entry_point_runtime_statuses")
        ),
        "entry_point_kinds": _string_values(item.get("entry_point_kinds"), 25),
        "hop_count": item.get("hop_count"),
        "files": _string_values(item.get("files"), 9),
        "runtime_context": _as_object(item.get("runtime_context")),
        "validation": _as_object(item.get("validation")),
        "evidence_assurance": _closure_evidence_assurance(
            item.get("evidence_assurance")
        ),
        "ownership_context": _closure_route_ownership(item.get("ownership_context")),
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
        "uncovered_changed_lines": _integer_values(
            item.get("uncovered_changed_lines"), 100
        ),
        "advisory_citations": _bounded_objects(item.get("advisory_citations"), 25),
        "recommended_action": str(
            item.get("recommended_action") or "Review dependency use."
        ),
    }


def _closure_exposure_advisory_intersections(value: Any) -> list[dict[str, Any]]:
    return [
        _closure_exposure_advisory_intersection(item)
        for item in _bounded_objects(value, 25)
    ]


def _closure_exposure_advisory_intersection(
    item: dict[str, Any],
) -> dict[str, Any]:
    return {
        "intersection_id": str(item.get("intersection_id") or "unknown"),
        "priority": str(item.get("priority") or "P4"),
        "path": str(item.get("path") or "unknown"),
        "line": item.get("line"),
        "sink_route_id": str(item.get("sink_route_id") or "unknown"),
        "dependency_route_id": str(item.get("dependency_route_id") or "unknown"),
        "advisory_cluster_id": str(item.get("advisory_cluster_id") or "unknown"),
        "primary_identifier": str(item.get("primary_identifier") or "unknown"),
        "package": str(item.get("package") or "unknown"),
        "sdk": item.get("sdk"),
        "sink_family": str(item.get("sink_family") or "unknown"),
        "trust_boundary": str(item.get("trust_boundary") or "unknown"),
        "data_classes": _string_values(item.get("data_classes"), 25),
        "protection_status": str(item.get("protection_status") or "unknown"),
        "known_exploited": item.get("known_exploited") is True,
        "epss_high": item.get("epss_high") is True,
        "fix_available": item.get("fix_available") is True,
        "package_lifecycle": _as_object(item.get("package_lifecycle")),
        "entry_point_exposure_count": item.get("entry_point_exposure_count"),
        "entry_point_ids": _string_values(item.get("entry_point_ids"), 50),
        "entry_point_exposures_omitted": item.get("entry_point_exposures_omitted"),
        "entry_point_runtime_statuses": _as_object(
            item.get("entry_point_runtime_statuses")
        ),
        "validation_statuses": _as_object(item.get("validation_statuses")),
        "evidence_assurance_statuses": _as_object(
            item.get("evidence_assurance_statuses")
        ),
        "advisory_citations": _bounded_objects(item.get("advisory_citations"), 25),
        "secret_exposure_advisory_intersection_ids": _string_values(
            item.get("secret_exposure_advisory_intersection_ids"), 100
        ),
        "secret_exposure_advisory_intersections": (
            _closure_secret_exposure_advisory_intersections(
                item.get("secret_exposure_advisory_intersections")
            )
        ),
        "secret_exposure_advisory_intersections_omitted": _nonnegative_integer(
            item.get("secret_exposure_advisory_intersections_omitted")
        ),
        "recommended_action": str(
            item.get("recommended_action")
            or "Review the exposure-advisory intersection."
        ),
    }


def _closure_sensitive_data_route(value: Any) -> dict[str, Any]:
    item = _as_object(value)
    if not item:
        return {}
    return {
        "sensitive_route_id": str(item.get("sensitive_route_id") or "unknown"),
        "route_id": str(item.get("route_id") or "unknown"),
        "priority": str(item.get("priority") or "P4"),
        "evidence_basis": str(item.get("evidence_basis") or "unknown"),
        "path": str(item.get("path") or "unknown"),
        "line": item.get("line"),
        "concern": str(item.get("concern") or "sensitive-data-exposure"),
        "sink_family": str(item.get("sink_family") or "unknown"),
        "sink": item.get("sink"),
        "sdk": item.get("sdk"),
        "confidence": item.get("confidence"),
        "data_classes": _string_values(item.get("data_classes"), 25),
        "trust_boundary": str(item.get("trust_boundary") or "unknown"),
        "protection_status": str(item.get("protection_status") or "unknown"),
        "risk_factors": _string_values(item.get("risk_factors"), 25),
        "citations": _closure_citations(item.get("citations")),
        "entry_point_ids": _string_values(item.get("entry_point_ids"), 100),
        "entry_point_runtime_statuses": _as_object(
            item.get("entry_point_runtime_statuses")
        ),
        "validation_status": str(item.get("validation_status") or "not-assessed"),
        "validation_handoff": _closure_sensitive_validation_handoff(
            item.get("validation_handoff")
        ),
        "evidence_assurance_status": str(
            item.get("evidence_assurance_status") or "not-assessed"
        ),
        "ownership_coordination_status": str(
            item.get("ownership_coordination_status") or "not-established"
        ),
        "ownership_boundaries": item.get("ownership_boundaries"),
        "owners": _string_values(item.get("owners"), 100),
        "secret_exposure_intersection_ids": _string_values(
            item.get("secret_exposure_intersection_ids"), 100
        ),
        "secret_exposure_intersections": _closure_secret_exposure_intersections(
            item.get("secret_exposure_intersections")
        ),
        "secret_exposure_intersections_omitted": int(
            item.get("secret_exposure_intersections_omitted") or 0
        ),
        "secret_exposure_advisory_intersection_ids": _string_values(
            item.get("secret_exposure_advisory_intersection_ids"), 100
        ),
        "secret_exposure_advisory_intersections": (
            _closure_secret_exposure_advisory_intersections(
                item.get("secret_exposure_advisory_intersections")
            )
        ),
        "secret_exposure_advisory_intersections_omitted": _nonnegative_integer(
            item.get("secret_exposure_advisory_intersections_omitted")
        ),
        "recommended_action": str(
            item.get("recommended_action") or "Review the sensitive-data route."
        ),
    }


def _closure_citations(value: Any) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for item in _bounded_objects(value, 10):
        identifier = str(item.get("identifier") or "").strip()
        if not identifier:
            continue
        uri = item.get("uri")
        result.append(
            {
                "kind": str(item.get("kind") or "reference")[:100],
                "identifier": identifier[:500],
                "title": str(item.get("title") or identifier)[:1000],
                "uri": str(uri)[:4000] if isinstance(uri, str) else None,
            }
        )
    return result


def _risk_path_closure_context(
    evidence: dict[str, Any],
) -> tuple[list[str], list[str], dict[str, Any]]:
    risk_path = _as_object(evidence.get("risk_path"))
    if not risk_path:
        return [], [], {}
    status = str(risk_path.get("status") or "unknown")
    refs = ["risk-paths.json"]
    evidence_assurance = _closure_evidence_assurance(
        risk_path.get("evidence_assurance")
    )
    lifecycle_attribution = _closure_change_lifecycle_attribution(
        risk_path.get("change_lifecycle_attribution")
    )
    ownership_context = _closure_route_ownership(risk_path.get("ownership_context"))
    route_applicability = _closure_route_applicability(
        risk_path.get("route_applicability")
    )
    unrouted_structural_intersections = _closure_unrouted_structural_intersections(
        risk_path.get("unrouted_structural_intersections")
    )
    sensitive_data_route = _closure_sensitive_data_route(
        risk_path.get("sensitive_data_route")
    )
    details: dict[str, Any] = {
        "status": status,
        "evidence_assurance": evidence_assurance,
        "change_lifecycle_attribution": lifecycle_attribution,
        "ownership_context": ownership_context,
        "route_applicability": route_applicability,
        "unrouted_structural_intersections": unrouted_structural_intersections,
        "sensitive_data_route": sensitive_data_route,
    }
    if evidence_assurance["tool_records"]:
        refs.extend(["effectiveness.json", "scanner-trust.json"])
    if lifecycle_attribution:
        refs.extend(_string_values(lifecycle_attribution.get("evidence_artifacts"), 10))
    if ownership_context:
        refs.extend(_string_values(ownership_context.get("evidence_artifacts"), 10))
        refs.extend(_string_values(ownership_context.get("unowned_files"), 225))
    if route_applicability:
        refs.extend(_string_values(route_applicability.get("evidence_artifacts"), 3))
    if unrouted_structural_intersections:
        refs.extend(
            artifact
            for intersection in unrouted_structural_intersections
            for artifact in _string_values(intersection.get("evidence_artifacts"), 10)
        )
        refs.extend(
            str(intersection["path"])
            for intersection in unrouted_structural_intersections
        )
        refs.extend(
            test
            for intersection in unrouted_structural_intersections
            for test in _string_values(intersection.get("direct_test_files"), 25)
        )
    if sensitive_data_route:
        refs.extend(["data-exposure.json", str(sensitive_data_route["path"])])
        refs.extend(
            artifact
            for intersection in _bounded_objects(
                sensitive_data_route.get("secret_exposure_intersections"), 25
            )
            for artifact in _string_values(intersection.get("evidence_artifacts"), 25)
        )
    if status == "routed":
        route_id = str(risk_path.get("route_id") or "unknown")
        files = _string_values(risk_path.get("files"), 9)
        refs.extend(files)
        entry_point_exposures = _closure_entry_point_exposures(
            risk_path.get("entry_point_exposures")
        )
        refs.extend(
            path for exposure in entry_point_exposures for path in exposure["files"]
        )
        validation = _as_object(risk_path.get("validation"))
        assessment = str(validation.get("assessment_status") or "not-assessed")
        campaign_ids = _string_values(risk_path.get("validation_campaign_ids"), 50)
        campaigns = _closure_validation_campaigns(risk_path.get("validation_campaigns"))
        refs.extend(
            test for campaign in campaigns for test in campaign["selected_test_files"]
        )
        refs.extend(
            artifact
            for campaign in campaigns
            for artifact in _string_values(
                _as_object(campaign.get("route_evidence_assurance")).get(
                    "evidence_artifacts"
                ),
                10,
            )
        )
        refs.extend(
            artifact
            for campaign in campaigns
            for artifact in _string_values(
                _as_object(campaign.get("shared_test_evidence_quality")).get(
                    "evidence_artifacts"
                ),
                10,
            )
        )
        dependency_routes = _closure_dependency_advisory_routes(
            risk_path.get("dependency_advisory_routes")
        )
        if dependency_routes:
            refs.append("evidence-fusion.json")
            refs.extend(str(item["import_path"]) for item in dependency_routes)
        exposure_advisory_intersections = _closure_exposure_advisory_intersections(
            risk_path.get("exposure_advisory_intersections")
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
                "entry_point_exposure_count": risk_path.get(
                    "entry_point_exposure_count"
                ),
                "entry_point_exposures": entry_point_exposures,
                "entry_point_exposures_omitted": risk_path.get(
                    "entry_point_exposures_omitted"
                ),
                "entry_point_kinds": _string_values(
                    risk_path.get("entry_point_kinds"), 25
                ),
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
        acceptance = _routed_risk_path_acceptance(
            route_id=route_id,
            assessment=assessment,
            risk_path=risk_path,
            evidence_assurance=evidence_assurance,
            lifecycle_attribution=lifecycle_attribution,
            ownership_context=ownership_context,
            campaigns=campaigns,
            dependency_routes=dependency_routes,
            exposure_advisory_intersections=exposure_advisory_intersections,
            sensitive_data_route=sensitive_data_route,
        )
        return refs, acceptance, details
    reason = str(risk_path.get("reason") or "bounded static route unavailable")
    details["reason"] = reason
    return (
        refs,
        [
            *_unrouted_route_applicability_acceptance(route_applicability),
            *_unrouted_structural_acceptance(unrouted_structural_intersections),
            *_evidence_assurance_acceptance(evidence_assurance),
            *_change_lifecycle_acceptance(lifecycle_attribution),
            *_route_ownership_acceptance(ownership_context),
        ],
        details,
    )


def _closure_unrouted_structural_intersections(value: Any) -> list[dict[str, Any]]:
    return [
        {
            "intersection_id": str(item.get("intersection_id") or "unknown"),
            "priority": str(item.get("priority") or "P4"),
            "evidence_basis": str(item.get("evidence_basis") or "unknown"),
            "island_id": str(item.get("island_id") or "unknown"),
            "island_state": str(item.get("island_state") or "unknown"),
            "island_classification": str(
                item.get("island_classification") or "unknown"
            ),
            "runtime_observation": str(item.get("runtime_observation") or "unknown"),
            "boundary_classification": str(
                item.get("boundary_classification") or "not-established"
            ),
            "path": str(item.get("path") or "unknown"),
            "candidate_entry_paths": _string_values(
                item.get("candidate_entry_paths"), 25
            ),
            "direct_test_files": _string_values(item.get("direct_test_files"), 25),
            "dead_code_finding_ids": _string_values(
                item.get("dead_code_finding_ids"), 25
            ),
            "security_finding_ids": _string_values(
                item.get("security_finding_ids"), 25
            ),
            "coordination_owners": _string_values(item.get("coordination_owners"), 100),
            "risk_signal": str(item.get("risk_signal") or "unknown"),
            "decision": str(item.get("decision") or "review"),
            "recommended_action": str(
                item.get("recommended_action") or "Review structural evidence."
            ),
            "evidence_artifacts": _string_values(item.get("evidence_artifacts"), 10),
            "interpretation": str(item.get("interpretation") or ""),
        }
        for item in _bounded_objects(value, 5)
    ]


def _unrouted_structural_acceptance(values: list[dict[str, Any]]) -> list[str]:
    if not values:
        return []
    result = [
        "Every exact unrouted-target/structural-island intersection is resolved by modeling the missing production path or by removing the capability with owner approval, focused regression evidence, and a clean replacement reachability, structural, and security scan; island membership alone is not accepted as proof of dead code or safety."
    ]
    if any(item["runtime_observation"] == "observed" for item in values):
        result.append(
            "Every retained runtime-observed structural conflict has its callback, registry, plugin, framework, generated, or external entry path modeled in the replacement report before any removal decision."
        )
    if any(item["candidate_entry_paths"] for item in values):
        result.append(
            "Every cited candidate production entry path is dispositioned as an executable/load path, an explicitly governed dynamic boundary, or an obsolete integration removed with focused tests."
        )
    if any(item["direct_test_files"] for item in values):
        result.append(
            "The cited structural-boundary tests pass against the replacement source revision and retain coverage for the remediated or removed behavior."
        )
    if any(not item["coordination_owners"] for item in values):
        result.append(
            "An accountable owner is established for every unowned route-gap/island decision before suppression, entry-model expansion, or removal."
        )
    return result


def _closure_route_applicability(value: Any) -> dict[str, Any]:
    raw = _as_object(value)
    if not raw:
        return {}
    return {
        "assessment": str(raw.get("assessment") or "not-established"),
        "classification": str(raw.get("classification") or "not-established"),
        "reason": str(raw.get("reason") or "route applicability is not established"),
        "source_inventory_available": raw.get("source_inventory_available") is True,
        "source_inventory_member": raw.get("source_inventory_member"),
        "graph_available": raw.get("graph_available") is True,
        "graph_path_member": raw.get("graph_path_member"),
        "artifact_manifest_available": raw.get("artifact_manifest_available") is True,
        "artifact_manifest_member": raw.get("artifact_manifest_member"),
        "evidence_artifacts": _string_values(raw.get("evidence_artifacts"), 3),
        "recommended_action": str(raw.get("recommended_action") or "Review."),
    }


def _unrouted_route_applicability_acceptance(value: dict[str, Any]) -> list[str]:
    if value.get("assessment") == "route-applicable":
        return [
            "The Python runtime target has a governed entry-point route or a documented dynamic/external-entry rationale in the replacement report."
        ]
    classification = str(value.get("classification") or "non-runtime target")
    return [
        f"The replacement report retains the {classification} disposition, and the finding is resolved or governed through its native evidence lane without inventing a Python entry point."
    ]


def _routed_risk_path_acceptance(
    *,
    route_id: str,
    assessment: str,
    risk_path: dict[str, Any],
    evidence_assurance: dict[str, Any],
    lifecycle_attribution: dict[str, Any],
    ownership_context: dict[str, Any],
    campaigns: list[dict[str, Any]],
    dependency_routes: list[dict[str, Any]],
    exposure_advisory_intersections: list[dict[str, Any]],
    sensitive_data_route: dict[str, Any],
) -> list[str]:
    result = [
        f"Static route {route_id} is reviewed with its owner and retained in the replacement report."
    ]
    if assessment == "gap":
        result.append(
            "The route validation assessment no longer reports a coverage or focused-test gap."
        )
    elif assessment in {"partial", "not-assessed"}:
        result.append(
            "The route has retained change-scope, line-coverage, and focused-test evidence sufficient for an aligned or explicit-gap assessment."
        )
    result.extend(_entry_point_exposure_acceptance(risk_path))
    result.extend(_evidence_assurance_acceptance(evidence_assurance))
    result.extend(_change_lifecycle_acceptance(lifecycle_attribution))
    result.extend(_route_ownership_acceptance(ownership_context))
    result.extend(_validation_campaign_acceptance(campaigns))
    if dependency_routes:
        result.extend(_dependency_route_acceptance(dependency_routes))
    if exposure_advisory_intersections:
        result.extend(
            [
                "Every exact-path sensitive-boundary/dependency intersection is reviewed for data minimization, redaction, recipient, retention, and access controls without treating path coincidence as proof of disclosure.",
                "Vulnerable-function use is established or ruled out independently, the dependency remediation or governed VEX disposition is recorded, and both sink and importer validation are rerun.",
            ]
        )
        if any(
            item["protection_status"] == "not-observed"
            for item in exposure_advisory_intersections
        ):
            result.append(
                "A tested protection control is retained at every intersection that previously reported no observed minimization, masking, hashing, or redaction."
            )
        compound_intersections = [
            compound
            for intersection in exposure_advisory_intersections
            for compound in _bounded_objects(
                intersection.get("secret_exposure_advisory_intersections"), 25
            )
        ]
        if compound_intersections:
            result.extend(
                [
                    "Every exact sensitive-route secret/sink/advisory intersection receives coordinated credential, boundary-protection, and dependency-remediation review without treating the join as proof of data flow or vulnerable-function execution.",
                    "A same-revision replacement report retains explicit synthetic-canary assertions, source-bound passing candidate tests, verified pre-sink protection, and the fixed built-artifact package or governed VEX disposition.",
                ]
            )
    if sensitive_data_route:
        result.append(
            "The end-to-end sensitive-data route is reviewed from each declared entry point through the cited sink, with concrete data classes, recipient, purpose, retention, and access controls documented without treating the static path as proof of disclosure."
        )
        if sensitive_data_route.get("protection_status") in {
            "not-observed",
            "unknown",
        }:
            result.append(
                "A tested allowlist, minimization, masking, hashing, or redaction control is retained before the cited trust boundary, including negative tests with synthetic sensitive canaries."
            )
        if not sensitive_data_route.get("citations"):
            result.append(
                "At least one applicable scanner rule, weakness classification, or security-practice citation is retained for the route, with its use limited to classification or remediation guidance rather than proof of disclosure."
            )
        validation_handoff = _as_object(sensitive_data_route.get("validation_handoff"))
        if validation_handoff.get("candidate_test_files"):
            result.append(
                "The graph-selected or route-mapped candidate sink tests are rerun with an explicit synthetic credential canary, and assertions prove minimization, masking, or rejection before the sink boundary."
            )
        else:
            result.append(
                "A focused sink-boundary test is retained with an explicit synthetic credential canary because no graph-selected or route-mapped candidate test was available."
            )
        if validation_handoff.get("source_revision_aligned") is not True:
            result.append(
                "Sink test execution and coverage evidence are producer-verified and bound to the replacement source revision before supporting closure."
            )
        if validation_handoff.get("campaign_assurance_prerequisite_met") is not True:
            result.append(
                "Every linked sink-validation campaign resolves scanner execution, trust, and route-reference gaps before its evidence supports closure."
            )
        if validation_handoff.get("test_file_finding_ids"):
            result.append(
                "Findings in candidate sink-validation tests are resolved or governed before their assertions are trusted."
            )
        if validation_handoff.get("cross_owner_test_files") or validation_handoff.get(
            "unowned_test_files"
        ):
            result.append(
                "Candidate sink-validation tests have accountable CODEOWNERS coverage and coordinated sink/test ownership."
            )
        secret_intersections = _bounded_objects(
            sensitive_data_route.get("secret_exposure_intersections"), 25
        )
        if secret_intersections:
            result.extend(
                [
                    "Every redacted secret candidate co-located with this sensitive sink route receives a protected symbol-level flow review; static file-route proximity alone is not accepted as proof of credential flow or disclosure.",
                    "Synthetic credential canaries verify that allowlisting, minimization, masking, or rejection occurs before the cited sensitive boundary, and the replacement report retains the result.",
                ]
            )
            if any(
                str(item.get("temporal_alignment")) == "history-to-current-route"
                for item in secret_intersections
            ):
                result.append(
                    "Historical secret evidence is revision-aligned to this sink route before correlation, and real credentials are rotated with a governed history-remediation decision."
                )
    return result


def _validation_campaign_acceptance(
    campaigns: list[dict[str, Any]],
) -> list[str]:
    result: list[str] = []
    if any(
        campaign.get("test_coverage_alignment") != "aligned-current-evidence"
        for campaign in campaigns
    ):
        result.append(
            "Every linked shared validation campaign has passing observed tests and retained hotspot coverage, or an approved evidence-gap disposition."
        )
    elif campaigns:
        result.append(
            "Linked shared validation campaigns are rerun after remediation and retain their case-level and hotspot-coverage evidence."
        )
    if any(
        _as_object(campaign.get("source_snapshot")).get("evidence_revision_binding")
        in {"mismatch", "unverified", "not-established"}
        for campaign in campaigns
    ):
        result.append(
            "Every linked campaign's retained test and coverage evidence declares the replacement report's sealed source-inventory digest through a valid producer-verified payload-binding receipt."
        )
    if any(
        _as_object(campaign.get("route_evidence_assurance")).get(
            "tool_assurance_prerequisite_met"
        )
        is not True
        for campaign in campaigns
    ):
        result.append(
            "Every linked campaign resolves every retained route and carries completed, integrity-verified, organization-approved evidence for each exact contributing scanner before test results are accepted as closure evidence."
        )
    if any(
        int(
            _as_object(
                _as_object(campaign.get("route_evidence_assurance")).get(
                    "route_statuses"
                )
            ).get("perspective-gap")
            or 0
        )
        > 0
        for campaign in campaigns
    ):
        result.append(
            "Every linked campaign with single-perspective routes adds an independent applicable scanner perspective or retains an approved single-perspective disposition."
        )
    if any(
        _as_object(campaign.get("control_point_context")).get("uncovered_changed_lines")
        for campaign in campaigns
    ):
        result.append(
            "Every linked campaign covers its retained uncovered changed lines or records an approved risk disposition."
        )
    if any(
        factor.get("id") == "runtime-observation-gap"
        for campaign in campaigns
        for factor in _bounded_objects(campaign.get("review_factors"), 20)
    ):
        result.append(
            "Runtime evidence observes each linked changed control point, or the replacement report records an approved runtime-evidence gap."
        )
    if any(campaign["shared_test_hotspot_ids"] for campaign in campaigns):
        result.append(
            "Shared validation-test hotspots have coordinated assertions and an independent-test or approved concentration-risk disposition."
        )
    if any(
        _as_object(campaign.get("shared_test_evidence_quality")).get("assessment")
        in {"weak", "not-established"}
        for campaign in campaigns
    ):
        result.append(
            "Every linked shared test has consistent source-bound passing execution before it is accepted as validation evidence."
        )
    if any(
        _as_object(campaign.get("shared_test_evidence_quality")).get(
            "test_file_finding_ids"
        )
        for campaign in campaigns
    ):
        result.append(
            "Active findings in linked shared-test files are resolved or governed, with reviewer confirmation that fixtures, assertions, and failure handling remain trustworthy."
        )
    if any(
        _as_object(campaign.get("shared_test_evidence_quality")).get(
            "cross_owner_test_files"
        )
        or _as_object(campaign.get("shared_test_evidence_quality")).get(
            "unowned_test_files"
        )
        or _as_object(campaign.get("shared_test_evidence_quality")).get(
            "ownership_not_established_test_files"
        )
        for campaign in campaigns
    ):
        result.append(
            "Every linked shared-test file has accountable CODEOWNERS coverage and coordinated campaign/test ownership before remediation changes are accepted."
        )
    return result


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


def _entry_point_exposure_acceptance(value: dict[str, Any]) -> list[str]:
    result: list[str] = []
    if _nonnegative_integer(value.get("entry_point_exposure_count")) > 1:
        result.append(
            "Focused validation exercises every retained declared entry-point route to the target, or records an approved interface-equivalence disposition."
        )
    if _nonnegative_integer(value.get("entry_point_exposures_omitted")) > 0:
        result.append(
            "The replacement report retains the complete declared entry-point route set without bounded omissions before interface exposure is closed."
        )
    exposures = _closure_entry_point_exposures(value.get("entry_point_exposures"))
    assessments = {
        str(_as_object(item.get("runtime_context")).get("assessment") or "")
        for item in exposures
    }
    if "not-observed" in assessments:
        result.append(
            "Every previously unobserved declared interface is exercised by retained production-representative runtime evidence, or has an approved interface-equivalence disposition."
        )
    if "not-available" in assessments:
        result.append(
            "Every declared interface is joined to its exact reachability node and a retained runtime-observation assessment in the replacement report."
        )
    return result


def _closure_route_ownership(value: Any) -> dict[str, Any]:
    ownership = _as_object(value)
    if not ownership:
        return {}
    records = [
        {
            "path": str(item.get("path") or "unknown"),
            "owners": _string_values(item.get("owners"), 20),
            "roles": _string_values(item.get("roles"), 3),
            "entry_point_exposure_ids": _string_values(
                item.get("entry_point_exposure_ids"), 25
            ),
        }
        for item in _object_list(ownership.get("file_records"), "route owner files")[
            :225
        ]
    ]
    boundaries = [
        {
            "boundary_id": str(item.get("boundary_id") or "unknown"),
            "source": str(item.get("source") or "unknown"),
            "target": str(item.get("target") or "unknown"),
            "source_owners": _string_values(item.get("source_owners"), 20),
            "target_owners": _string_values(item.get("target_owners"), 20),
            "entry_point_exposure_ids": _string_values(
                item.get("entry_point_exposure_ids"), 25
            ),
        }
        for item in _object_list(
            ownership.get("boundaries"), "route ownership boundaries"
        )[:200]
    ]
    return {
        "evidence_available": ownership.get("evidence_available") is True,
        "ownership_rules": _nonnegative_integer(ownership.get("ownership_rules")),
        "file_records": records,
        "boundaries": boundaries,
        "boundary_count": len(boundaries),
        "distinct_owners": _string_values(ownership.get("distinct_owners"), 100),
        "target_owners": _string_values(ownership.get("target_owners"), 20),
        "coordination_owners": _string_values(
            ownership.get("coordination_owners"), 100
        ),
        "target_owner_alignment": str(
            ownership.get("target_owner_alignment") or "not-established"
        ),
        "unowned_files": _string_values(ownership.get("unowned_files"), 225),
        "coordination_status": str(
            ownership.get("coordination_status") or "not-established"
        ),
        "recommended_action": str(
            ownership.get("recommended_action") or "Establish route ownership evidence."
        ),
        "evidence_artifacts": _string_values(ownership.get("evidence_artifacts"), 10),
    }


def _route_ownership_acceptance(value: dict[str, Any]) -> list[str]:
    if not value:
        return []
    status = str(value.get("coordination_status") or "not-established")
    result: list[str] = []
    if value.get("evidence_available") is not True:
        result.append(
            "Bounded CODEOWNERS evidence assigns every retained route file before cross-file remediation responsibility is closed."
        )
    if status == "unowned-segment":
        result.append(
            "Every previously unowned entry, transit, and target file has a retained CODEOWNERS assignment in the replacement report."
        )
    if status in {"cross-owner", "unowned-segment"}:
        result.append(
            "Every retained ownership handoff records coordinated remediation review and post-change regression evidence from the responsible route owners."
        )
    if value.get("target_owner_alignment") in {
        "mismatch",
        "target-owner-not-attributed",
        "target-unowned",
    }:
        result.append(
            "The target finding owner and exact-path CODEOWNERS assignment agree, or the replacement disposition explains and governs the mismatch."
        )
    return result


def _closure_change_lifecycle_attribution(value: Any) -> dict[str, Any]:
    attribution = _as_object(value)
    if not attribution:
        return {}
    return {
        "baseline_state": str(attribution.get("baseline_state") or "not-established"),
        "baseline_configured": attribution.get("baseline_configured") is True,
        "baseline_comparable": attribution.get("baseline_comparable") is True,
        "baseline_reasons": _string_values(attribution.get("baseline_reasons"), 20),
        "lifecycle_status": str(attribution.get("lifecycle_status") or "unclassified"),
        "baseline_match": _as_object(attribution.get("baseline_match")),
        "change_scope": str(attribution.get("change_scope") or "not-established"),
        "classification": str(
            attribution.get("classification") or "baseline-not-established"
        ),
        "review_signal": str(
            attribution.get("review_signal") or "baseline-not-established"
        ),
        "validation_status": str(
            attribution.get("validation_status") or "not-assessed"
        ),
        "evidence_assurance_status": str(
            attribution.get("evidence_assurance_status") or "not-assessed"
        ),
        "entry_point_runtime_statuses": _as_object(
            attribution.get("entry_point_runtime_statuses")
        ),
        "review_factors": _string_values(attribution.get("review_factors"), 20),
        "evidence_artifacts": _string_values(attribution.get("evidence_artifacts"), 10),
        "recommended_action": str(
            attribution.get("recommended_action")
            or "Establish comparable finding lifecycle evidence."
        ),
    }


def _change_lifecycle_acceptance(value: dict[str, Any]) -> list[str]:
    if not value:
        return []
    baseline_state = str(value.get("baseline_state") or "not-established")
    signal = str(value.get("review_signal") or "baseline-not-established")
    result: list[str] = []
    if baseline_state != "comparable":
        result.append(
            "Any claim that this finding was introduced or regressed by the current change is backed by a digest-approved comparable findings baseline; otherwise the disposition explicitly records that change origin is not established."
        )
    if signal == "baseline-new-or-regressed-change-gap":
        result.append(
            "The exact baseline-new or regressed changed-line finding is resolved or governed, and replacement focused-test plus coverage evidence reports aligned validation."
        )
    elif signal == "baseline-new-or-regressed-change-aligned":
        result.append(
            "The exact baseline-new or regressed changed-line finding is resolved or governed, and its aligned change-specific validation is retained after remediation."
        )
    elif signal == "baseline-new-or-regressed-outside-change":
        result.append(
            "Disposition does not attribute the baseline-new or regressed finding to the retained change scope without exact changed-line evidence."
        )
    elif signal == "existing-change-gap":
        result.append(
            "The modified pre-existing finding is reviewed for risk amplification and its linked change-specific validation gap is closed or governed."
        )
    return result


def _closure_evidence_assurance(value: Any) -> dict[str, Any]:
    assurance = _as_object(value)
    records = [
        {
            "tool": str(item.get("tool") or "unknown"),
            "status": str(item.get("status") or "unknown"),
            "evidence_lane": str(item.get("evidence_lane") or "other"),
            "normalized_findings": item.get("normalized_findings"),
            "unique_normalized_findings": item.get("unique_normalized_findings"),
            "executable_integrity_verified": item.get("executable_integrity_verified"),
            "executable_organization_approved": item.get(
                "executable_organization_approved"
            )
            is True,
            "executable_unchanged": item.get("executable_unchanged"),
            "auxiliary_executable_present": item.get("auxiliary_executable_present")
            is True,
            "auxiliary_executable_integrity_verified": item.get(
                "auxiliary_executable_integrity_verified"
            ),
            "auxiliary_executable_organization_approved": item.get(
                "auxiliary_executable_organization_approved"
            ),
            "auxiliary_executable_unchanged": item.get(
                "auxiliary_executable_unchanged"
            ),
            "assurance_status": str(item.get("assurance_status") or "unknown"),
        }
        for item in _object_list(
            assurance.get("tool_records"), "route tool evidence records"
        )[:25]
    ]
    return {
        "review_status": str(assurance.get("review_status") or "not-assessed"),
        "origin": str(assurance.get("origin") or "derived-analysis"),
        "perspective_assessment": str(
            assurance.get("perspective_assessment") or "not-established"
        ),
        "corroboration": assurance.get("corroboration"),
        "contributing_tools": _string_values(assurance.get("contributing_tools"), 25),
        "supporting_tools": _string_values(assurance.get("supporting_tools"), 25),
        "evidence_lanes": _string_values(assurance.get("evidence_lanes"), 25),
        "tool_records": records,
        "completed_tools": _string_values(assurance.get("completed_tools"), 25),
        "approved_tools": _string_values(assurance.get("approved_tools"), 25),
        "trust_gap_tools": _string_values(assurance.get("trust_gap_tools"), 25),
        "execution_gap_tools": _string_values(assurance.get("execution_gap_tools"), 25),
        "unassessed_tools": _string_values(assurance.get("unassessed_tools"), 25),
        "recommended_action": str(
            assurance.get("recommended_action") or "Establish route evidence assurance."
        ),
    }


def _evidence_assurance_acceptance(value: dict[str, Any]) -> list[str]:
    status = str(value.get("review_status") or "not-assessed")
    if status == "execution-gap":
        return [
            "Every contributing scanner completes and its normalized evidence is retained in the replacement report."
        ]
    if status == "trust-gap":
        return [
            "Every contributing scanner entry point and required helper is integrity-verified, unchanged during execution, and organization-approved in the replacement report."
        ]
    if status == "perspective-gap":
        return [
            "An independent applicable analysis validates the target, or a governed rationale records why the retained single perspective is sufficient."
        ]
    if status == "not-assessed":
        return [
            "The replacement report retains completion, integrity, continuity, and organization-approval posture for every contributing tool."
        ]
    if status == "derived-analysis":
        return [
            "The suite-derived correlation is reviewed against its cited source evidence and is not counted as an independent scanner observation."
        ]
    return [
        "Approved contributing scanner perspectives are rerun after remediation and remain bound to the replacement report."
    ]


def _dependency_route_acceptance(
    dependency_routes: list[dict[str, Any]],
) -> list[str]:
    result = [
        "Every linked dependency-advisory importer is reviewed for vulnerable-function invocation from its declared entry-point route; static import reachability alone is not used as exploitability proof.",
        "The affected dependency is upgraded, removed, mitigated, or covered by a governed VEX disposition, and focused importer tests are rerun with replacement evidence.",
    ]
    if any(item["fix_available"] for item in dependency_routes):
        result.append(
            "A retained fixed-version candidate is applied or an explicit exception records why it is not applicable."
        )
    if any(item["uncovered_changed_lines"] for item in dependency_routes):
        result.append(
            "Focused importer validation covers every retained uncovered changed line, or the replacement report records an approved coverage disposition."
        )
    result.extend(_package_lifecycle_acceptance(dependency_routes))
    assurance_statuses = {
        str(_as_object(item.get("evidence_assurance")).get("review_status") or "")
        for item in dependency_routes
    }
    for status in sorted(assurance_statuses):
        if status:
            result.extend(_evidence_assurance_acceptance({"review_status": status}))
    if any(
        _nonnegative_integer(item.get("entry_point_exposure_count")) > 1
        for item in dependency_routes
    ):
        result.append(
            "Dependency remediation validation covers every retained declared entry-point route to each exact importer, or records an approved interface-equivalence disposition."
        )
    return result


def _closure_entry_point_exposures(value: Any) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for item in _object_list(value, "entry-point exposures")[:25]:
        edges = [
            {
                "source": str(edge.get("source") or "unknown"),
                "target": str(edge.get("target") or "unknown"),
                "relation": str(edge.get("relation") or "unknown"),
            }
            for edge in _object_list(item.get("edges"), "entry-point exposure edges")[
                :8
            ]
        ]
        result.append(
            {
                "exposure_id": str(item.get("exposure_id") or "unknown"),
                "primary": item.get("primary") is True,
                "entry_point": _as_object(item.get("entry_point")),
                "runtime_context": _as_object(item.get("runtime_context")),
                "hop_count": item.get("hop_count"),
                "files": _string_values(item.get("files"), 9),
                "edges": edges,
            }
        )
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


def _advanced_analysis_items(advanced: dict[str, Any]) -> list[dict[str, Any]]:
    if (
        advanced.get("schema_id")
        != "urn:project-py-security-suite:advanced-analysis:1.0"
    ):
        return []
    items: list[dict[str, Any]] = []
    for control in _bounded_objects(advanced.get("control_topology"), 500):
        status = str(control.get("topology_status") or "unknown")
        if status not in {"bypass-capable", "not-established"}:
            continue
        identifier = str(control.get("control_point_id") or "unknown")
        evidence_gap = status == "not-established"
        items.append(
            _advanced_item(
                key=f"advanced:control:{identifier}",
                priority="P2" if evidence_gap else "P1",
                owner=_advanced_owner(control),
                title=(
                    f"Establish route-scoped control topology at {control.get('path') or 'unknown'}"
                    if evidence_gap
                    else f"Resolve bypass-capable candidate control at {control.get('path') or 'unknown'}"
                ),
                why=(
                    "The retained route entry could not be mapped to a Graphify path "
                    "that reaches the target, so control dominance is unknown."
                    if evidence_gap
                    else "An alternate retained Graphify path reaches one or more "
                    "review targets without crossing the candidate control point."
                ),
                action=str(
                    control.get("recommended_action") or "Review alternate paths."
                ),
                acceptance=[
                    "The replacement advanced analysis maps every retained route entry to the reviewed graph and classifies the point as mandatory, bypass-capable, or absent from the route."
                    if evidence_gap
                    else "The replacement advanced analysis classifies the point as mandatory, or every alternate path has an equivalent reviewed control and focused negative test.",
                    "The decision retains exact route, target, owner, and test evidence without claiming exploitability from topology alone.",
                ],
                details={
                    "control_point_id": identifier,
                    "path": control.get("path"),
                    "topology_status": status,
                },
            )
        )
    for artifact in _bounded_objects(advanced.get("artifact_route_parity"), 500):
        artifact_name = str(artifact.get("artifact") or "unknown")
        for entry in _bounded_objects(artifact.get("published_entry_points"), 500):
            if entry.get("parity_status") == "modeled-entry-point":
                continue
            subject = (
                f"{entry.get('group') or 'entry'}:{entry.get('name') or 'unknown'}"
            )
            items.append(
                _advanced_item(
                    key=f"advanced:artifact-entry:{artifact_name}:{subject}",
                    priority="P1",
                    owner="release-engineering",
                    title=f"Model published artifact entry point {subject}",
                    why=f"{artifact_name} publishes {entry.get('target') or 'an unknown target'} with parity status {entry.get('parity_status') or 'unknown'}.",
                    action=str(
                        entry.get("recommended_action")
                        or artifact.get("recommended_action")
                        or "Model the activation surface."
                    ),
                    acceptance=[
                        "The rebuilt digest-bound artifact publishes only reviewed entry points.",
                        "Every production command or plugin is present in the source graph and declared reachability model.",
                    ],
                    details={"artifact": artifact_name, "entry_point": entry},
                )
            )
        items.extend(_advanced_wheel_record_items(artifact_name, artifact))
    items.extend(_advanced_privacy_items(advanced))
    items.extend(_advanced_dependency_items(advanced))
    items.extend(_advanced_traceability_items(advanced))
    items.extend(_advanced_mutation_items(advanced))
    return items[:500]


def _advanced_wheel_record_items(
    artifact_name: str, artifact: dict[str, Any]
) -> list[dict[str, Any]]:
    return [
        _advanced_item(
            key=f"advanced:wheel-record:{artifact_name}:{gap.get('kind')}:{gap.get('path') or gap.get('detail')}",
            priority="P1",
            owner="release-engineering",
            title=f"Resolve wheel RECORD gap in {artifact_name}",
            why=f"{gap.get('kind') or 'identity-gap'}: {gap.get('path') or gap.get('detail') or 'unspecified member'}",
            action=str(
                artifact.get("recommended_action") or "Rebuild and verify the wheel."
            ),
            acceptance=[
                "The rebuilt wheel has exactly one RECORD and every required member has matching size and SHA-256 identity.",
                "The replacement artifact manifest binds the exact wheel digest.",
            ],
            details={"artifact": artifact_name, "record_gap": gap},
        )
        for gap in _bounded_objects(artifact.get("record_gaps"), 500)
    ]


def _advanced_privacy_items(advanced: dict[str, Any]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for route in _bounded_objects(advanced.get("telemetry_privacy_topology"), 500):
        status = str(route.get("review_status") or "unknown")
        if status == "protected-static-route":
            continue
        identifier = str(route.get("privacy_route_id") or "unknown")
        result.append(
            _advanced_item(
                key=f"advanced:privacy:{identifier}:{status}",
                priority="P1"
                if status in {"redaction-order-risk", "protection-gap"}
                else "P2",
                owner=_advanced_owner(route),
                title=f"Resolve telemetry privacy route at {route.get('path') or 'unknown'}",
                why=f"Telemetry privacy review status is {status}; protection is {route.get('protection_status') or 'unknown'} and redaction ordering is {route.get('redaction_order') or 'not-established'}.",
                action=str(
                    route.get("recommended_action") or "Protect and validate the route."
                ),
                acceptance=[
                    "Minimization and redaction occur before every applicable exporter branch.",
                    "A source-bound synthetic sensitive-data canary test proves the replacement exporter output omits protected values.",
                ],
                details={
                    "privacy_route_id": identifier,
                    "review_status": status,
                    "path": route.get("path"),
                    "line": route.get("line"),
                },
            )
        )
    return result


def _advanced_dependency_items(advanced: dict[str, Any]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for route in _bounded_objects(advanced.get("dependency_trust_routes"), 500):
        tier = str(route.get("review_tier") or "low")
        if tier not in {"critical", "high"}:
            continue
        identifier = str(route.get("dependency_trust_route_id") or "unknown")
        result.append(
            _advanced_item(
                key=f"advanced:dependency:{identifier}:{tier}",
                priority="P0" if tier == "critical" else "P1",
                owner=_advanced_owner(route),
                title=f"Resolve elevated dependency trust route for {route.get('package') or 'unknown'}",
                why="Risk factors: "
                + ", ".join(_string_values(route.get("risk_factors"), 50)),
                action=str(
                    route.get("recommended_action")
                    or "Upgrade and rebuild the artifact."
                ),
                acceptance=[
                    "The exact importer and final artifact contain an approved fixed package version or an independently reviewed contextual disposition.",
                    "Replacement route, SBOM, advisory, provenance, scanner-assurance, and validation evidence are complete and digest-bound.",
                ],
                details={
                    "dependency_trust_route_id": identifier,
                    "package": route.get("package"),
                    "review_tier": tier,
                    "risk_factors": route.get("risk_factors"),
                },
            )
        )
    return result


def _advanced_traceability_items(advanced: dict[str, Any]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for trace in _bounded_objects(
        advanced.get("threat_control_test_traceability"), 500
    ):
        status = str(trace.get("closure_status") or "unknown")
        if status == "mapped-control-and-test":
            continue
        identifier = str(trace.get("traceability_id") or "unknown")
        result.append(
            _advanced_item(
                key=f"advanced:threat-trace:{identifier}:{status}",
                priority=(
                    "P1" if status == "threat-without-control-evidence" else "P2"
                ),
                owner=_advanced_owner(trace),
                title=f"Close threat traceability gap for {trace.get('threat_finding_id') or 'unknown'}",
                why=(
                    f"Threat-control-test traceability is {status} at "
                    f"{trace.get('path') or 'the repository boundary'}."
                ),
                action=str(
                    trace.get("recommended_action")
                    or "Map the threat to an enforcing control and abuse-case test."
                ),
                acceptance=[
                    "The threat is mapped to an exact enforcing control and focused abuse-case or negative test.",
                    "A source-bound passing test contains an explicitly reviewed abuse-case or negative assertion for the mapped threat; selection, execution, and line coverage alone are insufficient.",
                ],
                details={
                    "traceability_id": identifier,
                    "threat_finding_id": trace.get("threat_finding_id"),
                    "closure_status": status,
                    "path": trace.get("path"),
                    "line": trace.get("line"),
                },
            )
        )
    return result


def _advanced_mutation_items(advanced: dict[str, Any]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for mutation in _bounded_objects(advanced.get("security_mutation_leverage"), 500):
        identifier = str(mutation.get("mutation_leverage_id") or "unknown")
        result.append(
            _advanced_item(
                key=f"advanced:security-mutation:{identifier}",
                priority="P1",
                owner=_advanced_owner(mutation),
                title=f"Kill surviving security mutation at {mutation.get('path') or 'unknown'}",
                why=(
                    "A mutation in security-relevant control code survived the retained "
                    "test run, so expected failure behavior is not demonstrated."
                ),
                action=str(
                    mutation.get("recommended_action")
                    or "Add a focused negative test and rerun mutation analysis."
                ),
                acceptance=[
                    "A focused negative test fails when the cited control mutation is present.",
                    "The replacement mutation report no longer lists the mutation as surviving and remains digest-bound to the scanned source.",
                ],
                details={
                    "mutation_leverage_id": identifier,
                    "finding_id": mutation.get("finding_id"),
                    "validation_signal": mutation.get("validation_signal"),
                    "path": mutation.get("path"),
                    "line": mutation.get("line"),
                    "test_files": mutation.get("test_files"),
                },
            )
        )
    return result


def _advanced_item(
    *,
    key: str,
    priority: str,
    owner: str,
    title: str,
    why: str,
    action: str,
    acceptance: list[str],
    details: dict[str, Any],
) -> dict[str, Any]:
    return _item(
        key=key,
        priority=priority,
        category="architecture",
        authority="repository",
        status="review",
        owner=owner,
        title=title,
        why=why,
        action=action,
        acceptance=acceptance,
        evidence_refs=["advanced-analysis.json", "risk-paths.json"],
        details={"advanced_analysis": True, **details},
    )


def _advanced_owner(value: dict[str, Any]) -> str:
    owners = _string_values(value.get("owners"), 100)
    return owners[0] if owners else "repository-maintainers"


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
        value = strict_json_loads(payload)
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


def _bounded_objects(value: Any, limit: int) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value[:limit] if isinstance(item, dict)]


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


def _nonnegative_integer(value: Any) -> int:
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return value
    return 0


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
