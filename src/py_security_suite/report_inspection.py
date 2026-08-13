from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from importlib.resources import files
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit

from .execution import sanitize_terminal_text
from .models import Outcome
from .passport import verify_report
from .path_safety import resolve_unlinked_path
from .prioritization import finding_order_key, finding_priority


_MAX_JSON_BYTES = 128 * 1024 * 1024
_INSPECTION_SCHEMA_ID = "urn:project-py-security-suite:schema:report-inspection:1.3"
_INSPECTION_VERIFICATION_SCHEMA_ID = (
    "urn:project-py-security-suite:schema:report-inspection-verification:1.3"
)
_REPORT_VERIFICATION_SCHEMA_ID = (
    "urn:project-py-security-suite:schema:report-verification:1.0"
)
BUNDLED_SCHEMA_RESOURCES = {
    "data-exposure-1.0": "data-exposure-1.0.schema.json",
    "data-exposure-1.1": "data-exposure-1.1.schema.json",
    "data-exposure-1.2": "data-exposure-1.2.schema.json",
    "data-exposure-1.3": "data-exposure-1.3.schema.json",
    "data-exposure-1.4": "data-exposure-1.4.schema.json",
    "data-exposure-1.5": "data-exposure-1.5.schema.json",
    "evidence-fusion-1.0": "evidence-fusion-1.0.schema.json",
    "evidence-fusion-1.1": "evidence-fusion-1.1.schema.json",
    "evidence-fusion-1.2": "evidence-fusion-1.2.schema.json",
    "evidence-fusion-1.3": "evidence-fusion.schema.json",
    "graphify-evidence-1.0": "graphify-evidence.schema.json",
    "graph-analysis-1.0": "graph-analysis.schema.json",
    "structural-synthesis-1.0": "structural-synthesis.schema.json",
    "structural-synthesis-1.1": "structural-synthesis-1.1.schema.json",
    "structural-synthesis-1.2": "structural-synthesis-1.2.schema.json",
    "adapter-conformance-1.0": "adapter-conformance.schema.json",
    "bundle-qualification-1.0": "bundle-qualification.schema.json",
    "bundle-qualification-1.1": "bundle-qualification-1.1.schema.json",
    "native-bundle-verification-1.0": "native-bundle-verification.schema.json",
    "config-advice-1.0": "config-advice.schema.json",
    "github-workflow-1.0": "github-workflow.schema.json",
    "precommit-config-1.0": "precommit-config.schema.json",
    "project-init-1.0": "project-init.schema.json",
    "doctor-readiness-1.1": "doctor-readiness-1.1.schema.json",
    "provision-plan-1.0": "provision-plan.schema.json",
    "admission-decisions-1.0": "admission-decisions.schema.json",
    "evidence-pack-1.0": "evidence-pack.schema.json",
    "evidence-pack-verification-1.0": "evidence-pack-verification.schema.json",
    "baseline-candidate-1.0": "baseline-candidate.schema.json",
    "effectiveness-corpus-1.0": "effectiveness-corpus.schema.json",
    "effectiveness-evaluation-1.0": "effectiveness-evaluation.schema.json",
    "scanner-trust-catalog-1.0": "scanner-trust-catalog.schema.json",
    "portfolio-health-1.0": "portfolio-health.schema.json",
    "portfolio-health-1.1": "portfolio-health-1.1.schema.json",
    "source-inventory-1.0": "source-inventory.schema.json",
    "isolation-attestation-1.0": "isolation-attestation.schema.json",
    "intelligence-approval-1.0": "intelligence-approval.schema.json",
    "release-readiness-1.0": "release-readiness.schema.json",
    "release-readiness-1.1": "release-readiness-1.1.schema.json",
    "release-readiness-1.2": "release-readiness-1.2.schema.json",
    "release-readiness-1.3": "release-readiness-1.3.schema.json",
    "governance-evidence-draft-1.0": "governance-evidence-draft.schema.json",
    "signing-request-1.0": "signing-request.schema.json",
    "signing-request-verification-1.0": "signing-request-verification.schema.json",
    "promotion-plan-1.0": "promotion-plan.schema.json",
    "promotion-plan-1.1": "promotion-plan-1.1.schema.json",
    "operational-trend-1.0": "operational-trend.schema.json",
    "operational-trend-1.1": "operational-trend-1.1.schema.json",
    "operational-trend-1.2": "operational-trend-1.2.schema.json",
    "release-evidence-manifest-1.0": "release-evidence-manifest.schema.json",
    "release-evidence-manifest-verification-1.0": "release-evidence-manifest-verification.schema.json",
    "policy-simulation-1.0": "policy-simulation.schema.json",
    "finding-register-1.0": "finding-register.schema.json",
    "github-annotations-1.0": "github-annotations.schema.json",
    "audit-package-verification-1.0": "audit-package-verification.schema.json",
    "coverage-merge-1.0": "coverage-merge.schema.json",
    "portfolio-dashboard-1.0": "portfolio-dashboard.schema.json",
    "config-provenance-1.0": "config-provenance.schema.json",
    "closure-plan-1.0": "closure-plan-1.0.schema.json",
    "closure-plan-1.1": "closure-plan-1.1.schema.json",
    "closure-plan-1.2": "closure-plan.schema.json",
    "reproducible-build-1.0": "reproducible-build.schema.json",
    "sdist-normalization-1.0": "sdist-normalization.schema.json",
    "audience-report-1.0": "audience-report.schema.json",
    "reachability-delta-1.0": "reachability-delta.schema.json",
    "report-inspection-1.0": "report-inspection.schema.json",
    "report-inspection-1.1": "report-inspection-1.1.schema.json",
    "report-inspection-1.2": "report-inspection-1.2.schema.json",
    "report-inspection-1.3": "report-inspection-1.3.schema.json",
    "report-inspection-verification-1.0": (
        "report-inspection-verification.schema.json"
    ),
    "report-inspection-verification-1.1": (
        "report-inspection-verification-1.1.schema.json"
    ),
    "report-inspection-verification-1.2": (
        "report-inspection-verification-1.2.schema.json"
    ),
    "report-inspection-verification-1.3": (
        "report-inspection-verification-1.3.schema.json"
    ),
    "report-verification-1.0": "report-verification.schema.json",
}
_POLICY_DISPOSITIONS = {
    Outcome.PASS: "allow",
    Outcome.WARN: "review",
    Outcome.FAIL: "block",
    Outcome.INCOMPLETE: "block",
}


def read_bundled_schema(name: str) -> str:
    """Return an installed, version-explicit JSON Schema without network access."""
    try:
        resource_name = BUNDLED_SCHEMA_RESOURCES[name]
    except KeyError as exc:
        choices = ", ".join(sorted(BUNDLED_SCHEMA_RESOURCES))
        raise ValueError(f"unknown schema {name!r}; choose one of: {choices}") from exc
    resource = files("py_security_suite").joinpath("schemas", resource_name)
    return resource.read_text(encoding="utf-8").rstrip("\r\n")


def report_verification_receipt(verification: dict[str, Any]) -> dict[str, Any]:
    """Add the stable contract identity to a verified report result."""
    return {
        "schema_version": "1.0",
        "schema_id": _REPORT_VERIFICATION_SCHEMA_ID,
        "verified": verification["verified"],
        "file_count": verification["file_count"],
        "checksums_sha256": verification["checksums_sha256"],
        "scan_id": verification["scan_id"],
        "outcome": verification["outcome"],
    }


def inspect_report(report: Path, *, limit: int = 5) -> dict[str, Any]:
    """Verify and summarize a report without trusting its HTML or Markdown."""
    if limit < 0 or limit > 100:
        raise ValueError("inspection limit must be between 0 and 100")
    verification = verify_report(report)
    root = report.expanduser().absolute().resolve()
    manifest = _read_object(root / "scan-manifest.json")
    findings_document = _read_object(root / "findings.json")
    findings = _object_list(findings_document.get("findings"), "findings")
    tools = _object_list(manifest.get("tools"), "tools")
    outcome, policy_reasons = _policy_metadata(manifest)
    policy_reasons = [_safe_text(reason) for reason in policy_reasons]
    sorted_findings = sorted(findings, key=_finding_key)
    top_actions = [_action(item) for item in sorted_findings[:limit]]
    action_summary = _action_summary(len(sorted_findings), len(top_actions), limit)
    return {
        "schema_version": "1.3",
        "schema_id": _INSPECTION_SCHEMA_ID,
        "verified": True,
        "scan": _scan_summary(manifest, outcome),
        "findings": _findings_summary(findings),
        "tool_health": _tool_health(tools),
        "entrypoint_integrity": _entrypoint_integrity(tools),
        "scan_policy": {
            "disposition": _POLICY_DISPOSITIONS[Outcome(outcome)],
            "reasons": policy_reasons,
        },
        # Retain the original field for consumers of the 1.0 inspection shape.
        "policy_reasons": policy_reasons,
        "action_summary": action_summary,
        "top_actions": top_actions,
        "integrity": {
            "status": "verified",
            "files_verified": verification["file_count"],
            "checksums_sha256": verification["checksums_sha256"],
        },
        "entrypoints": _entrypoints(),
    }


def verify_inspection(
    inspection: Path, *, report: Path, limit: int = 5
) -> dict[str, Any]:
    """Verify that an exported inspection exactly describes a sealed report."""
    requested = inspection.expanduser().absolute()
    source = resolve_unlinked_path(
        requested,
        "inspection document",
        boundary=Path(requested.anchor),
    )
    document, payload = _read_object_payload(source)
    actions = _object_list(document.get("top_actions"), "inspection top_actions")
    expected = inspect_report(report, limit=limit)
    if document != expected:
        raise ValueError("inspection document does not match the verified report")
    return {
        "schema_version": "1.3",
        "schema_id": _INSPECTION_VERIFICATION_SCHEMA_ID,
        "verified": True,
        "inspection_schema_id": str(expected["schema_id"]),
        "scan_id": str(expected["scan"]["id"]),
        "inspection_sha256": hashlib.sha256(payload).hexdigest(),
        "report_checksums_sha256": str(expected["integrity"]["checksums_sha256"]),
        "action_limit": limit,
        "top_actions_verified": len(actions),
        "action_summary": expected["action_summary"],
    }


def _object_list(value: object, name: str) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise ValueError(f"report {name} must be a list of objects")
    return value


def _policy_metadata(manifest: dict[str, Any]) -> tuple[str, list[str]]:
    outcome = str(manifest.get("outcome") or "")
    try:
        parsed_outcome = Outcome(outcome)
    except ValueError as exc:
        raise ValueError("report outcome is invalid") from exc
    reasons = manifest.get("policy_reasons") or []
    if not isinstance(reasons, list) or not all(
        isinstance(item, str) for item in reasons
    ):
        raise ValueError("report policy reasons must be a list of strings")
    return parsed_outcome.value, reasons


def _scan_summary(manifest: dict[str, Any], outcome: str) -> dict[str, Any]:
    return {
        "id": _safe_text(manifest.get("scan_id")),
        "target": _safe_text(manifest.get("target")),
        "profile": _safe_text(manifest.get("profile")),
        "outcome": outcome,
        "duration_seconds": manifest.get("duration_seconds"),
        "finished_at": _safe_text(manifest.get("finished_at")),
    }


def _findings_summary(findings: list[dict[str, Any]]) -> dict[str, Any]:
    severity = Counter(
        _safe_text(item.get("severity") or "unknown") for item in findings
    )
    domains = Counter(_safe_text(item.get("domain") or "unknown") for item in findings)
    lifecycle = Counter(
        _safe_text(item.get("status") or "unknown") for item in findings
    )
    return {
        "total": len(findings),
        "blocking": sum(bool(item.get("blocking")) for item in findings),
        "by_severity": dict(sorted(severity.items())),
        "by_domain": dict(sorted(domains.items())),
        "by_lifecycle": dict(sorted(lifecycle.items())),
    }


def _entrypoints() -> dict[str, str]:
    return {
        "html": "index.html",
        "summary": "summary.md",
        "action_plan": "action-plan.md",
    }


def render_inspection(
    document: dict[str, Any], *, report_root: Path | None = None
) -> str:
    """Render a compact summary suited to terminals and release logs."""
    scan = document["scan"]
    findings = document["findings"]
    health = document["tool_health"]
    entrypoints = document["entrypoint_integrity"]
    integrity = document["integrity"]
    policy = document["scan_policy"]
    lines = [
        (
            f"{str(scan['outcome']).upper()}: {scan['target']} "
            f"({scan['profile']}; {scan['id']})"
        ),
        (
            f"Decision: {str(policy['disposition']).upper()}; report integrity: "
            f"{str(integrity['status']).upper()} ({integrity['files_verified']} files)"
        ),
        (
            f"Findings: {findings['total']} total, {findings['blocking']} blocking; "
            f"severity {_counts(findings['by_severity'])}"
        ),
        (
            f"Tools: {health['completed']}/{health['applicable']} applicable completed; "
            f"{health['not_applicable']} not applicable; "
            f"{health['execution_gaps']} execution gaps"
        ),
        (
            f"Entrypoints: {entrypoints['approved_and_unchanged']}/"
            f"{entrypoints['observed']} approved and unchanged; "
            f"{entrypoints['unchanged_after_execution']}/"
            f"{entrypoints['observed']} unchanged after execution"
        ),
        f"Domains: {_counts(findings['by_domain'])}",
        f"Lifecycle: {_counts(findings['by_lifecycle'])}",
    ]
    approval_gaps = entrypoints["approval_gap_entrypoints"]
    if approval_gaps:
        lines.append(
            "Trust action: approve digests for " + _bounded_names(approval_gaps)
        )
    postcheck_gaps = entrypoints["postcheck_gap_entrypoints"]
    if postcheck_gaps:
        lines.append(
            "Trust action: restore post-checks for " + _bounded_names(postcheck_gaps)
        )
    approval_candidates = entrypoints["approval_candidate_entrypoints"]
    if approval_candidates:
        binding_label = "binding" if approval_candidates == 1 else "bindings"
        unique_digests = entrypoints["approval_candidate_unique_digests"]
        digest_label = "digest" if unique_digests == 1 else "digests"
        lines.append(
            f"Approval workload: {approval_candidates} candidate {binding_label} "
            f"across {unique_digests} unique {digest_label}"
        )
    reasons = policy["reasons"]
    if reasons:
        lines.append("Policy reasons:")
        lines.extend(f"- {_safe_text(reason)}" for reason in reasons)
    action_summary = document["action_summary"]
    actions = document["top_actions"]
    if actions:
        header = (
            f"Top actions ({action_summary['returned']} of "
            f"{action_summary['available']}"
        )
        if action_summary["truncated"]:
            header += (
                f"; {action_summary['omitted']} omitted by limit "
                f"{action_summary['limit']}"
            )
        lines.append(header + "):")
        for item in actions:
            lines.extend(_render_action(item, report_root=report_root))
    elif action_summary["available"]:
        lines.append(
            f"Top actions: 0 of {action_summary['available']} shown; "
            f"{action_summary['omitted']} omitted by limit "
            f"{action_summary['limit']}"
        )
    else:
        lines.append("Top actions: none")
    lines.extend(
        [
            "Open: "
            + _local_artifact_reference(document["entrypoints"]["html"], report_root),
            "Actions: "
            + _local_artifact_reference(
                document["entrypoints"]["action_plan"], report_root
            ),
        ]
    )
    return "\n".join(lines)


def _render_action(
    item: dict[str, Any], *, report_root: Path | None = None
) -> list[str]:
    risk_label = (
        f"{item['priority']} {str(item['severity']).upper()}/"
        f"{str(item['status']).upper()}"
    )
    lines = [
        f"- [{risk_label}] {item['title']} | {_action_location(item)}",
        "  Context: " + _action_context(item),
    ]
    if item["description"]:
        lines.append(f"  Summary: {item['description']}")
    if item["impact"]:
        lines.append(f"  Impact: {item['impact']}")
    lines.append("  Evidence: " + "; ".join(_action_evidence(item)))
    lines.extend(
        f"  Reference: {_reference_text(citation)}" for citation in item["citations"]
    )
    if item["remediation"]:
        lines.append(f"  Action: {item['remediation']}")
    lines.append("  Review: " + _local_artifact_reference(item["details"], report_root))
    return lines


def _action_context(item: dict[str, Any]) -> str:
    decision = "blocking" if item["blocking"] else "non-blocking"
    return (
        f"{decision}; area {item['area']}; confidence {str(item['confidence']).lower()}"
    )


def _local_artifact_reference(value: object, report_root: Path | None) -> str:
    reference = _safe_text(value)
    if report_root is None:
        return reference
    path_text, separator, fragment = reference.partition("#")
    relative = Path(path_text)
    if relative.is_absolute() or ".." in relative.parts:
        return reference
    root = report_root.expanduser().absolute().resolve()
    resolved = (root / relative).resolve()
    if not resolved.is_relative_to(root):
        return reference
    return f"{resolved}{separator}{fragment}"


def _action_location(item: dict[str, Any]) -> str:
    location = str(item["path"])
    return f"{location}:{item['line']}" if item["line"] is not None else location


def _action_evidence(item: dict[str, Any]) -> list[str]:
    evidence = [f"finding {item['finding_id']}", *item["source_rules"]]
    if item["classifications"]:
        evidence.append("classification " + ", ".join(item["classifications"]))
    if item["owners"]:
        evidence.append("owner " + ", ".join(item["owners"]))
    artifact = item["artifact_identity"]
    if artifact is not None:
        evidence.append(
            f"artifact sha256:{artifact['sha256']} ({artifact['size_bytes']} bytes)"
        )
    return evidence


def _reference_text(citation: dict[str, str]) -> str:
    reference = citation["title"] or citation["identifier"]
    return f"{reference} - {citation['uri']}" if citation["uri"] else reference


def _read_object(path: Path) -> dict[str, Any]:
    value, _ = _read_object_payload(path)
    return value


def _read_object_payload(path: Path) -> tuple[dict[str, Any], bytes]:
    if not path.is_file() or path.is_symlink() or path.stat().st_size > _MAX_JSON_BYTES:
        raise ValueError(f"report JSON is not a bounded regular file: {path}")
    payload = path.read_bytes()
    if len(payload) > _MAX_JSON_BYTES:
        raise ValueError(f"report JSON is not a bounded regular file: {path}")
    value = json.loads(payload, object_pairs_hook=_unique_json_object)
    if not isinstance(value, dict):
        raise ValueError(f"report JSON root must be an object: {path}")
    return value, payload


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("report JSON contains a duplicate object key")
        value[key] = item
    return value


def _finding_key(item: dict[str, Any]) -> tuple[int, int, int, int, str]:
    return finding_order_key(
        finding_id=item.get("finding_id"),
        severity=item.get("severity"),
        classifications=item.get("classifications"),
        evidence=item.get("evidence"),
        blocking=item.get("blocking"),
        status=item.get("status"),
    )


def _action_summary(available: int, returned: int, limit: int) -> dict[str, Any]:
    omitted = available - returned
    return {
        "available": available,
        "returned": returned,
        "omitted": omitted,
        "limit": limit,
        "truncated": omitted > 0,
    }


def _action(item: dict[str, Any]) -> dict[str, Any]:
    location = _primary_location(item.get("locations"))
    sources = _sources(item.get("sources"))
    finding_id = _safe_text(item.get("finding_id") or "")
    return {
        "finding_id": finding_id,
        "title": _safe_text(item.get("title")),
        "priority": _action_priority(item),
        "severity": _safe_text(item.get("severity")),
        "confidence": _safe_text(item.get("confidence") or "unknown"),
        "blocking": item.get("blocking") is True,
        "status": _safe_text(item.get("status")),
        "domain": _safe_text(item.get("domain")),
        "area": _safe_text(item.get("area") or "unknown"),
        "description": _safe_text(item.get("description") or ""),
        "impact": _safe_text(item.get("impact") or ""),
        "path": _safe_text(location.get("path", "<repository>")),
        "line": _line_number(location.get("start_line")),
        "tools": sorted({_safe_text(source["tool"]) for source in sources}),
        "source_rules": sorted({_source_rule(source) for source in sources}),
        "classifications": _strings(item.get("classifications")),
        "citations": _citations(item.get("citations")),
        "owners": _owners(item.get("evidence")),
        "artifact_identity": _artifact_identity(item.get("evidence")),
        "remediation": _safe_text(item.get("remediation") or ""),
        "details": f"index.html#{quote(finding_id, safe='')}",
    }


def _action_priority(item: dict[str, Any]) -> str:
    return finding_priority(
        severity=item.get("severity"),
        classifications=item.get("classifications"),
        evidence=item.get("evidence"),
    )


def _primary_location(value: object) -> dict[str, Any]:
    if isinstance(value, list) and value and isinstance(value[0], dict):
        return value[0]
    return {}


def _line_number(value: object) -> int | None:
    if isinstance(value, int) and not isinstance(value, bool) and value > 0:
        return value
    return None


def _sources(value: object) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [
        source for source in value if isinstance(source, dict) and source.get("tool")
    ]


def _source_rule(source: dict[str, Any]) -> str:
    tool = _safe_text(source["tool"])
    rule = source.get("rule_id")
    return f"{tool}/{_safe_text(rule)}" if rule else tool


def _owners(value: object) -> list[str]:
    if not isinstance(value, dict) or not isinstance(value.get("owners"), list):
        return []
    return [_safe_text(owner) for owner in value["owners"]]


def _artifact_identity(value: object) -> dict[str, object] | None:
    if not isinstance(value, dict):
        return None
    path = value.get("artifact_path")
    digest = value.get("artifact_sha256")
    size = value.get("artifact_size_bytes")
    if not isinstance(path, str) or not path or path == "<outside-target>":
        return None
    candidate = Path(path)
    if candidate.is_absolute() or ".." in candidate.parts:
        return None
    if not isinstance(digest, str) or re.fullmatch(r"[0-9A-Fa-f]{64}", digest) is None:
        return None
    if not isinstance(size, int) or isinstance(size, bool) or size < 0:
        return None
    return {
        "path": _safe_text(path),
        "sha256": digest.casefold(),
        "size_bytes": size,
    }


def _strings(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [_safe_text(item) for item in value]


def _citations(value: object) -> list[dict[str, str]]:
    if not isinstance(value, list):
        return []
    return [
        {
            "identifier": _safe_text(item.get("identifier") or ""),
            "title": _safe_text(item.get("title") or ""),
            "uri": _safe_web_uri(item.get("uri")),
        }
        for item in value
        if isinstance(item, dict)
    ]


def _counts(values: dict[str, int]) -> str:
    return (
        ", ".join(f"{_safe_text(name)}={count}" for name, count in values.items())
        or "none"
    )


def _tool_health(tools: list[dict[str, Any]]) -> dict[str, Any]:
    applicable = [item for item in tools if item.get("applicable", True) is not False]
    not_applicable = len(tools) - len(applicable)
    completed = sum(str(item.get("status")) == "completed" for item in applicable)
    by_status = Counter(_safe_text(item.get("status") or "unknown") for item in tools)
    return {
        "selected": len(tools),
        "applicable": len(applicable),
        "completed": completed,
        "not_applicable": not_applicable,
        "execution_gaps": len(applicable) - completed,
        "coverage_complete": completed == len(applicable),
        "by_status": dict(sorted(by_status.items())),
    }


def _entrypoint_integrity(tools: list[dict[str, Any]]) -> dict[str, Any]:
    states = [
        state
        for tool in tools
        for state in (
            (
                _safe_text(tool.get("tool") or "unknown"),
                "primary",
                tool.get("executable_sha256"),
                (
                    tool.get("executable_integrity_verified") is True
                    and tool.get("executable_organization_approved") is True
                ),
                tool.get("executable_unchanged"),
            ),
            (
                _safe_text(tool.get("tool") or "unknown"),
                "helper",
                tool.get("auxiliary_executable_sha256"),
                (
                    tool.get("auxiliary_executable_integrity_verified") is True
                    and tool.get("auxiliary_executable_organization_approved") is True
                ),
                tool.get("auxiliary_executable_unchanged"),
            ),
        )
        if isinstance(state[2], str) and state[2]
    ]
    observed = len(states)
    approved = sum(
        approval is True and unchanged is True
        for _, _, _, approval, unchanged in states
    )
    unchanged = sum(value is True for _, _, _, _, value in states)
    actions = sorted(
        (
            _entrypoint_trust_action(state)
            for state in states
            if state[3] is not True or state[4] is not True
        ),
        key=lambda action: (
            _trust_priority_rank(action["priority"]),
            action["entrypoint"],
        ),
    )
    approval_candidates = [
        action for action in actions if action["approval_candidate"] is True
    ]
    return {
        "observed": observed,
        "approved_and_unchanged": approved,
        "unchanged_after_execution": unchanged,
        "postcheck_gaps": observed - unchanged,
        "fully_approved": observed > 0 and approved == observed,
        "approval_gap_entrypoints": sorted(
            _entrypoint_name(tool, role)
            for tool, role, _, approval, _ in states
            if approval is not True
        ),
        "postcheck_gap_entrypoints": sorted(
            _entrypoint_name(tool, role)
            for tool, role, _, _, postcheck in states
            if postcheck is not True
        ),
        "approval_candidate_entrypoints": len(approval_candidates),
        "approval_candidate_unique_digests": len(
            {action["sha256"] for action in approval_candidates}
        ),
        "actions": actions,
    }


def _entrypoint_trust_action(
    state: tuple[str, str, object, object, object],
) -> dict[str, Any]:
    tool, role, digest_value, approval, unchanged = state
    digest = _safe_text(digest_value)
    priority = "P0" if unchanged is False else "P1" if unchanged is not True else "P2"
    required_actions: list[str] = []
    if unchanged is False:
        required_actions.append("quarantine_changed_toolchain")
    elif unchanged is not True:
        required_actions.append("restore_post_execution_verification")
    if approval is not True:
        required_actions.extend(
            ["verify_provenance_before_approval", "approve_exact_digest"]
        )
    approval_candidate = approval is not True and unchanged is True
    field = "auxiliary_executable_sha256" if role == "helper" else "executable_sha256"
    return {
        "entrypoint": _entrypoint_name(tool, role),
        "tool": tool,
        "role": role,
        "sha256": digest,
        "priority": priority,
        "approval_status": "approved" if approval is True else "not_approved",
        "postcheck_status": (
            "unchanged"
            if unchanged is True
            else "changed"
            if unchanged is False
            else "unavailable"
        ),
        "approval_candidate": approval_candidate,
        "configuration_key": f"tools.{tool}.{field}" if approval_candidate else None,
        "required_actions": required_actions,
    }


def _entrypoint_name(tool: str, role: str) -> str:
    return f"{tool}:helper" if role == "helper" else tool


def _trust_priority_rank(priority: object) -> int:
    return {"P0": 0, "P1": 1, "P2": 2}.get(str(priority), 3)


def _bounded_names(values: list[str], *, limit: int = 5) -> str:
    displayed = values[:limit]
    summary = ", ".join(_safe_text(value) for value in displayed)
    omitted = len(values) - len(displayed)
    return f"{summary} (+{omitted} more)" if omitted else summary


def _safe_text(value: object) -> str:
    return sanitize_terminal_text(str(value))


def _safe_web_uri(value: object) -> str:
    uri = _safe_text(value or "").strip()
    try:
        parsed = urlsplit(uri)
    except ValueError:
        return ""
    return uri if parsed.scheme.lower() in {"http", "https"} and parsed.netloc else ""
