from __future__ import annotations


from .strict_json import loads as strict_json_loads
from pathlib import Path
from typing import Any

from .passport import verify_report
from .path_safety import resolve_regular_file

_MAX_JSON_BYTES = 128 * 1024 * 1024


def build_governance_evidence_draft(report: Path) -> dict[str, Any]:
    """Build a non-authoritative handoff package from a verified report."""
    verification = verify_report(report)
    root = report.expanduser().resolve()
    manifest = _read_object(root / "scan-manifest.json")
    intelligence = _read_object(root / "risk-intelligence.json")
    findings_document = _read_object(root / "findings.json")
    scanner_candidates = _scanner_candidates(manifest)
    return {
        "schema_version": "1.0",
        "status": "candidate",
        "authoritative": False,
        "scope": (
            "Observed evidence for independent review. This document cannot approve "
            "scanner identities, isolation, intelligence, or release artifacts."
        ),
        "report": {
            "scan_id": verification["scan_id"],
            "checksums_sha256": verification["checksums_sha256"],
            "source_sha256": str(
                findings_document.get("source_sha256")
                or manifest.get("inventory", {}).get("source_sha256")
                or ""
            ),
            "target": str(manifest.get("target") or ""),
        },
        "scanner_trust_candidates": scanner_candidates,
        "scanner_digest_groups": _scanner_digest_groups(scanner_candidates),
        "intelligence_candidates": _intelligence_candidates(intelligence),
        "isolation_candidate": {
            "target": str(manifest.get("target") or ""),
            "source_sha256": str(
                manifest.get("inventory", {}).get("source_sha256") or ""
            ),
            "network_policy": str(manifest.get("network_policy") or "deny"),
            "required_review": [
                "verify runner identity and policy enforcement outside the scan",
                "bind a signed validity window and organization trust root",
                "publish the approved document digest through organization policy",
            ],
        },
        "artifact_signing_candidates": _artifact_candidates(findings_document),
        "handoff": [
            "independently verify scanner publisher provenance and approve exact digests",
            "sign the exact release artifact digests in a controlled signing lane",
            "approve the exact consumed intelligence snapshot set",
            "issue signed isolation evidence for the exact source digest and runner",
            "rerun the scan with organization policy, then verify and sign the Passport",
        ],
    }


def _scanner_digest_groups(
    candidates: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Collapse shared launchers into one review unit without losing tool context."""
    grouped: dict[str, list[dict[str, Any]]] = {}
    for candidate in candidates:
        grouped.setdefault(str(candidate["sha256"]), []).append(candidate)
    return [
        {
            "sha256": digest,
            "entrypoints": len(values),
            "tools": sorted({str(value["tool"]) for value in values}),
            "roles": sorted({str(value["role"]) for value in values}),
            "versions": sorted({str(value["version"]) for value in values}),
            "organization_approved": all(
                value["organization_approved"] is True for value in values
            ),
            "unchanged": all(value["unchanged"] is True for value in values),
        }
        for digest, values in sorted(grouped.items())
    ]


def _scanner_candidates(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    values = manifest.get("tools")
    if not isinstance(values, list):
        raise TypeError("verified scan manifest tools must be an array")
    candidates: list[dict[str, Any]] = []
    for value in values:
        if not isinstance(value, dict) or value.get("applicable") is False:
            continue
        tool = str(value.get("tool") or "unknown")
        version = str(value.get("version") or "unknown")
        for role, digest_name, approved_name, unchanged_name in (
            (
                "primary",
                "executable_sha256",
                "executable_organization_approved",
                "executable_unchanged",
            ),
            (
                "auxiliary",
                "auxiliary_executable_sha256",
                "auxiliary_executable_organization_approved",
                "auxiliary_executable_unchanged",
            ),
        ):
            digest = value.get(digest_name)
            if not isinstance(digest, str) or not digest:
                continue
            candidates.append(
                {
                    "tool": tool,
                    "role": role,
                    "sha256": digest,
                    "version": version,
                    "organization_approved": value.get(approved_name) is True,
                    "unchanged": value.get(unchanged_name) is True,
                }
            )
    return sorted(candidates, key=lambda item: (item["tool"], item["role"]))


def _intelligence_candidates(intelligence: dict[str, Any]) -> list[dict[str, str]]:
    snapshots = intelligence.get("snapshots")
    if not isinstance(snapshots, dict):
        return []
    return sorted(
        (
            {"kind": str(kind), "sha256": str(value.get("sha256") or "")}
            for kind, value in snapshots.items()
            if isinstance(value, dict) and value.get("sha256")
        ),
        key=lambda item: item["kind"],
    )


def _artifact_candidates(findings_document: dict[str, Any]) -> list[dict[str, str]]:
    findings = findings_document.get("findings")
    if not isinstance(findings, list):
        raise TypeError("verified report findings must be an array")
    candidates: list[dict[str, str]] = []
    for finding in findings:
        if not isinstance(finding, dict) or finding.get("blocking") is not True:
            continue
        classifications = finding.get("classifications")
        if not isinstance(classifications, list) or not any(
            value in {"COSIGN-BUNDLE-MISSING", "SLSA-PROVENANCE"}
            for value in classifications
        ):
            continue
        evidence = finding.get("evidence")
        if not isinstance(evidence, dict):
            continue
        path = evidence.get("artifact_path")
        digest = evidence.get("artifact_sha256")
        if isinstance(path, str) and path and isinstance(digest, str) and digest:
            candidates.append(
                {
                    "finding_id": str(finding.get("finding_id") or "unknown"),
                    "path": path,
                    "sha256": digest,
                }
            )
    return sorted(candidates, key=lambda item: item["path"])


def _read_object(path: Path) -> dict[str, Any]:
    source = resolve_regular_file(path, "governance draft input")
    if source.stat().st_size > _MAX_JSON_BYTES:
        raise ValueError(f"governance draft input exceeds {_MAX_JSON_BYTES} bytes")
    value = strict_json_loads(source.read_bytes())
    if not isinstance(value, dict):
        raise TypeError("governance draft input root must be an object")
    return value
