from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

from .passport import verify_report
from .path_safety import resolve_regular_file

_MAX_REPORTS = 500
_MAX_JSON_BYTES = 128 * 1024 * 1024


def build_portfolio_dashboard(reports: list[Path]) -> dict[str, Any]:
    """Aggregate independently verified reports without weakening their authority."""
    if not reports or len(reports) > _MAX_REPORTS:
        raise ValueError("portfolio requires 1-500 reports")
    snapshots = [_snapshot(path) for path in reports]
    seals = [str(value["checksums_sha256"]) for value in snapshots]
    if len(set(seals)) != len(seals):
        raise ValueError("portfolio reports must have distinct checksum seals")
    snapshots.sort(
        key=lambda value: (
            str(value["target"]),
            str(value["finished_at"]),
            str(value["scan_id"]),
        )
    )
    outcomes = Counter(str(value["outcome"]) for value in snapshots)
    profiles = Counter(str(value["profile"]) for value in snapshots)
    return {
        "schema_version": "1.0",
        "authoritative": False,
        "scope": "Portfolio-level decision support over independently sealed reports; repository evidence and admission remain authoritative individually.",
        "summary": {
            "reports": len(snapshots),
            "targets": len({str(value["target"]) for value in snapshots}),
            "outcomes": dict(sorted(outcomes.items())),
            "profiles": dict(sorted(profiles.items())),
            "active_findings": sum(
                int(value["active_findings"]) for value in snapshots
            ),
            "blocking_findings": sum(
                int(value["blocking_findings"]) for value in snapshots
            ),
            "execution_gaps": sum(int(value["execution_gaps"]) for value in snapshots),
            "unknown_versions": sum(
                int(value["unknown_versions"]) for value in snapshots
            ),
        },
        "attention": [
            {
                "scan_id": value["scan_id"],
                "target": value["target"],
                "outcome": value["outcome"],
                "blocking_findings": value["blocking_findings"],
                "execution_gaps": value["execution_gaps"],
            }
            for value in snapshots
            if value["outcome"] != "pass"
            or value["blocking_findings"]
            or value["execution_gaps"]
        ],
        "reports": snapshots,
    }


def _snapshot(report: Path) -> dict[str, Any]:
    verification = verify_report(report)
    root = report.expanduser().resolve()
    manifest = _read(root / "scan-manifest.json")
    findings_document = _read(root / "findings.json")
    portfolio = _read(root / "portfolio-health.json")
    findings = findings_document.get("findings")
    tools = manifest.get("tools")
    if not isinstance(findings, list) or not isinstance(tools, list):
        raise TypeError("portfolio findings and tools must be arrays")
    active = [
        value
        for value in findings
        if isinstance(value, dict) and value.get("status") != "suppressed"
    ]
    applicable = [
        value
        for value in tools
        if isinstance(value, dict) and value.get("applicable") is not False
    ]
    overall_candidate = portfolio.get("overall")
    overall = overall_candidate if isinstance(overall_candidate, dict) else {}
    inventory_candidate = manifest.get("inventory")
    inventory = inventory_candidate if isinstance(inventory_candidate, dict) else {}
    return {
        "scan_id": verification["scan_id"],
        "checksums_sha256": verification["checksums_sha256"],
        "outcome": verification["outcome"],
        "target": str(
            inventory.get("target") or findings_document.get("target") or root.name
        ),
        "profile": str(manifest.get("profile") or ""),
        "finished_at": str(manifest.get("finished_at") or ""),
        "vcs_revision": str(findings_document.get("vcs_revision") or ""),
        "active_findings": len(active),
        "blocking_findings": sum(value.get("blocking") is True for value in active),
        "applicable_tools": len(applicable),
        "completed_tools": sum(
            value.get("status") == "completed" for value in applicable
        ),
        "execution_gaps": int(overall.get("domains_with_execution_gaps") or 0),
        "unknown_versions": sum(
            str(value.get("version") or "unknown") == "unknown" for value in applicable
        ),
    }


def _read(path: Path) -> dict[str, Any]:
    source = resolve_regular_file(path, "portfolio input")
    if source.stat().st_size > _MAX_JSON_BYTES:
        raise ValueError("portfolio input exceeds 128 MiB")
    value = json.loads(source.read_bytes())
    if not isinstance(value, dict):
        raise TypeError("portfolio input root must be an object")
    return value
