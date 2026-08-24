from __future__ import annotations


from .strict_json import loads as strict_json_loads
from pathlib import Path
from typing import Any

from .execution import sha256_file
from .passport import verify_report
from .path_safety import resolve_regular_file

_MAX_JSON_BYTES = 128 * 1024 * 1024


def build_baseline_candidate(report: Path) -> dict[str, Any]:
    """Prepare, but never approve, a sealed findings report as a baseline."""
    verification = verify_report(report)
    root = report.expanduser().resolve()
    source = resolve_regular_file(root / "findings.json", "baseline candidate")
    if source.stat().st_size > _MAX_JSON_BYTES:
        raise ValueError("baseline candidate exceeds 128 MiB")
    findings = strict_json_loads(source.read_bytes())
    if not isinstance(findings, dict):
        raise TypeError("findings report root must be an object")
    revision = str(findings.get("vcs_revision") or "")
    eligible = len(revision) == 40 and all(
        value in "0123456789abcdef" for value in revision
    )
    return {
        "schema_version": "1.0",
        "status": "candidate" if eligible else "ineligible",
        "authoritative": False,
        "scope": "Candidate metadata only; an organization authority must approve the exact findings digest.",
        "report": {
            "scan_id": verification["scan_id"],
            "checksums_sha256": verification["checksums_sha256"],
            "outcome": verification["outcome"],
        },
        "baseline": {
            "path": str(source),
            "sha256": sha256_file(source),
            "profile": str(findings.get("profile") or ""),
            "selected_tools": sorted(
                str(value)
                for value in findings.get("selected_tools", [])
                if isinstance(value, str) and value
            ),
            "source_sha256": str(findings.get("source_sha256") or ""),
            "vcs_revision": revision,
        },
        "requirements": [
            "independently review and approve the exact findings SHA-256",
            "retain local VCS history containing the approved baseline revision",
            "use the same scan profile and selected tool set",
            "configure both baseline_path and baseline_sha256 in organization policy",
        ],
    }
