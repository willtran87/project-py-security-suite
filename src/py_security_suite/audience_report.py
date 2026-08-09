from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .execution import sha256_file
from .passport import verify_report
from .path_safety import resolve_regular_file

AUDIENCES = ("executive", "developer", "security", "release_engineering", "auditor")
_MAX_JSON_BYTES = 128 * 1024 * 1024


def build_audience_report(
    plan: Path, *, plan_sha256: str, report: Path, audience: str
) -> dict[str, Any]:
    """Extract one digest-bound audience view from a verified promotion plan."""
    if audience not in AUDIENCES:
        raise ValueError(f"audience must be one of: {', '.join(AUDIENCES)}")
    source = resolve_regular_file(plan, "promotion plan")
    expected = _digest(plan_sha256)
    if sha256_file(source) != expected:
        raise ValueError("promotion plan does not match its SHA-256")
    if source.stat().st_size > _MAX_JSON_BYTES:
        raise ValueError("promotion plan exceeds 128 MiB")
    document = json.loads(source.read_bytes())
    if not isinstance(document, dict) or document.get("schema_version") != "1.1":
        raise ValueError("promotion plan schema_version must be '1.1'")
    verification = verify_report(report)
    bound = document.get("report")
    if (
        not isinstance(bound, dict)
        or bound.get("checksums_sha256") != verification["checksums_sha256"]
    ):
        raise ValueError("promotion plan is not bound to this report")
    audiences = document.get("audiences")
    if not isinstance(audiences, dict) or not isinstance(audiences.get(audience), dict):
        raise ValueError(f"promotion plan has no valid {audience} audience view")
    return {
        "schema_version": "1.0",
        "authoritative": False,
        "scope": "Audience-specific decision support; verify the sealed report and apply independent admission policy.",
        "audience": audience,
        "status": str(document.get("status") or "unknown"),
        "report": {
            "scan_id": verification["scan_id"],
            "checksums_sha256": verification["checksums_sha256"],
        },
        "promotion_plan_sha256": expected,
        "view": audiences[audience],
    }


def render_audience_markdown(document: dict[str, Any]) -> str:
    """Render a small stable Markdown card without remote dependencies."""
    lines = [
        f"# {str(document['audience']).replace('_', ' ').title()} security view",
        "",
        f"**Status:** {str(document['status']).upper()}  ",
        f"**Scan:** `{document['report']['scan_id']}`  ",
        f"**Evidence seal:** `{document['report']['checksums_sha256']}`",
        "",
        "## Decision information",
        "",
    ]
    for key, value in document["view"].items():
        label = str(key).replace("_", " ").title()
        if isinstance(value, list):
            lines.append(
                f"- **{label}:** {', '.join(str(item) for item in value) or 'none'}"
            )
        else:
            lines.append(f"- **{label}:** {value}")
    lines.extend(
        [
            "",
            "> Non-authoritative decision support. Verify the evidence seal before acting.",
            "",
        ]
    )
    return "\n".join(lines)


def _digest(value: str) -> str:
    normalized = value.strip().casefold()
    if len(normalized) != 64 or any(
        character not in "0123456789abcdef" for character in normalized
    ):
        raise ValueError("plan SHA-256 must be a lowercase digest")
    return normalized
