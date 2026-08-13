from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .execution import sanitize_terminal_text, sha256_file
from .passport import verify_report
from .path_safety import resolve_regular_file

_MAX_JSON_BYTES = 128 * 1024 * 1024


def build_github_annotations(
    plan: Path, *, plan_sha256: str, report: Path
) -> dict[str, Any]:
    """Verify a promotion plan and return bounded GitHub annotation records."""
    source = resolve_regular_file(plan, "promotion plan")
    expected = _digest(plan_sha256)
    if sha256_file(source) != expected:
        raise ValueError("promotion plan does not match its SHA-256")
    if source.stat().st_size > _MAX_JSON_BYTES:
        raise ValueError("promotion plan exceeds 128 MiB")
    document = json.loads(source.read_bytes())
    if not isinstance(document, dict) or document.get("schema_version") not in {
        "1.1",
        "1.2",
    }:
        raise ValueError("promotion plan schema_version must be '1.1' or '1.2'")
    verification = verify_report(report)
    bound = document.get("report")
    if (
        not isinstance(bound, dict)
        or bound.get("checksums_sha256") != verification["checksums_sha256"]
    ):
        raise ValueError("promotion plan is not bound to this report")
    raw = document.get("github_annotations")
    if not isinstance(raw, list) or len(raw) > 10000:
        raise TypeError("promotion plan annotations must be a bounded array")
    annotations = [_annotation(value, index) for index, value in enumerate(raw)]
    return {
        "schema_version": "1.0",
        "verified": True,
        "authoritative": False,
        "report": {
            "scan_id": verification["scan_id"],
            "checksums_sha256": verification["checksums_sha256"],
        },
        "plan_sha256": expected,
        "summary": {
            "annotations": len(annotations),
            "errors": sum(value["level"] == "error" for value in annotations),
            "warnings": sum(value["level"] == "warning" for value in annotations),
        },
        "annotations": annotations,
    }


def render_github_commands(receipt: dict[str, Any]) -> str:
    """Render verified annotations using GitHub workflow-command escaping."""
    lines: list[str] = []
    for value in receipt["annotations"]:
        properties = f"file={_property(value['file'])},line={value['line']},title={_property(value['title'])}"
        lines.append(f"::{value['level']} {properties}::{_message(value['message'])}")
    return "\n".join(lines) + ("\n" if lines else "")


def _annotation(value: object, index: int) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise TypeError(f"annotation {index} must be an object")
    level = str(value.get("level") or "").casefold()
    if level not in {"error", "warning", "notice"}:
        raise ValueError(f"annotation {index} has an invalid level")
    line = value.get("line")
    if not isinstance(line, int) or line < 1 or line > 2_147_483_647:
        raise ValueError(f"annotation {index} has an invalid line")
    path = str(value.get("file") or "")
    candidate = Path(path)
    if not path or candidate.is_absolute() or ".." in candidate.parts:
        raise ValueError(f"annotation {index} has an unsafe file path")
    return {
        "level": level,
        "title": sanitize_terminal_text(
            str(value.get("title") or "Security finding"), maximum=500
        ),
        "message": _safe_multiline(
            str(value.get("message") or "Review required"), maximum=4000
        ),
        "file": candidate.as_posix(),
        "line": line,
        "finding_id": sanitize_terminal_text(
            str(value.get("finding_id") or ""), maximum=200
        ),
    }


def _property(value: object) -> str:
    return (
        str(value)
        .replace("%", "%25")
        .replace("\r", "%0D")
        .replace("\n", "%0A")
        .replace(":", "%3A")
        .replace(",", "%2C")
    )


def _safe_multiline(value: str, *, maximum: int) -> str:
    lines = [
        sanitize_terminal_text(line, maximum=maximum) for line in value.splitlines()
    ]
    return "\n".join(lines)[:maximum]


def _message(value: object) -> str:
    return str(value).replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _digest(value: str) -> str:
    normalized = value.strip().casefold()
    if len(normalized) != 64 or any(
        character not in "0123456789abcdef" for character in normalized
    ):
        raise ValueError("plan SHA-256 must be a lowercase digest")
    return normalized
