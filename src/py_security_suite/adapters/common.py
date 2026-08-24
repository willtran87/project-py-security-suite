from __future__ import annotations

from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ..models import Confidence, Severity
from ..trusted_observation import governed_now


def map_severity(value: Any, *, default: Severity = Severity.UNKNOWN) -> Severity:
    normalized = str(value or "").strip().lower()
    mapping = {
        "critical": Severity.CRITICAL,
        "error": Severity.HIGH,
        "high": Severity.HIGH,
        "warning": Severity.MEDIUM,
        "warn": Severity.MEDIUM,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
        "info": Severity.INFORMATIONAL,
        "information": Severity.INFORMATIONAL,
        "informational": Severity.INFORMATIONAL,
        "unknown": Severity.UNKNOWN,
    }
    return mapping.get(normalized, default)


def database_freshness_error(
    root: Path, filename: str, maximum_age_days: float
) -> str | None:
    """Validate a staged database marker's age without consulting a network."""
    candidates = sorted(
        path
        for path in root.rglob(filename)
        if path.is_file() and not path.is_symlink()
    )
    if not candidates:
        return f"offline database freshness marker {filename!r} was not found"
    newest = max(candidates, key=lambda path: path.stat().st_mtime)
    modified = datetime.fromtimestamp(newest.stat().st_mtime, tz=UTC)
    age_days = (governed_now() - modified).total_seconds() / 86400
    if age_days > maximum_age_days:
        return (
            f"offline database is {age_days:.1f} days old; "
            f"maximum allowed age is {maximum_age_days:g} days"
        )
    return None


def map_confidence(value: Any) -> Confidence:
    normalized = str(value or "").strip().lower()
    mapping = {
        "high": Confidence.HIGH,
        "medium": Confidence.MEDIUM,
        "low": Confidence.LOW,
    }
    return mapping.get(normalized, Confidence.UNKNOWN)


def string_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, Iterable) and not isinstance(value, (bytes, dict)):
        return [str(item) for item in value]
    return [str(value)]
