from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from ..models import Confidence, Severity


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
        "informational": Severity.INFORMATIONAL,
        "unknown": Severity.UNKNOWN,
    }
    return mapping.get(normalized, default)


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

