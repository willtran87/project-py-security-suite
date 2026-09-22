"""Bounded JSON value readers shared by risk-route construction and summaries."""

from typing import Any


def _object(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _strings(value: Any, limit: int) -> list[str]:
    if isinstance(value, str):
        candidates = [value]
    elif isinstance(value, list):
        candidates = [str(item) for item in value if isinstance(item, (str, int))]
    else:
        candidates = []
    return sorted({item.strip()[:1000] for item in candidates if item.strip()})[:limit]


def _nonnegative_integer(value: Any) -> int | None:
    return (
        value
        if isinstance(value, int) and not isinstance(value, bool) and value >= 0
        else None
    )
