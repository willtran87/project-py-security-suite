"""Ordering, value-coercion and shared assessment helpers for risk-path analysis."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from .models import Citation
from .validation_alignment import TEST_EVIDENCE_ARTIFACTS


__all__ = [
    "_GRAPHIFY_REFERENCE",
    "_MAX_ADVISORY_IMPORT_PATHS",
    "_MAX_CAMPAIGN_MISSING_LINES",
    "_MAX_CAMPAIGN_TESTS",
    "_MAX_ENTRY_POINTS",
    "_MAX_EXPOSURE_ADVISORY_INTERSECTIONS",
    "_MAX_GRAPH_FILES",
    "_MAX_ROUTES",
    "_MAX_ROUTE_HOPS",
    "_MAX_SENSITIVE_ROUTE_CITATIONS",
    "_RISK_PATH_REFERENCE",
    "_STRUCTURAL_SYNTHESIS_REFERENCE",
    "_artifact_available",
    "_citation_records",
    "_digest",
    "_is_test_path",
    "_objects",
    "_optional_boolean",
    "_optional_number",
    "_optional_string",
    "_ordered_strings",
    "_path",
    "_positive_integer",
    "_positive_integers",
    "_priority_rank",
    "_route_order",
    "_test_execution_available",
]


_GRAPHIFY_REFERENCE = "https://graphify.com/docs/cli"


_RISK_PATH_REFERENCE = "docs/risk-paths.md"


_STRUCTURAL_SYNTHESIS_REFERENCE = "docs/structural-synthesis.md"


_MAX_ENTRY_POINTS = 100


_MAX_GRAPH_FILES = 100_000


_MAX_ROUTE_HOPS = 8


_MAX_ROUTES = 250


_MAX_CAMPAIGN_TESTS = 50


_MAX_CAMPAIGN_MISSING_LINES = 100


_MAX_ADVISORY_IMPORT_PATHS = 50


_MAX_EXPOSURE_ADVISORY_INTERSECTIONS = 100


_MAX_SENSITIVE_ROUTE_CITATIONS = 10


def _citation_records(
    value: Any,
    *,
    limit: int,
    default_kind: str,
) -> list[dict[str, str | None]]:
    """Normalize bounded citation metadata without treating it as finding proof."""
    if not isinstance(value, list):
        return []
    result: list[dict[str, str | None]] = []
    seen: set[tuple[str, str | None]] = set()
    for item in value:
        kind_value: Any
        identifier_value: Any
        title_value: Any
        uri_value: Any
        if isinstance(item, Citation):
            kind_value = item.kind
            identifier_value = item.identifier
            title_value = item.title
            uri_value = item.uri
        elif isinstance(item, dict):
            kind_value = item.get("kind")
            identifier_value = item.get("identifier")
            title_value = item.get("title")
            uri_value = item.get("uri")
        else:
            continue
        identifier = str(identifier_value or "").strip()[:500]
        uri = str(uri_value).strip()[:4000] if isinstance(uri_value, str) else None
        if not identifier or (identifier, uri) in seen:
            continue
        seen.add((identifier, uri))
        result.append(
            {
                "kind": str(kind_value or default_kind).strip()[:100] or default_kind,
                "identifier": identifier,
                "title": str(title_value or identifier).strip()[:1000] or identifier,
                "uri": uri,
            }
        )
        if len(result) >= limit:
            break
    return result


def _route_order(value: dict[str, Any]) -> tuple[int, int, int, str]:
    return (
        _priority_rank(str(value["priority"])),
        {
            "finding": 0,
            "dependency-advisory-import": 1,
            "sink-surface": 2,
        }.get(str(value["target"]["kind"]), 3),
        -int(value["hop_count"]),
        str(value["route_id"]),
    )


def _priority_rank(value: str) -> int:
    return {"P0": 0, "P1": 1, "P2": 2, "P3": 3, "P4": 4}.get(value, 5)


def _artifact_available(value: Any, key: str) -> bool:
    return isinstance(value, dict) and isinstance(value.get(key), (dict, list))


def _test_execution_available(artifacts: dict[str, Any]) -> bool:
    return any(
        isinstance(artifacts.get(name), dict) for name in TEST_EVIDENCE_ARTIFACTS
    )


def _path(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    normalized = value.replace("\\", "/").strip()
    while normalized.startswith("./"):
        normalized = normalized[2:]
    if not normalized or normalized.startswith("/") or ".." in normalized.split("/"):
        return ""
    return normalized[:4000]


def _is_test_path(path: str) -> bool:
    normalized = _path(path).casefold()
    name = normalized.rsplit("/", 1)[-1]
    return (
        normalized.startswith("tests/")
        or "/tests/" in normalized
        or name.startswith("test_")
        or name.endswith("_test.py")
    )


def _objects(value: Any, limit: int) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value[:limit] if isinstance(item, dict)]


def _ordered_strings(value: Any, limit: int) -> list[str]:
    """Retain bounded string order for route and other sequence evidence."""
    if isinstance(value, str):
        candidates = [value]
    elif isinstance(value, list):
        candidates = [str(item) for item in value if isinstance(item, (str, int))]
    else:
        candidates = []
    result: list[str] = []
    seen: set[str] = set()
    for item in candidates:
        normalized = item.strip()[:1000]
        if normalized and normalized not in seen:
            result.append(normalized)
            seen.add(normalized)
        if len(result) >= limit:
            break
    return result


def _positive_integers(value: Any, limit: int) -> list[int]:
    if not isinstance(value, list):
        return []
    return sorted(
        {
            item
            for item in value
            if isinstance(item, int) and not isinstance(item, bool) and item > 0
        }
    )[:limit]


def _optional_string(value: Any) -> str | None:
    return str(value)[:1000] if isinstance(value, (str, int)) and str(value) else None


def _optional_boolean(value: Any) -> bool | None:
    return value if isinstance(value, bool) else None


def _optional_number(value: Any) -> float | None:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return round(float(value), 2)
    return None


def _positive_integer(value: Any) -> int | None:
    return (
        value
        if isinstance(value, int) and not isinstance(value, bool) and value > 0
        else None
    )


def _digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
