from __future__ import annotations

from typing import Any

from .catalog_data import load_catalog


_CATALOG = load_catalog("industry_open_source_catalog")

OPEN_SOURCE_STANDARDS: tuple[dict[str, Any], ...] = _CATALOG["OPEN_SOURCE_STANDARDS"]
OPEN_SOURCE_BENCHMARKS: tuple[dict[str, Any], ...] = _CATALOG["OPEN_SOURCE_BENCHMARKS"]
OPEN_SOURCE_PROFILES: dict[str, dict[str, Any]] = _CATALOG["OPEN_SOURCE_PROFILES"]
