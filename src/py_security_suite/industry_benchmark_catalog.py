from __future__ import annotations

from typing import Any

from .catalog_data import load_catalog
from .industry_emerging_assurance_catalog import (
    EMERGING_ASSURANCE_BENCHMARKS,
    EMERGING_ASSURANCE_WATCHLIST,
)
from .industry_interoperability_sector_catalog import INTEROPERABILITY_SECTOR_BENCHMARKS
from .industry_maturity_product_catalog import MATURITY_PRODUCT_BENCHMARKS
from .industry_open_source_catalog import OPEN_SOURCE_BENCHMARKS
from .industry_resilience_catalog import (
    RESILIENCE_BENCHMARKS,
    RESILIENCE_WATCHLIST,
)


_CATALOG = load_catalog(
    "industry_benchmark_catalog",
    {
        "EMERGING_ASSURANCE_BENCHMARKS": EMERGING_ASSURANCE_BENCHMARKS,
        "EMERGING_ASSURANCE_WATCHLIST": EMERGING_ASSURANCE_WATCHLIST,
        "INTEROPERABILITY_SECTOR_BENCHMARKS": INTEROPERABILITY_SECTOR_BENCHMARKS,
        "MATURITY_PRODUCT_BENCHMARKS": MATURITY_PRODUCT_BENCHMARKS,
        "OPEN_SOURCE_BENCHMARKS": OPEN_SOURCE_BENCHMARKS,
        "RESILIENCE_BENCHMARKS": RESILIENCE_BENCHMARKS,
        "RESILIENCE_WATCHLIST": RESILIENCE_WATCHLIST,
    },
)

_STANDARDS_WATCHLIST: tuple[dict[str, str], ...] = _CATALOG["_STANDARDS_WATCHLIST"]
_BENCHMARKS: tuple[dict[str, Any], ...] = _CATALOG["_BENCHMARKS"]
