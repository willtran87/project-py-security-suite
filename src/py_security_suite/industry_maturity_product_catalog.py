from __future__ import annotations

from typing import Any

from .catalog_data import load_catalog


_CATALOG = load_catalog("industry_maturity_product_catalog")

MATURITY_PRODUCT_STANDARDS: tuple[dict[str, Any], ...] = _CATALOG[
    "MATURITY_PRODUCT_STANDARDS"
]
MATURITY_PRODUCT_PROFILES: dict[str, dict[str, Any]] = _CATALOG[
    "MATURITY_PRODUCT_PROFILES"
]
MATURITY_PRODUCT_BENCHMARKS: tuple[dict[str, Any], ...] = _CATALOG[
    "MATURITY_PRODUCT_BENCHMARKS"
]
MATURITY_PRODUCT_LABORATORY_BENCHMARKS: frozenset[str] = _CATALOG[
    "MATURITY_PRODUCT_LABORATORY_BENCHMARKS"
]
_COMMON_ACQUISITION: dict[str, bool] = _CATALOG["_COMMON_ACQUISITION"]
MATURITY_PRODUCT_ADAPTER_SPECS: tuple[dict[str, Any], ...] = _CATALOG[
    "MATURITY_PRODUCT_ADAPTER_SPECS"
]
MATURITY_PRODUCT_EVIDENCE_CONTRACTS: dict[str, dict[str, Any]] = _CATALOG[
    "MATURITY_PRODUCT_EVIDENCE_CONTRACTS"
]

MATURITY_PRODUCT_BENCHMARK_PROTOCOLS = {
    benchmark["id"]: "conformance" for benchmark in MATURITY_PRODUCT_BENCHMARKS
}
