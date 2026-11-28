from __future__ import annotations

from typing import Any

from .catalog_data import load_catalog


_CATALOG = load_catalog("industry_emerging_assurance_catalog")

EMERGING_ASSURANCE_STANDARDS: tuple[dict[str, Any], ...] = _CATALOG[
    "EMERGING_ASSURANCE_STANDARDS"
]
EMERGING_ASSURANCE_PROFILES: dict[str, dict[str, Any]] = _CATALOG[
    "EMERGING_ASSURANCE_PROFILES"
]
EMERGING_ASSURANCE_BENCHMARKS: tuple[dict[str, Any], ...] = _CATALOG[
    "EMERGING_ASSURANCE_BENCHMARKS"
]
EMERGING_ASSURANCE_LABORATORY_BENCHMARKS: frozenset[str] = _CATALOG[
    "EMERGING_ASSURANCE_LABORATORY_BENCHMARKS"
]
_COMMON_ACQUISITION: dict[str, bool] = _CATALOG["_COMMON_ACQUISITION"]
EMERGING_ASSURANCE_ADAPTER_SPECS: tuple[dict[str, Any], ...] = _CATALOG[
    "EMERGING_ASSURANCE_ADAPTER_SPECS"
]
_CIS_TRUE: tuple[str, ...] = _CATALOG["_CIS_TRUE"]
_CIS_FALSE: tuple[str, ...] = _CATALOG["_CIS_FALSE"]
EMERGING_ASSURANCE_EVIDENCE_CONTRACTS: dict[str, dict[str, Any]] = _CATALOG[
    "EMERGING_ASSURANCE_EVIDENCE_CONTRACTS"
]
EMERGING_ASSURANCE_WATCHLIST: tuple[dict[str, str], ...] = _CATALOG[
    "EMERGING_ASSURANCE_WATCHLIST"
]

EMERGING_ASSURANCE_BENCHMARK_PROTOCOLS = {
    benchmark["id"]: "conformance" for benchmark in EMERGING_ASSURANCE_BENCHMARKS
}
