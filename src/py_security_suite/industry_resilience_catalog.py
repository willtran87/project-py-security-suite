from __future__ import annotations

from typing import Any

from .catalog_data import load_catalog


_CATALOG = load_catalog("industry_resilience_catalog")

RESILIENCE_STANDARDS: tuple[dict[str, Any], ...] = _CATALOG["RESILIENCE_STANDARDS"]
RESILIENCE_WATCHLIST: tuple[dict[str, str], ...] = _CATALOG["RESILIENCE_WATCHLIST"]
RESILIENCE_BENCHMARKS: tuple[dict[str, Any], ...] = _CATALOG["RESILIENCE_BENCHMARKS"]
RESILIENCE_PROFILES: dict[str, dict[str, Any]] = _CATALOG["RESILIENCE_PROFILES"]
RESILIENCE_ADAPTER_SPECS: tuple[dict[str, Any], ...] = _CATALOG[
    "RESILIENCE_ADAPTER_SPECS"
]
RESILIENCE_EVIDENCE_CONTRACTS: dict[str, dict[str, Any]] = _CATALOG[
    "RESILIENCE_EVIDENCE_CONTRACTS"
]

RESILIENCE_BENCHMARK_IDS = frozenset(RESILIENCE_EVIDENCE_CONTRACTS)

RESILIENCE_BENCHMARK_PROTOCOLS = {
    identifier: (
        "assessor-agreement"
        if identifier
        in {
            "iec-62443-service-provider-evaluation",
            "crisis-exercise-assurance",
            "enterprise-ict-risk-aggregation",
        }
        else "conformance"
    )
    for identifier in RESILIENCE_BENCHMARK_IDS
}
