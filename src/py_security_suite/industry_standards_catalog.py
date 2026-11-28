from __future__ import annotations

from typing import Any

from .catalog_data import load_catalog
from .industry_emerging_assurance_catalog import EMERGING_ASSURANCE_STANDARDS
from .industry_interoperability_sector_catalog import INTEROPERABILITY_SECTOR_STANDARDS
from .industry_maturity_product_catalog import MATURITY_PRODUCT_STANDARDS
from .industry_open_source_catalog import OPEN_SOURCE_STANDARDS
from .industry_resilience_catalog import RESILIENCE_STANDARDS


_CATALOG = load_catalog(
    "industry_standards_catalog",
    {
        "EMERGING_ASSURANCE_STANDARDS": EMERGING_ASSURANCE_STANDARDS,
        "INTEROPERABILITY_SECTOR_STANDARDS": INTEROPERABILITY_SECTOR_STANDARDS,
        "MATURITY_PRODUCT_STANDARDS": MATURITY_PRODUCT_STANDARDS,
        "OPEN_SOURCE_STANDARDS": OPEN_SOURCE_STANDARDS,
        "RESILIENCE_STANDARDS": RESILIENCE_STANDARDS,
    },
)

_STANDARDS: tuple[dict[str, Any], ...] = _CATALOG["_STANDARDS"]
