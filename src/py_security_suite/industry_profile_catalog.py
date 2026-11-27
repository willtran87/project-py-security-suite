from __future__ import annotations

from typing import Any

from .catalog_data import load_catalog
from .industry_emerging_assurance_catalog import EMERGING_ASSURANCE_PROFILES
from .industry_interoperability_sector_catalog import INTEROPERABILITY_SECTOR_PROFILES
from .industry_maturity_product_catalog import MATURITY_PRODUCT_PROFILES
from .industry_open_source_catalog import OPEN_SOURCE_PROFILES
from .industry_resilience_catalog import RESILIENCE_PROFILES


_CATALOG = load_catalog(
    "industry_profile_catalog",
    {
        "EMERGING_ASSURANCE_PROFILES": EMERGING_ASSURANCE_PROFILES,
        "INTEROPERABILITY_SECTOR_PROFILES": INTEROPERABILITY_SECTOR_PROFILES,
        "MATURITY_PRODUCT_PROFILES": MATURITY_PRODUCT_PROFILES,
        "OPEN_SOURCE_PROFILES": OPEN_SOURCE_PROFILES,
        "RESILIENCE_PROFILES": RESILIENCE_PROFILES,
    },
)

_ASSURANCE_PROFILES: dict[str, dict[str, Any]] = _CATALOG["_ASSURANCE_PROFILES"]
