from __future__ import annotations

from scripts.validate_version_consistency import (
    authoritative_version,
    consistency_failures,
)


def test_release_surfaces_use_one_authoritative_version() -> None:
    assert authoritative_version() == "0.1.0"
    assert consistency_failures() == []
