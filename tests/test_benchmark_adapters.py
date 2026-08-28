from __future__ import annotations

import pytest

from py_security_suite.benchmark_adapters import (
    BUILTIN_ADAPTER_SPECS,
    benchmark_adapter_spec,
    benchmark_adapter_specs,
)
from py_security_suite.industry_assurance import _BENCHMARKS, _benchmark_protocol


def test_maintained_adapter_specs_are_registered_and_protocol_aligned() -> None:
    registered = {item["id"] for item in _BENCHMARKS}
    identifiers = [item["benchmark_id"] for item in BUILTIN_ADAPTER_SPECS]
    assert len(identifiers) == len(set(identifiers))
    assert set(identifiers) <= registered
    for item in BUILTIN_ADAPTER_SPECS:
        assert item["protocol"] == _benchmark_protocol(item["benchmark_id"])
        assert item["acquisition"]["immutable_revision_required"] is True
        assert item["acquisition"]["golden_negative_required"] is True
        assert item["required_inputs"]


def test_adapter_catalog_returns_detached_values_and_fails_closed() -> None:
    values = benchmark_adapter_specs()
    values[0]["required_inputs"].append("mutation")
    assert "mutation" not in BUILTIN_ADAPTER_SPECS[0]["required_inputs"]
    assert benchmark_adapter_spec("c2sp-wycheproof")["normalizer"].startswith(
        "wycheproof-"
    )
    with pytest.raises(ValueError, match="no maintained"):
        benchmark_adapter_spec("unknown")
