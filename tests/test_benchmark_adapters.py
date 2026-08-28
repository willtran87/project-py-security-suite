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
    assert len(identifiers) == 35
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


def test_high_risk_adapters_encode_domain_specific_safety_boundaries() -> None:
    tls = benchmark_adapter_spec("tls-protocol-conformance")
    assert "loopback-only" in tls["isolation"]
    assert "no production credentials" in tls["isolation"]

    malware = benchmark_adapter_spec("amtso-malware-protection-evaluation")
    assert "harmless or inert fixtures" in malware["isolation"]
    assert "destruction receipt" in malware["isolation"]
    assert "harmless-eicar-and-inert-fixtures" in malware["required_inputs"]

    penetration = benchmark_adapter_spec("penetration-test-engagement-quality")
    assert "authorized" in penetration["isolation"]
    assert "kill switches" in penetration["isolation"]
    assert "signed-authorization-and-scope" in penetration["required_inputs"]

    reproducible = benchmark_adapter_spec("reproducible-build-variation")
    assert "no-egress" in reproducible["isolation"]
    assert "environment-variation-matrix" in reproducible["required_inputs"]

    biometric = benchmark_adapter_spec("biometric-performance-pad")
    assert biometric["protocol"] == "biometric-performance"
    assert "informed consent" in biometric["isolation"]
    assert (
        "locked-thresholds-sensors-environments-and-decision-oracles"
        in biometric["required_inputs"]
    )

    proficiency = benchmark_adapter_spec("interlaboratory-proficiency-testing")
    assert proficiency["protocol"] == "proficiency-testing"
    assert "collusion controls" in proficiency["isolation"]

    cmvp = benchmark_adapter_spec("cmvp-fips-140-3-validation")
    international = benchmark_adapter_spec("iso-19790-24759-module-conformance")
    assert "scheme-referenced-standard-edition-map" in cmvp["required_inputs"]
    assert "licensed-19790-and-24759-requirements" in international["required_inputs"]
