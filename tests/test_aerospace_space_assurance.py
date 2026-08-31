from __future__ import annotations

from py_security_suite.benchmark_adapters import benchmark_adapter_spec
from py_security_suite.industry_assurance import (
    _ASSURANCE_PROFILES,
    _BENCHMARKS,
    _LABORATORY_QUALIFIED_BENCHMARKS,
    _STANDARDS,
    _benchmark_protocol,
)


def test_current_in_service_and_space_security_publications_are_versioned() -> None:
    standards = {item["id"]: item for item in _STANDARDS}
    expected = {
        "SAE-ARP5150B",
        "SAE-ARP5151B",
        "CCSDS-350-1-G-3",
        "CCSDS-350-7-G-2",
        "CCSDS-351-0-M-1",
        "CCSDS-352-0-B-2",
        "CCSDS-355-0-B-2",
        "CCSDS-355-1-B-1",
        "CCSDS-356-0-B-1",
        "CCSDS-357-0-B-1",
    }

    assert expected <= standards.keys()
    assert standards["SAE-ARP5150B"]["version"] == "2026-08-15"
    assert standards["SAE-ARP5151B"]["version"] == "2025-08-22"
    for identifier in expected:
        lifecycle = standards[identifier]["lifecycle"]
        assert lifecycle["edition_status"] == "final"
        assert lifecycle["observed_at"] == "2026-08-31"
        assert standards[identifier]["reference"].startswith("https://")
        assert len(standards[identifier]["evidence"]) >= 2


def test_continuing_airworthiness_joins_security_safety_and_service_outcomes() -> None:
    profile = _ASSURANCE_PROFILES["continuing-airworthiness-security"]
    assert {"SAE-ARP5150B", "SAE-ARP5151B", "RTCA-DO-355A"} <= set(profile["standards"])
    controls = {item[1]: item for item in profile["controls"]}
    assert {
        "IN-SERVICE-SAFETY-SECURITY-SIGNAL-AND-FLEET-EFFECTIVITY",
        "GENERAL-AVIATION-ROTORCRAFT-SERVICE-DATA-AND-CORRECTIVE-ACTION",
    } <= controls.keys()
    procedure = profile["procedures"][0]
    assert procedure[1] == "IN-SERVICE-SECURITY-EVENT-EXERCISE"
    assert procedure[4] is True
    assert "recurrence" in procedure[2]


def test_space_profile_covers_the_end_to_end_mission_security_lifecycle() -> None:
    profile = _ASSURANCE_PROFILES["space-mission-communications-security"]
    assert len(profile["standards"]) == 9
    assert {
        "CCSDS-350-1-G-3",
        "CCSDS-351-0-M-1",
        "CCSDS-355-0-B-2",
        "CCSDS-355-1-B-1",
        "CCSDS-357-0-B-1",
        "NASA-STD-8739-8B",
    } <= set(profile["standards"])
    assert {item[1] for item in profile["controls"]} == {
        "SPACE-MISSION-THREAT-SCOPE-AND-TRACEABILITY",
        "SPACE-DATA-SYSTEM-SECURITY-ARCHITECTURE",
        "SPACE-LINK-PROTOCOL-SECURITY-AND-ORDERING",
        "SPACE-SECURITY-ASSOCIATION-KEY-CREDENTIAL-AND-MONITORING-LIFECYCLE",
    }
    procedure = profile["procedures"][0]
    assert procedure[3] == "dynamic"
    assert procedure[4] is True
    assert "no-flight-qualification" in procedure[2]


def test_deepened_sector_benchmarks_have_maintained_fail_closed_adapters() -> None:
    benchmarks = {item["id"]: item for item in _BENCHMARKS}
    expected_normalizers = {
        "disa-stig-scap-conformance": (
            "disa-stig-scap-release-delta-applicability-agreement-and-drift-v2"
        ),
        "iec-62443-patch-management-exercise": (
            "iec62443-2-3-advisory-qualification-safe-deployment-rollback-and-outcome-v2"
        ),
        "do355-continuing-airworthiness-exercise": (
            "do355a-arp5150b-arp5151b-service-signal-safety-security-and-fleet-effectiveness-v2"
        ),
        "swift-cscf-independent-assessment": (
            "swift-cscf-2026-annual-delta-applicability-reliance-and-independent-assessment-v2"
        ),
        "ccsds-space-mission-link-security": (
            "ccsds-threat-architecture-credential-sdls-protocol-resilience-conformance-v1"
        ),
    }

    for identifier, normalizer in expected_normalizers.items():
        assert identifier in benchmarks
        assert _benchmark_protocol(identifier) == "conformance"
        assert identifier in _LABORATORY_QUALIFIED_BENCHMARKS
        adapter = benchmark_adapter_spec(identifier)
        assert adapter["normalizer"] == normalizer
        assert len(adapter["required_inputs"]) == 5
        assert adapter["acquisition"]["signed_provenance_required"] is True
        assert adapter["acquisition"]["golden_negative_required"] is True


def test_deepened_profiles_require_longitudinal_and_adversarial_evidence() -> None:
    expectations = {
        "federal-configuration-hardening": {
            "STIG-RELEASE-DELTA-APPLICABILITY-AND-DRIFT"
        },
        "ot-patch-management": {"PATCH-SAFETY-AVAILABILITY-AND-COMPENSATION-OUTCOMES"},
        "financial-messaging-security": {
            "ANNUAL-CSCF-DELTA-SIGNIFICANT-CHANGE-AND-RELIANCE"
        },
    }
    for profile_id, required_controls in expectations.items():
        profile = _ASSURANCE_PROFILES[profile_id]
        assert required_controls <= {item[1] for item in profile["controls"]}
        procedure = profile["procedures"][0]
        assert "benchmark-scorecard.json" in procedure[5]
        assert procedure[2]
