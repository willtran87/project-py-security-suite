from __future__ import annotations

import json
from copy import deepcopy
from typing import Any

import pytest

from py_security_suite.benchmark_adapters import benchmark_adapter_spec
from py_security_suite.industry_assurance import (
    _ASSURANCE_PROFILES,
    _BENCHMARKS,
    _STANDARDS,
    _STANDARDS_WATCHLIST,
    _benchmark_protocol,
)
from py_security_suite.industry_extension_evidence import (
    IndustryExtensionEvidenceError,
    industry_extension_runner_requirements,
    validate_industry_extension_evidence,
)


SOURCE = "1" * 64
SUBJECT = "2" * 64


CLAIMS: dict[str, dict[str, Any]] = {
    "water-sector-cyber-resilience-assurance": {
        "water_baseline": "AWWA-J100-21-G430-24-G440-22-EPA",
        "process_domains": [
            "source-water",
            "treatment",
            "chemical-feed",
            "distribution",
            "laboratory",
            "emergency-operations",
        ],
        "utilities_evaluated": 4,
        "process_stages_evaluated": 30,
        "scenarios_replayed": 96,
        "utility_population_process_asset_dependency_hazard_and_owner_bound": True,
        "water_quality_pressure_flow_chemical_and_availability_invariants_verified": True,
        "identity_remote_access_supplier_monitoring_backup_and_manual_operation_verified": True,
        "sensor_command_ransomware_communications_and_unsafe_automation_cases_replayed": True,
        "emergency_command_public_health_notification_and_alternate_supply_verified": True,
        "restoration_sampling_residue_independent_review_and_reassessment_verified": True,
        "production_water_system_actuated": False,
        "awwa_or_epa_compliance_claimed": False,
    },
    "public-safety-communications-assurance": {
        "communications_baseline": "NENA-NGSEC-I3-TIA102-P25-CAP",
        "service_domains": [
            "psap",
            "esinet",
            "ngcs",
            "location-routing",
            "dispatch",
            "land-mobile-radio",
        ],
        "systems_evaluated": 10,
        "interfaces_evaluated": 48,
        "cases_replayed": 144,
        "psap_esinet_function_interface_identity_route_radio_key_and_owner_bound": True,
        "ng911_message_location_routing_authorization_replay_and_privacy_verified": True,
        "p25_identity_key_lifecycle_emergency_signaling_and_interoperability_verified": True,
        "malformed_false_location_route_overload_site_loss_and_radio_mismatch_replayed": True,
        "dispatch_failover_degraded_mode_continuity_and_restoration_verified": True,
        "independent_ground_truth_traffic_exclusion_and_test_data_destruction_verified": True,
        "live_emergency_traffic_used": False,
        "nena_tia_or_p25_certification_claimed": False,
    },
    "global-gxp-data-integrity-assurance": {
        "gxp_baseline": "EU-ANNEX11-2011-WHO-TRS1033-PICS-PI041-1",
        "integrity_domains": [
            "validation",
            "metadata",
            "audit-trail",
            "electronic-signature",
            "backup-restore",
            "migration-retirement",
        ],
        "systems_evaluated": 8,
        "records_evaluated": 320,
        "mutations_replayed": 120,
        "jurisdiction_process_product_risk_system_record_metadata_and_owner_bound": True,
        "alcoa_plus_time_audit_trail_signature_copy_retention_and_retrieval_verified": True,
        "supplier_access_change_periodic_review_continuity_and_retirement_verified": True,
        "alteration_omission_backdating_shared_credential_clock_and_interface_cases_replayed": True,
        "backup_restore_migration_inspection_copy_and_reconstruction_verified": True,
        "independent_quality_review_current_annex_boundary_and_data_destruction_verified": True,
        "real_regulated_or_patient_data_used": False,
        "regulatory_compliance_or_acceptance_claimed": False,
    },
    "transit-cybersecurity-resilience-assurance": {
        "transit_baseline": "NIST-IR-8576-FINAL-2026",
        "transit_domains": [
            "rail",
            "bus",
            "station",
            "fare",
            "passenger-information",
            "operations-control",
        ],
        "agencies_evaluated": 4,
        "services_evaluated": 24,
        "scenarios_replayed": 90,
        "agency_mode_route_service_safety_it_ot_supplier_and_owner_bound": True,
        "csf_current_target_outcome_tolerance_dependency_and_risk_trace_verified": True,
        "detection_dispatch_manual_operation_passenger_communication_and_continuity_verified": True,
        "account_fare_telemetry_command_ransomware_communications_and_supplier_cases_replayed": True,
        "safety_degraded_operation_restoration_and_state_reconciliation_verified": True,
        "independent_transit_review_lessons_and_profile_reassessment_verified": True,
        "production_transit_system_connected_or_moved": False,
        "nist_or_transit_certification_claimed": False,
    },
    "emergency-incident-coordination-assurance": {
        "incident_baseline": "ISO-22320-2018",
        "coordination_domains": [
            "command",
            "information",
            "decisions",
            "resources",
            "communications",
            "handoff-recovery",
        ],
        "organizations_evaluated": 6,
        "decisions_evaluated": 90,
        "injects_replayed": 72,
        "incident_objective_command_role_authority_action_handoff_and_owner_bound": True,
        "information_source_time_confidence_classification_correction_and_audit_verified": True,
        "common_operating_picture_communications_resource_and_safety_coordination_verified": True,
        "authority_conflict_false_report_loss_mismatch_contention_and_privacy_cases_replayed": True,
        "transfer_demobilization_recovery_after_action_and_corrective_action_verified": True,
        "independent_observer_timing_traceability_and_reassessment_verified": True,
        "live_emergency_service_disrupted": False,
        "iso_certification_claimed": False,
    },
    "gas-scada-cryptographic-assurance": {
        "gas_scada_baseline": "AGA12-P1-API1164-IEC62351",
        "channel_domains": [
            "control-center",
            "field-site",
            "telemetry",
            "command",
            "key-management",
            "manual-control",
        ],
        "sites_evaluated": 12,
        "channels_evaluated": 48,
        "protocol_cases_replayed": 160,
        "endpoint_channel_protocol_message_key_clock_exception_and_owner_bound": True,
        "origin_integrity_confidentiality_replay_sequence_and_time_controls_verified": True,
        "key_establishment_rollover_loss_revocation_and_legacy_coexistence_verified": True,
        "forgery_reorder_delay_downgrade_substitution_clock_and_partition_cases_replayed": True,
        "latency_availability_manual_control_monitoring_restoration_and_reconciliation_verified": True,
        "independent_pipeline_crypto_review_residue_and_key_destruction_verified": True,
        "production_pipeline_connected_or_actuated": False,
        "aga_api_or_iec_certification_claimed": False,
    },
    "ot-water-research-corpus-calibration": {
        "corpus_baseline": "SWAT-WADI-BATADAL-RESEARCH",
        "datasets": ["SWaT", "WADI", "BATADAL"],
        "holdouts": [
            "temporal",
            "facility",
            "attack-family",
            "clean-control",
            "process-physics",
        ],
        "records_evaluated": 1000,
        "attack_windows_evaluated": 100,
        "repeated_trials": 10,
        "release_license_digest_acquisition_chain_and_citation_bound": True,
        "facility_process_sensor_actuator_attack_window_label_and_time_bound": True,
        "duplicate_near_duplicate_training_overlap_and_contamination_measured": True,
        "missingness_drift_label_quality_process_fidelity_and_uncertainty_measured": True,
        "protected_holdout_detection_latency_false_positive_and_generalization_reproduced": True,
        "independent_label_audit_confidence_intervals_and_limitations_reported": True,
        "production_water_system_connected": False,
        "compliance_operational_safety_or_product_claimed": False,
    },
}


FALSE_BOUNDARIES = {
    "water-sector-cyber-resilience-assurance": "production_water_system_actuated",
    "public-safety-communications-assurance": "live_emergency_traffic_used",
    "global-gxp-data-integrity-assurance": "real_regulated_or_patient_data_used",
    "transit-cybersecurity-resilience-assurance": "production_transit_system_connected_or_moved",
    "emergency-incident-coordination-assurance": "live_emergency_service_disrupted",
    "gas-scada-cryptographic-assurance": "production_pipeline_connected_or_actuated",
    "ot-water-research-corpus-calibration": "compliance_operational_safety_or_product_claimed",
}


def _evidence(identifier: str) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "integration": identifier,
        "source_sha256": SOURCE,
        "subject_sha256": SUBJECT,
        "execution": {
            "isolated": True,
            "network_policy": "deny",
            "repetitions": 3,
            "budget_seconds": 1800,
        },
        "claims": deepcopy(CLAIMS[identifier]),
        "negative_cases": [
            {"id": "source-tamper", "detected": True},
            {"id": "subject-misbinding", "detected": True},
            {"id": "domain-false-assurance", "detected": True},
        ],
        "provenance": {
            "producer": "digest-pinned-critical-sector-normalizer",
            "producer_sha256": "3" * 64,
            "signature_verified": True,
            "independent_replay_verified": True,
        },
        "complete": True,
    }


def test_critical_sector_catalogs_profiles_benchmarks_and_adapters_are_complete() -> (
    None
):
    standard_ids = {str(item["id"]) for item in _STANDARDS}
    assert {
        "AWWA-J100",
        "AWWA-G430",
        "AWWA-G440",
        "EPA-WATER-CYBERSECURITY-ASSESSMENT",
        "NENA-STA-040",
        "NENA-REF-012",
        "NENA-STA-010",
        "TIA-102-P25",
        "DHS-P25-CAP",
        "EU-GMP-ANNEX-11",
        "WHO-TRS-1033-ANNEX-4",
        "PICS-PI-041-1",
        "NIST-IR-8576",
        "ISO-22320",
        "AGA-REPORT-12-PART-1",
    } <= standard_ids
    assert {
        "water-sector-cyber-resilience",
        "public-safety-emergency-communications",
        "global-gxp-computerised-system-assurance",
        "transit-cybersecurity-resilience",
        "emergency-incident-coordination",
        "gas-scada-cryptographic-resilience",
    } <= set(_ASSURANCE_PROFILES)
    assert set(CLAIMS) <= {str(item["id"]) for item in _BENCHMARKS}
    for identifier in CLAIMS:
        spec = benchmark_adapter_spec(identifier)
        assert len(spec["required_inputs"]) == 5
        assert "no " in str(spec["isolation"]).lower()


def test_drafts_are_watchlisted_and_research_is_not_a_normative_standard() -> None:
    watch_ids = {str(item["id"]) for item in _STANDARDS_WATCHLIST}
    standard_ids = {str(item["id"]) for item in _STANDARDS}
    assert {"NIST-IR-8546", "EU-GMP-ANNEX-11-REVISION"} <= watch_ids
    assert {"NIST-IR-8546", "EU-GMP-ANNEX-11-REVISION"}.isdisjoint(standard_ids)
    assert {"SWAT", "WADI", "BATADAL"}.isdisjoint(standard_ids)


def test_protocols_preserve_conformance_and_research_boundaries() -> None:
    operational = set(CLAIMS) - {"ot-water-research-corpus-calibration"}
    assert {_benchmark_protocol(item) for item in operational} == {"conformance"}
    assert (
        _benchmark_protocol("ot-water-research-corpus-calibration") == "classification"
    )


def test_semantic_evidence_is_strict_replayable_and_operational() -> None:
    for identifier in CLAIMS:
        document = _evidence(identifier)
        assert (
            validate_industry_extension_evidence(
                json.dumps(document),
                expected_source_sha256=SOURCE,
                expected_subject_sha256=SUBJECT,
            )
            == document
        )
        requirements = industry_extension_runner_requirements(identifier)
        assert "suite-owned-extension-evidence" in requirements
        assert "extension-independent-replay" in requirements
    research_requirements = industry_extension_runner_requirements(
        "ot-water-research-corpus-calibration"
    )
    assert (
        "independent-label-duplicate-and-contamination-audit" in research_requirements
    )
    assert (
        "research-only-no-compliance-safety-or-product-claim-policy"
        in research_requirements
    )


@pytest.mark.parametrize("identifier", sorted(CLAIMS))
def test_false_assurance_boundaries_fail_closed(identifier: str) -> None:
    document = _evidence(identifier)
    document["claims"][FALSE_BOUNDARIES[identifier]] = True
    with pytest.raises(IndustryExtensionEvidenceError, match="boundaries must hold"):
        validate_industry_extension_evidence(
            json.dumps(document),
            expected_source_sha256=SOURCE,
            expected_subject_sha256=SUBJECT,
        )


def test_unknown_semantic_claims_fail_closed() -> None:
    document = _evidence("water-sector-cyber-resilience-assurance")
    document["claims"]["unsupported_claim"] = True
    with pytest.raises(IndustryExtensionEvidenceError, match="fields must be exactly"):
        validate_industry_extension_evidence(
            json.dumps(document),
            expected_source_sha256=SOURCE,
            expected_subject_sha256=SUBJECT,
        )
