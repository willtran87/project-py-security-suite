from __future__ import annotations

import json
from copy import deepcopy
from typing import Any

import pytest

from py_security_suite.industry_extension_evidence import (
    INDUSTRY_EXTENSION_BENCHMARKS,
    IndustryExtensionEvidenceError,
    industry_extension_runner_requirements,
    validate_industry_extension_evidence,
)


SOURCE = "1" * 64
SUBJECT = "2" * 64


CLAIMS: dict[str, dict[str, Any]] = {
    "disa-stig-scap-conformance": {
        "release_policy": "policy-pinned-quarterly-release",
        "assessment_modes": ["xccdf-oval", "manual"],
        "assets_evaluated": 12,
        "rules_evaluated": 240,
        "release_deltas_evaluated": 4,
        "release_signature_digest_and_delta_verified": True,
        "asset_cpe_profile_tailoring_and_applicability_verified": True,
        "automated_manual_and_engine_disagreement_adjudicated": True,
        "exception_poam_owner_and_expiry_verified": True,
        "laboratory_remediation_rollback_and_rescan_verified": True,
        "longitudinal_drift_and_durability_measured": True,
        "production_remediation_performed": False,
        "authorization_claimed": False,
    },
    "iec-62443-patch-management-exercise": {
        "iec_62443_2_3_edition": "2015",
        "lifecycle_phases": [
            "advisory",
            "qualification",
            "deployment",
            "rollback",
            "compensation",
            "restoration",
        ],
        "patches_evaluated": 20,
        "asset_cases_evaluated": 40,
        "signed_advisory_firmware_asset_and_applicability_bound": True,
        "exploit_safety_availability_and_maintenance_window_verified": True,
        "laboratory_qualification_acceptance_and_process_invariants_verified": True,
        "partial_failure_safe_state_rollback_and_restoration_replayed": True,
        "compensating_control_owner_expiry_and_residual_risk_verified": True,
        "deployment_latency_downtime_recurrence_and_outcomes_measured": True,
        "production_process_actuated": False,
        "iec_certification_claimed": False,
    },
    "do355-continuing-airworthiness-exercise": {
        "assurance_sources": ["DO-355A", "ARP5150B", "ARP5151B"],
        "aircraft_populations": ["transport", "general-aviation", "rotorcraft"],
        "service_events_evaluated": 36,
        "aircraft_configurations_evaluated": 18,
        "service_security_reliability_and_maintenance_signals_correlated": True,
        "function_hazard_security_impact_and_uncertainty_verified": True,
        "tail_equipment_software_operator_and_fleet_effectivity_verified": True,
        "interim_action_corrective_action_authority_and_communication_verified": True,
        "field_deployment_effectiveness_recurrence_and_lessons_measured": True,
        "independent_safety_security_adjudication_completed": True,
        "production_aircraft_connected": False,
        "certification_credit_claimed": False,
    },
    "swift-cscf-independent-assessment": {
        "cscf_edition": "2026",
        "assessment_dimensions": [
            "applicability",
            "annual-delta",
            "significant-change",
            "design",
            "operation",
            "reliance",
            "remediation-retest",
        ],
        "bics_evaluated": 3,
        "mandatory_controls_evaluated": 32,
        "samples_replayed": 64,
        "iaf_architecture_connectivity_and_scope_bound": True,
        "assessor_competence_independence_and_sampling_verified": True,
        "mandatory_advisory_exception_and_owner_applicability_verified": True,
        "significant_change_stale_evidence_and_reliance_limit_replayed": True,
        "transaction_recovery_remediation_retest_and_closure_verified": True,
        "annual_cycle_and_kyc_sa_handoff_independently_replayed": True,
        "production_messages_used": False,
        "swift_compliance_claimed": False,
    },
    "ccsds-space-mission-link-security": {
        "sdls_edition": "CCSDS-355.0-B-2",
        "publications": [
            "CCSDS-350.1-G-3",
            "CCSDS-350.7-G-2",
            "CCSDS-351.0-M-1",
            "CCSDS-352.0-B-2",
            "CCSDS-355.0-B-2",
            "CCSDS-355.1-B-1",
            "CCSDS-356.0-B-1",
            "CCSDS-357.0-B-1",
        ],
        "segments": ["ground", "relay", "flight"],
        "mission_profiles_evaluated": 6,
        "protocol_cases_replayed": 80,
        "mission_phase_function_asset_flow_boundary_and_threat_trace_verified": True,
        "security_architecture_domain_entity_service_and_policy_map_verified": True,
        "algorithm_key_credential_security_association_and_sequence_state_verified": True,
        "sdls_header_trailer_managed_parameter_and_protocol_ordering_verified": True,
        "forgery_replay_reorder_delay_downgrade_desync_rollover_and_reset_replayed": True,
        "link_fault_monitoring_recovery_safety_invariant_and_residue_verified": True,
        "production_spacecraft_connected": False,
        "flight_certification_claimed": False,
    },
}


FALSE_BOUNDARIES = {
    "disa-stig-scap-conformance": "authorization_claimed",
    "iec-62443-patch-management-exercise": "production_process_actuated",
    "do355-continuing-airworthiness-exercise": "production_aircraft_connected",
    "swift-cscf-independent-assessment": "swift_compliance_claimed",
    "ccsds-space-mission-link-security": "flight_certification_claimed",
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
            "budget_seconds": 900,
        },
        "claims": deepcopy(CLAIMS[identifier]),
        "negative_cases": [
            {"id": "source-tamper", "detected": True},
            {"id": "subject-misbinding", "detected": True},
            {"id": "domain-false-assurance", "detected": True},
        ],
        "provenance": {
            "producer": "digest-pinned-sector-normalizer",
            "producer_sha256": "3" * 64,
            "signature_verified": True,
            "independent_replay_verified": True,
        },
        "complete": True,
    }


def test_sector_depth_integrations_are_registered_and_accept_complete_evidence() -> (
    None
):
    assert len(INDUSTRY_EXTENSION_BENCHMARKS) == 96
    assert set(CLAIMS) <= INDUSTRY_EXTENSION_BENCHMARKS
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
        assert "domain-specific-adverse-case-report" in requirements
        assert "longitudinal-or-recovery-outcome-record" in requirements


@pytest.mark.parametrize("identifier", sorted(CLAIMS))
def test_sector_depth_false_assurance_boundaries_fail_closed(identifier: str) -> None:
    document = _evidence(identifier)
    document["claims"][FALSE_BOUNDARIES[identifier]] = True
    with pytest.raises(IndustryExtensionEvidenceError, match="boundaries must hold"):
        validate_industry_extension_evidence(
            json.dumps(document),
            expected_source_sha256=SOURCE,
            expected_subject_sha256=SUBJECT,
        )
