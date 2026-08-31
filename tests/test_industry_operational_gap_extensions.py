from __future__ import annotations

import json
from copy import deepcopy
from typing import Any

import pytest

from py_security_suite.benchmark_adapters import benchmark_execution_contracts
from py_security_suite.industry_assurance import (
    _ASSURANCE_PROFILES,
    _BENCHMARKS,
    _STANDARDS,
)
from py_security_suite.industry_extension_evidence import (
    IndustryExtensionEvidenceError,
    industry_extension_runner_requirements,
    validate_industry_extension_evidence,
)


SOURCE = "d" * 64
SUBJECT = "e" * 64


CLAIMS: dict[str, dict[str, Any]] = {
    "nss-dod-authorization-assurance": {
        "cnssi_1253_revision": "2022-r5",
        "authorities": ["system-owner", "assessor", "authorizing-official"],
        "authorization_packages_evaluated": 12,
        "adverse_cases_replayed": 36,
        "nss_category_baseline_overlay_and_odp_bound": True,
        "tailoring_inheritance_and_compensating_controls_verified": True,
        "rmf_roles_assessment_poam_and_authorization_term_verified": True,
        "significant_change_and_continuous_monitoring_verified": True,
        "controlled_source_and_oscal_provenance_verified": True,
        "independent_government_role_adjudication_completed": True,
        "classified_data_used": False,
        "authorization_decision_claimed": False,
    },
    "zero-trust-zig-microsegmentation-assurance": {
        "zig_release": "2026-primer-discovery-phase1-phase2",
        "pillars": [
            "user",
            "device",
            "network-environment",
            "application-workload",
            "data",
            "visibility-analytics",
            "automation-orchestration",
        ],
        "phase_one_two_activities_evaluated": 77,
        "adverse_paths_replayed": 42,
        "discovery_inventory_identity_flow_and_dependency_graph_verified": True,
        "policy_decision_enforcement_and_continuous_signals_verified": True,
        "lateral_movement_and_cross_pillar_denial_verified": True,
        "fail_closed_propagation_session_revocation_and_outage_verified": True,
        "telemetry_exception_recovery_and_restoration_verified": True,
        "independent_topology_and_policy_replay_completed": True,
        "production_traffic_modified": False,
        "government_maturity_endorsed": False,
    },
    "healthcare-operational-resilience-assurance": {
        "hicp_edition": "2023",
        "scenario_classes": ["ransomware", "identity", "outage", "supplier"],
        "clinical_services_evaluated": 9,
        "exercises_replayed": 20,
        "hicp_and_hph_goal_applicability_bound": True,
        "clinical_ephi_device_facility_and_vendor_dependencies_verified": True,
        "identity_segmentation_backup_and_emergency_access_verified": True,
        "downtime_continuity_restoration_and_reconciliation_verified": True,
        "patient_safety_and_service_outcomes_measured": True,
        "independent_clinical_safety_review_completed": True,
        "real_ephi_used": False,
        "regulatory_compliance_claimed": False,
    },
    "aircraft-system-safety-development-assurance": {
        "assurance_sources": [
            "ARP4754B",
            "ARP4761A",
            "DO-178C",
            "DO-330",
            "DO-326A",
        ],
        "system_cases_evaluated": 16,
        "hazards_evaluated": 48,
        "function_requirement_architecture_item_and_interface_trace_verified": True,
        "dal_allocation_derived_requirements_and_independence_verified": True,
        "fha_pssa_ssa_and_common_cause_reasoning_verified": True,
        "safety_security_interaction_and_tool_qualification_verified": True,
        "change_impact_and_configuration_identity_verified": True,
        "qualified_independent_assessor_adjudication_completed": True,
        "flight_or_production_actuation_performed": False,
        "certification_credit_claimed": False,
    },
    "ilac-laboratory-operating-assurance": {
        "ilac_policies": ["P9:01/2024", "P10:07/2020", "P14:09/2020", "P15:05/2020"],
        "proficiency_results_evaluated": 24,
        "laboratories_evaluated": 4,
        "scope_method_measurand_and_decision_rule_bound": True,
        "metrological_traceability_and_measurement_uncertainty_verified": True,
        "provider_assigned_value_and_proficiency_performance_verified": True,
        "competence_impartiality_and_inspection_independence_verified": True,
        "nonconformity_corrective_action_and_followup_verified": True,
        "blinded_interlaboratory_adjudication_completed": True,
        "accredited_scope_extended": False,
        "accreditation_claimed": False,
    },
    "maritime-operational-cyber-resilience-assurance": {
        "imo_guidance": "MSC-FAL.1/Circ.3/Rev.3",
        "functions": ["govern", "identify", "protect", "detect", "respond", "recover"],
        "operational_modes_evaluated": 6,
        "digital_twin_scenarios_replayed": 30,
        "ship_shore_port_supplier_and_safety_management_scope_bound": True,
        "computer_based_system_inventory_and_dependency_map_verified": True,
        "access_segmentation_media_logging_training_and_supply_chain_verified": True,
        "navigation_machinery_cargo_and_communications_failures_replayed": True,
        "degraded_operation_manual_fallback_recovery_and_reconciliation_verified": True,
        "independent_maritime_safety_review_completed": True,
        "production_vessel_actuation_performed": False,
        "flag_or_class_approval_claimed": False,
    },
    "weakness-prioritization-temporal-calibration": {
        "dimensions": ["cwe-hierarchy", "multi-label", "temporal", "project-holdout"],
        "findings_evaluated": 500,
        "snapshots_evaluated": 12,
        "projects_evaluated": 20,
        "taxonomy_release_abstraction_and_label_policy_bound": True,
        "independent_multi_language_label_audit_completed": True,
        "project_chronology_duplicate_and_near_duplicate_controls_verified": True,
        "point_in_time_epss_kev_and_exploit_outcomes_verified": True,
        "calibration_recall_at_budget_effort_and_response_time_reported": True,
        "misses_label_noise_and_disagreements_adjudicated": True,
        "future_data_used": False,
        "vulnerability_certification_claimed": False,
    },
    "formal-methods-tool-disagreement-assurance": {
        "task_families": ["sv-comp", "test-comp", "rers", "chc"],
        "tasks_evaluated": 120,
        "tools_evaluated": 6,
        "disagreements_adjudicated": 14,
        "task_property_language_semantics_and_resource_model_bound": True,
        "independent_witness_and_generated_test_validation_completed": True,
        "ground_truth_assumptions_and_undefined_behavior_reviewed": True,
        "timeout_memory_parser_and_unsound_witness_cases_replayed": True,
        "solver_and_validator_disagreement_matrix_reported": True,
        "sandbox_restoration_and_artifact_provenance_verified": True,
        "production_proof_claimed": False,
        "formal_certification_claimed": False,
    },
    "process-supplier-assessor-outcome-calibration": {
        "domains": ["process-capability", "supplier-resilience"],
        "assessors_evaluated": 6,
        "projects_evaluated": 18,
        "supplier_incidents_replayed": 24,
        "licensed_criteria_scope_period_and_evidence_bound": True,
        "blinded_assessor_agreement_and_adjudication_completed": True,
        "defect_escape_security_incident_and_recovery_outcomes_joined": True,
        "fourth_party_concentration_substitution_and_exit_verified": True,
        "scope_drift_stale_attestation_and_hidden_dependency_detected": True,
        "longitudinal_uncertainty_reassessment_and_causal_limits_reported": True,
        "individual_performance_ranking_performed": False,
        "capability_certification_claimed": False,
    },
    "incident-privacy-outcome-exercise-calibration": {
        "outcomes": ["containment", "recovery", "individual-impact", "reassessment"],
        "exercises_evaluated": 20,
        "data_flows_evaluated": 40,
        "affected_person_cases_evaluated": 80,
        "incident_service_data_flow_processing_and_recipient_scope_bound": True,
        "detection_containment_eradication_restoration_and_reconciliation_measured": True,
        "privacy_likelihood_severity_rights_and_residual_risk_verified": True,
        "notification_decision_timing_authority_and_exception_verified": True,
        "missed_flow_reidentification_scope_change_and_delay_cases_replayed": True,
        "independent_privacy_legal_and_incident_review_completed": True,
        "real_notification_sent": False,
        "legal_compliance_claimed": False,
    },
}


FALSE_BOUNDARIES = {
    "nss-dod-authorization-assurance": "authorization_decision_claimed",
    "zero-trust-zig-microsegmentation-assurance": "production_traffic_modified",
    "healthcare-operational-resilience-assurance": "real_ephi_used",
    "aircraft-system-safety-development-assurance": "certification_credit_claimed",
    "ilac-laboratory-operating-assurance": "accreditation_claimed",
    "maritime-operational-cyber-resilience-assurance": "production_vessel_actuation_performed",
    "weakness-prioritization-temporal-calibration": "future_data_used",
    "formal-methods-tool-disagreement-assurance": "production_proof_claimed",
    "process-supplier-assessor-outcome-calibration": "capability_certification_claimed",
    "incident-privacy-outcome-exercise-calibration": "real_notification_sent",
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
            "budget_seconds": 600,
        },
        "claims": deepcopy(CLAIMS[identifier]),
        "negative_cases": [
            {"id": "source-tamper", "detected": True},
            {"id": "subject-misbinding", "detected": True},
        ],
        "provenance": {
            "producer": "digest-pinned-gap-normalizer",
            "producer_sha256": "f" * 64,
            "signature_verified": True,
            "independent_replay_verified": True,
        },
        "complete": True,
    }


def test_operational_gap_domains_are_registered_end_to_end() -> None:
    standard_ids = {item["id"] for item in _STANDARDS}
    benchmark_ids = {item["id"] for item in _BENCHMARKS}
    assert {
        "NSA-ZIG-PHASE-2",
        "CNSSI-1253",
        "HHS-HICP",
        "SAE-ARP4754B",
        "ILAC-P9",
        "IMO-MSC-FAL-1-CIRC-3-REV3",
    } <= standard_ids
    assert {
        "national-security-system-authorization",
        "operational-zero-trust-implementation",
        "healthcare-operational-resilience-depth",
        "aircraft-system-development-safety-assurance",
        "accredited-laboratory-operating-assurance",
        "maritime-operational-cyber-risk-depth",
        "empirical-assurance-benchmark-calibration",
    } <= set(_ASSURANCE_PROFILES)
    assert set(CLAIMS) <= benchmark_ids
    assert set(CLAIMS) <= set(benchmark_execution_contracts())


@pytest.mark.parametrize("identifier", sorted(CLAIMS))
def test_operational_gap_evidence_accepts_complete_bound_results(
    identifier: str,
) -> None:
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
    assert "applicability-and-authority-boundary-record" in requirements
    assert len(requirements) >= 10


@pytest.mark.parametrize("identifier", sorted(CLAIMS))
def test_operational_gap_evidence_rejects_false_assurance(identifier: str) -> None:
    document = _evidence(identifier)
    document["claims"][FALSE_BOUNDARIES[identifier]] = True
    with pytest.raises(IndustryExtensionEvidenceError, match="boundaries must hold"):
        validate_industry_extension_evidence(
            json.dumps(document),
            expected_source_sha256=SOURCE,
            expected_subject_sha256=SUBJECT,
        )
