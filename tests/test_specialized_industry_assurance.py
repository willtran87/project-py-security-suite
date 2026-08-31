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
)
from py_security_suite.industry_extension_evidence import (
    INDUSTRY_EXTENSION_BENCHMARKS,
    IndustryExtensionEvidenceError,
    industry_extension_runner_requirements,
    validate_industry_extension_evidence,
)


SOURCE = "d" * 64
SUBJECT = "e" * 64


CLAIMS: dict[str, dict[str, Any]] = {
    "semi-fab-equipment-cybersecurity-assurance": {
        "semi_baseline": "E187-0122-E188-0222-E191-policy-pinned",
        "lifecycle_stages": [
            "delivery",
            "installation",
            "operation",
            "service",
            "recovery",
        ],
        "equipment_items_evaluated": 18,
        "service_cases_replayed": 42,
        "status_reports_verified": 90,
        "fab_tool_supplier_device_software_firmware_and_owner_bound": True,
        "os_support_network_endpoint_monitoring_and_exception_controls_verified": True,
        "delivery_media_remote_service_install_upgrade_and_replacement_custody_verified": True,
        "device_status_inventory_vulnerability_protection_and_timestamp_semantics_verified": True,
        "contamination_substitution_report_suppression_and_recovery_cases_replayed": True,
        "known_good_restoration_residue_and_independent_review_verified": True,
        "production_fab_equipment_mutated": False,
        "semi_conformity_claimed": False,
    },
    "api-1164-pipeline-control-resilience": {
        "api_1164_edition": "3-2021",
        "control_domains": [
            "scada",
            "local-control",
            "remote-access",
            "safety-interface",
        ],
        "pipeline_segments_evaluated": 8,
        "essential_functions_evaluated": 24,
        "scenarios_replayed": 72,
        "operator_segment_control_center_asset_zone_conduit_and_owner_bound": True,
        "essential_function_command_telemetry_remote_access_and_manual_operation_verified": True,
        "safety_availability_degraded_mode_and_emergency_response_invariants_verified": True,
        "forgery_replay_ransomware_segmentation_and_communications_failures_replayed": True,
        "restoration_order_configuration_state_and_process_reconciliation_verified": True,
        "independent_pipeline_safety_security_review_completed": True,
        "production_pipeline_actuated": False,
        "api_certification_claimed": False,
    },
    "gxp-part11-data-integrity-assurance": {
        "part11_baseline": "current-2026-08-27",
        "record_controls": [
            "validation",
            "audit-trail",
            "electronic-signature",
            "retention",
            "inspection-copy",
        ],
        "systems_evaluated": 6,
        "records_evaluated": 240,
        "mutations_replayed": 80,
        "predicate_rule_system_record_user_role_signature_and_event_bound": True,
        "accuracy_reliability_access_authority_sequence_and_device_checks_verified": True,
        "audit_trail_signature_record_link_copy_retention_and_retrieval_verified": True,
        "supplier_change_configuration_backup_migration_and_periodic_review_verified": True,
        "alteration_deletion_backdating_replay_shared_credential_and_clock_cases_replayed": True,
        "restoration_data_integrity_and_independent_quality_review_verified": True,
        "real_regulated_records_used": False,
        "fda_compliance_claimed": False,
    },
    "fbi-cjis-security-policy-assurance": {
        "cjis_policy_version": "6.1-2026-06-25",
        "access_contexts": [
            "agency",
            "contractor",
            "cloud",
            "mobile",
            "remote-maintenance",
        ],
        "agencies_evaluated": 5,
        "systems_evaluated": 20,
        "adverse_cases_replayed": 75,
        "csa_agency_personnel_cji_system_device_location_agreement_and_owner_bound": True,
        "purpose_identity_access_privilege_encryption_and_key_custody_verified": True,
        "audit_media_mobile_remote_maintenance_and_physical_controls_verified": True,
        "incident_reporting_retention_sanitization_and_corrective_action_verified": True,
        "stale_personnel_device_loss_cloud_gap_misuse_suppression_and_disclosure_replayed": True,
        "policy_version_jurisdiction_and_independent_review_verified": True,
        "real_cji_used": False,
        "fbi_approval_claimed": False,
    },
    "automotive-spice-capability-assurance": {
        "pam_version": "Automotive-SPICE-4.0",
        "assessment_dimensions": [
            "process-outcome",
            "base-practice",
            "information-item",
            "capability-attribute",
            "cybersecurity-trace",
        ],
        "processes_evaluated": 12,
        "work_products_evaluated": 180,
        "assessors_calibrated": 8,
        "organization_project_scope_process_outcome_and_sample_bound": True,
        "base_practice_information_item_work_product_and_evidence_trace_verified": True,
        "capability_attribute_rating_strength_weakness_and_action_verified": True,
        "cybersecurity_goal_requirement_architecture_test_and_supplier_trace_verified": True,
        "substitution_sampling_gap_rating_inflation_conflict_and_omission_cases_replayed": True,
        "blinded_agreement_adjudication_competence_and_independence_verified": True,
        "individual_public_ranking_performed": False,
        "automotive_spice_certification_claimed": False,
    },
    "iec-61511-sis-safety-security-assurance": {
        "iec_61511_edition": "2016-AMD1-2017",
        "sis_lifecycle": [
            "hazard",
            "specification",
            "design",
            "validation",
            "operation",
            "proof-test",
            "modification",
        ],
        "sifs_evaluated": 16,
        "demands_replayed": 48,
        "fault_cases_replayed": 96,
        "process_hazard_sif_sil_srs_architecture_component_and_owner_bound": True,
        "risk_reduction_independence_diagnostic_timing_and_safe_state_verified": True,
        "application_program_validation_operation_bypass_and_proof_test_verified": True,
        "functional_safety_security_dependency_and_control_conflict_verified": True,
        "dangerous_common_cause_logic_change_delay_partial_trip_and_recovery_replayed": True,
        "restored_state_residue_and_independent_safety_security_review_verified": True,
        "production_process_actuated": False,
        "iec_safety_certification_claimed": False,
    },
    "bacnet-secure-connect-assurance": {
        "bacnet_baseline": "ANSI-ASHRAE-135-2024",
        "node_roles": ["node", "primary-hub", "failover-hub", "legacy-gateway"],
        "buildings_evaluated": 4,
        "devices_evaluated": 48,
        "protocol_cases_replayed": 120,
        "building_device_node_hub_vmac_certificate_object_command_and_owner_bound": True,
        "trust_store_certificate_lifecycle_mutual_auth_and_authorization_verified": True,
        "segmentation_hub_failover_broadcast_time_logging_and_remote_admin_verified": True,
        "legacy_gateway_operator_override_safe_fallback_and_life_safety_boundary_verified": True,
        "certificate_substitution_replay_write_partition_time_and_failover_cases_replayed": True,
        "restoration_certificate_cleanup_and_independent_review_verified": True,
        "occupied_building_actuated": False,
        "bacnet_certification_claimed": False,
    },
    "industrial-robotics-safety-security-assurance": {
        "robot_safety_baseline": "ISO-10218-1-2-2025",
        "robot_classes": [
            "fixed-industrial",
            "collaborative-application",
            "industrial-mobile",
        ],
        "robots_evaluated": 12,
        "cells_evaluated": 8,
        "scenarios_replayed": 90,
        "robot_controller_software_cell_zone_tool_workpiece_map_and_owner_bound": True,
        "mode_stop_speed_space_limit_enabling_device_and_diagnostic_functions_verified": True,
        "cell_mobile_route_safeguard_human_interaction_restart_and_maintenance_verified": True,
        "cybersecurity_dependency_command_integrity_sensor_and_change_controls_verified": True,
        "mode_confusion_intrusion_sensor_loss_injection_limit_failure_and_conflict_replayed": True,
        "safe_state_homing_residue_and_independent_machine_safety_review_verified": True,
        "production_robot_motion_performed": False,
        "robot_safety_certification_claimed": False,
    },
    "data-centre-facility-resilience-assurance": {
        "facility_baseline": "ISO-IEC-22237-TIA-942-C",
        "infrastructure_domains": [
            "power",
            "cooling",
            "telecommunications",
            "fire",
            "physical-security",
            "monitoring",
        ],
        "facilities_evaluated": 4,
        "topologies_evaluated": 12,
        "failure_cases_replayed": 84,
        "site_building_room_service_tenant_class_dependency_and_owner_bound": True,
        "power_cooling_cabling_fire_access_monitoring_and_capacity_evidence_verified": True,
        "redundancy_maintainability_fault_tolerance_and_resilience_kpis_reproduced": True,
        "utility_generator_ups_cooling_path_access_sensor_and_maintenance_failures_replayed": True,
        "cascading_load_safe_operation_restoration_and_post_state_reconciliation_verified": True,
        "model_validity_and_independent_facility_safety_security_review_verified": True,
        "production_facility_disrupted": False,
        "facility_certification_claimed": False,
    },
}


FALSE_BOUNDARIES = {
    "semi-fab-equipment-cybersecurity-assurance": "production_fab_equipment_mutated",
    "api-1164-pipeline-control-resilience": "production_pipeline_actuated",
    "gxp-part11-data-integrity-assurance": "real_regulated_records_used",
    "fbi-cjis-security-policy-assurance": "real_cji_used",
    "automotive-spice-capability-assurance": "automotive_spice_certification_claimed",
    "iec-61511-sis-safety-security-assurance": "production_process_actuated",
    "bacnet-secure-connect-assurance": "occupied_building_actuated",
    "industrial-robotics-safety-security-assurance": "production_robot_motion_performed",
    "data-centre-facility-resilience-assurance": "production_facility_disrupted",
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
            "budget_seconds": 1200,
        },
        "claims": deepcopy(CLAIMS[identifier]),
        "negative_cases": [
            {"id": "source-tamper", "detected": True},
            {"id": "subject-misbinding", "detected": True},
            {"id": "domain-false-assurance", "detected": True},
        ],
        "provenance": {
            "producer": "digest-pinned-specialized-sector-normalizer",
            "producer_sha256": "f" * 64,
            "signature_verified": True,
            "independent_replay_verified": True,
        },
        "complete": True,
    }


def test_specialized_sector_catalogs_profiles_benchmarks_and_adapters() -> None:
    standard_ids = {str(item["id"]) for item in _STANDARDS}
    assert {
        "SEMI-E187",
        "SEMI-E188",
        "SEMI-E191",
        "API-STD-1164",
        "FDA-21-CFR-PART-11",
        "ISPE-GAMP-5",
        "FBI-CJIS-SECURITY-POLICY",
        "AUTOMOTIVE-SPICE-PAM",
        "AUTOMOTIVE-SPICE-CYBERSECURITY",
        "IEC-61511-1",
        "IEC-TR-63069",
        "ANSI-ASHRAE-135",
        "ISO-10218-1",
        "ISO-10218-2",
        "ANSI-RIA-R15-08-1",
        "ISO-IEC-22237-1",
        "ISO-IEC-22237-2",
        "ISO-IEC-TS-22237-31",
        "ANSI-TIA-942-C",
    } <= standard_ids
    assert {
        "semiconductor-equipment-cybersecurity",
        "pipeline-control-system-cybersecurity",
        "gxp-computerized-system-data-integrity",
        "criminal-justice-information-security",
        "automotive-process-capability-assurance",
        "process-industry-functional-safety-security",
        "building-automation-secure-connect",
        "industrial-robotics-safety-security",
        "data-centre-facility-resilience",
    } <= set(_ASSURANCE_PROFILES)
    assert set(CLAIMS) <= {str(item["id"]) for item in _BENCHMARKS}
    assert set(CLAIMS) <= INDUSTRY_EXTENSION_BENCHMARKS
    for identifier in CLAIMS:
        spec = benchmark_adapter_spec(identifier)
        assert len(spec["required_inputs"]) >= 5
        assert "no " in str(spec["isolation"]).lower()


def test_specialized_sector_evidence_is_strict_replayable_and_operational() -> None:
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
def test_specialized_sector_false_assurance_boundaries_fail_closed(
    identifier: str,
) -> None:
    document = _evidence(identifier)
    document["claims"][FALSE_BOUNDARIES[identifier]] = True
    with pytest.raises(IndustryExtensionEvidenceError, match="boundaries must hold"):
        validate_industry_extension_evidence(
            json.dumps(document),
            expected_source_sha256=SOURCE,
            expected_subject_sha256=SUBJECT,
        )
