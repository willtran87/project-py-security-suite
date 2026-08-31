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
    IndustryExtensionEvidenceError,
    industry_extension_runner_requirements,
    validate_industry_extension_evidence,
)


SOURCE = "a" * 64
SUBJECT = "b" * 64


CLAIMS: dict[str, dict[str, Any]] = {
    "firmware-resilience-measured-boot": {
        "platform_scope": "client-server-bus-based",
        "assurance_sources": [
            "NIST-SP-800-147",
            "NIST-SP-800-147B",
            "NIST-SP-800-193",
            "NIST-SP-1800-34",
            "NIST-CSWP-45",
            "NIST-CSWP-52",
            "TCG-TPM-2.0",
        ],
        "platforms_evaluated": 6,
        "components_evaluated": 48,
        "fault_cases_replayed": 96,
        "platform_component_firmware_provenance_and_certificate_bound": True,
        "root_of_trust_update_signing_revocation_and_anti_rollback_verified": True,
        "measured_boot_event_log_pcr_quote_freshness_and_verifier_replayed": True,
        "hardware_weakness_attack_threat_and_sensitivity_metrics_reproduced": True,
        "bus_monitor_detection_consensus_false_positive_and_blind_spot_measured": True,
        "known_good_recovery_post_state_and_residue_independently_verified": True,
        "production_device_mutated": False,
        "platform_certification_claimed": False,
    },
    "cis-kubernetes-hardening-conformance": {
        "kubernetes_minor": "1.36",
        "pod_security_levels": ["privileged", "baseline", "restricted"],
        "admission_modes": ["enforce", "audit", "warn"],
        "clusters_evaluated": 4,
        "namespaces_evaluated": 32,
        "admission_cases_replayed": 144,
        "cluster_distribution_version_role_os_and_responsibility_bound": True,
        "namespace_level_mode_version_exemption_owner_and_expiry_verified": True,
        "direct_pod_controller_template_and_dry_run_admission_replayed": True,
        "restricted_field_os_semantics_webhook_and_upgrade_drift_verified": True,
        "bypass_exception_compensating_control_and_privileged_scope_adjudicated": True,
        "remediation_cleanup_rescan_audit_and_warning_evidence_verified": True,
        "production_cluster_mutated": False,
        "kubernetes_certification_claimed": False,
    },
    "pci-payment-acceptance-conformance": {
        "emv_3ds_version": "2.3.1.1",
        "payment_components": [
            "mpoc",
            "p2pe",
            "pin",
            "pts-poi",
            "hsm",
            "acs",
            "directory-server",
            "3ds-server",
        ],
        "devices_evaluated": 12,
        "key_ceremonies_replayed": 18,
        "transactions_replayed": 240,
        "solution_component_account_pin_key_device_hsm_and_3ds_flow_bound": True,
        "pin_block_key_block_split_knowledge_dual_control_and_destruction_verified": True,
        "poi_model_firmware_sred_tamper_inventory_and_listing_scope_verified": True,
        "acs_directory_server_3ds_server_message_and_assessor_scope_verified": True,
        "substitution_cleartext_replay_downgrade_outage_and_recovery_replayed": True,
        "synthetic_data_test_key_cleanup_retest_and_independent_review_verified": True,
        "live_pan_or_pin_used": False,
        "pci_or_emv_validation_claimed": False,
    },
    "ecss-space-software-product-assurance": {
        "ecss_q_st_80_edition": "Rev.2-2025",
        "software_segments": ["flight", "ground"],
        "lifecycle_phases": [
            "requirements",
            "architecture",
            "implementation",
            "verification",
            "validation",
            "operations",
            "maintenance",
        ],
        "software_items_evaluated": 14,
        "requirements_evaluated": 320,
        "mutations_replayed": 80,
        "mission_system_software_item_criticality_and_tailoring_bound": True,
        "bidirectional_requirement_architecture_interface_code_and_test_trace_verified": True,
        "product_assurance_independence_supplier_reuse_cots_and_tool_evidence_verified": True,
        "coverage_review_metric_configuration_nonconformance_and_anomaly_closure_verified": True,
        "traceability_reuse_interface_substitution_and_acceptance_mutations_replayed": True,
        "corrected_package_residual_risk_and_independent_replay_verified": True,
        "production_mission_connected": False,
        "space_qualification_claimed": False,
    },
    "regional-financial-technology-resilience-assurance": {
        "jurisdictions": ["australia", "singapore"],
        "outcome_dimensions": [
            "technology-risk",
            "information-security",
            "critical-operation-tolerance",
            "supplier-resilience",
            "incident-response",
            "recovery-reconciliation",
        ],
        "entities_evaluated": 4,
        "critical_operations_evaluated": 20,
        "scenarios_replayed": 72,
        "entity_jurisdiction_obligation_guidance_and_applicability_bound": True,
        "critical_operation_tolerance_asset_dependency_provider_and_owner_verified": True,
        "control_design_operation_independent_test_and_board_oversight_verified": True,
        "incident_materiality_escalation_notification_decision_and_timing_replayed": True,
        "cyber_cloud_fourth_party_concentration_corruption_and_outage_cases_replayed": True,
        "restoration_reconciliation_lessons_remediation_and_reassessment_verified": True,
        "production_financial_service_disrupted": False,
        "regulatory_compliance_claimed": False,
    },
    "secure-information-sharing-competence-assurance": {
        "handling_policies": ["TLP-2.0", "IEP-2.0"],
        "roles": ["originator", "releaser", "recipient", "assessor"],
        "communities_evaluated": 6,
        "sharing_cases_replayed": 90,
        "assessors_calibrated": 8,
        "community_organization_participant_purpose_agreement_and_scope_bound": True,
        "classification_originator_control_recipient_forwarding_retention_and_withdrawal_verified": True,
        "transport_privacy_incident_containment_deletion_and_audit_evidence_verified": True,
        "role_competence_independence_golden_case_agreement_bias_and_drift_measured": True,
        "economic_alternatives_assumptions_cost_benefit_uncertainty_and_outcomes_verified": True,
        "misclassification_confusion_leakage_expiry_conflict_and_reassessment_replayed": True,
        "real_sensitive_information_shared": False,
        "individual_public_ranking_performed": False,
        "iso_certification_claimed": False,
    },
}


FALSE_BOUNDARIES = {
    "firmware-resilience-measured-boot": "production_device_mutated",
    "cis-kubernetes-hardening-conformance": "production_cluster_mutated",
    "pci-payment-acceptance-conformance": "live_pan_or_pin_used",
    "ecss-space-software-product-assurance": "space_qualification_claimed",
    "regional-financial-technology-resilience-assurance": "regulatory_compliance_claimed",
    "secure-information-sharing-competence-assurance": "individual_public_ranking_performed",
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
            "producer": "digest-pinned-industry-normalizer",
            "producer_sha256": "c" * 64,
            "signature_verified": True,
            "independent_replay_verified": True,
        },
        "complete": True,
    }


def test_remaining_gap_catalog_profiles_benchmarks_and_adapters_are_complete() -> None:
    standard_ids = {str(item["id"]) for item in _STANDARDS}
    assert {
        "NIST-SP-800-147",
        "NIST-SP-800-147B",
        "NIST-SP-1800-34",
        "NIST-CSWP-45",
        "NIST-CSWP-52",
        "ECSS-E-ST-40C",
        "ECSS-Q-ST-80C-REV2",
        "KUBERNETES-POD-SECURITY-STANDARDS",
        "PCI-PIN-SECURITY",
        "PCI-PTS-POI",
        "PCI-3DS-CORE",
        "EMVCO-3DS",
        "APRA-CPS-230",
        "APRA-CPS-234",
        "MAS-TRM",
        "ISO-IEC-27010",
        "ISO-IEC-TR-27016",
        "ISO-IEC-27021",
    } <= standard_ids
    assert {
        "space-software-product-assurance",
        "regional-financial-technology-resilience",
        "secure-information-sharing-and-competence",
    } <= set(_ASSURANCE_PROFILES)
    assert set(CLAIMS) <= {str(item["id"]) for item in _BENCHMARKS}
    for identifier in CLAIMS:
        spec = benchmark_adapter_spec(identifier)
        assert len(spec["required_inputs"]) >= 5
        assert "no " in str(spec["isolation"]).lower()


def test_remaining_gap_semantic_evidence_is_strict_and_operational() -> None:
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
def test_remaining_gap_false_assurance_boundaries_fail_closed(identifier: str) -> None:
    document = _evidence(identifier)
    document["claims"][FALSE_BOUNDARIES[identifier]] = True
    with pytest.raises(IndustryExtensionEvidenceError, match="boundaries must hold"):
        validate_industry_extension_evidence(
            json.dumps(document),
            expected_source_sha256=SOURCE,
            expected_subject_sha256=SUBJECT,
        )
