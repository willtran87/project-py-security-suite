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
    _STANDARDS_WATCHLIST,
)
from py_security_suite.industry_extension_evidence import (
    IndustryExtensionEvidenceError,
    industry_extension_runner_requirements,
    validate_industry_extension_evidence,
)


SOURCE = "a" * 64
SUBJECT = "b" * 64


def test_new_industry_domains_are_registered_end_to_end() -> None:
    standard_ids = {item["id"] for item in _STANDARDS}
    profile_ids = set(_ASSURANCE_PROFILES)
    benchmark_ids = {item["id"] for item in _BENCHMARKS}
    contracts = benchmark_execution_contracts()
    assert {
        "ANSI-AAMI-SW96",
        "IEC-80001-1",
        "ISO-PAS-8800",
        "MISRA-CPP",
        "TCG-ATTESTATION-FRAMEWORK",
        "EAC-VVSG",
        "IEC-62645",
        "NASA-STD-8739-8B",
    } <= standard_ids
    assert {
        "medical-device-cybersecurity-depth",
        "autonomous-physical-ai-safety",
        "critical-c-cpp-coding-assurance",
        "cross-vendor-confidential-computing-attestation",
        "voting-system-assurance",
        "critical-sector-safety-security",
        "stateful-smart-contract-assurance",
    } <= profile_ids
    assert set(CLAIMS) <= benchmark_ids
    assert set(CLAIMS) <= set(contracts)
    watch = {item["id"]: item for item in _STANDARDS_WATCHLIST}
    assert watch["OWASP-SCSVS"]["status"] == "alpha"


CLAIMS: dict[str, dict[str, Any]] = {
    "medical-device-cybersecurity-assurance": {
        "criteria_version": "sw96-2023-iec80001-2021-iec60601-4-5-2021",
        "device_types": ["embedded", "software", "connected"],
        "devices_evaluated": 6,
        "adversarial_cases_replayed": 24,
        "security_risk_and_patient_harm_trace_verified": True,
        "capability_levels_and_clinical_zones_verified": True,
        "manufacturer_operator_and_service_responsibility_verified": True,
        "sbom_legacy_patch_and_end_of_support_verified": True,
        "clinical_availability_and_safe_recovery_verified": True,
        "independent_medical_safety_review_completed": True,
        "real_patient_data_used": False,
        "regulatory_certification_claimed": False,
    },
    "autonomous-physical-ai-safety": {
        "standards": [
            "ISO-21448:2022",
            "ISO-PAS-8800:2024",
            "ISO-34502:2022",
            "UL-4600:ED3",
        ],
        "scenario_classes": ["nominal", "boundary", "rare", "adversarial"],
        "scenarios_evaluated": 80,
        "ai_element_data_odd_and_hazard_binding_verified": True,
        "sensor_timing_map_weather_and_actor_mutations_replayed": True,
        "monitor_fallback_and_safe_state_verified": True,
        "scenario_coverage_and_metamorphic_consistency_verified": True,
        "deterministic_reproduction_verified": True,
        "independent_safety_case_review_completed": True,
        "real_world_actuation_performed": False,
        "product_certification_claimed": False,
    },
    "critical-c-cpp-coding-conformance": {
        "editions": ["MISRA-C:2023", "MISRA-CPP:2023"],
        "compiler_families": ["gcc", "clang", "msvc"],
        "cases_evaluated": 120,
        "rules_evaluated": 179,
        "licensed_rule_digest_bound": True,
        "language_mode_target_and_optimization_bound": True,
        "positive_negative_and_ambiguous_oracles_verified": True,
        "compiler_warning_sanitizer_and_runtime_corroboration_verified": True,
        "deviation_approval_and_expiry_verified": True,
        "independent_disagreement_adjudication_completed": True,
        "production_binary_executed": False,
        "misra_certification_claimed": False,
    },
    "confidential-computing-attestation-conformance": {
        "rats_architecture": "RFC9334",
        "eat_version": "RFC9711",
        "platforms": ["amd-sev-snp", "intel-tdx", "arm-cca"],
        "roles": ["attester", "verifier", "relying-party"],
        "evidence_vectors_evaluated": 36,
        "endorsement_reference_value_and_appraisal_policy_bound": True,
        "signature_measurement_freshness_and_tcb_verified": True,
        "revocation_debug_and_outage_behavior_verified": True,
        "replay_downgrade_claim_confusion_and_substitution_detected": True,
        "cross_vendor_semantic_differences_preserved": True,
        "independent_verifier_replayed": True,
        "secret_release_failed_closed": True,
        "production_secret_released": False,
        "hardware_certification_claimed": False,
    },
    "vvsg-voting-system-assurance": {
        "vvsg_version": "2.0",
        "test_assertions_version": "1.4",
        "assertions_evaluated": 40,
        "applicability_matrix_complete": True,
        "software_independence_and_auditability_verified": True,
        "security_accessibility_reliability_and_usability_verified": True,
        "ballot_record_log_media_network_and_power_cases_replayed": True,
        "chain_of_custody_and_build_identity_verified": True,
        "deterministic_synthetic_election_reset_verified": True,
        "vstl_and_jurisdiction_claim_boundaries_verified": True,
        "real_ballots_or_voter_data_used": False,
        "eac_certification_claimed": False,
    },
    "critical-sector-safety-security-assurance": {
        "sectors": ["nuclear", "rail", "space"],
        "digital_twin_scenarios_evaluated": 36,
        "sector_specific_applicability_and_licensed_criteria_bound": True,
        "essential_function_hazard_zone_conduit_and_mode_map_verified": True,
        "safety_security_interaction_and_independence_verified": True,
        "loss_of_view_control_timing_sequence_and_communication_replayed": True,
        "degraded_operation_recovery_and_reconciliation_verified": True,
        "qualified_independent_assurance_and_ivv_completed": True,
        "production_actuation_performed": False,
        "sector_certification_claimed": False,
    },
    "stateful-smart-contract-security": {
        "chain_type": "disposable-local-evm",
        "normative_sources": ["OWASP-SMART-CONTRACT-TOP10", "SMARTBUGS-2"],
        "contracts_evaluated": 48,
        "multi_transaction_cases_replayed": 96,
        "source_compiler_bytecode_deployment_and_chain_bound": True,
        "roles_assets_state_governance_proxy_oracle_and_bridge_modeled": True,
        "exploit_balance_state_liveness_and_economic_invariants_verified": True,
        "reentrancy_price_signature_ordering_upgrade_and_dos_cases_replayed": True,
        "clean_controls_and_fix_replay_verified": True,
        "deterministic_chain_reset_and_independent_exploit_replay_verified": True,
        "alpha_scsvs_included": False,
        "real_assets_used": False,
        "audit_certification_claimed": False,
    },
    "devsecops-test-maturity-longitudinal": {
        "dora_metric_set": "five",
        "maturity_models": ["samm", "dsomm", "dsovs", "tmmi"],
        "periods_evaluated": 4,
        "teams_evaluated": 6,
        "blinded_cases_evaluated": 24,
        "organization_product_team_and_period_scope_bound": True,
        "immutable_delivery_events_and_metric_definitions_verified": True,
        "quality_security_defect_escape_and_test_outcomes_joined": True,
        "scope_drift_level_inflation_and_metric_gaming_detected": True,
        "licensed_model_content_protected": True,
        "independent_assessor_agreement_and_adjudication_completed": True,
        "longitudinal_uncertainty_and_causal_limits_reported": True,
        "individual_performance_ranking_performed": False,
        "maturity_certification_claimed": False,
    },
    "detection-product-longitudinal-calibration": {
        "outcome_dimensions": [
            "visibility",
            "detection",
            "protection",
            "false-positive",
            "latency",
        ],
        "variant_classes": [
            "encoding",
            "fragmentation",
            "lolbin",
            "timing",
            "policy",
            "sensor-outage",
        ],
        "attack_steps_replayed": 48,
        "benign_workloads_replayed": 24,
        "product_versions_evaluated": 3,
        "product_policy_sensor_content_environment_and_time_bound": True,
        "independent_step_level_ground_truth_verified": True,
        "telemetry_normalization_preserved_source_semantics": True,
        "benign_false_positive_and_adversary_evasion_measured": True,
        "version_content_and_environment_drift_reported": True,
        "misses_false_positives_and_disagreements_adjudicated": True,
        "laboratory_restoration_verified": True,
        "live_malware_used": False,
        "vendor_endorsement_or_certification_claimed": False,
    },
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
            "budget_seconds": 300,
        },
        "claims": deepcopy(CLAIMS[identifier]),
        "negative_cases": [
            {"id": "tamper", "detected": True},
            {"id": "subject-misbinding", "detected": True},
        ],
        "provenance": {
            "producer": "digest-pinned-test-normalizer",
            "producer_sha256": "c" * 64,
            "signature_verified": True,
            "independent_replay_verified": True,
        },
        "complete": True,
    }


@pytest.mark.parametrize("identifier", sorted(CLAIMS))
def test_new_domain_evidence_accepts_complete_bound_results(identifier: str) -> None:
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
    assert len(requirements) >= 8


@pytest.mark.parametrize(
    ("identifier", "field"),
    [
        ("medical-device-cybersecurity-assurance", "regulatory_certification_claimed"),
        ("autonomous-physical-ai-safety", "real_world_actuation_performed"),
        ("critical-c-cpp-coding-conformance", "misra_certification_claimed"),
        (
            "confidential-computing-attestation-conformance",
            "production_secret_released",
        ),
        ("vvsg-voting-system-assurance", "real_ballots_or_voter_data_used"),
        ("critical-sector-safety-security-assurance", "production_actuation_performed"),
        ("stateful-smart-contract-security", "alpha_scsvs_included"),
        ("devsecops-test-maturity-longitudinal", "maturity_certification_claimed"),
        ("detection-product-longitudinal-calibration", "live_malware_used"),
    ],
)
def test_new_domain_evidence_rejects_false_assurance(
    identifier: str, field: str
) -> None:
    document = _evidence(identifier)
    document["claims"][field] = True
    with pytest.raises(IndustryExtensionEvidenceError, match="boundaries must hold"):
        validate_industry_extension_evidence(
            json.dumps(document),
            expected_source_sha256=SOURCE,
            expected_subject_sha256=SUBJECT,
        )
