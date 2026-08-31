from __future__ import annotations

import json
from copy import deepcopy
from typing import Any

import pytest

from py_security_suite.industry_extension_evidence import (
    IndustryExtensionEvidenceError,
    industry_extension_runner_requirements,
    industry_extension_score_evidence_valid,
    validate_industry_extension_evidence,
)
from py_security_suite.industry_assurance import _benchmark_reproducibility_gaps


SOURCE = "a" * 64
SUBJECT = "b" * 64


def _claims() -> dict[str, dict[str, Any]]:
    return {
        "oss-crs-crsbench": {
            "challenges_evaluated": 117,
            "valid_povs": 12,
            "functional_regressions": 0,
            "hidden_set_separated": True,
            "confidence_bounds_reported": True,
        },
        "openssf-security-insights-conformance": {
            "schema_version": "1.0.0",
            "repository_bound": True,
            "expiry_checked": True,
            "future_schema_quarantined": True,
            "source_provenance_preserved": True,
        },
        "guac-interoperability": {
            "formats": ["cyclonedx", "spdx", "slsa", "vex", "scorecard"],
            "identity_conflicts": 0,
            "query_oracle_passes": 25,
            "roundtrip_verified": True,
            "source_provenance_preserved": True,
        },
        "gittuf-source-policy-conformance": {
            "root_verified": True,
            "policy_verified": True,
            "threshold_verified": True,
            "reference_state_verified": True,
            "transparency_log_verified": True,
            "rollback_protection_verified": True,
        },
        "openssf-package-analysis-malicious-packages": {
            "behavior_signals": ["filesystem", "process", "network", "command"],
            "sandbox_verified": True,
            "protected_labels": True,
            "clean_false_positives": 0,
            "feed_snapshot_bound": True,
        },
        "owasp-kubernetes-top10-conformance": {
            "risk_ids": [f"K{index:02d}" for index in range(1, 11)],
            "mutations_detected": 10,
            "nonapplicability_reviewed": True,
        },
        "owasp-cicd-top10-conformance": {
            "risk_ids": [f"CICD-SEC-{index}" for index in range(1, 11)],
            "mutations_detected": 10,
            "nonapplicability_reviewed": True,
        },
        "sbomit-build-observed-sbom": {
            "observations": ["filesystem", "process", "network"],
            "attestation_verified": True,
            "subject_bound": True,
            "declared_observed_reconciled": True,
            "unexplained_dependencies": 0,
        },
        "primevul-real-world-vulnerability-detection": _vulnerability_claims(
            "paired-functions"
        ),
        "diversevul-unseen-project-generalization": _vulnerability_claims(
            "unseen-projects"
        ),
        "cvefixes-chronological-fix-pair-validation": _vulnerability_claims(
            "chronological-fixes"
        ),
        "reposvul-repository-context-validation": {
            **_vulnerability_claims("repository-context"),
            "granularities": ["repository", "file", "function", "line"],
            "dependency_graph_verified": True,
            "tangled_patches_untangled": True,
            "stale_patches_filtered": True,
        },
        "vuleval-repository-dependency-evaluation": {
            **_vulnerability_claims("repository-dependency-tasks"),
            "evaluation_tasks": [
                "function-detection",
                "dependency-prediction",
                "repository-detection",
            ],
            "repository_context_verified": True,
            "dependency_oracle_passes": 12,
            "interprocedural_cases": 8,
        },
        "owasp-mobile-top10-conformance": {
            "risk_ids": [f"M{index}" for index in range(1, 11)],
            "mutations_detected": 10,
            "nonapplicability_reviewed": True,
        },
        "owasp-smart-contract-top10-conformance": {
            "risk_ids": [f"SC{index:02d}" for index in range(1, 11)],
            "mutations_detected": 10,
            "nonapplicability_reviewed": True,
        },
        "cncf-cloud-native-security-controls-conformance": {
            "lifecycle_phases": ["develop", "distribute", "deploy", "runtime"],
            "nist_mappings_verified": True,
            "architecture_evidence_verified": True,
            "safe_mutations_detected": 4,
            "uncovered_applicable_controls": 0,
            "applicability_reviewed": True,
        },
        "mitre-emb3d-property-threat-conformance": {
            "model_version": "2.0.2",
            "device_properties_evaluated": 14,
            "threats_evaluated": 21,
            "properties_to_threats_verified": True,
            "threats_to_mitigations_verified": True,
            "stix_roundtrip_verified": True,
            "residual_risk_reviewed": True,
            "safe_mutations_detected": 5,
        },
        "owasp-business-logic-abuse-top10-conformance": {
            "risk_ids": [f"BLA{index:02d}" for index in range(1, 11)],
            "mutations_detected": 10,
            "nonapplicability_reviewed": True,
        },
        "cncf-supply-chain-best-practices-v2-conformance": {
            "personas": ["producer", "consumer", "operator"],
            "lifecycle_phases": [
                "source",
                "build",
                "distribution",
                "deployment",
                "operation",
            ],
            "ssdf_mapping_verified": True,
            "slsa_mapping_verified": True,
            "s2c2f_mapping_verified": True,
            "safe_mutations_detected": 7,
            "uncovered_applicable_practices": 0,
            "applicability_reviewed": True,
        },
        "owasp-juice-shop": _vulnerable_target_claims("juice-shop-20.0.0"),
        "owasp-webgoat": _vulnerable_target_claims("webgoat-webwolf"),
        "owasp-crapi": _vulnerable_target_claims("crapi"),
        "owasp-api-security-testing-framework": {
            "framework_version": "2.0.1",
            "targets": ["crapi", "vampi", "dvga", "clean-api"],
            "protocols": ["rest", "graphql", "grpc", "mtls", "llm"],
            "rule_manifest_bound": True,
            "cross_target_labels_verified": True,
            "two_identity_oracles_replayed": True,
            "positive_cases": 30,
            "clean_cases": 20,
            "state_reset_verified": True,
            "claimed_coverage_inherited": False,
        },
        "google-fuzzbench": _fuzzing_claims("edge-coverage", 20),
        "magma-ground-truth": _fuzzing_claims("ground-truth-bugs", 10),
        "oss-fuzz-clusterfuzzlite": _fuzzing_claims("continuous-integration", 3),
        "sbom-sca-holdout": {
            "ecosystems": ["python", "npm", "maven"],
            "component_labels": 80,
            "relationship_labels": 120,
            "advisory_labels": 25,
            "source_locks_bound": True,
            "resolver_graphs_verified": True,
            "build_observations_verified": True,
            "installed_artifacts_verified": True,
            "container_layers_verified": True,
            "known_unknowns_replayed": True,
            "project_time_holdouts_verified": True,
            "training_overlap_checked": True,
        },
        "architecture-quality-holdout": {
            "systems_evaluated": 6,
            "rules_evaluated": 24,
            "mutations": [
                "cycle",
                "layering",
                "unstable-dependency",
                "change-coupling",
                "ownership-concentration",
                "architecture-drift",
            ],
            "labels_independently_reviewed": True,
            "project_time_holdouts_verified": True,
            "training_overlap_checked": True,
            "clean_baselines_replayed": True,
            "change_history_bound": True,
            "ownership_bound": True,
            "adjudication_complete": True,
        },
        "epss-kev-temporal-backtest": {
            "snapshot_dates": ["2025-01-01", "2025-04-01", "2025-07-01"],
            "outcome_window_days": 90,
            "cves_evaluated": 1000,
            "strict_asof_verified": True,
            "future_data_excluded": True,
            "aliases_reconciled": True,
            "censoring_documented": True,
            "historical_snapshots_verified": True,
            "brier_score_reported": True,
            "calibration_reported": True,
            "budget_curves_reported": True,
            "time_shift_negative_detected": True,
        },
        "scim-lifecycle-security-conformance": {
            "rfc_set": ["RFC7643", "RFC7644", "RFC9865", "RFC9967"],
            "lifecycle_operations": [
                "create",
                "read",
                "replace",
                "patch",
                "delete",
                "deprovision",
            ],
            "resources_evaluated": 24,
            "schema_and_mutability_verified": True,
            "tenant_and_role_authorization_verified": True,
            "filter_bulk_etag_verified": True,
            "cursor_integrity_and_expiry_verified": True,
            "deprovision_and_tombstone_verified": True,
            "set_signature_and_replay_verified": True,
            "roundtrip_verified": True,
            "clean_controls_passed": True,
        },
        "openid-shared-signals-conformance": {
            "profiles": ["ssf", "caep", "risc"],
            "delivery_modes": ["push", "poll"],
            "event_types_evaluated": 12,
            "metadata_and_stream_management_verified": True,
            "set_claims_verified": True,
            "replay_and_subject_confusion_detected": True,
            "ordering_and_removal_verified": True,
            "key_rotation_and_outage_verified": True,
            "revocation_latency_reported": True,
            "upstream_conformance_alpha_acknowledged": True,
            "openid_certification_claimed": False,
        },
        "authzen-authorization-api-conformance": {
            "specification_version": "1.0",
            "roles": ["pdp", "pep"],
            "decisions_evaluated": 32,
            "metadata_and_capability_negotiation_verified": True,
            "subject_resource_action_context_binding_verified": True,
            "single_and_batch_evaluation_verified": True,
            "search_capabilities_verified": True,
            "fail_closed_default_verified": True,
            "type_tenant_and_context_confusion_detected": True,
            "stale_policy_and_cache_detected": True,
            "partial_failure_timeout_and_outage_handled": True,
            "draft_profiles_included": False,
            "openid_certification_claimed": False,
        },
        "openid-federation-conformance": {
            "specifications": [
                "openid-federation-1.1",
                "openid-federation-connect-1.1",
            ],
            "entity_roles": ["trust-anchor", "intermediate", "leaf"],
            "trust_chains_evaluated": 12,
            "entity_statement_signature_verified": True,
            "authority_hint_and_path_resolution_verified": True,
            "metadata_policy_application_verified": True,
            "trust_mark_and_oidc_binding_verified": True,
            "key_rollover_expiry_and_revocation_verified": True,
            "cycle_fork_substitution_and_downgrade_detected": True,
            "official_early_suite_acknowledged": True,
            "independent_negative_oracles_replayed": True,
            "openid_certification_claimed": False,
        },
        "nist-hpc-ai-infrastructure-assurance": {
            "publications": ["NIST-SP-800-223", "NIST-SP-800-234"],
            "zones_evaluated": 6,
            "threats_evaluated": 24,
            "tailored_controls_evaluated": 60,
            "reference_architecture_bound": True,
            "moderate_baseline_overlay_verified": True,
            "applicability_odp_and_compensation_verified": True,
            "scheduler_accelerator_storage_and_shared_resource_verified": True,
            "management_plane_and_cross_job_isolation_verified": True,
            "performance_security_tradeoffs_measured": True,
            "recovery_and_residue_checks_verified": True,
            "sp800_239_draft_included": False,
            "nist_certification_claimed": False,
        },
        "iso-24760-identity-management-assurance": {
            "parts": [
                "ISO-IEC-24760-1:2025",
                "ISO-IEC-24760-2:2025",
                "ISO-IEC-24760-3:2025",
            ],
            "principal_types": ["person", "organization", "device", "software"],
            "lifecycle_operations": [
                "proof",
                "enroll",
                "issue",
                "use",
                "maintain",
                "recover",
                "suspend",
                "revoke",
                "delete",
            ],
            "identities_evaluated": 40,
            "concept_and_terminology_consistency_verified": True,
            "reference_architecture_and_authorities_verified": True,
            "identifier_attribute_alias_and_namespace_verified": True,
            "privacy_minimization_and_correlation_verified": True,
            "federation_and_assurance_verified": True,
            "lifecycle_closure_and_authoritative_reconciliation_verified": True,
            "licensed_criteria_used": True,
            "iso_certification_claimed": False,
        },
        "iso-5259-6-data-quality-visualization": {
            "technical_report_version": "2026",
            "quality_measures_evaluated": 12,
            "visualizations_evaluated": 24,
            "measure_dataset_population_and_strata_bound": True,
            "transformation_provenance_and_freshness_verified": True,
            "uncertainty_missingness_and_limitations_visible": True,
            "comparison_context_and_reproduction_verified": True,
            "accessibility_and_role_fitness_verified": True,
            "scale_aggregation_subgroup_color_and_order_mutations_detected": True,
            "technical_report_guidance_only_acknowledged": True,
            "iso_conformance_or_certification_claimed": False,
        },
        "spiffe-workload-identity-conformance": {
            "svid_types": ["x509", "jwt"],
            "trust_domains_evaluated": 3,
            "stable_spec_snapshot_bound": True,
            "node_and_workload_attestation_verified": True,
            "selector_isolation_verified": True,
            "workload_api_authorization_verified": True,
            "bundle_rotation_and_revocation_verified": True,
            "federation_verified": True,
            "impersonation_replay_and_domain_substitution_detected": True,
            "experimental_remote_api_included": False,
        },
        "openssf-model-signing-conformance": {
            "oms_version": "1.0",
            "signing_modes": ["sigstore", "dsse-in-toto", "pki"],
            "official_vectors_passed": 20,
            "schemas_bound": True,
            "all_model_files_manifested": True,
            "signer_identity_verified": True,
            "independent_verifier_replayed": True,
            "partial_duplicate_path_and_tamper_detected": True,
            "key_destruction_verified": True,
            "model_safety_or_quality_claimed": False,
        },
        "cyclonedx-mlbom-conformance": {
            "cyclonedx_version": "1.7",
            "formats": ["json", "xml"],
            "model_components_evaluated": 10,
            "model_card_verified": True,
            "datasets_and_dependencies_verified": True,
            "training_parameters_and_provenance_verified": True,
            "bomlink_verified": True,
            "roundtrip_and_unknown_fields_verified": True,
            "omission_tamper_and_misbinding_detected": True,
            "safety_fairness_or_quality_proof_claimed": False,
        },
        "uptane-ota-security-conformance": {
            "uptane_version": "2.1.0",
            "ecu_verification_modes": ["full", "partial"],
            "vehicles_evaluated": 8,
            "director_and_image_repositories_verified": True,
            "metadata_roles_and_thresholds_verified": True,
            "secure_time_and_expiry_verified": True,
            "pouf_bound": True,
            "install_and_recovery_verified": True,
            "rollback_freeze_mixmatch_compromise_detected": True,
            "certification_claimed": False,
        },
        "darpa-aixcc-autonomous-vulnerability-remediation": {
            "challenges_evaluated": 63,
            "challenge_classes": ["real", "synthetic"],
            "corpus_and_pipeline_bound": True,
            "license_manifest_verified": True,
            "protected_split_verified": True,
            "training_overlap_checked": True,
            "contamination_assessed": True,
            "resource_and_model_budgets_bound": True,
            "povs_independently_validated": True,
            "patches_independently_replayed": True,
            "functional_regressions": 0,
            "real_and_synthetic_results_separated": True,
            "confidence_bounds_reported": True,
            "public_corpus_readiness_inferred": False,
        },
        "openssf-criticality-score-calibration": {
            "snapshots_evaluated": 4,
            "algorithm_and_collector_bound": True,
            "raw_signals_preserved": True,
            "provenance_and_freshness_preserved": True,
            "aliases_reconciled": True,
            "missing_stale_and_outlier_cases_replayed": True,
            "deterministic_recomputation_verified": True,
            "sensitivity_reported": True,
            "downstream_calibration_reported": True,
            "reachability_exploitability_maintenance_separated": True,
            "context_only": True,
            "used_as_security_gate_or_vulnerability_likelihood": False,
        },
    }


def _vulnerability_claims(corpus_oracle: str) -> dict[str, Any]:
    return {
        "corpus_oracle": corpus_oracle,
        "dataset_version_bound": True,
        "license_verified": True,
        "source_revisions_verified": True,
        "label_audit_sample_size": 30,
        "unresolved_label_conflicts": 0,
        "exact_duplicates_removed": True,
        "near_duplicates_measured": True,
        "training_overlap_checked": True,
        "project_disjoint_holdout": True,
        "chronological_holdout": True,
        "fixes_independently_replayed": 5,
        "cwe_stratified_metrics": True,
        "confidence_bounds_reported": True,
    }


def _vulnerable_target_claims(target: str) -> dict[str, Any]:
    return {
        "target": target,
        "target_release_bound": True,
        "target_image_verified": True,
        "label_authority_verified": True,
        "positive_cases": 20,
        "clean_cases": 10,
        "route_coverage_verified": True,
        "state_reset_verified": True,
        "external_egress_blocked": True,
        "multistep_oracles_replayed": True,
        "role_and_session_oracles_replayed": True,
    }


def _fuzzing_claims(oracle: str, trials: int) -> dict[str, Any]:
    return {
        "oracle": oracle,
        "trials": trials,
        "equal_resource_budgets": True,
        "toolchains_bound": True,
        "seeds_bound": True,
        "raw_trial_data_retained": True,
        "independent_replay_verified": True,
        "baseline_control_passed": True,
        "broken_control_detected": True,
        "environment_drift_measured": True,
        "domain_oracles_replayed": True,
    }


def _evidence(integration: str) -> dict[str, Any]:
    repetitions = {
        "google-fuzzbench": 20,
        "magma-ground-truth": 10,
    }.get(integration, 3)
    return {
        "schema_version": "1.0",
        "integration": integration,
        "source_sha256": SOURCE,
        "subject_sha256": SUBJECT,
        "execution": {
            "isolated": True,
            "network_policy": "deny",
            "repetitions": repetitions,
            "budget_seconds": 300,
        },
        "claims": deepcopy(_claims()[integration]),
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


@pytest.mark.parametrize("integration", sorted(_claims()))
def test_all_extension_evidence_contracts_accept_complete_bound_results(
    integration: str,
) -> None:
    document = _evidence(integration)
    result = validate_industry_extension_evidence(
        json.dumps(document),
        expected_source_sha256=SOURCE,
        expected_subject_sha256=SUBJECT,
    )
    assert result == document


@pytest.mark.parametrize(
    ("integration", "mutate", "message"),
    [
        (
            "oss-crs-crsbench",
            lambda item: item["execution"].update(repetitions=2),
            "three trials",
        ),
        (
            "openssf-security-insights-conformance",
            lambda item: item["claims"].update(schema_version="2.2.0"),
            "released schema",
        ),
        (
            "guac-interoperability",
            lambda item: item["claims"].update(identity_conflicts=1),
            "identity conflicts",
        ),
        (
            "guac-interoperability",
            lambda item: item["claims"].update(formats=["cyclonedx"]),
            "required formats",
        ),
        (
            "guac-interoperability",
            lambda item: item["claims"].update(roundtrip_verified=False),
            "roundtrip",
        ),
        (
            "gittuf-source-policy-conformance",
            lambda item: item["claims"].update(threshold_verified=False),
            "required claims",
        ),
        (
            "openssf-package-analysis-malicious-packages",
            lambda item: item["claims"].update(behavior_signals=["filesystem"]),
            "signals",
        ),
        (
            "owasp-kubernetes-top10-conformance",
            lambda item: item["claims"].update(risk_ids=["K01"]),
            "exactly ten",
        ),
        (
            "owasp-cicd-top10-conformance",
            lambda item: item["claims"].update(mutations_detected=9),
            "all ten",
        ),
        (
            "owasp-cicd-top10-conformance",
            lambda item: item["claims"].update(nonapplicability_reviewed=False),
            "independently reviewed",
        ),
        (
            "sbomit-build-observed-sbom",
            lambda item: item["claims"].update(unexplained_dependencies=1),
            "reconciliation",
        ),
        (
            "sbomit-build-observed-sbom",
            lambda item: item["claims"].update(observations=["filesystem"]),
            "observations",
        ),
        (
            "openssf-package-analysis-malicious-packages",
            lambda item: item["claims"].update(sandbox_verified=False),
            "sandbox",
        ),
        (
            "oss-crs-crsbench",
            lambda item: item["claims"].update(functional_regressions=1),
            "zero regressions",
        ),
        (
            "primevul-real-world-vulnerability-detection",
            lambda item: item["claims"].update(label_audit_sample_size=29),
            "at least 30",
        ),
        (
            "diversevul-unseen-project-generalization",
            lambda item: item["claims"].update(project_disjoint_holdout=False),
            "split, provenance",
        ),
        (
            "cvefixes-chronological-fix-pair-validation",
            lambda item: item["claims"].update(unresolved_label_conflicts=1),
            "unresolved label conflicts",
        ),
        (
            "owasp-mobile-top10-conformance",
            lambda item: item["claims"].update(risk_ids=["M1"]),
            "exactly ten",
        ),
        (
            "owasp-smart-contract-top10-conformance",
            lambda item: item["claims"].update(mutations_detected=9),
            "all ten",
        ),
        (
            "cncf-cloud-native-security-controls-conformance",
            lambda item: item["claims"].update(lifecycle_phases=["runtime"]),
            "every cloud-native lifecycle phase",
        ),
        (
            "cncf-cloud-native-security-controls-conformance",
            lambda item: item["claims"].update(uncovered_applicable_controls=1),
            "must be complete",
        ),
        (
            "cncf-cloud-native-security-controls-conformance",
            lambda item: item["claims"].update(safe_mutations_detected=3),
            "mutation in every lifecycle phase",
        ),
        (
            "cncf-cloud-native-security-controls-conformance",
            lambda item: item["claims"].update(uncovered_applicable_controls=-1),
            "non-negative integer",
        ),
        (
            "primevul-real-world-vulnerability-detection",
            lambda item: item["claims"].update(corpus_oracle="chronological-fixes"),
            "oracle is incorrect",
        ),
        (
            "reposvul-repository-context-validation",
            lambda item: item["claims"].update(granularities=["function"]),
            "preserve repository, file, function and line",
        ),
        (
            "reposvul-repository-context-validation",
            lambda item: item["claims"].update(tangled_patches_untangled=False),
            "tangled-patch",
        ),
        (
            "vuleval-repository-dependency-evaluation",
            lambda item: item["claims"].update(evaluation_tasks=["function-detection"]),
            "all three repository evaluation tasks",
        ),
        (
            "vuleval-repository-dependency-evaluation",
            lambda item: item["claims"].update(dependency_oracle_passes=0),
            "positive integer",
        ),
        (
            "vuleval-repository-dependency-evaluation",
            lambda item: item["claims"].update(repository_context_verified=False),
            "repository context",
        ),
        (
            "mitre-emb3d-property-threat-conformance",
            lambda item: item["claims"].update(model_version="2.0.1"),
            "model 2.0.2",
        ),
        (
            "mitre-emb3d-property-threat-conformance",
            lambda item: item["claims"].update(safe_mutations_detected=2),
            "at least three",
        ),
        (
            "mitre-emb3d-property-threat-conformance",
            lambda item: item["claims"].update(stix_roundtrip_verified=False),
            "STIX roundtrip",
        ),
        (
            "owasp-business-logic-abuse-top10-conformance",
            lambda item: item["claims"].update(risk_ids=["BLA01"]),
            "exactly ten",
        ),
        (
            "cncf-supply-chain-best-practices-v2-conformance",
            lambda item: item["claims"].update(personas=["producer"]),
            "producer, consumer and operator",
        ),
        (
            "cncf-supply-chain-best-practices-v2-conformance",
            lambda item: item["claims"].update(lifecycle_phases=["build"]),
            "every lifecycle phase",
        ),
        (
            "cncf-supply-chain-best-practices-v2-conformance",
            lambda item: item["claims"].update(uncovered_applicable_practices=1),
            "must be complete",
        ),
        (
            "owasp-juice-shop",
            lambda item: item["claims"].update(target="wrong"),
            "target identity",
        ),
        (
            "owasp-webgoat",
            lambda item: item["claims"].update(clean_cases=0),
            "positive integer",
        ),
        (
            "owasp-webgoat",
            lambda item: item["claims"].update(clean_cases=4),
            "representative positive and clean cases",
        ),
        (
            "owasp-crapi",
            lambda item: item["claims"].update(external_egress_blocked=False),
            "isolation must be verified",
        ),
        (
            "owasp-api-security-testing-framework",
            lambda item: item["claims"].update(framework_version="2.0.0"),
            "version 2.0.1",
        ),
        (
            "owasp-api-security-testing-framework",
            lambda item: item["claims"].update(targets=["crapi"]),
            "all approved target",
        ),
        (
            "owasp-api-security-testing-framework",
            lambda item: item["claims"].update(protocols=["rest"]),
            "protocol capability",
        ),
        (
            "owasp-api-security-testing-framework",
            lambda item: item["claims"].update(claimed_coverage_inherited=True),
            "independent coverage",
        ),
        (
            "google-fuzzbench",
            lambda item: item["claims"].update(trials=19),
            "at least 20 matched trials",
        ),
        (
            "magma-ground-truth",
            lambda item: item["claims"].update(oracle="edge-coverage"),
            "oracle identity",
        ),
        (
            "oss-fuzz-clusterfuzzlite",
            lambda item: item["claims"].update(raw_trial_data_retained=False),
            "raw data and replay",
        ),
        (
            "sbom-sca-holdout",
            lambda item: item["claims"].update(ecosystems=["python"]),
            "at least three ecosystems",
        ),
        (
            "sbom-sca-holdout",
            lambda item: item["claims"].update(resolver_graphs_verified=False),
            "resolver, build, artifact",
        ),
        (
            "architecture-quality-holdout",
            lambda item: item["claims"].update(mutations=["cycle"]),
            "all governed fitness mutations",
        ),
        (
            "architecture-quality-holdout",
            lambda item: item["claims"].update(adjudication_complete=False),
            "adjudication must be verified",
        ),
        (
            "epss-kev-temporal-backtest",
            lambda item: item["claims"].update(
                snapshot_dates=["2025-04-01", "2025-01-01", "2025-07-01"]
            ),
            "unique ordered ISO date",
        ),
        (
            "epss-kev-temporal-backtest",
            lambda item: item["claims"].update(future_data_excluded=False),
            "as-of joins, calibration",
        ),
        (
            "scim-lifecycle-security-conformance",
            lambda item: item["claims"].update(rfc_set=["RFC7644"]),
            "all four RFCs",
        ),
        (
            "openid-shared-signals-conformance",
            lambda item: item["claims"].update(openid_certification_claimed=True),
            "no-certification boundary",
        ),
        (
            "authzen-authorization-api-conformance",
            lambda item: item["claims"].update(draft_profiles_included=True),
            "draft-exclusion",
        ),
        (
            "authzen-authorization-api-conformance",
            lambda item: item["claims"].update(roles=["pdp"]),
            "PDP and PEP",
        ),
        (
            "openid-federation-conformance",
            lambda item: item["claims"].update(official_early_suite_acknowledged=False),
            "early-suite",
        ),
        (
            "openid-federation-conformance",
            lambda item: item["claims"].update(entity_roles=["leaf"]),
            "anchor, intermediate and leaf",
        ),
        (
            "nist-hpc-ai-infrastructure-assurance",
            lambda item: item["claims"].update(tailored_controls_evaluated=59),
            "all 60 tailored controls",
        ),
        (
            "nist-hpc-ai-infrastructure-assurance",
            lambda item: item["claims"].update(sp800_239_draft_included=True),
            "draft-exclusion",
        ),
        (
            "iso-24760-identity-management-assurance",
            lambda item: item["claims"].update(principal_types=["person"]),
            "every principal type",
        ),
        (
            "iso-24760-identity-management-assurance",
            lambda item: item["claims"].update(iso_certification_claimed=True),
            "no-certification",
        ),
        (
            "iso-5259-6-data-quality-visualization",
            lambda item: item["claims"].update(
                iso_conformance_or_certification_claimed=True
            ),
            "no-certification",
        ),
        (
            "iso-5259-6-data-quality-visualization",
            lambda item: item["claims"].update(
                uncertainty_missingness_and_limitations_visible=False
            ),
            "visualization fidelity",
        ),
        (
            "spiffe-workload-identity-conformance",
            lambda item: item["claims"].update(experimental_remote_api_included=True),
            "experimental APIs excluded",
        ),
        (
            "openssf-model-signing-conformance",
            lambda item: item["claims"].update(model_safety_or_quality_claimed=True),
            "integrity-only claim boundary",
        ),
        (
            "cyclonedx-mlbom-conformance",
            lambda item: item["claims"].update(formats=["json"]),
            "JSON and XML",
        ),
        (
            "uptane-ota-security-conformance",
            lambda item: item["claims"].update(ecu_verification_modes=["full"]),
            "full and partial",
        ),
        (
            "darpa-aixcc-autonomous-vulnerability-remediation",
            lambda item: item["claims"].update(public_corpus_readiness_inferred=True),
            "upstream-readiness boundaries",
        ),
        (
            "openssf-criticality-score-calibration",
            lambda item: item["claims"].update(
                used_as_security_gate_or_vulnerability_likelihood=True
            ),
            "context-only",
        ),
        (
            "scim-lifecycle-security-conformance",
            lambda item: item["claims"].update(lifecycle_operations=["create"]),
            "complete lifecycle",
        ),
        (
            "scim-lifecycle-security-conformance",
            lambda item: item["claims"].update(roundtrip_verified=False),
            "clean controls must pass",
        ),
        (
            "scim-lifecycle-security-conformance",
            lambda item: item["claims"].update(rfc_set=["RFC7643", "RFC7643"]),
            "unique non-empty strings",
        ),
        (
            "openid-shared-signals-conformance",
            lambda item: item["claims"].update(profiles=["ssf"]),
            "SSF, CAEP and RISC",
        ),
        (
            "openid-shared-signals-conformance",
            lambda item: item["claims"].update(delivery_modes=["push"]),
            "push and poll",
        ),
        (
            "spiffe-workload-identity-conformance",
            lambda item: item["claims"].update(svid_types=["x509"]),
            "X.509 and JWT",
        ),
        (
            "openssf-model-signing-conformance",
            lambda item: item["claims"].update(oms_version="0.9"),
            "OMS 1.0",
        ),
        (
            "openssf-model-signing-conformance",
            lambda item: item["claims"].update(signing_modes=["sigstore"]),
            "required signing mode",
        ),
        (
            "cyclonedx-mlbom-conformance",
            lambda item: item["claims"].update(cyclonedx_version="1.6"),
            "CycloneDX 1.7",
        ),
        (
            "cyclonedx-mlbom-conformance",
            lambda item: item["claims"].update(model_card_verified=False),
            "no-safety-proof boundary",
        ),
        (
            "uptane-ota-security-conformance",
            lambda item: item["claims"].update(uptane_version="2.0.0"),
            "version 2.1.0",
        ),
        (
            "uptane-ota-security-conformance",
            lambda item: item["claims"].update(secure_time_and_expiry_verified=False),
            "no-certification boundaries",
        ),
        (
            "darpa-aixcc-autonomous-vulnerability-remediation",
            lambda item: item["claims"].update(challenge_classes=["synthetic"]),
            "real and synthetic",
        ),
        (
            "darpa-aixcc-autonomous-vulnerability-remediation",
            lambda item: item["execution"].update(repetitions=2),
            "at least three trials",
        ),
        (
            "openssf-criticality-score-calibration",
            lambda item: item["claims"].update(snapshots_evaluated=2),
            "at least three snapshots",
        ),
    ],
)
def test_domain_specific_false_assurance_fails_closed(
    integration: str, mutate: Any, message: str
) -> None:
    document = _evidence(integration)
    mutate(document)
    with pytest.raises(IndustryExtensionEvidenceError, match=message):
        validate_industry_extension_evidence(
            json.dumps(document),
            expected_source_sha256=SOURCE,
            expected_subject_sha256=SUBJECT,
        )


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda item: item.update(source_sha256="d" * 64), "source digest"),
        (lambda item: item.update(subject_sha256="d" * 64), "subject digest"),
        (lambda item: item["execution"].update(isolated=False), "isolated"),
        (
            lambda item: item["execution"].update(network_policy="open"),
            "network policy",
        ),
        (
            lambda item: item["provenance"].update(signature_verified=False),
            "signature",
        ),
        (
            lambda item: item["provenance"].update(producer=""),
            "producer is required",
        ),
        (
            lambda item: item["provenance"].update(producer_sha256="C" * 64),
            "lowercase SHA-256",
        ),
        (
            lambda item: item["execution"].update(budget_seconds=0),
            "positive integer",
        ),
        (lambda item: item.update(negative_cases=[]), "negative cases"),
        (
            lambda item: item["negative_cases"][0].update(detected=False),
            "not detected",
        ),
        (
            lambda item: item["negative_cases"][1].update(id="tamper"),
            "unique",
        ),
        (lambda item: item.update(claims=[]), "claims must be an object"),
        (lambda item: item.update(extra=True), "fields must be exactly"),
        (lambda item: item.update(complete=False), "must be complete"),
        (lambda item: item.update(integration="unknown"), "unsupported"),
    ],
)
def test_common_trust_boundary_failures_are_rejected(mutate: Any, message: str) -> None:
    document = _evidence("gittuf-source-policy-conformance")
    mutate(document)
    with pytest.raises(IndustryExtensionEvidenceError, match=message):
        validate_industry_extension_evidence(
            json.dumps(document),
            expected_source_sha256=SOURCE,
            expected_subject_sha256=SUBJECT,
        )


def test_ambiguous_and_oversized_json_is_rejected() -> None:
    with pytest.raises(IndustryExtensionEvidenceError, match="duplicate"):
        validate_industry_extension_evidence(
            '{"schema_version":"1.0","schema_version":"1.0"}',
            expected_source_sha256=SOURCE,
            expected_subject_sha256=SUBJECT,
        )
    with pytest.raises(IndustryExtensionEvidenceError, match="4 MiB"):
        validate_industry_extension_evidence(
            " " * (4 * 1024 * 1024 + 1),
            expected_source_sha256=SOURCE,
            expected_subject_sha256=SUBJECT,
        )


def test_scorecard_reproducibility_gate_requires_bound_extension_evidence() -> None:
    benchmark = {
        "id": "guac-interoperability",
        "version": "guac-1.0-policy-pinned",
        "lane": "authorized-companion",
    }
    evidence = {
        "corpus": {"sha256": SOURCE, "revision": "pinned"},
        "execution_context": {"target_sha256": SUBJECT},
        "extension_evidence": _evidence("guac-interoperability"),
    }
    marker = "suite-owned industry extension evidence is missing or invalid"
    assert marker not in _benchmark_reproducibility_gaps(evidence, benchmark)
    del evidence["extension_evidence"]
    assert marker in _benchmark_reproducibility_gaps(evidence, benchmark)


def test_extension_runner_and_scorecard_helpers_fail_closed_by_scope() -> None:
    assert industry_extension_runner_requirements("unknown") == ()
    common = industry_extension_runner_requirements("owasp-mobile-top10-conformance")
    assert "suite-owned-extension-evidence" in common
    assert "independent-label-audit-report" not in common

    real_world = industry_extension_runner_requirements(
        "primevul-real-world-vulnerability-detection"
    )
    assert "independent-label-audit-report" in real_world
    assert "training-overlap-assessment" in real_world

    repository = industry_extension_runner_requirements(
        "reposvul-repository-context-validation"
    )
    assert "dependency-context-oracle" in repository
    assert "tangled-patch-audit" in repository
    assert "multi-granularity-label-map" in repository

    vulnerable_target = industry_extension_runner_requirements("owasp-crapi")
    assert "target-label-authority-map" in vulnerable_target
    assert "external-egress-transcript" in vulnerable_target

    fuzzing = industry_extension_runner_requirements("google-fuzzbench")
    assert "repeated-trial-raw-data" in fuzzing
    assert "equal-resource-manifest" in fuzzing

    sbom = industry_extension_runner_requirements("sbom-sca-holdout")
    assert "resolver-and-build-truth-map" in sbom

    architecture = industry_extension_runner_requirements(
        "architecture-quality-holdout"
    )
    assert "architecture-mutation-corpus" in architecture

    temporal = industry_extension_runner_requirements("epss-kev-temporal-backtest")
    assert "future-data-exclusion-report" in temporal

    identity = industry_extension_runner_requirements(
        "openid-shared-signals-conformance"
    )
    assert "authorization-and-subject-boundary-oracles" in identity
    assert "no-certification-claim-policy" in identity

    federation = industry_extension_runner_requirements("openid-federation-conformance")
    assert "synthetic-identity-and-trust-domain-manifest" in federation
    assert "rotation-revocation-replay-report" in federation

    hpc = industry_extension_runner_requirements("nist-hpc-ai-infrastructure-assurance")
    assert "sixty-control-applicability-and-odp-report" in hpc
    assert "sp800-239-draft-exclusion-and-no-certification-policy" in hpc

    visualization = industry_extension_runner_requirements(
        "iso-5259-6-data-quality-visualization"
    )
    assert "misleading-presentation-mutation-report" in visualization
    assert "technical-report-guidance-only-claim-policy" in visualization

    model = industry_extension_runner_requirements("openssf-model-signing-conformance")
    assert "official-schema-and-vector-lock" in model
    assert "integrity-inventory-not-safety-claim-policy" in model

    uptane = industry_extension_runner_requirements("uptane-ota-security-conformance")
    assert "repository-role-key-threshold-and-pouf-map" in uptane

    aixcc = industry_extension_runner_requirements(
        "darpa-aixcc-autonomous-vulnerability-remediation"
    )
    assert "license-training-overlap-and-contamination-report" in aixcc

    criticality = industry_extension_runner_requirements(
        "openssf-criticality-score-calibration"
    )
    assert "context-only-calibration-policy" in criticality

    assert industry_extension_score_evidence_valid({}, "unknown") is True
    assert (
        industry_extension_score_evidence_valid(
            [], "primevul-real-world-vulnerability-detection"
        )
        is False
    )
