from __future__ import annotations

from collections.abc import Callable
from typing import Any, cast

from .industry_emerging_assurance_catalog import EMERGING_ASSURANCE_EVIDENCE_CONTRACTS
from .industry_interoperability_sector_catalog import (
    INTEROPERABILITY_SECTOR_EVIDENCE_CONTRACTS,
)
from .industry_maturity_product_catalog import MATURITY_PRODUCT_EVIDENCE_CONTRACTS
from .industry_resilience_catalog import (
    RESILIENCE_BENCHMARK_IDS,
    RESILIENCE_EVIDENCE_CONTRACTS,
)
from .strict_json import loads


_MAX_PAYLOAD_BYTES = 4 * 1024 * 1024
_SHA256_LENGTH = 64
_TOP_LEVEL_FIELDS = {
    "schema_version",
    "integration",
    "source_sha256",
    "subject_sha256",
    "execution",
    "claims",
    "negative_cases",
    "provenance",
    "complete",
}
_KUBERNETES_RISKS = {f"K{index:02d}" for index in range(1, 11)}
_CICD_RISKS = {f"CICD-SEC-{index}" for index in range(1, 11)}
_MOBILE_RISKS = {f"M{index}" for index in range(1, 11)}
_SMART_CONTRACT_RISKS = {f"SC{index:02d}" for index in range(1, 11)}
_BUSINESS_LOGIC_RISKS = {f"BLA{index:02d}" for index in range(1, 11)}
_CLOUD_NATIVE_PHASES = {"develop", "distribute", "deploy", "runtime"}
_SUPPLY_CHAIN_PERSONAS = {"producer", "consumer", "operator"}
_SUPPLY_CHAIN_PHASES = {"source", "build", "distribution", "deployment", "operation"}


class IndustryExtensionEvidenceError(ValueError):
    """Raised when imported industry-extension evidence is not trustworthy."""


def validate_industry_extension_evidence(
    payload: str | bytes,
    *,
    expected_source_sha256: str,
    expected_subject_sha256: str,
) -> dict[str, Any]:
    """Validate a bounded, subject-bound normalized integration result.

    This accepts only the suite-owned normalized envelope. Upstream output must be
    transformed by a digest-pinned adapter before it reaches this trust boundary.
    """

    size = len(payload.encode("utf-8")) if isinstance(payload, str) else len(payload)
    if size > _MAX_PAYLOAD_BYTES:
        raise IndustryExtensionEvidenceError("evidence exceeds the 4 MiB limit")
    try:
        document = loads(
            payload,
            maximum_depth=12,
            maximum_nodes=20_000,
            maximum_string_length=16_384,
        )
    except (TypeError, ValueError) as error:
        raise IndustryExtensionEvidenceError(f"invalid strict JSON: {error}") from error
    return validate_industry_extension_evidence_document(
        document,
        expected_source_sha256=expected_source_sha256,
        expected_subject_sha256=expected_subject_sha256,
    )


def validate_industry_extension_evidence_document(
    document: object,
    *,
    expected_source_sha256: str,
    expected_subject_sha256: str,
) -> dict[str, Any]:
    """Validate an already strict-decoded normalized integration result."""

    evidence = _object(document, "evidence")
    _exact_fields(evidence, _TOP_LEVEL_FIELDS, "evidence")
    if evidence["schema_version"] != "1.0" or evidence["complete"] is not True:
        raise IndustryExtensionEvidenceError(
            "evidence must be complete schema version 1.0"
        )
    source_sha256 = _digest(evidence["source_sha256"], "source_sha256")
    subject_sha256 = _digest(evidence["subject_sha256"], "subject_sha256")
    if source_sha256 != _digest(expected_source_sha256, "expected_source_sha256"):
        raise IndustryExtensionEvidenceError("source digest does not match expectation")
    if subject_sha256 != _digest(expected_subject_sha256, "expected_subject_sha256"):
        raise IndustryExtensionEvidenceError(
            "subject digest does not match expectation"
        )

    execution = _object(evidence["execution"], "execution")
    _exact_fields(
        execution,
        {"isolated", "network_policy", "repetitions", "budget_seconds"},
        "execution",
    )
    if execution["isolated"] is not True:
        raise IndustryExtensionEvidenceError("execution must be isolated")
    if execution["network_policy"] not in {"deny", "sinkhole", "target-only"}:
        raise IndustryExtensionEvidenceError("network policy is not fail-closed")
    _positive_integer(execution["repetitions"], "execution.repetitions")
    _positive_integer(execution["budget_seconds"], "execution.budget_seconds")

    provenance = _object(evidence["provenance"], "provenance")
    _exact_fields(
        provenance,
        {
            "producer",
            "producer_sha256",
            "signature_verified",
            "independent_replay_verified",
        },
        "provenance",
    )
    if not isinstance(provenance["producer"], str) or not provenance["producer"]:
        raise IndustryExtensionEvidenceError("provenance producer is required")
    _digest(provenance["producer_sha256"], "provenance.producer_sha256")
    if (
        provenance["signature_verified"] is not True
        or provenance["independent_replay_verified"] is not True
    ):
        raise IndustryExtensionEvidenceError(
            "signature and independent replay must both be verified"
        )

    negative_cases = evidence["negative_cases"]
    if not isinstance(negative_cases, list) or len(negative_cases) < 2:
        raise IndustryExtensionEvidenceError("at least two negative cases are required")
    identifiers: set[str] = set()
    for index, value in enumerate(negative_cases):
        case = _object(value, f"negative_cases[{index}]")
        _exact_fields(case, {"id", "detected"}, f"negative_cases[{index}]")
        identifier = case["id"]
        if (
            not isinstance(identifier, str)
            or not identifier
            or identifier in identifiers
        ):
            raise IndustryExtensionEvidenceError(
                "negative-case identifiers must be non-empty and unique"
            )
        identifiers.add(identifier)
        if case["detected"] is not True:
            raise IndustryExtensionEvidenceError(
                f"negative case {identifier!r} was not detected"
            )

    integration = evidence["integration"]
    if not isinstance(integration, str) or integration not in _CLAIM_VALIDATORS:
        raise IndustryExtensionEvidenceError("unsupported integration identifier")
    claims = _object(evidence["claims"], "claims")
    _CLAIM_VALIDATORS[integration](claims, execution)
    return evidence


def _validate_crsbench(claims: dict[str, Any], execution: dict[str, Any]) -> None:
    _exact_fields(
        claims,
        {
            "challenges_evaluated",
            "valid_povs",
            "functional_regressions",
            "hidden_set_separated",
            "confidence_bounds_reported",
        },
        "claims",
    )
    _positive_integer(claims["challenges_evaluated"], "claims.challenges_evaluated")
    _nonnegative_integer(claims["valid_povs"], "claims.valid_povs")
    if execution["repetitions"] < 3:
        raise IndustryExtensionEvidenceError("CRSBench requires at least three trials")
    if (
        claims["functional_regressions"] != 0
        or claims["hidden_set_separated"] is not True
        or claims["confidence_bounds_reported"] is not True
    ):
        raise IndustryExtensionEvidenceError(
            "CRSBench requires zero regressions, holdout separation and confidence bounds"
        )


def _validate_security_insights(
    claims: dict[str, Any], execution: dict[str, Any]
) -> None:
    del execution
    _required_true_claims(
        claims,
        {
            "repository_bound",
            "expiry_checked",
            "future_schema_quarantined",
            "source_provenance_preserved",
        },
        extra={"schema_version"},
    )
    if claims["schema_version"] != "1.0.0":
        raise IndustryExtensionEvidenceError(
            "Security Insights evidence must use released schema 1.0.0"
        )


def _validate_guac(claims: dict[str, Any], execution: dict[str, Any]) -> None:
    del execution
    _exact_fields(
        claims,
        {
            "formats",
            "identity_conflicts",
            "query_oracle_passes",
            "roundtrip_verified",
            "source_provenance_preserved",
        },
        "claims",
    )
    formats = claims["formats"]
    required = {"cyclonedx", "spdx", "slsa", "vex", "scorecard"}
    if (
        not isinstance(formats, list)
        or any(not isinstance(item, str) for item in formats)
        or not required <= set(formats)
    ):
        raise IndustryExtensionEvidenceError("GUAC required formats are incomplete")
    if claims["identity_conflicts"] != 0:
        raise IndustryExtensionEvidenceError("GUAC has unexplained identity conflicts")
    _positive_integer(claims["query_oracle_passes"], "claims.query_oracle_passes")
    if (
        claims["roundtrip_verified"] is not True
        or claims["source_provenance_preserved"] is not True
    ):
        raise IndustryExtensionEvidenceError(
            "GUAC roundtrip and source provenance must be verified"
        )


def _validate_gittuf(claims: dict[str, Any], execution: dict[str, Any]) -> None:
    del execution
    _required_true_claims(
        claims,
        {
            "root_verified",
            "policy_verified",
            "threshold_verified",
            "reference_state_verified",
            "transparency_log_verified",
            "rollback_protection_verified",
        },
    )


def _validate_package_analysis(
    claims: dict[str, Any], execution: dict[str, Any]
) -> None:
    del execution
    _exact_fields(
        claims,
        {
            "behavior_signals",
            "sandbox_verified",
            "protected_labels",
            "clean_false_positives",
            "feed_snapshot_bound",
        },
        "claims",
    )
    signals = claims["behavior_signals"]
    if not isinstance(signals, list) or not {
        "filesystem",
        "process",
        "network",
        "command",
    } <= set(signals):
        raise IndustryExtensionEvidenceError(
            "package analysis behavior signals are incomplete"
        )
    _nonnegative_integer(
        claims["clean_false_positives"], "claims.clean_false_positives"
    )
    if (
        claims["sandbox_verified"] is not True
        or claims["protected_labels"] is not True
        or claims["feed_snapshot_bound"] is not True
    ):
        raise IndustryExtensionEvidenceError(
            "package analysis sandbox, labels and feed must be verified"
        )


def _validate_kubernetes(claims: dict[str, Any], execution: dict[str, Any]) -> None:
    del execution
    _validate_risk_taxonomy(claims, _KUBERNETES_RISKS, "Kubernetes")


def _validate_cicd(claims: dict[str, Any], execution: dict[str, Any]) -> None:
    del execution
    _validate_risk_taxonomy(claims, _CICD_RISKS, "CI/CD")


def _validate_risk_taxonomy(
    claims: dict[str, Any], expected: set[str], label: str
) -> None:
    _exact_fields(
        claims,
        {"risk_ids", "mutations_detected", "nonapplicability_reviewed"},
        "claims",
    )
    risk_ids = claims["risk_ids"]
    if not isinstance(risk_ids, list) or set(risk_ids) != expected:
        raise IndustryExtensionEvidenceError(f"{label} must cover exactly ten risks")
    if claims["mutations_detected"] != 10:
        raise IndustryExtensionEvidenceError(f"{label} must detect all ten mutations")
    if claims["nonapplicability_reviewed"] is not True:
        raise IndustryExtensionEvidenceError(
            f"{label} non-applicability must be independently reviewed"
        )


def _validate_sbomit(claims: dict[str, Any], execution: dict[str, Any]) -> None:
    del execution
    _exact_fields(
        claims,
        {
            "observations",
            "attestation_verified",
            "subject_bound",
            "declared_observed_reconciled",
            "unexplained_dependencies",
        },
        "claims",
    )
    observations = claims["observations"]
    if not isinstance(observations, list) or not {
        "filesystem",
        "process",
        "network",
    } <= set(observations):
        raise IndustryExtensionEvidenceError("SBOMit observations are incomplete")
    if (
        claims["attestation_verified"] is not True
        or claims["subject_bound"] is not True
        or claims["declared_observed_reconciled"] is not True
        or claims["unexplained_dependencies"] != 0
    ):
        raise IndustryExtensionEvidenceError(
            "SBOMit attestation, binding and reconciliation must be complete"
        )


def _validate_primevul(claims: dict[str, Any], execution: dict[str, Any]) -> None:
    _validate_real_world_vulnerability_corpus(claims, execution, "paired-functions")


def _validate_diversevul(claims: dict[str, Any], execution: dict[str, Any]) -> None:
    _validate_real_world_vulnerability_corpus(claims, execution, "unseen-projects")


def _validate_cvefixes(claims: dict[str, Any], execution: dict[str, Any]) -> None:
    _validate_real_world_vulnerability_corpus(claims, execution, "chronological-fixes")


def _validate_reposvul(claims: dict[str, Any], execution: dict[str, Any]) -> None:
    extra = {
        "granularities",
        "dependency_graph_verified",
        "tangled_patches_untangled",
        "stale_patches_filtered",
    }
    _validate_real_world_vulnerability_corpus(
        claims, execution, "repository-context", extra_fields=extra
    )
    granularities = claims["granularities"]
    if (
        not isinstance(granularities, list)
        or any(not isinstance(item, str) for item in granularities)
        or set(granularities) != {"repository", "file", "function", "line"}
    ):
        raise IndustryExtensionEvidenceError(
            "ReposVul must preserve repository, file, function and line labels"
        )
    if any(
        claims[name] is not True
        for name in {
            "dependency_graph_verified",
            "tangled_patches_untangled",
            "stale_patches_filtered",
        }
    ):
        raise IndustryExtensionEvidenceError(
            "ReposVul dependency, tangled-patch and stale-patch controls must be verified"
        )


def _validate_vuleval(claims: dict[str, Any], execution: dict[str, Any]) -> None:
    extra = {
        "evaluation_tasks",
        "repository_context_verified",
        "dependency_oracle_passes",
        "interprocedural_cases",
    }
    _validate_real_world_vulnerability_corpus(
        claims, execution, "repository-dependency-tasks", extra_fields=extra
    )
    tasks = claims["evaluation_tasks"]
    if (
        not isinstance(tasks, list)
        or any(not isinstance(item, str) for item in tasks)
        or set(tasks)
        != {"function-detection", "dependency-prediction", "repository-detection"}
    ):
        raise IndustryExtensionEvidenceError(
            "VulEval must preserve all three repository evaluation tasks"
        )
    _positive_integer(
        claims["dependency_oracle_passes"], "claims.dependency_oracle_passes"
    )
    _positive_integer(claims["interprocedural_cases"], "claims.interprocedural_cases")
    if claims["repository_context_verified"] is not True:
        raise IndustryExtensionEvidenceError(
            "VulEval repository context must be independently verified"
        )


def _validate_real_world_vulnerability_corpus(
    claims: dict[str, Any],
    execution: dict[str, Any],
    expected_oracle: str,
    *,
    extra_fields: set[str] | None = None,
) -> None:
    del execution
    fields = {
        "corpus_oracle",
        "dataset_version_bound",
        "license_verified",
        "source_revisions_verified",
        "label_audit_sample_size",
        "unresolved_label_conflicts",
        "exact_duplicates_removed",
        "near_duplicates_measured",
        "training_overlap_checked",
        "project_disjoint_holdout",
        "chronological_holdout",
        "fixes_independently_replayed",
        "cwe_stratified_metrics",
        "confidence_bounds_reported",
    }
    _exact_fields(
        claims,
        fields | (extra_fields or set()),
        "claims",
    )
    if claims["corpus_oracle"] != expected_oracle:
        raise IndustryExtensionEvidenceError("vulnerability corpus oracle is incorrect")
    _positive_integer(
        claims["label_audit_sample_size"], "claims.label_audit_sample_size"
    )
    _nonnegative_integer(
        claims["unresolved_label_conflicts"], "claims.unresolved_label_conflicts"
    )
    _positive_integer(
        claims["fixes_independently_replayed"],
        "claims.fixes_independently_replayed",
    )
    if claims["label_audit_sample_size"] < 30:
        raise IndustryExtensionEvidenceError(
            "vulnerability corpus requires at least 30 independently audited labels"
        )
    if claims["unresolved_label_conflicts"] != 0:
        raise IndustryExtensionEvidenceError(
            "vulnerability corpus has unresolved label conflicts"
        )
    required_true = {
        "dataset_version_bound",
        "license_verified",
        "source_revisions_verified",
        "exact_duplicates_removed",
        "near_duplicates_measured",
        "training_overlap_checked",
        "project_disjoint_holdout",
        "chronological_holdout",
        "cwe_stratified_metrics",
        "confidence_bounds_reported",
    }
    if any(claims[name] is not True for name in required_true):
        raise IndustryExtensionEvidenceError(
            "vulnerability corpus split, provenance and statistical controls must be verified"
        )


def _validate_mobile(claims: dict[str, Any], execution: dict[str, Any]) -> None:
    del execution
    _validate_risk_taxonomy(claims, _MOBILE_RISKS, "Mobile")


def _validate_smart_contract(claims: dict[str, Any], execution: dict[str, Any]) -> None:
    del execution
    _validate_risk_taxonomy(claims, _SMART_CONTRACT_RISKS, "Smart contract")


def _validate_cncf_cloud_native(
    claims: dict[str, Any], execution: dict[str, Any]
) -> None:
    del execution
    _exact_fields(
        claims,
        {
            "lifecycle_phases",
            "nist_mappings_verified",
            "architecture_evidence_verified",
            "safe_mutations_detected",
            "uncovered_applicable_controls",
            "applicability_reviewed",
        },
        "claims",
    )
    phases = claims["lifecycle_phases"]
    if (
        not isinstance(phases, list)
        or any(not isinstance(item, str) for item in phases)
        or set(phases) != _CLOUD_NATIVE_PHASES
    ):
        raise IndustryExtensionEvidenceError(
            "CNCF evidence must cover every cloud-native lifecycle phase"
        )
    _positive_integer(
        claims["safe_mutations_detected"], "claims.safe_mutations_detected"
    )
    _nonnegative_integer(
        claims["uncovered_applicable_controls"],
        "claims.uncovered_applicable_controls",
    )
    if claims["safe_mutations_detected"] < len(_CLOUD_NATIVE_PHASES):
        raise IndustryExtensionEvidenceError(
            "CNCF evidence requires a detected safe mutation in every lifecycle phase"
        )
    if (
        claims["nist_mappings_verified"] is not True
        or claims["architecture_evidence_verified"] is not True
        or claims["applicability_reviewed"] is not True
        or claims["uncovered_applicable_controls"] != 0
    ):
        raise IndustryExtensionEvidenceError(
            "CNCF mapping, architecture and applicability evidence must be complete"
        )


def _validate_emb3d(claims: dict[str, Any], execution: dict[str, Any]) -> None:
    del execution
    _exact_fields(
        claims,
        {
            "model_version",
            "device_properties_evaluated",
            "threats_evaluated",
            "properties_to_threats_verified",
            "threats_to_mitigations_verified",
            "stix_roundtrip_verified",
            "residual_risk_reviewed",
            "safe_mutations_detected",
        },
        "claims",
    )
    if claims["model_version"] != "2.0.2":
        raise IndustryExtensionEvidenceError("EMB3D evidence must use model 2.0.2")
    _positive_integer(
        claims["device_properties_evaluated"],
        "claims.device_properties_evaluated",
    )
    _positive_integer(claims["threats_evaluated"], "claims.threats_evaluated")
    _positive_integer(
        claims["safe_mutations_detected"], "claims.safe_mutations_detected"
    )
    if claims["safe_mutations_detected"] < 3:
        raise IndustryExtensionEvidenceError(
            "EMB3D evidence requires at least three detected mapping mutations"
        )
    required = {
        "properties_to_threats_verified",
        "threats_to_mitigations_verified",
        "stix_roundtrip_verified",
        "residual_risk_reviewed",
    }
    if any(claims[name] is not True for name in required):
        raise IndustryExtensionEvidenceError(
            "EMB3D mappings, STIX roundtrip and residual risk must be verified"
        )


def _validate_business_logic(claims: dict[str, Any], execution: dict[str, Any]) -> None:
    del execution
    _validate_risk_taxonomy(claims, _BUSINESS_LOGIC_RISKS, "Business logic abuse")


def _validate_cncf_supply_chain(
    claims: dict[str, Any], execution: dict[str, Any]
) -> None:
    del execution
    _exact_fields(
        claims,
        {
            "personas",
            "lifecycle_phases",
            "ssdf_mapping_verified",
            "slsa_mapping_verified",
            "s2c2f_mapping_verified",
            "safe_mutations_detected",
            "uncovered_applicable_practices",
            "applicability_reviewed",
        },
        "claims",
    )
    personas = claims["personas"]
    phases = claims["lifecycle_phases"]
    if (
        not isinstance(personas, list)
        or any(not isinstance(item, str) for item in personas)
        or set(personas) != _SUPPLY_CHAIN_PERSONAS
    ):
        raise IndustryExtensionEvidenceError(
            "CNCF supply-chain evidence must cover producer, consumer and operator"
        )
    if (
        not isinstance(phases, list)
        or any(not isinstance(item, str) for item in phases)
        or set(phases) != _SUPPLY_CHAIN_PHASES
    ):
        raise IndustryExtensionEvidenceError(
            "CNCF supply-chain evidence must cover every lifecycle phase"
        )
    _positive_integer(
        claims["safe_mutations_detected"], "claims.safe_mutations_detected"
    )
    _nonnegative_integer(
        claims["uncovered_applicable_practices"],
        "claims.uncovered_applicable_practices",
    )
    required = {
        "ssdf_mapping_verified",
        "slsa_mapping_verified",
        "s2c2f_mapping_verified",
        "applicability_reviewed",
    }
    if (
        claims["safe_mutations_detected"] < len(_SUPPLY_CHAIN_PHASES)
        or claims["uncovered_applicable_practices"] != 0
        or any(claims[name] is not True for name in required)
    ):
        raise IndustryExtensionEvidenceError(
            "CNCF supply-chain mappings, mutations and applicability must be complete"
        )


def _validate_vulnerable_application(
    claims: dict[str, Any], execution: dict[str, Any], expected_target: str
) -> None:
    del execution
    _exact_fields(
        claims,
        {
            "target",
            "target_release_bound",
            "target_image_verified",
            "label_authority_verified",
            "positive_cases",
            "clean_cases",
            "route_coverage_verified",
            "state_reset_verified",
            "external_egress_blocked",
            "multistep_oracles_replayed",
            "role_and_session_oracles_replayed",
        },
        "claims",
    )
    if claims["target"] != expected_target:
        raise IndustryExtensionEvidenceError("vulnerable target identity is incorrect")
    _positive_integer(claims["positive_cases"], "claims.positive_cases")
    _positive_integer(claims["clean_cases"], "claims.clean_cases")
    if claims["positive_cases"] < 10 or claims["clean_cases"] < 5:
        raise IndustryExtensionEvidenceError(
            "vulnerable target evidence requires representative positive and clean cases"
        )
    required = {
        "target_release_bound",
        "target_image_verified",
        "label_authority_verified",
        "route_coverage_verified",
        "state_reset_verified",
        "external_egress_blocked",
        "multistep_oracles_replayed",
        "role_and_session_oracles_replayed",
    }
    if any(claims[name] is not True for name in required):
        raise IndustryExtensionEvidenceError(
            "vulnerable target identity, labels, routes, state and isolation must be verified"
        )


def _validate_juice_shop(claims: dict[str, Any], execution: dict[str, Any]) -> None:
    _validate_vulnerable_application(claims, execution, "juice-shop-20.0.0")


def _validate_webgoat(claims: dict[str, Any], execution: dict[str, Any]) -> None:
    _validate_vulnerable_application(claims, execution, "webgoat-webwolf")


def _validate_crapi(claims: dict[str, Any], execution: dict[str, Any]) -> None:
    _validate_vulnerable_application(claims, execution, "crapi")


def _validate_astf(claims: dict[str, Any], execution: dict[str, Any]) -> None:
    del execution
    _exact_fields(
        claims,
        {
            "framework_version",
            "targets",
            "protocols",
            "rule_manifest_bound",
            "cross_target_labels_verified",
            "two_identity_oracles_replayed",
            "positive_cases",
            "clean_cases",
            "state_reset_verified",
            "claimed_coverage_inherited",
        },
        "claims",
    )
    if claims["framework_version"] != "2.0.1":
        raise IndustryExtensionEvidenceError("ASTF evidence must use version 2.0.1")
    targets = claims["targets"]
    protocols = claims["protocols"]
    if (
        not isinstance(targets, list)
        or any(not isinstance(item, str) for item in targets)
        or set(targets) != {"crapi", "vampi", "dvga", "clean-api"}
    ):
        raise IndustryExtensionEvidenceError(
            "ASTF evidence must retain all approved target identities"
        )
    if (
        not isinstance(protocols, list)
        or any(not isinstance(item, str) for item in protocols)
        or not {"rest", "graphql", "grpc", "mtls", "llm"} <= set(protocols)
    ):
        raise IndustryExtensionEvidenceError(
            "ASTF protocol capability evidence is incomplete"
        )
    _positive_integer(claims["positive_cases"], "claims.positive_cases")
    _positive_integer(claims["clean_cases"], "claims.clean_cases")
    if (
        claims["rule_manifest_bound"] is not True
        or claims["cross_target_labels_verified"] is not True
        or claims["two_identity_oracles_replayed"] is not True
        or claims["state_reset_verified"] is not True
        or claims["claimed_coverage_inherited"] is not False
    ):
        raise IndustryExtensionEvidenceError(
            "ASTF rules, labels, authorization oracles and independent coverage must be verified"
        )


def _validate_fuzzing_extension(
    claims: dict[str, Any],
    execution: dict[str, Any],
    expected_oracle: str,
    minimum_trials: int,
) -> None:
    _exact_fields(
        claims,
        {
            "oracle",
            "trials",
            "equal_resource_budgets",
            "toolchains_bound",
            "seeds_bound",
            "raw_trial_data_retained",
            "independent_replay_verified",
            "baseline_control_passed",
            "broken_control_detected",
            "environment_drift_measured",
            "domain_oracles_replayed",
        },
        "claims",
    )
    if claims["oracle"] != expected_oracle:
        raise IndustryExtensionEvidenceError("fuzzing oracle identity is incorrect")
    _positive_integer(claims["trials"], "claims.trials")
    if (
        claims["trials"] < minimum_trials
        or execution["repetitions"] < minimum_trials
        or claims["trials"] != execution["repetitions"]
    ):
        raise IndustryExtensionEvidenceError(
            f"fuzzing evidence requires at least {minimum_trials} matched trials"
        )
    required = set(claims) - {"oracle", "trials"}
    if any(claims[name] is not True for name in required):
        raise IndustryExtensionEvidenceError(
            "fuzzing budgets, inputs, controls, raw data and replay must be verified"
        )


def _validate_fuzzbench(claims: dict[str, Any], execution: dict[str, Any]) -> None:
    _validate_fuzzing_extension(claims, execution, "edge-coverage", 20)


def _validate_magma(claims: dict[str, Any], execution: dict[str, Any]) -> None:
    _validate_fuzzing_extension(claims, execution, "ground-truth-bugs", 10)


def _validate_oss_fuzz(claims: dict[str, Any], execution: dict[str, Any]) -> None:
    _validate_fuzzing_extension(claims, execution, "continuous-integration", 3)


def _validate_sbom_build_truth(
    claims: dict[str, Any], execution: dict[str, Any]
) -> None:
    del execution
    _exact_fields(
        claims,
        {
            "ecosystems",
            "component_labels",
            "relationship_labels",
            "advisory_labels",
            "source_locks_bound",
            "resolver_graphs_verified",
            "build_observations_verified",
            "installed_artifacts_verified",
            "container_layers_verified",
            "known_unknowns_replayed",
            "project_time_holdouts_verified",
            "training_overlap_checked",
        },
        "claims",
    )
    ecosystems = claims["ecosystems"]
    if (
        not isinstance(ecosystems, list)
        or any(not isinstance(item, str) for item in ecosystems)
        or len(set(ecosystems)) < 3
    ):
        raise IndustryExtensionEvidenceError(
            "SBOM build-truth evidence requires at least three ecosystems"
        )
    for name in {"component_labels", "relationship_labels", "advisory_labels"}:
        _positive_integer(claims[name], f"claims.{name}")
    required = set(claims) - {
        "ecosystems",
        "component_labels",
        "relationship_labels",
        "advisory_labels",
    }
    if any(claims[name] is not True for name in required):
        raise IndustryExtensionEvidenceError(
            "SBOM resolver, build, artifact, layer, holdout and overlap evidence must be verified"
        )


def _validate_architecture_fitness(
    claims: dict[str, Any], execution: dict[str, Any]
) -> None:
    del execution
    _exact_fields(
        claims,
        {
            "systems_evaluated",
            "rules_evaluated",
            "mutations",
            "labels_independently_reviewed",
            "project_time_holdouts_verified",
            "training_overlap_checked",
            "clean_baselines_replayed",
            "change_history_bound",
            "ownership_bound",
            "adjudication_complete",
        },
        "claims",
    )
    _positive_integer(claims["systems_evaluated"], "claims.systems_evaluated")
    _positive_integer(claims["rules_evaluated"], "claims.rules_evaluated")
    mutations = claims["mutations"]
    expected = {
        "cycle",
        "layering",
        "unstable-dependency",
        "change-coupling",
        "ownership-concentration",
        "architecture-drift",
    }
    if (
        not isinstance(mutations, list)
        or any(not isinstance(item, str) for item in mutations)
        or set(mutations) != expected
    ):
        raise IndustryExtensionEvidenceError(
            "architecture evidence must cover all governed fitness mutations"
        )
    required = set(claims) - {"systems_evaluated", "rules_evaluated", "mutations"}
    if any(claims[name] is not True for name in required):
        raise IndustryExtensionEvidenceError(
            "architecture labels, holdouts, history, ownership and adjudication must be verified"
        )


def _validate_temporal_backtest(
    claims: dict[str, Any], execution: dict[str, Any]
) -> None:
    del execution
    _exact_fields(
        claims,
        {
            "snapshot_dates",
            "outcome_window_days",
            "cves_evaluated",
            "strict_asof_verified",
            "future_data_excluded",
            "aliases_reconciled",
            "censoring_documented",
            "historical_snapshots_verified",
            "brier_score_reported",
            "calibration_reported",
            "budget_curves_reported",
            "time_shift_negative_detected",
        },
        "claims",
    )
    dates = claims["snapshot_dates"]
    if (
        not isinstance(dates, list)
        or len(dates) < 3
        or any(
            not isinstance(item, str)
            or len(item) != 10
            or item[4] != "-"
            or item[7] != "-"
            for item in dates
        )
        or dates != sorted(set(dates))
    ):
        raise IndustryExtensionEvidenceError(
            "temporal backtest requires unique ordered ISO date snapshots"
        )
    _positive_integer(claims["outcome_window_days"], "claims.outcome_window_days")
    _positive_integer(claims["cves_evaluated"], "claims.cves_evaluated")
    required = set(claims) - {"snapshot_dates", "outcome_window_days", "cves_evaluated"}
    if any(claims[name] is not True for name in required):
        raise IndustryExtensionEvidenceError(
            "temporal snapshots, as-of joins, calibration and negative controls must be verified"
        )


def _validate_scim_lifecycle(claims: dict[str, Any], execution: dict[str, Any]) -> None:
    del execution
    _exact_fields(
        claims,
        {
            "rfc_set",
            "lifecycle_operations",
            "resources_evaluated",
            "schema_and_mutability_verified",
            "tenant_and_role_authorization_verified",
            "filter_bulk_etag_verified",
            "cursor_integrity_and_expiry_verified",
            "deprovision_and_tombstone_verified",
            "set_signature_and_replay_verified",
            "roundtrip_verified",
            "clean_controls_passed",
        },
        "claims",
    )
    if set(_string_list(claims["rfc_set"], "claims.rfc_set")) != {
        "RFC7643",
        "RFC7644",
        "RFC9865",
        "RFC9967",
    }:
        raise IndustryExtensionEvidenceError("SCIM evidence must bind all four RFCs")
    if set(
        _string_list(claims["lifecycle_operations"], "claims.lifecycle_operations")
    ) != {"create", "read", "replace", "patch", "delete", "deprovision"}:
        raise IndustryExtensionEvidenceError(
            "SCIM evidence must cover the complete lifecycle"
        )
    _positive_integer(claims["resources_evaluated"], "claims.resources_evaluated")
    for name in set(claims) - {
        "rfc_set",
        "lifecycle_operations",
        "resources_evaluated",
    }:
        if claims[name] is not True:
            raise IndustryExtensionEvidenceError(
                "SCIM schema, authorization, pagination, lifecycle, event and clean controls must pass"
            )


def _validate_shared_signals(claims: dict[str, Any], execution: dict[str, Any]) -> None:
    del execution
    _exact_fields(
        claims,
        {
            "profiles",
            "delivery_modes",
            "event_types_evaluated",
            "metadata_and_stream_management_verified",
            "set_claims_verified",
            "replay_and_subject_confusion_detected",
            "ordering_and_removal_verified",
            "key_rotation_and_outage_verified",
            "revocation_latency_reported",
            "upstream_conformance_alpha_acknowledged",
            "openid_certification_claimed",
        },
        "claims",
    )
    if set(_string_list(claims["profiles"], "claims.profiles")) != {
        "ssf",
        "caep",
        "risc",
    }:
        raise IndustryExtensionEvidenceError(
            "shared-signals evidence must cover SSF, CAEP and RISC"
        )
    if set(_string_list(claims["delivery_modes"], "claims.delivery_modes")) != {
        "push",
        "poll",
    }:
        raise IndustryExtensionEvidenceError(
            "shared-signals evidence must cover push and poll"
        )
    _positive_integer(claims["event_types_evaluated"], "claims.event_types_evaluated")
    required = set(claims) - {
        "profiles",
        "delivery_modes",
        "event_types_evaluated",
        "openid_certification_claimed",
    }
    if (
        any(claims[name] is not True for name in required)
        or claims["openid_certification_claimed"] is not False
    ):
        raise IndustryExtensionEvidenceError(
            "shared-signals trust, alpha acknowledgement and no-certification boundary must hold"
        )


def _validate_authzen(claims: dict[str, Any], execution: dict[str, Any]) -> None:
    del execution
    _exact_fields(
        claims,
        {
            "specification_version",
            "roles",
            "decisions_evaluated",
            "metadata_and_capability_negotiation_verified",
            "subject_resource_action_context_binding_verified",
            "single_and_batch_evaluation_verified",
            "search_capabilities_verified",
            "fail_closed_default_verified",
            "type_tenant_and_context_confusion_detected",
            "stale_policy_and_cache_detected",
            "partial_failure_timeout_and_outage_handled",
            "draft_profiles_included",
            "openid_certification_claimed",
        },
        "claims",
    )
    if claims["specification_version"] != "1.0":
        raise IndustryExtensionEvidenceError("AuthZEN evidence must use version 1.0")
    if set(_string_list(claims["roles"], "claims.roles")) != {"pdp", "pep"}:
        raise IndustryExtensionEvidenceError(
            "AuthZEN evidence must cover PDP and PEP roles"
        )
    _positive_integer(claims["decisions_evaluated"], "claims.decisions_evaluated")
    required = set(claims) - {
        "specification_version",
        "roles",
        "decisions_evaluated",
        "draft_profiles_included",
        "openid_certification_claimed",
    }
    if (
        any(claims[name] is not True for name in required)
        or claims["draft_profiles_included"] is not False
        or claims["openid_certification_claimed"] is not False
    ):
        raise IndustryExtensionEvidenceError(
            "AuthZEN decision, failure, draft-exclusion and no-certification boundaries must hold"
        )


def _validate_openid_federation(
    claims: dict[str, Any], execution: dict[str, Any]
) -> None:
    del execution
    _exact_fields(
        claims,
        {
            "specifications",
            "entity_roles",
            "trust_chains_evaluated",
            "entity_statement_signature_verified",
            "authority_hint_and_path_resolution_verified",
            "metadata_policy_application_verified",
            "trust_mark_and_oidc_binding_verified",
            "key_rollover_expiry_and_revocation_verified",
            "cycle_fork_substitution_and_downgrade_detected",
            "official_early_suite_acknowledged",
            "independent_negative_oracles_replayed",
            "openid_certification_claimed",
        },
        "claims",
    )
    if set(_string_list(claims["specifications"], "claims.specifications")) != {
        "openid-federation-1.1",
        "openid-federation-connect-1.1",
    }:
        raise IndustryExtensionEvidenceError(
            "OpenID Federation evidence must bind both final 1.1 specifications"
        )
    if set(_string_list(claims["entity_roles"], "claims.entity_roles")) != {
        "trust-anchor",
        "intermediate",
        "leaf",
    }:
        raise IndustryExtensionEvidenceError(
            "OpenID Federation evidence must cover anchor, intermediate and leaf roles"
        )
    _positive_integer(claims["trust_chains_evaluated"], "claims.trust_chains_evaluated")
    required = set(claims) - {
        "specifications",
        "entity_roles",
        "trust_chains_evaluated",
        "openid_certification_claimed",
    }
    if (
        any(claims[name] is not True for name in required)
        or claims["openid_certification_claimed"] is not False
    ):
        raise IndustryExtensionEvidenceError(
            "Federation trust, early-suite and no-certification boundaries must hold"
        )


def _validate_hpc_ai_infrastructure(
    claims: dict[str, Any], execution: dict[str, Any]
) -> None:
    del execution
    _exact_fields(
        claims,
        {
            "publications",
            "zones_evaluated",
            "threats_evaluated",
            "tailored_controls_evaluated",
            "reference_architecture_bound",
            "moderate_baseline_overlay_verified",
            "applicability_odp_and_compensation_verified",
            "scheduler_accelerator_storage_and_shared_resource_verified",
            "management_plane_and_cross_job_isolation_verified",
            "performance_security_tradeoffs_measured",
            "recovery_and_residue_checks_verified",
            "sp800_239_draft_included",
            "nist_certification_claimed",
        },
        "claims",
    )
    if set(_string_list(claims["publications"], "claims.publications")) != {
        "NIST-SP-800-223",
        "NIST-SP-800-234",
    }:
        raise IndustryExtensionEvidenceError(
            "HPC evidence must bind final SP 800-223 and SP 800-234"
        )
    _positive_integer(claims["zones_evaluated"], "claims.zones_evaluated")
    _positive_integer(claims["threats_evaluated"], "claims.threats_evaluated")
    _positive_integer(
        claims["tailored_controls_evaluated"],
        "claims.tailored_controls_evaluated",
    )
    if claims["tailored_controls_evaluated"] != 60:
        raise IndustryExtensionEvidenceError(
            "HPC overlay evidence must evaluate all 60 tailored controls"
        )
    required = set(claims) - {
        "publications",
        "zones_evaluated",
        "threats_evaluated",
        "tailored_controls_evaluated",
        "sp800_239_draft_included",
        "nist_certification_claimed",
    }
    if (
        any(claims[name] is not True for name in required)
        or claims["sp800_239_draft_included"] is not False
        or claims["nist_certification_claimed"] is not False
    ):
        raise IndustryExtensionEvidenceError(
            "HPC architecture, complete overlay, draft-exclusion and claim boundaries must hold"
        )


def _validate_iso_24760(claims: dict[str, Any], execution: dict[str, Any]) -> None:
    del execution
    _exact_fields(
        claims,
        {
            "parts",
            "principal_types",
            "lifecycle_operations",
            "identities_evaluated",
            "concept_and_terminology_consistency_verified",
            "reference_architecture_and_authorities_verified",
            "identifier_attribute_alias_and_namespace_verified",
            "privacy_minimization_and_correlation_verified",
            "federation_and_assurance_verified",
            "lifecycle_closure_and_authoritative_reconciliation_verified",
            "licensed_criteria_used",
            "iso_certification_claimed",
        },
        "claims",
    )
    if set(_string_list(claims["parts"], "claims.parts")) != {
        "ISO-IEC-24760-1:2025",
        "ISO-IEC-24760-2:2025",
        "ISO-IEC-24760-3:2025",
    }:
        raise IndustryExtensionEvidenceError(
            "identity-management evidence must bind all three 2025 parts"
        )
    if set(_string_list(claims["principal_types"], "claims.principal_types")) != {
        "person",
        "organization",
        "device",
        "software",
    }:
        raise IndustryExtensionEvidenceError(
            "identity-management evidence must cover every principal type"
        )
    if set(
        _string_list(claims["lifecycle_operations"], "claims.lifecycle_operations")
    ) != {
        "proof",
        "enroll",
        "issue",
        "use",
        "maintain",
        "recover",
        "suspend",
        "revoke",
        "delete",
    }:
        raise IndustryExtensionEvidenceError(
            "identity-management evidence must cover the complete lifecycle"
        )
    _positive_integer(claims["identities_evaluated"], "claims.identities_evaluated")
    required = set(claims) - {
        "parts",
        "principal_types",
        "lifecycle_operations",
        "identities_evaluated",
        "iso_certification_claimed",
    }
    if (
        any(claims[name] is not True for name in required)
        or claims["iso_certification_claimed"] is not False
    ):
        raise IndustryExtensionEvidenceError(
            "identity concepts, architecture, lifecycle, privacy and no-certification boundaries must hold"
        )


def _validate_iso_5259_6(claims: dict[str, Any], execution: dict[str, Any]) -> None:
    del execution
    _exact_fields(
        claims,
        {
            "technical_report_version",
            "quality_measures_evaluated",
            "visualizations_evaluated",
            "measure_dataset_population_and_strata_bound",
            "transformation_provenance_and_freshness_verified",
            "uncertainty_missingness_and_limitations_visible",
            "comparison_context_and_reproduction_verified",
            "accessibility_and_role_fitness_verified",
            "scale_aggregation_subgroup_color_and_order_mutations_detected",
            "technical_report_guidance_only_acknowledged",
            "iso_conformance_or_certification_claimed",
        },
        "claims",
    )
    if claims["technical_report_version"] != "2026":
        raise IndustryExtensionEvidenceError(
            "data-quality visualization evidence must use TR 5259-6:2026"
        )
    _positive_integer(
        claims["quality_measures_evaluated"], "claims.quality_measures_evaluated"
    )
    _positive_integer(
        claims["visualizations_evaluated"], "claims.visualizations_evaluated"
    )
    required = set(claims) - {
        "technical_report_version",
        "quality_measures_evaluated",
        "visualizations_evaluated",
        "iso_conformance_or_certification_claimed",
    }
    if (
        any(claims[name] is not True for name in required)
        or claims["iso_conformance_or_certification_claimed"] is not False
    ):
        raise IndustryExtensionEvidenceError(
            "visualization fidelity, guidance-only and no-certification boundaries must hold"
        )


def _validate_spiffe(claims: dict[str, Any], execution: dict[str, Any]) -> None:
    del execution
    _exact_fields(
        claims,
        {
            "svid_types",
            "trust_domains_evaluated",
            "stable_spec_snapshot_bound",
            "node_and_workload_attestation_verified",
            "selector_isolation_verified",
            "workload_api_authorization_verified",
            "bundle_rotation_and_revocation_verified",
            "federation_verified",
            "impersonation_replay_and_domain_substitution_detected",
            "experimental_remote_api_included",
        },
        "claims",
    )
    if set(_string_list(claims["svid_types"], "claims.svid_types")) != {"x509", "jwt"}:
        raise IndustryExtensionEvidenceError(
            "SPIFFE evidence must cover X.509 and JWT SVIDs"
        )
    _positive_integer(
        claims["trust_domains_evaluated"], "claims.trust_domains_evaluated"
    )
    required = set(claims) - {
        "svid_types",
        "trust_domains_evaluated",
        "experimental_remote_api_included",
    }
    if (
        any(claims[name] is not True for name in required)
        or claims["experimental_remote_api_included"] is not False
    ):
        raise IndustryExtensionEvidenceError(
            "SPIFFE attestation, identity, bundle and federation checks must pass with experimental APIs excluded"
        )


def _validate_model_signing(claims: dict[str, Any], execution: dict[str, Any]) -> None:
    del execution
    _exact_fields(
        claims,
        {
            "oms_version",
            "signing_modes",
            "official_vectors_passed",
            "schemas_bound",
            "all_model_files_manifested",
            "signer_identity_verified",
            "independent_verifier_replayed",
            "partial_duplicate_path_and_tamper_detected",
            "key_destruction_verified",
            "model_safety_or_quality_claimed",
        },
        "claims",
    )
    if claims["oms_version"] != "1.0":
        raise IndustryExtensionEvidenceError("model-signing evidence must use OMS 1.0")
    if not {"sigstore", "dsse-in-toto", "pki"} <= set(
        _string_list(claims["signing_modes"], "claims.signing_modes")
    ):
        raise IndustryExtensionEvidenceError(
            "model-signing evidence is missing a required signing mode"
        )
    _positive_integer(
        claims["official_vectors_passed"], "claims.official_vectors_passed"
    )
    required = set(claims) - {
        "oms_version",
        "signing_modes",
        "official_vectors_passed",
        "model_safety_or_quality_claimed",
    }
    if (
        any(claims[name] is not True for name in required)
        or claims["model_safety_or_quality_claimed"] is not False
    ):
        raise IndustryExtensionEvidenceError(
            "model-signing completeness, verification and integrity-only claim boundary must hold"
        )


def _validate_mlbom(claims: dict[str, Any], execution: dict[str, Any]) -> None:
    del execution
    _exact_fields(
        claims,
        {
            "cyclonedx_version",
            "formats",
            "model_components_evaluated",
            "model_card_verified",
            "datasets_and_dependencies_verified",
            "training_parameters_and_provenance_verified",
            "bomlink_verified",
            "roundtrip_and_unknown_fields_verified",
            "omission_tamper_and_misbinding_detected",
            "safety_fairness_or_quality_proof_claimed",
        },
        "claims",
    )
    if claims["cyclonedx_version"] != "1.7":
        raise IndustryExtensionEvidenceError("ML-BOM evidence must use CycloneDX 1.7")
    if set(_string_list(claims["formats"], "claims.formats")) != {"json", "xml"}:
        raise IndustryExtensionEvidenceError("ML-BOM evidence must cover JSON and XML")
    _positive_integer(
        claims["model_components_evaluated"], "claims.model_components_evaluated"
    )
    required = set(claims) - {
        "cyclonedx_version",
        "formats",
        "model_components_evaluated",
        "safety_fairness_or_quality_proof_claimed",
    }
    if (
        any(claims[name] is not True for name in required)
        or claims["safety_fairness_or_quality_proof_claimed"] is not False
    ):
        raise IndustryExtensionEvidenceError(
            "ML-BOM inventory, roundtrip, negative cases and no-safety-proof boundary must hold"
        )


def _validate_uptane(claims: dict[str, Any], execution: dict[str, Any]) -> None:
    del execution
    _exact_fields(
        claims,
        {
            "uptane_version",
            "ecu_verification_modes",
            "vehicles_evaluated",
            "director_and_image_repositories_verified",
            "metadata_roles_and_thresholds_verified",
            "secure_time_and_expiry_verified",
            "pouf_bound",
            "install_and_recovery_verified",
            "rollback_freeze_mixmatch_compromise_detected",
            "certification_claimed",
        },
        "claims",
    )
    if claims["uptane_version"] != "2.1.0":
        raise IndustryExtensionEvidenceError("Uptane evidence must use version 2.1.0")
    if set(
        _string_list(claims["ecu_verification_modes"], "claims.ecu_verification_modes")
    ) != {"full", "partial"}:
        raise IndustryExtensionEvidenceError(
            "Uptane evidence must cover full and partial verification ECUs"
        )
    _positive_integer(claims["vehicles_evaluated"], "claims.vehicles_evaluated")
    required = set(claims) - {
        "uptane_version",
        "ecu_verification_modes",
        "vehicles_evaluated",
        "certification_claimed",
    }
    if (
        any(claims[name] is not True for name in required)
        or claims["certification_claimed"] is not False
    ):
        raise IndustryExtensionEvidenceError(
            "Uptane repository, ECU, attack, recovery and no-certification boundaries must hold"
        )


def _validate_aixcc(claims: dict[str, Any], execution: dict[str, Any]) -> None:
    _exact_fields(
        claims,
        {
            "challenges_evaluated",
            "challenge_classes",
            "corpus_and_pipeline_bound",
            "license_manifest_verified",
            "protected_split_verified",
            "training_overlap_checked",
            "contamination_assessed",
            "resource_and_model_budgets_bound",
            "povs_independently_validated",
            "patches_independently_replayed",
            "functional_regressions",
            "real_and_synthetic_results_separated",
            "confidence_bounds_reported",
            "public_corpus_readiness_inferred",
        },
        "claims",
    )
    _positive_integer(claims["challenges_evaluated"], "claims.challenges_evaluated")
    if set(_string_list(claims["challenge_classes"], "claims.challenge_classes")) != {
        "real",
        "synthetic",
    }:
        raise IndustryExtensionEvidenceError(
            "AIxCC evidence must separate real and synthetic challenges"
        )
    if execution["repetitions"] < 3:
        raise IndustryExtensionEvidenceError(
            "AIxCC evaluation requires at least three trials"
        )
    _nonnegative_integer(
        claims["functional_regressions"], "claims.functional_regressions"
    )
    required = set(claims) - {
        "challenges_evaluated",
        "challenge_classes",
        "functional_regressions",
        "public_corpus_readiness_inferred",
    }
    if (
        any(claims[name] is not True for name in required)
        or claims["functional_regressions"] != 0
        or claims["public_corpus_readiness_inferred"] is not False
    ):
        raise IndustryExtensionEvidenceError(
            "AIxCC corpus, split, oracle, budget, regression and upstream-readiness boundaries must hold"
        )


def _validate_criticality_score(
    claims: dict[str, Any], execution: dict[str, Any]
) -> None:
    del execution
    _exact_fields(
        claims,
        {
            "snapshots_evaluated",
            "algorithm_and_collector_bound",
            "raw_signals_preserved",
            "provenance_and_freshness_preserved",
            "aliases_reconciled",
            "missing_stale_and_outlier_cases_replayed",
            "deterministic_recomputation_verified",
            "sensitivity_reported",
            "downstream_calibration_reported",
            "reachability_exploitability_maintenance_separated",
            "context_only",
            "used_as_security_gate_or_vulnerability_likelihood",
        },
        "claims",
    )
    _positive_integer(claims["snapshots_evaluated"], "claims.snapshots_evaluated")
    if claims["snapshots_evaluated"] < 3:
        raise IndustryExtensionEvidenceError(
            "criticality calibration requires at least three snapshots"
        )
    required = set(claims) - {
        "snapshots_evaluated",
        "used_as_security_gate_or_vulnerability_likelihood",
    }
    if (
        any(claims[name] is not True for name in required)
        or claims["used_as_security_gate_or_vulnerability_likelihood"] is not False
    ):
        raise IndustryExtensionEvidenceError(
            "criticality evidence must be reproducible, calibrated and context-only"
        )


def _string_list(value: object, label: str) -> list[str]:
    if (
        not isinstance(value, list)
        or not value
        or any(not isinstance(item, str) or not item for item in value)
        or len(value) != len(set(value))
    ):
        raise IndustryExtensionEvidenceError(
            f"{label} must contain unique non-empty strings"
        )
    return value


def _required_true_claims(
    claims: dict[str, Any], required: set[str], *, extra: set[str] | None = None
) -> None:
    _exact_fields(claims, required | (extra or set()), "claims")
    if any(claims[name] is not True for name in required):
        raise IndustryExtensionEvidenceError("all required claims must be verified")


def _object(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise IndustryExtensionEvidenceError(f"{label} must be an object")
    return cast(dict[str, Any], value)


def _exact_fields(value: dict[str, Any], expected: set[str], label: str) -> None:
    if set(value) != expected:
        raise IndustryExtensionEvidenceError(
            f"{label} fields must be exactly: {', '.join(sorted(expected))}"
        )


def _digest(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != _SHA256_LENGTH
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise IndustryExtensionEvidenceError(f"{label} must be lowercase SHA-256")
    return value


def _positive_integer(value: object, label: str) -> None:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise IndustryExtensionEvidenceError(f"{label} must be a positive integer")


def _nonnegative_integer(value: object, label: str) -> None:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise IndustryExtensionEvidenceError(f"{label} must be a non-negative integer")


def _validate_strict_domain_claims(
    claims: dict[str, Any],
    *,
    scalars: dict[str, str],
    sets: dict[str, set[str]],
    counts: tuple[str, ...],
    required_true: tuple[str, ...],
    required_false: tuple[str, ...],
) -> None:
    expected = (
        set(scalars)
        | set(sets)
        | set(counts)
        | set(required_true)
        | set(required_false)
    )
    _exact_fields(claims, expected, "claims")
    for name, value in scalars.items():
        if claims[name] != value:
            raise IndustryExtensionEvidenceError(f"claims.{name} must equal {value!r}")
    for name, values in sets.items():
        if set(_string_list(claims[name], f"claims.{name}")) != values:
            raise IndustryExtensionEvidenceError(
                f"claims.{name} must cover the exact governed set"
            )
    for name in counts:
        _positive_integer(claims[name], f"claims.{name}")
    if any(claims[name] is not True for name in required_true):
        raise IndustryExtensionEvidenceError("all domain assurance checks must pass")
    if any(claims[name] is not False for name in required_false):
        raise IndustryExtensionEvidenceError(
            "domain isolation, draft-exclusion and no-certification boundaries must hold"
        )


def _validate_medical_device(claims: dict[str, Any], execution: dict[str, Any]) -> None:
    del execution
    _validate_strict_domain_claims(
        claims,
        scalars={"criteria_version": "sw96-2023-iec80001-2021-iec60601-4-5-2021"},
        sets={"device_types": {"embedded", "software", "connected"}},
        counts=("devices_evaluated", "adversarial_cases_replayed"),
        required_true=(
            "security_risk_and_patient_harm_trace_verified",
            "capability_levels_and_clinical_zones_verified",
            "manufacturer_operator_and_service_responsibility_verified",
            "sbom_legacy_patch_and_end_of_support_verified",
            "clinical_availability_and_safe_recovery_verified",
            "independent_medical_safety_review_completed",
        ),
        required_false=("real_patient_data_used", "regulatory_certification_claimed"),
    )


def _validate_physical_ai(claims: dict[str, Any], execution: dict[str, Any]) -> None:
    del execution
    _validate_strict_domain_claims(
        claims,
        scalars={},
        sets={
            "standards": {
                "ISO-21448:2022",
                "ISO-PAS-8800:2024",
                "ISO-34502:2022",
                "UL-4600:ED3",
            },
            "scenario_classes": {"nominal", "boundary", "rare", "adversarial"},
        },
        counts=("scenarios_evaluated",),
        required_true=(
            "ai_element_data_odd_and_hazard_binding_verified",
            "sensor_timing_map_weather_and_actor_mutations_replayed",
            "monitor_fallback_and_safe_state_verified",
            "scenario_coverage_and_metamorphic_consistency_verified",
            "deterministic_reproduction_verified",
            "independent_safety_case_review_completed",
        ),
        required_false=(
            "real_world_actuation_performed",
            "product_certification_claimed",
        ),
    )


def _validate_critical_cpp(claims: dict[str, Any], execution: dict[str, Any]) -> None:
    del execution
    _validate_strict_domain_claims(
        claims,
        scalars={},
        sets={
            "editions": {"MISRA-C:2023", "MISRA-CPP:2023"},
            "compiler_families": {"gcc", "clang", "msvc"},
        },
        counts=("cases_evaluated", "rules_evaluated"),
        required_true=(
            "licensed_rule_digest_bound",
            "language_mode_target_and_optimization_bound",
            "positive_negative_and_ambiguous_oracles_verified",
            "compiler_warning_sanitizer_and_runtime_corroboration_verified",
            "deviation_approval_and_expiry_verified",
            "independent_disagreement_adjudication_completed",
        ),
        required_false=("production_binary_executed", "misra_certification_claimed"),
    )


def _validate_confidential_computing(
    claims: dict[str, Any], execution: dict[str, Any]
) -> None:
    del execution
    _validate_strict_domain_claims(
        claims,
        scalars={"rats_architecture": "RFC9334", "eat_version": "RFC9711"},
        sets={
            "platforms": {"amd-sev-snp", "intel-tdx", "arm-cca"},
            "roles": {"attester", "verifier", "relying-party"},
        },
        counts=("evidence_vectors_evaluated",),
        required_true=(
            "endorsement_reference_value_and_appraisal_policy_bound",
            "signature_measurement_freshness_and_tcb_verified",
            "revocation_debug_and_outage_behavior_verified",
            "replay_downgrade_claim_confusion_and_substitution_detected",
            "cross_vendor_semantic_differences_preserved",
            "independent_verifier_replayed",
            "secret_release_failed_closed",
        ),
        required_false=("production_secret_released", "hardware_certification_claimed"),
    )


def _validate_vvsg(claims: dict[str, Any], execution: dict[str, Any]) -> None:
    del execution
    _validate_strict_domain_claims(
        claims,
        scalars={"vvsg_version": "2.0", "test_assertions_version": "1.4"},
        sets={},
        counts=("assertions_evaluated",),
        required_true=(
            "applicability_matrix_complete",
            "software_independence_and_auditability_verified",
            "security_accessibility_reliability_and_usability_verified",
            "ballot_record_log_media_network_and_power_cases_replayed",
            "chain_of_custody_and_build_identity_verified",
            "deterministic_synthetic_election_reset_verified",
            "vstl_and_jurisdiction_claim_boundaries_verified",
        ),
        required_false=("real_ballots_or_voter_data_used", "eac_certification_claimed"),
    )


def _validate_critical_sector(
    claims: dict[str, Any], execution: dict[str, Any]
) -> None:
    del execution
    _validate_strict_domain_claims(
        claims,
        scalars={},
        sets={"sectors": {"nuclear", "rail", "space"}},
        counts=("digital_twin_scenarios_evaluated",),
        required_true=(
            "sector_specific_applicability_and_licensed_criteria_bound",
            "essential_function_hazard_zone_conduit_and_mode_map_verified",
            "safety_security_interaction_and_independence_verified",
            "loss_of_view_control_timing_sequence_and_communication_replayed",
            "degraded_operation_recovery_and_reconciliation_verified",
            "qualified_independent_assurance_and_ivv_completed",
        ),
        required_false=(
            "production_actuation_performed",
            "sector_certification_claimed",
        ),
    )


def _validate_stateful_smart_contract(
    claims: dict[str, Any], execution: dict[str, Any]
) -> None:
    del execution
    _validate_strict_domain_claims(
        claims,
        scalars={"chain_type": "disposable-local-evm"},
        sets={"normative_sources": {"OWASP-SMART-CONTRACT-TOP10", "SMARTBUGS-2"}},
        counts=("contracts_evaluated", "multi_transaction_cases_replayed"),
        required_true=(
            "source_compiler_bytecode_deployment_and_chain_bound",
            "roles_assets_state_governance_proxy_oracle_and_bridge_modeled",
            "exploit_balance_state_liveness_and_economic_invariants_verified",
            "reentrancy_price_signature_ordering_upgrade_and_dos_cases_replayed",
            "clean_controls_and_fix_replay_verified",
            "deterministic_chain_reset_and_independent_exploit_replay_verified",
        ),
        required_false=(
            "alpha_scsvs_included",
            "real_assets_used",
            "audit_certification_claimed",
        ),
    )


def _validate_devsecops_longitudinal(
    claims: dict[str, Any], execution: dict[str, Any]
) -> None:
    del execution
    _validate_strict_domain_claims(
        claims,
        scalars={"dora_metric_set": "five"},
        sets={"maturity_models": {"samm", "dsomm", "dsovs", "tmmi"}},
        counts=("periods_evaluated", "teams_evaluated", "blinded_cases_evaluated"),
        required_true=(
            "organization_product_team_and_period_scope_bound",
            "immutable_delivery_events_and_metric_definitions_verified",
            "quality_security_defect_escape_and_test_outcomes_joined",
            "scope_drift_level_inflation_and_metric_gaming_detected",
            "licensed_model_content_protected",
            "independent_assessor_agreement_and_adjudication_completed",
            "longitudinal_uncertainty_and_causal_limits_reported",
        ),
        required_false=(
            "individual_performance_ranking_performed",
            "maturity_certification_claimed",
        ),
    )


def _validate_detection_longitudinal(
    claims: dict[str, Any], execution: dict[str, Any]
) -> None:
    del execution
    _validate_strict_domain_claims(
        claims,
        scalars={},
        sets={
            "outcome_dimensions": {
                "visibility",
                "detection",
                "protection",
                "false-positive",
                "latency",
            },
            "variant_classes": {
                "encoding",
                "fragmentation",
                "lolbin",
                "timing",
                "policy",
                "sensor-outage",
            },
        },
        counts=(
            "attack_steps_replayed",
            "benign_workloads_replayed",
            "product_versions_evaluated",
        ),
        required_true=(
            "product_policy_sensor_content_environment_and_time_bound",
            "independent_step_level_ground_truth_verified",
            "telemetry_normalization_preserved_source_semantics",
            "benign_false_positive_and_adversary_evasion_measured",
            "version_content_and_environment_drift_reported",
            "misses_false_positives_and_disagreements_adjudicated",
            "laboratory_restoration_verified",
        ),
        required_false=(
            "live_malware_used",
            "vendor_endorsement_or_certification_claimed",
        ),
    )


def _validate_stig_configuration(
    claims: dict[str, Any], execution: dict[str, Any]
) -> None:
    del execution
    _validate_strict_domain_claims(
        claims,
        scalars={"release_policy": "policy-pinned-quarterly-release"},
        sets={"assessment_modes": {"xccdf-oval", "manual"}},
        counts=("assets_evaluated", "rules_evaluated", "release_deltas_evaluated"),
        required_true=(
            "release_signature_digest_and_delta_verified",
            "asset_cpe_profile_tailoring_and_applicability_verified",
            "automated_manual_and_engine_disagreement_adjudicated",
            "exception_poam_owner_and_expiry_verified",
            "laboratory_remediation_rollback_and_rescan_verified",
            "longitudinal_drift_and_durability_measured",
        ),
        required_false=("production_remediation_performed", "authorization_claimed"),
    )


def _validate_ot_patch_lifecycle(
    claims: dict[str, Any], execution: dict[str, Any]
) -> None:
    del execution
    _validate_strict_domain_claims(
        claims,
        scalars={"iec_62443_2_3_edition": "2015"},
        sets={
            "lifecycle_phases": {
                "advisory",
                "qualification",
                "deployment",
                "rollback",
                "compensation",
                "restoration",
            }
        },
        counts=("patches_evaluated", "asset_cases_evaluated"),
        required_true=(
            "signed_advisory_firmware_asset_and_applicability_bound",
            "exploit_safety_availability_and_maintenance_window_verified",
            "laboratory_qualification_acceptance_and_process_invariants_verified",
            "partial_failure_safe_state_rollback_and_restoration_replayed",
            "compensating_control_owner_expiry_and_residual_risk_verified",
            "deployment_latency_downtime_recurrence_and_outcomes_measured",
        ),
        required_false=("production_process_actuated", "iec_certification_claimed"),
    )


def _validate_continuing_airworthiness(
    claims: dict[str, Any], execution: dict[str, Any]
) -> None:
    del execution
    _validate_strict_domain_claims(
        claims,
        scalars={},
        sets={
            "assurance_sources": {"DO-355A", "ARP5150B", "ARP5151B"},
            "aircraft_populations": {"transport", "general-aviation", "rotorcraft"},
        },
        counts=("service_events_evaluated", "aircraft_configurations_evaluated"),
        required_true=(
            "service_security_reliability_and_maintenance_signals_correlated",
            "function_hazard_security_impact_and_uncertainty_verified",
            "tail_equipment_software_operator_and_fleet_effectivity_verified",
            "interim_action_corrective_action_authority_and_communication_verified",
            "field_deployment_effectiveness_recurrence_and_lessons_measured",
            "independent_safety_security_adjudication_completed",
        ),
        required_false=(
            "production_aircraft_connected",
            "certification_credit_claimed",
        ),
    )


def _validate_swift_cscf_assessment(
    claims: dict[str, Any], execution: dict[str, Any]
) -> None:
    del execution
    _validate_strict_domain_claims(
        claims,
        scalars={"cscf_edition": "2026"},
        sets={
            "assessment_dimensions": {
                "applicability",
                "annual-delta",
                "significant-change",
                "design",
                "operation",
                "reliance",
                "remediation-retest",
            }
        },
        counts=("bics_evaluated", "mandatory_controls_evaluated", "samples_replayed"),
        required_true=(
            "iaf_architecture_connectivity_and_scope_bound",
            "assessor_competence_independence_and_sampling_verified",
            "mandatory_advisory_exception_and_owner_applicability_verified",
            "significant_change_stale_evidence_and_reliance_limit_replayed",
            "transaction_recovery_remediation_retest_and_closure_verified",
            "annual_cycle_and_kyc_sa_handoff_independently_replayed",
        ),
        required_false=("production_messages_used", "swift_compliance_claimed"),
    )


def _validate_ccsds_space_mission(
    claims: dict[str, Any], execution: dict[str, Any]
) -> None:
    del execution
    _validate_strict_domain_claims(
        claims,
        scalars={"sdls_edition": "CCSDS-355.0-B-2"},
        sets={
            "publications": {
                "CCSDS-350.1-G-3",
                "CCSDS-350.7-G-2",
                "CCSDS-351.0-M-1",
                "CCSDS-352.0-B-2",
                "CCSDS-355.0-B-2",
                "CCSDS-355.1-B-1",
                "CCSDS-356.0-B-1",
                "CCSDS-357.0-B-1",
            },
            "segments": {"ground", "relay", "flight"},
        },
        counts=("mission_profiles_evaluated", "protocol_cases_replayed"),
        required_true=(
            "mission_phase_function_asset_flow_boundary_and_threat_trace_verified",
            "security_architecture_domain_entity_service_and_policy_map_verified",
            "algorithm_key_credential_security_association_and_sequence_state_verified",
            "sdls_header_trailer_managed_parameter_and_protocol_ordering_verified",
            "forgery_replay_reorder_delay_downgrade_desync_rollover_and_reset_replayed",
            "link_fault_monitoring_recovery_safety_invariant_and_residue_verified",
        ),
        required_false=(
            "production_spacecraft_connected",
            "flight_certification_claimed",
        ),
    )


def _validate_nss_dod(claims: dict[str, Any], execution: dict[str, Any]) -> None:
    del execution
    _validate_strict_domain_claims(
        claims,
        scalars={"cnssi_1253_revision": "2022-r5"},
        sets={"authorities": {"system-owner", "assessor", "authorizing-official"}},
        counts=("authorization_packages_evaluated", "adverse_cases_replayed"),
        required_true=(
            "nss_category_baseline_overlay_and_odp_bound",
            "tailoring_inheritance_and_compensating_controls_verified",
            "rmf_roles_assessment_poam_and_authorization_term_verified",
            "significant_change_and_continuous_monitoring_verified",
            "controlled_source_and_oscal_provenance_verified",
            "independent_government_role_adjudication_completed",
        ),
        required_false=("classified_data_used", "authorization_decision_claimed"),
    )


def _validate_zero_trust_zig(claims: dict[str, Any], execution: dict[str, Any]) -> None:
    del execution
    _validate_strict_domain_claims(
        claims,
        scalars={"zig_release": "2026-primer-discovery-phase1-phase2"},
        sets={
            "pillars": {
                "user",
                "device",
                "network-environment",
                "application-workload",
                "data",
                "visibility-analytics",
                "automation-orchestration",
            }
        },
        counts=("phase_one_two_activities_evaluated", "adverse_paths_replayed"),
        required_true=(
            "discovery_inventory_identity_flow_and_dependency_graph_verified",
            "policy_decision_enforcement_and_continuous_signals_verified",
            "lateral_movement_and_cross_pillar_denial_verified",
            "fail_closed_propagation_session_revocation_and_outage_verified",
            "telemetry_exception_recovery_and_restoration_verified",
            "independent_topology_and_policy_replay_completed",
        ),
        required_false=("production_traffic_modified", "government_maturity_endorsed"),
    )


def _validate_healthcare_operations(
    claims: dict[str, Any], execution: dict[str, Any]
) -> None:
    del execution
    _validate_strict_domain_claims(
        claims,
        scalars={"hicp_edition": "2023"},
        sets={"scenario_classes": {"ransomware", "identity", "outage", "supplier"}},
        counts=("clinical_services_evaluated", "exercises_replayed"),
        required_true=(
            "hicp_and_hph_goal_applicability_bound",
            "clinical_ephi_device_facility_and_vendor_dependencies_verified",
            "identity_segmentation_backup_and_emergency_access_verified",
            "downtime_continuity_restoration_and_reconciliation_verified",
            "patient_safety_and_service_outcomes_measured",
            "independent_clinical_safety_review_completed",
        ),
        required_false=("real_ephi_used", "regulatory_compliance_claimed"),
    )


def _validate_aircraft_system_assurance(
    claims: dict[str, Any], execution: dict[str, Any]
) -> None:
    del execution
    _validate_strict_domain_claims(
        claims,
        scalars={},
        sets={
            "assurance_sources": {
                "ARP4754B",
                "ARP4761A",
                "DO-178C",
                "DO-330",
                "DO-326A",
            }
        },
        counts=("system_cases_evaluated", "hazards_evaluated"),
        required_true=(
            "function_requirement_architecture_item_and_interface_trace_verified",
            "dal_allocation_derived_requirements_and_independence_verified",
            "fha_pssa_ssa_and_common_cause_reasoning_verified",
            "safety_security_interaction_and_tool_qualification_verified",
            "change_impact_and_configuration_identity_verified",
            "qualified_independent_assessor_adjudication_completed",
        ),
        required_false=(
            "flight_or_production_actuation_performed",
            "certification_credit_claimed",
        ),
    )


def _validate_ilac_laboratory(
    claims: dict[str, Any], execution: dict[str, Any]
) -> None:
    del execution
    _validate_strict_domain_claims(
        claims,
        scalars={},
        sets={
            "ilac_policies": {"P9:01/2024", "P10:07/2020", "P14:09/2020", "P15:05/2020"}
        },
        counts=("proficiency_results_evaluated", "laboratories_evaluated"),
        required_true=(
            "scope_method_measurand_and_decision_rule_bound",
            "metrological_traceability_and_measurement_uncertainty_verified",
            "provider_assigned_value_and_proficiency_performance_verified",
            "competence_impartiality_and_inspection_independence_verified",
            "nonconformity_corrective_action_and_followup_verified",
            "blinded_interlaboratory_adjudication_completed",
        ),
        required_false=("accredited_scope_extended", "accreditation_claimed"),
    )


def _validate_maritime_operations(
    claims: dict[str, Any], execution: dict[str, Any]
) -> None:
    del execution
    _validate_strict_domain_claims(
        claims,
        scalars={"imo_guidance": "MSC-FAL.1/Circ.3/Rev.3"},
        sets={
            "functions": {
                "govern",
                "identify",
                "protect",
                "detect",
                "respond",
                "recover",
            }
        },
        counts=("operational_modes_evaluated", "digital_twin_scenarios_replayed"),
        required_true=(
            "ship_shore_port_supplier_and_safety_management_scope_bound",
            "computer_based_system_inventory_and_dependency_map_verified",
            "access_segmentation_media_logging_training_and_supply_chain_verified",
            "navigation_machinery_cargo_and_communications_failures_replayed",
            "degraded_operation_manual_fallback_recovery_and_reconciliation_verified",
            "independent_maritime_safety_review_completed",
        ),
        required_false=(
            "production_vessel_actuation_performed",
            "flag_or_class_approval_claimed",
        ),
    )


def _validate_weakness_temporal(
    claims: dict[str, Any], execution: dict[str, Any]
) -> None:
    del execution
    _validate_strict_domain_claims(
        claims,
        scalars={},
        sets={
            "dimensions": {
                "cwe-hierarchy",
                "multi-label",
                "temporal",
                "project-holdout",
            }
        },
        counts=("findings_evaluated", "snapshots_evaluated", "projects_evaluated"),
        required_true=(
            "taxonomy_release_abstraction_and_label_policy_bound",
            "independent_multi_language_label_audit_completed",
            "project_chronology_duplicate_and_near_duplicate_controls_verified",
            "point_in_time_epss_kev_and_exploit_outcomes_verified",
            "calibration_recall_at_budget_effort_and_response_time_reported",
            "misses_label_noise_and_disagreements_adjudicated",
        ),
        required_false=("future_data_used", "vulnerability_certification_claimed"),
    )


def _validate_formal_disagreement(
    claims: dict[str, Any], execution: dict[str, Any]
) -> None:
    del execution
    _validate_strict_domain_claims(
        claims,
        scalars={},
        sets={"task_families": {"sv-comp", "test-comp", "rers", "chc"}},
        counts=("tasks_evaluated", "tools_evaluated", "disagreements_adjudicated"),
        required_true=(
            "task_property_language_semantics_and_resource_model_bound",
            "independent_witness_and_generated_test_validation_completed",
            "ground_truth_assumptions_and_undefined_behavior_reviewed",
            "timeout_memory_parser_and_unsound_witness_cases_replayed",
            "solver_and_validator_disagreement_matrix_reported",
            "sandbox_restoration_and_artifact_provenance_verified",
        ),
        required_false=("production_proof_claimed", "formal_certification_claimed"),
    )


def _validate_process_supplier_outcomes(
    claims: dict[str, Any], execution: dict[str, Any]
) -> None:
    del execution
    _validate_strict_domain_claims(
        claims,
        scalars={},
        sets={"domains": {"process-capability", "supplier-resilience"}},
        counts=(
            "assessors_evaluated",
            "projects_evaluated",
            "supplier_incidents_replayed",
        ),
        required_true=(
            "licensed_criteria_scope_period_and_evidence_bound",
            "blinded_assessor_agreement_and_adjudication_completed",
            "defect_escape_security_incident_and_recovery_outcomes_joined",
            "fourth_party_concentration_substitution_and_exit_verified",
            "scope_drift_stale_attestation_and_hidden_dependency_detected",
            "longitudinal_uncertainty_reassessment_and_causal_limits_reported",
        ),
        required_false=(
            "individual_performance_ranking_performed",
            "capability_certification_claimed",
        ),
    )


def _validate_incident_privacy_outcomes(
    claims: dict[str, Any], execution: dict[str, Any]
) -> None:
    del execution
    _validate_strict_domain_claims(
        claims,
        scalars={},
        sets={
            "outcomes": {"containment", "recovery", "individual-impact", "reassessment"}
        },
        counts=(
            "exercises_evaluated",
            "data_flows_evaluated",
            "affected_person_cases_evaluated",
        ),
        required_true=(
            "incident_service_data_flow_processing_and_recipient_scope_bound",
            "detection_containment_eradication_restoration_and_reconciliation_measured",
            "privacy_likelihood_severity_rights_and_residual_risk_verified",
            "notification_decision_timing_authority_and_exception_verified",
            "missed_flow_reidentification_scope_change_and_delay_cases_replayed",
            "independent_privacy_legal_and_incident_review_completed",
        ),
        required_false=("real_notification_sent", "legal_compliance_claimed"),
    )


def _validate_firmware_device_integrity(
    claims: dict[str, Any], execution: dict[str, Any]
) -> None:
    del execution
    _validate_strict_domain_claims(
        claims,
        scalars={"platform_scope": "client-server-bus-based"},
        sets={
            "assurance_sources": {
                "NIST-SP-800-147",
                "NIST-SP-800-147B",
                "NIST-SP-800-193",
                "NIST-SP-1800-34",
                "NIST-CSWP-45",
                "NIST-CSWP-52",
                "TCG-TPM-2.0",
            }
        },
        counts=("platforms_evaluated", "components_evaluated", "fault_cases_replayed"),
        required_true=(
            "platform_component_firmware_provenance_and_certificate_bound",
            "root_of_trust_update_signing_revocation_and_anti_rollback_verified",
            "measured_boot_event_log_pcr_quote_freshness_and_verifier_replayed",
            "hardware_weakness_attack_threat_and_sensitivity_metrics_reproduced",
            "bus_monitor_detection_consensus_false_positive_and_blind_spot_measured",
            "known_good_recovery_post_state_and_residue_independently_verified",
        ),
        required_false=("production_device_mutated", "platform_certification_claimed"),
    )


def _validate_kubernetes_pss_admission(
    claims: dict[str, Any], execution: dict[str, Any]
) -> None:
    del execution
    _validate_strict_domain_claims(
        claims,
        scalars={"kubernetes_minor": "1.36"},
        sets={
            "pod_security_levels": {"privileged", "baseline", "restricted"},
            "admission_modes": {"enforce", "audit", "warn"},
        },
        counts=(
            "clusters_evaluated",
            "namespaces_evaluated",
            "admission_cases_replayed",
        ),
        required_true=(
            "cluster_distribution_version_role_os_and_responsibility_bound",
            "namespace_level_mode_version_exemption_owner_and_expiry_verified",
            "direct_pod_controller_template_and_dry_run_admission_replayed",
            "restricted_field_os_semantics_webhook_and_upgrade_drift_verified",
            "bypass_exception_compensating_control_and_privileged_scope_adjudicated",
            "remediation_cleanup_rescan_audit_and_warning_evidence_verified",
        ),
        required_false=(
            "production_cluster_mutated",
            "kubernetes_certification_claimed",
        ),
    )


def _validate_payment_end_to_end(
    claims: dict[str, Any], execution: dict[str, Any]
) -> None:
    del execution
    _validate_strict_domain_claims(
        claims,
        scalars={"emv_3ds_version": "2.3.1.1"},
        sets={
            "payment_components": {
                "mpoc",
                "p2pe",
                "pin",
                "pts-poi",
                "hsm",
                "acs",
                "directory-server",
                "3ds-server",
            }
        },
        counts=(
            "devices_evaluated",
            "key_ceremonies_replayed",
            "transactions_replayed",
        ),
        required_true=(
            "solution_component_account_pin_key_device_hsm_and_3ds_flow_bound",
            "pin_block_key_block_split_knowledge_dual_control_and_destruction_verified",
            "poi_model_firmware_sred_tamper_inventory_and_listing_scope_verified",
            "acs_directory_server_3ds_server_message_and_assessor_scope_verified",
            "substitution_cleartext_replay_downgrade_outage_and_recovery_replayed",
            "synthetic_data_test_key_cleanup_retest_and_independent_review_verified",
        ),
        required_false=("live_pan_or_pin_used", "pci_or_emv_validation_claimed"),
    )


def _validate_ecss_space_software(
    claims: dict[str, Any], execution: dict[str, Any]
) -> None:
    del execution
    _validate_strict_domain_claims(
        claims,
        scalars={"ecss_q_st_80_edition": "Rev.2-2025"},
        sets={
            "software_segments": {"flight", "ground"},
            "lifecycle_phases": {
                "requirements",
                "architecture",
                "implementation",
                "verification",
                "validation",
                "operations",
                "maintenance",
            },
        },
        counts=(
            "software_items_evaluated",
            "requirements_evaluated",
            "mutations_replayed",
        ),
        required_true=(
            "mission_system_software_item_criticality_and_tailoring_bound",
            "bidirectional_requirement_architecture_interface_code_and_test_trace_verified",
            "product_assurance_independence_supplier_reuse_cots_and_tool_evidence_verified",
            "coverage_review_metric_configuration_nonconformance_and_anomaly_closure_verified",
            "traceability_reuse_interface_substitution_and_acceptance_mutations_replayed",
            "corrected_package_residual_risk_and_independent_replay_verified",
        ),
        required_false=("production_mission_connected", "space_qualification_claimed"),
    )


def _validate_regional_financial_resilience(
    claims: dict[str, Any], execution: dict[str, Any]
) -> None:
    del execution
    _validate_strict_domain_claims(
        claims,
        scalars={},
        sets={
            "jurisdictions": {"australia", "singapore"},
            "outcome_dimensions": {
                "technology-risk",
                "information-security",
                "critical-operation-tolerance",
                "supplier-resilience",
                "incident-response",
                "recovery-reconciliation",
            },
        },
        counts=(
            "entities_evaluated",
            "critical_operations_evaluated",
            "scenarios_replayed",
        ),
        required_true=(
            "entity_jurisdiction_obligation_guidance_and_applicability_bound",
            "critical_operation_tolerance_asset_dependency_provider_and_owner_verified",
            "control_design_operation_independent_test_and_board_oversight_verified",
            "incident_materiality_escalation_notification_decision_and_timing_replayed",
            "cyber_cloud_fourth_party_concentration_corruption_and_outage_cases_replayed",
            "restoration_reconciliation_lessons_remediation_and_reassessment_verified",
        ),
        required_false=(
            "production_financial_service_disrupted",
            "regulatory_compliance_claimed",
        ),
    )


def _validate_information_sharing_competence(
    claims: dict[str, Any], execution: dict[str, Any]
) -> None:
    del execution
    _validate_strict_domain_claims(
        claims,
        scalars={},
        sets={
            "handling_policies": {"TLP-2.0", "IEP-2.0"},
            "roles": {"originator", "releaser", "recipient", "assessor"},
        },
        counts=(
            "communities_evaluated",
            "sharing_cases_replayed",
            "assessors_calibrated",
        ),
        required_true=(
            "community_organization_participant_purpose_agreement_and_scope_bound",
            "classification_originator_control_recipient_forwarding_retention_and_withdrawal_verified",
            "transport_privacy_incident_containment_deletion_and_audit_evidence_verified",
            "role_competence_independence_golden_case_agreement_bias_and_drift_measured",
            "economic_alternatives_assumptions_cost_benefit_uncertainty_and_outcomes_verified",
            "misclassification_confusion_leakage_expiry_conflict_and_reassessment_replayed",
        ),
        required_false=(
            "real_sensitive_information_shared",
            "individual_public_ranking_performed",
            "iso_certification_claimed",
        ),
    )


def _validate_semiconductor_equipment(
    claims: dict[str, Any], execution: dict[str, Any]
) -> None:
    del execution
    _validate_strict_domain_claims(
        claims,
        scalars={"semi_baseline": "E187-0122-E188-0222-E191-policy-pinned"},
        sets={
            "lifecycle_stages": {
                "delivery",
                "installation",
                "operation",
                "service",
                "recovery",
            }
        },
        counts=(
            "equipment_items_evaluated",
            "service_cases_replayed",
            "status_reports_verified",
        ),
        required_true=(
            "fab_tool_supplier_device_software_firmware_and_owner_bound",
            "os_support_network_endpoint_monitoring_and_exception_controls_verified",
            "delivery_media_remote_service_install_upgrade_and_replacement_custody_verified",
            "device_status_inventory_vulnerability_protection_and_timestamp_semantics_verified",
            "contamination_substitution_report_suppression_and_recovery_cases_replayed",
            "known_good_restoration_residue_and_independent_review_verified",
        ),
        required_false=("production_fab_equipment_mutated", "semi_conformity_claimed"),
    )


def _validate_pipeline_control(
    claims: dict[str, Any], execution: dict[str, Any]
) -> None:
    del execution
    _validate_strict_domain_claims(
        claims,
        scalars={"api_1164_edition": "3-2021"},
        sets={
            "control_domains": {
                "scada",
                "local-control",
                "remote-access",
                "safety-interface",
            }
        },
        counts=(
            "pipeline_segments_evaluated",
            "essential_functions_evaluated",
            "scenarios_replayed",
        ),
        required_true=(
            "operator_segment_control_center_asset_zone_conduit_and_owner_bound",
            "essential_function_command_telemetry_remote_access_and_manual_operation_verified",
            "safety_availability_degraded_mode_and_emergency_response_invariants_verified",
            "forgery_replay_ransomware_segmentation_and_communications_failures_replayed",
            "restoration_order_configuration_state_and_process_reconciliation_verified",
            "independent_pipeline_safety_security_review_completed",
        ),
        required_false=("production_pipeline_actuated", "api_certification_claimed"),
    )


def _validate_gxp_data_integrity(
    claims: dict[str, Any], execution: dict[str, Any]
) -> None:
    del execution
    _validate_strict_domain_claims(
        claims,
        scalars={"part11_baseline": "current-2026-08-27"},
        sets={
            "record_controls": {
                "validation",
                "audit-trail",
                "electronic-signature",
                "retention",
                "inspection-copy",
            }
        },
        counts=("systems_evaluated", "records_evaluated", "mutations_replayed"),
        required_true=(
            "predicate_rule_system_record_user_role_signature_and_event_bound",
            "accuracy_reliability_access_authority_sequence_and_device_checks_verified",
            "audit_trail_signature_record_link_copy_retention_and_retrieval_verified",
            "supplier_change_configuration_backup_migration_and_periodic_review_verified",
            "alteration_deletion_backdating_replay_shared_credential_and_clock_cases_replayed",
            "restoration_data_integrity_and_independent_quality_review_verified",
        ),
        required_false=("real_regulated_records_used", "fda_compliance_claimed"),
    )


def _validate_cjis_security(claims: dict[str, Any], execution: dict[str, Any]) -> None:
    del execution
    _validate_strict_domain_claims(
        claims,
        scalars={"cjis_policy_version": "6.1-2026-06-25"},
        sets={
            "access_contexts": {
                "agency",
                "contractor",
                "cloud",
                "mobile",
                "remote-maintenance",
            }
        },
        counts=("agencies_evaluated", "systems_evaluated", "adverse_cases_replayed"),
        required_true=(
            "csa_agency_personnel_cji_system_device_location_agreement_and_owner_bound",
            "purpose_identity_access_privilege_encryption_and_key_custody_verified",
            "audit_media_mobile_remote_maintenance_and_physical_controls_verified",
            "incident_reporting_retention_sanitization_and_corrective_action_verified",
            "stale_personnel_device_loss_cloud_gap_misuse_suppression_and_disclosure_replayed",
            "policy_version_jurisdiction_and_independent_review_verified",
        ),
        required_false=("real_cji_used", "fbi_approval_claimed"),
    )


def _validate_automotive_spice(
    claims: dict[str, Any], execution: dict[str, Any]
) -> None:
    del execution
    _validate_strict_domain_claims(
        claims,
        scalars={"pam_version": "Automotive-SPICE-4.0"},
        sets={
            "assessment_dimensions": {
                "process-outcome",
                "base-practice",
                "information-item",
                "capability-attribute",
                "cybersecurity-trace",
            }
        },
        counts=(
            "processes_evaluated",
            "work_products_evaluated",
            "assessors_calibrated",
        ),
        required_true=(
            "organization_project_scope_process_outcome_and_sample_bound",
            "base_practice_information_item_work_product_and_evidence_trace_verified",
            "capability_attribute_rating_strength_weakness_and_action_verified",
            "cybersecurity_goal_requirement_architecture_test_and_supplier_trace_verified",
            "substitution_sampling_gap_rating_inflation_conflict_and_omission_cases_replayed",
            "blinded_agreement_adjudication_competence_and_independence_verified",
        ),
        required_false=(
            "individual_public_ranking_performed",
            "automotive_spice_certification_claimed",
        ),
    )


def _validate_iec61511_sis(claims: dict[str, Any], execution: dict[str, Any]) -> None:
    del execution
    _validate_strict_domain_claims(
        claims,
        scalars={"iec_61511_edition": "2016-AMD1-2017"},
        sets={
            "sis_lifecycle": {
                "hazard",
                "specification",
                "design",
                "validation",
                "operation",
                "proof-test",
                "modification",
            }
        },
        counts=("sifs_evaluated", "demands_replayed", "fault_cases_replayed"),
        required_true=(
            "process_hazard_sif_sil_srs_architecture_component_and_owner_bound",
            "risk_reduction_independence_diagnostic_timing_and_safe_state_verified",
            "application_program_validation_operation_bypass_and_proof_test_verified",
            "functional_safety_security_dependency_and_control_conflict_verified",
            "dangerous_common_cause_logic_change_delay_partial_trip_and_recovery_replayed",
            "restored_state_residue_and_independent_safety_security_review_verified",
        ),
        required_false=(
            "production_process_actuated",
            "iec_safety_certification_claimed",
        ),
    )


def _validate_bacnet_sc(claims: dict[str, Any], execution: dict[str, Any]) -> None:
    del execution
    _validate_strict_domain_claims(
        claims,
        scalars={"bacnet_baseline": "ANSI-ASHRAE-135-2024"},
        sets={"node_roles": {"node", "primary-hub", "failover-hub", "legacy-gateway"}},
        counts=("buildings_evaluated", "devices_evaluated", "protocol_cases_replayed"),
        required_true=(
            "building_device_node_hub_vmac_certificate_object_command_and_owner_bound",
            "trust_store_certificate_lifecycle_mutual_auth_and_authorization_verified",
            "segmentation_hub_failover_broadcast_time_logging_and_remote_admin_verified",
            "legacy_gateway_operator_override_safe_fallback_and_life_safety_boundary_verified",
            "certificate_substitution_replay_write_partition_time_and_failover_cases_replayed",
            "restoration_certificate_cleanup_and_independent_review_verified",
        ),
        required_false=("occupied_building_actuated", "bacnet_certification_claimed"),
    )


def _validate_industrial_robotics(
    claims: dict[str, Any], execution: dict[str, Any]
) -> None:
    del execution
    _validate_strict_domain_claims(
        claims,
        scalars={"robot_safety_baseline": "ISO-10218-1-2-2025"},
        sets={
            "robot_classes": {
                "fixed-industrial",
                "collaborative-application",
                "industrial-mobile",
            }
        },
        counts=("robots_evaluated", "cells_evaluated", "scenarios_replayed"),
        required_true=(
            "robot_controller_software_cell_zone_tool_workpiece_map_and_owner_bound",
            "mode_stop_speed_space_limit_enabling_device_and_diagnostic_functions_verified",
            "cell_mobile_route_safeguard_human_interaction_restart_and_maintenance_verified",
            "cybersecurity_dependency_command_integrity_sensor_and_change_controls_verified",
            "mode_confusion_intrusion_sensor_loss_injection_limit_failure_and_conflict_replayed",
            "safe_state_homing_residue_and_independent_machine_safety_review_verified",
        ),
        required_false=(
            "production_robot_motion_performed",
            "robot_safety_certification_claimed",
        ),
    )


def _validate_data_centre_resilience(
    claims: dict[str, Any], execution: dict[str, Any]
) -> None:
    del execution
    _validate_strict_domain_claims(
        claims,
        scalars={"facility_baseline": "ISO-IEC-22237-TIA-942-C"},
        sets={
            "infrastructure_domains": {
                "power",
                "cooling",
                "telecommunications",
                "fire",
                "physical-security",
                "monitoring",
            }
        },
        counts=(
            "facilities_evaluated",
            "topologies_evaluated",
            "failure_cases_replayed",
        ),
        required_true=(
            "site_building_room_service_tenant_class_dependency_and_owner_bound",
            "power_cooling_cabling_fire_access_monitoring_and_capacity_evidence_verified",
            "redundancy_maintainability_fault_tolerance_and_resilience_kpis_reproduced",
            "utility_generator_ups_cooling_path_access_sensor_and_maintenance_failures_replayed",
            "cascading_load_safe_operation_restoration_and_post_state_reconciliation_verified",
            "model_validity_and_independent_facility_safety_security_review_verified",
        ),
        required_false=(
            "production_facility_disrupted",
            "facility_certification_claimed",
        ),
    )


def _validate_water_sector_resilience(
    claims: dict[str, Any], execution: dict[str, Any]
) -> None:
    del execution
    _validate_strict_domain_claims(
        claims,
        scalars={"water_baseline": "AWWA-J100-21-G430-24-G440-22-EPA"},
        sets={
            "process_domains": {
                "source-water",
                "treatment",
                "chemical-feed",
                "distribution",
                "laboratory",
                "emergency-operations",
            }
        },
        counts=(
            "utilities_evaluated",
            "process_stages_evaluated",
            "scenarios_replayed",
        ),
        required_true=(
            "utility_population_process_asset_dependency_hazard_and_owner_bound",
            "water_quality_pressure_flow_chemical_and_availability_invariants_verified",
            "identity_remote_access_supplier_monitoring_backup_and_manual_operation_verified",
            "sensor_command_ransomware_communications_and_unsafe_automation_cases_replayed",
            "emergency_command_public_health_notification_and_alternate_supply_verified",
            "restoration_sampling_residue_independent_review_and_reassessment_verified",
        ),
        required_false=(
            "production_water_system_actuated",
            "awwa_or_epa_compliance_claimed",
        ),
    )


def _validate_public_safety_communications(
    claims: dict[str, Any], execution: dict[str, Any]
) -> None:
    del execution
    _validate_strict_domain_claims(
        claims,
        scalars={"communications_baseline": "NENA-NGSEC-I3-TIA102-P25-CAP"},
        sets={
            "service_domains": {
                "psap",
                "esinet",
                "ngcs",
                "location-routing",
                "dispatch",
                "land-mobile-radio",
            }
        },
        counts=(
            "systems_evaluated",
            "interfaces_evaluated",
            "cases_replayed",
        ),
        required_true=(
            "psap_esinet_function_interface_identity_route_radio_key_and_owner_bound",
            "ng911_message_location_routing_authorization_replay_and_privacy_verified",
            "p25_identity_key_lifecycle_emergency_signaling_and_interoperability_verified",
            "malformed_false_location_route_overload_site_loss_and_radio_mismatch_replayed",
            "dispatch_failover_degraded_mode_continuity_and_restoration_verified",
            "independent_ground_truth_traffic_exclusion_and_test_data_destruction_verified",
        ),
        required_false=(
            "live_emergency_traffic_used",
            "nena_tia_or_p25_certification_claimed",
        ),
    )


def _validate_global_gxp_data_integrity(
    claims: dict[str, Any], execution: dict[str, Any]
) -> None:
    del execution
    _validate_strict_domain_claims(
        claims,
        scalars={"gxp_baseline": "EU-ANNEX11-2011-WHO-TRS1033-PICS-PI041-1"},
        sets={
            "integrity_domains": {
                "validation",
                "metadata",
                "audit-trail",
                "electronic-signature",
                "backup-restore",
                "migration-retirement",
            }
        },
        counts=(
            "systems_evaluated",
            "records_evaluated",
            "mutations_replayed",
        ),
        required_true=(
            "jurisdiction_process_product_risk_system_record_metadata_and_owner_bound",
            "alcoa_plus_time_audit_trail_signature_copy_retention_and_retrieval_verified",
            "supplier_access_change_periodic_review_continuity_and_retirement_verified",
            "alteration_omission_backdating_shared_credential_clock_and_interface_cases_replayed",
            "backup_restore_migration_inspection_copy_and_reconstruction_verified",
            "independent_quality_review_current_annex_boundary_and_data_destruction_verified",
        ),
        required_false=(
            "real_regulated_or_patient_data_used",
            "regulatory_compliance_or_acceptance_claimed",
        ),
    )


def _validate_transit_resilience(
    claims: dict[str, Any], execution: dict[str, Any]
) -> None:
    del execution
    _validate_strict_domain_claims(
        claims,
        scalars={"transit_baseline": "NIST-IR-8576-FINAL-2026"},
        sets={
            "transit_domains": {
                "rail",
                "bus",
                "station",
                "fare",
                "passenger-information",
                "operations-control",
            }
        },
        counts=(
            "agencies_evaluated",
            "services_evaluated",
            "scenarios_replayed",
        ),
        required_true=(
            "agency_mode_route_service_safety_it_ot_supplier_and_owner_bound",
            "csf_current_target_outcome_tolerance_dependency_and_risk_trace_verified",
            "detection_dispatch_manual_operation_passenger_communication_and_continuity_verified",
            "account_fare_telemetry_command_ransomware_communications_and_supplier_cases_replayed",
            "safety_degraded_operation_restoration_and_state_reconciliation_verified",
            "independent_transit_review_lessons_and_profile_reassessment_verified",
        ),
        required_false=(
            "production_transit_system_connected_or_moved",
            "nist_or_transit_certification_claimed",
        ),
    )


def _validate_emergency_incident_coordination(
    claims: dict[str, Any], execution: dict[str, Any]
) -> None:
    del execution
    _validate_strict_domain_claims(
        claims,
        scalars={"incident_baseline": "ISO-22320-2018"},
        sets={
            "coordination_domains": {
                "command",
                "information",
                "decisions",
                "resources",
                "communications",
                "handoff-recovery",
            }
        },
        counts=(
            "organizations_evaluated",
            "decisions_evaluated",
            "injects_replayed",
        ),
        required_true=(
            "incident_objective_command_role_authority_action_handoff_and_owner_bound",
            "information_source_time_confidence_classification_correction_and_audit_verified",
            "common_operating_picture_communications_resource_and_safety_coordination_verified",
            "authority_conflict_false_report_loss_mismatch_contention_and_privacy_cases_replayed",
            "transfer_demobilization_recovery_after_action_and_corrective_action_verified",
            "independent_observer_timing_traceability_and_reassessment_verified",
        ),
        required_false=(
            "live_emergency_service_disrupted",
            "iso_certification_claimed",
        ),
    )


def _validate_gas_scada_cryptography(
    claims: dict[str, Any], execution: dict[str, Any]
) -> None:
    del execution
    _validate_strict_domain_claims(
        claims,
        scalars={"gas_scada_baseline": "AGA12-P1-API1164-IEC62351"},
        sets={
            "channel_domains": {
                "control-center",
                "field-site",
                "telemetry",
                "command",
                "key-management",
                "manual-control",
            }
        },
        counts=(
            "sites_evaluated",
            "channels_evaluated",
            "protocol_cases_replayed",
        ),
        required_true=(
            "endpoint_channel_protocol_message_key_clock_exception_and_owner_bound",
            "origin_integrity_confidentiality_replay_sequence_and_time_controls_verified",
            "key_establishment_rollover_loss_revocation_and_legacy_coexistence_verified",
            "forgery_reorder_delay_downgrade_substitution_clock_and_partition_cases_replayed",
            "latency_availability_manual_control_monitoring_restoration_and_reconciliation_verified",
            "independent_pipeline_crypto_review_residue_and_key_destruction_verified",
        ),
        required_false=(
            "production_pipeline_connected_or_actuated",
            "aga_api_or_iec_certification_claimed",
        ),
    )


def _validate_water_ot_research_corpus(
    claims: dict[str, Any], execution: dict[str, Any]
) -> None:
    del execution
    _validate_strict_domain_claims(
        claims,
        scalars={"corpus_baseline": "SWAT-WADI-BATADAL-RESEARCH"},
        sets={
            "datasets": {"SWaT", "WADI", "BATADAL"},
            "holdouts": {
                "temporal",
                "facility",
                "attack-family",
                "clean-control",
                "process-physics",
            },
        },
        counts=(
            "records_evaluated",
            "attack_windows_evaluated",
            "repeated_trials",
        ),
        required_true=(
            "release_license_digest_acquisition_chain_and_citation_bound",
            "facility_process_sensor_actuator_attack_window_label_and_time_bound",
            "duplicate_near_duplicate_training_overlap_and_contamination_measured",
            "missingness_drift_label_quality_process_fidelity_and_uncertainty_measured",
            "protected_holdout_detection_latency_false_positive_and_generalization_reproduced",
            "independent_label_audit_confidence_intervals_and_limitations_reported",
        ),
        required_false=(
            "production_water_system_connected",
            "compliance_operational_safety_or_product_claimed",
        ),
    )


def _resilience_validator(
    identifier: str,
) -> Callable[[dict[str, Any], dict[str, Any]], None]:
    contract = RESILIENCE_EVIDENCE_CONTRACTS[identifier]

    def validate(claims: dict[str, Any], execution: dict[str, Any]) -> None:
        del execution
        _validate_strict_domain_claims(
            claims,
            scalars=cast(dict[str, str], contract["scalars"]),
            sets=cast(dict[str, set[str]], contract["sets"]),
            counts=cast(tuple[str, ...], contract["counts"]),
            required_true=cast(tuple[str, ...], contract["required_true"]),
            required_false=cast(tuple[str, ...], contract["required_false"]),
        )

    return validate


def _interoperability_sector_validator(
    identifier: str,
) -> Callable[[dict[str, Any], dict[str, Any]], None]:
    contract = INTEROPERABILITY_SECTOR_EVIDENCE_CONTRACTS[identifier]

    def validate(claims: dict[str, Any], execution: dict[str, Any]) -> None:
        del execution
        _validate_strict_domain_claims(
            claims,
            scalars=cast(dict[str, str], contract["scalars"]),
            sets=cast(dict[str, set[str]], contract["sets"]),
            counts=cast(tuple[str, ...], contract["counts"]),
            required_true=cast(tuple[str, ...], contract["required_true"]),
            required_false=cast(tuple[str, ...], contract["required_false"]),
        )

    return validate


def _maturity_product_validator(
    identifier: str,
) -> Callable[[dict[str, Any], dict[str, Any]], None]:
    contract = MATURITY_PRODUCT_EVIDENCE_CONTRACTS[identifier]

    def validate(claims: dict[str, Any], execution: dict[str, Any]) -> None:
        del execution
        _validate_strict_domain_claims(
            claims,
            scalars=cast(dict[str, str], contract["scalars"]),
            sets=cast(dict[str, set[str]], contract["sets"]),
            counts=cast(tuple[str, ...], contract["counts"]),
            required_true=cast(tuple[str, ...], contract["required_true"]),
            required_false=cast(tuple[str, ...], contract["required_false"]),
        )

    return validate


def _emerging_assurance_validator(
    identifier: str,
) -> Callable[[dict[str, Any], dict[str, Any]], None]:
    contract = EMERGING_ASSURANCE_EVIDENCE_CONTRACTS[identifier]

    def validate(claims: dict[str, Any], execution: dict[str, Any]) -> None:
        del execution
        _validate_strict_domain_claims(
            claims,
            scalars=cast(dict[str, str], contract["scalars"]),
            sets=cast(dict[str, set[str]], contract["sets"]),
            counts=cast(tuple[str, ...], contract["counts"]),
            required_true=cast(tuple[str, ...], contract["required_true"]),
            required_false=cast(tuple[str, ...], contract["required_false"]),
        )

    return validate


_CLAIM_VALIDATORS: dict[str, Callable[[dict[str, Any], dict[str, Any]], None]] = {
    "oss-crs-crsbench": _validate_crsbench,
    "openssf-security-insights-conformance": _validate_security_insights,
    "guac-interoperability": _validate_guac,
    "gittuf-source-policy-conformance": _validate_gittuf,
    "openssf-package-analysis-malicious-packages": _validate_package_analysis,
    "owasp-kubernetes-top10-conformance": _validate_kubernetes,
    "owasp-cicd-top10-conformance": _validate_cicd,
    "sbomit-build-observed-sbom": _validate_sbomit,
    "primevul-real-world-vulnerability-detection": _validate_primevul,
    "diversevul-unseen-project-generalization": _validate_diversevul,
    "cvefixes-chronological-fix-pair-validation": _validate_cvefixes,
    "reposvul-repository-context-validation": _validate_reposvul,
    "vuleval-repository-dependency-evaluation": _validate_vuleval,
    "owasp-mobile-top10-conformance": _validate_mobile,
    "owasp-smart-contract-top10-conformance": _validate_smart_contract,
    "cncf-cloud-native-security-controls-conformance": _validate_cncf_cloud_native,
    "mitre-emb3d-property-threat-conformance": _validate_emb3d,
    "owasp-business-logic-abuse-top10-conformance": _validate_business_logic,
    "cncf-supply-chain-best-practices-v2-conformance": _validate_cncf_supply_chain,
    "owasp-juice-shop": _validate_juice_shop,
    "owasp-webgoat": _validate_webgoat,
    "owasp-crapi": _validate_crapi,
    "owasp-api-security-testing-framework": _validate_astf,
    "google-fuzzbench": _validate_fuzzbench,
    "magma-ground-truth": _validate_magma,
    "oss-fuzz-clusterfuzzlite": _validate_oss_fuzz,
    "sbom-sca-holdout": _validate_sbom_build_truth,
    "architecture-quality-holdout": _validate_architecture_fitness,
    "epss-kev-temporal-backtest": _validate_temporal_backtest,
    "scim-lifecycle-security-conformance": _validate_scim_lifecycle,
    "openid-shared-signals-conformance": _validate_shared_signals,
    "authzen-authorization-api-conformance": _validate_authzen,
    "openid-federation-conformance": _validate_openid_federation,
    "nist-hpc-ai-infrastructure-assurance": _validate_hpc_ai_infrastructure,
    "iso-24760-identity-management-assurance": _validate_iso_24760,
    "iso-5259-6-data-quality-visualization": _validate_iso_5259_6,
    "medical-device-cybersecurity-assurance": _validate_medical_device,
    "autonomous-physical-ai-safety": _validate_physical_ai,
    "critical-c-cpp-coding-conformance": _validate_critical_cpp,
    "confidential-computing-attestation-conformance": _validate_confidential_computing,
    "vvsg-voting-system-assurance": _validate_vvsg,
    "critical-sector-safety-security-assurance": _validate_critical_sector,
    "stateful-smart-contract-security": _validate_stateful_smart_contract,
    "devsecops-test-maturity-longitudinal": _validate_devsecops_longitudinal,
    "detection-product-longitudinal-calibration": _validate_detection_longitudinal,
    "disa-stig-scap-conformance": _validate_stig_configuration,
    "iec-62443-patch-management-exercise": _validate_ot_patch_lifecycle,
    "do355-continuing-airworthiness-exercise": _validate_continuing_airworthiness,
    "swift-cscf-independent-assessment": _validate_swift_cscf_assessment,
    "ccsds-space-mission-link-security": _validate_ccsds_space_mission,
    "firmware-resilience-measured-boot": _validate_firmware_device_integrity,
    "cis-kubernetes-hardening-conformance": _validate_kubernetes_pss_admission,
    "pci-payment-acceptance-conformance": _validate_payment_end_to_end,
    "ecss-space-software-product-assurance": _validate_ecss_space_software,
    "regional-financial-technology-resilience-assurance": _validate_regional_financial_resilience,
    "secure-information-sharing-competence-assurance": _validate_information_sharing_competence,
    "semi-fab-equipment-cybersecurity-assurance": _validate_semiconductor_equipment,
    "api-1164-pipeline-control-resilience": _validate_pipeline_control,
    "gxp-part11-data-integrity-assurance": _validate_gxp_data_integrity,
    "fbi-cjis-security-policy-assurance": _validate_cjis_security,
    "automotive-spice-capability-assurance": _validate_automotive_spice,
    "iec-61511-sis-safety-security-assurance": _validate_iec61511_sis,
    "bacnet-secure-connect-assurance": _validate_bacnet_sc,
    "industrial-robotics-safety-security-assurance": _validate_industrial_robotics,
    "data-centre-facility-resilience-assurance": _validate_data_centre_resilience,
    "water-sector-cyber-resilience-assurance": _validate_water_sector_resilience,
    "public-safety-communications-assurance": _validate_public_safety_communications,
    "global-gxp-data-integrity-assurance": _validate_global_gxp_data_integrity,
    "transit-cybersecurity-resilience-assurance": _validate_transit_resilience,
    "emergency-incident-coordination-assurance": _validate_emergency_incident_coordination,
    "gas-scada-cryptographic-assurance": _validate_gas_scada_cryptography,
    "ot-water-research-corpus-calibration": _validate_water_ot_research_corpus,
    "nss-dod-authorization-assurance": _validate_nss_dod,
    "zero-trust-zig-microsegmentation-assurance": _validate_zero_trust_zig,
    "healthcare-operational-resilience-assurance": _validate_healthcare_operations,
    "aircraft-system-safety-development-assurance": _validate_aircraft_system_assurance,
    "ilac-laboratory-operating-assurance": _validate_ilac_laboratory,
    "maritime-operational-cyber-resilience-assurance": _validate_maritime_operations,
    "weakness-prioritization-temporal-calibration": _validate_weakness_temporal,
    "formal-methods-tool-disagreement-assurance": _validate_formal_disagreement,
    "process-supplier-assessor-outcome-calibration": _validate_process_supplier_outcomes,
    "incident-privacy-outcome-exercise-calibration": _validate_incident_privacy_outcomes,
    "spiffe-workload-identity-conformance": _validate_spiffe,
    "openssf-model-signing-conformance": _validate_model_signing,
    "cyclonedx-mlbom-conformance": _validate_mlbom,
    "uptane-ota-security-conformance": _validate_uptane,
    "darpa-aixcc-autonomous-vulnerability-remediation": _validate_aixcc,
    "openssf-criticality-score-calibration": _validate_criticality_score,
}

_CLAIM_VALIDATORS.update(
    {
        identifier: _resilience_validator(identifier)
        for identifier in RESILIENCE_BENCHMARK_IDS
    }
)
_CLAIM_VALIDATORS.update(
    {
        identifier: _interoperability_sector_validator(identifier)
        for identifier in INTEROPERABILITY_SECTOR_EVIDENCE_CONTRACTS
    }
)
_CLAIM_VALIDATORS.update(
    {
        identifier: _maturity_product_validator(identifier)
        for identifier in MATURITY_PRODUCT_EVIDENCE_CONTRACTS
    }
)
_CLAIM_VALIDATORS.update(
    {
        identifier: _emerging_assurance_validator(identifier)
        for identifier in EMERGING_ASSURANCE_EVIDENCE_CONTRACTS
    }
)

INDUSTRY_EXTENSION_BENCHMARKS = frozenset(_CLAIM_VALIDATORS)
REAL_WORLD_VULNERABILITY_BENCHMARKS = frozenset(
    {
        "primevul-real-world-vulnerability-detection",
        "diversevul-unseen-project-generalization",
        "cvefixes-chronological-fix-pair-validation",
        "reposvul-repository-context-validation",
        "vuleval-repository-dependency-evaluation",
    }
)
REPOSITORY_LEVEL_VULNERABILITY_BENCHMARKS = frozenset(
    {
        "reposvul-repository-context-validation",
        "vuleval-repository-dependency-evaluation",
    }
)
VULNERABLE_APPLICATION_BENCHMARKS = frozenset(
    {
        "owasp-juice-shop",
        "owasp-webgoat",
        "owasp-crapi",
        "owasp-api-security-testing-framework",
    }
)
FUZZING_EXTENSION_BENCHMARKS = frozenset(
    {"google-fuzzbench", "magma-ground-truth", "oss-fuzz-clusterfuzzlite"}
)
IDENTITY_EXTENSION_BENCHMARKS = frozenset(
    {
        "scim-lifecycle-security-conformance",
        "openid-shared-signals-conformance",
        "authzen-authorization-api-conformance",
        "openid-federation-conformance",
        "iso-24760-identity-management-assurance",
        "spiffe-workload-identity-conformance",
    }
)
AI_ARTIFACT_EXTENSION_BENCHMARKS = frozenset(
    {"openssf-model-signing-conformance", "cyclonedx-mlbom-conformance"}
)
HPC_EXTENSION_BENCHMARKS = frozenset({"nist-hpc-ai-infrastructure-assurance"})
AI_DATA_QUALITY_EXTENSION_BENCHMARKS = frozenset(
    {"iso-5259-6-data-quality-visualization"}
)
MEDICAL_EXTENSION_BENCHMARKS = frozenset({"medical-device-cybersecurity-assurance"})
PHYSICAL_AI_EXTENSION_BENCHMARKS = frozenset({"autonomous-physical-ai-safety"})
CRITICAL_CODE_EXTENSION_BENCHMARKS = frozenset({"critical-c-cpp-coding-conformance"})
ATTESTATION_EXTENSION_BENCHMARKS = frozenset(
    {"confidential-computing-attestation-conformance"}
)
VOTING_EXTENSION_BENCHMARKS = frozenset({"vvsg-voting-system-assurance"})
CRITICAL_SECTOR_EXTENSION_BENCHMARKS = frozenset(
    {"critical-sector-safety-security-assurance"}
)
SMART_CONTRACT_EXTENSION_BENCHMARKS = frozenset({"stateful-smart-contract-security"})
MATURITY_EXTENSION_BENCHMARKS = frozenset({"devsecops-test-maturity-longitudinal"})
DETECTION_EXTENSION_BENCHMARKS = frozenset(
    {"detection-product-longitudinal-calibration"}
)
RESEARCH_CORPUS_EXTENSION_BENCHMARKS = frozenset(
    {"ot-water-research-corpus-calibration"}
)
INTEROPERABILITY_SECTOR_EXTENSION_BENCHMARKS = frozenset(
    INTEROPERABILITY_SECTOR_EVIDENCE_CONTRACTS
)
MATURITY_PRODUCT_EXTENSION_BENCHMARKS = frozenset(MATURITY_PRODUCT_EVIDENCE_CONTRACTS)
EMERGING_ASSURANCE_EXTENSION_BENCHMARKS = frozenset(
    EMERGING_ASSURANCE_EVIDENCE_CONTRACTS
)
OPERATIONAL_GAP_EXTENSION_BENCHMARKS = frozenset(
    {
        "disa-stig-scap-conformance",
        "iec-62443-patch-management-exercise",
        "do355-continuing-airworthiness-exercise",
        "swift-cscf-independent-assessment",
        "ccsds-space-mission-link-security",
        "firmware-resilience-measured-boot",
        "cis-kubernetes-hardening-conformance",
        "pci-payment-acceptance-conformance",
        "ecss-space-software-product-assurance",
        "regional-financial-technology-resilience-assurance",
        "secure-information-sharing-competence-assurance",
        "semi-fab-equipment-cybersecurity-assurance",
        "api-1164-pipeline-control-resilience",
        "gxp-part11-data-integrity-assurance",
        "fbi-cjis-security-policy-assurance",
        "automotive-spice-capability-assurance",
        "iec-61511-sis-safety-security-assurance",
        "bacnet-secure-connect-assurance",
        "industrial-robotics-safety-security-assurance",
        "data-centre-facility-resilience-assurance",
        "water-sector-cyber-resilience-assurance",
        "public-safety-communications-assurance",
        "global-gxp-data-integrity-assurance",
        "transit-cybersecurity-resilience-assurance",
        "emergency-incident-coordination-assurance",
        "gas-scada-cryptographic-assurance",
        "nss-dod-authorization-assurance",
        "zero-trust-zig-microsegmentation-assurance",
        "healthcare-operational-resilience-assurance",
        "aircraft-system-safety-development-assurance",
        "ilac-laboratory-operating-assurance",
        "maritime-operational-cyber-resilience-assurance",
        "weakness-prioritization-temporal-calibration",
        "formal-methods-tool-disagreement-assurance",
        "process-supplier-assessor-outcome-calibration",
        "incident-privacy-outcome-exercise-calibration",
        "cbest-threat-led-assurance",
        "ocp-safe-hardware-firmware-assurance",
    }
)
RESILIENCE_EXTENSION_BENCHMARKS = RESILIENCE_BENCHMARK_IDS


def industry_extension_runner_requirements(identifier: str) -> tuple[str, ...]:
    """Return extra runner evidence required by an extension benchmark."""

    if identifier not in INDUSTRY_EXTENSION_BENCHMARKS:
        return ()
    requirements: tuple[str, ...] = (
        "suite-owned-extension-evidence",
        "extension-source-and-subject-binding",
        "extension-independent-replay",
        "extension-domain-negative-cases",
    )
    if identifier in REAL_WORLD_VULNERABILITY_BENCHMARKS:
        requirements += (
            "independent-label-audit-report",
            "exact-and-near-duplicate-report",
            "project-and-chronological-split-manifest",
            "training-overlap-assessment",
            "independent-fix-replay-report",
        )
    if identifier in REPOSITORY_LEVEL_VULNERABILITY_BENCHMARKS:
        requirements += (
            "repository-snapshot-manifest",
            "dependency-context-oracle",
            "tangled-patch-audit",
            "multi-granularity-label-map",
        )
    if identifier in VULNERABLE_APPLICATION_BENCHMARKS:
        requirements += (
            "target-release-and-image-manifest",
            "target-label-authority-map",
            "clean-control-corpus",
            "deterministic-target-reset",
            "external-egress-transcript",
        )
    if identifier in FUZZING_EXTENSION_BENCHMARKS:
        requirements += (
            "repeated-trial-raw-data",
            "equal-resource-manifest",
            "fuzzer-target-build-lock",
            "seed-and-dictionary-manifest",
            "statistical-analysis-report",
        )
    if identifier in IDENTITY_EXTENSION_BENCHMARKS:
        requirements += (
            "synthetic-identity-and-trust-domain-manifest",
            "authorization-and-subject-boundary-oracles",
            "rotation-revocation-replay-report",
            "no-certification-claim-policy",
        )
    if identifier in AI_ARTIFACT_EXTENSION_BENCHMARKS:
        requirements += (
            "model-artifact-and-metadata-manifest",
            "official-schema-and-vector-lock",
            "tamper-omission-and-roundtrip-report",
            "integrity-inventory-not-safety-claim-policy",
        )
    if identifier in HPC_EXTENSION_BENCHMARKS:
        requirements += (
            "hpc-reference-architecture-and-zone-inventory",
            "sp800-53b-moderate-overlay-tailoring-record",
            "sixty-control-applicability-and-odp-report",
            "scheduler-accelerator-storage-isolation-and-recovery-report",
            "sp800-239-draft-exclusion-and-no-certification-policy",
        )
    if identifier in AI_DATA_QUALITY_EXTENSION_BENCHMARKS:
        requirements += (
            "quality-measure-dataset-and-population-binding",
            "visualization-transformation-and-provenance-record",
            "uncertainty-missingness-accessibility-and-role-review",
            "misleading-presentation-mutation-report",
            "technical-report-guidance-only-claim-policy",
        )
    if identifier in MEDICAL_EXTENSION_BENCHMARKS:
        requirements += (
            "medical-device-clinical-context-and-hazard-map",
            "patient-safety-security-risk-and-capability-level-report",
            "sbom-legacy-patch-and-end-of-support-record",
            "synthetic-patient-and-no-regulatory-certification-policy",
        )
    if identifier in PHYSICAL_AI_EXTENSION_BENCHMARKS:
        requirements += (
            "operational-design-domain-and-hazard-manifest",
            "deterministic-scenario-and-simulator-lock",
            "degradation-fallback-and-safe-state-report",
            "no-real-world-actuation-and-no-certification-policy",
        )
    if identifier in CRITICAL_CODE_EXTENSION_BENCHMARKS:
        requirements += (
            "licensed-rule-edition-and-digest-record",
            "compiler-language-target-and-optimization-matrix",
            "positive-negative-ambiguous-and-sanitizer-report",
            "deviation-adjudication-and-no-certification-policy",
        )
    if identifier in ATTESTATION_EXTENSION_BENCHMARKS:
        requirements += (
            "attester-verifier-relying-party-and-trust-root-manifest",
            "endorsement-reference-value-tcb-and-revocation-record",
            "cross-vendor-negative-evidence-corpus",
            "synthetic-secret-and-no-hardware-certification-policy",
        )
    if identifier in VOTING_EXTENSION_BENCHMARKS:
        requirements += (
            "vvsg-applicability-and-test-assertion-matrix",
            "synthetic-election-ballot-and-role-manifest",
            "software-independence-accessibility-and-recovery-report",
            "no-real-ballot-and-no-eac-certification-policy",
        )
    if identifier in CRITICAL_SECTOR_EXTENSION_BENCHMARKS:
        requirements += (
            "sector-applicability-and-licensed-criteria-record",
            "essential-function-hazard-zone-and-conduit-map",
            "digital-twin-failure-degraded-mode-and-recovery-report",
            "no-production-actuation-and-no-sector-certification-policy",
        )
    if identifier in SMART_CONTRACT_EXTENSION_BENCHMARKS:
        requirements += (
            "source-compiler-bytecode-deployment-and-chain-manifest",
            "state-economic-invariant-and-exploit-oracle-map",
            "multi-transaction-clean-control-and-fix-replay-report",
            "alpha-scsvs-exclusion-and-no-real-asset-policy",
        )
    if identifier in MATURITY_EXTENSION_BENCHMARKS:
        requirements += (
            "organization-product-team-period-and-model-scope",
            "immutable-delivery-event-and-outcome-ledger",
            "blinded-assessor-agreement-and-adjudication-report",
            "licensed-content-privacy-anti-gaming-and-no-certification-policy",
        )
    if identifier in DETECTION_EXTENSION_BENCHMARKS:
        requirements += (
            "product-policy-sensor-content-environment-and-time-manifest",
            "independent-step-ground-truth-and-benign-workload-corpus",
            "evasion-false-positive-latency-and-drift-report",
            "inert-payload-restoration-and-no-vendor-endorsement-policy",
        )
    if identifier in RESEARCH_CORPUS_EXTENSION_BENCHMARKS:
        requirements += (
            "license-source-digest-and-acquisition-chain",
            "independent-label-duplicate-and-contamination-audit",
            "temporal-facility-attack-family-clean-and-physics-holdouts",
            "repeated-trial-confidence-generalization-and-drift-report",
            "research-only-no-compliance-safety-or-product-claim-policy",
        )
    if identifier in INTEROPERABILITY_SECTOR_EXTENSION_BENCHMARKS:
        requirements += (
            "normative-or-policy-pinned-source-and-license-lock",
            "subject-identity-scope-and-applicability-map",
            "positive-negative-conflict-and-loss-or-failure-report",
            "independent-adjudication-remediation-and-replay-ledger",
            "no-equivalence-certification-supervisory-or-product-claim-policy",
        )
    if identifier in MATURITY_PRODUCT_EXTENSION_BENCHMARKS:
        requirements += (
            "publisher-version-license-and-source-digest-lock",
            "subject-scope-applicability-owner-and-responsibility-map",
            "positive-negative-disagreement-drift-and-change-report",
            "independent-assessment-adjudication-remediation-and-retest-ledger",
            "no-endorsement-accreditation-certification-or-legal-compliance-claim-policy",
        )
    if identifier in EMERGING_ASSURANCE_EXTENSION_BENCHMARKS:
        requirements += (
            "publisher-edition-license-and-source-digest-lock",
            "subject-profile-scope-applicability-and-authority-map",
            "positive-negative-manual-disagreement-drift-and-change-report",
            "independent-replay-remediation-cleanup-restoration-and-retest-ledger",
            "no-provider-scheme-product-safety-certification-or-compliance-claim-policy",
        )
    if identifier in RESILIENCE_EXTENSION_BENCHMARKS:
        requirements += (
            "normative-edition-applicability-and-license-lock",
            "domain-asset-dependency-owner-and-decision-map",
            "positive-negative-clean-control-and-failure-injection-report",
            "independent-replay-adjudication-recovery-and-retest-ledger",
            "production-isolation-and-no-certification-claim-policy",
        )
    if identifier == "uptane-ota-security-conformance":
        requirements += (
            "simulated-fleet-and-ecu-capability-manifest",
            "repository-role-key-threshold-and-pouf-map",
            "rollback-freeze-mixmatch-and-recovery-report",
            "no-real-vehicle-and-no-certification-policy",
        )
    if identifier == "darpa-aixcc-autonomous-vulnerability-remediation":
        requirements += (
            "immutable-corpus-and-scoring-pipeline-manifest",
            "license-training-overlap-and-contamination-report",
            "protected-challenge-split-and-resource-budget",
            "independent-pov-patch-and-functional-replay",
            "real-versus-synthetic-confidence-report",
        )
    if identifier == "openssf-criticality-score-calibration":
        requirements += (
            "raw-signal-provenance-and-freshness-snapshots",
            "algorithm-reproduction-and-sensitivity-report",
            "missing-stale-alias-and-outlier-report",
            "context-only-calibration-policy",
        )
    if identifier == "sbom-sca-holdout":
        requirements += (
            "resolver-and-build-truth-map",
            "installed-artifact-observation",
            "container-layer-observation",
            "ecosystem-project-time-split-manifest",
        )
    if identifier == "architecture-quality-holdout":
        requirements += (
            "architecture-rule-manifest",
            "change-and-ownership-history",
            "architecture-mutation-corpus",
            "independent-label-adjudication",
        )
    if identifier == "epss-kev-temporal-backtest":
        requirements += (
            "dated-snapshot-manifest",
            "future-data-exclusion-report",
            "cve-alias-reconciliation",
            "outcome-window-and-censoring-report",
        )
    if identifier in OPERATIONAL_GAP_EXTENSION_BENCHMARKS:
        requirements += (
            "applicability-and-authority-boundary-record",
            "versioned-source-criteria-and-fixture-lock",
            "independent-ground-truth-or-assessor-review",
            "domain-specific-adverse-case-report",
            "longitudinal-or-recovery-outcome-record",
            "no-accreditation-authorization-certification-or-compliance-claim-policy",
        )
    return requirements


def industry_extension_score_evidence_valid(value: object, identifier: str) -> bool:
    """Validate the extension envelope embedded in a benchmark score artifact."""

    if identifier not in INDUSTRY_EXTENSION_BENCHMARKS:
        return True
    if not isinstance(value, dict):
        return False
    corpus = value.get("corpus")
    execution = value.get("execution_context")
    source_digest = corpus.get("sha256") if isinstance(corpus, dict) else None
    subject_digest = (
        execution.get("target_sha256") if isinstance(execution, dict) else None
    )
    try:
        validate_industry_extension_evidence_document(
            value.get("extension_evidence"),
            expected_source_sha256=str(source_digest or ""),
            expected_subject_sha256=str(subject_digest or ""),
        )
    except IndustryExtensionEvidenceError:
        return False
    return True
