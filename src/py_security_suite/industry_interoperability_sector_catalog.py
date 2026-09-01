from __future__ import annotations

from typing import Any


INTEROPERABILITY_SECTOR_STANDARDS: tuple[dict[str, Any], ...] = (
    {
        "id": "OWASP-OPENCRE",
        "version": "2026-08-31-graph-policy-pinned",
        "kind": "common-security-requirement-enumeration-and-crosswalk",
        "reference": "https://github.com/OWASP/OpenCRE",
        "evidence": [
            "standards-crosswalk.json",
            "security-requirements-coverage.json",
        ],
        "lifecycle": {
            "edition_status": "policy-pinned",
            "published": "2026-08-31",
            "observed_at": "2026-08-31",
        },
    },
    {
        "id": "OPENSSF-GEMARA",
        "version": "2026-08-31-schema-policy-pinned",
        "kind": "machine-readable-grc-control-and-evidence-model",
        "reference": "https://github.com/gemaraproj/gemara",
        "evidence": [
            "standards-crosswalk.json",
            "oscal-assessment-results.json",
            "audit-package-verification.json",
        ],
        "lifecycle": {
            "edition_status": "policy-pinned",
            "published": "2026-08-31",
            "observed_at": "2026-08-31",
        },
    },
    {
        "id": "UK-CBEST",
        "version": "implementation-guide-2024",
        "kind": "uk-financial-threat-intelligence-led-assessment",
        "reference": "https://www.bankofengland.co.uk/financial-stability/operational-resilience-of-the-financial-sector/cbest-threat-intelligence-led-assessments-implementation-guide",
        "evidence": [
            "adversarial-campaign.json",
            "external-conformity-assessment.json",
            "control-assessment.json",
            "operational-trend.json",
        ],
        "lifecycle": {
            "edition_status": "final",
            "published": "2024",
            "observed_at": "2026-08-31",
        },
    },
    {
        "id": "OCP-SAFE",
        "version": "2026-08-31-policy-pinned",
        "kind": "third-party-hardware-firmware-security-appraisal-framework",
        "reference": "https://github.com/opencomputeproject/OCP-Security-SAFE",
        "evidence": [
            "trust-policy-attestation.json",
            "domain-assurance.json",
            "audit-package-verification.json",
        ],
        "lifecycle": {
            "edition_status": "policy-pinned",
            "published": "2026-08-31",
            "observed_at": "2026-08-31",
        },
    },
    {
        "id": "OCP-SOLID",
        "version": "1.0-2026-01-27",
        "kind": "open-compute-hardware-security-requirements",
        "reference": "https://github.com/opencomputeproject/OCP-Security-SOLID/blob/main/requirements.md",
        "evidence": [
            "trust-policy-attestation.json",
            "domain-assurance.json",
            "software-supply-chain.json",
        ],
        "lifecycle": {
            "edition_status": "final",
            "published": "2026-01-27",
            "observed_at": "2026-08-31",
        },
    },
)


INTEROPERABILITY_SECTOR_PROFILES: dict[str, dict[str, Any]] = {
    "control-knowledge-interoperability": {
        "standards": ["OWASP-OPENCRE", "OPENSSF-GEMARA", "NIST-OSCAL"],
        "controls": [
            (
                "OWASP-OPENCRE",
                "OPENCRE-IDENTITY-MAPPING-PROVENANCE-AND-DRIFT",
                "Bind every imported CRE, standard, section, requirement, relationship, source revision and mapping assertion to immutable provenance; reject dangling, duplicate, cyclic, stale and ambiguous mappings rather than silently treating semantic similarity as equivalence.",
                ["standards-crosswalk.json", "audit-package-verification.json"],
            ),
            (
                "OPENSSF-GEMARA",
                "GEMARA-CONTROL-EVIDENCE-AND-OSCAL-SEMANTIC-PRESERVATION",
                "Preserve control, threat, implementation, assessment, evidence, responsibility, applicability and status semantics across Gemara and OSCAL import and export, with explicit loss reports for concepts that cannot be represented exactly.",
                ["standards-crosswalk.json", "oscal-assessment-results.json"],
            ),
        ],
        "procedures": [
            (
                "OPENSSF-GEMARA",
                "OPENCRE-GEMARA-OSCAL-ROUNDTRIP-AND-CONFLICT-CONFORMANCE",
                "Replay signed graph and schema snapshots through OpenCRE, Gemara and OSCAL transformations; inject unknown versions, identifier collisions, many-to-one mappings, contradictory applicability, evidence misbinding and lossy round trips; require deterministic conflict quarantine and independent semantic adjudication.",
                "automated",
                True,
                ["benchmark-scorecard.json", "standards-crosswalk.json"],
            )
        ],
    },
    "uk-financial-cbest-assurance": {
        "standards": [
            "UK-CBEST",
            "TIBER-EU",
            "EU-DORA-RTS-TLPT",
            "CREST-PENETRATION-TESTING-GUIDE",
        ],
        "controls": [
            (
                "UK-CBEST",
                "CBEST-SCOPE-GOVERNANCE-INTELLIGENCE-AND-PRODUCTION-SAFETY",
                "Bind the regulated entity, important business services, critical functions, systems, third parties, threat-intelligence provider, red-team provider, control group, test manager, objectives, exclusions, risk decisions, legal authority, kill switches and restoration responsibilities before execution.",
                ["adversarial-campaign.json", "control-assessment.json"],
            ),
            (
                "UK-CBEST",
                "CBEST-DETECTION-RESPONSE-REMEDIATION-AND-CLOSURE",
                "Trace each threat scenario and attack action to prevention, visibility, detection, escalation, response, business impact, cleanup, remediation ownership, retest and closure evidence while separating framework alignment from supervisory approval.",
                ["operational-trend.json", "audit-package-verification.json"],
            ),
        ],
        "procedures": [
            (
                "UK-CBEST",
                "CBEST-THREAT-LED-ENGAGEMENT-AND-REMEDIATION-REPLAY",
                "Conduct only an explicitly authorized, production-safe assessment using approved threat intelligence, representative privileged-insider and supply-chain scenarios, real-time control-group oversight, emergency stops, restoration checks and independent remediation retest; use a digital twin when production authorization is absent.",
                "dynamic",
                True,
                ["benchmark-scorecard.json", "adversarial-campaign.json"],
            )
        ],
    },
    "ocp-safe-hardware-firmware-assurance": {
        "standards": [
            "OCP-SAFE",
            "OCP-SOLID",
            "NIST-SP-800-193",
            "TCG-TPM-2.0",
        ],
        "controls": [
            (
                "OCP-SAFE",
                "OCP-SAFE-LAB-SCOPE-INDEPENDENCE-AND-REPORT-PROVENANCE",
                "Bind product, board, silicon, immutable and mutable firmware, source revision, build, debug and management interfaces, appraisal objectives, review provider competence and independence, exclusions, findings, report digest, disclosure limits, remediation and retest to the exact delivered configuration.",
                ["domain-assurance.json", "audit-package-verification.json"],
            ),
            (
                "OCP-SOLID",
                "OCP-HARDWARE-ROOT-OF-TRUST-UPDATE-DEBUG-PHYSICAL-AND-SUPPLY-CHAIN",
                "Verify secure and measured boot, authenticated update, rollback resistance, key and entropy handling, debug lockdown, physical interfaces, exploit mitigations, SBOM and dependency maintenance, vulnerability handling, recovery and production configuration without converting an appraisal into a certification claim.",
                ["trust-policy-attestation.json", "software-supply-chain.json"],
            ),
        ],
        "procedures": [
            (
                "OCP-SAFE",
                "OCP-SAFE-SOURCE-FIRMWARE-AND-PHYSICAL-FAULT-APPRAISAL",
                "In a residue-controlled laboratory, independently review source and design and replay signed-image substitution, rollback, recovery interruption, debug unlock, key extraction attempts, bus and storage tamper, malformed update, dependency compromise and known-good restoration against production-equivalent hardware.",
                "dynamic",
                True,
                ["benchmark-scorecard.json", "domain-assurance.json"],
            )
        ],
    },
}


INTEROPERABILITY_SECTOR_BENCHMARKS: tuple[dict[str, Any], ...] = (
    {
        "id": "opencre-gemara-control-interoperability",
        "version": "opencre-gemara-oscal-2026-08-31-policy-pinned",
        "kind": "control-knowledge-graph-schema-provenance-conflict-and-roundtrip-conformance",
        "source": "Immutable OWASP OpenCRE graph, OpenSSF Gemara schemas and NIST OSCAL 1.2.2 fixtures with organization-owned mapping conflicts, loss cases and semantic oracles",
        "languages": ["opencre", "gemara", "oscal", "json", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "cbest-threat-led-assurance",
        "version": "cbest-implementation-guide-2024-policy-pinned",
        "kind": "uk-financial-threat-intelligence-led-production-safety-detection-and-remediation-assurance",
        "source": "Bank of England CBEST Implementation Guide 2024 with legally approved synthetic or authorized engagement scope, threat intelligence, control-group, detection, restoration and remediation fixtures",
        "languages": [
            "financial",
            "threat-intelligence",
            "red-team",
            "resilience",
            "multi",
        ],
        "lane": "authorized-companion",
    },
    {
        "id": "ocp-safe-hardware-firmware-assurance",
        "version": "ocp-safe-2026-08-31-solid-1.0-policy-pinned",
        "kind": "independent-hardware-firmware-source-physical-interface-and-recovery-appraisal",
        "source": "Policy-pinned OCP S.A.F.E. review scope and OCP SOLID 1.0 requirements with approved production-equivalent hardware, source, firmware, fault, tamper and recovery fixtures",
        "languages": ["hardware", "firmware", "source", "supply-chain", "multi"],
        "lane": "authorized-companion",
    },
)

INTEROPERABILITY_FORMATS: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    ("OpenCRE", "2026-08-31-policy-pinned", ("standards-crosswalk.json",)),
    (
        "Gemara",
        "2026-08-31-schema-policy-pinned",
        ("standards-crosswalk.json", "oscal-assessment-results.json"),
    ),
)

INTEROPERABILITY_SECTOR_BENCHMARK_PROTOCOLS = {
    "opencre-gemara-control-interoperability": "conformance",
    "cbest-threat-led-assurance": "detection-evaluation",
    "ocp-safe-hardware-firmware-assurance": "conformance",
}

INTEROPERABILITY_SECTOR_LABORATORY_BENCHMARKS = frozenset(
    {"cbest-threat-led-assurance", "ocp-safe-hardware-firmware-assurance"}
)


_COMMON_ACQUISITION: dict[str, bool] = {
    "immutable_revision_required": True,
    "corpus_digest_required": True,
    "license_digest_required": True,
    "label_authority_digest_required": True,
    "golden_positive_required": True,
    "golden_negative_required": True,
    "signed_provenance_required": True,
    "replay_ledger_required": True,
}


INTEROPERABILITY_SECTOR_ADAPTER_SPECS: tuple[dict[str, Any], ...] = (
    {
        "benchmark_id": "opencre-gemara-control-interoperability",
        "protocol": "conformance",
        "upstream": "https://github.com/OWASP/OpenCRE and https://github.com/gemaraproj/gemara",
        "acquisition": {
            **_COMMON_ACQUISITION,
            "license": "upstream-data-schema-and-content-specific",
        },
        "normalizer": "opencre-gemara-oscal-semantic-roundtrip-v1",
        "required_inputs": [
            "opencre-graph-snapshot",
            "gemara-schema-snapshot",
            "oscal-schema-snapshot",
            "mapping-and-conflict-fixtures",
            "semantic-ground-truth",
        ],
        "isolation": "read-only no-egress mapping workspace with immutable snapshots, protected semantic oracles, deterministic reset and no equivalence claim for unadjudicated mappings",
    },
    {
        "benchmark_id": "cbest-threat-led-assurance",
        "protocol": "detection-evaluation",
        "upstream": "https://www.bankofengland.co.uk/financial-stability/operational-resilience-of-the-financial-sector/cbest-threat-intelligence-led-assessments-implementation-guide",
        "acquisition": {
            **_COMMON_ACQUISITION,
            "license": "publisher-guidance-engagement-and-evidence-specific",
        },
        "normalizer": "cbest-objective-detection-response-remediation-v1",
        "required_inputs": [
            "legal-authority-and-approved-scope",
            "threat-intelligence-and-scenario-plan",
            "control-group-kill-switch-and-restoration-plan",
            "detection-response-and-business-impact-evidence",
            "remediation-retest-and-closure-record",
        ],
        "isolation": "separately authorized production-safe engagement or no-egress financial-service twin with control-group oversight, emergency stops, deterministic restoration, no regulator connectivity and no CBEST completion or supervisory approval claim",
    },
    {
        "benchmark_id": "ocp-safe-hardware-firmware-assurance",
        "protocol": "conformance",
        "upstream": "https://github.com/opencomputeproject/OCP-Security-SAFE",
        "acquisition": {
            **_COMMON_ACQUISITION,
            "license": "upstream-framework-product-source-firmware-and-laboratory-specific",
        },
        "normalizer": "ocp-safe-source-firmware-physical-appraisal-v1",
        "required_inputs": [
            "product-source-firmware-and-build-manifest",
            "review-scope-provider-competence-and-independence",
            "hardware-root-of-trust-debug-and-interface-map",
            "fault-tamper-update-and-recovery-fixtures",
            "findings-remediation-retest-and-report-provenance",
        ],
        "isolation": "no-egress residue-controlled hardware laboratory with synthetic keys, production-equivalent sacrificial devices, bounded fault injection, independent observer, deterministic recovery and no OCP recognition, certification or product-security claim",
    },
)


INTEROPERABILITY_SECTOR_EVIDENCE_CONTRACTS: dict[str, dict[str, Any]] = {
    "opencre-gemara-control-interoperability": {
        "scalars": {"baseline": "OPENCRE-GEMARA-OSCAL-2026-08-31"},
        "sets": {
            "representations": {"opencre", "gemara", "oscal"},
            "semantic_surfaces": {
                "requirements",
                "controls",
                "threats",
                "evidence",
                "applicability",
                "responsibility",
            },
        },
        "counts": (
            "nodes_evaluated",
            "mappings_evaluated",
            "conflict_cases_replayed",
        ),
        "required_true": (
            "source_revision_schema_license_and_digest_bound",
            "identifier_referential_integrity_and_dangling_links_verified",
            "mapping_provenance_direction_confidence_and_review_preserved",
            "many_to_one_conflict_cycle_and_contradiction_quarantined",
            "roundtrip_semantic_equivalence_and_loss_report_verified",
            "independent_mapping_adjudication_and_drift_replay_completed",
        ),
        "required_false": (
            "network_floating_source_used",
            "unreviewed_mapping_treated_as_equivalent",
        ),
    },
    "cbest-threat-led-assurance": {
        "scalars": {"framework": "CBEST-IMPLEMENTATION-GUIDE-2024"},
        "sets": {
            "phases": {
                "initiation",
                "threat-intelligence",
                "red-teaming",
                "reporting",
                "remediation",
                "closure",
            },
            "scenario_classes": {
                "external",
                "privileged-insider",
                "supply-chain",
            },
        },
        "counts": (
            "important_services_evaluated",
            "attack_actions_replayed",
            "remediations_retested",
        ),
        "required_true": (
            "entity_service_scope_authority_provider_and_test_manager_bound",
            "threat_intelligence_scenario_objective_and_targeting_approved",
            "control_group_kill_switch_production_safety_and_restoration_verified",
            "prevention_visibility_detection_response_and_impact_timeline_reproduced",
            "cleanup_remediation_ownership_retest_and_closure_verified",
            "independent_review_and_framework_claim_boundary_verified",
        ),
        "required_false": (
            "production_activity_executed_without_explicit_authority",
            "supervisory_approval_or_cbest_completion_claimed",
        ),
    },
    "ocp-safe-hardware-firmware-assurance": {
        "scalars": {"criteria": "OCP-SAFE-2026-08-31-SOLID-1.0"},
        "sets": {
            "surfaces": {
                "source",
                "immutable-firmware",
                "mutable-firmware",
                "debug",
                "physical-interfaces",
                "supply-chain",
            },
            "fault_classes": {
                "signature-substitution",
                "rollback",
                "debug-unlock",
                "bus-or-storage-tamper",
                "update-interruption",
                "recovery",
            },
        },
        "counts": (
            "products_evaluated",
            "components_evaluated",
            "fault_cases_replayed",
        ),
        "required_true": (
            "product_revision_source_build_firmware_and_delivered_configuration_bound",
            "review_provider_competence_independence_scope_and_report_provenance_verified",
            "secure_measured_boot_update_rollback_key_entropy_and_debug_controls_verified",
            "physical_interface_exploit_mitigation_sbom_and_dependency_controls_verified",
            "fault_tamper_known_good_recovery_cleanup_and_residue_replayed",
            "findings_disclosure_remediation_retest_and_independent_closure_verified",
        ),
        "required_false": (
            "production_fleet_or_customer_device_mutated",
            "ocp_recognition_certification_or_vulnerability_free_claimed",
        ),
    },
}
