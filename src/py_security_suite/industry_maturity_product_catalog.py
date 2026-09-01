from __future__ import annotations

from typing import Any


MATURITY_PRODUCT_STANDARDS: tuple[dict[str, Any], ...] = (
    {
        "id": "DOE-C2M2",
        "version": "2.1-2022-06",
        "kind": "cybersecurity-capability-maturity-model",
        "reference": "https://www.energy.gov/ceser/cybersecurity-capability-maturity-model-c2m2",
        "evidence": [
            "maturity-model-assessment.json",
            "operational-trend.json",
            "closure-plan.json",
        ],
        "lifecycle": {
            "edition_status": "final",
            "published": "2022-06",
            "observed_at": "2026-08-31",
        },
    },
    {
        "id": "FINOS-CCC",
        "version": "core-v2025.10",
        "kind": "financial-services-common-cloud-controls",
        "reference": "https://ccc.finos.org/catalogs/core/core/",
        "evidence": [
            "control-assessment.json",
            "standards-crosswalk.json",
            "oscal-assessment-results.json",
        ],
        "lifecycle": {
            "edition_status": "policy-pinned",
            "published": "2025-10",
            "observed_at": "2026-08-31",
        },
    },
    {
        "id": "NCSC-CRT-APC",
        "version": "1.0-2025-04",
        "kind": "product-cyber-resilience-assurance-principles-and-claims",
        "reference": "https://www.ncsc.gov.uk/files/CRT-APC-v1-0.pdf",
        "evidence": [
            "structured-assurance-case.json",
            "domain-assurance.json",
            "risk-assessment.json",
        ],
        "lifecycle": {
            "edition_status": "final",
            "published": "2025-04",
            "observed_at": "2026-08-31",
        },
    },
    {
        "id": "NCSC-CRTF-SCHEME",
        "version": "1.1-2025-10",
        "kind": "cyber-resilience-test-facility-scheme-standard",
        "reference": "https://www.ncsc.gov.uk/schemes/cyber-resilience-test-facilities/documents",
        "evidence": [
            "external-conformity-assessment.json",
            "audit-package-verification.json",
            "evaluator-competence.json",
        ],
        "lifecycle": {
            "edition_status": "final",
            "published": "2025-10",
            "observed_at": "2026-08-31",
        },
    },
    {
        "id": "UK-SOFTWARE-SECURITY-CODE-OF-PRACTICE",
        "version": "1.0-2025-05-07",
        "kind": "software-vendor-security-and-resilience-code-of-practice",
        "reference": "https://www.gov.uk/government/publications/software-security-code-of-practice",
        "evidence": [
            "security-requirements-coverage.json",
            "software-supply-chain.json",
            "operational-trend.json",
        ],
        "lifecycle": {
            "edition_status": "final",
            "published": "2025-05-07",
            "observed_at": "2026-08-31",
        },
    },
    {
        "id": "NIST-PRAM",
        "version": "2021-04-23-policy-pinned",
        "kind": "privacy-risk-assessment-methodology",
        "reference": "https://www.nist.gov/privacy-framework/nist-pram",
        "evidence": [
            "risk-assessment.json",
            "data-exposure.json",
            "closure-plan.json",
        ],
        "lifecycle": {
            "edition_status": "policy-pinned",
            "published": "2021-04-23",
            "observed_at": "2026-08-31",
        },
    },
    {
        "id": "NIST-IR-8062",
        "version": "final-2017-01-04",
        "kind": "privacy-engineering-objectives-and-risk-model",
        "reference": "https://csrc.nist.gov/pubs/ir/8062/final",
        "evidence": ["risk-assessment.json", "data-exposure.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2017-01-04",
            "observed_at": "2026-08-31",
        },
    },
    {
        "id": "ITIL-4",
        "version": "licensed-policy-pinned-2026-08-31",
        "kind": "it-service-management-practice-framework",
        "reference": "https://www.peoplecert.org/Organizations/Certifications/ITIL-Corporate-Framework",
        "evidence": [
            "procedure-assessment.json",
            "operational-trend.json",
            "maturity-model-assessment.json",
        ],
        "lifecycle": {
            "edition_status": "policy-pinned",
            "published": "2026-08-31",
            "observed_at": "2026-08-31",
        },
    },
)


MATURITY_PRODUCT_PROFILES: dict[str, dict[str, Any]] = {
    "c2m2-capability-maturity": {
        "standards": ["DOE-C2M2", "NIST-CSF", "NIST-SP-800-82"],
        "controls": [
            (
                "DOE-C2M2",
                "C2M2-SCOPE-DOMAIN-OBJECTIVE-PRACTICE-AND-MATURITY-BINDING",
                "Bind the assessed organization, business and essential functions, IT and OT assets, dependencies, threat profile, ten C2M2 domains, objectives, practices, approach objectives, maturity-indicator levels, evidence period, participants and accountable decision owners to one immutable assessment scope.",
                ["maturity-model-assessment.json", "risk-assessment.json"],
            ),
            (
                "DOE-C2M2",
                "C2M2-EVIDENCE-GAP-INVESTMENT-OUTCOME-AND-REASSESSMENT",
                "Require practice-level evidence, disagreement and uncertainty records, prioritized capability gaps, risk and dependency traceability, funded improvement actions, outcome measures and repeat assessments without treating self-reported maturity as certification or control effectiveness.",
                ["operational-trend.json", "closure-plan.json"],
            ),
        ],
        "procedures": [
            (
                "DOE-C2M2",
                "C2M2-INDEPENDENT-SELF-EVALUATION-AND-IMPROVEMENT-REPLAY",
                "Replay a facilitated C2M2 2.1 evaluation against blinded evidence, inject missing and contradictory practice evidence, compare independent assessor ratings, challenge maturity inflation, verify prioritized investment decisions and repeat the assessment after corrective actions.",
                "test",
                True,
                ["benchmark-scorecard.json", "maturity-model-assessment.json"],
            )
        ],
    },
    "finos-common-cloud-controls": {
        "standards": ["FINOS-CCC", "NIST-OSCAL", "CSA-CCM", "ISO-IEC-27017"],
        "controls": [
            (
                "FINOS-CCC",
                "FINOS-CCC-CATALOG-IDENTITY-TAXONOMY-AND-APPLICABILITY",
                "Bind the Core and service-catalog releases, capability, threat, control and assessment-requirement identifiers, cloud service and deployment model, provider, region, tenant, responsibility allocation, regulatory mappings and applicability decisions to signed source and subject digests.",
                ["standards-crosswalk.json", "control-assessment.json"],
            ),
            (
                "FINOS-CCC",
                "FINOS-CCC-CONTROL-EVIDENCE-OSCAL-AND-CLOUD-DRIFT",
                "Preserve FINOS CCC control and threat semantics through OSCAL conversion, retain implementation and evidence ownership, verify automated and manual assessment requirements, reconcile provider-native findings, quarantine loss or conflicts and detect configuration and catalog drift.",
                ["oscal-assessment-results.json", "operational-trend.json"],
            ),
        ],
        "procedures": [
            (
                "FINOS-CCC",
                "FINOS-CCC-CROSS-CLOUD-CONTROL-AND-ASSESSMENT-CONFORMANCE",
                "Evaluate release-pinned Core and applicable service catalogs against isolated AWS, Azure, Google Cloud and private-cloud fixtures; inject identifier, responsibility, mapping and configuration mutations; independently replay assessment requirements and require explicit semantic-loss and exception records.",
                "automated",
                True,
                ["benchmark-scorecard.json", "oscal-assessment-results.json"],
            )
        ],
    },
    "ncsc-product-cyber-resilience-testing": {
        "standards": [
            "NCSC-CRT-APC",
            "NCSC-CRTF-SCHEME",
            "UK-SOFTWARE-SECURITY-CODE-OF-PRACTICE",
            "ISO-IEC-17020",
        ],
        "controls": [
            (
                "NCSC-CRT-APC",
                "NCSC-CRT-CONTEXT-PRINCIPLE-CLAIM-ARGUMENT-EVIDENCE-AND-RISK",
                "Bind product, version, configuration, deployment context, public and less-trusted interfaces, users, assets, commodity-threat assumptions, assurance principles, claims, argument trees, evidence, residual risks, vendor responses and customer-facing limitations to the assessed subject.",
                ["structured-assurance-case.json", "risk-assessment.json"],
            ),
            (
                "NCSC-CRTF-SCHEME",
                "NCSC-CRTF-INDEPENDENCE-COMPETENCE-TEST-SAFETY-AND-REPORTING",
                "Verify facility approval scope, ISO/IEC 17020 status, evaluator competence and independence, evidence custody, test authorization, safety controls, vulnerability disclosure, risk interpretation, report provenance, remediation and retest while separating suite readiness from NCSC assessment or approval.",
                [
                    "external-conformity-assessment.json",
                    "audit-package-verification.json",
                ],
            ),
        ],
        "procedures": [
            (
                "NCSC-CRT-APC",
                "NCSC-CRT-PUBLIC-INTERFACE-RESILIENCE-AND-CLAIM-CHALLENGE",
                "In a no-egress product laboratory, challenge each applicable claim using malformed, unauthorized, replayed, downgraded and resource-exhaustion interactions against public or less-trusted interfaces; preserve essential behavior, recover known-good state and independently adjudicate evidence gaps and residual risk.",
                "dynamic",
                True,
                ["benchmark-scorecard.json", "domain-assurance.json"],
            )
        ],
    },
    "nist-pram-privacy-risk-assessment": {
        "standards": [
            "NIST-PRAM",
            "NIST-PRIVACY-FRAMEWORK",
            "NIST-IR-8062",
            "ISO-IEC-29134",
        ],
        "controls": [
            (
                "NIST-PRAM",
                "PRAM-DATA-ACTION-PROBLEMATIC-DATA-ACTION-AND-INDIVIDUAL-IMPACT",
                "Bind system context, mission and business purpose, data actions, actors, individuals, data elements, processing and transfer flows, contextual factors, problematic data actions, affected populations and individual impacts to reviewed diagrams and evidence rather than generic compliance labels.",
                ["data-exposure.json", "risk-assessment.json"],
            ),
            (
                "NIST-PRAM",
                "PRAM-LIKELIHOOD-IMPACT-PRIORITIZATION-RESPONSE-AND-VALIDATION",
                "Apply documented likelihood and impact criteria, retain assumptions and uncertainty, prioritize privacy risks, trace responses to engineering changes, test effectiveness against representative and vulnerable populations and reassess after data, purpose, recipient or system changes.",
                ["risk-assessment.json", "closure-plan.json"],
            ),
        ],
        "procedures": [
            (
                "NIST-PRAM",
                "PRAM-PRIVACY-RISK-MODEL-AND-RESPONSE-EFFECTIVENESS-CHALLENGE",
                "Replay a complete PRAM assessment with missed-flow, inferred-data, secondary-use, recipient-expansion, reidentification, vulnerable-population and changed-context cases; require independent scoring agreement, calibrated uncertainty and verified response effectiveness without claiming legal compliance.",
                "test",
                True,
                ["benchmark-scorecard.json", "risk-assessment.json"],
            )
        ],
    },
    "itil4-service-management-alignment": {
        "standards": ["ITIL-4", "ISO-IEC-20000-1", "ISO-IEC-27013"],
        "controls": [
            (
                "ITIL-4",
                "ITIL4-LICENSED-PRACTICE-SCOPE-VALUE-STREAM-AND-OWNERSHIP",
                "Bind the licensed criteria snapshot, service and customer scope, value streams, practices, products, configurations, suppliers, responsibilities, risks, policies, controls, measures and records to ISO/IEC 20000-1 and security-management outcomes; preserve unmapped concepts and tailoring decisions.",
                ["procedure-assessment.json", "standards-crosswalk.json"],
            ),
            (
                "ITIL-4",
                "ITIL4-CHANGE-INCIDENT-PROBLEM-CONTINUITY-AND-IMPROVEMENT-OUTCOMES",
                "Trace changes, releases, events, incidents, problems, service continuity, information security, suppliers and continual-improvement actions to service and security outcomes, segregation of duties, approvals, restoration, reconciliation, recurrence and customer impact.",
                ["operational-trend.json", "maturity-model-assessment.json"],
            ),
        ],
        "procedures": [
            (
                "ITIL-4",
                "ITIL4-SERVICE-VALUE-CHAIN-FAULT-AND-IMPROVEMENT-REPLAY",
                "Using organization-licensed criteria, replay unauthorized change, failed release, alert loss, recurring incident, supplier outage, continuity invocation and incomplete improvement cases; verify ownership, decisions, restoration, reconciliation and measurable outcomes without issuing training, practitioner or organizational certification claims.",
                "test",
                True,
                ["benchmark-scorecard.json", "operational-trend.json"],
            )
        ],
    },
}


MATURITY_PRODUCT_BENCHMARKS: tuple[dict[str, Any], ...] = (
    {
        "id": "doe-c2m2-capability-assessment",
        "version": "c2m2-2.1-2022-06-policy-pinned",
        "kind": "it-ot-cybersecurity-capability-maturity-evidence-investment-and-reassessment",
        "source": "DOE C2M2 2.1 model, help text and self-evaluation guidance with blinded evidence, rating disagreements, maturity-inflation mutations and longitudinal improvement fixtures",
        "languages": ["maturity", "energy", "it", "ot", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "finos-ccc-cloud-control-conformance",
        "version": "finos-ccc-core-v2025.10-policy-pinned",
        "kind": "financial-cloud-capability-threat-control-assessment-and-oscal-conformance",
        "source": "FINOS CCC Core v2025.10 and approved service catalogs with immutable schemas, cross-cloud fixtures, OSCAL round trips, configuration mutations and semantic oracles",
        "languages": ["cloud", "financial", "oscal", "iac", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "ncsc-product-cyber-resilience-testing",
        "version": "crt-apc-1.0-crtf-scheme-1.1-policy-pinned",
        "kind": "connected-product-principles-claims-evidence-public-interface-and-resilience-assurance",
        "source": "NCSC CRT APC 1.0 and CRTF Scheme Standard 1.1 with approved assurance-case, public-interface attack, risk, recovery, evaluator and report fixtures",
        "languages": ["product", "connected", "assurance-case", "dynamic", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "nist-pram-privacy-risk-assessment",
        "version": "nist-pram-2021-04-23-policy-pinned",
        "kind": "data-action-problematic-action-individual-impact-risk-and-response-assurance",
        "source": "NIST PRAM and NISTIR 8062 risk model with synthetic data-flow, contextual, vulnerable-population, scoring-disagreement and response-effectiveness cases",
        "languages": ["privacy", "data", "risk", "engineering", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "itil4-service-management-outcome-assurance",
        "version": "itil4-licensed-policy-pinned-2026-08-31",
        "kind": "service-value-practice-change-incident-continuity-and-improvement-outcome-assurance",
        "source": "Organization-licensed ITIL 4 criteria mapped to ISO/IEC 20000-1 and ISO/IEC 27013 with synthetic service events, faults, recovery, recurrence and improvement fixtures",
        "languages": [
            "service-management",
            "operations",
            "security",
            "governance",
            "multi",
        ],
        "lane": "authorized-companion",
    },
)


MATURITY_PRODUCT_BENCHMARK_PROTOCOLS = {
    benchmark["id"]: "conformance" for benchmark in MATURITY_PRODUCT_BENCHMARKS
}

MATURITY_PRODUCT_LABORATORY_BENCHMARKS = frozenset(
    {"ncsc-product-cyber-resilience-testing"}
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


MATURITY_PRODUCT_ADAPTER_SPECS: tuple[dict[str, Any], ...] = (
    {
        "benchmark_id": "doe-c2m2-capability-assessment",
        "protocol": "conformance",
        "upstream": "https://www.energy.gov/ceser/cybersecurity-capability-maturity-model-c2m2",
        "acquisition": {
            **_COMMON_ACQUISITION,
            "license": "us-government-work-and-assessment-record-specific",
        },
        "normalizer": "c2m2-domain-practice-maturity-and-outcome-v1",
        "required_inputs": [
            "c2m2-model-help-text-and-version-lock",
            "organization-function-it-ot-and-threat-scope",
            "practice-evidence-and-participant-rating-record",
            "gap-risk-investment-and-action-plan",
            "independent-reassessment-and-outcome-ledger",
        ],
        "isolation": "access-controlled evidence workspace with blinded assessor views, immutable source records, protected operational details, independent adjudication and no DOE endorsement, certification or control-effectiveness claim",
    },
    {
        "benchmark_id": "finos-ccc-cloud-control-conformance",
        "protocol": "conformance",
        "upstream": "https://ccc.finos.org/",
        "acquisition": {
            **_COMMON_ACQUISITION,
            "license": "community-specification-and-catalog-release-specific",
        },
        "normalizer": "finos-ccc-control-threat-assessment-oscal-v1",
        "required_inputs": [
            "core-and-service-catalog-release-manifest",
            "capability-threat-control-and-assessment-schema",
            "cloud-inventory-responsibility-and-applicability-map",
            "provider-native-findings-and-oscal-fixtures",
            "semantic-loss-drift-and-independent-replay-report",
        ],
        "isolation": "read-only cloud evidence plane plus disposable no-egress cloud fixtures with synthetic identities and data, least privilege, deterministic cleanup and no FINOS, provider or regulatory certification claim",
    },
    {
        "benchmark_id": "ncsc-product-cyber-resilience-testing",
        "protocol": "conformance",
        "upstream": "https://www.ncsc.gov.uk/schemes/cyber-resilience-test-facilities/documents",
        "acquisition": {
            **_COMMON_ACQUISITION,
            "license": "uk-crown-copyright-guidance-product-and-laboratory-specific",
        },
        "normalizer": "ncsc-crt-apc-claim-evidence-resilience-v1",
        "required_inputs": [
            "crt-apc-and-crtf-scheme-version-lock",
            "product-context-interface-threat-and-claim-map",
            "argument-evidence-risk-and-vendor-response-record",
            "authorized-attack-recovery-and-cleanup-fixtures",
            "evaluator-independence-report-and-retest-ledger",
        ],
        "isolation": "NCSC-approved facility for scheme claims or a no-egress residue-controlled product laboratory with synthetic identities, bounded interfaces, emergency stop, deterministic recovery and no NCSC approval or CRTF certificate claim",
    },
    {
        "benchmark_id": "nist-pram-privacy-risk-assessment",
        "protocol": "conformance",
        "upstream": "https://www.nist.gov/privacy-framework/nist-pram",
        "acquisition": {
            **_COMMON_ACQUISITION,
            "license": "us-government-work-and-organization-risk-record-specific",
        },
        "normalizer": "nist-pram-data-action-impact-response-v1",
        "required_inputs": [
            "pram-and-nistir8062-version-lock",
            "system-purpose-data-action-and-flow-map",
            "problematic-action-population-and-impact-record",
            "likelihood-impact-uncertainty-and-priority-model",
            "response-test-change-and-reassessment-ledger",
        ],
        "isolation": "access-controlled no-egress privacy workspace using synthetic or irreversibly deidentified records, protected population strata, independent review and no legal-compliance or privacy-safety claim",
    },
    {
        "benchmark_id": "itil4-service-management-outcome-assurance",
        "protocol": "conformance",
        "upstream": "https://www.peoplecert.org/Organizations/Certifications/ITIL-Corporate-Framework",
        "acquisition": {
            **_COMMON_ACQUISITION,
            "license": "organization-licensed-itil-criteria-and-service-record-specific",
        },
        "normalizer": "itil4-service-value-practice-outcome-v1",
        "required_inputs": [
            "licensed-criteria-edition-and-digest-record",
            "service-value-stream-practice-and-ownership-map",
            "change-incident-problem-supplier-and-continuity-record",
            "security-service-outcome-and-customer-impact-ledger",
            "improvement-recurrence-and-independent-review-report",
        ],
        "isolation": "licensed access-controlled service-management workspace with deidentified operational records, synthetic fault cases, independent review and no PeopleCert, practitioner or organizational certification claim",
    },
)


MATURITY_PRODUCT_EVIDENCE_CONTRACTS: dict[str, dict[str, Any]] = {
    "doe-c2m2-capability-assessment": {
        "scalars": {"model": "DOE-C2M2-2.1"},
        "sets": {
            "environments": {"it", "ot"},
            "assessment_surfaces": {
                "domains",
                "objectives",
                "practices",
                "approach-objectives",
                "maturity-indicator-levels",
            },
        },
        "counts": (
            "practices_evaluated",
            "evidence_items_reviewed",
            "improvement_actions_reassessed",
        ),
        "required_true": (
            "organization_function_asset_dependency_threat_and_period_scope_bound",
            "all_ten_domains_objectives_practices_and_maturity_indicators_evaluated",
            "practice_evidence_participants_disagreement_and_uncertainty_preserved",
            "gap_risk_dependency_investment_owner_and_due_date_trace_verified",
            "independent_rating_adjudication_maturity_inflation_challenge_completed",
            "longitudinal_outcome_and_corrective_action_reassessment_verified",
        ),
        "required_false": (
            "unsupported_practice_treated_as_implemented",
            "doe_endorsement_certification_or_control_effectiveness_claimed",
        ),
    },
    "finos-ccc-cloud-control-conformance": {
        "scalars": {"catalog": "FINOS-CCC-CORE-v2025.10"},
        "sets": {
            "clouds": {"aws", "azure", "gcp", "private-cloud"},
            "semantic_surfaces": {
                "capabilities",
                "threats",
                "controls",
                "assessment-requirements",
                "responsibilities",
                "evidence",
            },
        },
        "counts": (
            "controls_evaluated",
            "assessment_requirements_replayed",
            "drift_cases_detected",
        ),
        "required_true": (
            "core_service_catalog_schema_license_version_and_digest_bound",
            "cloud_service_region_tenant_responsibility_and_applicability_bound",
            "capability_threat_control_assessment_and_evidence_links_verified",
            "oscal_roundtrip_conflict_and_semantic_loss_reporting_verified",
            "provider_native_finding_configuration_mutation_and_drift_replayed",
            "independent_assessment_exception_cleanup_and_rescan_verified",
        ),
        "required_false": (
            "floating_or_mixed_catalog_release_used",
            "finos_provider_regulatory_or_cloud_security_certification_claimed",
        ),
    },
    "ncsc-product-cyber-resilience-testing": {
        "scalars": {"criteria": "NCSC-CRT-APC-1.0-CRTF-1.1"},
        "sets": {
            "themes": {
                "organizational",
                "product",
                "deployment",
                "maintenance",
                "product-specific",
            },
            "attack_classes": {
                "malformed-input",
                "unauthorized-action",
                "replay",
                "downgrade",
                "resource-exhaustion",
                "recovery",
            },
        },
        "counts": (
            "claims_evaluated",
            "evidence_items_replayed",
            "adverse_cases_executed",
        ),
        "required_true": (
            "product_version_configuration_context_interface_and_threat_scope_bound",
            "principle_claim_argument_evidence_residual_risk_and_response_trace_verified",
            "facility_scope_evaluator_competence_independence_and_custody_verified",
            "test_authority_safety_disclosure_cleanup_and_known_good_recovery_verified",
            "public_interface_adverse_cases_essential_behavior_and_risk_interpretation_replayed",
            "report_provenance_evidence_gap_remediation_retest_and_independent_review_verified",
        ),
        "required_false": (
            "production_or_customer_product_tested_without_explicit_authority",
            "ncsc_crtf_approval_certificate_or_vulnerability_free_claimed",
        ),
    },
    "nist-pram-privacy-risk-assessment": {
        "scalars": {"method": "NIST-PRAM-2021-04-23-NISTIR-8062"},
        "sets": {
            "risk_elements": {
                "data-actions",
                "problematic-data-actions",
                "likelihood",
                "individual-impact",
                "priority",
                "response",
            },
            "challenge_classes": {
                "missed-flow",
                "inference",
                "secondary-use",
                "recipient-expansion",
                "reidentification",
                "vulnerable-population",
                "context-change",
            },
        },
        "counts": (
            "data_actions_evaluated",
            "privacy_risks_scored",
            "responses_retested",
        ),
        "required_true": (
            "system_purpose_actor_data_element_action_flow_and_recipient_scope_bound",
            "problematic_action_context_population_and_individual_impact_trace_verified",
            "likelihood_impact_priority_assumption_and_uncertainty_model_reproduced",
            "representative_vulnerable_population_and_changed_context_cases_replayed",
            "response_engineering_change_effectiveness_and_residual_risk_verified",
            "independent_scoring_agreement_adjudication_and_reassessment_completed",
        ),
        "required_false": (
            "unobserved_data_flow_treated_as_absent",
            "nist_endorsement_legal_compliance_or_zero_privacy_risk_claimed",
        ),
    },
    "itil4-service-management-outcome-assurance": {
        "scalars": {"framework": "ITIL4-LICENSED-2026-08-31"},
        "sets": {
            "practices": {
                "change-enablement",
                "release-management",
                "incident-management",
                "problem-management",
                "service-continuity",
                "information-security",
                "supplier-management",
                "continual-improvement",
            },
            "outcomes": {
                "availability",
                "integrity",
                "confidentiality",
                "restoration",
                "customer-impact",
                "recurrence",
                "improvement",
            },
        },
        "counts": (
            "services_evaluated",
            "practice_records_sampled",
            "fault_cases_replayed",
        ),
        "required_true": (
            "licensed_criteria_edition_digest_scope_and_access_rights_bound",
            "service_customer_value_stream_practice_configuration_and_owner_scope_bound",
            "change_release_incident_problem_supplier_and_continuity_trace_verified",
            "security_service_customer_impact_restoration_and_reconciliation_outcomes_verified",
            "unauthorized_change_failure_recurrence_and_supplier_fault_cases_replayed",
            "improvement_effectiveness_independent_review_and_iso_crosswalk_loss_verified",
        ),
        "required_false": (
            "unlicensed_criteria_content_exported",
            "peoplecert_training_practitioner_or_organization_certification_claimed",
        ),
    },
}
