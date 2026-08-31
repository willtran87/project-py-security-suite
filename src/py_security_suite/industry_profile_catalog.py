from __future__ import annotations

from typing import Any

from .industry_open_source_catalog import OPEN_SOURCE_PROFILES
from .industry_resilience_catalog import RESILIENCE_PROFILES

_ASSURANCE_PROFILES: dict[str, dict[str, Any]] = {
    "enterprise-security": {
        "standards": [
            "ISO-IEC-27001",
            "ISO-IEC-27002",
            "ISO-IEC-27014",
            "ISO-IEC-27032",
            "ISO-IEC-27033-1",
            "ISO-IEC-27040",
            "ISO-IEC-27034-1",
            "NIST-SP-800-18",
        ],
        "controls": [
            (
                "ISO-IEC-27001",
                "ISMS-RISK",
                "Retain scoped information-security risk and control evidence.",
                ["control-proof.json", "audit-package-verification.json"],
            ),
            (
                "ISO-IEC-27002",
                "ORG-CONTROLS",
                "Assess organizational and technical security controls against retained evidence.",
                ["domain-assurance.json", "control-proof.json"],
            ),
            (
                "ISO-IEC-27034-1",
                "APPLICATION-SECURITY",
                "Integrate application-security requirements and verification into the lifecycle.",
                [
                    "security-requirements-coverage.json",
                    "application-contract-analysis.json",
                ],
            ),
        ],
        "procedures": [
            (
                "ISO-IEC-27001",
                "INTERNAL-REVIEW",
                "Review the scoped ISMS evidence package and unresolved control gaps.",
                "examine",
                False,
                ["audit-package-verification.json", "control-assessment.json"],
            ),
        ],
    },
    "privacy": {
        "standards": [
            "ISO-IEC-27701",
            "NIST-PRIVACY-FRAMEWORK",
            "NIST-SP-800-188",
            "ISO-IEC-27555",
            "ISO-IEC-27559",
        ],
        "controls": [
            (
                "ISO-IEC-27701",
                "PIMS",
                "Retain privacy-management and accountable data-processing evidence.",
                ["data-exposure.json", "domain-assurance.json"],
            ),
            (
                "NIST-PRIVACY-FRAMEWORK",
                "PRIVACY-RISK",
                "Identify and treat privacy risks across discovered data flows.",
                ["data-exposure.json", "risk-paths.json"],
            ),
        ],
        "procedures": [
            (
                "ISO-IEC-27701",
                "PROCESSING-REVIEW",
                "Review data inventory, purposes, boundaries, retention, and protection evidence.",
                "manual",
                False,
                ["data-exposure.json", "domain-assurance.json"],
            ),
        ],
    },
    "psirt-incident": {
        "standards": ["ISO-IEC-29147", "ISO-IEC-30111", "NIST-SP-800-61"],
        "controls": [
            (
                "ISO-IEC-29147",
                "DISCLOSURE",
                "Maintain coordinated vulnerability intake and disclosure evidence.",
                ["finding-register.json", "closure-plan.json"],
            ),
            (
                "ISO-IEC-30111",
                "HANDLING",
                "Triage, prioritize, remediate, and communicate retained vulnerability records.",
                [
                    "risk-intelligence.json",
                    "finding-register.json",
                    "closure-plan.json",
                ],
            ),
            (
                "NIST-SP-800-61",
                "INCIDENT-READINESS",
                "Retain incident preparation, detection, response, recovery, and improvement evidence.",
                ["operational-trend.json", "domain-assurance.json"],
            ),
        ],
        "procedures": [
            (
                "ISO-IEC-30111",
                "REMEDIATION-DRILL",
                "Exercise vulnerability triage through closure with ownership and elapsed-time evidence.",
                "test",
                True,
                ["finding-register.json", "closure-plan.json"],
            ),
            (
                "NIST-SP-800-61",
                "INCIDENT-EXERCISE",
                "Execute an authorized incident-response exercise and retain observations.",
                "test",
                True,
                ["operational-trend.json"],
            ),
        ],
    },
    "software-supply-chain": {
        "standards": [
            "NIST-SP-800-204D",
            "SLSA",
            "ISO-IEC-18974",
            "ISO-IEC-5230",
            "SPDX",
        ],
        "controls": [
            (
                "NIST-SP-800-204D",
                "CICD-INTEGRITY",
                "Bind CI/CD security evidence to the exact source and release subjects.",
                ["release-readiness.json", "evidence-fusion.json"],
            ),
            (
                "SLSA",
                "BUILD-SOURCE",
                "Verify source and build provenance at the organization-selected SLSA levels.",
                ["security-passport.json", "release-readiness.json"],
            ),
            (
                "ISO-IEC-18974",
                "OSS-SECURITY",
                "Operate an evidence-backed open-source security assurance process.",
                ["dependency-surface.json", "risk-intelligence.json"],
            ),
            (
                "ISO-IEC-5230",
                "OSS-LICENSE",
                "Operate an evidence-backed open-source license compliance process.",
                ["reuse-compliance.json", "scancode-inventory.json"],
            ),
            (
                "SPDX",
                "SBOM-INTERCHANGE",
                "Retain machine-readable component, license, and artifact identity evidence.",
                ["artifact-manifest.json", "reuse-compliance.json"],
            ),
        ],
        "procedures": [
            (
                "SLSA",
                "PROVENANCE-VERIFY",
                "Verify provenance authenticity, subject identity, builder policy, and source revision.",
                "test",
                False,
                ["security-passport.json", "release-readiness.json"],
            ),
        ],
    },
    "ai-development": {
        "standards": ["NIST-SP-800-218A", "NIST-AI-RMF", "OWASP-AITG", "MITRE-ATLAS"],
        "controls": [
            (
                "NIST-SP-800-218A",
                "AI-SSDF",
                "Apply AI-specific secure-development practices to models, data, and dependent systems.",
                ["llm-adversarial-plan.json", "domain-assurance.json"],
            ),
        ],
        "procedures": [
            (
                "OWASP-AITG",
                "AI-ADVERSARIAL",
                "Execute the approved adversarial campaign with deterministic oracles and negative controls.",
                "dynamic",
                True,
                ["llm-adversarial-plan.json"],
            ),
        ],
    },
    "eu-cra": {
        "standards": ["EU-CRA", "ISO-IEC-29147", "ISO-IEC-30111"],
        "controls": [
            (
                "EU-CRA",
                "ESSENTIAL-REQUIREMENTS",
                "Retain product risk, secure-default, component, update, and support evidence.",
                [
                    "release-readiness.json",
                    "artifact-sbom.cdx.json",
                    "risk-intelligence.json",
                ],
            ),
            (
                "EU-CRA",
                "VULNERABILITY-HANDLING",
                "Retain vulnerability handling, disclosure, remediation, and support-period evidence.",
                ["finding-register.json", "closure-plan.json"],
            ),
        ],
        "procedures": [
            (
                "EU-CRA",
                "CONFORMITY-REVIEW",
                "Review technical documentation and applicable conformity evidence before release.",
                "manual",
                False,
                ["audit-package-verification.json", "release-readiness.json"],
            ),
        ],
    },
    "payment-software": {
        "standards": ["PCI-DSS", "PCI-SECURE-SOFTWARE"],
        "controls": [
            (
                "PCI-DSS",
                "REQ-6",
                "Retain secure-development and change-control evidence for payment-impacting software.",
                ["security-requirements-coverage.json", "release-readiness.json"],
            ),
            (
                "PCI-SECURE-SOFTWARE",
                "SOFTWARE-SECURITY",
                "Retain payment-software design, implementation, and testing evidence.",
                ["application-contract-analysis.json", "data-exposure.json"],
            ),
        ],
        "procedures": [
            (
                "PCI-DSS",
                "PENETRATION-TEST",
                "Execute the authorized applicable penetration-test scope and retain results.",
                "dynamic",
                True,
                ["llm-adversarial-plan.json"],
            ),
        ],
    },
    "federal-cui": {
        "standards": ["NIST-SP-800-171", "NIST-SP-800-53A"],
        "controls": [
            (
                "NIST-SP-800-171",
                "CUI-REQUIREMENTS",
                "Assess applicable CUI protection requirements with organization-approved evidence.",
                ["control-proof.json", "audit-package-verification.json"],
            ),
        ],
        "procedures": [
            (
                "NIST-SP-800-53A",
                "CUI-ASSESSMENT",
                "Execute applicable examination, interview, and test procedures for the CUI boundary.",
                "test",
                True,
                ["procedure-assessment.json"],
            ),
        ],
    },
    "service-organization": {
        "standards": ["SOC2-TSC", "NIST-CSF"],
        "controls": [
            (
                "SOC2-TSC",
                "TRUST-SERVICES",
                "Retain scoped security, availability, confidentiality, processing-integrity, and privacy control evidence.",
                ["control-proof.json", "audit-package-verification.json"],
            ),
        ],
        "procedures": [
            (
                "SOC2-TSC",
                "OPERATING-EFFECTIVENESS",
                "Review control design and time-bounded operating-effectiveness evidence.",
                "examine",
                False,
                ["operational-trend.json", "audit-package-verification.json"],
            ),
        ],
    },
}

_ASSURANCE_PROFILES.update(
    {
        "identity-protocol-security": {
            "standards": [
                "NIST-SP-800-63-4",
                "IETF-RFC-9700",
                "W3C-WEBAUTHN",
                "OIDF-FAPI",
            ],
            "controls": [
                (
                    "NIST-SP-800-63-4",
                    "IDENTITY-ASSURANCE",
                    "Retain identity proofing, authenticator, recovery, and federation assurance evidence.",
                    ["application-contract-analysis.json", "domain-assurance.json"],
                ),
                (
                    "IETF-RFC-9700",
                    "OAUTH-BCP",
                    "Reject unsafe OAuth modes and verify PKCE, replay resistance, redirect binding, and token handling.",
                    ["application-contract-analysis.json", "risk-paths.json"],
                ),
                (
                    "W3C-WEBAUTHN",
                    "PHISHING-RESISTANCE",
                    "Retain origin-bound public-key authentication and recovery-path evidence.",
                    [
                        "application-contract-analysis.json",
                        "security-requirements-coverage.json",
                    ],
                ),
            ],
            "procedures": [
                (
                    "OIDF-FAPI",
                    "PROTOCOL-CONFORMANCE",
                    "Execute an authorized identity-protocol conformance suite with negative and replay controls.",
                    "dynamic",
                    True,
                    ["benchmark-scorecard.json"],
                ),
            ],
        },
        "cloud-container-zero-trust": {
            "standards": [
                "ISO-IEC-27017",
                "ISO-IEC-27018",
                "NIST-SP-800-190",
                "NIST-SP-800-207",
                "NIST-SP-800-207A",
                "CIS-BENCHMARKS",
            ],
            "controls": [
                (
                    "ISO-IEC-27017",
                    "SHARED-RESPONSIBILITY",
                    "Retain cloud customer/provider responsibility, configuration, tenancy, and supplier evidence.",
                    ["control-assessment.json", "domain-assurance.json"],
                ),
                (
                    "NIST-SP-800-190",
                    "CONTAINER-LIFECYCLE",
                    "Verify image provenance, least privilege, isolation, configuration, and runtime monitoring.",
                    ["release-readiness.json", "domain-assurance.json"],
                ),
                (
                    "NIST-SP-800-207",
                    "CONTINUOUS-VERIFICATION",
                    "Require explicit workload and user identity with policy enforcement at every trust transition.",
                    ["risk-paths.json", "static-architecture.json"],
                ),
            ],
            "procedures": [
                (
                    "CIS-BENCHMARKS",
                    "CLOUD-CONFIGURATION-TEST",
                    "Execute version-pinned container, Kubernetes, and applicable cloud configuration benchmarks.",
                    "test",
                    True,
                    ["checkov-iac.json", "kics-iac.json"],
                ),
            ],
        },
        "cryptography-pqc": {
            "standards": [
                "FIPS-140-3",
                "FIPS-203",
                "FIPS-204",
                "FIPS-205",
                "NIST-SP-800-131A",
                "IETF-RFC-9325",
            ],
            "controls": [
                (
                    "NIST-SP-800-131A",
                    "CRYPTO-INVENTORY",
                    "Retain an algorithm, protocol, key, certificate, library, and data-lifetime inventory with transition decisions.",
                    ["dependency-surface.json", "domain-assurance.json"],
                ),
                (
                    "FIPS-203",
                    "PQC-MIGRATION",
                    "Identify quantum-vulnerable uses and retain approved ML-KEM and signature migration evidence.",
                    ["closure-plan.json", "release-readiness.json"],
                ),
                (
                    "IETF-RFC-9325",
                    "TLS-BASELINE",
                    "Enforce current TLS/DTLS versions, algorithms, certificate validation, and downgrade resistance.",
                    ["domain-assurance.json", "security-requirements-coverage.json"],
                ),
            ],
            "procedures": [
                (
                    "FIPS-140-3",
                    "CRYPTO-CONFORMANCE",
                    "Execute applicable algorithm test vectors and verify module identity and operating environment.",
                    "test",
                    True,
                    ["benchmark-scorecard.json", "release-readiness.json"],
                ),
            ],
        },
        "operational-resilience": {
            "standards": ["ISO-22301", "NIST-SP-800-34", "NIST-SP-800-61"],
            "controls": [
                (
                    "ISO-22301",
                    "SERVICE-CONTINUITY",
                    "Retain dependency, recovery-objective, backup, failover, communications, and improvement evidence.",
                    ["operational-trend.json", "control-assessment.json"],
                ),
                (
                    "NIST-SP-800-34",
                    "CONTINGENCY-PLAN",
                    "Bind contingency strategies and restoration order to current architecture and critical dependencies.",
                    ["static-architecture.json", "domain-assurance.json"],
                ),
            ],
            "procedures": [
                (
                    "NIST-SP-800-34",
                    "RECOVERY-EXERCISE",
                    "Execute an authorized dependency-failure, restoration, and evidence-integrity exercise.",
                    "test",
                    True,
                    ["operational-trend.json", "benchmark-scorecard.json"],
                ),
            ],
        },
        "eu-digital-regulation": {
            "standards": [
                "EU-GDPR",
                "EU-NIS2",
                "EU-DORA",
                "EU-AI-ACT",
                "EU-CRA",
                "TIBER-EU",
            ],
            "controls": [
                (
                    "EU-GDPR",
                    "DATA-PROTECTION",
                    "Retain purpose, minimization, retention, rights, transfer, protection, and breach evidence for personal data.",
                    ["data-exposure.json", "control-assessment.json"],
                ),
                (
                    "EU-NIS2",
                    "RISK-AND-REPORTING",
                    "Retain applicable cybersecurity risk measures, supply-chain controls, incident decisions, and reporting evidence.",
                    ["operational-trend.json", "risk-intelligence.json"],
                ),
                (
                    "EU-AI-ACT",
                    "AI-RISK-CLASSIFICATION",
                    "Classify applicable AI roles and risks and retain documentation, oversight, robustness, and monitoring evidence.",
                    ["llm-adversarial-plan.json", "domain-assurance.json"],
                ),
            ],
            "procedures": [
                (
                    "EU-DORA",
                    "RESILIENCE-TEST",
                    "Execute the authorized applicable operational-resilience test scope and retain remediation evidence.",
                    "test",
                    True,
                    ["operational-trend.json", "closure-plan.json"],
                ),
            ],
        },
        "iot-consumer": {
            "standards": [
                "NISTIR-8259",
                "NISTIR-8259A",
                "NISTIR-8259B",
                "ETSI-EN-303-645",
                "ISO-IEC-27400",
                "ISO-IEC-27402",
                "ISO-IEC-27403",
                "ISO-IEC-27404",
            ],
            "controls": [
                (
                    "NISTIR-8259A",
                    "DEVICE-CAPABILITIES",
                    "Verify device identity, configuration, data protection, interface restriction, update, and state awareness.",
                    ["security-requirements-coverage.json", "domain-assurance.json"],
                ),
                (
                    "ETSI-EN-303-645",
                    "CONSUMER-IOT-BASELINE",
                    "Verify secure defaults, vulnerability handling, updates, credential safety, telemetry, and deletion behavior.",
                    ["finding-register.json", "release-readiness.json"],
                ),
            ],
            "procedures": [
                (
                    "NISTIR-8259",
                    "DEVICE-LIFECYCLE-TEST",
                    "Exercise commissioning, update, recovery, decommissioning, and customer-notification paths.",
                    "dynamic",
                    True,
                    ["procedure-assessment.json", "operational-trend.json"],
                ),
            ],
        },
        "ot-industrial": {
            "standards": ["IEC-62443-4-1", "IEC-62443-4-2", "NIST-SP-800-61"],
            "controls": [
                (
                    "IEC-62443-4-1",
                    "INDUSTRIAL-SDL",
                    "Retain industrial threat modeling, secure implementation, verification, defect, patch, and end-of-life evidence.",
                    ["security-requirements-coverage.json", "release-readiness.json"],
                ),
                (
                    "IEC-62443-4-2",
                    "COMPONENT-SECURITY",
                    "Verify identification, use control, integrity, confidentiality, event, availability, and resource controls.",
                    ["domain-assurance.json", "risk-paths.json"],
                ),
            ],
            "procedures": [
                (
                    "IEC-62443-4-2",
                    "ZONE-CONDUIT-TEST",
                    "Execute an authorized zone, conduit, degraded-mode, and safety-boundary security assessment.",
                    "test",
                    True,
                    ["procedure-assessment.json", "risk-paths.json"],
                ),
            ],
        },
        "automotive": {
            "standards": ["ISO-SAE-21434", "UNECE-R155", "UNECE-R156"],
            "controls": [
                (
                    "ISO-SAE-21434",
                    "TARA-LIFECYCLE",
                    "Retain item definition, threat analysis, risk treatment, verification, and post-development evidence.",
                    ["risk-paths.json", "release-readiness.json"],
                ),
                (
                    "UNECE-R156",
                    "SOFTWARE-UPDATES",
                    "Verify authorized, integrity-protected, recoverable software updates and retained version identity.",
                    ["security-passport.json", "release-readiness.json"],
                ),
            ],
            "procedures": [
                (
                    "UNECE-R155",
                    "VEHICLE-CYBER-ASSESSMENT",
                    "Execute an authorized applicable vehicle attack-path and update-recovery assessment.",
                    "test",
                    True,
                    ["procedure-assessment.json", "risk-paths.json"],
                ),
            ],
        },
        "medical-device": {
            "standards": [
                "IEC-62304",
                "IEC-81001-5-1",
                "FDA-MEDICAL-CYBERSECURITY",
                "ISO-27799",
            ],
            "controls": [
                (
                    "IEC-62304",
                    "SAFETY-LIFECYCLE",
                    "Bind software lifecycle, risk controls, configuration, problem resolution, and traceability evidence.",
                    ["security-requirements-coverage.json", "release-readiness.json"],
                ),
                (
                    "FDA-MEDICAL-CYBERSECURITY",
                    "CYBER-DEVICE-EVIDENCE",
                    "Retain threat modeling, SBOM, vulnerability management, update, support, and labeling evidence.",
                    ["artifact-sbom.cdx.json", "closure-plan.json"],
                ),
            ],
            "procedures": [
                (
                    "IEC-81001-5-1",
                    "SAFETY-SECURITY-VERIFICATION",
                    "Execute authorized security verification with patient-safety impact and residual-risk review.",
                    "test",
                    True,
                    ["procedure-assessment.json", "finding-validation.json"],
                ),
            ],
        },
        "federal-cloud-defense": {
            "standards": [
                "FEDRAMP",
                "CMMC",
                "NIST-SP-800-171",
                "NIST-SP-800-171A",
                "NIST-SP-800-53A",
            ],
            "controls": [
                (
                    "FEDRAMP",
                    "CLOUD-AUTHORIZATION",
                    "Retain version-pinned baseline, parameter, implementation, continuous-monitoring, and authorization evidence.",
                    [
                        "oscal-system-security-plan.json",
                        "audit-package-verification.json",
                    ],
                ),
                (
                    "CMMC",
                    "ASSESSMENT-LEVEL",
                    "Record applicable CMMC level, assessment authority, scope, inherited controls, findings, and POA&M constraints.",
                    ["control-assessment.json", "closure-plan.json"],
                ),
            ],
            "procedures": [
                (
                    "NIST-SP-800-171A",
                    "CUI-EVIDENCE-ASSESSMENT",
                    "Execute applicable examination, interview, and testing objectives with independent assessment identity.",
                    "test",
                    True,
                    ["procedure-assessment.json", "audit-package-verification.json"],
                ),
            ],
        },
    }
)

_ASSURANCE_PROFILES.update(RESILIENCE_PROFILES)

_ASSURANCE_PROFILES.update(
    {
        "water-sector-cyber-resilience": {
            "standards": [
                "AWWA-J100",
                "AWWA-G430",
                "AWWA-G440",
                "EPA-WATER-CYBERSECURITY-ASSESSMENT",
                "IEC-62443-3-3",
            ],
            "controls": [
                (
                    "AWWA-J100",
                    "WATER-MISSION-HAZARD-CONSEQUENCE-AND-RESILIENCE-BOUNDARY",
                    "Bind utility, treatment and distribution mission, population served, source water, process stage, chemical feed, pressure and quality invariant, cyber-physical asset, dependency, threat, consequence, resilience objective, owner and accepted residual risk to the current risk and resilience assessment.",
                    ["domain-assurance.json", "safety-security-analysis.json"],
                ),
                (
                    "AWWA-G430",
                    "WATER-OT-ACCESS-MONITORING-MANUAL-OPERATION-AND-SUPPLIER-SECURITY",
                    "Verify inventory, zoning, remote and local access, identity, least privilege, removable media, supplier service, configuration, logging, detection, communications, manual operation, laboratory dependencies, backups and compensating controls across water IT and OT boundaries.",
                    ["control-assessment.json", "static-architecture.json"],
                ),
                (
                    "AWWA-G440",
                    "WATER-EMERGENCY-COMMAND-COMMUNICATION-RECOVERY-AND-PUBLIC-SAFETY",
                    "Trace cyber incident recognition to command activation, public-health and emergency-partner communication, sampling, alternate treatment and supply, safe shutdown, restoration sequencing, water-quality confirmation, regulatory notification, lessons learned and five-year reassessment evidence.",
                    [
                        "incident-management-assessment.json",
                        "procedure-assessment.json",
                    ],
                ),
            ],
            "procedures": [
                (
                    "EPA-WATER-CYBERSECURITY-ASSESSMENT",
                    "WATER-TREATMENT-CYBER-PHYSICAL-ATTACK-RECOVERY-EXERCISE",
                    "Use a validated inert treatment and distribution twin to replay forged sensors, unauthorized chemical or pump commands, stale telemetry, remote-access compromise, ransomware, communications loss, unsafe automation and restoration. Require process invariants, manual fallback, independent water-quality review, deterministic reset and no production actuation.",
                    "dynamic",
                    True,
                    ["benchmark-scorecard.json", "safety-security-analysis.json"],
                )
            ],
        },
        "public-safety-emergency-communications": {
            "standards": [
                "NENA-STA-040",
                "NENA-REF-012",
                "NENA-STA-010",
                "TIA-102-P25",
                "DHS-P25-CAP",
            ],
            "controls": [
                (
                    "NENA-STA-040",
                    "NG911-TRUST-ZONE-IDENTITY-ROUTING-LOGGING-AND-CONTINUITY",
                    "Bind PSAP, ESInet, NGCS, functional element, identity, certificate, route, location, incident data object, administrative interface, logging path, external service, trust zone, continuity objective and accountable owner to the deployed NG911 architecture.",
                    ["static-architecture.json", "control-assessment.json"],
                ),
                (
                    "NENA-STA-010",
                    "NG911-I3-EIDO-MESSAGE-ROUTING-LOCATION-AND-FAILOVER-SEMANTICS",
                    "Validate protocol version, schema, message and incident identity, location and routing authority, integrity, authorization, duplicate and replay handling, overload, queueing, failover, fallback, audit correlation and privacy semantics across i3 interfaces without inferring operational certification.",
                    [
                        "application-contract-analysis.json",
                        "security-automation-interoperability.json",
                    ],
                ),
                (
                    "TIA-102-P25",
                    "P25-RADIO-IDENTITY-KEY-MANAGEMENT-CONFORMANCE-AND-INTEROPERABILITY",
                    "Bind subscriber, infrastructure, talkgroup, unit identity, cryptographic keyset, algorithm, service and interface to the exact TIA-102 profile; retain conformance, performance, interoperability, key lifecycle, emergency signaling, roaming, failover and degraded-mode evidence from authorized fixtures.",
                    ["procedure-assessment.json", "trust-policy-attestation.json"],
                ),
            ],
            "procedures": [
                (
                    "DHS-P25-CAP",
                    "NG911-P25-END-TO-END-INTEROPERABILITY-FAILURE-AND-RECOVERY-EXERCISE",
                    "In an isolated public-safety communications laboratory, replay malformed and replayed i3 messages, false location, route manipulation, certificate and key rollover failures, denial and overload, radio interoperability mismatches, lost sites, dispatch failover and restoration; require independent ground truth and prohibit live emergency traffic.",
                    "dynamic",
                    True,
                    ["benchmark-scorecard.json", "audit-package-verification.json"],
                )
            ],
        },
        "global-gxp-computerised-system-assurance": {
            "standards": [
                "EU-GMP-ANNEX-11",
                "WHO-TRS-1033-ANNEX-4",
                "PICS-PI-041-1",
                "FDA-21-CFR-PART-11",
                "ISPE-GAMP-5",
            ],
            "controls": [
                (
                    "EU-GMP-ANNEX-11",
                    "GLOBAL-GXP-LIFECYCLE-VALIDATION-SUPPLIER-CHANGE-AND-CONTINUITY",
                    "Bind regulated process, product and patient risk, system boundary, intended use, lifecycle category, supplier and service responsibility, user requirements, configuration, validation, release, operation, security, backup, restore, business continuity, change, periodic review, migration and retirement to approved evidence.",
                    ["lifecycle-traceability.json", "procedure-assessment.json"],
                ),
                (
                    "WHO-TRS-1033-ANNEX-4",
                    "GLOBAL-GXP-ALCOA-PLUS-METADATA-AUDIT-TRAIL-AND-RECORD-GOVERNANCE",
                    "Preserve attributable, legible, contemporaneous, original, accurate, complete, consistent, enduring and available records with metadata, audit trails, secure time, review, exception, retention, retrieval, true-copy, archiving and deletion governance across hybrid paper and electronic workflows.",
                    ["audit-package-verification.json", "data-exposure.json"],
                ),
                (
                    "PICS-PI-041-1",
                    "GLOBAL-GXP-DATA-GOVERNANCE-CULTURE-OUTSOURCING-AND-INSPECTION-READINESS",
                    "Verify accountable data governance, quality culture, role separation, training, privileged access, outsourced activity oversight, data-flow and vulnerability assessment, investigation, remediation, management review and inspection-ready reconstruction without asserting regulator acceptance.",
                    ["control-assessment.json", "process-capability-assessment.json"],
                ),
            ],
            "procedures": [
                (
                    "EU-GMP-ANNEX-11",
                    "GLOBAL-GXP-RECORD-METADATA-AUDIT-TRAIL-MIGRATION-AND-RESTORE-CHALLENGE",
                    "Exercise a synthetic multinational GxP workflow with record, metadata and audit-trail alteration or omission, backdating, shared credentials, signature transfer, clock drift, interface truncation, failed backup, incomplete restore, migration transformation, supplier outage and inspection-copy reconstruction; require independent quality review.",
                    "test",
                    True,
                    ["benchmark-scorecard.json", "audit-package-verification.json"],
                )
            ],
        },
        "transit-cybersecurity-resilience": {
            "standards": ["NIST-IR-8576", "NIST-CSF", "IEC-62443-3-3", "CLC-TS-50701"],
            "controls": [
                (
                    "NIST-IR-8576",
                    "TRANSIT-MISSION-SERVICE-SAFETY-IT-OT-AND-SUPPLY-CHAIN-PROFILE",
                    "Bind transit agency, mode, route and service, rider and workforce safety, fare and passenger systems, signaling and vehicle OT, facilities, communications, cloud and suppliers to CSF 2.0 current and target outcomes, accountable owners, tolerances, dependencies and accepted residual risk.",
                    ["domain-assurance.json", "control-assessment.json"],
                ),
                (
                    "NIST-IR-8576",
                    "TRANSIT-DEGRADED-OPERATION-INCIDENT-RECOVERY-AND-SERVICE-RECONCILIATION",
                    "Prove detection, dispatch and operations coordination, passenger communication, safe degraded and manual operation, alternate service, emergency interfaces, restoration order, configuration and operational-state reconciliation, supplier recovery, after-action review and profile reassessment.",
                    [
                        "incident-management-assessment.json",
                        "operational-trend.json",
                    ],
                ),
            ],
            "procedures": [
                (
                    "NIST-IR-8576",
                    "TRANSIT-MULTIMODAL-IT-OT-SAFETY-AND-SERVICE-RESILIENCE-EXERCISE",
                    "Use an inert multimodal transit twin to replay account compromise, fare and passenger-information disruption, vehicle and signaling telemetry deception, unauthorized commands, communications loss, ransomware, supplier outage and cascading service failure; preserve safety, dispatch authority, recovery and rider communication without production connectivity.",
                    "dynamic",
                    True,
                    ["benchmark-scorecard.json", "safety-security-analysis.json"],
                )
            ],
        },
        "emergency-incident-coordination": {
            "standards": ["ISO-22320", "ISO-22301", "NIST-SP-800-61"],
            "controls": [
                (
                    "ISO-22320",
                    "INCIDENT-COMMAND-ROLE-AUTHORITY-OBJECTIVE-AND-DECISION-TRACE",
                    "Bind incident, objectives, command and coordination structure, roles, authority, competence, common operating picture, decision, resource request, action, handoff, communication, safety constraint and accountable record across participating organizations.",
                    [
                        "incident-management-assessment.json",
                        "audit-package-verification.json",
                    ],
                ),
                (
                    "ISO-22320",
                    "INCIDENT-INFORMATION-QUALITY-INTEROPERABILITY-RESOURCE-AND-RECOVERY",
                    "Verify source, time, confidence, classification, dissemination, acknowledgement and correction of incident information; interoperable terminology and communications; resource tracking; escalation; transfer of command; recovery objectives; demobilization and lessons learned.",
                    [
                        "security-automation-interoperability.json",
                        "procedure-assessment.json",
                    ],
                ),
            ],
            "procedures": [
                (
                    "ISO-22320",
                    "MULTI-ORGANIZATION-INCIDENT-COMMAND-INFORMATION-AND-HANDOFF-EXERCISE",
                    "Run a synthetic multi-organization exercise containing conflicting authority, stale and false reports, communication loss, terminology mismatch, resource contention, privacy and public-information tension, shift handoff, cascading events and recovery; require timed decisions, independent observers and complete after-action traceability.",
                    "manual",
                    False,
                    ["benchmark-scorecard.json", "incident-management-assessment.json"],
                )
            ],
        },
        "gas-scada-cryptographic-resilience": {
            "standards": [
                "AGA-REPORT-12-PART-1",
                "API-STD-1164",
                "IEC-62351",
                "IEC-62443-3-3",
            ],
            "controls": [
                (
                    "AGA-REPORT-12-PART-1",
                    "GAS-SCADA-CHANNEL-ENDPOINT-KEY-AND-CRYPTOGRAPHIC-POLICY",
                    "Bind control center, field site, endpoint, channel, protocol, command and telemetry object, cryptographic mechanism, key and credential lifecycle, clock, availability requirement, exception, compensating control and owner to the current gas SCADA architecture and API 1164 risk treatment.",
                    ["static-architecture.json", "trust-policy-attestation.json"],
                ),
                (
                    "AGA-REPORT-12-PART-1",
                    "GAS-SCADA-FORGERY-REPLAY-DOWNGRADE-ROLLOVER-AND-RECOVERY-TEST-PLAN",
                    "Verify origin and data integrity, confidentiality where required, replay resistance, sequence and time handling, key establishment and rollover, loss and revocation, legacy coexistence, fail-safe and manual operation, monitoring, performance, restoration and state reconciliation under bounded adverse cases.",
                    [
                        "application-contract-analysis.json",
                        "procedure-assessment.json",
                    ],
                ),
            ],
            "procedures": [
                (
                    "AGA-REPORT-12-PART-1",
                    "GAS-SCADA-CRYPTOGRAPHIC-PROTOCOL-DEGRADED-MODE-AND-RECOVERY-EXERCISE",
                    "In an inert gas pipeline SCADA twin, replay message forgery, replay, reorder, delay, downgrade, endpoint and key substitution, rollover failure, clock loss, packet loss, partition and recovery; preserve safety, bounded latency, manual control, restoration and residue checks without production actuation.",
                    "dynamic",
                    True,
                    ["benchmark-scorecard.json", "safety-security-analysis.json"],
                )
            ],
        },
    }
)

_ASSURANCE_PROFILES.update(
    {
        "authorization-decision-interoperability": {
            "standards": [
                "OIDF-AUTHZEN-AUTHORIZATION-API",
                "NIST-SP-800-162",
                "NIST-SP-800-192",
            ],
            "controls": [
                (
                    "OIDF-AUTHZEN-AUTHORIZATION-API",
                    "AUTHZEN-PDP-PEP-DECISION-BOUNDARY",
                    "Bind every policy decision request to the exact subject, resource, action, context, tenant, policy revision and enforcement point; negotiate only declared PDP capabilities; deny safely on malformed, ambiguous, unavailable, stale or unsupported decisions.",
                    [
                        "application-contract-analysis.json",
                        "trust-policy-attestation.json",
                    ],
                ),
                (
                    "OIDF-AUTHZEN-AUTHORIZATION-API",
                    "AUTHZEN-CACHE-BATCH-FAILURE-AND-DRAFT-BOUNDARY",
                    "Constrain decision caching and batch evaluation by policy revision, subject and resource identity, isolate partial failures, and exclude obligations, access-request and approval drafts from normative Authorization API 1.0 claims unless separately versioned and approved.",
                    ["risk-paths.json", "security-automation-interoperability.json"],
                ),
            ],
            "procedures": [
                (
                    "OIDF-AUTHZEN-AUTHORIZATION-API",
                    "AUTHZEN-DECISION-INTEROPERABILITY-AND-ABUSE",
                    "Replay supported single, batch, search and metadata capabilities across independent PDP and PEP implementations; inject subject-resource-action confusion, unknown types, malformed context, cross-tenant identifiers, stale policy, poisoned cache, partial batch failure, timeout and PDP outage cases and require fail-closed enforcement.",
                    "dynamic",
                    True,
                    [
                        "benchmark-scorecard.json",
                        "security-automation-interoperability.json",
                    ],
                )
            ],
        },
        "openid-federation-security": {
            "standards": [
                "OIDF-OPENID-FEDERATION",
                "OIDF-OPENID-FEDERATION-CONNECT",
                "OIDF-FAPI",
            ],
            "controls": [
                (
                    "OIDF-OPENID-FEDERATION",
                    "FEDERATION-ENTITY-STATEMENT-TRUST-CHAIN-AND-POLICY",
                    "Cryptographically bind entity configurations, subordinate statements, authority hints, trust anchors, metadata policies, trust marks, keys, validity intervals and resolved trust paths; reject ambiguous, cyclic, expired, forked or unauthorized chains.",
                    [
                        "trust-policy-attestation.json",
                        "security-automation-interoperability.json",
                    ],
                ),
                (
                    "OIDF-OPENID-FEDERATION-CONNECT",
                    "FEDERATION-OIDC-METADATA-AND-CLIENT-BINDING",
                    "Apply resolved federation metadata to OpenID Provider and Relying Party behavior without accepting weaker local metadata, algorithm downgrade, entity substitution, key confusion or registration outside the approved trust chain.",
                    [
                        "application-contract-analysis.json",
                        "threat-model-assessment.json",
                    ],
                ),
            ],
            "procedures": [
                (
                    "OIDF-OPENID-FEDERATION",
                    "FEDERATION-OFFICIAL-EARLY-SUITE-PLUS-NEGATIVE-ORACLES",
                    "Run the official deployed-entity, OP and RP Federation plans as an explicitly early upstream suite, then independently replay signature, trust-chain, metadata-policy, authority-hint, trust-mark, rollover, expiration, cycle, forked-anchor, entity-substitution and downgrade cases; never translate an early-suite pass into OpenID certification.",
                    "dynamic",
                    True,
                    [
                        "benchmark-scorecard.json",
                        "audit-package-verification.json",
                    ],
                )
            ],
        },
        "hpc-ai-infrastructure-security": {
            "standards": [
                "NIST-SP-800-223",
                "NIST-SP-800-234",
                "NIST-SP-800-53",
                "NIST-SP-800-53B",
            ],
            "controls": [
                (
                    "NIST-SP-800-223",
                    "HPC-ZONE-COMPONENT-DATA-WORKFLOW-THREAT-MODEL",
                    "Model the actual HPC zones, management and access planes, compute and accelerator nodes, schedulers, storage, software and data flows, trust boundaries, users, tenants and mission constraints; trace identified threats and shared-resource risks to retained mitigations.",
                    ["static-architecture.json", "threat-model-assessment.json"],
                ),
                (
                    "NIST-SP-800-234",
                    "HPC-MODERATE-BASELINE-OVERLAY-TAILORING",
                    "Apply all 60 SP 800-234 tailored controls and supplemental guidance against the pinned SP 800-53B moderate baseline, preserving applicability, organization-defined parameters, performance tradeoffs, compensating controls, residual risk and accountable approvals.",
                    ["control-assessment.json", "oscal-assessment-plan.json"],
                ),
            ],
            "procedures": [
                (
                    "NIST-SP-800-234",
                    "HPC-OVERLAY-ARCHITECTURE-AND-FAILURE-EXERCISE",
                    "Independently assess the complete overlay and exercise unauthorized cross-job access, scheduler compromise, accelerator and memory residue, storage leakage, management-plane loss, malicious workload, supply-chain substitution, telemetry blind spots and recovery while measuring containment, performance and restoration effects.",
                    "test",
                    True,
                    ["benchmark-scorecard.json", "audit-package-verification.json"],
                )
            ],
        },
        "identity-management-framework": {
            "standards": [
                "ISO-IEC-24760-1",
                "ISO-IEC-24760-2",
                "ISO-IEC-24760-3",
                "ISO-IEC-29100",
                "NIST-SP-800-63-4",
            ],
            "controls": [
                (
                    "ISO-IEC-24760-1",
                    "IDENTITY-CONCEPT-IDENTIFIER-ATTRIBUTE-AND-PRINCIPAL-SEMANTICS",
                    "Use consistent identity, identifier, attribute, principal, entity, assurance and relationship semantics for people, organizations, devices and software; reject alias, reassignment, namespace and correlation ambiguities that would change authorization or privacy outcomes.",
                    ["domain-assurance.json", "data-exposure.json"],
                ),
                (
                    "ISO-IEC-24760-2",
                    "IDENTITY-MANAGEMENT-REFERENCE-ARCHITECTURE",
                    "Trace identity sources, authorities, service providers, relying parties, registries, lifecycle services, federation boundaries and privacy controls to the licensed reference architecture and system requirements.",
                    ["static-architecture.json", "control-assessment.json"],
                ),
                (
                    "ISO-IEC-24760-3",
                    "IDENTITY-LIFECYCLE-PRACTICE-AND-ASSURANCE",
                    "Govern proofing, enrollment, issuance, use, maintenance, recovery, suspension, revocation, deprovisioning and deletion with purpose limitation, data minimization, authoritative reconciliation, separation of duties and retained assurance evidence.",
                    [
                        "process-capability-assessment.json",
                        "lifecycle-traceability.json",
                    ],
                ),
            ],
            "procedures": [
                (
                    "ISO-IEC-24760-3",
                    "IDENTITY-ARCHITECTURE-LIFECYCLE-AND-PRIVACY-ASSESSMENT",
                    "Assess licensed ISO/IEC 24760 criteria across representative person, organization, device and software identities; replay duplicate, recycled, stale, orphaned, over-correlated, cross-domain and prematurely retained identities and require authorized lifecycle closure without implying ISO certification.",
                    "manual",
                    False,
                    ["benchmark-scorecard.json", "audit-package-verification.json"],
                )
            ],
        },
    }
)

_ASSURANCE_PROFILES.update(OPEN_SOURCE_PROFILES)

_ASSURANCE_PROFILES.update(
    {
        "systems-risk-measurement": {
            "standards": [
                "NIST-SP-800-160-1",
                "NIST-SP-800-160-2",
                "NIST-SP-800-37",
                "NIST-SP-800-55-1",
                "NIST-SP-800-55-2",
                "ISO-IEC-27005",
            ],
            "controls": [
                (
                    "NIST-SP-800-160-1",
                    "TRUSTWORTHY-SYSTEM-ENGINEERING",
                    "Bind stakeholder protection needs, architecture decisions, requirements, verification, and lifecycle evidence.",
                    [
                        "static-architecture.json",
                        "security-requirements-coverage.json",
                    ],
                ),
                (
                    "ISO-IEC-27005",
                    "RISK-LIFECYCLE",
                    "Retain scoped risk identification, analysis, evaluation, treatment, acceptance, monitoring, and communication evidence.",
                    ["risk-paths.json", "control-assessment.json"],
                ),
                (
                    "NIST-SP-800-55-1",
                    "MEASURE-SELECTION",
                    "Define decision-linked measures with owners, data quality, collection frequency, targets, and interpretation limits.",
                    ["effectiveness.json", "benchmark-scorecard.json"],
                ),
            ],
            "procedures": [
                (
                    "NIST-SP-800-37",
                    "RMF-LIFECYCLE-REVIEW",
                    "Review categorization, control selection, implementation, assessment, authorization, and continuous monitoring evidence.",
                    "examine",
                    False,
                    ["control-assessment.json", "oscal-system-security-plan.json"],
                ),
            ],
        },
        "security-data-interoperability": {
            "standards": [
                "OASIS-SARIF",
                "OASIS-CSAF",
                "ISO-IEC-20153",
                "ECMA-424",
                "NIST-OSCAL",
                "OPENVEX",
            ],
            "controls": [
                (
                    "OASIS-SARIF",
                    "RESULT-SEMANTICS",
                    "Preserve rule identity, locations, code flows, severity semantics, invocation state, and redaction across SARIF normalization.",
                    ["results.sarif", "audit-package-verification.json"],
                ),
                (
                    "ECMA-424",
                    "BOM-SEMANTICS",
                    "Retain component identity, dependency relationships, hashes, licenses, lifecycle context, and known-unknown accounting.",
                    ["sbom.cdx.json", "artifact-sbom.cdx.json"],
                ),
                (
                    "OASIS-CSAF",
                    "ADVISORY-SEMANTICS",
                    "Preserve product status, vulnerability, remediation, justification, provenance, and revision semantics across advisory exchange.",
                    ["risk-intelligence.json", "closure-plan.json"],
                ),
            ],
            "procedures": [
                (
                    "NIST-OSCAL",
                    "OFFICIAL-SCHEMA-ROUNDTRIP",
                    "Validate positive and negative artifacts against official schemas and verify semantic round trips without field loss.",
                    "test",
                    False,
                    ["benchmark-scorecard.json", "audit-package-verification.json"],
                ),
            ],
        },
        "product-certification": {
            "standards": ["ISO-IEC-15408", "ISO-IEC-18045"],
            "controls": [
                (
                    "ISO-IEC-15408",
                    "TOE-BOUNDARY",
                    "Define the target of evaluation, assumptions, threats, organizational policies, security objectives, and external interfaces.",
                    ["static-architecture.json", "security-requirements-coverage.json"],
                ),
                (
                    "ISO-IEC-15408",
                    "SFR-SAR-TRACEABILITY",
                    "Trace applicable functional and assurance requirements to implementation and evaluator-consumable evidence.",
                    ["control-assessment.json", "audit-package-verification.json"],
                ),
            ],
            "procedures": [
                (
                    "ISO-IEC-18045",
                    "EVALUATION-READINESS",
                    "Independently review evaluator work units, evidence completeness, configuration identity, and unresolved observations.",
                    "examine",
                    False,
                    ["procedure-assessment.json", "audit-package-verification.json"],
                ),
            ],
        },
        "detection-threat-intelligence": {
            "standards": [
                "SIGMA",
                "MITRE-ATTACK",
                "OASIS-STIX",
                "OASIS-TAXII",
            ],
            "controls": [
                (
                    "SIGMA",
                    "DETECTION-AS-CODE",
                    "Retain parseable detection logic, required telemetry, ATT&CK mapping, tests, ownership, tuning, and lifecycle state.",
                    ["domain-assurance.json", "control-assessment.json"],
                ),
                (
                    "OASIS-STIX",
                    "THREAT-OBJECT-PROVENANCE",
                    "Validate threat-object identity, marking, confidence, relationships, versions, provenance, and freshness before use.",
                    ["risk-intelligence.json", "artifact-manifest.json"],
                ),
            ],
            "procedures": [
                (
                    "MITRE-ATTACK",
                    "DETECTION-EFFECTIVENESS",
                    "Execute approved atomic techniques and retain expected telemetry, alert outcome, latency, cleanup, and negative-control evidence.",
                    "dynamic",
                    True,
                    ["benchmark-scorecard.json", "operational-trend.json"],
                ),
                (
                    "OASIS-TAXII",
                    "THREAT-EXCHANGE-INTEROPERABILITY",
                    "Exercise authenticated collection discovery, pagination, version negotiation, replay handling, and STIX exchange.",
                    "test",
                    True,
                    ["benchmark-scorecard.json", "risk-intelligence.json"],
                ),
            ],
        },
        "secure-coding": {
            "standards": [
                "SEI-CERT-C",
                "SEI-CERT-CPP",
                "SEI-CERT-JAVA",
                "MISRA-C",
                "ISO-IEC-TS-17961",
                "ISO-IEC-TR-24772",
            ],
            "controls": [
                (
                    "SEI-CERT-C",
                    "C-RULE-CONFORMANCE",
                    "Map applicable C rules to compiler, static-analysis, review, deviation, and test evidence.",
                    ["finding-validation.json", "code-health.json"],
                ),
                (
                    "SEI-CERT-CPP",
                    "CPP-RULE-CONFORMANCE",
                    "Map applicable C++ rules to compiler, static-analysis, review, deviation, and test evidence.",
                    ["finding-validation.json", "code-health.json"],
                ),
                (
                    "SEI-CERT-JAVA",
                    "JAVA-RULE-CONFORMANCE",
                    "Map applicable Java rules to static-analysis, review, framework, and adversarial-test evidence.",
                    ["finding-validation.json", "framework-coverage.json"],
                ),
            ],
            "procedures": [
                (
                    "ISO-IEC-TR-24772",
                    "LANGUAGE-RULE-BENCHMARK",
                    "Execute positive and negative language-rule cases with rule-level recall, precision, unsupported-rule, and deviation accounting.",
                    "static",
                    False,
                    ["benchmark-scorecard.json", "finding-validation.json"],
                ),
            ],
        },
        "software-testing-vv": {
            "standards": [
                "ISO-IEC-IEEE-29119-1",
                "ISO-IEC-IEEE-29119-2",
                "ISO-IEC-IEEE-29119-3",
                "ISO-IEC-IEEE-29119-4",
                "ISO-IEC-IEEE-29119-5",
                "ISO-IEC-20246",
                "NIST-SP-800-55-1",
            ],
            "controls": [
                (
                    "ISO-IEC-IEEE-29119-2",
                    "TEST-PROCESS",
                    "Retain test basis, strategy, design, environment, data, execution, incidents, completion, and traceability evidence.",
                    ["test-evidence.json", "security-requirements-coverage.json"],
                ),
                (
                    "ISO-IEC-IEEE-29119-3",
                    "TEST-DOCUMENTATION",
                    "Retain controlled test plans, designs, cases, procedures, data requirements, environment requirements, logs, incident reports, status, and completion reports with bidirectional traceability.",
                    ["test-evidence.json", "audit-package-verification.json"],
                ),
                (
                    "ISO-IEC-IEEE-29119-4",
                    "TEST-TECHNIQUE-SELECTION",
                    "Select specification-, structure-, and experience-based techniques from risk, coverage, independence, lifecycle, and oracle needs; record limitations and omitted techniques.",
                    ["test-evidence.json", "procedure-assessment.json"],
                ),
                (
                    "ISO-IEC-20246",
                    "REVIEW-PROCESS",
                    "Retain independent review scope, entry criteria, findings, dispositions, exit criteria, and reviewer identity.",
                    ["finding-validation.json", "audit-package-verification.json"],
                ),
            ],
            "procedures": [
                (
                    "ISO-IEC-IEEE-29119-4",
                    "TEST-PROCESS-CONFORMANCE",
                    "Execute risk-derived positive, negative, boundary, state-transition, decision, combinatorial, experience-based, traceability-break, and omitted-document cases with environment and oracle pinning.",
                    "test",
                    True,
                    [
                        "test-evidence.json",
                        "benchmark-scorecard.json",
                        "benchmark-delta.json",
                    ],
                ),
            ],
        },
        "safety-security": {
            "standards": [
                "IEC-61508",
                "ISO-26262",
                "ISO-14971",
                "RTCA-DO-326A",
                "RTCA-DO-356A",
            ],
            "controls": [
                (
                    "IEC-61508",
                    "SAFETY-SECURITY-TRACEABILITY",
                    "Trace cyber threats and failure modes through hazards, safety functions, integrity levels, controls, verification, and residual risk.",
                    ["risk-paths.json", "security-requirements-coverage.json"],
                ),
                (
                    "ISO-14971",
                    "MEDICAL-BENEFIT-RISK",
                    "Link security threats and control failures to patient harm, risk acceptability, benefit-risk analysis, and post-market evidence.",
                    ["risk-paths.json", "finding-validation.json"],
                ),
                (
                    "ISO-26262",
                    "AUTOMOTIVE-SAFETY-INTERACTION",
                    "Link cybersecurity scenarios to safety goals, ASIL assumptions, dependent failures, verification, and safety cases.",
                    ["risk-paths.json", "release-readiness.json"],
                ),
            ],
            "procedures": [
                (
                    "RTCA-DO-356A",
                    "SECURITY-EFFECTIVENESS-ASSURANCE",
                    "Independently review applicable security risk, architecture, verification, configuration, and safety-impact evidence.",
                    "examine",
                    False,
                    ["procedure-assessment.json", "audit-package-verification.json"],
                ),
            ],
        },
        "specialized-target-validation": {
            "standards": [
                "OWASP-MASVS",
                "CSA-CCM",
                "OWASP-SCVS",
                "ETSI-TS-103-701",
            ],
            "controls": [
                (
                    "OWASP-MASVS",
                    "MOBILE-TARGET-COVERAGE",
                    "Map mobile storage, crypto, authentication, network, platform, code, resilience, and privacy requirements to labeled targets.",
                    ["security-requirements-coverage.json", "domain-assurance.json"],
                ),
                (
                    "CSA-CCM",
                    "CLOUD-ATTACK-PATH-COVERAGE",
                    "Trace identity, network, data, logging, workload, and control-plane findings through contained cloud attack paths.",
                    ["risk-paths.json", "domain-assurance.json"],
                ),
                (
                    "OWASP-SCVS",
                    "SMART-CONTRACT-COVERAGE",
                    "Map smart-contract requirements to compiler, bytecode, runtime, exploitability, and negative-control evidence.",
                    ["finding-validation.json", "domain-assurance.json"],
                ),
            ],
            "procedures": [
                (
                    "ETSI-TS-103-701",
                    "SPECIALIZED-PUBLIC-TARGETS",
                    "Execute pinned mobile, cloud, smart-contract, and IoT targets in disposable authorized environments with cleanup verification.",
                    "dynamic",
                    True,
                    ["benchmark-scorecard.json", "audit-package-verification.json"],
                ),
            ],
        },
        "ai-robustness-impact": {
            "standards": [
                "NIST-AI-100-2",
                "ISO-IEC-42005",
                "ISO-IEC-24029",
                "NIST-AI-RMF",
            ],
            "controls": [
                (
                    "NIST-AI-100-2",
                    "AML-TAXONOMY-COVERAGE",
                    "Cover applicable evasion, poisoning, privacy, misuse, model, data, pipeline, and tool-use attacks with explicit attacker capabilities.",
                    ["llm-adversarial-plan.json", "domain-assurance.json"],
                ),
                (
                    "ISO-IEC-42005",
                    "AI-IMPACT-ASSESSMENT",
                    "Retain lifecycle impact scope, affected stakeholders, foreseeable uses, severity, likelihood, mitigations, monitoring, and approvals.",
                    ["control-assessment.json", "domain-assurance.json"],
                ),
            ],
            "procedures": [
                (
                    "ISO-IEC-24029",
                    "ROBUSTNESS-ASSESSMENT",
                    "Execute approved robustness tests with pinned model, data, perturbation, oracle, repetitions, confidence bounds, and limitations.",
                    "dynamic",
                    True,
                    ["benchmark-scorecard.json", "llm-adversarial-plan.json"],
                ),
            ],
        },
        "privacy-by-design": {
            "standards": [
                "ISO-31700",
                "ISO-IEC-29100",
                "ISO-IEC-27701",
                "ISO-IEC-TS-27560",
                "NIST-PRIVACY-FRAMEWORK",
            ],
            "controls": [
                (
                    "ISO-31700",
                    "PRIVACY-BY-DESIGN",
                    "Translate consumer privacy needs into lifecycle requirements, defaults, controls, notices, choices, tests, and accountable evidence.",
                    ["data-exposure.json", "security-requirements-coverage.json"],
                ),
                (
                    "ISO-IEC-29100",
                    "PRIVACY-PRINCIPLES",
                    "Trace consent, purpose, minimization, use limitation, accuracy, retention, disclosure, security, openness, access, and accountability.",
                    ["data-exposure.json", "control-assessment.json"],
                ),
                (
                    "ISO-IEC-TS-27560",
                    "CONSENT-RECORD-INTEROPERABILITY",
                    "Bind consent receipts to subject, controller, purpose, processing, notice, choices, timestamps, withdrawal, provenance, and retention without leaking unnecessary personal data.",
                    ["data-exposure.json", "procedure-assessment.json"],
                ),
            ],
            "procedures": [
                (
                    "ISO-31700",
                    "PRIVACY-MISUSE-CASES",
                    "Exercise consent withdrawal, deletion, export, retention, secondary use, inference, and dark-pattern negative cases.",
                    "test",
                    True,
                    ["procedure-assessment.json", "data-exposure.json"],
                ),
            ],
        },
        "zero-trust-implementation": {
            "standards": [
                "NIST-SP-800-207",
                "NIST-SP-800-207A",
                "NIST-SP-1800-35",
                "CISA-ZTMM",
            ],
            "controls": [
                (
                    "NIST-SP-1800-35",
                    "IMPLEMENTED-ZTA",
                    "Retain resource, identity, policy-decision, policy-enforcement, telemetry, integration, and migration evidence for the deployed architecture.",
                    ["static-architecture.json", "domain-assurance.json"],
                ),
                (
                    "CISA-ZTMM",
                    "MATURITY-PILLARS",
                    "Assess identity, device, network, application, data, visibility, analytics, automation, orchestration, and governance maturity.",
                    ["control-assessment.json", "operational-trend.json"],
                ),
            ],
            "procedures": [
                (
                    "NIST-SP-1800-35",
                    "ZTA-DECISION-ENFORCEMENT",
                    "Exercise identity, device, context, session, workload, lateral-movement, revocation, and policy-failure scenarios.",
                    "dynamic",
                    True,
                    ["procedure-assessment.json", "risk-paths.json"],
                ),
            ],
        },
    }
)

_ASSURANCE_PROFILES.update(
    {
        "independent-evaluator-assurance": {
            "standards": ["ISO-IEC-17025", "ISO-IEC-17020", "ISO-IEC-17065"],
            "controls": [
                (
                    "ISO-IEC-17025",
                    "METHOD-COMPETENCE",
                    "Retain method validation, analyst competency, measurement traceability, uncertainty, environment, and proficiency evidence for each claimed test scope.",
                    ["audit-package-verification.json", "reproducibility.json"],
                ),
                (
                    "ISO-IEC-17020",
                    "IMPARTIALITY-INDEPENDENCE",
                    "Identify conflicts, separate evaluator and developer authority, and retain independent technical review of material conclusions.",
                    ["trust-policy-attestation.json", "control-assessment.json"],
                ),
                (
                    "ISO-IEC-17065",
                    "CERTIFICATION-BOUNDARY",
                    "Separate test evidence from certification decisions and retain the exact product, version, scheme, evaluator, and claim scope.",
                    ["audit-package-verification.json", "control-assessment.json"],
                ),
            ],
            "procedures": [
                (
                    "ISO-IEC-17025",
                    "QUALIFIED-METHOD-REVIEW",
                    "Review the selected benchmark method, corpus, oracle, competence, calibration, uncertainty, deviations, and independent approval before accepting results.",
                    "examine",
                    False,
                    ["benchmark-scorecard.json", "audit-package-verification.json"],
                ),
            ],
        },
        "ot-system-operations": {
            "standards": [
                "IEC-62443-2-1",
                "IEC-62443-2-4",
                "IEC-62443-3-2",
                "IEC-62443-3-3",
                "NERC-CIP",
                "NISTIR-7628",
            ],
            "controls": [
                (
                    "IEC-62443-2-1",
                    "ASSET-OWNER-PROGRAM",
                    "Retain IACS ownership, inventory, risk, remote access, supplier, patch, backup, incident, and legacy-system exception evidence.",
                    ["control-assessment.json", "operational-trend.json"],
                ),
                (
                    "IEC-62443-3-2",
                    "ZONES-CONDUITS-SL-T",
                    "Trace assets, zones, conduits, threat scenarios, consequence, likelihood, target security levels, and residual risk to architecture evidence.",
                    ["risk-paths.json", "static-architecture.json"],
                ),
                (
                    "NERC-CIP",
                    "BES-APPLICABILITY",
                    "Record bulk-electric-system applicability and retain asset categorization, access, configuration, incident, recovery, and supply-chain evidence.",
                    ["domain-assurance.json", "operational-trend.json"],
                ),
            ],
            "procedures": [
                (
                    "IEC-62443-3-3",
                    "SYSTEM-SECURITY-LEVEL-TEST",
                    "Execute an authorized licensed-requirement conformance assessment for the claimed system security level with safe-state and recovery controls.",
                    "test",
                    True,
                    ["benchmark-scorecard.json", "procedure-assessment.json"],
                ),
            ],
        },
        "healthcare-security": {
            "standards": [
                "HIPAA-SECURITY-RULE",
                "NIST-SP-800-66",
                "HITRUST-CSF",
                "ISO-27799",
            ],
            "controls": [
                (
                    "HIPAA-SECURITY-RULE",
                    "EPHI-SAFEGUARDS",
                    "Trace electronic protected health information through administrative, physical, and technical safeguards, risk decisions, access, audit, integrity, transmission, and contingency controls.",
                    ["data-exposure.json", "control-assessment.json"],
                ),
                (
                    "NIST-SP-800-66",
                    "SECURITY-RULE-MAPPING",
                    "Retain scoped HIPAA implementation-specification mappings to current system controls, evidence owners, deficiencies, and remediation.",
                    ["security-requirements-coverage.json", "closure-plan.json"],
                ),
            ],
            "procedures": [
                (
                    "NIST-SP-800-66",
                    "EPHI-CONTROL-VALIDATION",
                    "Validate role access, emergency access, audit, integrity, transmission protection, backup, restoration, and breach-response paths using authorized synthetic data.",
                    "test",
                    True,
                    ["procedure-assessment.json", "data-exposure.json"],
                ),
            ],
        },
        "airborne-software-assurance": {
            "standards": [
                "RTCA-DO-178C",
                "RTCA-DO-330",
                "RTCA-DO-331",
                "RTCA-DO-332",
                "RTCA-DO-333",
                "RTCA-DO-326A",
                "RTCA-DO-356A",
            ],
            "controls": [
                (
                    "RTCA-DO-178C",
                    "SOFTWARE-LIFECYCLE-DATA",
                    "Bind software level, plans, standards, requirements, design, source, object code, verification, configuration, quality, and certification-liaison evidence.",
                    ["security-requirements-coverage.json", "test-evidence.json"],
                ),
                (
                    "RTCA-DO-330",
                    "TOOL-QUALIFICATION",
                    "Record tool qualification level, operational requirements, validation cases, version identity, configuration, anomalies, and usage constraints.",
                    ["scanner-trust.json", "bundle-qualification.json"],
                ),
                (
                    "RTCA-DO-333",
                    "FORMAL-METHOD-CREDIT",
                    "Define any formal-method verification credit, assumptions, soundness boundary, proof obligations, review independence, and complementary testing.",
                    ["finding-validation.json", "test-evidence.json"],
                ),
            ],
            "procedures": [
                (
                    "RTCA-DO-178C",
                    "OBJECTIVE-TRACEABILITY-REVIEW",
                    "Execute requirements-to-code-to-object-to-test traceability, structural coverage, independence, dead-code, robustness, and problem-report review for the claimed software level.",
                    "test",
                    False,
                    ["security-requirements-coverage.json", "test-evidence.json"],
                ),
            ],
        },
        "federal-configuration-hardening": {
            "standards": ["DISA-STIG", "NIST-SCAP", "CIS-BENCHMARKS"],
            "controls": [
                (
                    "DISA-STIG",
                    "APPLICABLE-STIG-BASELINE",
                    "Pin applicable STIG and SRG releases, assets, severities, check content, exceptions, compensating controls, and POA&M ownership.",
                    ["domain-assurance.json", "control-assessment.json"],
                ),
                (
                    "NIST-SCAP",
                    "AUTOMATED-CHECK-INTEGRITY",
                    "Verify XCCDF, OVAL, CPE, signatures, benchmark identity, tailoring, scanner identity, and result provenance before accepting automated checks.",
                    ["audit-package-verification.json", "benchmark-scorecard.json"],
                ),
                (
                    "DISA-STIG",
                    "STIG-RELEASE-DELTA-APPLICABILITY-AND-DRIFT",
                    "Ingest every approved quarterly release into an immutable baseline; independently review added, removed and changed rules, CPE and platform applicability, automated-to-manual coverage, tailoring and exception effects, then measure configuration drift and remediation durability against the exact assessed asset and release.",
                    ["lifecycle-traceability.json", "operational-trend.json"],
                ),
            ],
            "procedures": [
                (
                    "DISA-STIG",
                    "STIG-SCAP-ASSESSMENT",
                    "Execute the pinned application, operating-system, container, Kubernetes, database, and platform checks against disposable representative targets; reconcile XCCDF and OVAL results with blinded manual-check decisions, inject applicability and engine-disagreement cases, verify exception expiry, perform authorized remediation and rollback in the laboratory, and rescan for durable closure without mutating production assets.",
                    "test",
                    True,
                    ["benchmark-scorecard.json", "procedure-assessment.json"],
                ),
            ],
        },
        "software-quality-evaluation": {
            "standards": [
                "ISO-IEC-25010",
                "ISO-IEC-25023",
                "ISO-IEC-25040",
                "ISO-IEC-25041",
                "ISO-IEC-5055",
            ],
            "controls": [
                (
                    "ISO-IEC-25040",
                    "EVALUATION-DESIGN",
                    "Define evaluation purpose, target, stakeholders, quality requirements, measures, rating rules, resources, schedule, acceptance criteria, limitations, and conclusion process.",
                    ["effectiveness.json", "benchmark-scorecard.json"],
                ),
                (
                    "ISO-IEC-25041",
                    "EVALUATOR-VIEWPOINT",
                    "Retain developer, acquirer, or independent-evaluator viewpoint, inputs, deviations, review authority, and reproducible conclusions.",
                    ["audit-package-verification.json", "finding-validation.json"],
                ),
            ],
            "procedures": [
                (
                    "ISO-IEC-25040",
                    "QUALITY-EVALUATION",
                    "Execute the planned quality evaluation and retain measurements, ratings, uncertainty, anomalies, limitations, conclusion, and independent review evidence.",
                    "test",
                    False,
                    ["effectiveness.json", "benchmark-scorecard.json"],
                ),
            ],
        },
        "incident-management": {
            "standards": [
                "ISO-IEC-27035-1",
                "ISO-IEC-27035-2",
                "ISO-IEC-27035-3",
                "ISO-IEC-IEEE-23612",
                "NIST-SP-800-61",
            ],
            "controls": [
                (
                    "ISO-IEC-27035-1",
                    "INCIDENT-LIFECYCLE",
                    "Retain preparation, detection, reporting, triage, decision, response, recovery, evidence preservation, communications, and lessons-learned records.",
                    ["operational-trend.json", "control-assessment.json"],
                ),
                (
                    "ISO-IEC-IEEE-23612",
                    "SOFTWARE-INCIDENT-TRACEABILITY",
                    "Trace development and operational incidents to affected versions, severity, ownership, corrective action, verification, closure, recurrence, and release decisions.",
                    ["finding-register.json", "closure-plan.json"],
                ),
            ],
            "procedures": [
                (
                    "ISO-IEC-27035-3",
                    "COORDINATED-INCIDENT-EXERCISE",
                    "Execute an authorized detection-through-recovery exercise with evidence custody, escalation, supplier coordination, regulatory decision, restoration, and retrospective review.",
                    "test",
                    True,
                    ["procedure-assessment.json", "operational-trend.json"],
                ),
            ],
        },
        "privacy-impact-assessment": {
            "standards": [
                "ISO-IEC-29134",
                "ISO-31700",
                "ISO-IEC-29100",
                "NIST-PRIVACY-FRAMEWORK",
            ],
            "controls": [
                (
                    "ISO-IEC-29134",
                    "PIA-SCOPE-AND-REPORT",
                    "Retain PII flows, parties, purposes, legal basis, necessity, proportionality, impacts, stakeholder consultation, controls, owners, residual risk, approval, and review triggers.",
                    ["data-exposure.json", "control-assessment.json"],
                ),
                (
                    "ISO-31700",
                    "PIA-DESIGN-TRACE",
                    "Trace privacy impact treatments into requirements, architecture, defaults, interfaces, telemetry, retention, deletion, testing, and release evidence.",
                    ["security-requirements-coverage.json", "risk-paths.json"],
                ),
            ],
            "procedures": [
                (
                    "ISO-IEC-29134",
                    "PIA-NEGATIVE-SCENARIOS",
                    "Exercise unauthorized collection, secondary use, inference, linkage, over-retention, failed deletion, export, objection, consent withdrawal, and processor-boundary scenarios.",
                    "test",
                    True,
                    ["procedure-assessment.json", "data-exposure.json"],
                ),
            ],
        },
        "supply-chain-identity": {
            "standards": [
                "IN-TOTO-ATTESTATION",
                "DSSE",
                "NIST-CPE",
                "ISO-IEC-19770-2",
                "PURL",
                "OSV-SCHEMA",
                "CVE-JSON",
                "ECMA-424",
                "SPDX",
            ],
            "controls": [
                (
                    "IN-TOTO-ATTESTATION",
                    "ATTESTATION-SUBJECT-PREDICATE",
                    "Verify attestation type, subject digest, predicate schema, producer identity, materials, products, environment, policy, freshness, and trust root.",
                    ["security-passport.json", "audit-package-verification.json"],
                ),
                (
                    "DSSE",
                    "ENVELOPE-VERIFICATION",
                    "Verify payload type and bytes before parsing, threshold signatures, signer purpose, key lifecycle, timestamps, revocation, replay protection, and countersignatures.",
                    [
                        "audit-package-verification.json",
                        "trust-policy-attestation.json",
                    ],
                ),
                (
                    "NIST-CPE",
                    "IDENTIFIER-NORMALIZATION",
                    "Retain lossless CPE, SWID, package URL, ecosystem, version, qualifier, CVE, and OSV identities with explicit ambiguity and alias decisions.",
                    ["dependency-surface.json", "risk-intelligence.json"],
                ),
            ],
            "procedures": [
                (
                    "IN-TOTO-ATTESTATION",
                    "SUPPLY-CHAIN-ROUND-TRIP",
                    "Validate signed attestation and SBOM/advisory identifier round trips, type-confusion resistance, subject binding, alias resolution, and unknown-field handling.",
                    "test",
                    False,
                    ["benchmark-scorecard.json", "audit-package-verification.json"],
                ),
            ],
        },
        "threat-model-quality": {
            "standards": [
                "OWASP-THREAT-MODELING",
                "NIST-SP-800-160-1",
                "NIST-SP-800-160-2",
                "CAPEC",
                "MITRE-ATTACK",
            ],
            "controls": [
                (
                    "OWASP-THREAT-MODELING",
                    "FOUR-QUESTIONS",
                    "Retain model scope, assets, actors, data, dependencies, trust boundaries, assumptions, threats, abuse cases, mitigations, verification, residual risk, and review cadence.",
                    ["static-architecture.json", "risk-paths.json"],
                ),
                (
                    "NIST-SP-800-160-1",
                    "DESIGN-DECISION-TRACE",
                    "Trace stakeholder protection needs and threat-model decisions into architecture, requirements, implementation, verification, operations, and accepted residual risk.",
                    ["security-requirements-coverage.json", "closure-plan.json"],
                ),
            ],
            "procedures": [
                (
                    "OWASP-THREAT-MODELING",
                    "MODEL-CHALLENGE",
                    "Conduct an authorized independent challenge for missing assets, boundaries, assumptions, threat paths, bypasses, mitigations, tests, and architecture drift.",
                    "manual",
                    True,
                    ["benchmark-scorecard.json", "llm-adversarial-plan.json"],
                ),
            ],
        },
    }
)

_ASSURANCE_PROFILES.update(
    {
        "software-lifecycle-traceability": {
            "standards": [
                "ISO-IEC-IEEE-12207",
                "ISO-IEC-IEEE-15288",
                "ISO-IEC-IEEE-29148",
            ],
            "controls": [
                (
                    "ISO-IEC-IEEE-12207",
                    "LIFECYCLE-EVIDENCE-CHAIN",
                    "Trace acquisition, development, verification, release, operation, maintenance, and retirement evidence across the software life cycle.",
                    ["lifecycle-traceability.json"],
                ),
                (
                    "ISO-IEC-IEEE-29148",
                    "BIDIRECTIONAL-REQUIREMENTS-TRACE",
                    "Retain bidirectional stakeholder-need, requirement, architecture, implementation, test, and operational traceability with orphan and change-impact gaps.",
                    [
                        "lifecycle-traceability.json",
                        "security-requirements-coverage.json",
                    ],
                ),
            ],
            "procedures": [
                (
                    "ISO-IEC-IEEE-15288",
                    "LIFECYCLE-CHANGE-IMPACT-CHALLENGE",
                    "Mutate approved requirements and lifecycle links and verify that missing downstream architecture, code, test, release, operation, and retirement impacts fail closed.",
                    "test",
                    False,
                    ["benchmark-scorecard.json", "lifecycle-traceability.json"],
                ),
            ],
        },
        "architecture-evaluation-process": {
            "standards": [
                "ISO-IEC-IEEE-42010",
                "ISO-IEC-IEEE-42020",
                "ISO-IEC-IEEE-42030",
                "SEI-ATAM",
            ],
            "controls": [
                (
                    "ISO-IEC-IEEE-42020",
                    "ARCHITECTURE-GOVERNANCE",
                    "Govern architecture concerns, viewpoints, decisions, alternatives, trade-offs, ownership, change, and evaluation throughout the entity life cycle.",
                    ["architecture-evaluation.json", "architecture-history.json"],
                ),
                (
                    "ISO-IEC-IEEE-42030",
                    "SCENARIO-EVALUATION",
                    "Evaluate architecture against stakeholder concerns, quality-attribute scenarios, threat paths, operational evidence, limitations, and independent challenge.",
                    ["architecture-evaluation.json", "risk-paths.json"],
                ),
                (
                    "SEI-ATAM",
                    "UTILITY-TREE-TRADEOFFS",
                    "Prioritize quality-attribute scenarios and retain architectural approaches, sensitivity points, trade-off points, risks, non-risks, themes, dissent, and dispositions.",
                    ["architecture-evaluation.json", "architecture-history.json"],
                ),
            ],
            "procedures": [
                (
                    "SEI-ATAM",
                    "INDEPENDENT-ARCHITECTURE-CHALLENGE",
                    "Execute an independent, scenario-based architecture evaluation and retain evaluator agreement, dissent, trade-offs, risks, and decision dispositions.",
                    "manual",
                    False,
                    ["benchmark-scorecard.json", "architecture-evaluation.json"],
                ),
            ],
        },
        "software-process-capability": {
            "standards": [
                "ISO-IEC-33020",
                "ISO-IEC-TS-33061",
                "ISO-IEC-IEEE-12207",
            ],
            "controls": [
                (
                    "ISO-IEC-33020",
                    "CAPABILITY-MEASUREMENT",
                    "Measure process performance and capability using defined outcomes, evidence sufficiency, reproducibility, governance, and improvement criteria.",
                    ["process-capability-assessment.json"],
                ),
                (
                    "ISO-IEC-TS-33061",
                    "SOFTWARE-PROCESS-ASSESSMENT",
                    "Assess requirements, implementation, verification, release, vulnerability response, incident management, and governance processes against retained evidence.",
                    [
                        "process-capability-assessment.json",
                        "audit-package-verification.json",
                    ],
                ),
            ],
            "procedures": [
                (
                    "ISO-IEC-33020",
                    "ASSESSOR-AGREEMENT",
                    "Blind at least two qualified assessors to prior ratings and measure exact and adjacent-level agreement on a pinned process-evidence corpus.",
                    "manual",
                    False,
                    ["benchmark-scorecard.json", "process-capability-assessment.json"],
                ),
            ],
        },
        "comprehensive-weakness-mapping": {
            "standards": ["MITRE-CWE", "CWE-TOP-25", "CAPEC"],
            "controls": [
                (
                    "MITRE-CWE",
                    "FULL-CATALOG-PIN",
                    "Pin the complete CWE release and retain supported views, deprecated entries, relationships, and source digest instead of limiting analysis to a Top-N list.",
                    ["finding-validation.json", "effectiveness.json"],
                ),
                (
                    "MITRE-CWE",
                    "MAPPING-PRECISION",
                    "Validate weakness mappings at the most specific supportable abstraction and preserve ambiguity, parent-child alternatives, and unmapped findings.",
                    ["finding-validation.json", "benchmark-scorecard.json"],
                ),
            ],
            "procedures": [
                (
                    "MITRE-CWE",
                    "CWE-MAPPING-CONFORMANCE",
                    "Evaluate exact, overly broad, overly narrow, deprecated, ambiguous, architecture, hardware, AI, mobile, and quality-weakness mappings against independently reviewed labels.",
                    "test",
                    False,
                    ["benchmark-scorecard.json"],
                ),
            ],
        },
        "exploit-prioritization-validation": {
            "standards": ["FIRST-EPSS", "CISA-KEV", "CISA-SSVC", "FIRST-CVSS"],
            "controls": [
                (
                    "FIRST-EPSS",
                    "TEMPORAL-CALIBRATION",
                    "Backtest point-in-time exploit probabilities without future-data leakage and retain calibration, coverage, effort, and uncertainty evidence.",
                    ["prioritization-calibration.json", "risk-intelligence.json"],
                ),
                (
                    "CISA-KEV",
                    "KNOWN-EXPLOITED-RESPONSE",
                    "Measure time-to-prioritize, inventory applicability, reachability, impact, remediation, exception, and closure for known-exploited vulnerabilities.",
                    ["prioritization-calibration.json", "closure-plan.json"],
                ),
            ],
            "procedures": [
                (
                    "FIRST-EPSS",
                    "EPSS-KEV-POINT-IN-TIME-BACKTEST",
                    "Replay digest-pinned historical EPSS and KEV snapshots against later outcomes using declared windows, base rates, calibration error, Brier score, recall, effort, and leakage controls.",
                    "test",
                    False,
                    ["benchmark-scorecard.json", "prioritization-calibration.json"],
                ),
            ],
        },
        "ai-lifecycle-data-evaluation": {
            "standards": [
                "ISO-IEC-5338",
                "ISO-IEC-5259-1",
                "ISO-IEC-5259-2",
                "ISO-IEC-5259-3",
                "ISO-IEC-5259-4",
                "ISO-IEC-5259-5",
                "NIST-AI-700-2",
                "UK-AISI-INSPECT",
            ],
            "controls": [
                (
                    "ISO-IEC-5338",
                    "AI-LIFECYCLE-TRACE",
                    "Trace AI-specific conception, data, model, evaluation, deployment, monitoring, change, incident, and retirement processes to accountable evidence.",
                    ["lifecycle-traceability.json", "domain-assurance.json"],
                ),
                (
                    "ISO-IEC-5259-4",
                    "AI-DATA-PROCESS",
                    "Govern dataset provenance, authorization, representativeness, labeling, contamination, drift, quality measures, limitations, and change control.",
                    ["process-capability-assessment.json", "effectiveness.json"],
                ),
            ],
            "procedures": [
                (
                    "NIST-AI-700-2",
                    "ARIA-SCENARIO-REDTEAM-FIELD",
                    "Execute model, red-team, and field evaluation layers with pinned scenarios, human-impact measures, stochastic repetitions, grader reliability, and protected participant data.",
                    "dynamic",
                    True,
                    ["benchmark-scorecard.json", "audit-package-verification.json"],
                ),
            ],
        },
        "supplier-relationship-assurance": {
            "standards": [
                "ISO-IEC-27036-1",
                "ISO-IEC-27036-2",
                "ISO-IEC-27036-3",
                "ISO-IEC-27036-4",
                "NIST-SP-800-161",
            ],
            "controls": [
                (
                    "ISO-IEC-27036-2",
                    "SUPPLIER-RELATIONSHIP-LIFECYCLE",
                    "Retain supplier selection, security requirements, agreements, access, monitoring, change, incident, continuity, termination, and evidence-return obligations.",
                    ["control-assessment.json", "audit-package-verification.json"],
                ),
                (
                    "ISO-IEC-27036-3",
                    "ICT-SUPPLY-CHAIN-TRACE",
                    "Trace hardware, software, service, build, dependency, provenance, vulnerability, and transitive supplier risks to accountable dispositions.",
                    ["dependency-surface.json", "security-passport.json"],
                ),
            ],
            "procedures": [
                (
                    "ISO-IEC-27036-2",
                    "SUPPLIER-EVIDENCE-CHALLENGE",
                    "Independently sample supplier obligations and verify evidence authenticity, freshness, scope, exception approval, incident notification, and termination handling.",
                    "manual",
                    False,
                    ["audit-package-verification.json", "procedure-assessment.json"],
                ),
            ],
        },
        "software-signing-conformance": {
            "standards": ["SIGSTORE", "SLSA", "IN-TOTO-ATTESTATION", "DSSE"],
            "controls": [
                (
                    "SIGSTORE",
                    "IDENTITY-TRANSPARENCY-BINDING",
                    "Verify artifact digest, expected signing identity and issuer, certificate chain, signed timestamps, transparency inclusion, trust root, and bundle schema.",
                    [
                        "trust-policy-attestation.json",
                        "audit-package-verification.json",
                    ],
                ),
                (
                    "SLSA",
                    "PROVENANCE-VERIFIER-BINDING",
                    "Verify provenance signature, builder identity, source repository, immutable revision, build parameters, dependencies, subject digest, and policy level.",
                    ["security-passport.json", "audit-package-verification.json"],
                ),
            ],
            "procedures": [
                (
                    "SIGSTORE",
                    "CLIENT-CONFORMANCE-NEGATIVE-CASES",
                    "Run official client conformance and provenance-verifier negative cases for invalid roots, identities, inclusion proofs, timestamps, subjects, builders, sources, and mutable references.",
                    "test",
                    False,
                    ["benchmark-scorecard.json", "audit-package-verification.json"],
                ),
            ],
        },
        "remote-attestation-assurance": {
            "standards": ["IETF-RFC-9334", "IETF-RFC-9711", "NIST-SP-800-207A"],
            "controls": [
                (
                    "IETF-RFC-9334",
                    "RATS-ROLE-AND-POLICY-BINDING",
                    "Bind attester, verifier, relying party, evidence, endorsements, reference values, appraisal policy, results, freshness, and trust anchors.",
                    ["trust-policy-attestation.json", "control-assessment.json"],
                ),
                (
                    "IETF-RFC-9711",
                    "EAT-CLAIM-VALIDATION",
                    "Validate token profile, issuer, audience, nonce or freshness, measurements, submodules, key confirmation, privacy, signature, and appraisal use.",
                    [
                        "trust-policy-attestation.json",
                        "audit-package-verification.json",
                    ],
                ),
            ],
            "procedures": [
                (
                    "IETF-RFC-9334",
                    "REMOTE-ATTESTATION-NEGATIVE-CASES",
                    "Reject replayed, stale, forged, mismatched, downgraded, privacy-violating, unendorsed, and policy-incompatible evidence and attestation results.",
                    "dynamic",
                    True,
                    ["benchmark-scorecard.json", "trust-policy-attestation.json"],
                ),
            ],
        },
        "ot-patch-management": {
            "standards": ["IEC-62443-2-3", "IEC-62443-2-1", "IEC-62443-4-1"],
            "controls": [
                (
                    "IEC-62443-2-3",
                    "IACS-PATCH-PROGRAM",
                    "Govern patch identification, supplier information, risk and safety review, testing, approval, deployment, rollback, compensating controls, inventory, and status communication.",
                    ["control-assessment.json", "operational-trend.json"],
                ),
                (
                    "IEC-62443-4-1",
                    "SUPPLIER-PATCH-EVIDENCE",
                    "Retain supplier vulnerability, patch-development, validation, distribution, integrity, support-window, and end-of-life evidence.",
                    ["risk-intelligence.json", "audit-package-verification.json"],
                ),
                (
                    "IEC-62443-2-3",
                    "PATCH-SAFETY-AVAILABILITY-AND-COMPENSATION-OUTCOMES",
                    "Bind each advisory and patch to affected firmware and asset identities, exploit and safety impact, vendor qualification, maintenance window, redundancy and safe-state constraints, acceptance tests, rollback triggers, compensating-control owner and expiry, deployment latency, availability effects, residual risk and observed recurrence.",
                    ["enterprise-risk-assessment.json", "operational-trend.json"],
                ),
            ],
            "procedures": [
                (
                    "IEC-62443-2-3",
                    "PATCH-DEPLOYMENT-ROLLBACK-EXERCISE",
                    "Execute an authorized representative IACS exercise from signed supplier advisory through applicability, safety and availability review, laboratory qualification, staged deployment, health and process-invariant checks, induced partial failure, rollback, compensating-control activation and expiry, restoration, reconciliation and longitudinal recurrence review.",
                    "dynamic",
                    True,
                    ["benchmark-scorecard.json", "operational-trend.json"],
                ),
            ],
        },
        "continuing-airworthiness-security": {
            "standards": [
                "RTCA-DO-355A",
                "RTCA-DO-326A",
                "RTCA-DO-356A",
                "SAE-ARP5150B",
                "SAE-ARP5151B",
            ],
            "controls": [
                (
                    "RTCA-DO-355A",
                    "CONTINUING-AIRWORTHINESS-SECURITY",
                    "Maintain in-service security monitoring, vulnerability intake, safety impact, configuration effectivity, mitigation, approval, communication, and continuing-airworthiness records.",
                    ["operational-trend.json", "control-assessment.json"],
                ),
                (
                    "RTCA-DO-326A",
                    "AIRWORTHINESS-LIFECYCLE-HANDOFF",
                    "Trace certified design assumptions, security requirements, verification, residual risk, operational limitations, and change triggers into continuing airworthiness.",
                    ["lifecycle-traceability.json", "audit-package-verification.json"],
                ),
                (
                    "SAE-ARP5150B",
                    "IN-SERVICE-SAFETY-SECURITY-SIGNAL-AND-FLEET-EFFECTIVITY",
                    "Join transport-airplane service events, reliability and maintenance data, security intelligence and vulnerability reports to certified functions, hazards, safety objectives, aircraft and equipment configurations, fleet effectivity, interim limitations, corrective actions, approval authority, operator communication and verified field effectiveness.",
                    ["operational-trend.json", "lifecycle-traceability.json"],
                ),
                (
                    "SAE-ARP5151B",
                    "GENERAL-AVIATION-ROTORCRAFT-SERVICE-DATA-AND-CORRECTIVE-ACTION",
                    "Adapt continuing assessment to general-aviation and rotorcraft operating populations, sparse and heterogeneous service data, operator and maintainer communication, configuration identification, uncertainty, lessons learned and timely corrective action without treating transport-airplane evidence as automatically representative.",
                    ["enterprise-risk-assessment.json", "procedure-assessment.json"],
                ),
            ],
            "procedures": [
                (
                    "RTCA-DO-355A",
                    "IN-SERVICE-SECURITY-EVENT-EXERCISE",
                    "Exercise authorized transport-airplane and general-aviation or rotorcraft in-service events from intake through independent security and safety triage, signal correlation, affected-tail and equipment configuration identification, hazard reassessment, interim action, approved corrective action, operator and maintainer communication, fleet deployment, effectiveness monitoring, recurrence detection and closure.",
                    "manual",
                    True,
                    ["benchmark-scorecard.json", "procedure-assessment.json"],
                ),
            ],
        },
        "maritime-cyber-resilience": {
            "standards": ["IACS-UR-E26", "IACS-UR-E27", "IEC-62443-3-3"],
            "controls": [
                (
                    "IACS-UR-E26",
                    "SHIP-CYBER-RESILIENCE",
                    "Retain ship-level asset, zone, network, access, detection, response, recovery, maintenance, survey, and evidence requirements for applicable vessels.",
                    ["domain-assurance.json", "control-assessment.json"],
                ),
                (
                    "IACS-UR-E27",
                    "ONBOARD-SYSTEM-RESILIENCE",
                    "Assess on-board equipment identification, secure design, interface protection, least privilege, logging, integrity, update, recovery, and supplier evidence.",
                    ["domain-assurance.json", "audit-package-verification.json"],
                ),
            ],
            "procedures": [
                (
                    "IACS-UR-E26",
                    "SHIP-SYSTEM-RESILIENCE-SURVEY",
                    "Execute an authorized representative survey of ship and on-board system segmentation, remote access, detection, degraded operation, restoration, and evidence traceability.",
                    "dynamic",
                    True,
                    ["benchmark-scorecard.json", "procedure-assessment.json"],
                ),
            ],
        },
        "financial-messaging-security": {
            "standards": ["SWIFT-CSCF", "ISO-IEC-27001", "NIST-CSF"],
            "controls": [
                (
                    "SWIFT-CSCF",
                    "MANDATORY-CONTROL-SCOPE",
                    "Pin the applicable SWIFT architecture type and assess every mandatory control with scoped, fresh, independently reviewable evidence and explicit exceptions.",
                    ["control-assessment.json", "audit-package-verification.json"],
                ),
                (
                    "SWIFT-CSCF",
                    "TRANSACTION-ENVIRONMENT-RESILIENCE",
                    "Assess environment segregation, attack-surface reduction, access, credential protection, anomaly detection, transaction integrity, response, and recovery.",
                    ["domain-assurance.json", "operational-trend.json"],
                ),
                (
                    "SWIFT-CSCF",
                    "ANNUAL-CSCF-DELTA-SIGNIFICANT-CHANGE-AND-RELIANCE",
                    "Bind the assessment to the current CSCF and Independent Assessment Framework, BIC and connectivity architecture, mandatory and advisory applicability, prior-year findings and evidence reliance; independently evaluate framework deltas and significant changes, prohibit evidence reuse beyond the permitted cycle, and retain assessor competence, independence, sampling and KYC-SA handoff decisions.",
                    ["lifecycle-traceability.json", "audit-package-verification.json"],
                ),
            ],
            "procedures": [
                (
                    "SWIFT-CSCF",
                    "INDEPENDENT-CSCF-ASSESSMENT",
                    "Perform a policy-pinned annual independent assessment with architecture-specific scope, complete mandatory-control applicability, current-versus-prior CSCF delta, significant-change detection, bounded prior-evidence reliance, assessor competence and independence, evidence authenticity, design and operating-effectiveness sampling, transaction and recovery scenarios, exceptions, findings, remediation, retest and KYC-SA attestation handoff.",
                    "manual",
                    False,
                    ["benchmark-scorecard.json", "audit-package-verification.json"],
                ),
            ],
        },
    }
)

_ASSURANCE_PROFILES.update(
    {
        "devsecops-maturity": {
            "standards": ["OWASP-DSOVS", "OWASP-DSOMM"],
            "controls": [
                (
                    "OWASP-DSOVS",
                    "DEVSECOPS-VERIFICATION-MATURITY",
                    "Assess every applicable DevSecOps verification control against retained, scoped evidence and independently reviewed maturity ratings.",
                    ["maturity-model-assessment.json"],
                ),
                (
                    "OWASP-DSOMM",
                    "DEVSECOPS-CAPABILITY-IMPROVEMENT",
                    "Measure current and target DevSecOps capabilities, accountable improvements, exceptions, and evidence freshness without self-attested inflation.",
                    ["maturity-model-assessment.json"],
                ),
            ],
            "procedures": [
                (
                    "OWASP-DSOMM",
                    "DEVSECOPS-BLINDED-REASSESSMENT",
                    "Blind independent reviewers to prior ratings and compare evidence-backed maturity outcomes across representative delivery teams.",
                    "manual",
                    False,
                    ["maturity-model-assessment.json", "benchmark-scorecard.json"],
                )
            ],
        },
        "test-maturity": {
            "standards": ["TMMI", "ISO-IEC-33020"],
            "controls": [
                (
                    "TMMI",
                    "TEST-PROCESS-MATURITY",
                    "Assess test policy, planning, monitoring, design, environment, non-functional testing, defect prevention, and optimization using retained evidence.",
                    ["maturity-model-assessment.json"],
                ),
                (
                    "ISO-IEC-33020",
                    "TEST-CAPABILITY-TRACE",
                    "Trace test maturity ratings to process outcomes, objective evidence, capability attributes, owners, and improvement actions.",
                    [
                        "maturity-model-assessment.json",
                        "process-capability-assessment.json",
                    ],
                ),
            ],
            "procedures": [
                (
                    "TMMI",
                    "TMMI-INDEPENDENT-ASSESSMENT",
                    "Reassess a pinned test-process evidence set with qualified independent reviewers and measure agreement and rating drift.",
                    "manual",
                    False,
                    ["maturity-model-assessment.json", "benchmark-scorecard.json"],
                )
            ],
        },
        "ai-conformity-quality": {
            "standards": [
                "ISO-IEC-42006",
                "ISO-IEC-25059",
                "ISO-IEC-TR-24027",
                "ISO-IEC-TR-24028",
                "CSA-AICM",
            ],
            "controls": [
                (
                    "ISO-IEC-25059",
                    "AI-QUALITY-MODEL",
                    "Define and measure context-specific AI quality characteristics, limits, uncertainty, failure modes, human impact, and acceptance criteria.",
                    ["external-conformity-assessment.json", "benchmark-scorecard.json"],
                ),
                (
                    "ISO-IEC-42006",
                    "AI-CONFORMITY-INDEPENDENCE",
                    "Retain scoped AI management-system conformity evidence with assessor competence, impartiality, method, validity period, and unresolved findings.",
                    ["external-conformity-assessment.json"],
                ),
            ],
            "procedures": [
                (
                    "ISO-IEC-TR-24027",
                    "AI-BIAS-TRUST-CHALLENGE",
                    "Evaluate representative bias, robustness, explainability, misuse, uncertainty, and human-oversight scenarios with repeated trials and independent acceptance criteria.",
                    "test",
                    True,
                    ["benchmark-scorecard.json", "external-conformity-assessment.json"],
                )
            ],
        },
        "security-automation-interoperability": {
            "standards": ["OASIS-CACAO", "OASIS-OPENC2", "OCSF"],
            "controls": [
                (
                    "OASIS-CACAO",
                    "PLAYBOOK-ROUND-TRIP",
                    "Validate lossless security-playbook parsing, serialization, version handling, signatures, extensions, and negative fixtures.",
                    ["security-automation-interoperability.json"],
                ),
                (
                    "OASIS-OPENC2",
                    "COMMAND-TELEMETRY-SEMANTICS",
                    "Preserve OpenC2 command intent and correlate execution outcomes to normalized OCSF events without silent semantic loss.",
                    ["security-automation-interoperability.json"],
                ),
            ],
            "procedures": [
                (
                    "OCSF",
                    "AUTOMATION-INTEROP-CONFORMANCE",
                    "Execute positive, negative, downgrade, unknown-field, round-trip, and semantic-equivalence cases across pinned CACAO, OpenC2, and OCSF implementations.",
                    "test",
                    True,
                    [
                        "security-automation-interoperability.json",
                        "benchmark-scorecard.json",
                    ],
                )
            ],
        },
        "cloud-independent-assurance": {
            "standards": ["CSA-STAR", "CSA-CCM"],
            "controls": [
                (
                    "CSA-STAR",
                    "INDEPENDENT-CLOUD-ASSURANCE",
                    "Bind STAR level, CAIQ or CCM scope, assessor independence, validity, findings, exceptions, and shared-responsibility boundaries to retained evidence.",
                    ["external-conformity-assessment.json"],
                ),
                (
                    "CSA-CCM",
                    "CLOUD-CONTROL-SCOPE",
                    "Map applicable cloud controls to services, regions, tenants, suppliers, inherited controls, implementation evidence, and customer responsibilities.",
                    ["external-conformity-assessment.json", "control-assessment.json"],
                ),
            ],
            "procedures": [
                (
                    "CSA-STAR",
                    "STAR-CAIQ-EVIDENCE-CHALLENGE",
                    "Sample declared cloud controls and independently validate evidence authenticity, scope, freshness, operating effectiveness, exceptions, and public registry claims.",
                    "manual",
                    False,
                    ["external-conformity-assessment.json", "benchmark-scorecard.json"],
                )
            ],
        },
        "federal-vulnerability-disclosure": {
            "standards": ["NIST-SP-800-216", "ISO-IEC-29147", "ISO-IEC-30111"],
            "controls": [
                (
                    "NIST-SP-800-216",
                    "VDP-GOVERNANCE",
                    "Retain vulnerability disclosure scope, safe harbor, intake, validation, coordination, remediation, communication, metrics, and escalation evidence.",
                    ["external-conformity-assessment.json"],
                ),
                (
                    "ISO-IEC-30111",
                    "VULNERABILITY-HANDLING-TRACE",
                    "Trace reported vulnerabilities through triage, root cause, affected products, remediation, advisory, verification, exceptions, and closure.",
                    ["external-conformity-assessment.json", "closure-plan.json"],
                ),
            ],
            "procedures": [
                (
                    "NIST-SP-800-216",
                    "VDP-END-TO-END-EXERCISE",
                    "Exercise an authorized disclosure from researcher intake through validation, coordination, remediation, communication, and closure with time-bound evidence.",
                    "manual",
                    True,
                    [
                        "external-conformity-assessment.json",
                        "procedure-assessment.json",
                    ],
                )
            ],
        },
        "consumer-product-regulation": {
            "standards": ["UK-PSTI", "ETSI-EN-18031"],
            "controls": [
                (
                    "UK-PSTI",
                    "PRODUCT-APPLICABILITY-AND-DUTIES",
                    "Document product, role, market, exemption, support period, credential, disclosure, statement-of-compliance, and records obligations with legal review.",
                    ["external-conformity-assessment.json"],
                ),
                (
                    "ETSI-EN-18031",
                    "RADIO-EQUIPMENT-CYBERSECURITY",
                    "Trace applicable radio-equipment cybersecurity requirements to product design, data, fraud, interfaces, tests, technical documentation, and conformity evidence.",
                    ["external-conformity-assessment.json"],
                ),
            ],
            "procedures": [
                (
                    "ETSI-EN-18031",
                    "PRODUCT-CONFORMITY-NEGATIVE-CASES",
                    "Test default credentials, update, disclosure, data protection, fraud, interface abuse, downgrade, recovery, and documentation cases on representative product configurations.",
                    "dynamic",
                    True,
                    ["benchmark-scorecard.json", "external-conformity-assessment.json"],
                )
            ],
        },
        "detection-product-evaluation": {
            "standards": ["MITRE-ATTACK-EVALUATIONS", "MITRE-ATTACK"],
            "controls": [
                (
                    "MITRE-ATTACK-EVALUATIONS",
                    "EVALUATION-INGESTION",
                    "Ingest pinned evaluation results without converting visibility, telemetry, protection, configuration, or vendor-context qualifiers into unsupported detection claims.",
                    ["external-conformity-assessment.json", "benchmark-scorecard.json"],
                ),
                (
                    "MITRE-ATTACK",
                    "TECHNIQUE-REPLAY-TRACE",
                    "Trace evaluated techniques and sub-techniques to replay fixtures, data sources, analytics, expected observations, misses, false positives, and latency.",
                    ["external-conformity-assessment.json", "benchmark-scorecard.json"],
                ),
            ],
            "procedures": [
                (
                    "MITRE-ATTACK-EVALUATIONS",
                    "EVALUATION-REPLAY",
                    "Replay an authorized digest-pinned subset with declared configuration and measure analytic coverage, false positives, latency, visibility, and protection separately.",
                    "dynamic",
                    True,
                    ["benchmark-scorecard.json", "external-conformity-assessment.json"],
                )
            ],
        },
        "external-maturity-comparison": {
            "standards": ["BSIMM", "CMMI-DEV", "OWASP-DSOMM", "TMMI"],
            "controls": [
                (
                    "BSIMM",
                    "LICENSED-NORMATIVE-EVIDENCE",
                    "Pin licensed normative or empirical model editions, permitted use, requirement identifiers, interpretation decisions, and source digests without redistributing restricted text.",
                    [
                        "maturity-model-assessment.json",
                        "external-conformity-assessment.json",
                    ],
                ),
                (
                    "CMMI-DEV",
                    "COHORT-COMPARISON-GOVERNANCE",
                    "Compare maturity only against compatible, sufficiently sized, anonymized cohorts with declared selection, normalization, uncertainty, date, and prohibited ranking claims.",
                    ["maturity-model-assessment.json"],
                ),
            ],
            "procedures": [
                (
                    "BSIMM",
                    "EXTERNAL-MATURITY-CALIBRATION",
                    "Independently calibrate internal ratings against licensed model criteria and a compatible external cohort while retaining assessor agreement and uncertainty.",
                    "manual",
                    False,
                    ["maturity-model-assessment.json", "benchmark-scorecard.json"],
                )
            ],
        },
    }
)

_ASSURANCE_PROFILES.update(
    {
        "cloud-native-api-assurance": {
            "standards": [
                "NIST-SP-800-228",
                "NIST-SP-800-204",
                "NIST-SP-800-204A",
                "NIST-SP-800-204B",
                "NIST-SP-800-204C",
                "NIST-SP-800-233",
                "NISTIR-8505",
            ],
            "controls": [
                (
                    "NIST-SP-800-228",
                    "API-LIFECYCLE-CONTROLS",
                    "Trace API inventory, ownership, schema, identity, authorization, input, rate, gateway, data, logging, version, deprecation, and runtime controls to lifecycle evidence.",
                    ["application-contract-analysis.json", "risk-paths.json"],
                ),
                (
                    "NIST-SP-800-204C",
                    "DEVSECOPS-CODE-TYPES",
                    "Assess application, service, infrastructure, policy, and observability code through governed build, verification, deployment, and runtime evidence.",
                    ["domain-assurance.json", "release-readiness.json"],
                ),
                (
                    "NIST-SP-800-233",
                    "SERVICE-MESH-THREAT-PROFILE",
                    "Map proxy topology, trust boundaries, control and data planes, workload identity, policy distribution, bypass paths, downgrade, and failure modes.",
                    ["static-architecture.json", "risk-paths.json"],
                ),
            ],
            "procedures": [
                (
                    "NIST-SP-800-228",
                    "API-MESH-ADVERSARIAL-CONFORMANCE",
                    "Exercise object, function, property, tenant, identity, token, gateway, sidecar, policy, egress, replay, downgrade, and fail-open scenarios on a disposable authorized target.",
                    "dynamic",
                    True,
                    ["benchmark-scorecard.json", "application-contract-analysis.json"],
                )
            ],
        },
        "supply-chain-transparency-consumer": {
            "standards": [
                "IETF-RFC-9942",
                "IETF-RFC-9943",
                "OPENSSF-S2C2F",
                "NTIA-SBOM-MINIMUM-ELEMENTS",
                "SLSA",
            ],
            "controls": [
                (
                    "IETF-RFC-9943",
                    "TRANSPARENT-SIGNED-STATEMENTS",
                    "Verify signed statement registration, issuer authorization, transparency-service policy, receipts, inclusion, consistency, history, revocation context, and artifact binding.",
                    [
                        "security-automation-interoperability.json",
                        "security-passport.json",
                    ],
                ),
                (
                    "OPENSSF-S2C2F",
                    "DEPENDENCY-CONSUMPTION",
                    "Govern dependency discovery, selection, acquisition, verification, inventory, update, substitution defense, quarantine, exceptions, and compromise response.",
                    ["dependency-surface.json", "closure-plan.json"],
                ),
                (
                    "NTIA-SBOM-MINIMUM-ELEMENTS",
                    "SBOM-MINIMUM-ELEMENTS",
                    "Validate required component fields, dependency relationships, timestamp, authorship, machine readability, generation practices, known unknowns, and supplier handoff.",
                    ["sbom.cdx.json", "artifact-sbom.cdx.json"],
                ),
            ],
            "procedures": [
                (
                    "IETF-RFC-9943",
                    "SCITT-CONSUMER-CHALLENGE",
                    "Run valid, invalid, stale, replayed, substituted, equivocating, revoked, incomplete-history, and unauthorized-issuer cases with pinned trust roots and independent receipts.",
                    "test",
                    True,
                    [
                        "security-automation-interoperability.json",
                        "benchmark-scorecard.json",
                    ],
                )
            ],
        },
        "ai-agentic-testing": {
            "standards": [
                "OWASP-AGENTIC-TOP-10",
                "ISO-IEC-TR-29119-11",
                "ISO-IEC-TS-42119-2",
                "NIST-AI-RMF",
            ],
            "controls": [
                (
                    "OWASP-AGENTIC-TOP-10",
                    "AGENTIC-RISK-COVERAGE",
                    "Map agent goals, tool authority, memory, identity, delegation, communication, environment, human oversight, cascading failures, and shutdown paths to adversarial tests.",
                    ["llm-adversarial-plan.json", "domain-assurance.json"],
                ),
                (
                    "ISO-IEC-TS-42119-2",
                    "RISK-BASED-AI-TEST-DESIGN",
                    "Define AI risk hypotheses, statistical power, test oracle, sampling, repetitions, uncertainty, subgroup coverage, utility retention, acceptance, and residual-risk limits.",
                    ["test-evidence.json", "benchmark-scorecard.json"],
                ),
            ],
            "procedures": [
                (
                    "ISO-IEC-TR-29119-11",
                    "STOCHASTIC-AGENTIC-CHALLENGE",
                    "Repeat controlled direct, indirect, memory, tool, privilege, exfiltration, deception, denial, recovery, and utility cases across pinned models and environments.",
                    "dynamic",
                    True,
                    ["llm-adversarial-plan.json", "benchmark-scorecard.json"],
                )
            ],
        },
        "vulnerability-intake-patch-operations": {
            "standards": [
                "IETF-RFC-9116",
                "NIST-SP-800-40",
                "NIST-SP-800-216",
                "ISO-IEC-29147",
                "ISO-IEC-30111",
            ],
            "controls": [
                (
                    "IETF-RFC-9116",
                    "SECURITY-TXT-DISCOVERY",
                    "Validate canonical location, media type, contact, expiry, canonical URI, language, policy, acknowledgments, encryption, signature, redirects, caching, and parser safety.",
                    ["benchmark-scorecard.json", "closure-plan.json"],
                ),
                (
                    "NIST-SP-800-40",
                    "ENTERPRISE-PATCH-MANAGEMENT",
                    "Govern asset discovery, vulnerability intelligence, risk prioritization, testing, rollout, rollback, emergency change, exceptions, unsupported assets, verification, and effectiveness metrics.",
                    ["closure-plan.json", "operational-trend.json"],
                ),
            ],
            "procedures": [
                (
                    "NIST-SP-800-40",
                    "DISCLOSURE-TO-PATCH-DRILL",
                    "Exercise security.txt discovery through triage, affected-product analysis, remediation, staged deployment, rollback, advisory, verification, exception expiry, and closure.",
                    "test",
                    True,
                    [
                        "closure-plan.json",
                        "operational-trend.json",
                        "benchmark-scorecard.json",
                    ],
                )
            ],
        },
        "runtime-contract-interoperability": {
            "standards": [
                "OPENAPI-SPECIFICATION",
                "ASYNCAPI-SPECIFICATION",
                "GRAPHQL-SPECIFICATION",
                "JSON-SCHEMA",
                "OPENTELEMETRY-SEMCONV",
            ],
            "controls": [
                (
                    "OPENAPI-SPECIFICATION",
                    "API-CONTRACT-ROUND-TRIP",
                    "Validate schema resolution, dialect, authentication declarations, operation identity, request and response semantics, examples, extensions, downgrade handling, and lossless round trips.",
                    [
                        "security-automation-interoperability.json",
                        "application-contract-analysis.json",
                    ],
                ),
                (
                    "OPENTELEMETRY-SEMCONV",
                    "TELEMETRY-SEMANTIC-INTEGRITY",
                    "Preserve trace, metric, log, resource, span, event, error, network, service, and messaging semantics while enforcing redaction and trust-boundary policy.",
                    ["security-automation-interoperability.json", "data-exposure.json"],
                ),
            ],
            "procedures": [
                (
                    "JSON-SCHEMA",
                    "CONTRACT-TELEMETRY-CONFORMANCE",
                    "Execute official positive and negative fixtures, reference cycles, unknown keywords, coercion, ambiguity, version drift, trace propagation, baggage injection, redaction, and round-trip cases.",
                    "test",
                    True,
                    [
                        "security-automation-interoperability.json",
                        "benchmark-scorecard.json",
                    ],
                )
            ],
        },
        "uk-cyber-resilience": {
            "standards": ["NCSC-CAF", "NCSC-CYBER-ESSENTIALS"],
            "controls": [
                (
                    "NCSC-CAF",
                    "ESSENTIAL-FUNCTION-OUTCOMES",
                    "Scope essential functions and assess governance, protection, detection, response, recovery, dependencies, threat capability, profile targets, and indicators of good practice.",
                    ["external-conformity-assessment.json", "operational-trend.json"],
                ),
                (
                    "NCSC-CYBER-ESSENTIALS",
                    "ESSENTIAL-TECHNICAL-CONTROLS",
                    "Assess firewalls, secure configuration, security updates, user access control, malware protection, scope, sampling, exceptions, and assessor evidence.",
                    ["external-conformity-assessment.json", "control-assessment.json"],
                ),
            ],
            "procedures": [
                (
                    "NCSC-CAF",
                    "CAF-INDEPENDENT-CHALLENGE",
                    "Independently sample outcome and indicator claims against current, scoped, attributable evidence and record assessor agreement, gaps, profile variance, and residual risk.",
                    "manual",
                    False,
                    ["external-conformity-assessment.json", "benchmark-scorecard.json"],
                )
            ],
        },
        "australian-essential-eight": {
            "standards": ["ASD-ESSENTIAL-EIGHT"],
            "controls": [
                (
                    "ASD-ESSENTIAL-EIGHT",
                    "CONSISTENT-MATURITY-LEVEL",
                    "Assess all eight mitigations at a common target maturity, including scope, exceptions, compensating controls, evidence freshness, unsupported systems, restoration tests, and tradecraft assumptions.",
                    ["maturity-model-assessment.json", "control-assessment.json"],
                )
            ],
            "procedures": [
                (
                    "ASD-ESSENTIAL-EIGHT",
                    "ESSENTIAL-EIGHT-ASSESSOR-REPLAY",
                    "Blind two qualified assessors to prior ratings and compare maturity decisions across representative systems, users, privileged paths, patch records, controls, and recovery evidence.",
                    "manual",
                    False,
                    ["maturity-model-assessment.json", "benchmark-scorecard.json"],
                )
            ],
        },
        "cisa-cross-sector-cpg": {
            "standards": ["CISA-CPG"],
            "controls": [
                (
                    "CISA-CPG",
                    "PRIORITIZED-CROSS-SECTOR-OUTCOMES",
                    "Assess applicable prioritized goals across account, device, data, vulnerability, supply-chain, architecture, monitoring, response, and recovery outcomes with owners and measurable evidence.",
                    ["control-assessment.json", "operational-trend.json"],
                )
            ],
            "procedures": [
                (
                    "CISA-CPG",
                    "CPG-EFFECTIVENESS-SAMPLING",
                    "Challenge a risk-selected sample of declared outcomes through configuration inspection, identity and recovery tests, telemetry review, exceptions, and independent evidence validation.",
                    "test",
                    True,
                    ["control-assessment.json", "benchmark-scorecard.json"],
                )
            ],
        },
        "automotive-software-update": {
            "standards": ["ISO-24089", "UNECE-R156", "ISO-SAE-21434"],
            "controls": [
                (
                    "ISO-24089",
                    "UPDATE-ENGINEERING-LIFECYCLE",
                    "Trace update need, compatibility, dependency, safety, security, authenticity, integrity, campaign, vehicle state, installation, rollback, recovery, records, and post-update monitoring.",
                    ["release-readiness.json", "security-passport.json"],
                )
            ],
            "procedures": [
                (
                    "ISO-24089",
                    "VEHICLE-UPDATE-NEGATIVE-CASES",
                    "Test wrong vehicle, incompatible version, dependency failure, interrupted install, downgrade, signature failure, rollback, recovery, safety interaction, and audit-record scenarios.",
                    "dynamic",
                    True,
                    ["benchmark-scorecard.json", "release-readiness.json"],
                )
            ],
        },
        "energy-product-security": {
            "standards": [
                "IEC-62351",
                "UL-2900",
                "NERC-CIP",
                "NISTIR-7628",
                "ISO-IEC-27019",
            ],
            "controls": [
                (
                    "IEC-62351",
                    "POWER-PROTOCOL-SECURITY",
                    "Assess role-based access, key management, authentication, integrity, confidentiality, event logging, network and system management, secure profiles, legacy boundaries, and availability constraints.",
                    ["domain-assurance.json", "procedure-assessment.json"],
                ),
                (
                    "UL-2900",
                    "PRODUCT-SOFTWARE-ASSURANCE",
                    "Retain product attack surface, weakness, vulnerability, malware, fuzzing, access, cryptography, update, communication, privacy, resource-exhaustion, and residual-risk test evidence.",
                    ["external-conformity-assessment.json", "benchmark-scorecard.json"],
                ),
            ],
            "procedures": [
                (
                    "IEC-62351",
                    "ENERGY-PRODUCT-CONFORMANCE-CHALLENGE",
                    "Execute licensed protocol and product test cases including malformed traffic, replay, role bypass, key rollover, downgrade, denial, recovery, logging, and safe-state observations in an isolated laboratory.",
                    "dynamic",
                    True,
                    ["benchmark-scorecard.json", "external-conformity-assessment.json"],
                )
            ],
        },
    }
)

_ASSURANCE_PROFILES.update(
    {
        "modern-sbom-assurance": {
            "standards": [
                "CISA-SBOM-MINIMUM-ELEMENTS",
                "NTIA-SBOM-MINIMUM-ELEMENTS",
                "OPENSSF-S2C2F",
            ],
            "controls": [
                (
                    "CISA-SBOM-MINIMUM-ELEMENTS",
                    "CURRENT-SBOM-MINIMUMS",
                    "Validate current minimum fields, author signature, format name and version, SBOM version, component hashes and licenses, dependency relationships, known unknowns, generation context, timestamps, identity, automation, distribution, and update practices without treating the replaced NTIA edition or 2025 draft as current.",
                    [
                        "sbom.cdx.json",
                        "artifact-sbom.cdx.json",
                        "dependency-surface.json",
                    ],
                )
            ],
            "procedures": [
                (
                    "CISA-SBOM-MINIMUM-ELEMENTS",
                    "SBOM-NEGATIVE-CONFORMANCE",
                    "Run complete, incomplete, stale, ambiguous, cyclic, omitted-transitive, unknown-supplier, and known-unknown fixtures across every supported SBOM format.",
                    "test",
                    True,
                    [
                        "benchmark-scorecard.json",
                        "sbom.cdx.json",
                        "artifact-sbom.cdx.json",
                    ],
                )
            ],
        },
        "enhanced-cui-assurance": {
            "standards": ["NIST-SP-800-172", "NIST-SP-800-172A", "NIST-SP-800-53B"],
            "controls": [
                (
                    "NIST-SP-800-172",
                    "ENHANCED-CUI-REQUIREMENTS",
                    "Tailor enhanced requirements to the threat, CUI boundary, organization-defined parameters, control baseline, dependencies, and residual-risk decision with OSCAL traceability.",
                    [
                        "control-assessment.json",
                        "oscal-profile.json",
                        "oscal-system-security-plan.json",
                    ],
                )
            ],
            "procedures": [
                (
                    "NIST-SP-800-172A",
                    "ENHANCED-CUI-ASSESSMENT",
                    "Execute examination, interview, and test procedures with scoped objects, depth, coverage, assessor independence, findings, evidence, and remediation traceability.",
                    "test",
                    True,
                    [
                        "procedure-assessment.json",
                        "external-conformity-assessment.json",
                        "benchmark-scorecard.json",
                    ],
                )
            ],
        },
        "developer-verification-minimums": {
            "standards": ["NISTIR-8397", "NIST-SP-800-231", "NIST-SSDF", "OWASP-ASVS"],
            "controls": [
                (
                    "NISTIR-8397",
                    "VERIFICATION-TECHNIQUE-COVERAGE",
                    "Apply threat modeling, automated testing, static analysis, code review, black-box testing, structural testing, fuzzing, web scanning, dependency checks, and compiler-integrated defenses with technique-specific limitations.",
                    [
                        "security-requirements-coverage.json",
                        "test-evidence.json",
                        "effectiveness.json",
                        "risk-paths.json",
                    ],
                )
            ],
            "procedures": [
                (
                    "NISTIR-8397",
                    "MINIMUMS-EVIDENCE-CHALLENGE",
                    "Challenge each verification technique with seeded positive, negative, boundary, parser, reachability, and suppression cases and measure independent detection and overlap.",
                    "test",
                    True,
                    [
                        "benchmark-scorecard.json",
                        "test-evidence.json",
                        "effectiveness.json",
                    ],
                )
            ],
        },
        "cryptographic-key-agility": {
            "standards": [
                "NIST-SP-800-57-PART-1",
                "NIST-SP-800-57-PART-2",
                "NIST-SP-800-57-PART-3",
                "NIST-SP-800-227",
                "NIST-CSWP-39",
                "NIST-SP-800-232",
            ],
            "controls": [
                (
                    "NIST-SP-800-57-PART-1",
                    "KEY-LIFECYCLE-INVENTORY",
                    "Inventory cryptographic uses, keys, algorithms, modules, owners, protection levels, generation, storage, distribution, activation, rotation, revocation, archival, destruction, recovery, and dependencies.",
                    [
                        "domain-assurance.json",
                        "dependency-surface.json",
                        "security-passport.json",
                    ],
                ),
                (
                    "NIST-CSWP-39",
                    "PQC-TRANSITION-AGILITY",
                    "Maintain discovery, dependency, interoperability, hybrid-mode, migration, rollback, exception, retirement, and residual-risk plans for post-quantum transition.",
                    [
                        "domain-assurance.json",
                        "dependency-surface.json",
                        "closure-plan.json",
                    ],
                ),
            ],
            "procedures": [
                (
                    "NIST-SP-800-227",
                    "KEM-ROLLOVER-DOWNGRADE-CHALLENGE",
                    "Test valid and invalid encapsulation, decapsulation, key confirmation, algorithm negotiation, downgrade, rollover, compromised-key recovery, hybrid interoperability, and zeroization cases.",
                    "dynamic",
                    True,
                    ["benchmark-scorecard.json", "domain-assurance.json"],
                )
            ],
        },
        "continuous-security-monitoring": {
            "standards": [
                "NIST-SP-800-137",
                "NIST-SP-800-137A",
                "NISTIR-8212",
                "ISO-IEC-27004",
                "NIST-SP-800-92",
            ],
            "controls": [
                (
                    "NIST-SP-800-137",
                    "ISCM-STRATEGY-AND-OPERATIONS",
                    "Define objectives, scope, assets, controls, frequencies, metrics, collection, analysis, reporting, response thresholds, authorization inputs, ownership, and improvement for continuous monitoring.",
                    [
                        "operational-trend.json",
                        "control-assessment.json",
                        "domain-assurance.json",
                    ],
                )
            ],
            "procedures": [
                (
                    "NIST-SP-800-137A",
                    "ISCM-INDEPENDENT-ASSESSMENT",
                    "Blind qualified assessors to prior ratings and evaluate strategy, policies, procedures, operations, data quality, analysis, reporting, response, and improvement against current evidence.",
                    "manual",
                    False,
                    [
                        "external-conformity-assessment.json",
                        "operational-trend.json",
                        "benchmark-scorecard.json",
                    ],
                )
            ],
        },
        "ict-continuity-readiness": {
            "standards": ["ISO-IEC-27031", "ISO-22301"],
            "controls": [
                (
                    "ISO-IEC-27031",
                    "ICT-CONTINUITY-CAPABILITY",
                    "Trace critical activities, dependencies, recovery objectives, minimum service levels, capacity, redundancy, suppliers, communications, failover, restoration, return, exercise, and improvement evidence.",
                    [
                        "operational-trend.json",
                        "control-assessment.json",
                        "domain-assurance.json",
                    ],
                )
            ],
            "procedures": [
                (
                    "ISO-IEC-27031",
                    "DISRUPTION-RECOVERY-EXERCISE",
                    "Exercise component, region, identity, network, data, supplier, corruption, capacity, and recovery failures while measuring detection, failover, degraded service, integrity, restoration, and lessons learned.",
                    "dynamic",
                    True,
                    [
                        "operational-trend.json",
                        "procedure-assessment.json",
                        "benchmark-scorecard.json",
                    ],
                )
            ],
        },
        "digital-forensics-readiness": {
            "standards": [
                "ISO-IEC-27037",
                "ISO-IEC-27041",
                "ISO-IEC-27042",
                "ISO-IEC-27043",
                "ISO-IEC-27050-1",
                "ISO-IEC-27050-2",
                "ISO-IEC-27050-3",
                "ISO-IEC-27050-4",
                "NIST-SP-800-86",
            ],
            "controls": [
                (
                    "ISO-IEC-27037",
                    "EVIDENCE-IDENTIFICATION-COLLECTION-PRESERVATION",
                    "Govern authority, competence, identification, acquisition, collection, preservation, hashes, time, custody, storage, transport, privacy, repeatability, and auditability for potential digital evidence.",
                    [
                        "audit-package-verification.json",
                        "security-passport.json",
                        "external-conformity-assessment.json",
                    ],
                )
            ],
            "procedures": [
                (
                    "ISO-IEC-27041",
                    "FORENSIC-METHOD-REPRODUCIBILITY",
                    "Independently replay validated methods across representative and adverse evidence cases, verify custody and tool qualification, and compare analysis, interpretation, uncertainty, and conclusions.",
                    "manual",
                    False,
                    [
                        "external-conformity-assessment.json",
                        "audit-package-verification.json",
                        "benchmark-scorecard.json",
                    ],
                )
            ],
        },
        "accessibility-quality": {
            "standards": [
                "W3C-WCAG",
                "W3C-ACT-RULES-FORMAT",
                "ETSI-EN-301-549",
                "US-SECTION-508",
            ],
            "controls": [
                (
                    "W3C-WCAG",
                    "WCAG-2.2-AA",
                    "Evaluate perceivable, operable, understandable, and robust outcomes at WCAG 2.2 AA, including new 2.2 criteria, complete page states, authentication, errors, and user journeys.",
                    ["test-evidence.json", "external-conformity-assessment.json"],
                )
            ],
            "procedures": [
                (
                    "ETSI-EN-301-549",
                    "ACCESSIBILITY-MIXED-METHOD-CONFORMANCE",
                    "Combine deterministic automation with keyboard-only, zoom, reflow, contrast, focus, screen-reader, speech, captions, documents, software, support, and representative assistive-technology evaluation by qualified reviewers.",
                    "manual",
                    False,
                    [
                        "test-evidence.json",
                        "external-conformity-assessment.json",
                        "benchmark-scorecard.json",
                    ],
                )
            ],
        },
    }
)

_ASSURANCE_PROFILES.update(
    {
        "audit-assessment-integrity": {
            "standards": [
                "ISO-19011",
                "ISO-IEC-27007",
                "ISO-IEC-TS-27008",
                "ISO-IEC-27006-1",
                "ISO-IEC-17021-1",
                "ISO-IEC-17029",
            ],
            "controls": [
                (
                    "ISO-19011",
                    "AUDIT-PROGRAM-INTEGRITY",
                    "Govern audit objectives, scope, criteria, risk, methods, sampling, competence, independence, evidence, findings, reporting, follow-up, and program improvement.",
                    ["control-assessment.json", "audit-package-verification.json"],
                ),
                (
                    "ISO-IEC-TS-27008",
                    "CONTROL-ASSESSMENT-TRACEABILITY",
                    "Trace every assessed control to authoritative criteria, scoped objects, methods, samples, observations, uncertainty, findings, and retained evidence.",
                    ["control-assessment.json", "procedure-assessment.json"],
                ),
            ],
            "procedures": [
                (
                    "ISO-IEC-27007",
                    "BLINDED-AUDIT-REPERFORMANCE",
                    "Reperform a stratified evidence sample with an independent qualified team, compare findings and severity, adjudicate disagreement, and retain conflict-of-interest and supervision records.",
                    "manual",
                    False,
                    [
                        "external-conformity-assessment.json",
                        "audit-package-verification.json",
                        "benchmark-scorecard.json",
                    ],
                )
            ],
        },
        "security-evaluator-competence": {
            "standards": [
                "ISO-IEC-19896-1",
                "ISO-IEC-19896-2",
                "ISO-IEC-19896-3",
                "ISO-IEC-17025",
                "ISO-IEC-17065",
            ],
            "controls": [
                (
                    "ISO-IEC-19896-1",
                    "ROLE-COMPETENCE-AND-IMPARTIALITY",
                    "Bind evaluator roles to education, experience, technical knowledge, supervised performance, authorization, continuing competence, impartiality, and current scope.",
                    [
                        "external-conformity-assessment.json",
                        "audit-package-verification.json",
                    ],
                ),
                (
                    "ISO-IEC-19896-2",
                    "CRYPTO-EVALUATOR-QUALIFICATION",
                    "Verify role-specific competence for cryptographic module testing and validation without generalizing qualification beyond the approved scheme and technology scope.",
                    ["external-conformity-assessment.json", "benchmark-scorecard.json"],
                ),
            ],
            "procedures": [
                (
                    "ISO-IEC-19896-3",
                    "BLINDED-EVALUATOR-CALIBRATION",
                    "Run blinded positive, negative, ambiguous, and boundary cases against protected golden decisions; measure inter-rater agreement, bias, drift, adjudication, and retraining outcomes.",
                    "manual",
                    False,
                    ["external-conformity-assessment.json", "benchmark-scorecard.json"],
                )
            ],
        },
        "application-security-governance": {
            "standards": [
                "ISO-IEC-27034-1",
                "ISO-IEC-27034-2",
                "ISO-IEC-27034-3",
                "ISO-IEC-27034-5",
                "ISO-IEC-TS-27034-5-1",
                "ISO-IEC-27034-6",
                "ISO-IEC-27034-7",
                "OWASP-ASVS",
            ],
            "controls": [
                (
                    "ISO-IEC-27034-2",
                    "ORGANIZATION-NORMATIVE-FRAMEWORK",
                    "Maintain an approved organization normative framework that tailors application-security controls to business, technology, threat, legal, and assurance contexts with accountable exceptions.",
                    ["security-requirements-coverage.json", "control-assessment.json"],
                ),
                (
                    "ISO-IEC-27034-5",
                    "ASC-DATA-AND-PROTOCOL-INTEGRITY",
                    "Preserve application-security-control identity, attributes, lifecycle roles, evidence links, version semantics, and lossless exchange across supported representations.",
                    ["application-contract-analysis.json", "control-assessment.json"],
                ),
            ],
            "procedures": [
                (
                    "ISO-IEC-27034-7",
                    "ASSURANCE-PREDICTION-VALIDATION",
                    "Backtest predicted application assurance against independently observed verification outcomes, disclose uncertainty and unsupported contexts, and prevent prediction from replacing direct evidence.",
                    "test",
                    False,
                    [
                        "effectiveness.json",
                        "benchmark-scorecard.json",
                        "security-requirements-coverage.json",
                    ],
                )
            ],
        },
        "firmware-hardware-trust": {
            "standards": ["NIST-SP-800-193", "TCG-TPM-2.0", "FIPS-140-3"],
            "controls": [
                (
                    "NIST-SP-800-193",
                    "PLATFORM-PROTECT-DETECT-RECOVER",
                    "Trace authenticated updates, write protection, rollback prevention, integrity measurement, corruption detection, recovery roots, known-good images, recovery policy, and failure reporting.",
                    ["domain-assurance.json", "security-passport.json"],
                ),
                (
                    "TCG-TPM-2.0",
                    "MEASURED-BOOT-ATTESTATION",
                    "Bind PCR policy, event-log replay, endorsement and attestation identities, nonce freshness, quote verification, algorithm policy, key protection, reset semantics, and verifier decisions.",
                    ["domain-assurance.json", "benchmark-scorecard.json"],
                ),
            ],
            "procedures": [
                (
                    "NIST-SP-800-193",
                    "FIRMWARE-RESILIENCE-FAULT-INJECTION",
                    "In an authorized recoverable laboratory, challenge valid, malformed, unsigned, replayed, downgraded, interrupted, corrupted, and rollback firmware paths and independently replay measured-boot evidence.",
                    "dynamic",
                    True,
                    [
                        "benchmark-scorecard.json",
                        "procedure-assessment.json",
                        "security-passport.json",
                    ],
                )
            ],
        },
        "differential-privacy-engineering": {
            "standards": ["NIST-SP-800-226", "ISO-IEC-29100", "ISO-IEC-27701"],
            "controls": [
                (
                    "NIST-SP-800-226",
                    "DP-GUARANTEE-AND-HAZARD-MODEL",
                    "Specify neighboring datasets, threat model, mechanism, privacy definition, epsilon and delta, composition, accounting, implementation hazards, utility objectives, and claim limits.",
                    ["data-exposure.json", "security-requirements-coverage.json"],
                )
            ],
            "procedures": [
                (
                    "NIST-SP-800-226",
                    "DP-IMPLEMENTATION-REPRODUCTION",
                    "Reproduce privacy accounting and utility results over approved neighboring datasets, seeds, repetitions, boundary budgets, composition, floating-point, side-channel, and misuse cases.",
                    "test",
                    True,
                    [
                        "benchmark-scorecard.json",
                        "data-exposure.json",
                        "effectiveness.json",
                    ],
                )
            ],
        },
        "data-quality-engineering": {
            "standards": [
                "ISO-IEC-25010",
                "ISO-IEC-25012",
                "ISO-IEC-25020",
                "ISO-IEC-25024",
                "ISO-IEC-25030",
            ],
            "controls": [
                (
                    "ISO-IEC-25030",
                    "MEASURABLE-QUALITY-REQUIREMENTS",
                    "Define stakeholder-grounded software and data quality requirements with measures, scales, target values, decision rules, context, ownership, traceability, and acceptance thresholds.",
                    ["security-requirements-coverage.json", "code-health.json"],
                ),
                (
                    "ISO-IEC-25012",
                    "DATA-QUALITY-MODEL",
                    "Assess intrinsic and system-dependent data quality characteristics across provenance, lifecycle, transformations, consumers, defects, and fitness-for-use decisions.",
                    ["code-health.json", "effectiveness.json"],
                ),
            ],
            "procedures": [
                (
                    "ISO-IEC-25024",
                    "QUALITY-MEASUREMENT-CONFORMANCE",
                    "Recompute approved measures over versioned reference datasets, verify formula, scale, unit, missing-data handling, aggregation, uncertainty, thresholds, and repeatability against golden outcomes.",
                    "test",
                    False,
                    [
                        "benchmark-scorecard.json",
                        "code-health.json",
                        "effectiveness.json",
                    ],
                )
            ],
        },
    }
)

_ASSURANCE_PROFILES.update(
    {
        "quality-in-use-cloud": {
            "standards": [
                "ISO-IEC-25010",
                "ISO-IEC-25019",
                "ISO-IEC-TS-25052-1",
                "ISO-IEC-TS-25052-2",
            ],
            "controls": [
                (
                    "ISO-IEC-25019",
                    "QUALITY-IN-USE-CONTEXT",
                    "Define users, goals, tasks, environments, risks, measures, target values, uncertainty, and acceptance rules for each claimed quality-in-use context.",
                    ["security-requirements-coverage.json", "effectiveness.json"],
                ),
                (
                    "ISO-IEC-TS-25052-1",
                    "CLOUD-SERVICE-QUALITY-MODEL",
                    "Map cloud-service quality characteristics to service boundaries, shared responsibilities, consumers, workloads, dependencies, service levels, and measurable requirements.",
                    ["domain-assurance.json", "code-health.json"],
                ),
            ],
            "procedures": [
                (
                    "ISO-IEC-TS-25052-2",
                    "CLOUD-QUALITY-MEASUREMENT",
                    "Execute representative and adverse workload, tenancy, dependency, degradation, recovery, and user-context cases; recompute approved measures and retain uncertainty, exclusions, and decision outcomes.",
                    "test",
                    True,
                    ["benchmark-scorecard.json", "effectiveness.json"],
                )
            ],
        },
        "enterprise-risk-techniques": {
            "standards": ["ISO-31000", "IEC-31010", "NIST-SP-800-37"],
            "controls": [
                (
                    "ISO-31000",
                    "RISK-FRAMEWORK-AND-CRITERIA",
                    "Bind risk objectives, scope, context, criteria, owners, communication, consultation, assessment, treatment, monitoring, review, recording, and improvement to organizational decisions.",
                    ["risk-paths.json", "control-assessment.json"],
                ),
                (
                    "IEC-31010",
                    "RISK-TECHNIQUE-SELECTION",
                    "Select complementary assessment techniques from decision purpose, lifecycle phase, data quality, complexity, uncertainty, human factors, resources, limitations, and validation needs.",
                    ["risk-paths.json", "procedure-assessment.json"],
                ),
            ],
            "procedures": [
                (
                    "IEC-31010",
                    "BLINDED-RISK-TECHNIQUE-CALIBRATION",
                    "Run blinded scenarios through multiple applicable techniques, compare assumptions, coverage, uncertainty, sensitivity, ranking stability, assessor agreement, and adjudicated decisions against protected reference cases.",
                    "manual",
                    False,
                    ["benchmark-scorecard.json", "risk-paths.json"],
                )
            ],
        },
        "secure-by-design-product": {
            "standards": [
                "CISA-SECURE-BY-DESIGN",
                "CISA-PRODUCT-SECURITY-BAD-PRACTICES",
                "NIST-SSDF",
            ],
            "controls": [
                (
                    "CISA-SECURE-BY-DESIGN",
                    "SECURE-DEFAULT-PRODUCT-PROPERTIES",
                    "Make security ownership explicit and provide secure defaults, MFA, SSO, logging, safe recovery, vulnerability transparency, supported upgrade paths, and no avoidable security tax for essential protections.",
                    ["control-proof.json", "security-requirements-coverage.json"],
                ),
                (
                    "CISA-PRODUCT-SECURITY-BAD-PRACTICES",
                    "PROHIBITED-PRODUCT-PRACTICES",
                    "Prohibit default credentials, known exploited unpatched components, avoidable memory-unsafe exposure in critical products, silent security-feature absence, and unsupported insecure deployment defaults unless a governed exception is evidenced.",
                    ["finding-validation.json", "risk-acceptance.json"],
                ),
            ],
            "procedures": [
                (
                    "CISA-PRODUCT-SECURITY-BAD-PRACTICES",
                    "INSECURE-DEFAULT-NEGATIVE-CHALLENGE",
                    "Install and exercise a clean product image with omitted configuration, first-use, weak identity, logging failure, upgrade, recovery, exposed-service, and known-exploited-component cases; fail closed on undocumented or insecure behavior.",
                    "dynamic",
                    True,
                    ["benchmark-scorecard.json", "test-evidence.json"],
                )
            ],
        },
        "tls-protocol-assurance": {
            "standards": ["IETF-RFC-8446", "IETF-RFC-8996", "IETF-RFC-9325"],
            "controls": [
                (
                    "IETF-RFC-8446",
                    "TLS-STATE-MACHINE-AND-KEY-SCHEDULE",
                    "Bind supported protocol versions, roles, extensions, cipher suites, key schedule, certificate validation, resumption, early data, alerts, downgrade behavior, and unsupported features to implementation evidence.",
                    ["domain-assurance.json", "security-requirements-coverage.json"],
                )
            ],
            "procedures": [
                (
                    "IETF-RFC-8446",
                    "TLS-NEGATIVE-CONFORMANCE",
                    "Execute pinned BoGo and tlsfuzzer positive, malformed-handshake, state-transition, certificate, extension, alert, replay, downgrade, fragmentation, resumption, early-data, and interoperability cases with a declared supported-case matrix.",
                    "dynamic",
                    True,
                    ["benchmark-scorecard.json", "test-evidence.json"],
                )
            ],
        },
        "reproducible-build-assurance": {
            "standards": ["REPRODUCIBLE-BUILDS-TEST-PROTOCOL", "SLSA"],
            "controls": [
                (
                    "REPRODUCIBLE-BUILDS-TEST-PROTOCOL",
                    "BUILD-VARIATION-MATRIX",
                    "Pin source, dependencies, build instructions, toolchains, and expected artifacts; vary time, path, user, locale, timezone, filesystem ordering, parallelism, and builder image through an approved matrix.",
                    ["release-readiness.json", "artifact-validation.json"],
                )
            ],
            "procedures": [
                (
                    "REPRODUCIBLE-BUILDS-TEST-PROTOCOL",
                    "INDEPENDENT-REBUILD-EQUIVALENCE",
                    "Perform isolated independent rebuilds for every required variation, compare artifact digests, classify byte-level differences, verify provenance subjects, and fail unexplained or policy-prohibited nondeterminism.",
                    "test",
                    True,
                    ["benchmark-scorecard.json", "release-readiness.json"],
                )
            ],
        },
        "malware-protection-validation": {
            "standards": ["AMTSO-TESTING-PROTOCOL"],
            "controls": [
                (
                    "AMTSO-TESTING-PROTOCOL",
                    "TRANSPARENT-ANTIMALWARE-TEST-PLAN",
                    "Predeclare scope, participants, product configuration, samples, prevalence, timing, metrics, disputes, exclusions, safety, restoration, reporting, and statistical limitations under an approved test plan.",
                    ["test-evidence.json", "external-conformity-assessment.json"],
                )
            ],
            "procedures": [
                (
                    "AMTSO-TESTING-PROTOCOL",
                    "SAFE-MALWARE-CONTROL-EVALUATION",
                    "Verify installation with the harmless EICAR test file, then evaluate approved inert or isolated malicious and clean cases across protection, visibility, false positives, latency, remediation, restoration, tamper resistance, and configuration states.",
                    "dynamic",
                    True,
                    ["benchmark-scorecard.json", "test-evidence.json"],
                )
            ],
        },
        "confidential-computing-attestation": {
            "standards": [
                "TCG-DICE-ATTESTATION-ARCHITECTURE",
                "TCG-TPM-2.0",
                "IETF-RFC-9334",
                "IETF-RFC-9711",
            ],
            "controls": [
                (
                    "TCG-DICE-ATTESTATION-ARCHITECTURE",
                    "LAYERED-DEVICE-IDENTITY",
                    "Trace unique device secrets, compound device identity, layer measurements, aliases, certificates, evidence, endorsements, lifecycle transitions, ownership changes, privacy, and verifier policy without exporting protected secrets.",
                    ["security-passport.json", "domain-assurance.json"],
                )
            ],
            "procedures": [
                (
                    "TCG-DICE-ATTESTATION-ARCHITECTURE",
                    "DICE-EVIDENCE-AND-VERIFIER-CONFORMANCE",
                    "Exercise valid boot chains plus mutated measurements, reordered layers, stale evidence, substituted endorsements, revoked identities, rollback, reset, recovery, ownership transfer, and unsupported-profile cases against explicit verifier decisions.",
                    "dynamic",
                    True,
                    ["benchmark-scorecard.json", "security-passport.json"],
                )
            ],
        },
        "telecommunications-security": {
            "standards": ["ISO-IEC-27011", "ISO-IEC-27001", "ISO-IEC-27002"],
            "controls": [
                (
                    "ISO-IEC-27011",
                    "TELECOM-CONTROL-APPLICABILITY",
                    "Tailor information-security controls to telecom services, signaling, management, customer data, interconnection, roaming, infrastructure, suppliers, shared responsibility, availability, lawful obligations, and recovery boundaries.",
                    ["domain-assurance.json", "control-assessment.json"],
                )
            ],
            "procedures": [
                (
                    "ISO-IEC-27011",
                    "TELECOM-CONTROL-EVIDENCE-CHALLENGE",
                    "Challenge representative network, service, management, identity, interconnection, supplier, outage, incident, and recovery cases; retain scoped evidence and explicit non-applicability decisions.",
                    "test",
                    True,
                    ["benchmark-scorecard.json", "procedure-assessment.json"],
                )
            ],
        },
        "cyber-workforce-assurance": {
            "standards": ["NIST-SP-800-181-R1", "NIST-NICE-FRAMEWORK-COMPONENTS"],
            "controls": [
                (
                    "NIST-SP-800-181-R1",
                    "ROLE-TASK-COMPETENCE-MAPPING",
                    "Map cybersecurity responsibilities to current NICE tasks, knowledge, and skills with named accountable roles, scope, independence, qualification evidence, supervision, succession, and continuing development.",
                    ["external-conformity-assessment.json", "control-assessment.json"],
                )
            ],
            "procedures": [
                (
                    "NIST-NICE-FRAMEWORK-COMPONENTS",
                    "WORKFORCE-COVERAGE-AND-DRIFT",
                    "Evaluate critical task coverage, single-person dependencies, incompatible duties, stale component mappings, evidence-backed proficiency, scenario performance, handoff quality, and remediation against the pinned NICE release.",
                    "manual",
                    False,
                    ["benchmark-scorecard.json", "external-conformity-assessment.json"],
                )
            ],
        },
        "penetration-testing-governance": {
            "standards": ["CREST-PENETRATION-TESTING-GUIDE", "PTES", "NIST-SP-800-115"],
            "controls": [
                (
                    "CREST-PENETRATION-TESTING-GUIDE",
                    "AUTHORIZED-ENGAGEMENT-GOVERNANCE",
                    "Govern objectives, scope, exclusions, rules of engagement, authorization, competence, communications, evidence handling, safety, privacy, escalation, kill switches, reporting, remediation, retest, and closure.",
                    [
                        "adversarial-campaign.json",
                        "external-conformity-assessment.json",
                    ],
                )
            ],
            "procedures": [
                (
                    "PTES",
                    "ENGAGEMENT-QUALITY-REPERFORMANCE",
                    "Independently sample pre-engagement, intelligence, threat modeling, vulnerability analysis, exploitation, post-exploitation, cleanup, evidence, severity, remediation, and retest records against the approved scope and methodology.",
                    "manual",
                    True,
                    ["benchmark-scorecard.json", "adversarial-campaign.json"],
                )
            ],
        },
        "software-delivery-outcomes": {
            "standards": ["DORA-SOFTWARE-DELIVERY-PERFORMANCE"],
            "controls": [
                (
                    "DORA-SOFTWARE-DELIVERY-PERFORMANCE",
                    "DELIVERY-METRIC-DATA-CONTRACT",
                    "Define service and deployment boundaries, successful and failed deployments, recovery, rework, lead-time anchors, observation windows, exclusions, source systems, ownership, missing data, uncertainty, and anti-gaming controls.",
                    ["operational-trend.json", "control-assessment.json"],
                )
            ],
            "procedures": [
                (
                    "DORA-SOFTWARE-DELIVERY-PERFORMANCE",
                    "FIVE-METRIC-OUTCOME-RECOMPUTATION",
                    "Independently recompute change lead time, deployment frequency, failed deployment recovery time, change fail rate, and deployment rework rate from immutable delivery and incident events; reject mixed scopes and unsupported causal claims.",
                    "test",
                    False,
                    ["benchmark-scorecard.json", "operational-trend.json"],
                )
            ],
        },
    }
)

_ASSURANCE_PROFILES.update(
    {
        "structured-assurance-case": {
            "standards": [
                "ISO-IEC-IEEE-15026-2",
                "ISO-IEC-IEEE-15026-4",
                "OMG-SACM",
            ],
            "controls": [
                (
                    "ISO-IEC-IEEE-15026-2",
                    "CLAIM-ARGUMENT-EVIDENCE-INTEGRITY",
                    "Maintain a scoped assurance case whose claims, context, assumptions, strategies, defeaters, evidence, confidence, applicability, and decision status are uniquely identified and traceable without dangling or circular support.",
                    ["assurance-case-assessment.json"],
                ),
                (
                    "OMG-SACM",
                    "MACHINE-READABLE-ASSURANCE-EXCHANGE",
                    "Validate the SACM 2.3 representation against pinned machine-readable syntax and semantic rules while preserving claim, artifact, citation, argument, and package identities across round trips.",
                    ["assurance-case-assessment.json"],
                ),
            ],
            "procedures": [
                (
                    "ISO-IEC-IEEE-15026-2",
                    "ASSURANCE-CASE-MUTATION-CHALLENGE",
                    "Inject missing and stale evidence, dangling relationships, cycles, contradictions, scope mismatches, unsupported top-level claims, and unresolved defeaters; require deterministic rejection and independent adjudication.",
                    "test",
                    False,
                    ["assurance-case-assessment.json", "benchmark-scorecard.json"],
                )
            ],
        },
        "integrity-level-vv": {
            "standards": ["IEEE-1012", "ISO-IEC-IEEE-12207", "ISO-IEC-IEEE-15288"],
            "controls": [
                (
                    "IEEE-1012",
                    "INTEGRITY-LEVEL-VV-RIGOR",
                    "Assign system, software, and hardware integrity levels from consequence and risk, then bind required V&V tasks, independence, methods, coverage, anomaly disposition, reuse, COTS, interfaces, and evidence to each assigned level.",
                    ["lifecycle-traceability.json", "control-assessment.json"],
                )
            ],
            "procedures": [
                (
                    "IEEE-1012",
                    "INDEPENDENT-VV-REPERFORMANCE",
                    "Independently reperform a risk-stratified sample of requirements, architecture, interfaces, implementation, integration, installation, operation, reuse, and COTS V&V tasks and challenge under-classified integrity levels and omitted evidence.",
                    "test",
                    False,
                    ["benchmark-scorecard.json", "lifecycle-traceability.json"],
                )
            ],
        },
        "cmvp-cryptographic-module": {
            "standards": ["FIPS-140-3", "NIST-CMVP"],
            "controls": [
                (
                    "NIST-CMVP",
                    "SCHEME-PINNED-MODULE-VALIDATION",
                    "Pin the applicable CMVP management manual, implementation guidance, SP 800-140 publications, scheme-referenced ISO editions, algorithm prerequisites, module boundary, security policy, certificate status, historical transitions, and tested configurations at assessment time.",
                    ["external-conformity-assessment.json", "control-assessment.json"],
                )
            ],
            "procedures": [
                (
                    "FIPS-140-3",
                    "CMVP-EVIDENCE-AND-STATUS-REPERFORMANCE",
                    "Reperform approved positive, negative, error-state, self-test, role, service, key-management, physical or non-invasive, operational-environment, and lifecycle cases; verify current certificate and algorithm status without importing requirements from a newer ISO edition.",
                    "test",
                    True,
                    ["benchmark-scorecard.json", "external-conformity-assessment.json"],
                )
            ],
        },
        "international-cryptographic-module": {
            "standards": [
                "ISO-IEC-19790",
                "ISO-IEC-24759",
                "ISO-IEC-17825",
                "ISO-IEC-20085-1",
                "ISO-IEC-20085-2",
            ],
            "controls": [
                (
                    "ISO-IEC-19790",
                    "MODULE-SECURITY-LEVEL-AND-BOUNDARY",
                    "Declare the cryptographic module boundary, claimed security level by requirement area, approved operational environments, roles, services, interfaces, sensitive parameters, self-tests, lifecycle states, physical protections, and non-invasive mitigation claims.",
                    ["external-conformity-assessment.json", "control-assessment.json"],
                ),
                (
                    "ISO-IEC-24759",
                    "LABORATORY-TEST-AND-VENDOR-EVIDENCE",
                    "Trace each applicable test assertion to vendor evidence, method, fixture, calibrated equipment, expected result, observation, uncertainty, deviation, verdict, assessor identity, and approved module configuration.",
                    ["external-conformity-assessment.json", "benchmark-scorecard.json"],
                ),
            ],
            "procedures": [
                (
                    "ISO-IEC-24759",
                    "MODULE-CONFORMANCE-REPERFORMANCE",
                    "Execute licensed test methods against representative and adverse module states, including malformed inputs, power-up and conditional self-tests, error transitions, key zeroization, role separation, fault response, and claimed non-invasive mitigations under calibrated laboratory controls.",
                    "dynamic",
                    True,
                    ["benchmark-scorecard.json", "external-conformity-assessment.json"],
                )
            ],
        },
        "biometric-identity-assurance": {
            "standards": ["ISO-IEC-19795-1", "ISO-IEC-30107-3", "ISO-IEC-30107-4"],
            "controls": [
                (
                    "ISO-IEC-19795-1",
                    "BIOMETRIC-PERFORMANCE-DESIGN",
                    "Predeclare population, demographic strata, sensors, environment, enrollment and comparison procedures, thresholds, sample-size rationale, exclusions, failure-to-acquire and failure-to-enroll handling, FMR, FNMR, uncertainty, and claim limits.",
                    ["external-conformity-assessment.json", "control-assessment.json"],
                ),
                (
                    "ISO-IEC-30107-3",
                    "PRESENTATION-ATTACK-EVALUATION",
                    "Define attack potential, presentation attack instruments, species, fabrication, operators, attempts, sensors, IAPAR decision rules, safety, sequestering, and reporting without disclosing reusable bypass material.",
                    ["external-conformity-assessment.json", "benchmark-scorecard.json"],
                ),
            ],
            "procedures": [
                (
                    "ISO-IEC-30107-3",
                    "SEQUESTERED-BIOMETRIC-PAD-EVALUATION",
                    "Evaluate locked thresholds on sequestered bona-fide, zero-effort impostor, and presentation-attack trials; report Wilson confidence bounds overall and by demographic and attack-instrument strata and reject unsupported subgroup claims.",
                    "dynamic",
                    True,
                    ["benchmark-scorecard.json", "external-conformity-assessment.json"],
                )
            ],
        },
        "integrated-service-security-management": {
            "standards": ["ISO-IEC-20000-1", "ISO-IEC-27013", "ISO-IEC-27001"],
            "controls": [
                (
                    "ISO-IEC-20000-1",
                    "SERVICE-LIFECYCLE-EVIDENCE",
                    "Bind service requirements, catalog and ownership, assets and configuration, changes, releases, deployments, capacity, availability, continuity, suppliers, incidents, problems, requests, knowledge, measurement, internal audit, corrective action, and continual improvement to retained operational evidence.",
                    ["operational-trend.json", "control-assessment.json"],
                ),
                (
                    "ISO-IEC-27013",
                    "INTEGRATED-SMS-ISMS-GOVERNANCE",
                    "Maintain one scoped and non-duplicative governance model for service and information-security management, including shared objectives, risk, roles, competence, documented information, audits, management review, corrective action, and evidence lineage.",
                    ["control-assessment.json", "audit-package-verification.json"],
                ),
            ],
            "procedures": [
                (
                    "ISO-IEC-20000-1",
                    "SERVICE-SECURITY-TRACE-AND-FAULT-CHALLENGE",
                    "Trace representative changes and incidents from request through approval, configuration, deployment, observation, recovery, problem resolution, supplier action, evidence retention, and improvement; inject stale configuration, failed rollback, broken ownership, and unlinked security incidents.",
                    "test",
                    True,
                    ["benchmark-scorecard.json", "operational-trend.json"],
                )
            ],
        },
        "interlaboratory-proficiency": {
            "standards": ["ISO-IEC-17043", "ISO-IEC-17025"],
            "controls": [
                (
                    "ISO-IEC-17043",
                    "PROFICIENCY-SCHEME-DESIGN",
                    "Govern objectives, participant scope, impartiality, confidentiality, item preparation, homogeneity, stability, assigned values, uncertainty, statistical design, collusion prevention, reporting, appeals, corrective action, and retention for blinded proficiency exercises.",
                    ["external-conformity-assessment.json", "control-assessment.json"],
                )
            ],
            "procedures": [
                (
                    "ISO-IEC-17043",
                    "BLINDED-INTERLABORATORY-ROUND-ROBIN",
                    "Distribute equivalent blinded positive, negative, ambiguous, and boundary items across independent engines, operators, laboratories, and environments; measure agreement, chance-corrected agreement, reference accuracy, bias, drift, outliers, adjudication, and corrective action.",
                    "test",
                    False,
                    ["benchmark-scorecard.json", "external-conformity-assessment.json"],
                )
            ],
        },
    }
)

_ASSURANCE_PROFILES.update(
    {
        "enterprise-cyber-risk-integration": {
            "standards": [
                "NIST-IR-8286",
                "NIST-IR-8286A",
                "NIST-IR-8286B",
                "NIST-IR-8286C",
                "NIST-IR-8286D",
                "NIST-SP-800-30",
                "NIST-SP-800-39",
                "CIS-RAM",
                "OPEN-FAIR",
            ],
            "controls": [
                (
                    "NIST-IR-8286",
                    "CSRM-ERM-INTEGRATION",
                    "Maintain bidirectional traceability between system cybersecurity risks, mission and business consequences, enterprise objectives, risk appetite and tolerance, response decisions, ownership, escalation, aggregation, and enterprise risk reporting.",
                    ["risk-paths.json", "domain-assurance.json"],
                ),
                (
                    "NIST-IR-8286A",
                    "RISK-IDENTIFICATION-ESTIMATION",
                    "Retain threat, vulnerability, condition, asset, consequence, likelihood, uncertainty, evidence, assumptions, time horizon, and scenario records using the approved risk detail schema and calibrated estimation method.",
                    ["risk-paths.json", "control-assessment.json"],
                ),
                (
                    "NIST-IR-8286B",
                    "RISK-PRIORITIZATION-RESPONSE",
                    "Prioritize risks against documented enterprise objectives, dependencies, appetite, tolerance, cost, urgency, uncertainty, and response options without replacing evidence with untraceable ordinal labels.",
                    ["risk-paths.json", "standardized-prioritization.json"],
                ),
                (
                    "NIST-IR-8286C",
                    "RISK-ROLLUP-GOVERNANCE",
                    "Stage and aggregate cybersecurity risks without double counting, loss of scope, unit mismatch, hidden correlation, or unsupported precision; preserve drill-down to source risk detail records and accountable governance decisions.",
                    ["risk-paths.json", "audit-package-verification.json"],
                ),
                (
                    "NIST-IR-8286D",
                    "BIA-RISK-CONSEQUENCE",
                    "Connect business impact analysis, dependency propagation, service degradation, recovery objectives, mission consequences, and enterprise risk response using explicit time horizons and independently reviewable assumptions.",
                    ["risk-paths.json", "operational-trend.json"],
                ),
                (
                    "CIS-RAM",
                    "REASONABLE-SECURITY-RISK-CRITERIA",
                    "Define acceptable risk and due-care criteria, analyze foreseeable threats and safeguard reliability, and retain attack-path, stakeholder-impact, treatment, exception, and approval evidence against the pinned CIS RAM edition.",
                    ["risk-paths.json", "control-assessment.json"],
                ),
                (
                    "OPEN-FAIR",
                    "LICENSED-QUANTITATIVE-RISK",
                    "Where licensed and approved, retain calibrated frequency and magnitude inputs, distributions, uncertainty, sensitivity, validation, and decision limits without redistributing restricted Open FAIR content or presenting estimates as certainty.",
                    ["risk-paths.json", "benchmark-scorecard.json"],
                ),
            ],
            "procedures": [
                (
                    "NIST-IR-8286",
                    "RISK-REGISTER-SCHEMA-ROLLUP-CHALLENGE",
                    "Validate risk registers and detail records against the pinned NIST schemas, reperform sampled estimations and rollups, and inject duplicate risks, unit and horizon mismatches, broken lineage, hidden correlation, appetite breaches, stale evidence, and unsupported executive summaries.",
                    "test",
                    False,
                    ["benchmark-scorecard.json", "risk-paths.json"],
                ),
                (
                    "CIS-RAM",
                    "ATTACK-PATH-RISK-CALIBRATION",
                    "Blindly compare independent assessors over positive, negative, boundary, and ambiguous attack paths; verify criteria application, safeguard reliability, impact, risk acceptance, treatment, agreement, adjudication, and sensitivity.",
                    "test",
                    False,
                    ["benchmark-scorecard.json", "control-assessment.json"],
                ),
            ],
        },
        "enterprise-architecture-governance": {
            "standards": [
                "COBIT-2019",
                "TOGAF-STANDARD",
                "ARCHIMATE",
                "OPEN-FAIR",
                "ISO-IEC-IEEE-42010",
                "ISO-22340",
            ],
            "controls": [
                (
                    "COBIT-2019",
                    "LICENSED-I-T-GOVERNANCE",
                    "Using organization-licensed criteria, trace stakeholder needs and enterprise goals to governance and management objectives, decision rights, ownership, capability, performance, risk, assurance, exceptions, and improvement without embedding restricted framework text.",
                    ["domain-assurance.json", "process-capability-assessment.json"],
                ),
                (
                    "TOGAF-STANDARD",
                    "LICENSED-ARCHITECTURE-GOVERNANCE",
                    "Using a licensed, policy-pinned edition, govern architecture scope, stakeholders, concerns, principles, baselines, target states, roadmaps, decisions, waivers, contracts, change, and implementation conformance with explicit security and resilience traceability.",
                    ["architecture-evaluation.json", "domain-assurance.json"],
                ),
                (
                    "ARCHIMATE",
                    "LICENSED-MODEL-SEMANTICS",
                    "Validate model elements, relationships, viewpoints, layers, identifiers, references, and exchanges against the licensed ArchiMate edition while preserving traceability to source evidence and rejecting invented semantics.",
                    ["static-architecture.json", "architecture-evaluation.json"],
                ),
                (
                    "OPEN-FAIR",
                    "ARCHITECTURE-RISK-QUANTIFICATION",
                    "Bind material architecture alternatives and control decisions to licensed quantitative-risk models, calibrated assumptions, uncertainty, sensitivity, residual exposure, decision authority, and claim limitations.",
                    ["risk-paths.json", "benchmark-scorecard.json"],
                ),
            ],
            "procedures": [
                (
                    "TOGAF-STANDARD",
                    "ARCHITECTURE-MODEL-DECISION-REPERFORMANCE",
                    "Using licensed requirements and blinded organization cases, reperform architecture decisions and model exchanges; challenge missing stakeholders, orphaned requirements, invalid relationships, contradictory views, unapproved waivers, stale baselines, unsafe transitions, and unsupported risk claims.",
                    "manual",
                    False,
                    ["architecture-evaluation.json", "benchmark-scorecard.json"],
                )
            ],
        },
        "ai-benchmark-governance": {
            "standards": [
                "ISO-IEC-TR-42106",
                "ISO-IEC-TS-42119-2",
                "ISO-IEC-25059",
                "ISO-IEC-42006",
            ],
            "controls": [
                (
                    "ISO-IEC-TR-42106",
                    "DIFFERENTIATED-BENCHMARK-DESIGN",
                    "Predeclare system complexity, context of use, stakeholders, quality characteristics, risk strata, task difficulty, comparators, sample-size rationale, repetitions, uncertainty, aggregation, decision thresholds, and claim boundaries for graded AI benchmarking.",
                    ["benchmark-scorecard.json", "effectiveness.json"],
                ),
                (
                    "ISO-IEC-25059",
                    "AI-QUALITY-CHARACTERISTIC-TRACE",
                    "Trace selected AI quality characteristics to stakeholder needs, context, measures, datasets, scenarios, adverse conditions, acceptance criteria, residual limitations, and post-deployment monitoring.",
                    ["security-requirements-coverage.json", "effectiveness.json"],
                ),
            ],
            "procedures": [
                (
                    "ISO-IEC-TR-42106",
                    "DIFFERENTIATED-BENCHMARK-METAMORPHIC-CHALLENGE",
                    "Reperform benchmark outcomes across declared complexity and context strata; vary seeds, prompts, ordering, model and evaluator versions, difficulty, demographics, and environment, and reject rank reversals, aggregation masking, leakage, evaluator manipulation, or claims unsupported by confidence bounds.",
                    "test",
                    False,
                    ["benchmark-scorecard.json", "effectiveness.json"],
                )
            ],
        },
    }
)

_ASSURANCE_PROFILES.update(
    {
        "ai-application-security-verification": {
            "standards": [
                "OWASP-AISVS",
                "OWASP-AITG",
                "OWASP-LLM-TOP-10",
                "OWASP-AGENTIC-TOP-10",
                "NIST-SP-800-218A",
            ],
            "controls": [
                (
                    "OWASP-AISVS",
                    "AI-VERIFICATION-LEVEL-AND-SCOPE",
                    "Pin AISVS 1.0, declare the target AI system, lifecycle stages, deployment and model boundaries, data and model providers, applicable Level 1 through 3 requirements, exclusions, compensating controls, owners, and claim limits before assessment.",
                    ["security-requirements-coverage.json", "domain-assurance.json"],
                ),
                (
                    "OWASP-AISVS",
                    "AI-ASSET-DATA-MODEL-AND-SUPPLY-CHAIN",
                    "Trace AI assets, datasets, labels, models, prompts, retrieval sources, tools, plugins, memory, identities, dependencies, training and serving infrastructure, provenance, authorization, integrity, privacy, monitoring, change, and retirement to retained evidence.",
                    ["lifecycle-traceability.json", "data-exposure.json"],
                ),
                (
                    "OWASP-AISVS",
                    "AI-AUTHORITY-AND-RUNTIME-CONTAINMENT",
                    "Constrain model and agent authority with least privilege, explicit tool and data allowlists, untrusted-output handling, instruction and context boundaries, rate and resource limits, human approval, safe failure, kill switches, auditability, incident response, and recoverable state.",
                    ["llm-adversarial-plan.json", "architecture-evaluation.json"],
                ),
            ],
            "procedures": [
                (
                    "OWASP-AISVS",
                    "AISVS-REQUIREMENT-NEGATIVE-AND-MUTATION-CONFORMANCE",
                    "Reperform every applicable requirement against immutable positive, negative, boundary, and mutation fixtures; challenge prompt and indirect injection, poisoning, extraction, unsafe output handling, tool misuse, excessive agency, memory contamination, cross-tenant access, model replacement, monitoring loss, and retirement failures with source-bound evidence and independent adjudication.",
                    "dynamic",
                    True,
                    ["benchmark-scorecard.json", "llm-adversarial-plan.json"],
                )
            ],
        },
        "responsible-ai-system-assurance": {
            "standards": [
                "ISO-IEC-TS-25058",
                "ISO-IEC-TR-27563",
                "ISO-IEC-TR-24030",
                "IEEE-7000",
                "IEEE-7001",
                "IEEE-7002",
                "IEEE-7003",
                "IEEE-7009",
                "ISO-IEC-25059",
            ],
            "controls": [
                (
                    "ISO-IEC-TS-25058",
                    "AI-QUALITY-EVALUATION-DESIGN",
                    "Select an AI quality model and context, stakeholders, intended and prohibited uses, measures, datasets, strata, environments, uncertainty, acceptance thresholds, evaluator independence, limitations, and post-deployment monitoring before observing results.",
                    ["effectiveness.json", "benchmark-scorecard.json"],
                ),
                (
                    "IEEE-7000",
                    "ETHICAL-VALUE-TRACEABILITY",
                    "Trace affected stakeholders, value conflicts, foreseeable harms, legal and social context, prioritized ethical values, requirements, design decisions, tradeoffs, verification, residual concerns, escalation, and accountable approvals throughout the lifecycle.",
                    ["lifecycle-traceability.json", "domain-assurance.json"],
                ),
                (
                    "IEEE-7001",
                    "MEASURABLE-TRANSPARENCY",
                    "Define audience-specific transparency objectives and testable information levels for users, affected persons, operators, investigators, and regulators without exposing protected secrets or presenting explanations beyond demonstrated fidelity.",
                    ["domain-assurance.json", "effectiveness.json"],
                ),
                (
                    "IEEE-7003",
                    "ALGORITHMIC-BIAS-PROCESS",
                    "Predeclare affected groups, intended population, validation data, intersectional strata, metrics, thresholds, uncertainty, application boundaries, utility tradeoffs, appeals, monitoring, drift, and remediation for intentional and unintentional bias.",
                    ["effectiveness.json", "data-exposure.json"],
                ),
                (
                    "IEEE-7009",
                    "AUTONOMOUS-FAIL-SAFE-DESIGN",
                    "Identify unsafe states and failure modes and retain independent monitors, bounded authority, degraded modes, intervention, shutdown, rollback, recovery, logging, validation, and residual-risk decisions for autonomous and semi-autonomous behavior.",
                    ["safety-security-analysis.json", "architecture-evaluation.json"],
                ),
            ],
            "procedures": [
                (
                    "ISO-IEC-TR-27563",
                    "DOMAIN-USE-CASE-ETHICS-PRIVACY-AND-SAFETY-CHALLENGE",
                    "Select representative domain use cases and execute blinded normal, adverse, out-of-domain, subgroup, transparency, privacy, misuse, safe-state, recovery, and appeal scenarios; report confidence bounds and reject aggregate results that hide material strata or unsupported claims.",
                    "test",
                    True,
                    ["benchmark-scorecard.json", "threat-model-assessment.json"],
                )
            ],
        },
        "eucc-product-certification": {
            "standards": [
                "EU-EUCC",
                "ISO-IEC-15408",
                "ISO-IEC-18045",
                "ISO-IEC-17025",
                "ISO-IEC-17065",
                "ISO-IEC-29147",
                "ISO-IEC-30111",
            ],
            "controls": [
                (
                    "EU-EUCC",
                    "EUCC-SCHEME-AND-ASSURANCE-CLAIM",
                    "Pin the applicable EUCC regulation, amendment, Common Criteria and evaluation-method editions, assurance level, protection profile, technical domain, state-of-the-art documents, transition rules, evaluation facility, certification body, accreditation and authorization status, and claim boundary.",
                    ["external-conformity-assessment.json", "control-assessment.json"],
                ),
                (
                    "EU-EUCC",
                    "EUCC-CERTIFICATE-PRODUCT-IDENTITY",
                    "Bind certificate and report identifiers, product series, versions, configurations, security target, TOE and physical boundaries, dependencies, development and manufacturing sites, evaluation evidence, validity period, public registry status, and cryptographic digests without extending the certified scope.",
                    [
                        "external-conformity-assessment.json",
                        "audit-package-verification.json",
                    ],
                ),
                (
                    "EU-EUCC",
                    "EUCC-ASSURANCE-CONTINUITY",
                    "Govern product changes, impact analysis, minor and major classification, vulnerability monitoring and disclosure, patching, surveillance, certificate suspension or withdrawal, re-evaluation, series certification, and customer notification across the certificate lifecycle.",
                    ["finding-validation.json", "release-readiness.json"],
                ),
            ],
            "procedures": [
                (
                    "EU-EUCC",
                    "EUCC-CERTIFICATE-SCOPE-CONTINUITY-REPERFORMANCE",
                    "Verify public certificate and laboratory authority, reperform sampled security-target and evaluation-evidence links, and inject expired, withdrawn, wrong-version, wrong-configuration, unaccredited, changed-product, missing-vulnerability, and unsupported-assurance claims; require fail-closed disposition.",
                    "test",
                    False,
                    ["benchmark-scorecard.json", "external-conformity-assessment.json"],
                )
            ],
        },
        "federal-software-attestation": {
            "standards": [
                "CISA-SECURE-SOFTWARE-ATTESTATION",
                "NIST-SSDF",
                "NIST-SP-800-218A",
                "SLSA",
                "SPDX",
            ],
            "controls": [
                (
                    "CISA-SECURE-SOFTWARE-ATTESTATION",
                    "ATTESTATION-PRODUCT-SCOPE",
                    "Bind producer identity, product and covered version, development and build scope, delivery model, attestation date, applicable form revision, covered SSDF practices, inherited services, exclusions, exceptions, and agency-specific conditions to immutable release subjects.",
                    ["release-evidence-manifest.json", "security-passport.json"],
                ),
                (
                    "CISA-SECURE-SOFTWARE-ATTESTATION",
                    "ATTESTATION-SIGNATORY-AUTHORITY",
                    "Verify the authorized signatory identity, role, authority, signature, trusted time, producer relationship, non-repudiation, revocation status, and separation from evidence preparation and approval.",
                    [
                        "audit-package-verification.json",
                        "trust-policy-attestation.json",
                    ],
                ),
                (
                    "CISA-SECURE-SOFTWARE-ATTESTATION",
                    "ATTESTATION-EVIDENCE-AND-EXCEPTIONS",
                    "Trace every asserted practice and exception to current, product-bound evidence, compensating controls, risk acceptance, owner, expiry, remediation, vulnerability disclosure, provenance, SBOM, and change-triggered re-attestation.",
                    ["control-proof.json", "closure-plan.json"],
                ),
            ],
            "procedures": [
                (
                    "CISA-SECURE-SOFTWARE-ATTESTATION",
                    "ATTESTATION-FORGERY-SCOPE-AND-STALE-EVIDENCE-CHALLENGE",
                    "Validate the form contract and inject unauthorized signers, altered products, uncovered versions, stale evidence, detached SBOMs, unsigned exceptions, expired approvals, contradictory claims, dependency changes, and replayed attestations; require deterministic rejection and an accountable renewal path.",
                    "test",
                    False,
                    ["benchmark-scorecard.json", "release-evidence-manifest.json"],
                )
            ],
        },
        "it-quality-governance": {
            "standards": [
                "ISO-IEC-38500",
                "ISO-9001",
                "ISO-IEC-IEEE-90003",
                "ISO-IEC-27000",
                "COBIT-2019",
            ],
            "controls": [
                (
                    "ISO-IEC-38500",
                    "GOVERNING-BODY-IT-DIRECTION-OVERSIGHT",
                    "Retain governing-body responsibility, strategy alignment, acquisition decisions, performance objectives, conformance obligations, human behavior considerations, delegated authority, risk and opportunity, monitoring, escalation, and improvement for current and future use of IT.",
                    ["domain-assurance.json", "architecture-evaluation.json"],
                ),
                (
                    "ISO-9001",
                    "QUALITY-MANAGEMENT-SYSTEM",
                    "Using a licensed, pinned edition, govern organizational context, interested parties, leadership, quality policy and objectives, risks and opportunities, resources, competence, operational controls, supplier inputs, monitoring, internal audit, management review, nonconformity, corrective action, and improvement.",
                    [
                        "process-capability-assessment.json",
                        "audit-package-verification.json",
                    ],
                ),
                (
                    "ISO-IEC-27000",
                    "ISMS-CONCEPT-AND-RELATIONSHIP-INTEGRITY",
                    "Maintain unambiguous organization-approved definitions and relationships among information-security management systems, risk, controls, objectives, assessment, audit, interested parties, and continual improvement across evidence and claims.",
                    ["control-assessment.json", "domain-assurance.json"],
                ),
            ],
            "procedures": [
                (
                    "ISO-IEC-38500",
                    "IT-QUALITY-GOVERNANCE-BLINDED-ASSESSMENT",
                    "Blind independent assessors to expected outcomes and evaluate representative governance and quality cases containing conflicting objectives, unclear accountability, failed suppliers, weak measures, nonconformities, unsafe acquisitions, evidence gaps, and improvement decisions; require agreement and adjudication.",
                    "manual",
                    False,
                    ["benchmark-scorecard.json", "process-capability-assessment.json"],
                )
            ],
        },
        "nist-csf-profile-management": {
            "standards": ["NIST-CSF", "NIST-SP-1301", "NIST-IR-8286"],
            "controls": [
                (
                    "NIST-SP-1301",
                    "CSF-CURRENT-TARGET-PROFILE",
                    "Create source-pinned current and target organizational profiles using valid CSF identifiers, tiers and informative references; retain scope, mission, stakeholders, assumptions, evidence, rationale, dependencies, priorities, tailoring, omissions, approvals, and dates.",
                    ["domain-assurance.json", "control-assessment.json"],
                ),
                (
                    "NIST-SP-1301",
                    "CSF-GAP-ACTION-REASSESSMENT",
                    "Trace each current-to-target gap to risk, business consequence, priority, action, owner, resources, dependency, milestone, acceptance criterion, evidence, status, exception, and reassessment without treating an aspirational target as an implemented outcome.",
                    ["closure-plan.json", "operational-trend.json"],
                ),
            ],
            "procedures": [
                (
                    "NIST-SP-1301",
                    "CSF-PROFILE-DIFF-AND-REASSESSMENT-CONFORMANCE",
                    "Validate identifiers and profile semantics, deterministically diff current and target states, reperform priorities and sampled outcomes, and inject unsupported implementation claims, missing evidence, stale targets, orphaned actions, circular dependencies, expired exceptions, and regression masked by aggregation.",
                    "test",
                    False,
                    ["benchmark-scorecard.json", "domain-assurance.json"],
                )
            ],
        },
        "privacy-engineering-pets": {
            "standards": [
                "ISO-IEC-27561",
                "ISO-IEC-TS-27564",
                "ISO-IEC-27565",
                "ISO-31700",
                "ISO-IEC-29100",
                "NIST-PRIVACY-FRAMEWORK",
            ],
            "controls": [
                (
                    "ISO-IEC-27561",
                    "PRIVACY-OPERATIONALISATION",
                    "Translate privacy principles, stakeholder needs, data processing, harms, obligations, objectives, controls, measures, accountability, residual risk, monitoring, change, and retirement into a traceable engineering model and method.",
                    ["data-exposure.json", "lifecycle-traceability.json"],
                ),
                (
                    "ISO-IEC-TS-27564",
                    "PRIVACY-MODEL-VALIDATION",
                    "Define model purpose, vocabulary, entities, data and trust boundaries, assumptions, attacker capabilities, properties, composition, abstraction limits, validation, versioning, and traceability to implementation and evidence.",
                    ["architecture-evaluation.json", "threat-model-assessment.json"],
                ),
                (
                    "ISO-IEC-27565",
                    "ZERO-KNOWLEDGE-PRIVACY-PRESERVATION",
                    "For applicable zero-knowledge proofs, bind the statement, witness relation, setup and trust assumptions, parameters, prover and verifier implementations, randomness, soundness and privacy claims, composition, side channels, revocation, agility, and claim limits to reviewed cryptographic evidence.",
                    ["control-proof.json", "benchmark-scorecard.json"],
                ),
            ],
            "procedures": [
                (
                    "ISO-IEC-27565",
                    "PRIVACY-MODEL-AND-ZKP-ADVERSARIAL-CONFORMANCE",
                    "Execute positive, negative, malformed, replay, cross-context, linkability, setup-substitution, weak-randomness, parameter-confusion, side-channel, composition, downgrade, and implementation-differential cases using approved public vectors and independently reviewed private cases.",
                    "test",
                    True,
                    ["benchmark-scorecard.json", "control-proof.json"],
                )
            ],
        },
    }
)

_ASSURANCE_PROFILES.update(
    {
        "mcp-protocol-security": {
            "standards": [
                "MCP-SPECIFICATION",
                "OWASP-MCP-SECURITY-CHEAT-SHEET",
                "IETF-RFC-9700",
                "JSON-SCHEMA",
            ],
            "controls": [
                (
                    "MCP-SPECIFICATION",
                    "MCP-PROTOCOL-AND-CAPABILITY-BOUNDARY",
                    "Pin the negotiated protocol revision and schemas; validate JSON-RPC envelopes, lifecycle state, capability declarations, method direction, identifiers, pagination, cancellation, progress, task ownership, and unsupported-feature failure without trusting server-supplied metadata.",
                    [
                        "security-automation-interoperability.json",
                        "application-contract-analysis.json",
                    ],
                ),
                (
                    "MCP-SPECIFICATION",
                    "MCP-AUTHORIZATION-AND-TOKEN-BOUNDARY",
                    "Validate protected-resource and authorization-server discovery, exact redirect handling, PKCE, state, resource indicators, token audience and issuer, scope challenges, refresh handling, task context binding, and separate downstream credentials; prohibit access-token passthrough, ambient credential inheritance, and authorization confusion.",
                    ["control-proof.json", "trust-policy-attestation.json"],
                ),
                (
                    "OWASP-MCP-SECURITY-CHEAT-SHEET",
                    "MCP-TOOL-RESOURCE-PROMPT-AND-SAMPLING-SAFETY",
                    "Treat tool descriptions, schemas, resources, prompts, elicitation, sampling, roots, links, embedded content, errors, and server changes as untrusted; require least privilege, explicit authority, schema drift detection, user-visible consent, output validation, secret minimization, bounded execution, provenance, audit, revocation, and safe failure.",
                    [
                        "threat-model-assessment.json",
                        "llm-adversarial-plan.json",
                    ],
                ),
            ],
            "procedures": [
                (
                    "MCP-SPECIFICATION",
                    "MCP-CLIENT-SERVER-PROXY-ADVERSARIAL-CONFORMANCE",
                    "Execute schema, lifecycle, capability, authorization, transport, task, tool, resource, prompt, elicitation, sampling, consent, and proxy cases against disposable clients and servers; inject malformed messages, version and schema drift, audience confusion, token passthrough, SSRF metadata, redirect abuse, scope escalation, cross-tenant task access, malicious descriptions, prompt injection, oversized content, replay, cancellation races, and server replacement, requiring deterministic containment and cleanup.",
                    "dynamic",
                    True,
                    [
                        "benchmark-scorecard.json",
                        "security-automation-interoperability.json",
                    ],
                )
            ],
        },
        "cloud-provider-native-security": {
            "standards": [
                "AWS-FOUNDATIONAL-SECURITY-BEST-PRACTICES",
                "MICROSOFT-CLOUD-SECURITY-BENCHMARK",
                "GCP-ENTERPRISE-FOUNDATIONS-BLUEPRINT",
                "CSA-CCM",
                "CIS-BENCHMARKS",
            ],
            "controls": [
                (
                    "AWS-FOUNDATIONAL-SECURITY-BEST-PRACTICES",
                    "AWS-FSBP-SCOPE-FINDING-AND-EXCEPTION-INTEGRITY",
                    "Bind the current FSBP control snapshot to every governed account, organizational unit, enabled region, resource inventory, Security Hub finding, delegated administrator, aggregation region, suppression, exception owner, expiry, remediation, and rescanned outcome without converting not-assessed or unavailable controls into passes.",
                    ["control-assessment.json", "cloud-attack-paths.json"],
                ),
                (
                    "MICROSOFT-CLOUD-SECURITY-BENCHMARK",
                    "MCSB-SCOPE-BASELINE-AND-DEFENDER-INTEGRITY",
                    "Pin MCSB v1 controls and service baselines to Azure tenants, management groups, subscriptions, resources, Defender assessments, initiatives, exemptions, shared responsibilities, evidence freshness, remediation, and reassessment while separating preview MCSB v2 observations from normative claims.",
                    ["control-assessment.json", "cloud-attack-paths.json"],
                ),
                (
                    "GCP-ENTERPRISE-FOUNDATIONS-BLUEPRINT",
                    "GCP-FOUNDATION-POLICY-ARCHITECTURE-AND-DETECTION",
                    "Trace the pinned foundation blueprint and Terraform revision to organizations, folders, projects, identities, networks, organization policies, logging, keys, secrets, Security Command Center findings, deviations, inheritance, drift, remediation, and post-change verification.",
                    ["architecture-evaluation.json", "cloud-attack-paths.json"],
                ),
            ],
            "procedures": [
                (
                    "CIS-BENCHMARKS",
                    "CLOUD-NATIVE-CONTROL-DRIFT-AND-ATTACK-PATH-CHALLENGE",
                    "Reconcile provider-native findings with independent inventory and IaC, then inject cross-account and cross-project omissions, disabled regions, inherited policy changes, stale suppressions, public exposure, excessive identity, logging loss, key misuse, unencrypted data, vulnerable workload paths, and remediation regressions in authorized disposable tenants; require complete cleanup and rescanning.",
                    "dynamic",
                    True,
                    ["benchmark-scorecard.json", "cloud-attack-paths.json"],
                )
            ],
        },
        "incident-response-service-maturity": {
            "standards": [
                "FIRST-CSIRT-SERVICES-FRAMEWORK",
                "FIRST-PSIRT-SERVICES-FRAMEWORK",
                "FIRST-PSIRT-MATURITY",
                "ISO-IEC-29147",
                "ISO-IEC-30111",
                "NIST-SP-800-61",
            ],
            "controls": [
                (
                    "FIRST-CSIRT-SERVICES-FRAMEWORK",
                    "CSIRT-MANDATE-CONSTITUENCY-AND-SERVICE-CATALOG",
                    "Maintain an approved mandate, constituency, authority, governance model, funding, roles, competencies, service catalog, service levels, intake paths, dependencies, information-sharing rules, measures, escalation, availability, and improvement plan matched to organizational needs rather than claiming every optional service.",
                    [
                        "maturity-model-assessment.json",
                        "process-capability-assessment.json",
                    ],
                ),
                (
                    "FIRST-PSIRT-SERVICES-FRAMEWORK",
                    "PSIRT-PRODUCT-VULNERABILITY-OPERATIONS",
                    "Trace supported products and components, reporting channels, researcher communications, qualification, reproduction, prioritization, remediation, branch and version support, coordinated disclosure, advisory and machine-readable publication, downstream notification, incidents, metrics, and lessons learned to accountable evidence.",
                    ["finding-validation.json", "operational-trend.json"],
                ),
                (
                    "FIRST-PSIRT-MATURITY",
                    "PSIRT-CAPABILITY-MATURITY-CLAIM",
                    "Score maturity only from current service capability and outcome evidence, retain assessor identity and independence, expose unavailable or weak services, prevent compensating strength from hiding foundational gaps, and bind every improvement target to an owner, date, acceptance criterion, and reassessment.",
                    ["maturity-model-assessment.json", "closure-plan.json"],
                ),
            ],
            "procedures": [
                (
                    "FIRST-PSIRT-MATURITY",
                    "CSIRT-PSIRT-BLINDED-SCENARIO-AND-MATURITY-ASSESSMENT",
                    "Have independent assessors evaluate blinded event, incident, vulnerability, disclosure, supplier, end-of-support, crisis-communication, and multi-party coordination scenarios; measure agreement, service outcomes, handoffs, timeliness, evidence integrity, recovery, appeals, and improvement closure rather than document presence alone.",
                    "manual",
                    True,
                    [
                        "benchmark-scorecard.json",
                        "maturity-model-assessment.json",
                    ],
                )
            ],
        },
        "memory-safety-engineering": {
            "standards": [
                "CISA-MEMORY-SAFE-ROADMAPS",
                "ISO-IEC-TR-24772",
                "SEI-CERT-C",
                "SEI-CERT-CPP",
                "ISO-IEC-TS-17961",
            ],
            "controls": [
                (
                    "CISA-MEMORY-SAFE-ROADMAPS",
                    "MEMORY-UNSAFE-FOOTPRINT-AND-BOUNDARY-INVENTORY",
                    "Inventory memory-unsafe languages, unsafe constructs, FFI and ABI boundaries, privileged and exposed components, parsers, codecs, dependencies, generated code, build profiles, ownership, exploitability, and production reachability using source and build evidence rather than file extensions alone.",
                    ["code-health.json", "static-architecture.json"],
                ),
                (
                    "CISA-MEMORY-SAFE-ROADMAPS",
                    "MEMORY-SAFETY-ELIMINATION-HARDENING-AND-MIGRATION",
                    "Prefer memory-safe implementation for new and replacement code; prioritize migration by privilege, exposure and consequence; minimize and encapsulate unavoidable unsafe boundaries; enable supported compiler, linker, allocator and runtime protections; govern exceptions, dependencies, interoperability, rollback, milestones, funding, owners, measures, and reassessment.",
                    ["closure-plan.json", "lifecycle-traceability.json"],
                ),
                (
                    "ISO-IEC-TR-24772",
                    "MEMORY-SAFETY-VERIFICATION-EVIDENCE",
                    "Retain warning-clean builds, language-specific static analysis, sanitizers, fuzzing, property and boundary tests, exploit mitigations, crash deduplication, root-cause classification, regression tests, negative controls, production-equivalent build flags, and residual-risk acceptance for applicable native-code paths.",
                    ["test-evidence.json", "finding-validation.json"],
                ),
            ],
            "procedures": [
                (
                    "CISA-MEMORY-SAFE-ROADMAPS",
                    "MEMORY-SAFETY-BUILD-RUNTIME-AND-MIGRATION-CONFORMANCE",
                    "Rebuild representative release configurations and execute static, sanitizer, fuzz, malformed-input, allocation-failure, concurrency, FFI, exploit-mitigation, and migration-parity cases over high-risk native boundaries; inject disabled hardening, uninstrumented modules, unsafe dependency changes, swallowed crashes, stale exceptions, and roadmap slippage, requiring traceable rejection or bounded risk acceptance.",
                    "dynamic",
                    True,
                    ["benchmark-scorecard.json", "test-evidence.json"],
                )
            ],
        },
        "organizational-ai-governance-impact": {
            "standards": [
                "IEEE-2863",
                "IEEE-7010",
                "IEEE-7000",
                "ISO-IEC-42001",
                "NIST-AI-RMF",
            ],
            "controls": [
                (
                    "IEEE-2863",
                    "AI-GOVERNING-BODY-PRINCIPLES-PROCESSES-AND-ACCOUNTABILITY",
                    "Retain governing-body principles, priorities, authority, roles, competence, resource decisions, risk appetite, lifecycle gates, provider oversight, human responsibility, conflicts and tradeoffs, performance, compliance, incidents, escalation, reporting, and improvement for every developed or used AI system.",
                    ["domain-assurance.json", "lifecycle-traceability.json"],
                ),
                (
                    "IEEE-7010",
                    "AI-HUMAN-WELLBEING-IMPACT-ASSESSMENT",
                    "Identify intended and unintended users and affected stakeholders, select justified well-being domains and indicators, establish baselines, disaggregate material populations and contexts, collect and analyze post-deployment evidence, monitor intended and unintended impacts, publish bounded reports, and feed findings into design and governance decisions.",
                    ["effectiveness.json", "domain-assurance.json"],
                ),
            ],
            "procedures": [
                (
                    "IEEE-7010",
                    "AI-GOVERNANCE-AND-WELLBEING-BLINDED-ASSESSMENT",
                    "Use independent reviewers and affected-stakeholder scenarios to challenge governance authority, value conflicts, impact pathways, missing populations, indicator validity, gaming, distributional harms, baseline choice, monitoring lag, appeals, incidents, provider changes, and retirement; measure reviewer agreement and require accountable adjudication.",
                    "manual",
                    False,
                    ["benchmark-scorecard.json", "effectiveness.json"],
                )
            ],
        },
        "organizational-resilience-bia": {
            "standards": [
                "ISO-22316",
                "ISO-TS-22317",
                "ISO-22301",
                "ISO-IEC-27031",
                "NIST-SP-800-34",
            ],
            "controls": [
                (
                    "ISO-TS-22317",
                    "BUSINESS-IMPACT-ANALYSIS-EVIDENCE",
                    "Define BIA scope, products and services, activities, resources, internal and external dependencies, disruption scenarios, impact categories and time profiles, maximum tolerable disruption, recovery objectives, minimum capacity, data loss tolerance, assumptions, uncertainty, prioritization, approvals, change triggers, and review dates.",
                    ["architecture-evaluation.json", "lifecycle-traceability.json"],
                ),
                (
                    "ISO-22316",
                    "ORGANIZATIONAL-RESILIENCE-CAPABILITY",
                    "Assess shared purpose, leadership, culture, information, awareness, adaptive capacity, coordinated disciplines, resource availability, supplier and community dependencies, anticipation, learning, and improvement using observed outcomes rather than continuity documents alone.",
                    [
                        "maturity-model-assessment.json",
                        "process-capability-assessment.json",
                    ],
                ),
            ],
            "procedures": [
                (
                    "ISO-TS-22317",
                    "BIA-DEPENDENCY-DEGRADATION-AND-RECOVERY-EXERCISE",
                    "Exercise authorized dependency loss, regional or provider outage, identity and key unavailability, data corruption, staff loss, degraded capacity, supplier failure, conflicting priorities, failover, restoration, reconciliation and backlog recovery; compare measured impacts and recovery against approved BIA assumptions and feed material variance into reassessment.",
                    "test",
                    True,
                    ["benchmark-scorecard.json", "operational-trend.json"],
                )
            ],
        },
        "open-source-project-assurance": {
            "standards": [
                "OPENSSF-BEST-PRACTICES-BADGE",
                "OpenSSF-OSPS",
                "SLSA",
                "SPDX",
            ],
            "controls": [
                (
                    "OPENSSF-BEST-PRACTICES-BADGE",
                    "OPENSSF-BADGE-CLAIM-EVIDENCE-AND-FRESHNESS",
                    "Pin the selected baseline or metal criteria revision and bind every claimed answer to current repository, release, vulnerability-reporting, testing, quality, hardening, dependency, provenance, governance, and project-identity evidence; preserve not-met and not-applicable rationale and never treat a badge image or self-assertion as independent verification.",
                    ["control-assessment.json", "audit-package-verification.json"],
                ),
            ],
            "procedures": [
                (
                    "OPENSSF-BEST-PRACTICES-BADGE",
                    "OPENSSF-BADGE-RECOMPUTATION-AND-STALE-CLAIM-CHALLENGE",
                    "Recompute applicable criteria from a pinned project response export and immutable repository snapshot; sample source evidence and inject stale links, renamed projects, missing branches, disabled tests, unsigned releases, unhandled vulnerabilities, dependency drift, unsupported not-applicable answers, and badge-level inflation, requiring deterministic downgrade or rejection.",
                    "test",
                    False,
                    ["benchmark-scorecard.json", "control-assessment.json"],
                )
            ],
        },
        "isms-implementation-process": {
            "standards": [
                "ISO-IEC-27003",
                "ISO-IEC-TS-27022",
                "ISO-IEC-27001",
                "ISO-IEC-27004",
                "ISO-IEC-27005",
            ],
            "controls": [
                (
                    "ISO-IEC-27003",
                    "ISMS-IMPLEMENTATION-TAILORING-AND-TRACEABILITY",
                    "Use licensed, pinned guidance to trace context, interested parties, scope, leadership, policy, risk criteria, objectives, controls, resources, competence, communications, operational plans, performance evaluation, audit, management review, corrective action, and improvement into the implemented ISMS without converting guidance into fabricated certification requirements.",
                    [
                        "process-capability-assessment.json",
                        "control-assessment.json",
                    ],
                ),
                (
                    "ISO-IEC-TS-27022",
                    "ISMS-PROCESS-REFERENCE-AND-CAPABILITY",
                    "Map implemented ISMS processes to the pinned process reference model, retain inputs, outputs, responsibilities, interfaces, measures, controls, records, capability evidence, weaknesses, corrective actions, and reassessment while separating process capability from ISO/IEC 27001 conformity.",
                    [
                        "process-capability-assessment.json",
                        "maturity-model-assessment.json",
                    ],
                ),
            ],
            "procedures": [
                (
                    "ISO-IEC-TS-27022",
                    "ISMS-IMPLEMENTATION-AND-PROCESS-ASSESSOR-CALIBRATION",
                    "Have qualified independent assessors evaluate blinded ISMS implementation and process cases with scope errors, missing interfaces, contradictory risk criteria, weak measures, stale evidence, ineffective controls, unsupported capability claims, audit conflicts, unclosed corrective actions, and management-review omissions; require agreement, adjudication, and claim-boundary review.",
                    "manual",
                    False,
                    [
                        "benchmark-scorecard.json",
                        "process-capability-assessment.json",
                    ],
                )
            ],
        },
    }
)

# These extensions keep adjacent standards in the established evidence packs so
# adopters receive a coherent assurance objective instead of disconnected catalog
# entries. Licensed standards are represented by identifiers and evidence contracts;
# their normative text is never embedded or implied by this registry.
_ASSURANCE_PROFILES["software-lifecycle-traceability"]["standards"].extend(
    [
        "ISO-IEC-IEEE-24748-1",
        "ISO-IEC-IEEE-15289",
        "ISO-IEC-IEEE-16085",
        "ISO-IEC-IEEE-90003",
    ]
)
_ASSURANCE_PROFILES["software-lifecycle-traceability"]["controls"].extend(
    [
        (
            "ISO-IEC-IEEE-24748-1",
            "LIFECYCLE-MANAGEMENT-PLAN",
            "Govern lifecycle models, stages, decision gates, roles, tailoring, dependencies, transitions, records, and retirement with approved plans and objective completion evidence.",
            ["lifecycle-traceability.json", "process-capability-assessment.json"],
        ),
        (
            "ISO-IEC-IEEE-15289",
            "INFORMATION-ITEM-TRACEABILITY",
            "Define required lifecycle information items, content, ownership, configuration state, approval, retention, and bidirectional traceability without claiming undocumented deliverables.",
            ["lifecycle-traceability.json", "audit-package-verification.json"],
        ),
        (
            "ISO-IEC-IEEE-16085",
            "LIFECYCLE-RISK-TRACE",
            "Trace identified risks, assumptions, criteria, treatment decisions, owners, residual exposure, monitoring, escalation, and closure across lifecycle stages and system levels.",
            ["risk-paths.json", "lifecycle-traceability.json"],
        ),
        (
            "ISO-IEC-IEEE-90003",
            "SOFTWARE-QUALITY-MANAGEMENT",
            "Bind software quality objectives, process controls, competence, supplier inputs, verification, nonconformity, corrective action, measurement, and continual improvement to retained evidence.",
            ["process-capability-assessment.json", "code-health.json"],
        ),
    ]
)
_ASSURANCE_PROFILES["software-lifecycle-traceability"]["procedures"].append(
    (
        "ISO-IEC-IEEE-15289",
        "LIFECYCLE-RECORD-OMISSION-CHALLENGE",
        "Remove, stale, misapprove, or detach representative lifecycle information items and verify that gate, risk, traceability, and release decisions reject incomplete evidence.",
        "test",
        False,
        ["benchmark-scorecard.json", "lifecycle-traceability.json"],
    )
)

_ASSURANCE_PROFILES["software-quality-evaluation"]["standards"].extend(
    [
        "ISO-IEC-25001",
        "ISO-IEC-25002",
        "ISO-IEC-25021",
        "ISO-IEC-25022",
        "ISO-IEC-25051",
    ]
)
_ASSURANCE_PROFILES["software-quality-evaluation"]["controls"].extend(
    [
        (
            "ISO-IEC-25001",
            "SQUARE-PLANNING-AND-MANAGEMENT",
            "Govern quality-requirements and evaluation technology, methods, tools, competence, roles, resources, schedules, records, deviations, feedback, and improvement against a licensed, policy-pinned SQuaRE requirement set.",
            ["process-capability-assessment.json", "benchmark-scorecard.json"],
        ),
        (
            "ISO-IEC-25002",
            "QUALITY-MODEL-SELECTION",
            "Select and justify quality models for the product, service, data, and quality-in-use contexts; retain tailoring, exclusions, conflicts, and stakeholder decision needs.",
            ["security-requirements-coverage.json", "code-health.json"],
        ),
        (
            "ISO-IEC-25021",
            "QUALITY-MEASURE-ELEMENTS",
            "Define base and derived measure elements, units, scales, collection methods, validity, uncertainty, aggregation, thresholds, and decision rules before observing results.",
            ["code-health.json", "effectiveness.json"],
        ),
        (
            "ISO-IEC-25051",
            "READY-TO-USE-PRODUCT-ACCEPTANCE",
            "Trace product descriptions, user documentation, quality requirements, test requirements, test records, anomalies, and acceptance decisions for ready-to-use software.",
            ["security-requirements-coverage.json", "test-evidence.json"],
        ),
    ]
)
_ASSURANCE_PROFILES["software-quality-evaluation"]["procedures"].append(
    (
        "ISO-IEC-25022",
        "QUALITY-IN-USE-REPRODUCTION",
        "Reproduce effectiveness, efficiency, satisfaction, freedom-from-risk, and context-coverage measures over declared users, tasks, environments, uncertainty, strata, and adverse cases.",
        "test",
        False,
        ["benchmark-scorecard.json", "effectiveness.json"],
    )
)
_ASSURANCE_PROFILES["software-quality-evaluation"]["procedures"].append(
    (
        "ISO-IEC-25001",
        "SQUARE-MANAGEMENT-FAULT-CHALLENGE",
        "Reperform sampled quality evaluations and inject unqualified personnel, unvalidated methods, stale tools, missing plans, changed thresholds, incomplete records, conflicts of interest, and ignored feedback; require deterministic rejection or accountable deviation handling.",
        "test",
        False,
        ["process-capability-assessment.json", "benchmark-scorecard.json"],
    )
)

_ASSURANCE_PROFILES["enterprise-risk-techniques"]["standards"].extend(
    ["NIST-SP-800-30", "NIST-SP-800-39", "ISO-IEC-IEEE-16085"]
)
_ASSURANCE_PROFILES["enterprise-risk-techniques"]["controls"].extend(
    [
        (
            "NIST-SP-800-30",
            "SYSTEM-RISK-ASSESSMENT",
            "Retain threat sources and events, vulnerabilities and predisposing conditions, likelihood, impact, uncertainty, assumptions, evidence, and risk determinations for the assessed system scope.",
            ["risk-paths.json", "control-assessment.json"],
        ),
        (
            "NIST-SP-800-39",
            "MULTI-TIER-RISK-TRACE",
            "Trace organization, mission and business process, and information-system risk decisions, risk appetite, common controls, dependencies, escalation, aggregation, and feedback without collapsing distinct contexts.",
            ["risk-paths.json", "domain-assurance.json"],
        ),
    ]
)

_ASSURANCE_PROFILES["privacy"]["standards"].extend(
    [
        "ISO-IEC-29100",
        "ISO-IEC-29151",
        "ISO-IEC-27557",
        "ISO-IEC-TR-27550",
        "ISO-IEC-38505-1",
    ]
)
_ASSURANCE_PROFILES["privacy"]["controls"].extend(
    [
        (
            "ISO-IEC-29151",
            "PII-PROTECTION-CONTROLS",
            "Map PII processing purposes, roles, jurisdictions, data categories, lifecycle states, transfers, retention, deletion, incidents, and applicable protection controls to objective evidence.",
            ["data-exposure.json", "control-assessment.json"],
        ),
        (
            "ISO-IEC-27557",
            "ORGANIZATIONAL-PRIVACY-RISK",
            "Govern privacy risk criteria, affected stakeholders, consequences, likelihood, uncertainty, treatments, residual risk, consultation, monitoring, and accountable acceptance.",
            ["data-exposure.json", "risk-paths.json"],
        ),
        (
            "ISO-IEC-TR-27550",
            "PRIVACY-ENGINEERING-LIFECYCLE",
            "Trace privacy principles and stakeholder needs through architecture, requirements, implementation, verification, deployment, operation, change, and retirement.",
            ["data-exposure.json", "lifecycle-traceability.json"],
        ),
        (
            "ISO-IEC-38505-1",
            "ACCOUNTABLE-DATA-GOVERNANCE",
            "Assign governing-body accountability for data value, risk, authority, quality, provenance, access, sharing, retention, disposal, and AI use across organizational boundaries.",
            ["data-exposure.json", "domain-assurance.json"],
        ),
    ]
)
_ASSURANCE_PROFILES["privacy"]["procedures"].append(
    (
        "ISO-IEC-29151",
        "PII-CONTROL-NEGATIVE-CHALLENGE",
        "Challenge purpose limitation, minimization, access, transfer, retention, deletion, logging, consent or authority, breach handling, and processor boundaries with synthetic PII and independently reviewed outcomes.",
        "test",
        True,
        ["data-exposure.json", "benchmark-scorecard.json"],
    )
)

_ASSURANCE_PROFILES["ai-lifecycle-data-evaluation"]["standards"].extend(
    [
        "ISO-IEC-22989",
        "ISO-IEC-23053",
        "ISO-IEC-38507",
        "ISO-IEC-38505-1",
        "ISO-IEC-8183",
        "ISO-IEC-12792",
        "ISO-IEC-TS-6254",
        "ISO-IEC-TS-8200",
        "ISO-IEC-TS-12791",
        "ISO-IEC-TR-5469",
        "ISO-IEC-TR-42106",
    ]
)
_ASSURANCE_PROFILES["ai-lifecycle-data-evaluation"]["controls"].extend(
    [
        (
            "ISO-IEC-22989",
            "AI-CONCEPT-CLAIM-SEMANTICS",
            "Use a governed AI vocabulary and retain explicit meanings, system roles, capabilities, limitations, autonomy, learning, inference, and human-oversight claims across evidence artifacts.",
            ["domain-assurance.json", "llm-adversarial-plan.json"],
        ),
        (
            "ISO-IEC-23053",
            "ML-SYSTEM-FRAMEWORK-TRACE",
            "Trace data acquisition and preparation, training, validation, inference, interfaces, feedback, monitoring, human roles, dependencies, and controls through the machine-learning system architecture.",
            ["static-architecture.json", "lifecycle-traceability.json"],
        ),
        (
            "ISO-IEC-38507",
            "GOVERNING-BODY-AI-OVERSIGHT",
            "Retain governing-body direction and oversight for AI accountability, competence, risk, opportunity, conformance, performance, human impact, escalation, and lifecycle decisions.",
            ["domain-assurance.json", "control-assessment.json"],
        ),
        (
            "ISO-IEC-8183",
            "AI-DATA-LIFECYCLE",
            "Trace data acquisition, creation, preparation, labeling, use, sharing, monitoring, change, retention, deletion, and decommissioning to provenance, authority, quality, privacy, security, bias, drift, and accountable decisions across the AI lifecycle.",
            ["lifecycle-traceability.json", "data-exposure.json"],
        ),
        (
            "ISO-IEC-12792",
            "AI-TRANSPARENCY-INFORMATION",
            "Identify stakeholder-specific transparency objectives and retain accurate, accessible, current, scope-bounded information about purpose, capabilities, limitations, data, operation, decisions, oversight, incidents, and change without exposing protected attack material.",
            ["domain-assurance.json", "audit-package-verification.json"],
        ),
        (
            "ISO-IEC-TS-6254",
            "AI-EXPLAINABILITY-INTERPRETABILITY",
            "Define explanation objectives, recipients, context, fidelity, stability, completeness, usability, limitations, validation, and adverse-case tests; distinguish system explanations from unsupported causal or model-internal claims.",
            ["effectiveness.json", "domain-assurance.json"],
        ),
        (
            "ISO-IEC-TS-8200",
            "AI-CONTROLLABILITY",
            "Specify observable states, permitted transitions, authority, control transfer, uncertainty handling, safe intervention, override, shutdown, recovery, logging, verification, and validation throughout the automated AI system lifecycle.",
            ["architecture-evaluation.json", "llm-adversarial-plan.json"],
        ),
        (
            "ISO-IEC-TS-12791",
            "AI-UNWANTED-BIAS-TREATMENT",
            "Define affected groups, contexts, harms, data and model mechanisms, metrics, thresholds, uncertainty, intersectional strata, treatment choices, utility tradeoffs, monitoring, appeals, and residual limitations for classification and regression tasks.",
            ["effectiveness.json", "data-exposure.json"],
        ),
        (
            "ISO-IEC-TR-5469",
            "AI-FUNCTIONAL-SAFETY-APPLICABILITY",
            "For safety-related AI, identify functional-safety roles, hazards, failure modes, uncertainty, data and model limitations, independence, safe states, monitors, fallback, change impact, verification, and residual risk without replacing the applicable sector safety standard.",
            ["safety-security-analysis.json", "lifecycle-traceability.json"],
        ),
    ]
)
_ASSURANCE_PROFILES["ai-lifecycle-data-evaluation"]["procedures"].append(
    (
        "ISO-IEC-TS-8200",
        "AI-CONTROL-TRANSFER-AND-TRANSPARENCY-CHALLENGE",
        "Exercise state observability, authority transfer, interruption, override, safe shutdown, recovery, uncertainty, stale or poisoned data, explanation instability, transparency omissions, subgroup bias, logging, and lifecycle deletion in a disposable target with independent adjudication.",
        "dynamic",
        True,
        ["llm-adversarial-plan.json", "benchmark-scorecard.json"],
    )
)

_ASSURANCE_PROFILES["firmware-hardware-trust"]["standards"].extend(
    [
        "NIST-SP-800-147",
        "NIST-SP-800-147B",
        "NIST-SP-1800-34",
        "NIST-CSWP-45",
        "NIST-CSWP-52",
    ]
)
_ASSURANCE_PROFILES["firmware-hardware-trust"]["controls"].extend(
    [
        (
            "NIST-SP-800-147B",
            "FIRMWARE-ROOT-OF-TRUST-UPDATE-AND-PLATFORM-IDENTITY",
            "Bind client or server platform model, hardware and firmware components, immutable and mutable regions, root of trust for update, signing hierarchy, recovery authority, anti-rollback state, configuration and update policy to the exact acquired device and firmware release.",
            ["trust-policy-attestation.json", "software-supply-chain.json"],
        ),
        (
            "NIST-SP-1800-34",
            "DEVICE-COMPONENT-PROVENANCE-AND-INTEGRITY-VALIDATION",
            "Verify manufacturer and supplier provenance, component identity, platform certificate, firmware inventory, acquired-versus-observed configuration, cryptographic validation, substitution and tamper evidence across receipt, deployment, update and retirement.",
            ["software-supply-chain.json", "audit-package-verification.json"],
        ),
        (
            "NIST-CSWP-45",
            "HARDWARE-WEAKNESS-ATTACK-THREAT-AND-SENSITIVITY-METRICS",
            "Maintain a versioned hardware weakness and attack graph, reproduce threat and sensitivity metrics, preserve unsupported-component and uncertainty boundaries, and join bus-monitor observations to independently verified events without treating absence of telemetry as absence of compromise.",
            ["domain-assurance.json", "operational-trend.json"],
        ),
    ]
)
_ASSURANCE_PROFILES["firmware-hardware-trust"]["procedures"].append(
    (
        "NIST-SP-1800-34",
        "FIRMWARE-DEVICE-INTEGRITY-SUPPLY-UPDATE-MONITOR-RECOVER-EXERCISE",
        "In an authorized recoverable laboratory, replay genuine, substituted, counterfeit, unsigned, revoked, downgraded, interrupted and corrupt component and firmware cases; independently verify update authorization, measured boot, bus-monitor detection, known-good recovery, post-recovery state and residue.",
        "dynamic",
        True,
        [
            "benchmark-scorecard.json",
            "trust-policy-attestation.json",
            "audit-package-verification.json",
        ],
    )
)

_ASSURANCE_PROFILES.update(
    {
        "space-software-product-assurance": {
            "standards": [
                "ECSS-E-ST-40C",
                "ECSS-Q-ST-80C-REV2",
                "NASA-STD-8739-8B",
                "ISO-IEC-IEEE-12207",
            ],
            "controls": [
                (
                    "ECSS-E-ST-40C",
                    "SPACE-SOFTWARE-CRITICALITY-LIFECYCLE-REQUIREMENT-AND-ARCHITECTURE-TRACE",
                    "Bind mission, system, software item, criticality, acquisition and reuse status to plans, requirements, architecture, interfaces, code, verification, validation, operations and maintenance with bidirectional traceability, independence and tailoring rationale.",
                    ["lifecycle-traceability.json", "static-architecture.json"],
                ),
                (
                    "ECSS-Q-ST-80C-REV2",
                    "SPACE-SOFTWARE-PRODUCT-ASSURANCE-REUSE-ANOMALY-AND-ACCEPTANCE",
                    "Verify software product assurance organization and independence, supplier surveillance, process and product evidence, reuse and COTS qualification, safety and dependability interfaces, metrics, reviews, configuration, nonconformance, anomaly closure, delivery and acceptance.",
                    ["assurance-case.json", "audit-package-verification.json"],
                ),
            ],
            "procedures": [
                (
                    "ECSS-Q-ST-80C-REV2",
                    "ECSS-SPACE-SOFTWARE-LIFECYCLE-MUTATION-AND-INDEPENDENT-ASSURANCE",
                    "Assess a source-bound synthetic flight and ground software project; inject missing or inconsistent requirements, unsafe reuse, unqualified tools, architecture and interface drift, verification gaps, weak coverage, unresolved anomalies, configuration substitution and unsupported acceptance claims; require independent adjudication and corrected-package replay.",
                    "test",
                    True,
                    ["benchmark-scorecard.json", "assurance-case.json"],
                )
            ],
        },
        "regional-financial-technology-resilience": {
            "standards": [
                "APRA-CPS-230",
                "APRA-CPS-234",
                "MAS-TRM",
                "ISO-IEC-27001",
                "ISO-22301",
            ],
            "controls": [
                (
                    "APRA-CPS-230",
                    "FINANCIAL-CRITICAL-OPERATION-TOLERANCE-PROVIDER-AND-BOARD-ACCOUNTABILITY",
                    "Bind regulated entity, jurisdiction, critical operation, tolerance, process, asset, dependency, material service provider, agreement, ownership, board oversight, scenario, continuity action and regulatory record to the applicable APRA or MAS obligation.",
                    ["control-assessment.json", "audit-package-verification.json"],
                ),
                (
                    "APRA-CPS-234",
                    "FINANCIAL-INFORMATION-ASSET-CONTROL-TEST-INCIDENT-AND-NOTIFICATION",
                    "Maintain information-asset criticality and sensitivity, threat and vulnerability, control design and operation, independent testing, third-party coverage, incident materiality, containment, notification decision, recovery, lessons and remediation evidence.",
                    ["incident-management-assessment.json", "operational-trend.json"],
                ),
            ],
            "procedures": [
                (
                    "MAS-TRM",
                    "REGIONAL-FINANCIAL-TECHNOLOGY-RISK-OUTAGE-SUPPLIER-AND-INCIDENT-EXERCISE",
                    "Run jurisdiction-specific, approved exercises over critical services using synthetic customers and transactions; inject cyber compromise, cloud and fourth-party failure, concentration, data corruption, tolerance breach, weak recovery, stale tests, late escalation and reporting errors without contacting a regulator or production provider.",
                    "dynamic",
                    True,
                    ["benchmark-scorecard.json", "operational-trend.json"],
                )
            ],
        },
        "secure-information-sharing-and-competence": {
            "standards": [
                "ISO-IEC-27010",
                "ISO-IEC-TR-27016",
                "ISO-IEC-27021",
                "FIRST-TLP",
                "FIRST-IEP",
            ],
            "controls": [
                (
                    "ISO-IEC-27010",
                    "INFORMATION-SHARING-COMMUNITY-AGREEMENT-CLASSIFICATION-AND-HANDLING",
                    "Bind each sharing community, organization, participant, information object, purpose, classification, TLP or IEP policy, originator control, transport, recipient, onward disclosure, retention, deletion, incident and withdrawal to an approved agreement and interoperable enforcement evidence.",
                    ["security-automation-interoperability.json", "data-exposure.json"],
                ),
                (
                    "ISO-IEC-27021",
                    "ISMS-PROFESSIONAL-ROLE-COMPETENCE-INDEPENDENCE-AND-CALIBRATION",
                    "Define role-specific knowledge, skills, experience, authority and independence; verify qualification evidence, observed performance, blinded golden cases, agreement, bias, drift, continuing development, reassessment, expiry and conflicts without ranking individuals publicly.",
                    [
                        "process-capability-assessment.json",
                        "audit-package-verification.json",
                    ],
                ),
                (
                    "ISO-IEC-TR-27016",
                    "INFORMATION-SECURITY-ECONOMIC-DECISION-ASSUMPTION-AND-OUTCOME",
                    "Trace limited-resource security decisions to alternatives, assumptions, costs, benefits, uncertainty, risk appetite, affected stakeholders, approval, realized outcomes and reassessment; keep Technical Report guidance distinct from mandatory ISMS requirements.",
                    ["risk-assessment.json", "operational-trend.json"],
                ),
            ],
            "procedures": [
                (
                    "ISO-IEC-27010",
                    "CROSS-ORGANIZATION-SHARING-COMPETENCE-AND-ECONOMIC-DECISION-CALIBRATION",
                    "Run blinded multi-organization cases with misclassification, unauthorized forwarding, recipient confusion, stale agreements, conflicting handling policies, privacy leakage, competence expiry, assessor conflict, weak economic assumptions and misleading optimization; measure agreement and verify containment, withdrawal and reassessment.",
                    "manual",
                    False,
                    ["benchmark-scorecard.json", "audit-package-verification.json"],
                )
            ],
        },
    }
)

_ASSURANCE_PROFILES.update(
    {
        "space-mission-communications-security": {
            "standards": [
                "CCSDS-350-1-G-3",
                "CCSDS-350-7-G-2",
                "CCSDS-351-0-M-1",
                "CCSDS-352-0-B-2",
                "CCSDS-355-0-B-2",
                "CCSDS-355-1-B-1",
                "CCSDS-356-0-B-1",
                "CCSDS-357-0-B-1",
                "NASA-STD-8739-8B",
            ],
            "controls": [
                (
                    "CCSDS-350-1-G-3",
                    "SPACE-MISSION-THREAT-SCOPE-AND-TRACEABILITY",
                    "Bind mission phase, functions, assets, data, commands, telemetry, tracking, ground and flight segments, relay and cross-support services, interfaces, trust boundaries, threat actors, communication conditions, safety effects and assumptions to independently reviewed security objectives and traceable mitigations.",
                    ["threat-model-assessment.json", "lifecycle-traceability.json"],
                ),
                (
                    "CCSDS-351-0-M-1",
                    "SPACE-DATA-SYSTEM-SECURITY-ARCHITECTURE",
                    "Describe the end-to-end mission security architecture using explicit security domains, entities, interfaces, services, policy decisions, enforcement points, keys, credentials, security associations, monitoring, degraded modes and recovery boundaries; reconcile the reference architecture with the implemented mission configuration.",
                    ["static-architecture.json", "assurance-case.json"],
                ),
                (
                    "CCSDS-355-0-B-2",
                    "SPACE-LINK-PROTOCOL-SECURITY-AND-ORDERING",
                    "Pin every applicable telemetry, telecommand, AOS and unified space data link profile; verify security header and trailer processing, authentication and confidentiality selection, anti-replay state, virtual-channel and managed-parameter binding, COP and SDLS ordering, malformed-frame handling and explicit unsupported combinations.",
                    ["application-contract-analysis.json", "control-assessment.json"],
                ),
                (
                    "CCSDS-355-1-B-1",
                    "SPACE-SECURITY-ASSOCIATION-KEY-CREDENTIAL-AND-MONITORING-LIFECYCLE",
                    "Govern cryptographic algorithms, authentication credentials, key generation and distribution, security-association creation and rollover, sequence-state continuity, revocation, compromise, reset, monitoring and control, contingency operations, audit evidence and post-event reconciliation across ground and flight segments.",
                    ["trust-policy-attestation.json", "operational-trend.json"],
                ),
            ],
            "procedures": [
                (
                    "CCSDS-355-0-B-2",
                    "SPACE-MISSION-LINK-SECURITY-CONFORMANCE-AND-RESILIENCE-EXERCISE",
                    "In a no-production-connectivity mission digital twin, replay valid mission traffic and inject forged, modified, reordered, duplicated, delayed and stale commands and telemetry; wrong keys and credentials; security-association desynchronization; rollover and reset faults; protocol downgrade and ordering errors; ground-station and relay substitution; loss, delay and intermittent links; monitoring outage and recovery. Require independent expected decisions, preserved safety invariants, deterministic restoration, residue checks and an explicit no-flight-qualification or certification claim.",
                    "dynamic",
                    True,
                    ["benchmark-scorecard.json", "procedure-assessment.json"],
                )
            ],
        }
    }
)

_ASSURANCE_PROFILES.update(
    {
        "national-security-system-authorization": {
            "standards": [
                "CNSSI-1253",
                "DODI-8500-01",
                "DODI-8510-01",
                "NIST-SP-800-53",
                "NIST-SP-800-53A",
            ],
            "controls": [
                (
                    "CNSSI-1253",
                    "NSS-CATEGORIZATION-BASELINE-TAILORING-OVERLAY-AND-ODP-TRACE",
                    "Identify the authoritative NSS determination, information types, confidentiality integrity and availability impacts, resulting category, CNSSI baseline, overlays, organization-defined parameters, tailoring decisions, inheritance, compensating controls and residual risk; bind every decision to the controlled-source edition and approval authority.",
                    ["oscal-system-security-plan.json", "control-assessment.json"],
                ),
                (
                    "DODI-8510-01",
                    "DOD-RMF-ROLE-LIFECYCLE-AUTHORIZATION-POAM-AND-MONITORING",
                    "Trace Prepare through Monitor activities to appointed system owner, program manager, control provider, assessor and authorizing official; bind implementation, assessment, findings, POA&M, acceptance, authorization term, acquisition phase, significant change and continuous-monitoring evidence without representing suite output as an authorization decision.",
                    ["oscal-assessment-plan.json", "audit-package-verification.json"],
                ),
            ],
            "procedures": [
                (
                    "DODI-8510-01",
                    "NSS-DOD-AUTHORIZATION-PACKAGE-REPERFORMANCE-AND-ADVERSE-CASE-CHALLENGE",
                    "Reperform synthetic authorization packages and inject NSS misclassification, high-water-mark substitution, missing overlays, stale control implementations, invalid inheritance, unapproved tailoring, incomplete POA&M, assessor conflicts, expired authorization, significant-change suppression and monitoring gaps; require two-person adjudication and preserve government-only authorization authority.",
                    "manual",
                    False,
                    ["benchmark-scorecard.json", "audit-package-verification.json"],
                )
            ],
        },
        "operational-zero-trust-implementation": {
            "standards": [
                "NSA-ZIG-PRIMER",
                "NSA-ZIG-DISCOVERY",
                "NSA-ZIG-PHASE-1",
                "NSA-ZIG-PHASE-2",
                "CISA-ZT-MICROSEGMENTATION",
                "NIST-SP-800-207",
            ],
            "controls": [
                (
                    "NSA-ZIG-DISCOVERY",
                    "ZT-ASSET-DATA-APPLICATION-SERVICE-IDENTITY-AND-FLOW-BASELINE",
                    "Maintain a time-bound inventory and relationship graph for users, workloads, devices, applications, services, data, identities, privileges, dependencies, communications and policy enforcement points; expose unknown, unmanaged, stale and conflicting observations instead of silently treating them as trusted.",
                    ["boundary-graph.json", "control-assessment.json"],
                ),
                (
                    "NSA-ZIG-PHASE-2",
                    "ZT-CROSS-PILLAR-POLICY-DECISION-ENFORCEMENT-TELEMETRY-AND-RECOVERY",
                    "Bind each applicable ZIG activity and capability across user, device, network, application and workload, data, visibility and analytics, and automation and orchestration pillars to policy decisions, enforcement, continuous signals, telemetry, exception expiry, fail-closed behavior, session revocation and recovery evidence.",
                    ["application-contract-analysis.json", "operational-trend.json"],
                ),
            ],
            "procedures": [
                (
                    "CISA-ZT-MICROSEGMENTATION",
                    "ZT-MICROSEGMENTATION-LATERAL-MOVEMENT-POLICY-AND-FAILURE-EXERCISE",
                    "Exercise identity-aware segmentation in an isolated topology using permitted and denied east-west paths; inject stale identity and posture, policy conflicts, propagation delay, enforcement outage, fail-open, discovery omissions, session persistence, emergency access, telemetry loss, rollback and recovery cases without disrupting production services.",
                    "test",
                    True,
                    ["benchmark-scorecard.json", "boundary-graph.json"],
                )
            ],
        },
        "healthcare-operational-resilience-depth": {
            "standards": ["HHS-HICP", "HHS-HPH-CPG", "NIST-SP-800-66", "HITRUST-CSF"],
            "controls": [
                (
                    "HHS-HICP",
                    "HEALTHCARE-THREAT-PRACTICE-CLINICAL-DEPENDENCY-AND-PATIENT-SAFETY-TRACE",
                    "Map applicable HICP practices and HPH essential and enhanced goals to ransomware, email compromise, data loss, insider, connected-device and supply-chain threats; trace clinical services, ePHI, biomedical and facility dependencies, downtime procedures, recovery priorities and patient-safety consequences.",
                    ["control-assessment.json", "incident-management-assessment.json"],
                ),
                (
                    "HHS-HPH-CPG",
                    "HEALTHCARE-IDENTITY-SEGMENTATION-BACKUP-VENDOR-AND-RECOVERY-OUTCOMES",
                    "Verify unique credentials, MFA, privileged access, IT OT and clinical segmentation, asset and vulnerability management, immutable tested backups, vendor obligations, incident coordination, degraded clinical operations, restoration, reconciliation and measured patient-safety recovery outcomes.",
                    ["operational-trend.json", "audit-package-verification.json"],
                ),
            ],
            "procedures": [
                (
                    "HHS-HPH-CPG",
                    "HEALTHCARE-RANSOMWARE-CLINICAL-CONTINUITY-AND-RECOVERY-EXERCISE",
                    "Run a synthetic hospital exercise spanning identity compromise, ransomware, EHR and imaging outage, biomedical isolation, diversion, downtime documentation, emergency access, third-party coordination, ePHI decisions, staged restoration and reconciliation; use synthetic data and record service and patient-safety outcomes without asserting regulatory compliance.",
                    "test",
                    True,
                    ["benchmark-scorecard.json", "incident-management-assessment.json"],
                )
            ],
        },
        "aircraft-system-development-safety-assurance": {
            "standards": [
                "SAE-ARP4754B",
                "SAE-ARP4761A",
                "RTCA-DO-178C",
                "RTCA-DO-330",
                "RTCA-DO-326A",
            ],
            "controls": [
                (
                    "SAE-ARP4754B",
                    "AIRCRAFT-FUNCTION-REQUIREMENT-ARCHITECTURE-DAL-AND-DERIVED-TRACE",
                    "Bind aircraft functions, operating conditions, requirements, architecture, interfaces, allocated development assurance levels, derived requirements, validation, verification, configuration, change impact and certification liaison evidence across system, item, software and airborne-security boundaries.",
                    ["lifecycle-traceability.json", "structured-assurance-case.json"],
                ),
                (
                    "SAE-ARP4761A",
                    "AIRCRAFT-FHA-PSSA-SSA-SECURITY-INTERACTION-AND-INDEPENDENCE",
                    "Trace functional hazards, failure conditions, severity, probability objectives, common causes, independence assumptions, preliminary and final safety assessments, security-originated failure effects, mitigations and residual limitations; preserve that ARP4761A safety assessment does not itself replace the DO-326A security process.",
                    ["threat-model-assessment.json", "structured-assurance-case.json"],
                ),
            ],
            "procedures": [
                (
                    "SAE-ARP4754B",
                    "AIRCRAFT-SYSTEM-SAFETY-SECURITY-TRACE-MUTATION-AND-ASSESSOR-AGREEMENT",
                    "Reperform licensed synthetic aircraft cases and inject untraced derived requirements, incorrect DAL allocation, interface omissions, shared-resource common causes, invalid independence, stale verification, tool qualification gaps, safety-security contradictions and change-impact omissions; require qualified independent adjudication and no certification claim.",
                    "manual",
                    False,
                    ["benchmark-scorecard.json", "structured-assurance-case.json"],
                )
            ],
        },
        "accredited-laboratory-operating-assurance": {
            "standards": [
                "ISO-IEC-17025",
                "ISO-IEC-17020",
                "ISO-IEC-17065",
                "ILAC-P9",
                "ILAC-P10",
                "ILAC-P14",
                "ILAC-P15",
            ],
            "controls": [
                (
                    "ILAC-P9",
                    "LAB-PROFICIENCY-PARTICIPATION-SCOPE-PERFORMANCE-AND-CORRECTIVE-ACTION",
                    "Define the accredited or claimed scope, proficiency-testing and interlaboratory-comparison plan, participation frequency, provider suitability, assigned values, acceptance criteria, performance, investigation, corrective action and follow-up while distinguishing internal readiness from accreditation-body decisions.",
                    ["proficiency-testing.json", "audit-package-verification.json"],
                ),
                (
                    "ILAC-P10",
                    "LAB-METROLOGICAL-TRACEABILITY-UNCERTAINTY-METHOD-AND-INSPECTION-IMPARTIALITY",
                    "Bind equipment, calibration chain, reference, method validation, measurement uncertainty, environmental conditions, personnel competence, decision rule, inspection independence, impartiality risk and report authorization to each result with versioned evidence and stated limitations.",
                    ["measurement-traceability.json", "measurement-uncertainty.json"],
                ),
            ],
            "procedures": [
                (
                    "ILAC-P15",
                    "LAB-BLINDED-PROFICIENCY-TRACEABILITY-UNCERTAINTY-AND-IMPARTIALITY-CHALLENGE",
                    "Run blinded interlaboratory cases with assigned values and uncertainty; inject broken traceability, unsuitable proficiency providers, environmental drift, transcription error, invalid decision rules, competency gaps, conflicts, selective reporting and ineffective corrective actions; require independent review without claiming accreditation.",
                    "manual",
                    False,
                    ["benchmark-scorecard.json", "proficiency-testing.json"],
                )
            ],
        },
        "maritime-operational-cyber-risk-depth": {
            "standards": ["IMO-MSC-FAL-1-CIRC-3-REV3", "IACS-UR-E26", "IACS-UR-E27"],
            "controls": [
                (
                    "IMO-MSC-FAL-1-CIRC-3-REV3",
                    "MARITIME-GOVERN-IDENTIFY-PROTECT-DETECT-RESPOND-RECOVER-TRACE",
                    "Trace accountable leadership, ship and shore inventories, safety-critical computer-based systems, ship-port interfaces, operational profile, threats, risk, access, segmentation, media, logging, training, continuity, supply chain, response, recovery, audit and feedback into the safety management system.",
                    ["control-assessment.json", "incident-management-assessment.json"],
                ),
                (
                    "IMO-MSC-FAL-1-CIRC-3-REV3",
                    "MARITIME-SHIP-SHORE-SUPPLIER-OPERATIONAL-MODE-AND-RECOVERY-EVIDENCE",
                    "Bind ship, fleet, shore, port and supplier responsibilities to navigation, propulsion, cargo, communications, access, update, remote support, degraded operation, manual fallback, restoration and reconciliation evidence while preserving flag, class and company authority boundaries.",
                    ["boundary-graph.json", "operational-trend.json"],
                ),
            ],
            "procedures": [
                (
                    "IMO-MSC-FAL-1-CIRC-3-REV3",
                    "MARITIME-OPERATIONAL-MODE-CYBER-INCIDENT-AND-RECOVERY-EXERCISE",
                    "Exercise an inert ship and shore digital twin across navigation, cargo and machinery modes; inject removable media, remote-support compromise, GPS and sensor inconsistency, network pivot, logging loss, supplier outage, communications failure and recovery reconciliation without production vessel actuation.",
                    "test",
                    True,
                    ["benchmark-scorecard.json", "incident-management-assessment.json"],
                )
            ],
        },
        "empirical-assurance-benchmark-calibration": {
            "standards": [
                "MITRE-CWE",
                "FIRST-EPSS",
                "CISA-KEV",
                "ISO-IEC-33020",
                "ISO-IEC-27036-2",
                "NIST-SP-800-61",
                "ISO-IEC-29134",
            ],
            "controls": [
                (
                    "MITRE-CWE",
                    "EMPIRICAL-LABEL-TIME-SPLIT-TOOL-VERSION-AND-DISAGREEMENT-GOVERNANCE",
                    "Bind labels, abstraction policy, weakness release, exploit observation time, tool and solver versions, project and chronology splits, assessor identities, uncertainty, disagreement and adjudication; prevent future-data leakage, duplicate leakage, metric cherry-picking and unsupported causal claims.",
                    ["benchmark-scorecard.json", "effectiveness.json"],
                ),
                (
                    "ISO-IEC-33020",
                    "EMPIRICAL-OUTCOME-REASSESSMENT-INCIDENT-PRIVACY-AND-SUPPLIER-VALIDATION",
                    "Join process, supplier, incident and privacy decisions to longitudinal defects, escapes, exploitation, recovery, service, individual-impact and reassessment outcomes using compatible scope, blinded review, confidence intervals, negative controls and explicit external-validity limits.",
                    ["operational-trend.json", "process-capability-assessment.json"],
                ),
            ],
            "procedures": [
                (
                    "FIRST-EPSS",
                    "MULTI-DOMAIN-HOLDOUT-CALIBRATION-MUTATION-AND-INDEPENDENT-REPLAY",
                    "Execute governed weakness mapping, temporal prioritization, solver disagreement, assessor agreement, supplier incident, incident response and privacy-impact holdouts; mutate labels, time boundaries, scopes, dependencies, assumptions and outcomes; require independent replay, adjudication and confidence reporting.",
                    "test",
                    False,
                    ["benchmark-scorecard.json", "effectiveness.json"],
                )
            ],
        },
    }
)

_ASSURANCE_PROFILES["devsecops-maturity"]["controls"].append(
    (
        "OWASP-DSOMM",
        "DEVSECOPS-LONGITUDINAL-EVENT-OUTCOME-AND-ANTI-GAMING",
        "Bind maturity ratings to immutable delivery events, quality and security outcomes, comparable team/product/time scopes, DORA metric definitions, uncertainty, exceptions, target actions and reassessment; reject aspirational policy, scope drift and metric gaming.",
        ["maturity-model-assessment.json", "operational-trend.json"],
    )
)
_ASSURANCE_PROFILES["devsecops-maturity"]["procedures"].append(
    (
        "OWASP-DSOVS",
        "DEVSECOPS-LONGITUDINAL-BLINDED-OUTCOME-REASSESSMENT",
        "Recompute maturity and delivery outcomes over multiple comparable periods, challenge stale evidence, level inflation, event manipulation and cohort leakage, and require independent reviewer agreement and adjudication.",
        "manual",
        False,
        ["benchmark-scorecard.json", "operational-trend.json"],
    )
)
_ASSURANCE_PROFILES["test-maturity"]["procedures"].append(
    (
        "TMMI",
        "TEST-MATURITY-DEFECT-ESCAPE-MUTATION-AND-OUTCOME-CALIBRATION",
        "Join test-process ratings to escaped defects, mutation sensitivity, changed-line coverage, flakiness, recovery and release outcomes over comparable periods while preserving causal uncertainty and independent reassessment.",
        "manual",
        False,
        ["benchmark-scorecard.json", "maturity-model-assessment.json"],
    )
)
_ASSURANCE_PROFILES["detection-product-evaluation"]["controls"].append(
    (
        "MITRE-ATTACK-EVALUATIONS",
        "DETECTION-GROUND-TRUTH-FALSE-POSITIVE-EVASION-AND-DRIFT",
        "Bind product, policy, sensor, content, environment and time; preserve visibility, detection and protection separately; measure benign-workload false positives, latency, evasion variants, telemetry loss, version drift and uncertainty against independent step-level ground truth.",
        ["external-conformity-assessment.json", "operational-trend.json"],
    )
)
_ASSURANCE_PROFILES["detection-product-evaluation"]["procedures"].append(
    (
        "MITRE-ATTACK-EVALUATIONS",
        "DETECTION-LONGITUDINAL-CALIBRATION-AND-EVASION-REPLAY",
        "Replay authorized ATT&CK steps and representative benign administration across product/content versions with fixed telemetry and clocks; inject encoding, fragmentation, timing, LOLBin, sensor-outage and policy variants and independently adjudicate misses and false positives.",
        "dynamic",
        True,
        ["benchmark-scorecard.json", "external-conformity-assessment.json"],
    )
)

_ASSURANCE_PROFILES.update(
    {
        "medical-device-cybersecurity-depth": {
            "standards": [
                "ANSI-AAMI-SW96",
                "IEC-80001-1",
                "IEC-TR-60601-4-5",
                "IMDRF-CYBER-N60",
                "IMDRF-CYBER-N70",
                "IMDRF-CYBER-N73",
                "IEC-81001-5-1",
                "ISO-14971",
            ],
            "controls": [
                (
                    "ANSI-AAMI-SW96",
                    "MEDICAL-DEVICE-SECURITY-RISK-AND-PATIENT-HARM-TRACE",
                    "Bind device, intended use, interfaces, clinical environment, hazards, threat scenarios, exploitability, patient and operational harms, risk controls, benefit-risk decisions, residual risk, production and post-production evidence to the exact released configuration.",
                    ["threat-model-assessment.json", "control-assessment.json"],
                ),
                (
                    "IEC-80001-1",
                    "CONNECTED-HEALTH-RESPONSIBILITY-CAPABILITY-AND-LIFECYCLE",
                    "Assign manufacturer, healthcare delivery organization and service-provider responsibilities; map security capability levels, zones, conduits, SBOM, legacy support, vulnerability disclosure, patching, compensating controls and end-of-support decisions without substituting suite output for regulatory approval.",
                    ["lifecycle-traceability.json", "software-supply-chain.json"],
                ),
            ],
            "procedures": [
                (
                    "IEC-TR-60601-4-5",
                    "MEDICAL-DEVICE-ADVERSARIAL-CAPABILITY-AND-SAFETY-REPLAY",
                    "Exercise synthetic devices and clinical networks across declared capability levels; inject unauthorized access, unsafe command, malformed protocol, resource exhaustion, update failure, stale SBOM, legacy isolation failure and recovery cases while measuring patient-safety and clinical-availability effects.",
                    "dynamic",
                    True,
                    ["benchmark-scorecard.json", "audit-package-verification.json"],
                )
            ],
        },
        "autonomous-physical-ai-safety": {
            "standards": [
                "ISO-21448",
                "ISO-PAS-8800",
                "ISO-34502",
                "ANSI-UL-4600",
                "ISO-26262",
                "ISO-SAE-21434",
            ],
            "controls": [
                (
                    "ISO-PAS-8800",
                    "PHYSICAL-AI-ODD-HAZARD-MODEL-DATA-AND-SAFETY-CASE",
                    "Bind AI element, training and validation data, operational design domain, perception and decision limitations, hazards, safety goals, monitors, fallback, human interaction, cybersecurity dependencies and post-deployment evidence to a structured safety case.",
                    ["ai-risk-assessment.json", "assurance-case.json"],
                ),
                (
                    "ANSI-UL-4600",
                    "AUTONOMY-EVIDENCE-INDEPENDENCE-UPDATE-AND-RESIDUAL-RISK",
                    "Require independent challenge of claims, argument completeness, supplier evidence, tool qualification, simulation validity, closed-course and bounded field evidence, safety performance indicators, incident response and regression after every safety-relevant update.",
                    [
                        "external-conformity-assessment.json",
                        "lifecycle-traceability.json",
                    ],
                ),
            ],
            "procedures": [
                (
                    "ISO-34502",
                    "AUTONOMY-SCENARIO-BOUNDARY-DEGRADATION-AND-FALLBACK-BENCHMARK",
                    "Run digest-pinned deterministic scenarios spanning nominal, boundary, rare and adversarial conditions; mutate sensors, timing, maps, communications, weather, actors and ODD assumptions; verify safe fallback, reproducibility, coverage, metamorphic consistency and no unsafe real-world actuation.",
                    "dynamic",
                    True,
                    ["benchmark-scorecard.json", "assurance-case.json"],
                )
            ],
        },
        "critical-c-cpp-coding-assurance": {
            "standards": [
                "MISRA-C-2023",
                "MISRA-CPP",
                "SEI-CERT-C",
                "SEI-CERT-CPP",
                "ISO-IEC-TS-17961",
            ],
            "controls": [
                (
                    "MISRA-CPP",
                    "CRITICAL-CODE-RULESET-COMPILER-DEVIATION-AND-TRACEABILITY",
                    "Bind licensed rule identifiers and edition digest, language and compiler modes, generated code, third-party and FFI boundaries, required diagnostics, decidability, deviations, approvals and safety-security impact to each production configuration.",
                    [
                        "security-requirements-coverage.json",
                        "audit-package-verification.json",
                    ],
                ),
                (
                    "MISRA-C-2023",
                    "CRITICAL-CODE-UNDEFINED-BEHAVIOR-MEMORY-CONCURRENCY-AND-PORTABILITY",
                    "Cross-check static rule results with compiler warnings, sanitizers, fuzzing, ABI and architecture variants; preserve true and false controls and prohibit tool compliance claims from being represented as product certification.",
                    ["benchmark-scorecard.json", "effectiveness.json"],
                ),
            ],
            "procedures": [
                (
                    "MISRA-CPP",
                    "CRITICAL-CODE-MULTI-COMPILER-CONFORMANCE-AND-DEVIATION-CHALLENGE",
                    "Compile and analyze licensed positive, negative and ambiguous cases across pinned compilers, optimizations and targets; replay undefined behavior, lifetime, bounds, conversion, concurrency, exception and preprocessor mutations and independently adjudicate disagreements and deviations.",
                    "test",
                    True,
                    ["benchmark-scorecard.json", "audit-package-verification.json"],
                )
            ],
        },
        "cross-vendor-confidential-computing-attestation": {
            "standards": [
                "IETF-RFC-9334",
                "IETF-RFC-9711",
                "TCG-ATTESTATION-FRAMEWORK",
                "AMD-SEV-SNP-ABI",
                "INTEL-TDX-DCAP",
                "ARM-CCA-ATTESTATION",
            ],
            "controls": [
                (
                    "TCG-ATTESTATION-FRAMEWORK",
                    "CONFIDENTIAL-COMPUTE-EVIDENCE-ENDORSEMENT-POLICY-AND-DECISION",
                    "Bind attester, verifier, relying party, endorsement, reference value, appraisal policy, hardware and firmware TCB, workload measurement, nonce, freshness, result and authorization decision while separating platform identity from workload trust and business authorization.",
                    [
                        "native-attestation-verification.json",
                        "trust-policy-attestation.json",
                    ],
                ),
                (
                    "IETF-RFC-9334",
                    "CONFIDENTIAL-COMPUTE-CROSS-VENDOR-REVOCATION-PRIVACY-AND-FAILURE",
                    "Normalize only explicitly equivalent claims across SEV-SNP, TDX and CCA; verify certificate and endorsement chains, TCB status, revocation, privacy, verifier independence, outage behavior and fail-closed secret release without claiming hardware certification.",
                    [
                        "security-automation-interoperability.json",
                        "audit-package-verification.json",
                    ],
                ),
            ],
            "procedures": [
                (
                    "IETF-RFC-9711",
                    "CONFIDENTIAL-COMPUTE-ATTESTATION-NEGATIVE-CORPUS",
                    "Replay genuine and synthetic evidence containing stale TCB, revoked endorsements, nonce replay, algorithm downgrade, claim confusion, debug mode, measurement substitution, verifier-policy drift and cross-vendor semantic mismatch; require independent verification and deterministic secret denial.",
                    "dynamic",
                    True,
                    [
                        "benchmark-scorecard.json",
                        "native-attestation-verification.json",
                    ],
                )
            ],
        },
        "voting-system-assurance": {
            "standards": [
                "EAC-VVSG",
                "EAC-VVSG-TEST-ASSERTIONS",
                "NIST-SP-800-53",
                "W3C-WCAG",
            ],
            "controls": [
                (
                    "EAC-VVSG",
                    "VOTING-SYSTEM-SOFTWARE-INDEPENDENCE-ACCESSIBILITY-AND-INTEGRITY",
                    "Bind voting-system version, jurisdiction profile, ballot definition, trusted build, chain of custody, software independence, auditability, accessibility, usability, authentication, physical controls, cryptography, logging and recovery to accredited-laboratory evidence.",
                    [
                        "security-requirements-coverage.json",
                        "external-conformity-assessment.json",
                    ],
                ),
                (
                    "EAC-VVSG",
                    "VOTING-SYSTEM-CERTIFICATION-LAB-AND-JURISDICTION-BOUNDARY",
                    "Verify VSTL authority, test campaign, interpretations, deviations, certificate identity and lifecycle while clearly separating suite readiness, federal certification and state or local acceptance decisions.",
                    ["audit-package-verification.json", "lifecycle-traceability.json"],
                ),
            ],
            "procedures": [
                (
                    "EAC-VVSG-TEST-ASSERTIONS",
                    "VVSG-OFFICIAL-ASSERTION-SECURITY-ACCESSIBILITY-AND-RECOVERY-REPLAY",
                    "Execute the exact Test Assertions 1.4 applicable matrix in an isolated synthetic election; challenge ballot integrity, privilege, removable media, wireless prohibition, logs, audit records, accessibility, power loss, recovery and end-to-end protocol behavior without handling real ballots or asserting EAC certification.",
                    "dynamic",
                    True,
                    ["benchmark-scorecard.json", "external-conformity-assessment.json"],
                )
            ],
        },
        "critical-sector-safety-security": {
            "standards": [
                "IEC-62645",
                "IEC-TR-63486",
                "CLC-TS-50701",
                "NASA-STD-8739-8B",
                "IEC-61508",
                "NIST-SP-800-160-1",
            ],
            "controls": [
                (
                    "IEC-62645",
                    "CRITICAL-SECTOR-FUNCTION-HAZARD-ZONE-CONDUIT-AND-CYBER-RISK",
                    "Select nuclear, rail or space applicability; bind essential functions, hazards, programmable systems, zones, conduits, operational modes, threat assumptions, safety-security interactions, independence, suppliers and residual risk to licensed sector criteria.",
                    ["threat-model-assessment.json", "enterprise-risk-assessment.json"],
                ),
                (
                    "NASA-STD-8739-8B",
                    "CRITICAL-SECTOR-INDEPENDENT-ASSURANCE-IVV-CHANGE-AND-OPERATIONS",
                    "Require competent independent assurance and IV&V, lifecycle traceability, anomaly and waiver governance, tool and model qualification, operational constraints, incident response, configuration control, safe recovery and reassessment after change.",
                    ["assurance-case.json", "lifecycle-traceability.json"],
                ),
            ],
            "procedures": [
                (
                    "IEC-TR-63486",
                    "CRITICAL-SECTOR-DIGITAL-TWIN-FAILURE-RECOVERY-AND-ASSESSOR-CALIBRATION",
                    "Use a sector-specific digital twin or inert laboratory to replay cyber-physical failures, loss of view or control, unsafe sequencing, time and communication faults, supply-chain compromise, degraded operation and recovery; require blinded assessor agreement and prohibit production actuation.",
                    "dynamic",
                    True,
                    ["benchmark-scorecard.json", "assurance-case.json"],
                )
            ],
        },
        "stateful-smart-contract-assurance": {
            "standards": ["OWASP-SMART-CONTRACT-TOP-10", "MITRE-CWE", "FIRST-CVSS"],
            "controls": [
                (
                    "OWASP-SMART-CONTRACT-TOP-10",
                    "SMART-CONTRACT-STATE-ECONOMIC-UPGRADE-AND-DEPENDENCY-MODEL",
                    "Model contract state, roles, governance, assets, invariants, upgrade and proxy paths, external calls, bridges, oracles, flash liquidity, ordering, liveness and off-chain dependencies across deployment and migration boundaries.",
                    [
                        "threat-model-assessment.json",
                        "application-contract-analysis.json",
                    ],
                ),
                (
                    "OWASP-SMART-CONTRACT-TOP-10",
                    "SMART-CONTRACT-SOURCE-BYTECODE-CHAIN-AND-INCIDENT-BINDING",
                    "Bind source, compiler, settings, bytecode, deployment, chain, libraries, privileged identities and incident oracles; separate static warnings from reproducible exploitability and quarantine alpha SCSVS material from normative claims.",
                    ["artifact-analysis.json", "audit-package-verification.json"],
                ),
            ],
            "procedures": [
                (
                    "OWASP-SMART-CONTRACT-TOP-10",
                    "SMART-CONTRACT-STATEFUL-EXPLOIT-INVARIANT-AND-UPGRADE-BENCHMARK",
                    "Replay labeled contracts and clean controls on a disposable chain with multi-transaction, multi-actor, oracle, governance, reentrancy, price, bridge, proxy, signature and denial mutations; require deterministic resets, economic invariant oracles and independent exploit replay.",
                    "dynamic",
                    True,
                    ["benchmark-scorecard.json", "application-contract-analysis.json"],
                )
            ],
        },
    }
)

_ASSURANCE_PROFILES["architecture-evaluation-process"]["standards"].append("ISO-22340")
_ASSURANCE_PROFILES["architecture-evaluation-process"]["controls"].append(
    (
        "ISO-22340",
        "INTEGRATED-PROTECTIVE-SECURITY-ARCHITECTURE",
        "Integrate physical, personnel, information, cyber, supplier, operational, and recovery concerns across assets, boundaries, dependencies, scenarios, controls, ownership, and residual risk.",
        ["architecture-evaluation.json", "risk-paths.json"],
    )
)

_ASSURANCE_PROFILES["secure-coding"]["standards"].append("OWASP-CODE-REVIEW-GUIDE")
_ASSURANCE_PROFILES["secure-coding"]["procedures"].append(
    (
        "OWASP-CODE-REVIEW-GUIDE",
        "RISK-BASED-MANUAL-CODE-REVIEW",
        "Review trust boundaries, entry points, authorization, data flow, validation, encoding, state, concurrency, error handling, logging, cryptography, resource ownership, dependencies, and security-control bypasses using independent evidence and adversarial cases.",
        "manual",
        False,
        ["finding-validation.json", "procedure-assessment.json"],
    )
)
_ASSURANCE_PROFILES["threat-model-quality"]["standards"].append("OWASP-CORNUCOPIA")
_ASSURANCE_PROFILES["threat-model-quality"]["procedures"].append(
    (
        "OWASP-CORNUCOPIA",
        "SCENARIO-DECK-COVERAGE-CHALLENGE",
        "Sample applicable web, mobile, cloud, DevOps, frontend, LLM, and agentic scenarios; trace each disposition to architecture, controls, tests, residual risk, and independent omission review.",
        "manual",
        False,
        ["threat-model-assessment.json", "benchmark-scorecard.json"],
    )
)
_ASSURANCE_PROFILES["secure-by-design-product"]["standards"].append(
    "CIS-SAFECODE-SECURE-BY-DESIGN"
)
_ASSURANCE_PROFILES["secure-by-design-product"]["controls"].append(
    (
        "CIS-SAFECODE-SECURE-BY-DESIGN",
        "SSDF-ALIGNED-PRACTICE-ASSESSMENT",
        "Assess governance, secure design, implementation, verification, vulnerability response, supply chain, operational feedback, and AI-assisted development practices with scoped evidence, maturity limits, accountable exceptions, and improvement ownership.",
        ["process-capability-assessment.json", "control-proof.json"],
    )
)

_ASSURANCE_PROFILES.update(
    {
        "a2a-protocol-security": {
            "standards": [
                "A2A-PROTOCOL",
                "MCP-SPECIFICATION",
                "IETF-RFC-9700",
                "OIDF-FAPI",
            ],
            "controls": [
                (
                    "A2A-PROTOCOL",
                    "A2A-IDENTITY-DISCOVERY-AND-INTERFACE-INTEGRITY",
                    "Pin A2A 1.0 protocol definitions and supported bindings; validate public and extended Agent Cards, JWS signatures, provider identity, endpoint origin, protocol version, tenant routing, capabilities, skills, cache invalidation, and downgrade behavior without trusting self-declared metadata or exposing internal endpoints and credentials.",
                    [
                        "security-automation-interoperability.json",
                        "application-contract-analysis.json",
                    ],
                ),
                (
                    "A2A-PROTOCOL",
                    "A2A-AUTHENTICATION-AUTHORIZATION-AND-TENANT-BOUNDARY",
                    "Authenticate every operation at the selected binding, authorize task, message, artifact, skill, subscription and extended-card access against the authenticated principal and tenant, bind delegated credentials to intended agent, audience, scope, purpose and lifetime, and prohibit ambient, in-payload, cross-agent or cross-tenant credential reuse.",
                    ["control-proof.json", "trust-policy-attestation.json"],
                ),
                (
                    "A2A-PROTOCOL",
                    "A2A-TASK-ARTIFACT-STREAM-AND-WEBHOOK-SAFETY",
                    "Treat messages, parts, files, data, artifacts, status, extensions, callbacks and peer output as untrusted; enforce schema and media validation, size and complexity limits, SSRF-safe callback registration, notification authentication, replay and ordering protection, cancellation and terminal-state integrity, output provenance, bounded authority, audit, cleanup and safe failure.",
                    ["threat-model-assessment.json", "llm-adversarial-plan.json"],
                ),
            ],
            "procedures": [
                (
                    "A2A-PROTOCOL",
                    "A2A-MULTIBINDING-ADVERSARIAL-CONFORMANCE",
                    "Run the pinned A2A compatibility suite and organization negative cases across HTTP+JSON, JSON-RPC and gRPC where implemented; challenge signed and unsigned cards, version negotiation, tenant confusion, object-level authorization, task enumeration, artifact substitution, delegated credential leakage, malicious extensions, oversized parts, stream races, webhook SSRF, forged notifications, replay, cancellation and cleanup in synthetic disposable agents.",
                    "dynamic",
                    True,
                    [
                        "benchmark-scorecard.json",
                        "security-automation-interoperability.json",
                    ],
                )
            ],
        },
        "sesip-iot-platform-evaluation": {
            "standards": [
                "GLOBALPLATFORM-SESIP",
                "EN-17927",
                "ISO-IEC-15408",
                "ISO-IEC-18045",
                "ETSI-EN-303-645",
            ],
            "controls": [
                (
                    "GLOBALPLATFORM-SESIP",
                    "SESIP-TARGET-PROFILE-AND-SECURITY-CLAIM",
                    "Bind the target of evaluation, platform parts, product and configuration identity, assets, attacker model, operational environment, claimed SESIP profile, Security Functional Requirements, Security Process Packages and assurance level to licensed criteria and explicit exclusions without extending component claims to the complete product.",
                    ["control-assessment.json", "architecture-evaluation.json"],
                ),
                (
                    "EN-17927",
                    "SESIP-COMPOSITION-REUSE-AND-DEPENDENCY-VALIDITY",
                    "Trace every reused evaluation to exact component, version, configuration, certificate, dependency, integration assumption, assurance compatibility, vulnerability status, change impact and expiry; reject broken composition, unsupported inheritance and stale or revoked evidence.",
                    [
                        "lifecycle-traceability.json",
                        "audit-package-verification.json",
                    ],
                ),
                (
                    "GLOBALPLATFORM-SESIP",
                    "SESIP-EVALUATOR-SCHEME-AND-CERTIFICATE-AUTHORITY",
                    "Retain scheme, certification body, laboratory, evaluator competence, accreditation or authorization, method, verdict, certificate status, maintenance and public record evidence; distinguish readiness, evaluation and certification and prohibit the suite from issuing or implying a SESIP certificate.",
                    [
                        "audit-package-verification.json",
                        "process-capability-assessment.json",
                    ],
                ),
            ],
            "procedures": [
                (
                    "EN-17927",
                    "SESIP-EVALUATION-COMPOSITION-AND-CLAIM-CHALLENGE",
                    "Reperform approved functional, process and assurance cases for representative platform configurations; inject component substitution, configuration drift, invalid profile mapping, unmet dependencies, assurance-level inflation, expired certificates, unreported vulnerabilities, incomplete penetration evidence and product-level overclaiming, requiring deterministic rejection and qualified independent adjudication.",
                    "test",
                    True,
                    ["benchmark-scorecard.json", "audit-package-verification.json"],
                )
            ],
        },
        "threat-intelligence-handling": {
            "standards": [
                "FIRST-TLP",
                "FIRST-IEP",
                "VERIS",
                "OASIS-STIX",
                "OASIS-TAXII",
            ],
            "controls": [
                (
                    "FIRST-TLP",
                    "TLP-LABEL-SEMANTICS-AND-DISCLOSURE-BOUNDARY",
                    "Accept only TLP 2.0 labels and exact semantics, preserve labels through storage, transformation, display, export and downstream exchange, enforce recipient and community boundaries including TLP:AMBER+STRICT, and reject missing, deprecated, ambiguous, translated or downgraded markings by policy.",
                    [
                        "security-automation-interoperability.json",
                        "control-proof.json",
                    ],
                ),
                (
                    "FIRST-IEP",
                    "IEP-MACHINE-READABLE-USE-AND-REDISTRIBUTION-POLICY",
                    "Validate IEP 2.0 identifiers, version, dates, encryption, permitted actions, affected-party notification, attribution, resale, external references and TLP relationship; preserve immutable applied policies, resolve references from approved snapshots and apply the restrictive unknown policy when a policy is inaccessible, overlapping or invalid.",
                    [
                        "security-automation-interoperability.json",
                        "audit-package-verification.json",
                    ],
                ),
                (
                    "VERIS",
                    "VERIS-INCIDENT-CLASSIFICATION-PROVENANCE-AND-QUALITY",
                    "Pin the VERIS schema and vocabularies; retain incident identity, source authority, actor, action, asset, attribute, timeline, discovery, response, impact, victim and notes provenance; distinguish unknown from absent, validate controlled values and cardinality, minimize sensitive data and prevent analytics transformations from silently changing meaning.",
                    ["operational-trend.json", "data-exposure.json"],
                ),
            ],
            "procedures": [
                (
                    "FIRST-IEP",
                    "TLP-IEP-ROUND-TRIP-AND-POLICY-ENFORCEMENT",
                    "Round-trip approved TLP and IEP fixtures through STIX, TAXII and supported JSON flows; inject obsolete labels, case and whitespace variants, label removal, TLP downgrade, inaccessible and mutable policy references, invalid dates, overlapping policies, unauthorized redistribution, storage and transport violations, requiring fail-closed handling and attributable audit evidence.",
                    "test",
                    False,
                    [
                        "benchmark-scorecard.json",
                        "security-automation-interoperability.json",
                    ],
                ),
                (
                    "VERIS",
                    "VERIS-SCHEMA-QUALITY-AND-ANALYTIC-EQUIVALENCE",
                    "Validate positive, incomplete and malformed incidents against the pinned schema; mutate enumerations, cardinality, unknown values, dates, identities and sensitive fields, then verify lossless round trips, deterministic normalization, aggregate invariants, de-identification and human-reviewed classification accuracy without treating schema validity as incident truth.",
                    "test",
                    False,
                    ["benchmark-scorecard.json", "operational-trend.json"],
                ),
            ],
        },
        "web-platform-defense": {
            "standards": [
                "W3C-CSP-LEVEL-2",
                "W3C-SUBRESOURCE-INTEGRITY",
                "OWASP-ASVS",
                "OWASP-WSTG",
            ],
            "controls": [
                (
                    "W3C-CSP-LEVEL-2",
                    "CSP-POLICY-DELIVERY-PARSER-AND-ENFORCEMENT",
                    "Deliver CSP through valid response headers, parse and enforce multiple policies without weakening intersection semantics, prefer nonce or hash based script controls, constrain object, base, frame, form, connect and plugin surfaces, collect reports safely, avoid unsafe bypasses and verify effective policy in the deployed browser rather than header presence alone.",
                    ["test-evidence.json", "finding-validation.json"],
                ),
                (
                    "W3C-SUBRESOURCE-INTEGRITY",
                    "SRI-RESOURCE-IDENTITY-CORS-AND-FAILURE",
                    "Bind third-party scripts and styles to approved SHA-256, SHA-384 or SHA-512 content digests, validate strongest supported metadata and CORS interaction, update integrity values through reviewed dependency changes, fail closed on mismatch and prevent fallback or transformation paths from silently executing unverified content.",
                    ["test-evidence.json", "release-readiness.json"],
                ),
            ],
            "procedures": [
                (
                    "W3C-CSP-LEVEL-2",
                    "CSP-SRI-BROWSER-CONFORMANCE-AND-BYPASS-CHALLENGE",
                    "Run pinned Web Platform Tests and application-owned browser cases against production-equivalent headers and resources; inject inline and external scripts, redirects, base changes, framed content, policy duplication, report abuse, CDN substitution, hash downgrade, missing CORS, transformed content and fallback execution, requiring observed blocking, reporting and safe recovery across supported browsers.",
                    "dynamic",
                    True,
                    ["benchmark-scorecard.json", "test-evidence.json"],
                )
            ],
        },
        "dora-level2-financial-resilience": {
            "standards": [
                "EU-DORA",
                "EU-DORA-RTS-ICT-RISK",
                "EU-DORA-RTS-INCIDENT-CLASSIFICATION",
                "EU-DORA-ITS-REGISTER-OF-INFORMATION",
                "EU-DORA-RTS-INCIDENT-REPORTING",
                "EU-DORA-ITS-INCIDENT-REPORTING",
                "EU-DORA-RTS-TLPT",
                "TIBER-EU",
            ],
            "controls": [
                (
                    "EU-DORA-RTS-ICT-RISK",
                    "DORA-ICT-RISK-FRAMEWORK-AND-CONTROL-TRACE",
                    "Determine legal and entity applicability with qualified counsel, then trace governance, assets, dependencies, protection, detection, response, recovery, backup, change, capacity, cryptography, logging, physical security, testing, learning and simplified-framework decisions to the exact in-force technical provisions and accountable evidence.",
                    ["control-assessment.json", "architecture-evaluation.json"],
                ),
                (
                    "EU-DORA-RTS-INCIDENT-REPORTING",
                    "DORA-INCIDENT-CLASSIFICATION-TIMELINE-AND-REPORT-INTEGRITY",
                    "Classify incidents and recurring incidents from authoritative impact evidence; preserve detection, awareness and classification times, submit complete initial, intermediate and final reports through secure channels within applicable deadlines, validate LEI and template semantics, protect personal data, reconcile updates and retain supervisory acknowledgements and corrections.",
                    ["operational-trend.json", "audit-package-verification.json"],
                ),
                (
                    "EU-DORA-ITS-REGISTER-OF-INFORMATION",
                    "DORA-THIRD-PARTY-REGISTER-AND-TLPT-GOVERNANCE",
                    "Maintain entity, sub-consolidated and consolidated ICT service registers with exact providers, contracts, functions, locations, dependencies, concentration and exit data; select TLPT scope and testers under the applicable criteria, control intelligence and production safety, retain remediation and closure evidence and separate legal compliance from benchmark execution.",
                    [
                        "lifecycle-traceability.json",
                        "audit-package-verification.json",
                    ],
                ),
            ],
            "procedures": [
                (
                    "EU-DORA-RTS-TLPT",
                    "DORA-LEVEL2-DATA-VALIDATION-AND-TLPT-EXERCISE",
                    "Validate risk-framework, incident, reporting and third-party-register fixtures against pinned legal acts, then run an explicitly authorized TLPT simulation with scoped critical functions, qualified control team and testers, threat intelligence, production safeguards, evidence custody, status communication, findings, remediation, closure, attestation and mutual-recognition fields; inject timing, template, scope, tester-independence and cleanup failures.",
                    "dynamic",
                    True,
                    ["benchmark-scorecard.json", "audit-package-verification.json"],
                )
            ],
        },
        "ffiec-banking-technology": {
            "standards": [
                "FFIEC-IT-HANDBOOK-DAM",
                "FFIEC-IT-HANDBOOK-AIO",
                "FFIEC-IT-HANDBOOK-INFORMATION-SECURITY",
                "NIST-CSF",
            ],
            "controls": [
                (
                    "FFIEC-IT-HANDBOOK-DAM",
                    "FFIEC-DEVELOPMENT-ACQUISITION-MAINTENANCE-LIFECYCLE",
                    "For in-scope US financial institutions and service providers, retain governance, requirements, architecture, secure development, acquisition due diligence, contracts, testing, data conversion, change, release, maintenance, vulnerability, end-of-life and independent assurance evidence aligned to examiner procedures without treating handbook guidance as a universal legal requirement.",
                    [
                        "process-capability-assessment.json",
                        "lifecycle-traceability.json",
                    ],
                ),
                (
                    "FFIEC-IT-HANDBOOK-AIO",
                    "FFIEC-ARCHITECTURE-INFRASTRUCTURE-OPERATIONS",
                    "Trace business services through current architecture, infrastructure, networks, physical and virtual assets, cloud and third parties, configuration, capacity, monitoring, resilience, backup, operations and emerging technology controls with management oversight, risk ownership and examiner-reperformable evidence.",
                    ["architecture-evaluation.json", "control-assessment.json"],
                ),
                (
                    "FFIEC-IT-HANDBOOK-INFORMATION-SECURITY",
                    "FFIEC-INFORMATION-SECURITY-PROGRAM-EFFECTIVENESS",
                    "Assess culture, governance, risk identification and measurement, mitigation, monitoring, security operations, threat intelligence, incident response, assurance and testing using current outcomes, independent review, corrective action and board reporting; exclude the retired FFIEC Cybersecurity Assessment Tool from current claims.",
                    ["control-assessment.json", "operational-trend.json"],
                ),
            ],
            "procedures": [
                (
                    "FFIEC-IT-HANDBOOK-DAM",
                    "FFIEC-BLINDED-EXAMINATION-PROCEDURE-ASSESSMENT",
                    "Have qualified independent assessors apply pinned handbook examination objectives to blinded acquisition, architecture, operations, security, incident, third-party, cloud, AI, maintenance and resilience cases; retain evidence samples, agreement, conflicts, adjudication, findings and corrective-action closure without using the retired CAT as an oracle.",
                    "manual",
                    False,
                    [
                        "benchmark-scorecard.json",
                        "process-capability-assessment.json",
                    ],
                )
            ],
        },
        "bsi-c5-cloud-assurance": {
            "standards": ["BSI-C5", "ISO-IEC-27001", "ISO-IEC-27017", "CSA-CCM"],
            "controls": [
                (
                    "BSI-C5",
                    "C5-SERVICE-DESCRIPTION-CONTROL-AND-CUSTOMER-RESPONSIBILITY",
                    "Pin C5:2020 licensed criteria and bind the cloud service, locations, architecture, subservice organizations, system boundaries, control design and operation, complementary customer controls, deviations, incidents and change to a complete service description and current evidence.",
                    ["control-assessment.json", "architecture-evaluation.json"],
                ),
                (
                    "BSI-C5",
                    "C5-ATTESTATION-AUDITOR-SCOPE-AND-REPORT-VALIDITY",
                    "Validate practitioner independence and competence, assurance standard, Type 1 or Type 2 period, sampling, exceptions, subservice treatment, management assertion, report signature and intended-use restrictions; distinguish a C5 attestation report from BSI certification and assess customer controls separately.",
                    [
                        "audit-package-verification.json",
                        "process-capability-assessment.json",
                    ],
                ),
            ],
            "procedures": [
                (
                    "BSI-C5",
                    "C5-REPORT-REPERFORMANCE-AND-ASSESSOR-CALIBRATION",
                    "Have independent assessors evaluate blinded C5 service descriptions and reports containing omitted regions, boundary drift, stale periods, qualified opinions, subservice gaps, ineffective controls, unsupported customer-control assumptions, incident omissions and certification overclaims; require agreement, adjudication and customer residual-risk decisions.",
                    "manual",
                    False,
                    ["benchmark-scorecard.json", "audit-package-verification.json"],
                )
            ],
        },
        "us-cyber-trust-mark": {
            "standards": [
                "FCC-CYBER-TRUST-MARK",
                "NISTIR-8259",
                "NISTIR-8259A",
                "NISTIR-8425",
            ],
            "controls": [
                (
                    "FCC-CYBER-TRUST-MARK",
                    "FCC-IOT-PRODUCT-BASELINE-AND-LABORATORY-EVIDENCE",
                    "Bind the complete consumer IoT product, components, interfaces, software and support versions to the approved program baseline, recognized laboratory, test plan, configuration, results, vulnerabilities, remediation and renewal triggers; retain laboratory recognition and prohibit self-generated evidence from implying authorization to use the mark.",
                    ["control-assessment.json", "test-evidence.json"],
                ),
                (
                    "FCC-CYBER-TRUST-MARK",
                    "FCC-LABEL-APPLICATION-REGISTRY-AND-CONSUMER-INFORMATION",
                    "Validate applicant and product identity, Label Administrator authorization, application and test-report binding, QR destination, registry accuracy, support period, update policy, vulnerability contact, privacy disclosure, renewal, withdrawal and change handling with tamper-evident records and consumer-readable information.",
                    [
                        "audit-package-verification.json",
                        "lifecycle-traceability.json",
                    ],
                ),
                (
                    "FCC-CYBER-TRUST-MARK",
                    "FCC-MARK-MISUSE-AND-CLAIM-BOUNDARY",
                    "Detect unauthorized, expired, transferred, misleading or product-mismatched mark use; require removal or correction after withdrawal and state that program authorization is product-specific, voluntary, not a legal safe harbor and not proof that the product is vulnerability-free.",
                    ["finding-validation.json", "audit-package-verification.json"],
                ),
            ],
            "procedures": [
                (
                    "FCC-CYBER-TRUST-MARK",
                    "FCC-IOT-LABEL-CONFORMANCE-AND-MISUSE-CHALLENGE",
                    "Reperform approved baseline cases and verify product, laboratory, application, authorization, QR and registry bindings; inject substituted firmware, unsupported components, stale support dates, unresolved vulnerabilities, forged reports, unrecognized laboratories, copied labels, redirected QR codes, missing registry fields, expired authorization and overbroad security claims, requiring rejection and traceable remediation.",
                    "test",
                    False,
                    ["benchmark-scorecard.json", "audit-package-verification.json"],
                )
            ],
        },
    }
)

_ASSURANCE_PROFILES["identity-protocol-security"]["standards"].extend(
    ["OIDF-FAPI-ATTACKER-MODEL", "OIDF-FAPI-MESSAGE-SIGNING"]
)
_ASSURANCE_PROFILES["identity-protocol-security"]["controls"].append(
    (
        "OIDF-FAPI",
        "FAPI2-FINAL-PROFILE-ATTACKER-AND-SIGNING-BOUNDARY",
        "Implement the final FAPI 2.0 Security Profile against its final attacker model; bind sender-constrained tokens, PAR, PKCE, issuer, audience, authorization server, client and resource server identities; and apply Message Signing only where selected with explicit non-repudiation and real-world identity claim boundaries.",
        ["application-contract-analysis.json", "threat-model-assessment.json"],
    )
)
_ASSURANCE_PROFILES["identity-protocol-security"]["procedures"].append(
    (
        "OIDF-FAPI",
        "FAPI2-FINAL-OFFICIAL-CONFORMANCE",
        "Run the official final FAPI 2.0 conformance profiles for each implemented authorization-server, client and resource-server role and selected MTLS, DPoP, OpenID Connect, JAR or JARM option; challenge replay, mix-up, browser swap, duplicate key identifiers, token injection, signing confusion and stale certification claims.",
        "dynamic",
        True,
        ["benchmark-scorecard.json", "security-automation-interoperability.json"],
    )
)

_ASSURANCE_PROFILES.update(
    {
        "digital-credential-security": {
            "standards": [
                "W3C-VC-DATA-MODEL",
                "W3C-VC-DATA-INTEGRITY",
                "W3C-BITSTRING-STATUS-LIST",
                "OIDF-OPENID4VP",
                "OIDF-OPENID4VCI",
                "OIDF-OPENID4VC-HAIP",
                "NIST-SP-800-63-4",
            ],
            "controls": [
                (
                    "W3C-VC-DATA-MODEL",
                    "VC-ISSUER-HOLDER-VERIFIER-TRUST-AND-DATA-BOUNDARY",
                    "Bind issuer, holder, verifier, subject, credential type, schema, status, validity, purpose, audience, trust framework and securing mechanism; minimize disclosed claims; reject ambiguous contexts, unauthorized extensions, untrusted issuers and unsupported credential formats without inferring real-world truth from cryptographic validity.",
                    ["security-automation-interoperability.json", "data-exposure.json"],
                ),
                (
                    "OIDF-OPENID4VC-HAIP",
                    "OPENID4VC-HIGH-ASSURANCE-PROTOCOL-BOUNDARY",
                    "Select final OpenID4VCI, OpenID4VP and HAIP roles and profiles; bind authorization, nonce, proof, key, credential, transaction, wallet, issuer and verifier identities; enforce replay, redirect, request-object, response-mode, downgrade, status, revocation, algorithm and cross-device protections.",
                    [
                        "application-contract-analysis.json",
                        "trust-policy-attestation.json",
                    ],
                ),
            ],
            "procedures": [
                (
                    "OIDF-OPENID4VC-HAIP",
                    "DIGITAL-CREDENTIAL-OFFICIAL-CONFORMANCE-AND-ABUSE",
                    "Execute official issuer, wallet and verifier conformance profiles plus malformed, forged, replayed, expired, revoked, selectively disclosed, cross-wallet, cross-device, mix-up, phishing, downgrade, status-correlation, trust-list and privacy-negative cases in synthetic credential ecosystems.",
                    "dynamic",
                    True,
                    [
                        "benchmark-scorecard.json",
                        "security-automation-interoperability.json",
                    ],
                )
            ],
        },
        "federal-saas-hardening": {
            "standards": ["CISA-SCUBA-M365", "CISA-SCUBA-GWS", "NIST-SP-800-53"],
            "controls": [
                (
                    "CISA-SCUBA-M365",
                    "SCUBA-TENANT-INVENTORY-BASELINE-AND-EXCEPTION-GOVERNANCE",
                    "Pin the authoritative SCuBA baseline and assessment-tool revisions; inventory every applicable tenant, domain, product and policy surface; preserve raw read-only observations, normalized decisions, justified exclusions, owners and expiry; and distinguish unavailable permissions from passing controls.",
                    ["control-assessment.json", "audit-package-verification.json"],
                ),
                (
                    "CISA-SCUBA-GWS",
                    "SCUBA-IDENTITY-MESSAGING-COLLABORATION-AND-VISIBILITY",
                    "Assess identity, privileged access, mail, collaboration, storage, sharing, audit, threat-protection and visibility settings against the pinned product baseline with independent inventory reconciliation, drift detection and service-specific applicability.",
                    ["domain-assurance.json", "operational-trend.json"],
                ),
            ],
            "procedures": [
                (
                    "CISA-SCUBA-M365",
                    "SCUBA-READ-ONLY-POSTURE-REPERFORMANCE",
                    "Run pinned ScubaGear or ScubaGoggles with least-privilege read-only identities; verify tenant and baseline identity, API and pagination completeness, policy evaluation, exclusions, unavailable checks, drift, remediation, cleanup and rescan without mutating production configuration.",
                    "test",
                    True,
                    ["benchmark-scorecard.json", "audit-package-verification.json"],
                )
            ],
        },
        "kubernetes-hardening-conformance": {
            "standards": [
                "CIS-KUBERNETES-BENCHMARK",
                "CIS-BENCHMARKS",
                "NIST-SP-800-190",
            ],
            "controls": [
                (
                    "CIS-KUBERNETES-BENCHMARK",
                    "K8S-ROLE-VERSION-SCOPE-AND-RECOMMENDATION-COVERAGE",
                    "Bind the Kubernetes distribution, version, control-plane, etcd, scheduler, controller, node, policy and managed-service responsibility boundaries to CIS Kubernetes 2.0.1; retain every applicable recommendation, manual check, exception, evidence source and remediation owner.",
                    ["control-assessment.json", "domain-assurance.json"],
                ),
                (
                    "CIS-KUBERNETES-BENCHMARK",
                    "K8S-POSTURE-DRIFT-AND-RUNTIME-CORROBORATION",
                    "Reconcile benchmark results with API inventory, workload and admission policy, node configuration, audit evidence, Kubescape, Falco and provider findings while keeping Sonobuoy functional conformance separate from security-hardening claims.",
                    ["control-proof.json", "operational-trend.json"],
                ),
            ],
            "procedures": [
                (
                    "CIS-KUBERNETES-BENCHMARK",
                    "K8S-HARDENING-NEGATIVE-AND-RESCAN-CONFORMANCE",
                    "Execute licensed CIS checks through an approved evaluator against representative disposable clusters; inject role-specific misconfigurations, skipped manual controls, managed-service responsibility errors, stale exceptions and parser drift; then verify remediation, cleanup and rescan.",
                    "test",
                    True,
                    ["benchmark-scorecard.json", "control-assessment.json"],
                )
            ],
        },
        "privacy-threat-modeling": {
            "standards": ["LINDDUN-PRO", "ISO-IEC-29134", "ISO-IEC-29100"],
            "controls": [
                (
                    "LINDDUN-PRO",
                    "LINDDUN-DFD-INTERACTION-AND-THREAT-TREE-COVERAGE",
                    "Bind a source and architecture-derived DFD of processes, stores, external entities, flows and boundaries to every applicable send-transfer-receive interaction and policy-pinned LINDDUN threat characteristic; record omissions, assumptions, participants, applicability and knowledge gaps.",
                    ["threat-model-assessment.json", "data-exposure.json"],
                ),
                (
                    "LINDDUN-PRO",
                    "LINDDUN-PRIVACY-RISK-MITIGATION-AND-REASSESSMENT",
                    "Trace linking, identifying, non-repudiation, detecting, disclosure, unawareness and non-compliance threats to affected people, impact, likelihood, PET and process mitigations, tests, residual risk, acceptance, ownership, change triggers and reassessment.",
                    ["threat-model-assessment.json", "control-proof.json"],
                ),
            ],
            "procedures": [
                (
                    "LINDDUN-PRO",
                    "LINDDUN-OMISSION-MUTATION-AND-ASSESSOR-AGREEMENT",
                    "Run blinded reviewers over golden DFD interactions and privacy threats; inject missing flows, boundary errors, reidentification, linkability, metadata, inference, secondary-use, consent and retention cases; measure coverage and agreement and adjudicate material disagreement.",
                    "manual",
                    False,
                    ["benchmark-scorecard.json", "threat-model-assessment.json"],
                )
            ],
        },
        "ast-modality-effectiveness": {
            "standards": ["OWASP-ASVS", "OWASP-WSTG", "NIST-SSDF"],
            "controls": [
                (
                    "OWASP-ASVS",
                    "AST-MODALITY-SCOPE-IDENTITY-AND-COVERAGE",
                    "Record SAST, DAST, IAST and RASP tool, rule, application build, deployment, route, authentication, crawler, instrumentation and policy identities separately; require comparable target scope and exact coverage before comparing or combining effectiveness claims.",
                    ["effectiveness.json", "application-contract-analysis.json"],
                ),
                (
                    "OWASP-WSTG",
                    "IAST-RASP-INSTRUMENTATION-PREVENTION-AND-UTILITY",
                    "Prove instrumentation health and exercised routes; distinguish observation from prevention; retain confirmed attacks, blocked operations, false positives, bypasses, latency, resource overhead, application errors and utility under benign and malicious workloads.",
                    ["test-evidence.json", "finding-validation.json"],
                ),
            ],
            "procedures": [
                (
                    "OWASP-ASVS",
                    "MATCHED-SAST-DAST-IAST-RASP-EFFECTIVENESS",
                    "Execute independently configured SAST, DAST and IAST lanes against the same pinned OWASP Benchmark cases and a separate RASP prevention corpus; preserve per-modality confusion matrices, route and instrumentation coverage, attack replay, utility and latency without treating unioned findings as one tool result.",
                    "dynamic",
                    True,
                    ["benchmark-scorecard.json", "effectiveness.json"],
                )
            ],
        },
        "telecom-equipment-assurance": {
            "standards": ["GSMA-NESAS", "3GPP-SCAS", "ISO-IEC-27011"],
            "controls": [
                (
                    "GSMA-NESAS",
                    "NESAS-VENDOR-PROCESS-SCOPE-AND-AUDIT",
                    "Pin FS.13 through FS.16 scheme material; bind vendor, sites, lifecycle processes, product families, releases, suppliers, vulnerabilities, assessors, audit organization, validity and findings; preserve scheme-specific authority and explicitly avoid describing NESAS as vendor or product certification.",
                    [
                        "process-capability-assessment.json",
                        "audit-package-verification.json",
                    ],
                ),
                (
                    "3GPP-SCAS",
                    "SCAS-PRODUCT-RELEASE-TEST-AND-LABORATORY-BOUNDARY",
                    "Select every product-function and release-applicable SCAS; bind requirements, test cases, equipment configuration, evidence, deviations, laboratory ISO 17025 scope, evaluator competence, tools, results, changes and retest triggers.",
                    [
                        "procedure-assessment.json",
                        "external-conformity-assessment.json",
                    ],
                ),
            ],
            "procedures": [
                (
                    "3GPP-SCAS",
                    "NESAS-SCAS-AUTHORIZED-PRODUCT-EVALUATION",
                    "Reperform selected SCAS cases in an authorized NESAS laboratory using representative non-production equipment; challenge product/release substitution, incomplete SCAS selection, process/product evidence mismatch, laboratory-scope expiry, forged results and misleading certification claims.",
                    "test",
                    True,
                    ["benchmark-scorecard.json", "audit-package-verification.json"],
                )
            ],
        },
        "tisax-automotive-information-assurance": {
            "standards": ["VDA-ISA", "ENX-TISAX", "ISO-IEC-27001", "ISO-SAE-21434"],
            "controls": [
                (
                    "VDA-ISA",
                    "TISAX-SCOPE-OBJECTIVE-SITE-AND-ISA-CONTROL-IDENTITY",
                    "Bind the assessment scope, participant, locations, processes, information assets, prototypes, personal data, assessment objectives, level, applicable ISA 6.0.3 controls, maturity ratings, evidence, findings, corrective actions and target dates.",
                    ["control-assessment.json", "audit-package-verification.json"],
                ),
                (
                    "ENX-TISAX",
                    "TISAX-PROVIDER-RESULT-EXCHANGE-VALIDITY-AND-CLAIM",
                    "Verify assessment-provider authorization, independence, result and label scope, assessment and expiry dates, exchange permissions, recipient restrictions, corrective-action closure and transition rules; do not issue or imply a TISAX label.",
                    [
                        "external-conformity-assessment.json",
                        "audit-package-verification.json",
                    ],
                ),
            ],
            "procedures": [
                (
                    "VDA-ISA",
                    "TISAX-BLINDED-MATURITY-AND-SCOPE-ASSESSMENT",
                    "Use licensed ISA criteria and blinded cases to calibrate scope, objectives, applicability, maturity and findings; inject omitted sites, prototype and personal-data objectives, unsupported ratings, stale evidence, provider conflicts, result misuse and premature ISA2027 application.",
                    "manual",
                    False,
                    ["benchmark-scorecard.json", "audit-package-verification.json"],
                )
            ],
        },
        "content-provenance-authenticity": {
            "standards": ["C2PA-CONTENT-CREDENTIALS", "IN-TOTO-ATTESTATION", "DSSE"],
            "controls": [
                (
                    "C2PA-CONTENT-CREDENTIALS",
                    "C2PA-MANIFEST-ASSET-INGREDIENT-AND-TRUST-BINDING",
                    "Bind the asset, active manifest, claim, assertions, ingredients, actions, hashes, signature, certificate chain, timestamp, trust-list decision, identity, generator, validation status and displayed provenance without equating provenance with factual truth.",
                    ["trust-policy-attestation.json", "software-supply-chain.json"],
                ),
                (
                    "C2PA-CONTENT-CREDENTIALS",
                    "C2PA-PRIVACY-HARMS-UX-AND-AI-DISCLOSURE",
                    "Apply data minimization, redaction, identity and location protection, harms modeling, accessibility and consistent user-facing status; distinguish cryptographically verified, invalid, unknown, stripped and soft-bound content and disclose algorithmic-generation claims only when evidenced.",
                    ["data-exposure.json", "finding-validation.json"],
                ),
            ],
            "procedures": [
                (
                    "C2PA-CONTENT-CREDENTIALS",
                    "C2PA-TAMPER-STRIP-SUBSTITUTE-AND-VIEWER-CONFORMANCE",
                    "Run pinned C2PA conformance assets and cross-verifier tests; mutate assets, manifests, ingredients, assertions, certificates, timestamps, status and soft bindings; test stripping, substitution, replay, unknown critical fields, oversized graphs and misleading UI while preserving safe sample media.",
                    "test",
                    False,
                    ["benchmark-scorecard.json", "trust-policy-attestation.json"],
                )
            ],
        },
        "payment-acceptance-security": {
            "standards": ["PCI-MPOC", "PCI-P2PE", "PCI-DSS", "PCI-SECURE-SOFTWARE"],
            "controls": [
                (
                    "PCI-MPOC",
                    "MPOC-SOLUTION-SDK-APP-DEVICE-AND-MONITORING-BOUNDARY",
                    "Bind the MPoC solution, SDKs, applications, COTS devices, attestation, key and credential boundaries, backend, monitoring, update, vulnerability, laboratory and listing identities; distinguish vendor, integrator, merchant and assessor responsibilities.",
                    ["control-assessment.json", "audit-package-verification.json"],
                ),
                (
                    "PCI-P2PE",
                    "P2PE-ENCRYPTION-DECRYPTION-KEY-CHAIN-OF-CUSTODY",
                    "Trace account data from approved point-of-interaction encryption through key management, device inventory, chain of custody, applications, transport, decryption environment, access, monitoring, incident response and listing scope with no cleartext leakage inference from paperwork alone.",
                    ["data-exposure.json", "control-proof.json"],
                ),
            ],
            "procedures": [
                (
                    "PCI-MPOC",
                    "PAYMENT-ACCEPTANCE-LAB-AND-LISTING-CONFORMANCE",
                    "Execute only approved synthetic payment fixtures in an authorized laboratory; challenge SDK/app/device substitution, rooting or tampering, attestation replay, overlay and accessibility abuse, key misuse, cleartext exposure, monitoring loss, stale reports, laboratory authority, listing scope and unsupported PCI claims.",
                    "test",
                    True,
                    ["benchmark-scorecard.json", "audit-package-verification.json"],
                )
            ],
        },
    }
)

_ASSURANCE_PROFILES.update(
    {
        "fedramp-20x-continuous-assurance": {
            "standards": ["FEDRAMP-20X", "FEDRAMP", "NIST-SP-800-53", "NIST-SP-800-18"],
            "controls": [
                (
                    "FEDRAMP-20X",
                    "FEDRAMP20X-CLASS-GOAL-MEASURE-AND-KSI-BINDING",
                    "Bind the cloud service offering, certification class, authorization boundary, security goals, measures, Key Security Indicators, implementation, validation code, failure criteria, evidence source, owner, freshness, limitations and agency-relevant risk context without translating a class into an overall security rating.",
                    ["control-assessment.json", "audit-package-verification.json"],
                ),
                (
                    "FEDRAMP-20X",
                    "FEDRAMP20X-PERSISTENT-PACKAGE-INDEPENDENCE-AND-STATUS",
                    "Maintain accurate human- and machine-readable certification data, representative samples, independent verification, continuous monitoring, vulnerability response, material-change handling and authoritative Marketplace status; distinguish provider assertions, assessor conclusions, FedRAMP validation and agency authorization decisions.",
                    ["operational-trend.json", "external-conformity-assessment.json"],
                ),
            ],
            "procedures": [
                (
                    "FEDRAMP-20X",
                    "FEDRAMP20X-CONTINUOUS-VALIDATION-AND-STALE-PACKAGE-CHALLENGE",
                    "Reperform class-applicable Key Security Indicators and independent-validation samples; inject stale evidence, unavailable telemetry, measure gaming, boundary drift, unreviewed validation-code changes, hidden failures, invalid Marketplace claims and Rev. 5-to-20x conflation, requiring visible failure and accountable correction.",
                    "test",
                    True,
                    ["benchmark-scorecard.json", "audit-package-verification.json"],
                )
            ],
        },
        "fido2-authenticator-assurance": {
            "standards": [
                "FIDO-CTAP",
                "FIDO-MDS",
                "FIDO-AUTHENTICATOR-CERTIFICATION",
                "W3C-WEBAUTHN",
            ],
            "controls": [
                (
                    "FIDO-CTAP",
                    "FIDO2-CLIENT-AUTHENTICATOR-TRANSPORT-AND-CREDENTIAL-BOUNDARY",
                    "Bind platform, client, authenticator, relying party, origin, credential, user verification, PIN/UV protocol, transport, resident-key, enterprise-attestation and extension behavior to CTAP 2.2 and WebAuthn profiles with downgrade, proximity, privacy and recovery boundaries.",
                    [
                        "application-contract-analysis.json",
                        "trust-policy-attestation.json",
                    ],
                ),
                (
                    "FIDO-MDS",
                    "FIDO-METADATA-AAGUID-STATUS-AND-CERTIFICATION-VALIDATION",
                    "Verify metadata BLOB signatures, roots, sequence and freshness; bind AAGUID, attestation roots, status reports, certification level and revocation to the exact authenticator model; reject unknown or stale metadata without treating certification hints as proof of current device integrity.",
                    [
                        "trust-policy-attestation.json",
                        "audit-package-verification.json",
                    ],
                ),
            ],
            "procedures": [
                (
                    "FIDO-CTAP",
                    "FIDO2-FUNCTIONAL-SECURITY-METADATA-AND-RECOVERY-CONFORMANCE",
                    "Run pinned FIDO functional cases across supported transports and authenticator roles; challenge malformed CBOR, origin or RP-ID confusion, credential substitution, UV bypass, PIN retries, downgrade, metadata rollback, revoked models, cloned passkeys, sync and account-recovery abuse, transport injection and misleading certification claims.",
                    "dynamic",
                    True,
                    ["benchmark-scorecard.json", "trust-policy-attestation.json"],
                )
            ],
        },
        "eudi-wallet-assurance": {
            "standards": [
                "EU-EIDAS2",
                "EU-EUDI-IMPLEMENTING-ACTS",
                "EU-EUDI-ARF",
                "EU-EUDI-FCAF",
                "OIDF-OPENID4VC-HAIP",
            ],
            "controls": [
                (
                    "EU-EUDI-IMPLEMENTING-ACTS",
                    "EUDI-WALLET-UNIT-PID-EAA-RP-AND-TRUST-BOUNDARY",
                    "Bind wallet solution and unit, provider, PID and EAA issuer, relying party and service, registration, trusted lists, LoTEs, attestation, key, device, notification and certification evidence to the applicable consolidated acts, Member State context and ARF requirements.",
                    ["control-assessment.json", "external-conformity-assessment.json"],
                ),
                (
                    "EU-EUDI-ARF",
                    "EUDI-SELECTIVE-DISCLOSURE-PRIVACY-UX-AND-LIFECYCLE",
                    "Enforce user control, purpose and data minimization, unlinkability, transaction logging, deletion and complaint paths, issuance, presentation, wallet-to-wallet interaction, backup, recovery, suspension, revocation and qualified-signature boundaries without inferring legal status from protocol success.",
                    ["data-exposure.json", "lifecycle-traceability.json"],
                ),
            ],
            "procedures": [
                (
                    "EU-EUDI-FCAF",
                    "EUDI-FUNCTIONAL-SECURITY-PRIVACY-AND-CROSS-WALLET-CONFORMANCE",
                    "Execute the version-pinned Functional Conformance Assessment Framework and reference fixtures across wallet, issuer and relying-party roles; inject registration, trust-anchor, PID/EAA binding, consent, over-request, replay, downgrade, wallet-to-wallet, recovery, notification and privacy failures.",
                    "dynamic",
                    True,
                    [
                        "benchmark-scorecard.json",
                        "security-automation-interoperability.json",
                    ],
                )
            ],
        },
        "hitrust-assessment-assurance": {
            "standards": [
                "HITRUST-CSF",
                "HIPAA-SECURITY-RULE",
                "NIST-SP-800-66",
                "ISO-IEC-27001",
            ],
            "controls": [
                (
                    "HITRUST-CSF",
                    "HITRUST-VERSION-SCOPE-FACTOR-AND-REQUIREMENT-IDENTITY",
                    "Use licensed CSF 11.8.0 content and bind assessment object, organization, systems, facilities, third parties, regulatory factors, requirement statements, illustrative procedures, inheritance, not-applicable decisions, evidence and maturity dimensions to the selected e1, i1 or r2 assurance type.",
                    ["control-assessment.json", "audit-package-verification.json"],
                ),
                (
                    "HITRUST-CSF",
                    "HITRUST-ASSESSOR-QA-CAP-REPORT-AND-VALIDITY",
                    "Verify assessor and external-assessor authority, independence, sampling, quality assurance, scoring, corrective-action plans, residual gaps, report dates, scope, reliance and expiry; prevent readiness or suite results from being represented as HITRUST certification.",
                    [
                        "external-conformity-assessment.json",
                        "audit-package-verification.json",
                    ],
                ),
            ],
            "procedures": [
                (
                    "HITRUST-CSF",
                    "HITRUST-E1-I1-R2-BLINDED-ASSESSMENT-AND-CLAIM-CHALLENGE",
                    "Calibrate qualified reviewers using licensed, blinded e1, i1 and r2 cases with scope changes, unsupported inheritance, weak samples, stale evidence, maturity inflation, incomplete corrective actions, assessor conflicts, expired reports and certification overclaims; require agreement and adjudication.",
                    "manual",
                    False,
                    ["benchmark-scorecard.json", "audit-package-verification.json"],
                )
            ],
        },
        "pci-software-security-framework": {
            "standards": [
                "PCI-SECURE-SOFTWARE",
                "PCI-SECURE-SLC",
                "PCI-DSS",
                "PCI-MPOC",
                "PCI-P2PE",
            ],
            "controls": [
                (
                    "PCI-SECURE-SOFTWARE",
                    "PCI-SSF-SOFTWARE-SDK-SENSITIVE-ASSET-AND-MODULE-SCOPE",
                    "Bind the evaluated software or SDK, functions, versions, platforms, payment flows, sensitive assets, dependencies, APIs, modules, deployment guidance, vulnerabilities, assessor, report and listing identity to Secure Software 2.0 and all applicable modules.",
                    [
                        "security-requirements-coverage.json",
                        "audit-package-verification.json",
                    ],
                ),
                (
                    "PCI-SECURE-SLC",
                    "PCI-SSF-LIFECYCLE-CHANGE-ATTESTATION-AND-LISTING",
                    "Trace governance, threat modeling, secure design, implementation, testing, release, vulnerability management, change-impact tiers, delta validation, annual attestation and listing updates through Secure SLC 1.1 and the applicable program guides without issuing PCI validation.",
                    [
                        "process-capability-assessment.json",
                        "lifecycle-traceability.json",
                    ],
                ),
            ],
            "procedures": [
                (
                    "PCI-SECURE-SOFTWARE",
                    "PCI-SSF-PRODUCT-LIFECYCLE-DELTA-AND-LISTING-CONFORMANCE",
                    "Reperform licensed product and lifecycle procedures using synthetic payment data; challenge sensitive-asset omissions, SDK and module scope, vulnerable components, API attacks, wildcards, change-tier manipulation, stale annual attestations, assessor authority, report binding and false listing claims.",
                    "test",
                    True,
                    ["benchmark-scorecard.json", "audit-package-verification.json"],
                )
            ],
        },
        "nis2-implementation-assurance": {
            "standards": [
                "EU-NIS2",
                "EU-NIS2-IMPLEMENTING-REGULATION",
                "ENISA-NIS2-TECHNICAL-GUIDANCE",
                "ISO-IEC-27001",
            ],
            "controls": [
                (
                    "EU-NIS2-IMPLEMENTING-REGULATION",
                    "NIS2-ENTITY-SERVICE-SECTOR-SCOPE-AND-MEASURE-TRACE",
                    "Determine entity, service, Member State, sector and Implementing Regulation applicability; trace each technical and methodological requirement for governance, risk, incident, continuity, supply chain, development, effectiveness, hygiene, cryptography, people, access, assets and physical security to owned evidence and exceptions.",
                    ["control-assessment.json", "audit-package-verification.json"],
                ),
                (
                    "ENISA-NIS2-TECHNICAL-GUIDANCE",
                    "NIS2-EVIDENCE-MAPPING-EFFECTIVENESS-AND-REPORTING",
                    "Pin the guidance and mapping-table versions, preserve legal-versus-guidance status, validate evidence completeness and control effectiveness, and bind material incident classification, chronology, notification decisions, competent authority, supply-chain impacts and management accountability.",
                    ["incident-management-assessment.json", "operational-trend.json"],
                ),
            ],
            "procedures": [
                (
                    "EU-NIS2-IMPLEMENTING-REGULATION",
                    "NIS2-APPLICABILITY-CONTROL-INCIDENT-AND-SUPPLY-CHAIN-EXERCISE",
                    "Reperform applicability and representative technical measures; inject service misclassification, missing assets, supplier compromise, ineffective controls, continuity failures, incident threshold and timing errors, stale mapping guidance and unapproved exceptions without sending real regulatory notifications.",
                    "test",
                    True,
                    ["benchmark-scorecard.json", "audit-package-verification.json"],
                )
            ],
        },
        "supplier-due-diligence": {
            "standards": [
                "NIST-SP-1326",
                "NIST-SP-800-161",
                "NIST-SP-800-18",
                "ISO-IEC-27036-2",
            ],
            "controls": [
                (
                    "NIST-SP-1326",
                    "SUPPLIER-SCOPE-OWNERSHIP-PROVENANCE-AND-DUE-DILIGENCE",
                    "Identify supplier, product, service, ownership, control, provenance, development, support, vulnerability, incident, dependency, concentration and foreign-influence factors; retain authoritative sources, collection time, confidence, contradictions and gaps without treating absence of adverse data as assurance.",
                    ["software-supply-chain.json", "audit-package-verification.json"],
                ),
                (
                    "NIST-SP-1326",
                    "SUPPLIER-RISK-DECISION-CONTRACT-MONITORING-AND-EXIT",
                    "Trace due-diligence findings to risk evaluation, approver, acquisition and contract conditions, compensating controls, monitoring, reassessment triggers, incident obligations, substitution, termination, transition and data-return or destruction evidence.",
                    ["control-proof.json", "lifecycle-traceability.json"],
                ),
            ],
            "procedures": [
                (
                    "NIST-SP-1326",
                    "SUPPLIER-DUE-DILIGENCE-REPERFORMANCE-AND-DECEPTION-CHALLENGE",
                    "Reperform approved supplier cases using immutable authoritative-source snapshots; inject aliases, ownership changes, stale attestations, hidden dependencies, conflicting reports, unsupported provenance, sanctions or incident signals, concentration risk and fabricated clean histories; require bounded adjudication and reassessment.",
                    "manual",
                    False,
                    ["benchmark-scorecard.json", "audit-package-verification.json"],
                )
            ],
        },
        "software-assurance-maturity": {
            "standards": ["OWASP-SAMM", "OWASP-DSOVS", "OWASP-DSOMM", "NIST-SSDF"],
            "controls": [
                (
                    "OWASP-SAMM",
                    "SAMM-SCOPE-PRACTICE-ACTIVITY-QUALITY-AND-EVIDENCE",
                    "Pin SAMM 2.1.0, define organizational and assessment scope, and bind every governance, design, implementation, verification and operations activity to quality criteria, objective evidence, maturity level, assessor, confidence, limitations and target state.",
                    [
                        "maturity-model-assessment.json",
                        "audit-package-verification.json",
                    ],
                ),
                (
                    "OWASP-SAMM",
                    "SAMM-ROADMAP-OUTCOME-REASSESSMENT-AND-BENCHMARK-PRIVACY",
                    "Trace gaps to prioritized roadmap actions, owners, resources, expected outcomes, milestones and reassessment; permit external cohort comparison only with compatible scope, privacy protection, sufficient strata and explicit sample-size and representativeness limitations.",
                    ["operational-trend.json", "process-capability-assessment.json"],
                ),
            ],
            "procedures": [
                (
                    "OWASP-SAMM",
                    "SAMM-BLINDED-ASSESSOR-AGREEMENT-AND-COHORT-CALIBRATION",
                    "Run blinded assessors over golden SAMM cases containing partial criteria, aspirational policy, stale evidence, inconsistent scope, level inflation and roadmap gaps; measure agreement, adjudicate differences and compare cohorts only after k-anonymity and representativeness checks.",
                    "manual",
                    False,
                    ["benchmark-scorecard.json", "maturity-model-assessment.json"],
                )
            ],
        },
    }
)

_ASSURANCE_PROFILES["ai-lifecycle-data-evaluation"]["standards"].append(
    "ISO-IEC-TR-5259-6"
)
_ASSURANCE_PROFILES["ai-lifecycle-data-evaluation"]["controls"].append(
    (
        "ISO-IEC-TR-5259-6",
        "AI-DATA-QUALITY-VISUALIZATION-FIDELITY",
        "Bind every data-quality visualization to the exact measure, dataset, population, stratum, time window, transformation, uncertainty and provenance; expose missingness and limitations and reject misleading scales, aggregation, color, ordering or comparison context.",
        ["benchmark-scorecard.json", "effectiveness.json"],
    )
)
_ASSURANCE_PROFILES["ai-lifecycle-data-evaluation"]["procedures"].append(
    (
        "ISO-IEC-TR-5259-6",
        "AI-DATA-QUALITY-VISUALIZATION-ADVERSE-CASE-REVIEW",
        "Reproduce role-appropriate visualizations from pinned quality measures and inject truncation, omitted uncertainty, hidden missing data, subgroup masking, aggregation reversal, stale provenance, inaccessible encoding and unsupported comparison cases; retain reviewer decisions and treat the Technical Report as guidance rather than certification criteria.",
        "test",
        False,
        ["benchmark-scorecard.json", "audit-package-verification.json"],
    )
)

_ASSURANCE_PROFILES["kubernetes-hardening-conformance"]["standards"].append(
    "KUBERNETES-POD-SECURITY-STANDARDS"
)
_ASSURANCE_PROFILES["kubernetes-hardening-conformance"]["controls"].extend(
    [
        (
            "KUBERNETES-POD-SECURITY-STANDARDS",
            "K8S-PSS-LEVEL-MODE-VERSION-NAMESPACE-AND-WORKLOAD-BINDING",
            "Bind every namespace and workload controller to explicit privileged, baseline or restricted policy, enforce, audit and warn modes, pinned Kubernetes minor version, operating-system semantics, exemptions, owner, expiry and admission evidence; treat unlabeled namespaces as unresolved scope.",
            ["control-proof.json", "domain-assurance.json"],
        ),
        (
            "KUBERNETES-POD-SECURITY-STANDARDS",
            "K8S-PSS-ADMISSION-BYPASS-EXCEPTION-AND-DRIFT-CLOSURE",
            "Trace direct pods and generated templates through admission; detect controller, namespace, user, runtime-class and operating-system bypasses; require least-privilege exception approval, compensating controls, expiry, migration, remediation, rescan and longitudinal drift evidence.",
            ["control-assessment.json", "operational-trend.json"],
        ),
    ]
)
_ASSURANCE_PROFILES["kubernetes-hardening-conformance"]["procedures"].append(
    (
        "KUBERNETES-POD-SECURITY-STANDARDS",
        "K8S-PSS-ADMISSION-NEGATIVE-BYPASS-REMEDIATION-AND-RESCAN",
        "In disposable version-matched clusters, submit direct and controller-generated pods spanning every restricted field and supported operating system; verify enforce denial, audit and warning records, dry-run behavior, exemption limits, privileged namespace controls, webhook interaction, upgrade drift, remediation and clean rescan.",
        "dynamic",
        True,
        ["benchmark-scorecard.json", "procedure-assessment.json"],
    )
)

_ASSURANCE_PROFILES["payment-acceptance-security"]["standards"].extend(
    ["PCI-PIN-SECURITY", "PCI-PTS-POI", "PCI-3DS-CORE", "EMVCO-3DS"]
)
_ASSURANCE_PROFILES["payment-acceptance-security"]["controls"].extend(
    [
        (
            "PCI-PIN-SECURITY",
            "PAYMENT-PIN-KEY-BLOCK-HSM-CEREMONY-AND-DUAL-CONTROL",
            "Bind PIN data, cryptographic keys and key blocks to generation, distribution, loading, storage, use, rotation, compromise, destruction, HSM and operator identities with split knowledge, dual control, tamper evidence, inventories and ceremony records.",
            ["control-proof.json", "audit-package-verification.json"],
        ),
        (
            "PCI-PTS-POI",
            "PAYMENT-POI-DEVICE-FIRMWARE-SRED-AND-LISTING-IDENTITY",
            "Verify POI model, hardware and firmware revision, approval class and expiry, secure reading and exchange of data, interfaces, keys, deployment, inspection, substitution, tamper response, application inventory and listing scope without inferring merchant PCI DSS compliance.",
            ["trust-policy-attestation.json", "external-conformity-assessment.json"],
        ),
        (
            "PCI-3DS-CORE",
            "PAYMENT-3DS-ACS-DS-SERVER-PROTOCOL-AND-ASSESSMENT-BOUNDARY",
            "Bind ACS, Directory Server and 3DS Server components, EMV 3DS protocol version, message and transaction identity, authentication decision, keys, data, environment, qualified assessor, report, remediation and validity while excluding the sunset PCI 3DS SDK program from new claims.",
            ["application-contract-analysis.json", "audit-package-verification.json"],
        ),
    ]
)
_ASSURANCE_PROFILES["payment-acceptance-security"]["procedures"].append(
    (
        "EMVCO-3DS",
        "PAYMENT-PIN-POI-HSM-AND-3DS-END-TO-END-ADVERSARIAL-CONFORMANCE",
        "Use synthetic account and transaction data and test keys to replay PIN-block, key-ceremony, HSM, POI tamper/substitution, SRED, ACS, DS, 3DS Server, challenge, frictionless, replay, downgrade, message mutation, outage, recovery and assessor-claim cases; prove key and data destruction afterward.",
        "dynamic",
        True,
        ["benchmark-scorecard.json", "audit-package-verification.json"],
    )
)

_ASSURANCE_PROFILES.update(
    {
        "semiconductor-equipment-cybersecurity": {
            "standards": ["SEMI-E187", "SEMI-E188", "SEMI-E191", "IEC-62443-3-3"],
            "controls": [
                (
                    "SEMI-E187",
                    "FAB-EQUIPMENT-IDENTITY-HARDENING-SUPPORT-AND-MONITORING",
                    "Bind fab, tool, supplier, integrator, computing device, OS and firmware release, supported lifetime, accounts, services, ports, protocols, endpoint controls, logs, monitoring ownership, exceptions and compensating controls to the exact delivered and maintained equipment configuration.",
                    ["control-assessment.json", "software-supply-chain.json"],
                ),
                (
                    "SEMI-E188",
                    "MALWARE-FREE-DELIVERY-INSTALLATION-SERVICE-AND-RESTORATION",
                    "Verify supplier build and staging hygiene, removable media and remote-service control, signed transfer, pre-shipment and receiving scans, installation state, maintenance authorization, component replacement, restoration images, incident handling and custody evidence throughout equipment integration.",
                    ["procedure-assessment.json", "audit-package-verification.json"],
                ),
                (
                    "SEMI-E191",
                    "FAB-DEVICE-CYBERSECURITY-STATUS-REPORTING",
                    "Normalize device identity, software and firmware inventory, support state, vulnerabilities, protections, monitoring health, exceptions and timestamps without treating incomplete or silent equipment as healthy.",
                    [
                        "operational-trend.json",
                        "security-automation-interoperability.json",
                    ],
                ),
            ],
            "procedures": [
                (
                    "SEMI-E187",
                    "SEMICONDUCTOR-EQUIPMENT-DELIVERY-SERVICE-AND-RECOVERY-EXERCISE",
                    "In an isolated fab-equipment twin, replay clean and contaminated delivery, unsigned or stale images, unsupported OS, exposed services, removable-media and remote-service abuse, status-report suppression, component substitution and recovery; require independent verdicts, known-good restoration and residue checks.",
                    "dynamic",
                    True,
                    ["benchmark-scorecard.json", "audit-package-verification.json"],
                )
            ],
        },
        "pipeline-control-system-cybersecurity": {
            "standards": ["API-STD-1164", "IEC-62443-3-3", "NIST-CSF"],
            "controls": [
                (
                    "API-STD-1164",
                    "PIPELINE-IAC-BOUNDARY-ESSENTIAL-FUNCTION-AND-REMOTE-ACCESS",
                    "Bind operator, pipeline segment, control center, SCADA and local-control assets, safety interfaces, zones, conduits, remote access, vendors, data flows, essential functions, tolerable degradation and ownership to the current IAC architecture and cyber-risk program.",
                    ["static-architecture.json", "control-assessment.json"],
                ),
                (
                    "API-STD-1164",
                    "PIPELINE-DETECTION-MANUAL-CONTROL-RECOVERY-AND-RECONCILIATION",
                    "Prove monitoring, alarm integrity, command authorization, fail-safe and manual operations, incident coordination, communications, backup configuration, restoration order, state reconciliation and lessons learned under loss or compromise of control-system services.",
                    ["operational-trend.json", "incident-management-assessment.json"],
                ),
            ],
            "procedures": [
                (
                    "API-STD-1164",
                    "PIPELINE-CONTROL-SYSTEM-CYBER-RESILIENCE-EXERCISE",
                    "Use an inert hydraulic and control-system digital twin to replay unauthorized commands, stale or forged telemetry, remote-access compromise, ransomware, segmentation failure, loss of communications and recovery; preserve pressure and flow safety invariants and prohibit production actuation.",
                    "dynamic",
                    True,
                    ["benchmark-scorecard.json", "safety-security-analysis.json"],
                )
            ],
        },
        "gxp-computerized-system-data-integrity": {
            "standards": ["FDA-21-CFR-PART-11", "ISPE-GAMP-5", "ISO-IEC-27001"],
            "controls": [
                (
                    "FDA-21-CFR-PART-11",
                    "GXP-RECORD-AUDIT-TRAIL-SIGNATURE-AND-RETENTION-INTEGRITY",
                    "Bind regulated process, record, predicate rule, system boundary, user, role, signature meaning and event to validated functions, access and authority checks, secure time-stamped audit trails, signature-record linking, accurate copies, retention, retrieval and inspection readiness.",
                    ["audit-package-verification.json", "lifecycle-traceability.json"],
                ),
                (
                    "ISPE-GAMP-5",
                    "GXP-RISK-BASED-VALIDATION-SUPPLIER-CHANGE-AND-PERIODIC-REVIEW",
                    "Apply licensed criteria to intended use, patient and product risk, software category, supplier assessment, requirements, configuration, verification, deviations, release, operation, backup, incident, change, periodic review, retirement and data migration with accountable approval.",
                    ["process-capability-assessment.json", "procedure-assessment.json"],
                ),
            ],
            "procedures": [
                (
                    "FDA-21-CFR-PART-11",
                    "GXP-ELECTRONIC-RECORD-AND-SIGNATURE-ADVERSARIAL-VALIDATION",
                    "Exercise a synthetic regulated workflow with altered, deleted, backdated, replayed and orphaned records; shared credentials; signature transfer; clock drift; privilege escalation; incomplete copies; failed restoration; migration and configuration drift. Require attributable, legible, contemporaneous, original, accurate and complete evidence.",
                    "test",
                    True,
                    ["benchmark-scorecard.json", "audit-package-verification.json"],
                )
            ],
        },
        "criminal-justice-information-security": {
            "standards": [
                "FBI-CJIS-SECURITY-POLICY",
                "NIST-SP-800-53",
                "NIST-SP-800-63-4",
            ],
            "controls": [
                (
                    "FBI-CJIS-SECURITY-POLICY",
                    "CJI-BOUNDARY-AGENCY-PERSONNEL-DEVICE-AND-EXCHANGE-AGREEMENT",
                    "Bind CSA, agency, contractor, personnel, purpose, CJI class, system, cloud service, device, network path, physical location, exchange agreement, management-control agreement, security addendum and responsibility to the exact authorized processing boundary.",
                    ["control-assessment.json", "data-exposure.json"],
                ),
                (
                    "FBI-CJIS-SECURITY-POLICY",
                    "CJI-IDENTITY-ENCRYPTION-AUDIT-MOBILE-INCIDENT-AND-DISPOSAL",
                    "Verify identity and access, privileged administration, encryption and key custody, audit generation and review, media and mobile safeguards, remote maintenance, personnel security, incident reporting, retention, sanitization, cloud inheritance and corrective-action evidence.",
                    [
                        "audit-package-verification.json",
                        "incident-management-assessment.json",
                    ],
                ),
            ],
            "procedures": [
                (
                    "FBI-CJIS-SECURITY-POLICY",
                    "CJIS-CJI-ACCESS-EXCHANGE-CLOUD-AND-MOBILE-EXERCISE",
                    "Use synthetic CJI to challenge unauthorized purpose, stale personnel status, device loss, insecure transport, cloud responsibility gaps, privileged misuse, audit suppression, onward disclosure, incident delay and incomplete sanitization; require independent policy-version and jurisdiction review without claiming FBI approval.",
                    "dynamic",
                    True,
                    ["benchmark-scorecard.json", "audit-package-verification.json"],
                )
            ],
        },
        "automotive-process-capability-assurance": {
            "standards": [
                "AUTOMOTIVE-SPICE-PAM",
                "AUTOMOTIVE-SPICE-CYBERSECURITY",
                "ISO-SAE-21434",
            ],
            "controls": [
                (
                    "AUTOMOTIVE-SPICE-PAM",
                    "ASPICE-PROCESS-SCOPE-OUTCOME-WORK-PRODUCT-AND-CAPABILITY-EVIDENCE",
                    "Bind assessment scope, organizational unit, project, lifecycle, process purpose, outcomes, base practices, information items, work products, capability attributes, evidence samples, ratings, weaknesses and improvement actions to the licensed PAM and assessment method.",
                    [
                        "process-capability-assessment.json",
                        "audit-package-verification.json",
                    ],
                ),
                (
                    "AUTOMOTIVE-SPICE-CYBERSECURITY",
                    "ASPICE-CYBERSECURITY-ENGINEERING-AND-ISO21434-TRACEABILITY",
                    "Trace cybersecurity goals, claims, requirements, architecture, implementation, verification, validation, supplier and vulnerability-management evidence across cybersecurity engineering processes and ISO SAE 21434 work products without double counting shared artifacts.",
                    ["lifecycle-traceability.json", "safety-security-analysis.json"],
                ),
            ],
            "procedures": [
                (
                    "AUTOMOTIVE-SPICE-PAM",
                    "ASPICE-BLINDED-PROCESS-CAPABILITY-AND-CYBERSECURITY-ASSESSMENT",
                    "Calibrate qualified assessors on licensed golden cases; inject missing outcomes, weak or substituted work products, nonrepresentative samples, trace gaps, supplier omissions, unsupported capability ratings and conflicts; measure agreement and adjudicate every material disagreement.",
                    "manual",
                    False,
                    ["benchmark-scorecard.json", "process-capability-assessment.json"],
                )
            ],
        },
        "process-industry-functional-safety-security": {
            "standards": ["IEC-61511-1", "IEC-TR-63069", "IEC-61508", "IEC-62443-3-3"],
            "controls": [
                (
                    "IEC-61511-1",
                    "SIS-HAZARD-SIF-SIL-SRS-ARCHITECTURE-AND-LIFECYCLE-TRACE",
                    "Bind process hazard, risk reduction, safety instrumented function, SIL target, safety requirements specification, sensors, logic solver, final elements, independence, architecture, application program, verification, validation, operation, proof testing, maintenance and modification across the SIS lifecycle.",
                    ["safety-security-analysis.json", "lifecycle-traceability.json"],
                ),
                (
                    "IEC-TR-63069",
                    "FUNCTIONAL-SAFETY-SECURITY-DEPENDENCY-AND-CONFLICT-ANALYSIS",
                    "Identify shared assets, communication, identities, tools, changes and failure modes across IEC 61511 or 61508 and IEC 62443; verify security controls do not defeat timing, independence, diagnostics, safe-state, bypass or recovery requirements and preserve residual-risk decisions.",
                    ["safety-security-analysis.json", "control-assessment.json"],
                ),
            ],
            "procedures": [
                (
                    "IEC-61511-1",
                    "PROCESS-SIS-SAFETY-SECURITY-FAULT-INJECTION-AND-PROOF-TEST",
                    "In an inert process and SIS twin, replay sensor faults, dangerous failures, common cause, bypass misuse, unauthorized logic change, network delay, stale configuration, proof-test gaps, partial trip, manual intervention and restoration; independently verify demand response, safe state and residue.",
                    "dynamic",
                    True,
                    ["benchmark-scorecard.json", "safety-security-analysis.json"],
                )
            ],
        },
        "building-automation-secure-connect": {
            "standards": ["ANSI-ASHRAE-135", "IEC-62443-3-3", "ISO-IEC-27001"],
            "controls": [
                (
                    "ANSI-ASHRAE-135",
                    "BACNET-SC-DEVICE-HUB-CERTIFICATE-AND-DATA-LINK-IDENTITY",
                    "Bind building, system, device, BACnet network, Secure Connect node, hub, failover hub, VMAC, certificate, trust store, connection, object and command to an approved topology, role, ownership and lifecycle state.",
                    [
                        "application-contract-analysis.json",
                        "trust-policy-attestation.json",
                    ],
                ),
                (
                    "ANSI-ASHRAE-135",
                    "BUILDING-CONTROL-SEGMENTATION-FAILOVER-SAFE-MODE-AND-RECOVERY",
                    "Verify certificate issuance, renewal and revocation, mutual authentication, authorization, segmentation, hub failover, broadcast handling, time, logging, remote administration, legacy gateway boundaries, operator override, safe fallback and post-event reconciliation.",
                    ["control-assessment.json", "operational-trend.json"],
                ),
            ],
            "procedures": [
                (
                    "ANSI-ASHRAE-135",
                    "BACNET-SC-TRUST-FAILOVER-AND-SAFE-BUILDING-CONTROL-EXERCISE",
                    "Use an inert building-automation twin to replay untrusted, expired and revoked certificates, node and hub substitution, message replay, unauthorized writes, legacy gateway escape, failover, network partition, time loss and recovery while preserving life-safety and environmental bounds.",
                    "dynamic",
                    True,
                    ["benchmark-scorecard.json", "application-contract-analysis.json"],
                )
            ],
        },
        "industrial-robotics-safety-security": {
            "standards": [
                "ISO-10218-1",
                "ISO-10218-2",
                "ANSI-RIA-R15-08-1",
                "IEC-62443-3-3",
            ],
            "controls": [
                (
                    "ISO-10218-1",
                    "ROBOT-SAFETY-FUNCTION-MODE-STOP-LIMIT-AND-INTEGRITY",
                    "Bind robot model, controller, software and parameter release, intended use, foreseeable misuse, operating mode, safety function, protective stop, emergency stop, speed and space limit, enabling device, diagnostics and validation to the delivered robot configuration.",
                    ["safety-security-analysis.json", "assurance-case.json"],
                ),
                (
                    "ISO-10218-2",
                    "ROBOT-CELL-INTEGRATION-ZONE-TOOL-WORKPIECE-AND-HUMAN-INTERACTION",
                    "Verify cell and mobile-robot risk assessment, layout, safeguarding, zones, end effectors, workpieces, interfaces, collaborative operation, restart, teach and maintenance access, cybersecurity dependencies, information for use and modification control.",
                    ["static-architecture.json", "procedure-assessment.json"],
                ),
            ],
            "procedures": [
                (
                    "ISO-10218-2",
                    "INDUSTRIAL-ROBOT-CELL-AND-MOBILE-ROBOT-SAFETY-SECURITY-EXERCISE",
                    "In a bounded simulator or physical safety cell, replay mode confusion, zone intrusion, sensor loss, stale map, command injection, speed-limit and stop failure, payload and tool substitution, mobile-route conflict, restart and recovery; require independent safety validation and prohibit production motion.",
                    "dynamic",
                    True,
                    ["benchmark-scorecard.json", "safety-security-analysis.json"],
                )
            ],
        },
        "data-centre-facility-resilience": {
            "standards": [
                "ISO-IEC-22237-1",
                "ISO-IEC-22237-2",
                "ISO-IEC-TS-22237-31",
                "ANSI-TIA-942-C",
            ],
            "controls": [
                (
                    "ISO-IEC-22237-1",
                    "DATA-CENTRE-AVAILABILITY-SECURITY-ENERGY-CLASSIFICATION-AND-SCOPE",
                    "Bind site, building, room, service, tenant, availability and physical-security class, energy objective, threat, dependency, capacity, topology, design assumption, owner and acceptance evidence over the planned facility lifetime.",
                    ["static-architecture.json", "risk-assessment.json"],
                ),
                (
                    "ANSI-TIA-942-C",
                    "DATA-CENTRE-POWER-COOLING-CABLING-FIRE-PHYSICAL-AND-MONITORING-RESILIENCE",
                    "Trace utility, generator, UPS, distribution, cooling, environmental control, cabling, telecommunications, fire protection, physical access, monitoring, redundancy, maintainability, fault tolerance, edge and high-density changes to verified design and operational evidence.",
                    ["physical-security-assessment.json", "operational-trend.json"],
                ),
            ],
            "procedures": [
                (
                    "ISO-IEC-TS-22237-31",
                    "DATA-CENTRE-FAILURE-MAINTENANCE-RECOVERY-AND-RESILIENCE-KPI-EXERCISE",
                    "Exercise an approved facility digital twin with utility loss, generator failure, UPS and distribution faults, cooling degradation, leak, fire alarm, network path loss, access compromise, sensor deception, maintenance error and cascading load; reproduce resilience KPIs and restoration without disrupting production.",
                    "dynamic",
                    True,
                    ["benchmark-scorecard.json", "operational-trend.json"],
                )
            ],
        },
    }
)
