from __future__ import annotations

import math
import uuid
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

from .benchmark_assurance import (
    BenchmarkAssuranceError,
    verify_execution_receipt_signature,
)
from .benchmark_protocols import validate_protocol_thresholds
from .industry_benchmark_scoring import (
    meets_protocol_thresholds as _meets_protocol_thresholds,
    protocol_acceptance as _protocol_acceptance,
    protocol_metrics_valid as _protocol_metrics_valid,
)
from .industry_receipt_trust import receipt_authority_projection
from .path_safety import read_regular_file
from .prioritization import finding_priority
from .strict_json import loads as strict_loads


_POLICY_PATH = "security/industry-assurance-policy.json"
_MAX_POLICY_BYTES = 4 * 1024 * 1024
_DIGEST = "0123456789abcdef"

_STANDARDS: tuple[dict[str, Any], ...] = (
    {
        "id": "OWASP-ASVS",
        "version": "5.0.0",
        "kind": "verification",
        "reference": "https://owasp.org/www-project-application-security-verification-standard/",
        "evidence": ["security-requirements-coverage.json"],
    },
    {
        "id": "OWASP-MASVS",
        "version": "2.1.0",
        "kind": "verification",
        "reference": "https://mas.owasp.org/MASVS/",
        "evidence": ["security-requirements-coverage.json"],
    },
    {
        "id": "OWASP-TCASVS",
        "version": "5.0.0",
        "kind": "verification",
        "reference": "https://github.com/OWASP/TCASVS",
        "evidence": ["security-requirements-coverage.json"],
    },
    {
        "id": "OWASP-WSTG",
        "version": "4.2",
        "kind": "web-testing-methodology",
        "reference": "https://wstg.owasp.org/v4.2/",
        "evidence": ["procedure-assessment.json", "application-contract-analysis.json"],
    },
    {
        "id": "OWASP-MASTG",
        "version": "2.0.0",
        "kind": "mobile-testing-methodology",
        "reference": "https://mas.owasp.org/MASTG/",
        "evidence": [
            "procedure-assessment.json",
            "security-requirements-coverage.json",
        ],
    },
    {
        "id": "OWASP-SCVS",
        "version": "1.0",
        "kind": "component-verification",
        "reference": "https://owasp.org/www-project-software-component-verification-standard/",
        "evidence": ["dependency-surface.json", "artifact-sbom.cdx.json"],
    },
    {
        "id": "OWASP-AITG",
        "version": "1.0",
        "kind": "ai-testing-methodology",
        "reference": "https://owasp.org/www-project-ai-testing-guide/",
        "evidence": ["procedure-assessment.json", "llm-adversarial-plan.json"],
    },
    {
        "id": "NIST-SSDF",
        "version": "1.1",
        "kind": "lifecycle",
        "reference": "https://csrc.nist.gov/pubs/sp/800/218/final",
        "evidence": [
            "capability-manifest.json",
            "finding-validation.json",
            "effectiveness.json",
        ],
    },
    {
        "id": "NIST-CSF",
        "version": "2.0",
        "kind": "governance",
        "reference": "https://www.nist.gov/cyberframework",
        "evidence": ["capability-manifest.json", "domain-assurance.json"],
    },
    {
        "id": "NIST-SP-800-53",
        "version": "5.2.0",
        "kind": "security-privacy-controls",
        "reference": "https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final",
        "evidence": ["control-assessment.json", "oscal-system-security-plan.json"],
    },
    {
        "id": "NIST-SP-800-53A",
        "version": "5.2.0",
        "kind": "control-assessment-procedures",
        "reference": "https://csrc.nist.gov/pubs/sp/800/53/a/r5/final",
        "evidence": ["procedure-assessment.json", "oscal-assessment-plan.json"],
    },
    {
        "id": "NIST-SP-800-115",
        "version": "2008",
        "kind": "technical-testing-methodology",
        "reference": "https://csrc.nist.gov/pubs/sp/800/115/final",
        "evidence": ["procedure-assessment.json", "llm-adversarial-plan.json"],
    },
    {
        "id": "NIST-SP-800-161",
        "version": "1-update-1",
        "kind": "supply-chain-risk-management",
        "reference": "https://csrc.nist.gov/pubs/sp/800/161/r1/upd1/final",
        "evidence": ["dependency-surface.json", "scanner-trust.json"],
    },
    {
        "id": "OWASP-SAMM",
        "version": "2.1.0",
        "kind": "maturity",
        "reference": "https://owaspsamm.org/model/",
        "evidence": ["capability-manifest.json", "effectiveness.json"],
    },
    {
        "id": "OpenSSF-OSPS",
        "version": "2026.02.19",
        "kind": "project-baseline",
        "reference": "https://baseline.openssf.org/versions/2026-02-19",
        "evidence": [
            "capability-manifest.json",
            "scanner-trust.json",
            "trust-policy-attestation.json",
        ],
    },
    {
        "id": "CIS-CONTROLS",
        "version": "8.1",
        "kind": "prioritized-security-controls",
        "reference": "https://www.cisecurity.org/controls/v8-1",
        "evidence": ["control-assessment.json", "domain-assurance.json"],
    },
    {
        "id": "CIS-BENCHMARKS",
        "version": "policy-pinned",
        "kind": "secure-configuration-baselines",
        "reference": "https://www.cisecurity.org/cis-benchmarks",
        "evidence": ["procedure-assessment.json", "checkov-iac.json", "kics-iac.json"],
    },
    {
        "id": "NIST-SCAP",
        "version": "1.4",
        "kind": "configuration-automation-interchange",
        "reference": "https://csrc.nist.gov/pubs/sp/800/126/r4/final",
        "evidence": ["procedure-assessment.json", "capability-manifest.json"],
    },
    {
        "id": "CWE-TOP-25",
        "version": "2025",
        "kind": "weakness-taxonomy",
        "reference": "https://cwe.mitre.org/top25/",
        "evidence": ["finding-validation.json", "effectiveness.json"],
    },
    {
        "id": "OWASP-TOP-10",
        "version": "2025",
        "kind": "risk-taxonomy",
        "reference": "https://owasp.org/Top10/2025/",
        "evidence": ["finding-validation.json", "application-contract-analysis.json"],
    },
    {
        "id": "OWASP-API-TOP-10",
        "version": "2023",
        "kind": "risk-taxonomy",
        "reference": "https://owasp.org/API-Security/editions/2023/en/0x00-toc/",
        "evidence": [
            "application-contract-analysis.json",
            "runtime-surface-binding.json",
        ],
    },
    {
        "id": "CAPEC",
        "version": "policy-pinned",
        "kind": "attack-pattern-taxonomy",
        "reference": "https://capec.mitre.org/",
        "evidence": ["risk-paths.json", "llm-adversarial-plan.json"],
    },
    {
        "id": "MITRE-ATTACK",
        "version": "policy-pinned",
        "kind": "adversary-taxonomy",
        "reference": "https://attack.mitre.org/",
        "evidence": ["risk-paths.json", "advanced-analysis.json"],
    },
    {
        "id": "MITRE-ATLAS",
        "version": "policy-pinned",
        "kind": "ai-adversary-taxonomy",
        "reference": "https://atlas.mitre.org/",
        "evidence": ["llm-adversarial-plan.json"],
    },
    {
        "id": "MITRE-D3FEND",
        "version": "policy-pinned",
        "kind": "defensive-technique-taxonomy",
        "reference": "https://d3fend.mitre.org/",
        "evidence": ["risk-paths.json", "advanced-analysis.json"],
    },
    {
        "id": "FIRST-CVSS",
        "version": "4.0",
        "kind": "vulnerability-severity",
        "reference": "https://www.first.org/cvss/v4.0/",
        "evidence": ["standardized-prioritization.json"],
    },
    {
        "id": "CISA-SSVC",
        "version": "policy-pinned",
        "kind": "vulnerability-response-decision",
        "reference": "https://www.cisa.gov/stakeholder-specific-vulnerability-categorization-ssvc",
        "evidence": ["standardized-prioritization.json"],
    },
    {
        "id": "OWASP-LLM-TOP-10",
        "version": "2025",
        "kind": "ai-risk-taxonomy",
        "reference": "https://genai.owasp.org/llm-top-10/",
        "evidence": ["llm-adversarial-plan.json"],
    },
    {
        "id": "NIST-AI-RMF",
        "version": "1.0",
        "kind": "ai-risk",
        "reference": "https://airc.nist.gov/RMF_Knowledge_Base/AI_RMF",
        "evidence": ["llm-adversarial-plan.json", "domain-assurance.json"],
    },
    {
        "id": "NIST-AI-600-1",
        "version": "1.0",
        "kind": "generative-ai-profile",
        "reference": "https://doi.org/10.6028/NIST.AI.600-1",
        "evidence": ["llm-adversarial-plan.json"],
    },
    {
        "id": "ISO-IEC-42001",
        "version": "2023",
        "kind": "ai-management-system",
        "reference": "https://www.iso.org/standard/42001",
        "evidence": ["control-assessment.json", "llm-adversarial-plan.json"],
    },
    {
        "id": "ISO-IEC-23894",
        "version": "2023",
        "kind": "ai-risk-management",
        "reference": "https://www.iso.org/standard/77304.html",
        "evidence": ["domain-assurance.json", "llm-adversarial-plan.json"],
    },
    {
        "id": "ISO-IEC-25010",
        "version": "2023",
        "kind": "product-quality",
        "reference": "https://www.iso.org/standard/78176.html",
        "evidence": ["code-health.json", "effectiveness.json"],
    },
    {
        "id": "ISO-IEC-5055",
        "version": "2021",
        "kind": "automated-source-quality-measures",
        "reference": "https://www.iso.org/standard/80623.html",
        "evidence": ["code-health.json", "static-architecture.json"],
    },
    {
        "id": "ISO-IEC-25023",
        "version": "2016",
        "kind": "product-quality-measures",
        "reference": "https://www.iso.org/standard/35747.html",
        "evidence": ["code-health.json", "effectiveness.json"],
    },
    {
        "id": "ISO-IEC-IEEE-42010",
        "version": "2022",
        "kind": "architecture-description",
        "reference": "https://www.iso.org/standard/74393.html",
        "evidence": ["static-architecture.json", "architecture-history.json"],
    },
    {
        "id": "CISQ-QUALITY",
        "version": "2020",
        "kind": "quality-measures",
        "reference": "https://www.omg.org/spec/ASCQM/",
        "evidence": ["code-health.json", "static-architecture.json"],
    },
    {
        "id": "CSA-CCM",
        "version": "4.1",
        "kind": "cloud-controls",
        "reference": "https://cloudsecurityalliance.org/research/cloud-controls-matrix",
        "evidence": ["control-assessment.json", "domain-assurance.json"],
    },
    {
        "id": "OWASP-APTS",
        "version": "0.1.0",
        "kind": "emerging-autonomous-testing-governance",
        "reference": "https://owasp.org/APTS/",
        "evidence": ["llm-adversarial-plan.json", "procedure-assessment.json"],
    },
    {
        "id": "ISO-IEC-27001",
        "version": "2022",
        "kind": "information-security-management-system",
        "reference": "https://www.iso.org/standard/27001.html",
        "evidence": ["control-assessment.json", "audit-package-verification.json"],
    },
    {
        "id": "ISO-IEC-27002",
        "version": "2022",
        "kind": "information-security-controls",
        "reference": "https://www.iso.org/standard/75652.html",
        "evidence": ["control-assessment.json", "domain-assurance.json"],
    },
    {
        "id": "ISO-IEC-27034-1",
        "version": "2011",
        "kind": "application-security-management",
        "reference": "https://www.iso.org/standard/44378.html",
        "evidence": [
            "security-requirements-coverage.json",
            "application-contract-analysis.json",
        ],
    },
    {
        "id": "ISO-IEC-27701",
        "version": "2025",
        "kind": "privacy-information-management-system",
        "reference": "https://www.iso.org/standard/27701.html",
        "evidence": ["control-assessment.json", "data-exposure.json"],
    },
    {
        "id": "NIST-PRIVACY-FRAMEWORK",
        "version": "1.0",
        "kind": "privacy-risk-management",
        "reference": "https://www.nist.gov/privacy-framework",
        "evidence": ["domain-assurance.json", "data-exposure.json"],
    },
    {
        "id": "ISO-IEC-29147",
        "version": "2018",
        "kind": "coordinated-vulnerability-disclosure",
        "reference": "https://www.iso.org/standard/72311.html",
        "evidence": ["finding-register.json", "closure-plan.json"],
    },
    {
        "id": "ISO-IEC-30111",
        "version": "2019",
        "kind": "vulnerability-handling",
        "reference": "https://www.iso.org/standard/69725.html",
        "evidence": [
            "finding-register.json",
            "risk-intelligence.json",
            "closure-plan.json",
        ],
    },
    {
        "id": "NIST-SP-800-61",
        "version": "3",
        "kind": "incident-response",
        "reference": "https://csrc.nist.gov/pubs/sp/800/61/r3/final",
        "evidence": ["control-assessment.json", "operational-trend.json"],
    },
    {
        "id": "NIST-SP-800-218A",
        "version": "2024",
        "kind": "generative-ai-secure-development",
        "reference": "https://csrc.nist.gov/pubs/sp/800/218/a/final",
        "evidence": ["llm-adversarial-plan.json", "domain-assurance.json"],
    },
    {
        "id": "NIST-SP-800-204D",
        "version": "2024",
        "kind": "cicd-supply-chain-security",
        "reference": "https://csrc.nist.gov/pubs/sp/800/204/d/final",
        "evidence": ["release-readiness.json", "evidence-fusion.json"],
    },
    {
        "id": "SLSA",
        "version": "1.2",
        "kind": "software-supply-chain-integrity",
        "reference": "https://slsa.dev/spec/v1.2/",
        "evidence": ["security-passport.json", "release-readiness.json"],
    },
    {
        "id": "ISO-IEC-18974",
        "version": "2023",
        "kind": "open-source-security-assurance",
        "reference": "https://www.iso.org/standard/86450.html",
        "evidence": ["dependency-surface.json", "risk-intelligence.json"],
    },
    {
        "id": "ISO-IEC-5230",
        "version": "2020",
        "kind": "open-source-license-compliance",
        "reference": "https://www.iso.org/standard/81039.html",
        "evidence": ["reuse-compliance.json", "scancode-inventory.json"],
    },
    {
        "id": "SPDX",
        "version": "3.0 / ISO-IEC-5962:2021",
        "kind": "software-bill-of-materials-interchange",
        "reference": "https://spdx.dev/use/specifications/",
        "evidence": ["reuse-compliance.json", "artifact-manifest.json"],
    },
    {
        "id": "EU-CRA",
        "version": "2024/2847",
        "kind": "product-cybersecurity-regulation",
        "reference": "https://eur-lex.europa.eu/eli/reg/2024/2847/oj/eng",
        "evidence": [
            "release-readiness.json",
            "risk-intelligence.json",
            "artifact-sbom.cdx.json",
        ],
    },
    {
        "id": "PCI-DSS",
        "version": "4.0.1",
        "kind": "payment-data-security",
        "reference": "https://www.pcisecuritystandards.org/standards/pci-dss/",
        "evidence": ["control-assessment.json", "data-exposure.json"],
    },
    {
        "id": "PCI-SECURE-SOFTWARE",
        "version": "2.0-2026",
        "kind": "payment-software-security",
        "reference": "https://www.pcisecuritystandards.org/standards/secure-software/",
        "evidence": [
            "security-requirements-coverage.json",
            "procedure-assessment.json",
        ],
        "lifecycle": {
            "edition_status": "final",
            "published": "2026-01-15",
            "observed_at": "2026-08-29",
        },
    },
    {
        "id": "NIST-SP-800-171",
        "version": "3",
        "kind": "controlled-unclassified-information",
        "reference": "https://csrc.nist.gov/pubs/sp/800/171/r3/final",
        "evidence": ["control-assessment.json", "audit-package-verification.json"],
    },
    {
        "id": "SOC2-TSC",
        "version": "policy-pinned",
        "kind": "service-organization-trust-controls",
        "reference": "https://www.aicpa-cima.com/resources/landing/system-and-organization-controls-soc-suite-of-services",
        "evidence": ["control-assessment.json", "audit-package-verification.json"],
    },
)

_STANDARDS += (
    {
        "id": "NIST-SP-800-63-4",
        "version": "2025",
        "kind": "digital-identity",
        "reference": "https://csrc.nist.gov/pubs/sp/800/63/4/final",
        "evidence": ["application-contract-analysis.json", "domain-assurance.json"],
    },
    {
        "id": "IETF-RFC-9700",
        "version": "2025 / BCP-240",
        "kind": "oauth-security-best-current-practice",
        "reference": "https://www.rfc-editor.org/info/rfc9700/",
        "evidence": ["application-contract-analysis.json", "risk-paths.json"],
    },
    {
        "id": "W3C-WEBAUTHN",
        "version": "2 / level-3-candidate",
        "kind": "phishing-resistant-authentication",
        "reference": "https://www.w3.org/TR/webauthn/",
        "evidence": ["application-contract-analysis.json", "procedure-assessment.json"],
    },
    {
        "id": "OIDF-FAPI",
        "version": "2.0-final-2025",
        "kind": "high-assurance-api-authorization",
        "reference": "https://openid.net/specs/fapi-security-profile-2_0-final.html",
        "evidence": ["application-contract-analysis.json", "procedure-assessment.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2025-02-22",
            "observed_at": "2026-08-29",
        },
    },
    {
        "id": "ISO-IEC-27017",
        "version": "2026",
        "kind": "cloud-security-controls",
        "reference": "https://www.iso.org/standard/27017",
        "evidence": ["control-assessment.json", "domain-assurance.json"],
    },
    {
        "id": "ISO-IEC-27018",
        "version": "policy-pinned",
        "kind": "public-cloud-pii-protection",
        "reference": "https://www.iso.org/standard/76559.html",
        "evidence": ["data-exposure.json", "control-assessment.json"],
    },
    {
        "id": "NIST-SP-800-190",
        "version": "2017",
        "kind": "application-container-security",
        "reference": "https://csrc.nist.gov/pubs/sp/800/190/final",
        "evidence": ["domain-assurance.json", "release-readiness.json"],
    },
    {
        "id": "NIST-SP-800-207",
        "version": "2020",
        "kind": "zero-trust-architecture",
        "reference": "https://csrc.nist.gov/pubs/sp/800/207/final",
        "evidence": ["risk-paths.json", "static-architecture.json"],
    },
    {
        "id": "NIST-SP-800-207A",
        "version": "2023",
        "kind": "cloud-native-zero-trust",
        "reference": "https://csrc.nist.gov/pubs/sp/800/207/a/final",
        "evidence": ["application-contract-analysis.json", "risk-paths.json"],
    },
    {
        "id": "FIPS-140-3",
        "version": "2019",
        "kind": "cryptographic-module-validation",
        "reference": "https://csrc.nist.gov/pubs/fips/140-3/final",
        "evidence": ["domain-assurance.json", "release-readiness.json"],
    },
    {
        "id": "FIPS-203",
        "version": "2024",
        "kind": "post-quantum-key-encapsulation",
        "reference": "https://csrc.nist.gov/pubs/fips/203/final",
        "evidence": ["domain-assurance.json", "dependency-surface.json"],
    },
    {
        "id": "FIPS-204",
        "version": "2024",
        "kind": "post-quantum-digital-signatures",
        "reference": "https://csrc.nist.gov/pubs/fips/204/final",
        "evidence": ["domain-assurance.json", "security-passport.json"],
    },
    {
        "id": "FIPS-205",
        "version": "2024",
        "kind": "stateless-hash-based-signatures",
        "reference": "https://csrc.nist.gov/pubs/fips/205/final",
        "evidence": ["domain-assurance.json", "security-passport.json"],
    },
    {
        "id": "NIST-SP-800-131A",
        "version": "2",
        "kind": "cryptographic-transition",
        "reference": "https://csrc.nist.gov/pubs/sp/800/131/a/r2/final",
        "evidence": ["dependency-surface.json", "closure-plan.json"],
    },
    {
        "id": "IETF-RFC-9325",
        "version": "2022 / BCP-195",
        "kind": "tls-dtls-security",
        "reference": "https://www.rfc-editor.org/info/rfc9325",
        "evidence": ["domain-assurance.json", "procedure-assessment.json"],
    },
    {
        "id": "ISO-22301",
        "version": "2019",
        "kind": "business-continuity-management",
        "reference": "https://www.iso.org/standard/75106.html",
        "evidence": ["operational-trend.json", "control-assessment.json"],
    },
    {
        "id": "NIST-SP-800-34",
        "version": "1",
        "kind": "contingency-planning",
        "reference": "https://csrc.nist.gov/pubs/sp/800/34/r1/final",
        "evidence": ["operational-trend.json", "procedure-assessment.json"],
    },
    {
        "id": "EU-NIS2",
        "version": "2022/2555",
        "kind": "cybersecurity-risk-and-incident-regulation",
        "reference": "https://eur-lex.europa.eu/eli/dir/2022/2555/oj/eng",
        "evidence": ["control-assessment.json", "operational-trend.json"],
    },
    {
        "id": "EU-DORA",
        "version": "2022/2554",
        "kind": "digital-operational-resilience-regulation",
        "reference": "https://eur-lex.europa.eu/eli/reg/2022/2554/oj/eng",
        "evidence": ["operational-trend.json", "audit-package-verification.json"],
    },
    {
        "id": "EU-GDPR",
        "version": "2016/679",
        "kind": "data-protection-regulation",
        "reference": "https://eur-lex.europa.eu/eli/reg/2016/679/oj/eng",
        "evidence": ["data-exposure.json", "control-assessment.json"],
    },
    {
        "id": "EU-AI-ACT",
        "version": "2024/1689",
        "kind": "artificial-intelligence-regulation",
        "reference": "https://eur-lex.europa.eu/eli/reg/2024/1689/oj/eng",
        "evidence": ["llm-adversarial-plan.json", "domain-assurance.json"],
    },
    {
        "id": "NISTIR-8259",
        "version": "1-2026",
        "kind": "iot-manufacturer-cybersecurity",
        "reference": "https://csrc.nist.gov/pubs/ir/8259/r1/final",
        "evidence": ["domain-assurance.json", "release-readiness.json"],
    },
    {
        "id": "NISTIR-8259A",
        "version": "2020",
        "kind": "iot-device-capability-baseline",
        "reference": "https://csrc.nist.gov/pubs/ir/8259/a/final",
        "evidence": ["security-requirements-coverage.json", "domain-assurance.json"],
    },
    {
        "id": "NISTIR-8259B",
        "version": "2021",
        "kind": "iot-supporting-capability-baseline",
        "reference": "https://csrc.nist.gov/pubs/ir/8259/b/final",
        "evidence": ["control-assessment.json", "closure-plan.json"],
    },
    {
        "id": "ETSI-EN-303-645",
        "version": "3.1.3-2024",
        "kind": "consumer-iot-security-baseline",
        "reference": "https://www.etsi.org/deliver/etsi_en/303600_303699/303645/03.01.03_60/",
        "evidence": [
            "security-requirements-coverage.json",
            "procedure-assessment.json",
        ],
    },
    {
        "id": "IEC-62443-4-1",
        "version": "2018",
        "kind": "industrial-secure-development-lifecycle",
        "reference": "https://webstore.iec.ch/en/publication/33615",
        "evidence": ["security-requirements-coverage.json", "release-readiness.json"],
    },
    {
        "id": "IEC-62443-4-2",
        "version": "2019",
        "kind": "industrial-component-security",
        "reference": "https://webstore.iec.ch/en/publication/34421",
        "evidence": ["domain-assurance.json", "procedure-assessment.json"],
    },
    {
        "id": "ISO-SAE-21434",
        "version": "2021",
        "kind": "automotive-cybersecurity-engineering",
        "reference": "https://www.iso.org/standard/70918.html",
        "evidence": ["risk-paths.json", "release-readiness.json"],
    },
    {
        "id": "UNECE-R155",
        "version": "policy-pinned",
        "kind": "vehicle-cybersecurity-management",
        "reference": "https://unece.org/transport/documents/2021/03/standards/un-regulation-no-155-cyber-security-and-cyber-security",
        "evidence": ["control-assessment.json", "audit-package-verification.json"],
    },
    {
        "id": "UNECE-R156",
        "version": "policy-pinned",
        "kind": "vehicle-software-update-management",
        "reference": "https://unece.org/transport/documents/2021/03/standards/un-regulation-no-156-software-update-and-software-update",
        "evidence": ["release-readiness.json", "security-passport.json"],
    },
    {
        "id": "IEC-62304",
        "version": "2006+A1:2015",
        "kind": "medical-device-software-lifecycle",
        "reference": "https://webstore.iec.ch/en/publication/22794",
        "evidence": ["security-requirements-coverage.json", "release-readiness.json"],
    },
    {
        "id": "IEC-81001-5-1",
        "version": "2021",
        "kind": "health-software-security-lifecycle",
        "reference": "https://webstore.iec.ch/en/publication/67397",
        "evidence": ["risk-paths.json", "procedure-assessment.json"],
    },
    {
        "id": "FDA-MEDICAL-CYBERSECURITY",
        "version": "policy-pinned",
        "kind": "medical-device-cybersecurity-guidance",
        "reference": "https://www.fda.gov/medical-devices/digital-health-center-excellence/cybersecurity",
        "evidence": ["artifact-sbom.cdx.json", "closure-plan.json"],
    },
    {
        "id": "FEDRAMP",
        "version": "rev5-policy-pinned",
        "kind": "federal-cloud-authorization",
        "reference": "https://www.fedramp.gov/documents-templates/",
        "evidence": [
            "oscal-system-security-plan.json",
            "audit-package-verification.json",
        ],
    },
    {
        "id": "CMMC",
        "version": "2.0 / 32-CFR-170",
        "kind": "defense-cybersecurity-assessment",
        "reference": "https://dodcio.defense.gov/CMMC/",
        "evidence": ["control-assessment.json", "procedure-assessment.json"],
    },
    {
        "id": "NIST-SP-800-171A",
        "version": "3",
        "kind": "cui-assessment-procedures",
        "reference": "https://csrc.nist.gov/pubs/sp/800/171/a/r3/final",
        "evidence": ["procedure-assessment.json", "audit-package-verification.json"],
    },
)

_STANDARDS += (
    {
        "id": "OASIS-SARIF",
        "version": "2.1.0+errata-01",
        "kind": "static-analysis-results-interchange",
        "reference": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html",
        "evidence": ["results.sarif", "audit-package-verification.json"],
    },
    {
        "id": "OASIS-CSAF",
        "version": "2.0+errata-01",
        "kind": "security-advisory-interchange",
        "reference": "https://docs.oasis-open.org/csaf/csaf/v2.0/csaf-v2.0.html",
        "evidence": ["risk-intelligence.json", "artifact-manifest.json"],
    },
    {
        "id": "ISO-IEC-20153",
        "version": "2025",
        "kind": "international-security-advisory-interchange",
        "reference": "https://www.oasis-open.org/2025/05/20/csaf-v2-approved-as-iso-iec-international-standard/",
        "evidence": ["risk-intelligence.json", "closure-plan.json"],
    },
    {
        "id": "ECMA-424",
        "version": "2-2025 / CycloneDX-1.7",
        "kind": "bill-of-materials-interchange",
        "reference": "https://ecma-international.org/publications-and-standards/standards/ecma-424/",
        "evidence": ["sbom.cdx.json", "artifact-sbom.cdx.json"],
    },
    {
        "id": "NIST-OSCAL",
        "version": "1.2.2",
        "kind": "machine-readable-control-assessment",
        "reference": "https://pages.nist.gov/OSCAL/",
        "evidence": ["oscal-assessment-results.json", "oscal-poam.json"],
    },
    {
        "id": "OPENVEX",
        "version": "0.2",
        "kind": "vulnerability-exploitability-exchange",
        "reference": "https://openvex.dev/",
        "evidence": ["risk-intelligence.json", "dependency-surface.json"],
    },
    {
        "id": "OASIS-STIX",
        "version": "2.1",
        "kind": "cyber-threat-intelligence-interchange",
        "reference": "https://www.oasis-open.org/standard/stix2-1/",
        "evidence": ["risk-intelligence.json", "domain-assurance.json"],
    },
    {
        "id": "OASIS-TAXII",
        "version": "2.1",
        "kind": "cyber-threat-intelligence-transport",
        "reference": "https://www.oasis-open.org/standard/taxii-version-2-1/",
        "evidence": ["risk-intelligence.json", "procedure-assessment.json"],
    },
    {
        "id": "ISO-IEC-15408",
        "version": "2022-parts-1-to-5",
        "kind": "common-criteria-security-evaluation",
        "reference": "https://www.commoncriteriaportal.org/cc/",
        "evidence": ["security-requirements-coverage.json", "control-assessment.json"],
    },
    {
        "id": "ISO-IEC-18045",
        "version": "2022",
        "kind": "common-evaluation-methodology",
        "reference": "https://www.commoncriteriaportal.org/cc/",
        "evidence": ["procedure-assessment.json", "audit-package-verification.json"],
    },
    {
        "id": "SIGMA",
        "version": "policy-pinned",
        "kind": "generic-siem-detection-rules",
        "reference": "https://sigmahq.io/sigma-specification/",
        "evidence": ["domain-assurance.json", "procedure-assessment.json"],
    },
    {
        "id": "SEI-CERT-C",
        "version": "2016+errata",
        "kind": "c-secure-coding",
        "reference": "https://wiki.sei.cmu.edu/confluence/display/c/SEI+CERT+C+Coding+Standard",
        "evidence": ["finding-validation.json", "code-health.json"],
    },
    {
        "id": "SEI-CERT-CPP",
        "version": "2016+errata",
        "kind": "cpp-secure-coding",
        "reference": "https://wiki.sei.cmu.edu/confluence/pages/viewpage.action?pageId=88046682",
        "evidence": ["finding-validation.json", "code-health.json"],
    },
    {
        "id": "SEI-CERT-JAVA",
        "version": "policy-pinned",
        "kind": "java-secure-coding",
        "reference": "https://wiki.sei.cmu.edu/confluence/display/java/SEI+CERT+Oracle+Coding+Standard+for+Java",
        "evidence": ["finding-validation.json", "code-health.json"],
    },
    {
        "id": "MISRA-C",
        "version": "2023-policy-pinned-addenda",
        "kind": "critical-system-c-guidelines",
        "reference": "https://misra.org.uk/misra-c/",
        "evidence": ["finding-validation.json", "release-readiness.json"],
    },
    {
        "id": "ISO-IEC-TS-17961",
        "version": "2013",
        "kind": "c-secure-coding-rules",
        "reference": "https://www.iso.org/standard/61134.html",
        "evidence": ["finding-validation.json", "security-requirements-coverage.json"],
    },
    {
        "id": "ISO-IEC-TR-24772",
        "version": "2019-series-policy-pinned",
        "kind": "language-vulnerability-guidance",
        "reference": "https://www.iso.org/standard/71094.html",
        "evidence": ["framework-coverage.json", "finding-validation.json"],
    },
    {
        "id": "ISO-IEC-IEEE-29119-1",
        "version": "2022",
        "kind": "software-testing-concepts-and-vocabulary",
        "reference": "https://www.iso.org/standard/81291.html",
        "evidence": ["test-evidence.json", "security-requirements-coverage.json"],
    },
    {
        "id": "ISO-IEC-IEEE-29119-2",
        "version": "2021",
        "kind": "software-testing-processes",
        "reference": "https://www.iso.org/standard/79428.html",
        "evidence": ["test-evidence.json", "procedure-assessment.json"],
    },
    {
        "id": "ISO-IEC-IEEE-29119-3",
        "version": "2021",
        "kind": "software-test-documentation",
        "reference": "https://www.iso.org/standard/79429.html",
        "evidence": ["test-evidence.json", "audit-package-verification.json"],
    },
    {
        "id": "ISO-IEC-IEEE-29119-4",
        "version": "2021",
        "kind": "software-test-techniques",
        "reference": "https://www.iso.org/standard/79430.html",
        "evidence": ["test-evidence.json", "benchmark-scorecard.json"],
    },
    {
        "id": "ISO-IEC-IEEE-29119-5",
        "version": "2024",
        "kind": "keyword-driven-testing",
        "reference": "https://www.iso.org/standard/87233.html",
        "evidence": ["test-evidence.json", "benchmark-scorecard.json"],
    },
    {
        "id": "ISO-IEC-20246",
        "version": "2017",
        "kind": "work-product-reviews",
        "reference": "https://www.iso.org/standard/63477.html",
        "evidence": ["finding-validation.json", "audit-package-verification.json"],
    },
    {
        "id": "NISTIR-8425",
        "version": "2022",
        "kind": "consumer-iot-product-profile",
        "reference": "https://csrc.nist.gov/pubs/ir/8425/final",
        "evidence": ["domain-assurance.json", "release-readiness.json"],
    },
    {
        "id": "ETSI-TS-103-701",
        "version": "2.1.1-2025",
        "kind": "consumer-iot-conformance-assessment",
        "reference": "https://www.etsi.org/deliver/etsi_ts/103700_103799/103701/02.01.01_60/",
        "evidence": ["procedure-assessment.json", "benchmark-scorecard.json"],
    },
    {
        "id": "IEC-61508",
        "version": "2010-policy-pinned-series",
        "kind": "functional-safety-lifecycle",
        "reference": "https://webstore.iec.ch/en/publication/5515",
        "evidence": ["security-requirements-coverage.json", "risk-paths.json"],
    },
    {
        "id": "ISO-26262",
        "version": "2018-policy-pinned-series",
        "kind": "automotive-functional-safety",
        "reference": "https://www.iso.org/publication/PUB200262.html",
        "evidence": ["security-requirements-coverage.json", "risk-paths.json"],
    },
    {
        "id": "ISO-14971",
        "version": "2019",
        "kind": "medical-device-risk-management",
        "reference": "https://www.iso.org/standard/72704.html",
        "evidence": ["risk-paths.json", "finding-validation.json"],
    },
    {
        "id": "RTCA-DO-326A",
        "version": "policy-pinned",
        "kind": "airworthiness-security-process",
        "reference": "https://www.rtca.org/security/",
        "evidence": ["security-requirements-coverage.json", "control-assessment.json"],
    },
    {
        "id": "RTCA-DO-356A",
        "version": "policy-pinned",
        "kind": "airworthiness-security-methods",
        "reference": "https://www.rtca.org/security/",
        "evidence": ["procedure-assessment.json", "risk-paths.json"],
    },
    {
        "id": "NIST-SP-800-160-1",
        "version": "1-rev1-2022",
        "kind": "systems-security-engineering",
        "reference": "https://csrc.nist.gov/pubs/sp/800/160/v1/r1/final",
        "evidence": ["static-architecture.json", "security-requirements-coverage.json"],
    },
    {
        "id": "NIST-SP-800-160-2",
        "version": "2-rev1-2021",
        "kind": "cyber-resilient-systems-engineering",
        "reference": "https://csrc.nist.gov/pubs/sp/800/160/v2/r1/final",
        "evidence": ["risk-paths.json", "operational-trend.json"],
    },
    {
        "id": "NIST-SP-800-37",
        "version": "2",
        "kind": "risk-management-framework",
        "reference": "https://csrc.nist.gov/pubs/sp/800/37/r2/final",
        "evidence": ["control-assessment.json", "oscal-system-security-plan.json"],
    },
    {
        "id": "NIST-SP-800-55-1",
        "version": "1-2024",
        "kind": "security-measure-selection",
        "reference": "https://csrc.nist.gov/pubs/sp/800/55/v1/final",
        "evidence": ["effectiveness.json", "benchmark-scorecard.json"],
    },
    {
        "id": "NIST-SP-800-55-2",
        "version": "2-2024",
        "kind": "security-measurement-program",
        "reference": "https://csrc.nist.gov/pubs/sp/800/55/v2/final",
        "evidence": ["operational-trend.json", "benchmark-delta.json"],
    },
    {
        "id": "ISO-IEC-27005",
        "version": "2022",
        "kind": "information-security-risk-management",
        "reference": "https://www.iso.org/standard/80585.html",
        "evidence": ["risk-paths.json", "control-assessment.json"],
    },
    {
        "id": "NIST-AI-100-2",
        "version": "e2025",
        "kind": "adversarial-machine-learning-taxonomy",
        "reference": "https://csrc.nist.gov/pubs/ai/100/2/e2025/final",
        "evidence": ["llm-adversarial-plan.json", "domain-assurance.json"],
    },
    {
        "id": "ISO-IEC-42005",
        "version": "2025",
        "kind": "ai-system-impact-assessment",
        "reference": "https://www.iso.org/standard/42005",
        "evidence": ["control-assessment.json", "domain-assurance.json"],
    },
    {
        "id": "ISO-IEC-24029",
        "version": "policy-pinned-series",
        "kind": "neural-network-robustness-assessment",
        "reference": "https://www.iso.org/committee/6794475/x/catalogue/",
        "evidence": ["procedure-assessment.json", "benchmark-scorecard.json"],
    },
    {
        "id": "NIST-SP-800-82",
        "version": "3-2023",
        "kind": "operational-technology-security",
        "reference": "https://csrc.nist.gov/pubs/sp/800/82/r3/final",
        "evidence": ["domain-assurance.json", "risk-paths.json"],
    },
    {
        "id": "NIST-SP-1800-35",
        "version": "2025",
        "kind": "zero-trust-implementation",
        "reference": "https://www.nccoe.nist.gov/projects/implementing-zero-trust-architecture",
        "evidence": ["domain-assurance.json", "procedure-assessment.json"],
    },
    {
        "id": "CISA-ZTMM",
        "version": "2.0",
        "kind": "zero-trust-maturity",
        "reference": "https://www.cisa.gov/resources-tools/resources/zero-trust-maturity-model",
        "evidence": ["control-assessment.json", "operational-trend.json"],
    },
    {
        "id": "ISO-31700",
        "version": "1-2023 / 2-2026",
        "kind": "privacy-by-design",
        "reference": "https://committee.iso.org/committee/10778243/x/catalogue/",
        "evidence": ["data-exposure.json", "security-requirements-coverage.json"],
    },
    {
        "id": "ISO-IEC-29100",
        "version": "2024",
        "kind": "privacy-framework",
        "reference": "https://www.iso.org/standard/85938.html",
        "evidence": ["data-exposure.json", "control-assessment.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2024-12",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "TUF",
        "version": "1.0-policy-pinned",
        "kind": "secure-software-update-framework",
        "reference": "https://theupdateframework.io/",
        "evidence": ["security-passport.json", "release-readiness.json"],
    },
)

_STANDARDS += (
    {
        "id": "ISO-IEC-17025",
        "version": "2017-confirmed-2023",
        "kind": "testing-laboratory-competence",
        "reference": "https://www.iso.org/standard/66912.html",
        "evidence": ["audit-package-verification.json", "reproducibility.json"],
    },
    {
        "id": "ISO-IEC-17020",
        "version": "2012-confirmed-2017",
        "kind": "inspection-body-competence-impartiality",
        "reference": "https://www.iso.org/standard/52994.html",
        "evidence": ["trust-policy-attestation.json", "control-assessment.json"],
    },
    {
        "id": "ISO-IEC-17065",
        "version": "2012-confirmed-2024",
        "kind": "product-certification-body-requirements",
        "reference": "https://www.iso.org/standard/46568.html",
        "evidence": ["control-assessment.json", "audit-package-verification.json"],
    },
    {
        "id": "IEC-62443-2-1",
        "version": "2024",
        "kind": "iacs-asset-owner-security-program",
        "reference": "https://www.isa.org/standards-and-publications/isa-standards/isa-iec-62443-series-of-standards",
        "evidence": ["control-assessment.json", "operational-trend.json"],
    },
    {
        "id": "IEC-62443-2-4",
        "version": "2023-policy-pinned-amendments",
        "kind": "iacs-service-provider-security-program",
        "reference": "https://www.isa.org/standards-and-publications/isa-standards/isa-iec-62443-series-of-standards",
        "evidence": ["domain-assurance.json", "audit-package-verification.json"],
    },
    {
        "id": "IEC-62443-3-2",
        "version": "2020",
        "kind": "iacs-zone-conduit-risk-assessment",
        "reference": "https://www.isa.org/standards-and-publications/isa-standards/isa-iec-62443-series-of-standards",
        "evidence": ["risk-paths.json", "static-architecture.json"],
    },
    {
        "id": "IEC-62443-3-3",
        "version": "2013-corrigendum-2014",
        "kind": "iacs-system-security-requirements-levels",
        "reference": "https://webstore.iec.ch/en/publication/7032",
        "evidence": ["security-requirements-coverage.json", "benchmark-scorecard.json"],
    },
    {
        "id": "NERC-CIP",
        "version": "policy-pinned-effective-set",
        "kind": "bulk-electric-system-critical-infrastructure-protection",
        "reference": "https://www.nerc.com/pa/Stand/Pages/CIPStandards.aspx",
        "evidence": ["domain-assurance.json", "operational-trend.json"],
    },
    {
        "id": "NISTIR-7628",
        "version": "1-rev1-2014",
        "kind": "smart-grid-cybersecurity",
        "reference": "https://csrc.nist.gov/pubs/ir/7628/r1/final",
        "evidence": ["risk-paths.json", "control-assessment.json"],
    },
    {
        "id": "HIPAA-SECURITY-RULE",
        "version": "45-CFR-parts-160-164-policy-pinned",
        "kind": "electronic-protected-health-information-safeguards",
        "reference": "https://www.hhs.gov/hipaa/for-professionals/security/",
        "evidence": ["data-exposure.json", "control-assessment.json"],
    },
    {
        "id": "NIST-SP-800-66",
        "version": "2-2024",
        "kind": "hipaa-cybersecurity-resource-guide",
        "reference": "https://csrc.nist.gov/pubs/sp/800/66/r2/final",
        "evidence": ["security-requirements-coverage.json", "risk-paths.json"],
    },
    {
        "id": "HITRUST-CSF",
        "version": "11.8.0",
        "kind": "healthcare-assurance-framework",
        "reference": "https://hitrustalliance.net/hitrust-framework",
        "evidence": ["control-assessment.json", "audit-package-verification.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2026-05-08",
            "observed_at": "2026-08-29",
        },
    },
    {
        "id": "RTCA-DO-178C",
        "version": "2011-policy-pinned",
        "kind": "airborne-software-development-assurance",
        "reference": "https://www.faa.gov/airports/resources/advisory_circulars/index.cfm/go/document.information/documentNumber/20-115D",
        "evidence": ["security-requirements-coverage.json", "test-evidence.json"],
    },
    {
        "id": "RTCA-DO-330",
        "version": "2011-policy-pinned",
        "kind": "airborne-software-tool-qualification",
        "reference": "https://www.faa.gov/airports/resources/advisory_circulars/index.cfm/go/document.information/documentNumber/20-115D",
        "evidence": ["scanner-trust.json", "bundle-qualification.json"],
    },
    {
        "id": "RTCA-DO-331",
        "version": "2011-policy-pinned",
        "kind": "airborne-model-based-development-verification",
        "reference": "https://www.faa.gov/airports/resources/advisory_circulars/index.cfm/go/document.information/documentNumber/20-115D",
        "evidence": ["static-architecture.json", "security-requirements-coverage.json"],
    },
    {
        "id": "RTCA-DO-332",
        "version": "2011-policy-pinned",
        "kind": "airborne-object-oriented-technology-assurance",
        "reference": "https://www.faa.gov/airports/resources/advisory_circulars/index.cfm/go/document.information/documentNumber/20-115D",
        "evidence": ["code-health.json", "static-architecture.json"],
    },
    {
        "id": "RTCA-DO-333",
        "version": "2011-policy-pinned",
        "kind": "airborne-formal-methods-assurance",
        "reference": "https://www.faa.gov/airports/resources/advisory_circulars/index.cfm/go/document.information/documentNumber/20-115D",
        "evidence": ["finding-validation.json", "test-evidence.json"],
    },
    {
        "id": "DISA-STIG",
        "version": "policy-pinned-quarterly-release",
        "kind": "dod-security-technical-implementation-guides",
        "reference": "https://public.cyber.mil/stigs/",
        "evidence": ["domain-assurance.json", "benchmark-scorecard.json"],
    },
    {
        "id": "ISO-IEC-25040",
        "version": "2024",
        "kind": "software-quality-evaluation-framework",
        "reference": "https://www.iso.org/standard/83467.html",
        "evidence": ["effectiveness.json", "benchmark-scorecard.json"],
    },
    {
        "id": "ISO-IEC-25041",
        "version": "2012-confirmed",
        "kind": "software-quality-evaluator-guidance",
        "reference": "https://www.iso.org/standard/35766.html",
        "evidence": ["audit-package-verification.json", "finding-validation.json"],
    },
    {
        "id": "ISO-IEC-27035-1",
        "version": "2023",
        "kind": "information-security-incident-management-process",
        "reference": "https://www.iso.org/standard/78973.html",
        "evidence": ["operational-trend.json", "control-assessment.json"],
    },
    {
        "id": "ISO-IEC-27035-2",
        "version": "2023",
        "kind": "information-security-incident-preparation",
        "reference": "https://www.iso.org/standard/78974.html",
        "evidence": ["closure-plan.json", "procedure-assessment.json"],
    },
    {
        "id": "ISO-IEC-27035-3",
        "version": "2020",
        "kind": "ict-incident-response-operations",
        "reference": "https://www.iso.org/standard/74033.html",
        "evidence": ["procedure-assessment.json", "operational-trend.json"],
    },
    {
        "id": "ISO-IEC-IEEE-23612",
        "version": "2026",
        "kind": "software-systems-incident-management",
        "reference": "https://www.iso.org/standard/87495.html",
        "evidence": ["finding-register.json", "closure-plan.json"],
    },
    {
        "id": "ISO-IEC-29134",
        "version": "2023",
        "kind": "privacy-impact-assessment",
        "reference": "https://www.iso.org/standard/86012.html",
        "evidence": ["data-exposure.json", "risk-paths.json"],
    },
    {
        "id": "IN-TOTO-ATTESTATION",
        "version": "1.0",
        "kind": "software-supply-chain-attestation-framework",
        "reference": "https://in-toto.io/docs/specs/",
        "evidence": ["security-passport.json", "audit-package-verification.json"],
    },
    {
        "id": "DSSE",
        "version": "community-spec-policy-pinned",
        "kind": "dead-simple-signing-envelope",
        "reference": "https://github.com/secure-systems-lab/dsse",
        "evidence": [
            "audit-package-verification.json",
            "trust-policy-attestation.json",
        ],
    },
    {
        "id": "NIST-CPE",
        "version": "2.3",
        "kind": "common-platform-enumeration",
        "reference": "https://csrc.nist.gov/pubs/ir/7695/final",
        "evidence": ["dependency-surface.json", "risk-intelligence.json"],
    },
    {
        "id": "ISO-IEC-19770-2",
        "version": "2015-policy-pinned-amendments",
        "kind": "software-identification-tags",
        "reference": "https://www.iso.org/standard/65666.html",
        "evidence": ["source-inventory.json", "artifact-manifest.json"],
    },
    {
        "id": "PURL",
        "version": "policy-pinned",
        "kind": "package-url-identifiers",
        "reference": "https://github.com/package-url/purl-spec",
        "evidence": ["dependency-surface.json", "artifact-sbom.cdx.json"],
    },
    {
        "id": "OSV-SCHEMA",
        "version": "policy-pinned",
        "kind": "open-source-vulnerability-schema",
        "reference": "https://ossf.github.io/osv-schema/",
        "evidence": ["risk-intelligence.json", "finding-register.json"],
    },
    {
        "id": "CVE-JSON",
        "version": "5-policy-pinned",
        "kind": "cve-record-interchange",
        "reference": "https://cveproject.github.io/cve-schema/",
        "evidence": ["risk-intelligence.json", "finding-register.json"],
    },
    {
        "id": "OWASP-THREAT-MODELING",
        "version": "maintained-guidance-policy-pinned",
        "kind": "application-threat-modeling-guidance",
        "reference": "https://owasp.org/www-project-threat-modeling/",
        "evidence": ["risk-paths.json", "static-architecture.json"],
    },
)

_STANDARDS += (
    {
        "id": "ISO-IEC-IEEE-12207",
        "version": "2026",
        "kind": "software-life-cycle-processes",
        "reference": "https://www.iso.org/standard/90219.html",
        "evidence": [
            "lifecycle-traceability.json",
            "process-capability-assessment.json",
        ],
    },
    {
        "id": "ISO-IEC-IEEE-15288",
        "version": "2023",
        "kind": "system-life-cycle-processes",
        "reference": "https://www.iso.org/standard/81702.html",
        "evidence": ["lifecycle-traceability.json", "domain-assurance.json"],
    },
    {
        "id": "ISO-IEC-IEEE-29148",
        "version": "2018-confirmed-2024",
        "kind": "requirements-engineering",
        "reference": "https://www.iso.org/standard/72089.html",
        "evidence": [
            "lifecycle-traceability.json",
            "security-requirements-coverage.json",
        ],
    },
    {
        "id": "ISO-IEC-IEEE-42020",
        "version": "2019-revision-monitored",
        "kind": "architecture-processes",
        "reference": "https://www.iso.org/standard/68982.html",
        "evidence": ["architecture-evaluation.json", "architecture-history.json"],
    },
    {
        "id": "ISO-IEC-IEEE-42030",
        "version": "2019",
        "kind": "architecture-evaluation-framework",
        "reference": "https://www.iso.org/standard/73436.html",
        "evidence": ["architecture-evaluation.json", "risk-paths.json"],
    },
    {
        "id": "ISO-IEC-33020",
        "version": "2019",
        "kind": "process-capability-measurement",
        "reference": "https://www.iso.org/standard/78526.html",
        "evidence": ["process-capability-assessment.json"],
    },
    {
        "id": "ISO-IEC-TS-33061",
        "version": "2021-confirmed-2024",
        "kind": "software-life-cycle-process-assessment-model",
        "reference": "https://www.iso.org/standard/80362.html",
        "evidence": [
            "process-capability-assessment.json",
            "audit-package-verification.json",
        ],
    },
    {
        "id": "MITRE-CWE",
        "version": "4.20",
        "kind": "comprehensive-weakness-enumeration",
        "reference": "https://cwe.mitre.org/data/index.html",
        "evidence": ["finding-validation.json", "effectiveness.json"],
    },
    {
        "id": "FIRST-EPSS",
        "version": "policy-pinned-model-and-snapshot",
        "kind": "exploit-probability-model",
        "reference": "https://www.first.org/epss/",
        "evidence": ["risk-intelligence.json", "prioritization-calibration.json"],
    },
    {
        "id": "CISA-KEV",
        "version": "digest-pinned-snapshot",
        "kind": "known-exploited-vulnerability-catalog",
        "reference": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        "evidence": ["risk-intelligence.json", "prioritization-calibration.json"],
    },
    {
        "id": "ISO-IEC-27036-1",
        "version": "2021",
        "kind": "supplier-relationship-concepts",
        "reference": "https://www.iso.org/standard/82905.html",
        "evidence": ["control-assessment.json", "dependency-surface.json"],
    },
    {
        "id": "ISO-IEC-27036-2",
        "version": "2022-policy-pinned",
        "kind": "supplier-relationship-requirements",
        "reference": "https://www.iso.org/standard/73980.html",
        "evidence": ["control-assessment.json", "audit-package-verification.json"],
    },
    {
        "id": "ISO-IEC-27036-3",
        "version": "2023",
        "kind": "ict-supply-chain-security",
        "reference": "https://www.iso.org/standard/82890.html",
        "evidence": ["dependency-surface.json", "security-passport.json"],
    },
    {
        "id": "ISO-IEC-27036-4",
        "version": "2016-policy-pinned",
        "kind": "cloud-supplier-relationship-security",
        "reference": "https://www.iso.org/standard/59689.html",
        "evidence": ["control-assessment.json", "domain-assurance.json"],
    },
    {
        "id": "SIGSTORE",
        "version": "bundle-0.3.2-policy-pinned-client",
        "kind": "identity-bound-software-signing",
        "reference": "https://docs.sigstore.dev/about/bundle/",
        "evidence": [
            "trust-policy-attestation.json",
            "audit-package-verification.json",
        ],
    },
    {
        "id": "IETF-RFC-9334",
        "version": "2023",
        "kind": "remote-attestation-architecture",
        "reference": "https://www.rfc-editor.org/rfc/rfc9334.html",
        "evidence": ["trust-policy-attestation.json", "control-assessment.json"],
    },
    {
        "id": "IETF-RFC-9711",
        "version": "2025",
        "kind": "entity-attestation-token",
        "reference": "https://www.rfc-editor.org/rfc/rfc9711.html",
        "evidence": [
            "trust-policy-attestation.json",
            "audit-package-verification.json",
        ],
    },
    {
        "id": "ISO-IEC-5338",
        "version": "2023",
        "kind": "ai-system-life-cycle-processes",
        "reference": "https://www.iso.org/standard/81118.html",
        "evidence": ["lifecycle-traceability.json", "llm-adversarial-plan.json"],
    },
    {
        "id": "ISO-IEC-5259-1",
        "version": "2024",
        "kind": "ai-data-quality-foundations",
        "reference": "https://www.iso.org/standard/81088.html",
        "evidence": ["control-assessment.json", "effectiveness.json"],
    },
    {
        "id": "ISO-IEC-5259-2",
        "version": "2024",
        "kind": "ai-data-quality-measures",
        "reference": "https://www.iso.org/standard/81860.html",
        "evidence": ["effectiveness.json", "benchmark-scorecard.json"],
    },
    {
        "id": "ISO-IEC-5259-3",
        "version": "2024",
        "kind": "ai-data-quality-management",
        "reference": "https://www.iso.org/standard/81092.html",
        "evidence": ["control-assessment.json", "audit-package-verification.json"],
    },
    {
        "id": "ISO-IEC-5259-4",
        "version": "2024",
        "kind": "ai-data-quality-process-framework",
        "reference": "https://www.iso.org/standard/81093.html",
        "evidence": ["process-capability-assessment.json", "effectiveness.json"],
    },
    {
        "id": "ISO-IEC-5259-5",
        "version": "2025",
        "kind": "ai-data-quality-governance",
        "reference": "https://www.iso.org/standard/84150.html",
        "evidence": ["control-assessment.json", "audit-package-verification.json"],
    },
    {
        "id": "NIST-AI-700-2",
        "version": "2025",
        "kind": "ai-risk-impact-evaluation-method",
        "reference": "https://www.nist.gov/publications/assessing-risks-and-impacts-ai-aria-pilot-evaluation-report",
        "evidence": ["benchmark-scorecard.json", "domain-assurance.json"],
    },
    {
        "id": "UK-AISI-INSPECT",
        "version": "policy-pinned",
        "kind": "ai-evaluation-execution-framework",
        "reference": "https://github.com/UKGovernmentBEIS/inspect_ai",
        "evidence": ["benchmark-scorecard.json", "audit-package-verification.json"],
    },
    {
        "id": "IEC-62443-2-3",
        "version": "2015",
        "kind": "iacs-patch-management",
        "reference": "https://www.isa.org/standards-and-publications/isa-standards/isa-iec-62443-series-of-standards",
        "evidence": ["control-assessment.json", "operational-trend.json"],
    },
    {
        "id": "RTCA-DO-355A",
        "version": "policy-pinned-accepted-means",
        "kind": "continuing-airworthiness-information-security",
        "reference": "https://www.faa.gov/aircraft/air_cert/design_approvals/dah/cybersecurity",
        "evidence": ["operational-trend.json", "procedure-assessment.json"],
    },
    {
        "id": "IACS-UR-E26",
        "version": "policy-pinned-current-revision",
        "kind": "ship-cyber-resilience",
        "reference": "https://iacs.org.uk/resolutions/unified-requirements/ur-e",
        "evidence": ["domain-assurance.json", "control-assessment.json"],
    },
    {
        "id": "IACS-UR-E27",
        "version": "rev-1-2023-policy-pinned",
        "kind": "on-board-system-cyber-resilience",
        "reference": "https://iacs.org.uk/resolutions/unified-requirements/ur-e/ur-e27-rev1",
        "evidence": ["domain-assurance.json", "procedure-assessment.json"],
    },
    {
        "id": "SWIFT-CSCF",
        "version": "2026",
        "kind": "financial-messaging-security-controls",
        "reference": "https://www.swift.com/myswift/customer-security-programme/understand-controls",
        "evidence": ["control-assessment.json", "audit-package-verification.json"],
    },
)

_STANDARDS += (
    {
        "id": "OWASP-DSOVS",
        "version": "1.0-policy-pinned",
        "kind": "devsecops-verification-maturity",
        "reference": "https://owasp.org/www-project-devsecops-verification-standard/",
        "evidence": ["maturity-model-assessment.json"],
    },
    {
        "id": "OWASP-DSOMM",
        "version": "5.0.2",
        "kind": "devsecops-maturity-model",
        "reference": "https://owasp.org/www-project-devsecops-maturity-model/",
        "evidence": ["maturity-model-assessment.json"],
    },
    {
        "id": "TMMI",
        "version": "2.0",
        "kind": "test-process-maturity",
        "reference": "https://www.tmmi.org/tmmi-documents/",
        "evidence": ["maturity-model-assessment.json"],
    },
    {
        "id": "BSIMM",
        "version": "licensed-policy-pinned",
        "kind": "empirical-software-security-maturity",
        "reference": "https://www.bsimm.com/",
        "evidence": ["maturity-model-assessment.json"],
    },
    {
        "id": "CMMI-DEV",
        "version": "licensed-policy-pinned",
        "kind": "development-process-maturity",
        "reference": "https://cmmiinstitute.com/cmmi/dev",
        "evidence": ["maturity-model-assessment.json"],
    },
    {
        "id": "ISO-IEC-42006",
        "version": "2025",
        "kind": "ai-management-system-certification-body-requirements",
        "reference": "https://www.iso.org/standard/42006",
        "evidence": ["external-conformity-assessment.json"],
    },
    {
        "id": "ISO-IEC-25059",
        "version": "2023",
        "kind": "ai-system-quality-model",
        "reference": "https://www.iso.org/standard/80655.html",
        "evidence": ["external-conformity-assessment.json", "benchmark-scorecard.json"],
    },
    {
        "id": "ISO-IEC-TR-24027",
        "version": "2021",
        "kind": "ai-bias",
        "reference": "https://www.iso.org/standard/77607.html",
        "evidence": ["external-conformity-assessment.json", "benchmark-scorecard.json"],
    },
    {
        "id": "ISO-IEC-TR-24028",
        "version": "2020",
        "kind": "ai-trustworthiness",
        "reference": "https://www.iso.org/standard/77608.html",
        "evidence": ["external-conformity-assessment.json"],
    },
    {
        "id": "CSA-AICM",
        "version": "1.1",
        "kind": "ai-cloud-controls-matrix",
        "reference": "https://cloudsecurityalliance.org/artifacts/ai-controls-matrix-v1-1",
        "evidence": ["external-conformity-assessment.json"],
    },
    {
        "id": "CSA-STAR",
        "version": "policy-pinned",
        "kind": "independent-cloud-security-assurance",
        "reference": "https://cloudsecurityalliance.org/star",
        "evidence": ["external-conformity-assessment.json"],
    },
    {
        "id": "OASIS-CACAO",
        "version": "2.0",
        "kind": "security-playbook-interchange",
        "reference": "https://docs.oasis-open.org/cacao/security-playbooks/v2.0/security-playbooks-v2.0.html",
        "evidence": ["security-automation-interoperability.json"],
    },
    {
        "id": "OASIS-OPENC2",
        "version": "1.0",
        "kind": "cyber-defense-command-language",
        "reference": "https://www.oasis-open.org/standard/oc2-ls-v1-0/",
        "evidence": ["security-automation-interoperability.json"],
    },
    {
        "id": "OCSF",
        "version": "policy-pinned",
        "kind": "security-event-schema",
        "reference": "https://ocsf.io/",
        "evidence": ["security-automation-interoperability.json"],
    },
    {
        "id": "NIST-SP-800-216",
        "version": "2023",
        "kind": "federal-vulnerability-disclosure-guidelines",
        "reference": "https://csrc.nist.gov/pubs/sp/800/216/final",
        "evidence": ["external-conformity-assessment.json"],
    },
    {
        "id": "UK-PSTI",
        "version": "2023-regulations-policy-pinned",
        "kind": "consumer-connectable-product-security",
        "reference": "https://www.gov.uk/guidance/regulations-consumer-connectable-product-security",
        "evidence": ["external-conformity-assessment.json"],
    },
    {
        "id": "ETSI-EN-18031",
        "version": "1-3:2024-policy-pinned",
        "kind": "radio-equipment-cybersecurity",
        "reference": "https://www.etsi.org/deliver/etsi_en/180300_180399/18003101/",
        "evidence": ["external-conformity-assessment.json"],
    },
    {
        "id": "MITRE-ATTACK-EVALUATIONS",
        "version": "policy-pinned",
        "kind": "detection-product-evaluation",
        "reference": "https://attackevals.mitre-engenuity.org/",
        "evidence": ["external-conformity-assessment.json", "benchmark-scorecard.json"],
    },
)

_STANDARDS += (
    {
        "id": "NIST-SP-800-228",
        "version": "2025-update-1-2026",
        "kind": "cloud-native-api-protection",
        "reference": "https://csrc.nist.gov/pubs/sp/800/228/upd1/final",
        "evidence": ["application-contract-analysis.json", "risk-paths.json"],
    },
    {
        "id": "NIST-SP-800-204",
        "version": "2020",
        "kind": "microservices-security-strategies",
        "reference": "https://csrc.nist.gov/pubs/sp/800/204/final",
        "evidence": ["static-architecture.json", "domain-assurance.json"],
    },
    {
        "id": "NIST-SP-800-204B",
        "version": "2021",
        "kind": "attribute-based-access-control-for-microservices",
        "reference": "https://csrc.nist.gov/pubs/sp/800/204/b/final",
        "evidence": ["application-contract-analysis.json", "risk-paths.json"],
    },
    {
        "id": "NIST-SP-800-204C",
        "version": "2022",
        "kind": "cloud-native-devsecops-service-mesh",
        "reference": "https://csrc.nist.gov/pubs/sp/800/204/c/final",
        "evidence": ["domain-assurance.json", "release-readiness.json"],
    },
    {
        "id": "NIST-SP-800-233",
        "version": "2024",
        "kind": "service-mesh-proxy-threat-models",
        "reference": "https://csrc.nist.gov/pubs/sp/800/233/final",
        "evidence": ["static-architecture.json", "risk-paths.json"],
    },
    {
        "id": "NISTIR-8505",
        "version": "2024",
        "kind": "cloud-native-data-protection",
        "reference": "https://csrc.nist.gov/pubs/ir/8505/final",
        "evidence": ["data-exposure.json", "domain-assurance.json"],
    },
    {
        "id": "IETF-RFC-9942",
        "version": "2026",
        "kind": "cose-receipts-for-verifiable-data-structures",
        "reference": "https://www.rfc-editor.org/info/rfc9942",
        "evidence": [
            "security-automation-interoperability.json",
            "security-passport.json",
        ],
    },
    {
        "id": "IETF-RFC-9943",
        "version": "2026",
        "kind": "supply-chain-integrity-transparency-and-trust",
        "reference": "https://www.rfc-editor.org/info/rfc9943",
        "evidence": [
            "security-automation-interoperability.json",
            "audit-package-verification.json",
        ],
    },
    {
        "id": "OWASP-AGENTIC-TOP-10",
        "version": "2026",
        "kind": "agentic-application-security-risk-baseline",
        "reference": "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/",
        "evidence": ["llm-adversarial-plan.json", "benchmark-scorecard.json"],
    },
    {
        "id": "ISO-IEC-TR-29119-11",
        "version": "2020",
        "kind": "ai-system-testing-guidance",
        "reference": "https://www.iso.org/standard/79016.html",
        "evidence": ["test-evidence.json", "benchmark-scorecard.json"],
    },
    {
        "id": "ISO-IEC-TS-42119-2",
        "version": "2025",
        "kind": "risk-based-ai-system-testing",
        "reference": "https://www.iso.org/standard/84127.html",
        "evidence": ["llm-adversarial-plan.json", "benchmark-scorecard.json"],
    },
    {
        "id": "IETF-RFC-9116",
        "version": "2022",
        "kind": "security-txt-vulnerability-disclosure",
        "reference": "https://www.rfc-editor.org/info/rfc9116",
        "evidence": ["benchmark-scorecard.json", "closure-plan.json"],
    },
    {
        "id": "NIST-SP-800-40",
        "version": "revision-4-2022",
        "kind": "enterprise-patch-management-planning",
        "reference": "https://csrc.nist.gov/pubs/sp/800/40/r4/final",
        "evidence": ["closure-plan.json", "operational-trend.json"],
    },
    {
        "id": "OPENSSF-S2C2F",
        "version": "1.0-policy-pinned",
        "kind": "software-supply-chain-consumption",
        "reference": "https://github.com/ossf/s2c2f",
        "evidence": [
            "dependency-surface.json",
            "security-automation-interoperability.json",
        ],
    },
    {
        "id": "NTIA-SBOM-MINIMUM-ELEMENTS",
        "version": "2021",
        "kind": "sbom-minimum-elements",
        "reference": "https://www.ntia.gov/report/2021/minimum-elements-software-bill-materials-sbom",
        "evidence": ["sbom.cdx.json", "artifact-sbom.cdx.json"],
        "lifecycle": {
            "edition_status": "historical",
            "published": "2021-07-12",
            "observed_at": "2026-08-28",
            "superseded_by": ["CISA-SBOM-MINIMUM-ELEMENTS@2026-v2.1"],
        },
    },
    {
        "id": "OPENTELEMETRY-SEMCONV",
        "version": "1.44.0-policy-pinned",
        "kind": "telemetry-semantic-conventions",
        "reference": "https://opentelemetry.io/docs/specs/semconv/",
        "evidence": ["security-automation-interoperability.json", "data-exposure.json"],
    },
    {
        "id": "OPENAPI-SPECIFICATION",
        "version": "3.1.1-policy-pinned",
        "kind": "http-api-description",
        "reference": "https://spec.openapis.org/oas/v3.1.1.html",
        "evidence": [
            "security-automation-interoperability.json",
            "application-contract-analysis.json",
        ],
    },
    {
        "id": "ASYNCAPI-SPECIFICATION",
        "version": "3.0.0-policy-pinned",
        "kind": "event-driven-api-description",
        "reference": "https://www.asyncapi.com/docs/reference/specification/v3.0.0",
        "evidence": [
            "security-automation-interoperability.json",
            "domain-assurance.json",
        ],
    },
    {
        "id": "GRAPHQL-SPECIFICATION",
        "version": "september-2025",
        "kind": "graphql-language-and-execution",
        "reference": "https://spec.graphql.org/September2025/",
        "evidence": [
            "security-automation-interoperability.json",
            "application-contract-analysis.json",
        ],
    },
    {
        "id": "JSON-SCHEMA",
        "version": "2020-12",
        "kind": "json-schema-validation",
        "reference": "https://json-schema.org/draft/2020-12",
        "evidence": [
            "security-automation-interoperability.json",
            "audit-package-verification.json",
        ],
    },
    {
        "id": "NCSC-CAF",
        "version": "4.0",
        "kind": "critical-services-cyber-resilience-assessment",
        "reference": "https://www.ncsc.gov.uk/collection/cyber-assessment-framework",
        "evidence": ["external-conformity-assessment.json", "operational-trend.json"],
    },
    {
        "id": "NCSC-CYBER-ESSENTIALS",
        "version": "3.3-2026",
        "kind": "uk-essential-cyber-controls",
        "reference": "https://www.ncsc.gov.uk/cyberessentials/resources",
        "evidence": ["external-conformity-assessment.json", "control-assessment.json"],
    },
    {
        "id": "ASD-ESSENTIAL-EIGHT",
        "version": "november-2023-policy-pinned",
        "kind": "australian-cyber-maturity-baseline",
        "reference": "https://www.cyber.gov.au/business-government/asds-cyber-security-frameworks/essential-eight/essential-eight-maturity-model",
        "evidence": ["maturity-model-assessment.json", "control-assessment.json"],
    },
    {
        "id": "CISA-CPG",
        "version": "cross-sector-1.0.1-policy-pinned",
        "kind": "prioritized-cross-sector-cybersecurity-baseline",
        "reference": "https://www.cisa.gov/cybersecurity-performance-goals",
        "evidence": ["control-assessment.json", "operational-trend.json"],
    },
    {
        "id": "ISO-24089",
        "version": "2023",
        "kind": "road-vehicle-software-update-engineering",
        "reference": "https://www.iso.org/standard/77796.html",
        "evidence": ["release-readiness.json", "security-passport.json"],
    },
    {
        "id": "IEC-62351",
        "version": "2026-series-policy-pinned",
        "kind": "power-system-communication-security",
        "reference": "https://webstore.iec.ch/en/publication/6912",
        "evidence": ["domain-assurance.json", "procedure-assessment.json"],
    },
    {
        "id": "UL-2900",
        "version": "series-policy-pinned",
        "kind": "software-cybersecurity-product-assurance",
        "reference": "https://www.ul.com/services/ul-2900-standards-cybersecurity",
        "evidence": ["external-conformity-assessment.json", "benchmark-scorecard.json"],
    },
    {
        "id": "SEI-ATAM",
        "version": "policy-pinned",
        "kind": "architecture-tradeoff-analysis-method",
        "reference": "https://www.sei.cmu.edu/library/architecture-tradeoff-analysis-method/",
        "evidence": ["architecture-evaluation.json", "benchmark-scorecard.json"],
    },
    {
        "id": "ISO-IEC-TS-27560",
        "version": "2023",
        "kind": "consent-record-information-structure",
        "reference": "https://www.iso.org/standard/80392.html",
        "evidence": ["data-exposure.json", "procedure-assessment.json"],
    },
    {
        "id": "CISA-SBOM-MINIMUM-ELEMENTS",
        "version": "2026-v2.1",
        "kind": "sbom-minimum-elements",
        "reference": "https://media.defense.gov/2026/Jul/29/2003971159/-1/-1/1/CSI_2026_cisa_sbom_minimum_elements_508c.PDF",
        "evidence": [
            "sbom.cdx.json",
            "artifact-sbom.cdx.json",
            "benchmark-scorecard.json",
        ],
        "lifecycle": {
            "edition_status": "final",
            "published": "2026-07-29",
            "observed_at": "2026-08-28",
            "supersedes": ["NTIA-SBOM-MINIMUM-ELEMENTS@2021"],
        },
    },
    {
        "id": "NIST-SP-800-172",
        "version": "revision-3-2026",
        "kind": "enhanced-cui-security-requirements",
        "reference": "https://csrc.nist.gov/pubs/sp/800/172/r3/final",
        "evidence": ["control-assessment.json", "external-conformity-assessment.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2026-05-13",
            "observed_at": "2026-08-28",
            "supersedes": ["NIST-SP-800-172@revision-2-2021"],
        },
    },
    {
        "id": "NIST-SP-800-172A",
        "version": "revision-3-2026",
        "kind": "enhanced-cui-assessment-procedures",
        "reference": "https://csrc.nist.gov/pubs/sp/800/172/a/r3/final",
        "evidence": [
            "procedure-assessment.json",
            "external-conformity-assessment.json",
        ],
        "lifecycle": {
            "edition_status": "final",
            "published": "2026-05-13",
            "observed_at": "2026-08-28",
            "supersedes": ["NIST-SP-800-172A@revision-2-2022"],
        },
    },
    {
        "id": "NIST-SP-800-53B",
        "version": "release-5.2.0-2025",
        "kind": "security-privacy-control-baselines",
        "reference": "https://csrc.nist.gov/pubs/sp/800/53/b/upd1/final",
        "evidence": ["control-assessment.json", "oscal-profile.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2025-08-27",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "NISTIR-8397",
        "version": "2021",
        "kind": "developer-verification-minimums",
        "reference": "https://csrc.nist.gov/pubs/ir/8397/final",
        "evidence": [
            "test-evidence.json",
            "security-requirements-coverage.json",
            "benchmark-scorecard.json",
        ],
        "lifecycle": {
            "edition_status": "final",
            "published": "2021-10",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "NIST-SP-800-57-PART-1",
        "version": "revision-5-2020",
        "kind": "key-management-general-guidance",
        "reference": "https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final",
        "evidence": ["domain-assurance.json", "security-passport.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2020-05",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "NIST-SP-800-57-PART-2",
        "version": "revision-1-2019",
        "kind": "key-management-organization-practices",
        "reference": "https://csrc.nist.gov/pubs/sp/800/57/pt2/r1/final",
        "evidence": ["domain-assurance.json", "control-assessment.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2019-05",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "NIST-SP-800-57-PART-3",
        "version": "revision-1-2015",
        "kind": "application-specific-key-management",
        "reference": "https://csrc.nist.gov/pubs/sp/800/57/pt3/r1/final",
        "evidence": ["application-contract-analysis.json", "domain-assurance.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2015-01",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "NIST-SP-800-227",
        "version": "2025",
        "kind": "key-encapsulation-mechanisms",
        "reference": "https://csrc.nist.gov/pubs/sp/800/227/final",
        "evidence": ["domain-assurance.json", "benchmark-scorecard.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2025-09-18",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "NIST-CSWP-39",
        "version": "update-1-2026",
        "kind": "post-quantum-cryptography-transition",
        "reference": "https://csrc.nist.gov/pubs/cswp/39/upd1/considerations-for-achieving-crypto-agility/final",
        "evidence": [
            "dependency-surface.json",
            "domain-assurance.json",
            "closure-plan.json",
        ],
        "lifecycle": {
            "edition_status": "final",
            "published": "2026-06-29",
            "observed_at": "2026-08-28",
            "supersedes": ["NIST-CSWP-39@2024"],
        },
    },
    {
        "id": "NIST-SP-800-137",
        "version": "2011",
        "kind": "information-security-continuous-monitoring",
        "reference": "https://csrc.nist.gov/pubs/sp/800/137/final",
        "evidence": ["operational-trend.json", "control-assessment.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2011-09",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "NIST-SP-800-137A",
        "version": "2020",
        "kind": "continuous-monitoring-program-assessment",
        "reference": "https://csrc.nist.gov/pubs/sp/800/137/a/final",
        "evidence": ["procedure-assessment.json", "operational-trend.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2020-05",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "NISTIR-8212",
        "version": "2021",
        "kind": "continuous-monitoring-assessment-method",
        "reference": "https://csrc.nist.gov/pubs/ir/8212/final",
        "evidence": ["benchmark-scorecard.json", "operational-trend.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2021-03",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "ISO-IEC-27004",
        "version": "2016",
        "kind": "information-security-monitoring-measurement-evaluation",
        "reference": "https://www.iso.org/standard/64120.html",
        "evidence": ["operational-trend.json", "control-assessment.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2016-12",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "ISO-IEC-27031",
        "version": "2025",
        "kind": "ict-readiness-for-business-continuity",
        "reference": "https://www.iso.org/standard/27031",
        "evidence": ["operational-trend.json", "procedure-assessment.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2025-05",
            "observed_at": "2026-08-28",
            "supersedes": ["ISO-IEC-27031@2011"],
        },
    },
    {
        "id": "ISO-IEC-27037",
        "version": "2012",
        "kind": "digital-evidence-identification-collection-preservation",
        "reference": "https://www.iso.org/standard/44381.html",
        "evidence": [
            "audit-package-verification.json",
            "external-conformity-assessment.json",
        ],
        "lifecycle": {
            "edition_status": "final-under-review",
            "published": "2012-10",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "ISO-IEC-27041",
        "version": "2015",
        "kind": "digital-investigation-method-assurance",
        "reference": "https://www.iso.org/standard/44405.html",
        "evidence": ["external-conformity-assessment.json", "benchmark-scorecard.json"],
        "lifecycle": {
            "edition_status": "final-under-review",
            "published": "2015-06",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "ISO-IEC-27042",
        "version": "2015",
        "kind": "digital-evidence-analysis-interpretation",
        "reference": "https://www.iso.org/standard/44406.html",
        "evidence": ["external-conformity-assessment.json", "benchmark-scorecard.json"],
        "lifecycle": {
            "edition_status": "final-under-review",
            "published": "2015-06",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "ISO-IEC-27043",
        "version": "2015",
        "kind": "incident-investigation-principles-processes",
        "reference": "https://www.iso.org/standard/44407.html",
        "evidence": [
            "procedure-assessment.json",
            "external-conformity-assessment.json",
        ],
        "lifecycle": {
            "edition_status": "final",
            "published": "2015-03",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "NIST-SP-800-86",
        "version": "2006",
        "kind": "incident-response-forensic-techniques",
        "reference": "https://csrc.nist.gov/pubs/sp/800/86/final",
        "evidence": ["procedure-assessment.json", "audit-package-verification.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2006-08",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "NIST-SP-800-18",
        "version": "2",
        "kind": "system-security-privacy-supply-chain-planning",
        "reference": "https://csrc.nist.gov/pubs/sp/800/18/r2/final",
        "evidence": [
            "oscal-system-security-plan.json",
            "lifecycle-traceability.json",
            "control-assessment.json",
        ],
        "lifecycle": {
            "edition_status": "final",
            "published": "2026-06-30",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "NIST-SP-800-92",
        "version": "2006",
        "kind": "security-log-management",
        "reference": "https://csrc.nist.gov/pubs/sp/800/92/final",
        "evidence": ["domain-assurance.json", "procedure-assessment.json"],
        "lifecycle": {
            "edition_status": "final-under-review",
            "published": "2006-09",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "ISO-IEC-27014",
        "version": "2020",
        "kind": "information-security-governance",
        "reference": "https://www.iso.org/standard/74046.html",
        "evidence": ["maturity-model-assessment.json", "control-assessment.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2020-12",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "ISO-IEC-27032",
        "version": "2023",
        "kind": "internet-security",
        "reference": "https://www.iso.org/standard/76070.html",
        "evidence": ["domain-assurance.json", "boundary-graph.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2023-06",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "ISO-IEC-27033-1",
        "version": "2015",
        "kind": "network-security-concepts",
        "reference": "https://www.iso.org/standard/63461.html",
        "evidence": ["boundary-graph.json", "domain-assurance.json"],
        "lifecycle": {
            "edition_status": "final-under-review",
            "published": "2015-03",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "ISO-IEC-27033-2",
        "version": "2012",
        "kind": "network-security-design-implementation",
        "reference": "https://www.iso.org/standard/51581.html",
        "evidence": ["static-architecture.json", "control-assessment.json"],
        "lifecycle": {
            "edition_status": "final-under-review",
            "published": "2012-07",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "ISO-IEC-27033-3",
        "version": "2010",
        "kind": "network-security-gateway-scenarios",
        "reference": "https://www.iso.org/standard/51582.html",
        "evidence": ["boundary-graph.json", "procedure-assessment.json"],
        "lifecycle": {
            "edition_status": "final-under-review",
            "published": "2010-12",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "ISO-IEC-27033-4",
        "version": "2014",
        "kind": "network-security-gateway-protocols",
        "reference": "https://www.iso.org/standard/51583.html",
        "evidence": ["boundary-graph.json", "procedure-assessment.json"],
        "lifecycle": {
            "edition_status": "final-under-review",
            "published": "2014-04",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "ISO-IEC-27033-5",
        "version": "2013",
        "kind": "virtual-private-network-security",
        "reference": "https://www.iso.org/standard/51584.html",
        "evidence": ["boundary-graph.json", "control-assessment.json"],
        "lifecycle": {
            "edition_status": "final-under-review",
            "published": "2013-08",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "ISO-IEC-27033-6",
        "version": "2016",
        "kind": "wireless-network-security",
        "reference": "https://www.iso.org/standard/51585.html",
        "evidence": ["domain-assurance.json", "procedure-assessment.json"],
        "lifecycle": {
            "edition_status": "final-under-review",
            "published": "2016-06",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "ISO-IEC-27040",
        "version": "2024",
        "kind": "storage-security",
        "reference": "https://www.iso.org/standard/80194.html",
        "evidence": ["data-exposure.json", "control-assessment.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2024-01",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "NIST-SP-800-188",
        "version": "2023",
        "kind": "data-de-identification-governance",
        "reference": "https://csrc.nist.gov/pubs/sp/800/188/final",
        "evidence": ["data-exposure.json", "procedure-assessment.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2023-09",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "ISO-IEC-27555",
        "version": "2021",
        "kind": "personally-identifiable-information-deletion",
        "reference": "https://www.iso.org/standard/71673.html",
        "evidence": ["data-exposure.json", "procedure-assessment.json"],
        "lifecycle": {
            "edition_status": "final-under-review",
            "published": "2021-10",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "ISO-IEC-27559",
        "version": "2022",
        "kind": "privacy-enhancing-data-de-identification",
        "reference": "https://www.iso.org/standard/71677.html",
        "evidence": ["data-exposure.json", "benchmark-scorecard.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2022-11",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "W3C-ACT-RULES-FORMAT",
        "version": "1.1",
        "kind": "accessibility-conformance-test-rule-format",
        "reference": "https://www.w3.org/TR/act-rules-format-1.1/",
        "evidence": ["test-evidence.json", "benchmark-scorecard.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2026-02-05",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "W3C-WCAG",
        "version": "2.2-2024-recommendation",
        "kind": "web-content-accessibility",
        "reference": "https://www.w3.org/TR/WCAG22/",
        "evidence": [
            "test-evidence.json",
            "external-conformity-assessment.json",
            "benchmark-scorecard.json",
        ],
        "lifecycle": {
            "edition_status": "final",
            "published": "2024-12-12",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "ETSI-EN-301-549",
        "version": "3.2.1-2021",
        "kind": "ict-product-service-accessibility",
        "reference": "https://www.etsi.org/deliver/etsi_en/301500_301599/301549/03.02.01_60/en_301549v030201p.pdf",
        "evidence": ["test-evidence.json", "external-conformity-assessment.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2021-03",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "US-SECTION-508",
        "version": "revised-2017-policy-current",
        "kind": "federal-ict-accessibility",
        "reference": "https://www.access-board.gov/ict/",
        "evidence": ["test-evidence.json", "external-conformity-assessment.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2017-01",
            "observed_at": "2026-08-28",
        },
    },
)

_STANDARDS += (
    {
        "id": "NIST-SP-800-232",
        "version": "2025-final",
        "kind": "ascon-lightweight-cryptography",
        "reference": "https://csrc.nist.gov/pubs/sp/800/232/final",
        "evidence": ["cryptographic-assurance.json", "benchmark-scorecard.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2025-08",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "NIST-SP-800-231",
        "version": "2025-final",
        "kind": "bugs-framework-software-weakness-analysis",
        "reference": "https://csrc.nist.gov/pubs/sp/800/231/final",
        "evidence": ["finding-validation.json", "benchmark-scorecard.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2025-11",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "ISO-IEC-27400",
        "version": "2022",
        "kind": "iot-security-and-privacy-guidelines",
        "reference": "https://www.iso.org/standard/44373.html",
        "evidence": ["control-proof.json", "domain-assurance.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2022-06",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "ISO-IEC-27402",
        "version": "2023",
        "kind": "iot-device-security-baseline",
        "reference": "https://www.iso.org/standard/80136.html",
        "evidence": ["control-proof.json", "benchmark-scorecard.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2023",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "ISO-IEC-27403",
        "version": "2024",
        "kind": "iot-domotics-security-and-privacy-guidelines",
        "reference": "https://www.iso.org/standard/78702.html",
        "evidence": ["control-assessment.json", "domain-assurance.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2024-06",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "ISO-IEC-27404",
        "version": "2025",
        "kind": "consumer-iot-cybersecurity-labelling-framework",
        "reference": "https://www.iso.org/standard/80138.html",
        "evidence": ["external-conformity-assessment.json", "benchmark-scorecard.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2025-10",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "TIBER-EU",
        "version": "2025",
        "kind": "threat-intelligence-based-ethical-red-teaming",
        "reference": "https://www.ecb.europa.eu/paym/cyber-resilience/tiber-eu/html/index.en.html",
        "evidence": [
            "adversarial-campaign.json",
            "external-conformity-assessment.json",
        ],
        "lifecycle": {
            "edition_status": "final",
            "published": "2025",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "ISO-IEC-27050-1",
        "version": "2019",
        "kind": "electronic-discovery-concepts-and-principles",
        "reference": "https://www.iso.org/standard/78647.html",
        "evidence": ["digital-evidence-analysis.json", "chain-of-custody.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2019",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "ISO-IEC-27050-3",
        "version": "2020",
        "kind": "electronic-discovery-code-of-practice",
        "reference": "https://www.iso.org/standard/78648.html",
        "evidence": ["digital-evidence-analysis.json", "chain-of-custody.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2020",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "ISO-19011",
        "version": "2026",
        "kind": "management-system-audit-program-and-methodology",
        "reference": "https://www.iso.org/standard/88984.html",
        "evidence": ["control-assessment.json", "audit-package-verification.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2026-05",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "ISO-IEC-27007",
        "version": "2020",
        "kind": "isms-audit-guidance",
        "reference": "https://www.iso.org/standard/77802.html",
        "evidence": ["control-assessment.json", "audit-package-verification.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2020-01",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "ISO-IEC-TS-27008",
        "version": "2019",
        "kind": "information-security-control-assessment-guidance",
        "reference": "https://www.iso.org/standard/67397.html",
        "evidence": ["control-assessment.json", "procedure-assessment.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2019-01",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "ISO-IEC-27006-1",
        "version": "2024",
        "kind": "isms-certification-body-requirements",
        "reference": "https://www.iso.org/standard/82908.html",
        "evidence": [
            "external-conformity-assessment.json",
            "audit-package-verification.json",
        ],
        "lifecycle": {
            "edition_status": "final",
            "published": "2024-03",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "ISO-IEC-17021-1",
        "version": "2015-confirmed-2021",
        "kind": "management-system-certification-body-requirements",
        "reference": "https://www.iso.org/standard/61651.html",
        "evidence": [
            "external-conformity-assessment.json",
            "audit-package-verification.json",
        ],
        "lifecycle": {
            "edition_status": "final",
            "published": "2015-06",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "ISO-IEC-17029",
        "version": "2019-confirmed-2025",
        "kind": "validation-and-verification-body-requirements",
        "reference": "https://www.iso.org/standard/29352.html",
        "evidence": [
            "external-conformity-assessment.json",
            "procedure-assessment.json",
        ],
        "lifecycle": {
            "edition_status": "final",
            "published": "2019-10",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "ISO-IEC-19896-1",
        "version": "2025",
        "kind": "security-conformance-personnel-concepts-and-requirements",
        "reference": "https://www.iso.org/standard/84987.html",
        "evidence": ["external-conformity-assessment.json", "benchmark-scorecard.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2025-11",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "ISO-IEC-19896-2",
        "version": "2026",
        "kind": "cryptographic-module-tester-and-validator-competence",
        "reference": "https://www.iso.org/standard/84988.html",
        "evidence": ["external-conformity-assessment.json", "benchmark-scorecard.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2026-01",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "ISO-IEC-19896-3",
        "version": "2025",
        "kind": "common-criteria-evaluator-and-reviewer-competence",
        "reference": "https://www.iso.org/standard/84989.html",
        "evidence": ["external-conformity-assessment.json", "benchmark-scorecard.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2025-11",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "ISO-IEC-27034-2",
        "version": "2015-confirmed-2021",
        "kind": "application-security-organization-normative-framework",
        "reference": "https://www.iso.org/standard/55582.html",
        "evidence": ["security-requirements-coverage.json", "control-assessment.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2015-08",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "ISO-IEC-27034-3",
        "version": "2018-confirmed-2023",
        "kind": "application-security-management-process",
        "reference": "https://www.iso.org/standard/55583.html",
        "evidence": [
            "security-requirements-coverage.json",
            "application-contract-analysis.json",
        ],
        "lifecycle": {
            "edition_status": "final",
            "published": "2018-05",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "ISO-IEC-27034-5",
        "version": "2017-confirmed-2023",
        "kind": "application-security-control-protocols-and-data-structure",
        "reference": "https://www.iso.org/standard/55585.html",
        "evidence": ["application-contract-analysis.json", "control-assessment.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2017-10",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "ISO-IEC-TS-27034-5-1",
        "version": "2018",
        "kind": "application-security-control-xml-schemas",
        "reference": "https://www.iso.org/standard/67741.html",
        "evidence": ["application-contract-analysis.json", "benchmark-scorecard.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2018-04",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "ISO-IEC-27034-6",
        "version": "2016-confirmed-2022",
        "kind": "application-security-case-studies",
        "reference": "https://www.iso.org/standard/60804.html",
        "evidence": [
            "security-requirements-coverage.json",
            "application-contract-analysis.json",
        ],
        "lifecycle": {
            "edition_status": "final",
            "published": "2016-10",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "ISO-IEC-27034-7",
        "version": "2018-confirmed-2023",
        "kind": "application-security-assurance-prediction",
        "reference": "https://www.iso.org/standard/66229.html",
        "evidence": ["security-requirements-coverage.json", "benchmark-scorecard.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2018-05",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "NIST-SP-800-204A",
        "version": "2020-final",
        "kind": "secure-service-mesh-architecture",
        "reference": "https://csrc.nist.gov/pubs/sp/800/204/a/final",
        "evidence": ["static-architecture.json", "runtime-surface-binding.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2020-05",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "NIST-SP-800-192",
        "version": "2017-final",
        "kind": "access-control-policy-and-model-verification",
        "reference": "https://csrc.nist.gov/pubs/sp/800/192/final",
        "evidence": ["security-requirements-coverage.json", "benchmark-scorecard.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2017-06",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "NIST-SP-800-193",
        "version": "2018-final",
        "kind": "platform-firmware-resiliency",
        "reference": "https://csrc.nist.gov/pubs/sp/800/193/final",
        "evidence": ["domain-assurance.json", "security-passport.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2018-05",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "TCG-TPM-2.0",
        "version": "library-v185-2026",
        "kind": "trusted-platform-module-library",
        "reference": "https://trustedcomputinggroup.org/resource/tpm-library-specification/",
        "evidence": [
            "domain-assurance.json",
            "security-passport.json",
            "benchmark-scorecard.json",
        ],
        "lifecycle": {
            "edition_status": "final",
            "published": "2026-03",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "NIST-SP-800-226",
        "version": "2025-final",
        "kind": "differential-privacy-guarantee-evaluation",
        "reference": "https://csrc.nist.gov/pubs/sp/800/226/final",
        "evidence": ["data-exposure.json", "benchmark-scorecard.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2025-03",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "ISO-IEC-25012",
        "version": "2008-confirmed-2025",
        "kind": "data-quality-model",
        "reference": "https://www.iso.org/standard/35736.html",
        "evidence": ["code-health.json", "effectiveness.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2008-12",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "ISO-IEC-25020",
        "version": "2019",
        "kind": "quality-measurement-framework",
        "reference": "https://www.iso.org/standard/72117.html",
        "evidence": ["code-health.json", "benchmark-scorecard.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2019-07",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "ISO-IEC-25024",
        "version": "2015-confirmed-2021",
        "kind": "data-quality-measurement",
        "reference": "https://www.iso.org/standard/35749.html",
        "evidence": [
            "code-health.json",
            "effectiveness.json",
            "benchmark-scorecard.json",
        ],
        "lifecycle": {
            "edition_status": "final",
            "published": "2015-12",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "ISO-IEC-25030",
        "version": "2019",
        "kind": "quality-requirements-framework",
        "reference": "https://www.iso.org/standard/72116.html",
        "evidence": ["security-requirements-coverage.json", "code-health.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2019-07",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "ISO-27799",
        "version": "2025",
        "kind": "health-information-security-controls",
        "reference": "https://www.iso.org/standard/84647.html",
        "evidence": ["domain-assurance.json", "control-assessment.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2025-12",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "ISO-IEC-27019",
        "version": "2024",
        "kind": "energy-utility-information-security-controls",
        "reference": "https://www.iso.org/standard/85056.html",
        "evidence": ["domain-assurance.json", "control-assessment.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2024-10",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "ISO-IEC-27050-2",
        "version": "2018",
        "kind": "electronic-discovery-governance-and-management",
        "reference": "https://www.iso.org/standard/66230.html",
        "evidence": ["digital-evidence-analysis.json", "chain-of-custody.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2018-11",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "ISO-IEC-27050-4",
        "version": "2021",
        "kind": "electronic-discovery-technical-readiness",
        "reference": "https://www.iso.org/standard/74034.html",
        "evidence": ["digital-evidence-analysis.json", "chain-of-custody.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2021-04",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "ISO-IEC-25019",
        "version": "2023",
        "kind": "quality-in-use-model",
        "reference": "https://www.iso.org/standard/78177.html",
        "evidence": ["code-health.json", "effectiveness.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2023-11",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "ISO-IEC-TS-25052-1",
        "version": "2022-confirmed-2026",
        "kind": "cloud-service-quality-model",
        "reference": "https://www.iso.org/standard/81467.html",
        "evidence": ["code-health.json", "domain-assurance.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2022-11",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "ISO-IEC-TS-25052-2",
        "version": "2024",
        "kind": "cloud-service-quality-measurement",
        "reference": "https://www.iso.org/standard/86722.html",
        "evidence": ["effectiveness.json", "benchmark-scorecard.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2024-10",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "ISO-31000",
        "version": "2018-confirmed-2023",
        "kind": "enterprise-risk-management-guidelines",
        "reference": "https://www.iso.org/standard/65694.html",
        "evidence": ["risk-paths.json", "control-assessment.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2018-02",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "IEC-31010",
        "version": "2019",
        "kind": "risk-assessment-techniques",
        "reference": "https://webstore.iec.ch/en/publication/59809",
        "evidence": ["risk-paths.json", "procedure-assessment.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2019-06",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "CISA-SECURE-BY-DESIGN",
        "version": "2023-policy-current",
        "kind": "voluntary-secure-by-design-principles",
        "reference": "https://www.cisa.gov/securebydesign",
        "evidence": ["control-proof.json", "security-requirements-coverage.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2023-04",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "CISA-PRODUCT-SECURITY-BAD-PRACTICES",
        "version": "2025-01",
        "kind": "voluntary-product-security-negative-guidance",
        "reference": "https://www.cisa.gov/news-events/alerts/2025/01/17/cisa-and-fbi-release-updated-guidance-product-security-bad-practices",
        "evidence": ["finding-validation.json", "benchmark-scorecard.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2025-01",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "TCG-DICE-ATTESTATION-ARCHITECTURE",
        "version": "1.2-errata-2026-01",
        "kind": "device-identity-and-attestation-architecture",
        "reference": "https://trustedcomputinggroup.org/resource/dice-attestation-architecture/",
        "evidence": ["security-passport.json", "benchmark-scorecard.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2025-04",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "ISO-IEC-27011",
        "version": "2024",
        "kind": "telecommunications-information-security-controls",
        "reference": "https://www.iso.org/standard/80584.html",
        "evidence": ["domain-assurance.json", "control-assessment.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2024",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "NIST-SP-800-181-R1",
        "version": "2020-final",
        "kind": "cybersecurity-workforce-framework",
        "reference": "https://csrc.nist.gov/pubs/sp/800/181/r1/final",
        "evidence": ["external-conformity-assessment.json", "control-assessment.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2020-11",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "NIST-NICE-FRAMEWORK-COMPONENTS",
        "version": "2.2.0-2025-04",
        "kind": "cybersecurity-workforce-task-knowledge-skill-components",
        "reference": "https://www.nist.gov/itl/applied-cybersecurity/nice/nice-framework-resource-center/nice-framework-current-versions",
        "evidence": ["external-conformity-assessment.json", "benchmark-scorecard.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2025-04",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "AMTSO-TESTING-PROTOCOL",
        "version": "1.3-2019-11",
        "kind": "antimalware-testing-protocol",
        "reference": "https://www.amtso.org/standards/",
        "evidence": ["test-evidence.json", "external-conformity-assessment.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2019-11",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "CREST-PENETRATION-TESTING-GUIDE",
        "version": "2022",
        "kind": "penetration-testing-engagement-guidance",
        "reference": "https://www.crest-approved.org/wp-content/uploads/2023/04/A-Guide-to-Penetration-Testing-2022.pdf",
        "evidence": [
            "adversarial-campaign.json",
            "external-conformity-assessment.json",
        ],
        "lifecycle": {
            "edition_status": "final",
            "published": "2022",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "PTES",
        "version": "policy-pinned-current",
        "kind": "penetration-testing-execution-methodology",
        "reference": "https://www.pentest-standard.org/index.php/Main_Page",
        "evidence": ["adversarial-campaign.json", "procedure-assessment.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2014",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "DORA-SOFTWARE-DELIVERY-PERFORMANCE",
        "version": "five-metrics-2026-policy-current",
        "kind": "research-backed-software-delivery-outcome-benchmark",
        "reference": "https://dora.dev/guides/dora-metrics/",
        "evidence": ["operational-trend.json", "benchmark-scorecard.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2026",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "IETF-RFC-8446",
        "version": "2018",
        "kind": "tls-1.3-protocol",
        "reference": "https://www.rfc-editor.org/rfc/rfc8446",
        "evidence": ["domain-assurance.json", "benchmark-scorecard.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2018-08",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "IETF-RFC-8996",
        "version": "2021",
        "kind": "tls-1.3-operational-profile",
        "reference": "https://www.rfc-editor.org/rfc/rfc8996",
        "evidence": ["domain-assurance.json", "control-assessment.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2021-03",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "REPRODUCIBLE-BUILDS-TEST-PROTOCOL",
        "version": "policy-pinned-current",
        "kind": "controlled-build-environment-variation-guidance",
        "reference": "https://reproducible-builds.org/docs/plans/",
        "evidence": ["release-readiness.json", "benchmark-scorecard.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2026-08",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "ISO-IEC-IEEE-15026-2",
        "version": "2022",
        "kind": "systems-and-software-assurance-case-structure",
        "reference": "https://www.iso.org/standard/80625.html",
        "evidence": ["assurance-case-assessment.json", "benchmark-scorecard.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2022-11",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "ISO-IEC-IEEE-15026-4",
        "version": "2021",
        "kind": "systems-and-software-lifecycle-assurance",
        "reference": "https://www.iso.org/standard/74396.html",
        "evidence": ["assurance-case-assessment.json", "lifecycle-traceability.json"],
        "lifecycle": {
            "edition_status": "final-under-review",
            "published": "2021-10",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "OMG-SACM",
        "version": "2.3",
        "kind": "machine-readable-structured-assurance-case-metamodel",
        "reference": "https://www.omg.org/spec/SACM/2.3",
        "evidence": ["assurance-case-assessment.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2023-10",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "IEEE-1012",
        "version": "2024",
        "kind": "integrity-level-system-software-and-hardware-verification-validation",
        "reference": "https://standards.ieee.org/ieee/1012/12536/",
        "evidence": ["lifecycle-traceability.json", "benchmark-scorecard.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2024-12",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "ISO-IEC-19790",
        "version": "2025",
        "kind": "cryptographic-module-security-requirements",
        "reference": "https://www.iso.org/standard/82423.html",
        "evidence": ["external-conformity-assessment.json", "benchmark-scorecard.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2025-02",
            "observed_at": "2026-08-28",
            "supersedes": ["ISO-IEC-19790-2012"],
        },
    },
    {
        "id": "ISO-IEC-24759",
        "version": "2025",
        "kind": "cryptographic-module-test-methods-and-vendor-evidence",
        "reference": "https://www.iso.org/standard/82424.html",
        "evidence": ["external-conformity-assessment.json", "benchmark-scorecard.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2025-02",
            "observed_at": "2026-08-28",
            "supersedes": ["ISO-IEC-24759-2017"],
        },
    },
    {
        "id": "ISO-IEC-17825",
        "version": "2024",
        "kind": "non-invasive-cryptographic-attack-mitigation-testing",
        "reference": "https://www.iso.org/standard/82422.html",
        "evidence": ["external-conformity-assessment.json", "benchmark-scorecard.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2024-12",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "ISO-IEC-20085-1",
        "version": "2019",
        "kind": "cryptographic-module-side-channel-test-tools",
        "reference": "https://www.iso.org/standard/70081.html",
        "evidence": ["external-conformity-assessment.json", "benchmark-scorecard.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2019-09",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "ISO-IEC-20085-2",
        "version": "2020",
        "kind": "cryptographic-module-side-channel-test-calibration",
        "reference": "https://www.iso.org/standard/70082.html",
        "evidence": ["external-conformity-assessment.json", "benchmark-scorecard.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2020-03",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "ISO-IEC-19795-1",
        "version": "2021",
        "kind": "biometric-performance-testing-principles-and-framework",
        "reference": "https://www.iso.org/standard/73515.html",
        "evidence": ["benchmark-scorecard.json", "external-conformity-assessment.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2021-08",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "ISO-IEC-30107-3",
        "version": "2023",
        "kind": "biometric-presentation-attack-detection-testing-reporting",
        "reference": "https://www.iso.org/standard/79520.html",
        "evidence": ["benchmark-scorecard.json", "external-conformity-assessment.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2023-11",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "ISO-IEC-30107-4",
        "version": "2024",
        "kind": "mobile-device-biometric-presentation-attack-detection-profile",
        "reference": "https://www.iso.org/standard/82584.html",
        "evidence": ["benchmark-scorecard.json", "external-conformity-assessment.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2024-11",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "ISO-IEC-20000-1",
        "version": "2018-amendment-1-2024",
        "kind": "service-management-system-requirements",
        "reference": "https://www.iso.org/standard/70636.html",
        "evidence": ["operational-trend.json", "benchmark-scorecard.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2018+A1:24",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "ISO-IEC-27013",
        "version": "2021-amendment-1-2024",
        "kind": "integrated-information-security-and-service-management-guidance",
        "reference": "https://www.iso.org/standard/78752.html",
        "evidence": ["control-assessment.json", "operational-trend.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2021+A1:24",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "ISO-IEC-17043",
        "version": "2023",
        "kind": "proficiency-testing-provider-competence-and-impartiality",
        "reference": "https://www.iso.org/standard/80864.html",
        "evidence": ["external-conformity-assessment.json", "benchmark-scorecard.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2023-05",
            "observed_at": "2026-08-28",
        },
    },
)

_STANDARDS += (
    {
        "id": "NIST-CMVP",
        "version": "fips-140-3-scheme-policy-pinned-current",
        "kind": "cryptographic-module-validation-program-scheme",
        "reference": "https://csrc.nist.gov/Projects/cryptographic-module-validation-program",
        "evidence": ["external-conformity-assessment.json", "benchmark-scorecard.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2026-07",
            "observed_at": "2026-08-28",
        },
    },
)

_STANDARDS += (
    {
        "id": "ISO-IEC-IEEE-24748-1",
        "version": "2024",
        "kind": "systems-software-lifecycle-management",
        "reference": "https://www.iso.org/standard/84709.html",
        "evidence": [
            "lifecycle-traceability.json",
            "process-capability-assessment.json",
        ],
        "lifecycle": {
            "edition_status": "final",
            "published": "2024-05",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "ISO-IEC-IEEE-15289",
        "version": "2019-confirmed-2025",
        "kind": "lifecycle-information-items",
        "reference": "https://www.iso.org/standard/74909.html",
        "evidence": ["lifecycle-traceability.json", "audit-package-verification.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2019-05",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "ISO-IEC-IEEE-16085",
        "version": "2021",
        "kind": "lifecycle-risk-management",
        "reference": "https://www.iso.org/standard/74371.html",
        "evidence": ["risk-paths.json", "lifecycle-traceability.json"],
        "lifecycle": {
            "edition_status": "final-under-review",
            "published": "2021-03",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "ISO-IEC-IEEE-90003",
        "version": "2018-confirmed-2025",
        "kind": "software-quality-management-guidance",
        "reference": "https://www.iso.org/standard/74348.html",
        "evidence": ["process-capability-assessment.json", "code-health.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2018-11",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "ISO-IEC-25002",
        "version": "2024",
        "kind": "square-quality-model-overview-and-usage",
        "reference": "https://www.iso.org/standard/78175.html",
        "evidence": ["code-health.json", "security-requirements-coverage.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2024-05",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "ISO-IEC-25021",
        "version": "2012",
        "kind": "quality-measure-elements",
        "reference": "https://www.iso.org/standard/55477.html",
        "evidence": ["code-health.json", "effectiveness.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2012-10",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "ISO-IEC-25022",
        "version": "2016",
        "kind": "quality-in-use-measurement",
        "reference": "https://www.iso.org/standard/35746.html",
        "evidence": ["effectiveness.json", "benchmark-scorecard.json"],
        "lifecycle": {
            "edition_status": "final-under-review",
            "published": "2016-06",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "ISO-IEC-25051",
        "version": "2014-confirmed-2024",
        "kind": "ready-to-use-software-quality-and-testing",
        "reference": "https://www.iso.org/standard/61579.html",
        "evidence": ["security-requirements-coverage.json", "test-evidence.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2014-02",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "NIST-SP-800-30",
        "version": "revision-1-2012",
        "kind": "information-security-risk-assessment",
        "reference": "https://csrc.nist.gov/pubs/sp/800/30/r1/final",
        "evidence": ["risk-paths.json", "control-assessment.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2012-09",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "NIST-SP-800-39",
        "version": "2011",
        "kind": "organization-mission-system-risk-management",
        "reference": "https://csrc.nist.gov/pubs/sp/800/39/final",
        "evidence": ["risk-paths.json", "domain-assurance.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2011-03",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "ISO-IEC-29151",
        "version": "2026",
        "kind": "personally-identifiable-information-protection-controls",
        "reference": "https://www.iso.org/standard/88151.html",
        "evidence": ["data-exposure.json", "control-assessment.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2026-07",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "ISO-IEC-27557",
        "version": "2022",
        "kind": "organizational-privacy-risk-management",
        "reference": "https://www.iso.org/standard/71675.html",
        "evidence": ["data-exposure.json", "risk-paths.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2022-11",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "ISO-IEC-TR-27550",
        "version": "2019",
        "kind": "privacy-engineering-system-lifecycle",
        "reference": "https://www.iso.org/standard/72024.html",
        "evidence": ["data-exposure.json", "lifecycle-traceability.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2019-09",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "ISO-IEC-38505-1",
        "version": "2026",
        "kind": "governance-of-data",
        "reference": "https://www.iso.org/standard/87195.html",
        "evidence": ["data-exposure.json", "domain-assurance.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2026-08",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "ISO-IEC-22989",
        "version": "2022",
        "kind": "artificial-intelligence-concepts-and-terminology",
        "reference": "https://www.iso.org/standard/74296.html",
        "evidence": ["domain-assurance.json", "llm-adversarial-plan.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2022-07",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "ISO-IEC-23053",
        "version": "2022",
        "kind": "machine-learning-system-framework",
        "reference": "https://www.iso.org/standard/74438.html",
        "evidence": ["static-architecture.json", "lifecycle-traceability.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2022-06",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "ISO-IEC-38507",
        "version": "2022",
        "kind": "governance-implications-of-ai",
        "reference": "https://www.iso.org/standard/56641.html",
        "evidence": ["domain-assurance.json", "control-assessment.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2022-04",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "ISO-22340",
        "version": "2024",
        "kind": "enterprise-protective-security-architecture",
        "reference": "https://www.iso.org/standard/85607.html",
        "evidence": ["architecture-evaluation.json", "risk-paths.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2024-06",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "OWASP-CODE-REVIEW-GUIDE",
        "version": "2.0-policy-pinned",
        "kind": "secure-code-review-methodology",
        "reference": "https://owasp.org/www-project-code-review-guide/",
        "evidence": ["finding-validation.json", "procedure-assessment.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2017",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "OWASP-CORNUCOPIA",
        "version": "2026-companion-edition-policy-pinned",
        "kind": "threat-modeling-security-requirements-scenarios",
        "reference": "https://cornucopia.owasp.org/",
        "evidence": [
            "threat-model-assessment.json",
            "security-requirements-coverage.json",
        ],
        "lifecycle": {
            "edition_status": "final",
            "published": "2026-05",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "CIS-SAFECODE-SECURE-BY-DESIGN",
        "version": "1.1-2026",
        "kind": "secure-by-design-practice-assessment",
        "reference": "https://safecode.org/press-releases/cis-and-safecode-release-secure-by-design-v1.1-a-guide-to-assessing-software-security-practices/",
        "evidence": ["process-capability-assessment.json", "control-proof.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2026-07",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "NIST-IR-8286",
        "version": "revision-1-2025",
        "kind": "cybersecurity-enterprise-risk-integration",
        "reference": "https://csrc.nist.gov/pubs/ir/8286/r1/final",
        "evidence": ["risk-paths.json", "domain-assurance.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2025-12",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "NIST-IR-8286A",
        "version": "revision-1-2025",
        "kind": "cybersecurity-risk-identification-and-estimation",
        "reference": "https://csrc.nist.gov/pubs/ir/8286/a/r1/final",
        "evidence": ["risk-paths.json", "control-assessment.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2025-12",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "NIST-IR-8286B",
        "version": "update-1-2025",
        "kind": "cybersecurity-risk-prioritization-and-response",
        "reference": "https://csrc.nist.gov/pubs/ir/8286/b/upd1/final",
        "evidence": ["risk-paths.json", "standardized-prioritization.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2025-12",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "NIST-IR-8286C",
        "version": "revision-1-2025",
        "kind": "cybersecurity-risk-staging-and-governance-oversight",
        "reference": "https://csrc.nist.gov/pubs/ir/8286/c/r1/final",
        "evidence": ["risk-paths.json", "audit-package-verification.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2025-12",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "NIST-IR-8286D",
        "version": "update-1-2025",
        "kind": "business-impact-informed-cybersecurity-risk",
        "reference": "https://csrc.nist.gov/pubs/ir/8286/d/upd1/final",
        "evidence": ["risk-paths.json", "operational-trend.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2025-12",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "CIS-RAM",
        "version": "2.2-policy-pinned",
        "kind": "cis-controls-risk-assessment-method",
        "reference": "https://learn.cisecurity.org/cis-ram-v2-2",
        "evidence": ["risk-paths.json", "control-assessment.json"],
        "lifecycle": {
            "edition_status": "policy-pinned",
            "published": "v2.2-pin",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "ISO-IEC-25001",
        "version": "2014-confirmed-2026",
        "kind": "square-planning-and-management",
        "reference": "https://www.iso.org/standard/64787.html",
        "evidence": [
            "process-capability-assessment.json",
            "benchmark-scorecard.json",
        ],
        "lifecycle": {
            "edition_status": "final",
            "published": "2026-01",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "ISO-IEC-TR-42106",
        "version": "2026",
        "kind": "differentiated-ai-quality-benchmarking",
        "reference": "https://www.iso.org/standard/86903.html",
        "evidence": ["benchmark-scorecard.json", "effectiveness.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2026-07",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "ISO-IEC-8183",
        "version": "2023",
        "kind": "artificial-intelligence-data-life-cycle-framework",
        "reference": "https://www.iso.org/standard/83002.html",
        "evidence": ["lifecycle-traceability.json", "data-exposure.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2023-07",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "ISO-IEC-12792",
        "version": "2025",
        "kind": "artificial-intelligence-transparency-taxonomy",
        "reference": "https://www.iso.org/standard/84111.html",
        "evidence": ["domain-assurance.json", "audit-package-verification.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2025-11",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "ISO-IEC-TS-6254",
        "version": "2025",
        "kind": "artificial-intelligence-explainability-and-interpretability",
        "reference": "https://www.iso.org/committee/6794475/x/catalogue/p/0/u/1/w/0/d/0",
        "evidence": ["effectiveness.json", "domain-assurance.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2025",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "ISO-IEC-TS-8200",
        "version": "2024",
        "kind": "automated-artificial-intelligence-system-controllability",
        "reference": "https://www.iso.org/standard/83012.html",
        "evidence": ["architecture-evaluation.json", "llm-adversarial-plan.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2024-04",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "ISO-IEC-TS-12791",
        "version": "2024",
        "kind": "machine-learning-unwanted-bias-treatment",
        "reference": "https://www.iso.org/committee/6794475/x/catalogue/p/0/u/1/w/0/d/0",
        "evidence": ["effectiveness.json", "data-exposure.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2024",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "ISO-IEC-TR-5469",
        "version": "2024",
        "kind": "artificial-intelligence-functional-safety",
        "reference": "https://www.iso.org/committee/6794475/x/catalogue/p/0/u/1/w/0/d/0",
        "evidence": ["safety-security-analysis.json", "lifecycle-traceability.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2024",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "COBIT-2019",
        "version": "2019-licensed-policy-pinned",
        "kind": "licensed-enterprise-information-technology-governance",
        "reference": "https://www.isaca.org/resources/cobit",
        "evidence": ["domain-assurance.json", "process-capability-assessment.json"],
        "lifecycle": {
            "edition_status": "policy-pinned",
            "published": "2019",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "TOGAF-STANDARD",
        "version": "10th-edition-tc1-licensed-policy-pinned",
        "kind": "licensed-enterprise-architecture-governance",
        "reference": "https://publications.opengroup.org/standards/togaf",
        "evidence": ["architecture-evaluation.json", "domain-assurance.json"],
        "lifecycle": {
            "edition_status": "policy-pinned",
            "published": "10th-TC1",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "ARCHIMATE",
        "version": "3.2-licensed-policy-pinned",
        "kind": "licensed-enterprise-architecture-modeling-language",
        "reference": "https://www.opengroup.org/archimate-licensed-downloads",
        "evidence": ["static-architecture.json", "architecture-evaluation.json"],
        "lifecycle": {
            "edition_status": "policy-pinned",
            "published": "v3.2-pin",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "OPEN-FAIR",
        "version": "2.0-licensed-policy-pinned",
        "kind": "licensed-quantitative-information-risk-analysis",
        "reference": "https://publications.opengroup.org/standards/open-fair",
        "evidence": ["risk-paths.json", "benchmark-scorecard.json"],
        "lifecycle": {
            "edition_status": "policy-pinned",
            "published": "v2.0-pin",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "OWASP-AISVS",
        "version": "1.0",
        "kind": "artificial-intelligence-security-verification",
        "reference": "https://owasp.org/www-project-artificial-intelligence-security-verification-standard-aisvs-docs/",
        "evidence": [
            "security-requirements-coverage.json",
            "llm-adversarial-plan.json",
        ],
        "lifecycle": {
            "edition_status": "final",
            "published": "2026-06",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "ISO-IEC-TS-25058",
        "version": "2024",
        "kind": "artificial-intelligence-system-quality-evaluation-guidance",
        "reference": "https://www.iso.org/standard/82570.html",
        "evidence": ["effectiveness.json", "benchmark-scorecard.json"],
        "lifecycle": {
            "edition_status": "final-under-review",
            "published": "2024-01",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "EU-EUCC",
        "version": "2024-482-amended-2025",
        "kind": "european-common-criteria-cybersecurity-certification-scheme",
        "reference": "https://certification.enisa.europa.eu/certification-library/eucc-certification-scheme_en",
        "evidence": [
            "external-conformity-assessment.json",
            "audit-package-verification.json",
        ],
        "lifecycle": {
            "edition_status": "final",
            "published": "2025-12",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "CISA-SECURE-SOFTWARE-ATTESTATION",
        "version": "common-form-policy-pinned",
        "kind": "federal-secure-software-development-producer-attestation",
        "reference": "https://www.cisa.gov/resources-tools/resources/secure-software-development-attestation-form",
        "evidence": [
            "release-evidence-manifest.json",
            "audit-package-verification.json",
        ],
        "lifecycle": {
            "edition_status": "policy-pinned",
            "published": "2024-pin",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "IEEE-7000",
        "version": "2021",
        "kind": "ethical-concerns-system-design-process",
        "reference": "https://standards.ieee.org/ieee/7000/6781/",
        "evidence": ["lifecycle-traceability.json", "domain-assurance.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2021",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "IEEE-7001",
        "version": "2021",
        "kind": "autonomous-system-transparency",
        "reference": "https://standards.ieee.org/ieee/7001/6929/",
        "evidence": ["domain-assurance.json", "effectiveness.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2021",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "IEEE-7002",
        "version": "2022",
        "kind": "data-privacy-engineering-process",
        "reference": "https://standards.ieee.org/ieee/7002/6898/",
        "evidence": ["data-exposure.json", "lifecycle-traceability.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2022",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "IEEE-7003",
        "version": "2024",
        "kind": "algorithmic-bias-considerations",
        "reference": "https://standards.ieee.org/ieee/7003/11357/",
        "evidence": ["effectiveness.json", "data-exposure.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2025-01",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "IEEE-7009",
        "version": "2024",
        "kind": "autonomous-system-fail-safe-design",
        "reference": "https://standards.ieee.org/initiatives/autonomous-intelligence-systems/standards/",
        "evidence": ["safety-security-analysis.json", "architecture-evaluation.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2024",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "ISO-IEC-TR-27563",
        "version": "2023",
        "kind": "artificial-intelligence-use-case-security-and-privacy",
        "reference": "https://www.iso.org/standard/80396.html",
        "evidence": ["threat-model-assessment.json", "data-exposure.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2023-05",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "ISO-IEC-TR-24030",
        "version": "2024",
        "kind": "artificial-intelligence-domain-use-case-catalog",
        "reference": "https://www.iso.org/standard/84144.html",
        "evidence": ["domain-assurance.json", "threat-model-assessment.json"],
        "lifecycle": {
            "edition_status": "final-under-review",
            "published": "2024-04",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "ISO-IEC-38500",
        "version": "2024",
        "kind": "organizational-governance-of-information-technology",
        "reference": "https://www.iso.org/standard/81684.html",
        "evidence": ["domain-assurance.json", "architecture-evaluation.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2024-02",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "ISO-9001",
        "version": "2026",
        "kind": "quality-management-system-requirements",
        "reference": "https://www.iso.org/9001-2026",
        "evidence": [
            "process-capability-assessment.json",
            "audit-package-verification.json",
        ],
        "lifecycle": {
            "edition_status": "final",
            "published": "2026",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "NIST-SP-1301",
        "version": "2024",
        "kind": "cybersecurity-framework-organizational-profile-lifecycle",
        "reference": "https://csrc.nist.gov/pubs/sp/1301/final",
        "evidence": ["domain-assurance.json", "closure-plan.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2024-02",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "ISO-IEC-27000",
        "version": "2026",
        "kind": "information-security-management-system-concepts-and-relationships",
        "reference": "https://www.iso.org/standard/27000",
        "evidence": ["control-assessment.json", "domain-assurance.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2026-07",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "ISO-IEC-27561",
        "version": "2024",
        "kind": "privacy-operationalisation-model-and-engineering-method",
        "reference": "https://www.iso.org/committee/45306/x/catalogue/p/1/u/0/w/0/d/0.html",
        "evidence": ["data-exposure.json", "lifecycle-traceability.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2024",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "ISO-IEC-TS-27564",
        "version": "2025",
        "kind": "privacy-engineering-model-guidance",
        "reference": "https://www.iso.org/committee/45306/x/catalogue/p/1/u/0/w/0/d/0.html",
        "evidence": ["data-exposure.json", "architecture-evaluation.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2025",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "ISO-IEC-27565",
        "version": "2026",
        "kind": "zero-knowledge-proof-privacy-preservation-guidance",
        "reference": "https://www.iso.org/committee/45306/x/catalogue/p/1/u/0/w/0/d/0.html",
        "evidence": ["control-proof.json", "benchmark-scorecard.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2026",
            "observed_at": "2026-08-28",
        },
    },
)

_STANDARDS += (
    {
        "id": "MCP-SPECIFICATION",
        "version": "2025-11-25",
        "kind": "model-context-protocol-interoperability-and-security",
        "reference": "https://modelcontextprotocol.io/specification/2025-11-25/",
        "evidence": ["security-automation-interoperability.json", "control-proof.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2025-11-25",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "OWASP-MCP-SECURITY-CHEAT-SHEET",
        "version": "policy-pinned-2026-08-28",
        "kind": "model-context-protocol-security-guidance",
        "reference": "https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html",
        "evidence": [
            "threat-model-assessment.json",
            "security-automation-interoperability.json",
        ],
        "lifecycle": {
            "edition_status": "policy-pinned",
            "published": "2026",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "AWS-FOUNDATIONAL-SECURITY-BEST-PRACTICES",
        "version": "1.0-continuous-2026-08-28",
        "kind": "aws-native-cloud-security-posture-baseline",
        "reference": "https://docs.aws.amazon.com/securityhub/latest/userguide/fsbp-standard.html",
        "evidence": ["control-assessment.json", "cloud-attack-paths.json"],
        "lifecycle": {
            "edition_status": "policy-pinned",
            "published": "2020",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "MICROSOFT-CLOUD-SECURITY-BENCHMARK",
        "version": "v1-observed-2026-08-28",
        "kind": "microsoft-native-multicloud-security-baseline",
        "reference": "https://learn.microsoft.com/en-us/security/benchmark/azure/overview-mcsb-v1",
        "evidence": ["control-assessment.json", "cloud-attack-paths.json"],
        "lifecycle": {
            "edition_status": "policy-pinned",
            "published": "2022-10",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "GCP-ENTERPRISE-FOUNDATIONS-BLUEPRINT",
        "version": "reviewed-2025-05-15",
        "kind": "google-cloud-enterprise-foundation-security-baseline",
        "reference": "https://docs.cloud.google.com/architecture/blueprints/security-foundations",
        "evidence": ["architecture-evaluation.json", "cloud-attack-paths.json"],
        "lifecycle": {
            "edition_status": "policy-pinned",
            "published": "2025-05-15",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "FIRST-CSIRT-SERVICES-FRAMEWORK",
        "version": "2.1",
        "kind": "computer-security-incident-response-service-framework",
        "reference": "https://www.first.org/standards/frameworks/csirts/csirt_services_framework_v2-1",
        "evidence": [
            "maturity-model-assessment.json",
            "process-capability-assessment.json",
        ],
        "lifecycle": {
            "edition_status": "policy-pinned",
            "published": "2024",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "FIRST-PSIRT-SERVICES-FRAMEWORK",
        "version": "1.1",
        "kind": "product-security-incident-response-service-framework",
        "reference": "https://www.first.org/standards/frameworks/psirts/psirt_services_framework_v1-1",
        "evidence": ["maturity-model-assessment.json", "finding-validation.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2020",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "FIRST-PSIRT-MATURITY",
        "version": "policy-pinned-2026-08-28",
        "kind": "product-security-incident-response-operational-maturity",
        "reference": "https://www.first.org/standards/frameworks/psirts/psirt_maturity_document",
        "evidence": ["maturity-model-assessment.json", "operational-trend.json"],
        "lifecycle": {
            "edition_status": "policy-pinned",
            "published": "2019",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "CISA-MEMORY-SAFE-ROADMAPS",
        "version": "2023-with-2025-buffer-overflow-guidance",
        "kind": "memory-safety-transition-and-product-engineering-guidance",
        "reference": "https://www.cisa.gov/resources-tools/resources/case-memory-safe-roadmaps",
        "evidence": ["code-health.json", "closure-plan.json"],
        "lifecycle": {
            "edition_status": "policy-pinned",
            "published": "2023-12-06",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "IEEE-2863",
        "version": "2026",
        "kind": "organizational-governance-of-artificial-intelligence",
        "reference": "https://standards.ieee.org/ieee/2863/10142/",
        "evidence": ["domain-assurance.json", "lifecycle-traceability.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2026-06-04",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "IEEE-7010",
        "version": "2020",
        "kind": "ai-human-wellbeing-impact-assessment",
        "reference": "https://standards.ieee.org/ieee/7010/7718/",
        "evidence": ["effectiveness.json", "domain-assurance.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2020-05-01",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "ISO-22316",
        "version": "2017",
        "kind": "organizational-resilience-principles-and-attributes",
        "reference": "https://www.iso.org/standard/50053.html",
        "evidence": ["maturity-model-assessment.json", "architecture-evaluation.json"],
        "lifecycle": {
            "edition_status": "final-under-review",
            "published": "2017-03",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "ISO-TS-22317",
        "version": "2021",
        "kind": "business-impact-analysis-guidance",
        "reference": "https://www.iso.org/standard/79000.html",
        "evidence": ["architecture-evaluation.json", "lifecycle-traceability.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2021-11",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "OPENSSF-BEST-PRACTICES-BADGE",
        "version": "criteria-observed-2026-08-28",
        "kind": "open-source-project-security-and-quality-self-certification",
        "reference": "https://openssf.org/projects/best-practices-badge/",
        "evidence": ["control-assessment.json", "audit-package-verification.json"],
        "lifecycle": {
            "edition_status": "policy-pinned",
            "published": "2021",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "ISO-IEC-27003",
        "version": "2017",
        "kind": "information-security-management-system-implementation-guidance",
        "reference": "https://www.iso.org/standard/63417.html",
        "evidence": ["process-capability-assessment.json", "control-assessment.json"],
        "lifecycle": {
            "edition_status": "final-under-review",
            "published": "2017-03",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "ISO-IEC-TS-27022",
        "version": "2021",
        "kind": "information-security-management-system-process-reference-model",
        "reference": "https://www.iso.org/standard/61004.html",
        "evidence": [
            "process-capability-assessment.json",
            "maturity-model-assessment.json",
        ],
        "lifecycle": {
            "edition_status": "final-under-review",
            "published": "2021-03",
            "observed_at": "2026-08-28",
        },
    },
)

_STANDARDS += (
    {
        "id": "A2A-PROTOCOL",
        "version": "1.0.0",
        "kind": "agent-to-agent-interoperability-and-security",
        "reference": "https://a2a-protocol.org/latest/specification/",
        "evidence": [
            "security-automation-interoperability.json",
            "threat-model-assessment.json",
        ],
        "lifecycle": {
            "edition_status": "final",
            "published": "2026-03-12",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "GLOBALPLATFORM-SESIP",
        "version": "1.2",
        "kind": "iot-platform-security-evaluation-methodology",
        "reference": "https://globalplatform.org/specs-library/sesip-methodology/",
        "evidence": ["control-assessment.json", "audit-package-verification.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2023-07",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "EN-17927",
        "version": "2023",
        "kind": "european-security-evaluation-standard-for-iot-platforms",
        "reference": "https://globalplatform.org/sesip/",
        "evidence": ["control-assessment.json", "audit-package-verification.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2023-11",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "FIRST-TLP",
        "version": "2.0",
        "kind": "cybersecurity-information-sharing-boundary-labels",
        "reference": "https://www.first.org/tlp/",
        "evidence": [
            "security-automation-interoperability.json",
            "audit-package-verification.json",
        ],
        "lifecycle": {
            "edition_status": "final",
            "published": "2022-08",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "FIRST-IEP",
        "version": "2.0",
        "kind": "machine-readable-cybersecurity-information-exchange-policy",
        "reference": "https://www.first.org/iep/",
        "evidence": [
            "security-automation-interoperability.json",
            "control-proof.json",
        ],
        "lifecycle": {
            "edition_status": "final",
            "published": "2019-11-06",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "VERIS",
        "version": "1.3.6-policy-pinned",
        "kind": "incident-description-and-classification-schema",
        "reference": "https://verisframework.org/",
        "evidence": [
            "security-automation-interoperability.json",
            "operational-trend.json",
        ],
        "lifecycle": {
            "edition_status": "policy-pinned",
            "published": "2025",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "W3C-CSP-LEVEL-2",
        "version": "2016",
        "kind": "web-content-execution-and-resource-policy",
        "reference": "https://www.w3.org/TR/CSP2/",
        "evidence": ["test-evidence.json", "finding-validation.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2016-12-15",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "W3C-SUBRESOURCE-INTEGRITY",
        "version": "1.0-2016",
        "kind": "web-subresource-cryptographic-integrity",
        "reference": "https://www.w3.org/TR/2016/REC-SRI-20160623/",
        "evidence": ["test-evidence.json", "software-supply-chain.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2016-06-23",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "EU-DORA-RTS-ICT-RISK",
        "version": "EU-2024-1774",
        "kind": "financial-sector-ict-risk-management-technical-standard",
        "reference": "https://eur-lex.europa.eu/eli/reg_del/2024/1774/oj",
        "evidence": ["control-assessment.json", "architecture-evaluation.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2024-06-25",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "EU-DORA-RTS-INCIDENT-CLASSIFICATION",
        "version": "EU-2024-1772",
        "kind": "financial-sector-ict-incident-classification-technical-standard",
        "reference": "https://eur-lex.europa.eu/eli/reg_del/2024/1772/oj",
        "evidence": ["operational-trend.json", "control-assessment.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2024-06-25",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "EU-DORA-ITS-REGISTER-OF-INFORMATION",
        "version": "EU-2024-2956",
        "kind": "financial-sector-ict-third-party-register-templates",
        "reference": "https://eur-lex.europa.eu/eli/reg_impl/2024/2956/oj",
        "evidence": ["supply-chain-risk.json", "control-assessment.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2024-12-02",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "EU-DORA-RTS-INCIDENT-REPORTING",
        "version": "EU-2025-301",
        "kind": "financial-sector-major-ict-incident-content-and-timelines",
        "reference": "https://eur-lex.europa.eu/eli/reg_del/2025/301/oj",
        "evidence": ["operational-trend.json", "audit-package-verification.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2025-02-20",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "EU-DORA-ITS-INCIDENT-REPORTING",
        "version": "EU-2025-302",
        "kind": "financial-sector-major-ict-incident-forms-and-procedures",
        "reference": "https://eur-lex.europa.eu/eli/reg_impl/2025/302/oj",
        "evidence": [
            "security-automation-interoperability.json",
            "operational-trend.json",
        ],
        "lifecycle": {
            "edition_status": "final",
            "published": "2025-02-20",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "EU-DORA-RTS-TLPT",
        "version": "EU-2025-1190",
        "kind": "financial-sector-threat-led-penetration-testing-technical-standard",
        "reference": "https://eur-lex.europa.eu/eli/reg_del/2025/1190/oj",
        "evidence": ["test-evidence.json", "audit-package-verification.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2025-06-18",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "FFIEC-IT-HANDBOOK-DAM",
        "version": "2024",
        "kind": "us-financial-development-acquisition-and-maintenance-examination",
        "reference": "https://www.federalreserve.gov/supervisionreg/srletters/SR2406.htm",
        "evidence": [
            "process-capability-assessment.json",
            "lifecycle-traceability.json",
        ],
        "lifecycle": {
            "edition_status": "final",
            "published": "2024-08-29",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "FFIEC-IT-HANDBOOK-AIO",
        "version": "2021",
        "kind": "us-financial-architecture-infrastructure-operations-examination",
        "reference": "https://www.ffiec.gov/news/press-releases/2021/pr-06-30",
        "evidence": ["architecture-evaluation.json", "control-assessment.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2021-06-30",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "FFIEC-IT-HANDBOOK-INFORMATION-SECURITY",
        "version": "2016",
        "kind": "us-financial-information-security-examination",
        "reference": "https://www.ffiec.gov/news/press-releases/2016/pr-09-09",
        "evidence": ["control-assessment.json", "operational-trend.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2016-09-09",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "BSI-C5",
        "version": "2020",
        "kind": "cloud-computing-compliance-criteria-catalogue",
        "reference": "https://www.bsi.bund.de/dok/C5",
        "evidence": ["control-assessment.json", "audit-package-verification.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2020",
            "observed_at": "2026-08-28",
        },
    },
    {
        "id": "FCC-CYBER-TRUST-MARK",
        "version": "FCC-24-26",
        "kind": "us-consumer-iot-cybersecurity-labeling-program",
        "reference": "https://docs.fcc.gov/public/attachments/FCC-24-26A1.pdf",
        "evidence": ["control-assessment.json", "audit-package-verification.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2024-03-15",
            "observed_at": "2026-08-28",
        },
    },
)

_STANDARDS += (
    {
        "id": "W3C-VC-DATA-MODEL",
        "version": "2.0-2025",
        "kind": "verifiable-credential-data-model",
        "reference": "https://www.w3.org/TR/vc-data-model-2.0/",
        "evidence": ["security-automation-interoperability.json", "control-proof.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2025-05-15",
            "observed_at": "2026-08-29",
        },
    },
    {
        "id": "W3C-VC-DATA-INTEGRITY",
        "version": "1.0-2025",
        "kind": "verifiable-credential-cryptographic-integrity",
        "reference": "https://www.w3.org/TR/vc-data-integrity/",
        "evidence": [
            "security-automation-interoperability.json",
            "trust-policy-attestation.json",
        ],
        "lifecycle": {
            "edition_status": "final",
            "published": "2025-05-15",
            "observed_at": "2026-08-29",
        },
    },
    {
        "id": "W3C-BITSTRING-STATUS-LIST",
        "version": "1.0-2025",
        "kind": "privacy-preserving-verifiable-credential-status",
        "reference": "https://www.w3.org/TR/vc-bitstring-status-list/",
        "evidence": ["security-automation-interoperability.json", "data-exposure.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2025-05-15",
            "observed_at": "2026-08-29",
        },
    },
    {
        "id": "OIDF-OPENID4VP",
        "version": "1.0-final-2025",
        "kind": "verifiable-credential-presentation-protocol",
        "reference": "https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html",
        "evidence": [
            "security-automation-interoperability.json",
            "application-contract-analysis.json",
        ],
        "lifecycle": {
            "edition_status": "final",
            "published": "2025-07-09",
            "observed_at": "2026-08-29",
        },
    },
    {
        "id": "OIDF-OPENID4VCI",
        "version": "1.0-final-2025",
        "kind": "verifiable-credential-issuance-protocol",
        "reference": "https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-final.html",
        "evidence": [
            "security-automation-interoperability.json",
            "application-contract-analysis.json",
        ],
        "lifecycle": {
            "edition_status": "final",
            "published": "2025",
            "observed_at": "2026-08-29",
        },
    },
    {
        "id": "OIDF-OPENID4VC-HAIP",
        "version": "1.0-final-2025",
        "kind": "high-assurance-digital-credential-interoperability-profile",
        "reference": "https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0-final.html",
        "evidence": [
            "security-automation-interoperability.json",
            "procedure-assessment.json",
        ],
        "lifecycle": {
            "edition_status": "final",
            "published": "2025-12-29",
            "observed_at": "2026-08-29",
        },
    },
    {
        "id": "CISA-SCUBA-M365",
        "version": "2026-08-29-policy-snapshot",
        "kind": "microsoft-365-secure-configuration-baselines",
        "reference": "https://github.com/cisagov/ScubaGear",
        "evidence": ["control-assessment.json", "audit-package-verification.json"],
        "lifecycle": {
            "edition_status": "policy-pinned",
            "published": "2022-10-20",
            "observed_at": "2026-08-29",
        },
    },
    {
        "id": "CISA-SCUBA-GWS",
        "version": "2026-08-29-policy-snapshot",
        "kind": "google-workspace-secure-configuration-baselines",
        "reference": "https://www.cisa.gov/resources-tools/services/secure-cloud-business-applications-scuba-project",
        "evidence": ["control-assessment.json", "audit-package-verification.json"],
        "lifecycle": {
            "edition_status": "policy-pinned",
            "published": "2024",
            "observed_at": "2026-08-29",
        },
    },
    {
        "id": "CIS-KUBERNETES-BENCHMARK",
        "version": "2.0.1",
        "kind": "kubernetes-secure-configuration-benchmark",
        "reference": "https://www.cisecurity.org/benchmark/kubernetes",
        "evidence": ["control-assessment.json", "domain-assurance.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2026-06",
            "observed_at": "2026-08-29",
        },
    },
    {
        "id": "OIDF-FAPI-ATTACKER-MODEL",
        "version": "2.0-final-2025",
        "kind": "financial-grade-api-formal-attacker-model",
        "reference": "https://openid.net/specs/fapi-attacker-model-2_0-final.html",
        "evidence": [
            "threat-model-assessment.json",
            "application-contract-analysis.json",
        ],
        "lifecycle": {
            "edition_status": "final",
            "published": "2025-02-22",
            "observed_at": "2026-08-29",
        },
    },
    {
        "id": "OIDF-FAPI-MESSAGE-SIGNING",
        "version": "2.0-final-2025",
        "kind": "financial-grade-api-message-signing",
        "reference": "https://openid.net/specs/fapi-message-signing-2_0-final.html",
        "evidence": [
            "application-contract-analysis.json",
            "trust-policy-attestation.json",
        ],
        "lifecycle": {
            "edition_status": "final",
            "published": "2025",
            "observed_at": "2026-08-29",
        },
    },
    {
        "id": "LINDDUN-PRO",
        "version": "2026-08-29-policy-snapshot",
        "kind": "systematic-privacy-threat-modeling-method",
        "reference": "https://linddun.org/pro/",
        "evidence": ["threat-model-assessment.json", "data-exposure.json"],
        "lifecycle": {
            "edition_status": "policy-pinned",
            "published": "2026",
            "observed_at": "2026-08-29",
        },
    },
    {
        "id": "GSMA-NESAS",
        "version": "3.0-2025",
        "kind": "network-equipment-security-assurance-scheme",
        "reference": "https://www.gsma.com/solutions-and-impact/technologies/security/nesas-documents/",
        "evidence": [
            "process-capability-assessment.json",
            "audit-package-verification.json",
        ],
        "lifecycle": {
            "edition_status": "final",
            "published": "2025-02",
            "observed_at": "2026-08-29",
        },
    },
    {
        "id": "3GPP-SCAS",
        "version": "release-and-product-policy-pinned-2026-08-29",
        "kind": "network-product-security-assurance-specification",
        "reference": "https://www.3gpp.org/dynareport?code=33-series.htm",
        "evidence": ["procedure-assessment.json", "audit-package-verification.json"],
        "lifecycle": {
            "edition_status": "policy-pinned",
            "published": "2026",
            "observed_at": "2026-08-29",
        },
    },
    {
        "id": "VDA-ISA",
        "version": "6.0.3",
        "kind": "automotive-information-security-assessment-catalog",
        "reference": "https://enx.com/en-us/TISAX/downloads/",
        "evidence": ["control-assessment.json", "audit-package-verification.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2024-04-25",
            "observed_at": "2026-08-29",
        },
    },
    {
        "id": "ENX-TISAX",
        "version": "participant-handbook-2.8-policy-pinned",
        "kind": "automotive-information-security-assessment-exchange",
        "reference": "https://portal.enx.com/handbook/",
        "evidence": [
            "audit-package-verification.json",
            "external-conformity-assessment.json",
        ],
        "lifecycle": {
            "edition_status": "final-under-review",
            "published": "2025",
            "observed_at": "2026-08-29",
        },
    },
    {
        "id": "C2PA-CONTENT-CREDENTIALS",
        "version": "2.4",
        "kind": "digital-content-provenance-and-authenticity",
        "reference": "https://spec.c2pa.org/specifications/",
        "evidence": ["trust-policy-attestation.json", "software-supply-chain.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2026",
            "observed_at": "2026-08-29",
        },
    },
    {
        "id": "PCI-MPOC",
        "version": "1.x-policy-pinned-2026-08-29",
        "kind": "mobile-payments-on-commercial-off-the-shelf-security",
        "reference": "https://www.pcisecuritystandards.org/standards/mobile-payments-on-cots-mpoc/",
        "evidence": ["control-assessment.json", "procedure-assessment.json"],
        "lifecycle": {
            "edition_status": "policy-pinned",
            "published": "2026",
            "observed_at": "2026-08-29",
        },
    },
    {
        "id": "PCI-P2PE",
        "version": "3.2-policy-pinned",
        "kind": "point-to-point-encryption-solution-security",
        "reference": "https://www.pcisecuritystandards.org/standards/point-to-point-encryption-p2pe/",
        "evidence": ["control-assessment.json", "audit-package-verification.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2026",
            "observed_at": "2026-08-29",
        },
    },
)

_STANDARDS += (
    {
        "id": "FEDRAMP-20X",
        "version": "consolidated-rules-2026-classes-a-b-c",
        "kind": "continuous-outcome-based-federal-cloud-certification",
        "reference": "https://www.fedramp.gov/20x/",
        "evidence": ["control-assessment.json", "audit-package-verification.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2026-07-04",
            "observed_at": "2026-08-29",
        },
    },
    {
        "id": "FIDO-CTAP",
        "version": "2.2-proposed-standard-2025-07-14",
        "kind": "client-to-authenticator-protocol",
        "reference": "https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html",
        "evidence": ["application-contract-analysis.json", "procedure-assessment.json"],
        "lifecycle": {
            "edition_status": "final-under-review",
            "published": "2025-07-14",
            "observed_at": "2026-08-29",
        },
    },
    {
        "id": "FIDO-MDS",
        "version": "3.1-proposed-standard-2025-05-21",
        "kind": "authenticator-metadata-and-status-service",
        "reference": "https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1-ps-20250521.html",
        "evidence": [
            "trust-policy-attestation.json",
            "audit-package-verification.json",
        ],
        "lifecycle": {
            "edition_status": "final-under-review",
            "published": "2025-05-21",
            "observed_at": "2026-08-29",
        },
    },
    {
        "id": "FIDO-AUTHENTICATOR-CERTIFICATION",
        "version": "2026-08-29-policy-snapshot",
        "kind": "authenticator-functional-and-security-certification-program",
        "reference": "https://fidoalliance.org/certification/authenticator-certification-levels/",
        "evidence": [
            "external-conformity-assessment.json",
            "audit-package-verification.json",
        ],
        "lifecycle": {
            "edition_status": "policy-pinned",
            "published": "2026",
            "observed_at": "2026-08-29",
        },
    },
    {
        "id": "EU-EIDAS2",
        "version": "regulation-eu-2024-1183",
        "kind": "european-digital-identity-framework-regulation",
        "reference": "https://eur-lex.europa.eu/eli/reg/2024/1183/oj",
        "evidence": ["control-assessment.json", "external-conformity-assessment.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2024-04-30",
            "observed_at": "2026-08-29",
        },
    },
    {
        "id": "EU-EUDI-IMPLEMENTING-ACTS",
        "version": "2024-2977-2979-2980-2982-2025-848-amended-2026",
        "kind": "eudi-wallet-core-protocol-notification-registration-and-certification-rules",
        "reference": "https://digital-strategy.ec.europa.eu/en/library/implementing-regulation-european-digital-identity-wallets",
        "evidence": ["control-assessment.json", "audit-package-verification.json"],
        "lifecycle": {
            "edition_status": "policy-pinned",
            "published": "2026-07",
            "observed_at": "2026-08-29",
        },
    },
    {
        "id": "EU-EUDI-ARF",
        "version": "3.0.0",
        "kind": "eudi-wallet-architecture-and-reference-framework",
        "reference": "https://github.com/eu-digital-identity-wallet/eudi-doc-architecture-and-reference-framework/releases/tag/v3.0.0",
        "evidence": [
            "security-automation-interoperability.json",
            "lifecycle-traceability.json",
        ],
        "lifecycle": {
            "edition_status": "final",
            "published": "2026-07-23",
            "observed_at": "2026-08-29",
        },
    },
    {
        "id": "EU-EUDI-FCAF",
        "version": "arf-3.0.0-2026-07-23",
        "kind": "eudi-wallet-functional-conformance-assessment-framework",
        "reference": "https://conformance.eudi.dev/",
        "evidence": ["procedure-assessment.json", "benchmark-scorecard.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2026-07-23",
            "observed_at": "2026-08-29",
        },
    },
    {
        "id": "EU-NIS2-IMPLEMENTING-REGULATION",
        "version": "eu-2024-2690",
        "kind": "nis2-technical-and-methodological-risk-management-requirements",
        "reference": "https://eur-lex.europa.eu/eli/reg_impl/2024/2690/oj",
        "evidence": ["control-assessment.json", "audit-package-verification.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2024-10-17",
            "observed_at": "2026-08-29",
        },
    },
    {
        "id": "ENISA-NIS2-TECHNICAL-GUIDANCE",
        "version": "1.0-mapping-1.2-2025",
        "kind": "nis2-technical-implementation-evidence-guidance",
        "reference": "https://www.enisa.europa.eu/publications/nis2-technical-implementation-guidance",
        "evidence": ["control-assessment.json", "procedure-assessment.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2025-06-26",
            "observed_at": "2026-08-29",
        },
    },
    {
        "id": "NIST-SP-1326",
        "version": "2026",
        "kind": "cybersecurity-supply-chain-due-diligence-quick-start-guide",
        "reference": "https://csrc.nist.gov/pubs/sp/1326/final",
        "evidence": ["software-supply-chain.json", "audit-package-verification.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2026-07-08",
            "observed_at": "2026-08-29",
        },
    },
    {
        "id": "PCI-SECURE-SLC",
        "version": "1.1-2021",
        "kind": "payment-software-secure-lifecycle-standard",
        "reference": "https://www.pcisecuritystandards.org/document_library/?category=sware_sec",
        "evidence": [
            "process-capability-assessment.json",
            "audit-package-verification.json",
        ],
        "lifecycle": {
            "edition_status": "final",
            "published": "2021-02",
            "observed_at": "2026-08-29",
        },
    },
)

_STANDARDS_WATCHLIST: tuple[dict[str, str], ...] = (
    {
        "id": "NIST-SSDF-1.2",
        "status": "under-development",
        "stage": "initial-public-draft-policy-observed",
        "reference": "https://csrc.nist.gov/Projects/ssdf/publications",
        "reason": "Retain NIST SP 800-218 SSDF 1.1 as the normative baseline until the revision is final and approved through governed promotion.",
    },
    {
        "id": "NIST-SP-800-154",
        "status": "under-development",
        "stage": "initial-public-draft-policy-observed",
        "reference": "https://csrc.nist.gov/pubs/sp/800/154/ipd",
        "reason": "Treat data-centric threat-model guidance as informative watch material until NIST publishes a final edition.",
    },
    {
        "id": "ISO-IEC-25000-22",
        "status": "under-development",
        "stage": "committee-draft-policy-observed",
        "reference": "https://www.iso.org/standard/92688.html",
        "reason": "Retain ISO/IEC 25022:2016 as the normative quality-in-use measurement baseline until its replacement is published and governed through promotion.",
    },
    {
        "id": "ISO-IEC-27090",
        "status": "under-publication",
        "stage": "60.00",
        "reference": "https://www.iso.org/standard/56581.html",
        "reason": "Do not claim the unpublished edition as a final normative baseline.",
    },
    {
        "id": "NIST-PRIVACY-FRAMEWORK-1.1",
        "status": "forthcoming",
        "stage": "development",
        "reference": "https://www.nist.gov/privacy-framework/new-projects/privacy-framework-version-11",
        "reason": "Keep Privacy Framework 1.0 as the final baseline until 1.1 is published.",
    },
    {
        "id": "ISO-IEC-42119-3",
        "status": "under-development",
        "stage": "committee-draft-policy-observed",
        "reference": "https://www.iso.org/committee/6794475/x/catalogue/p/0/u/1/w/0/d/0",
        "reason": "Do not claim AI testing design-method conformance until the publication is final and its licensed requirements are pinned.",
    },
    {
        "id": "ISO-IEC-42119-7",
        "status": "under-development",
        "stage": "working-draft-policy-observed",
        "reference": "https://www.iso.org/committee/6794475/x/catalogue/p/0/u/1/w/0/d/0",
        "reason": "Treat AI red-team guidance as informative watch material until publication rather than a normative baseline.",
    },
    {
        "id": "ISO-IEC-42119-8",
        "status": "under-development",
        "stage": "working-draft-policy-observed",
        "reference": "https://www.iso.org/committee/6794475/x/catalogue/p/0/u/1/w/0/d/0",
        "reason": "Keep evolving AI testing guidance outside conformity claims until ISO publishes a final edition.",
    },
    {
        "id": "ISO-IEC-27004-NEXT-EDITION",
        "status": "under-development",
        "stage": "draft-policy-observed",
        "reference": "https://www.iso.org/standard/85920.html",
        "reason": "Retain ISO/IEC 27004:2016 as the normative baseline until the replacement edition is final and approved.",
    },
    {
        "id": "ETSI-EN-301-549-V4",
        "status": "under-development",
        "stage": "final-vote-policy-observed",
        "reference": "https://portal.etsi.org/webapp/WorkProgram/Report_WorkItem.asp?WKI_ID=64282",
        "reason": "Retain EN 301 549 V3.2.1 until V4.1.0 is published, source-pinned, and approved for promotion.",
    },
    {
        "id": "NIST-SP-800-92-REVISION-1",
        "status": "under-development",
        "stage": "initial-public-draft-policy-observed",
        "reference": "https://csrc.nist.gov/pubs/sp/800/92/r1/ipd",
        "reason": "Retain SP 800-92 as the final baseline until Revision 1 is finalized and approved for promotion.",
    },
    {
        "id": "ISO-IEC-27555-NEXT-EDITION",
        "status": "under-development",
        "stage": "draft-international-standard-policy-observed",
        "reference": "https://www.iso.org/standard/88748.html",
        "reason": "Retain ISO/IEC 27555:2021 until its replacement is published, source-pinned, and approved.",
    },
    {
        "id": "W3C-WCAG-EM-2.0",
        "status": "under-development",
        "stage": "working-group-draft-policy-observed",
        "reference": "https://www.w3.org/WAI/test-evaluate/conformance/wcag-em/",
        "reason": "Use the final WCAG-EM 1.0 methodology until WCAG-EM 2.0 reaches W3C Recommendation status.",
    },
    {
        "id": "ISO-IEC-27007-NEXT-EDITION",
        "status": "under-development",
        "stage": "draft-international-standard-policy-observed",
        "reference": "https://www.iso.org/standard/77802.html",
        "reason": "Retain ISO/IEC 27007:2020 until its replacement is published, source-pinned, and approved for promotion.",
    },
    {
        "id": "ISO-IEC-TS-27008-NEXT-EDITION",
        "status": "under-development",
        "stage": "committee-draft-policy-observed",
        "reference": "https://www.iso.org/standard/67397.html",
        "reason": "Retain ISO/IEC TS 27008:2019 until its replacement completes publication and governed promotion.",
    },
    {
        "id": "ISO-IEC-17021-1-NEXT-EDITION",
        "status": "under-review",
        "stage": "systematic-review-policy-observed",
        "reference": "https://www.iso.org/standard/61651.html",
        "reason": "Keep the confirmed 2015 edition as the baseline while the review and any replacement remain incomplete.",
    },
    {
        "id": "ISO-IEC-27034-NEXT-SERIES",
        "status": "under-review",
        "stage": "preliminary-review-policy-observed",
        "reference": "https://committee.iso.org/files/live/sites/jtc1sc27/files/resources/jtc1%20sc27%20SD11-%202025%20January.pdf",
        "reason": "Pin the published application-security parts independently; do not infer a replacement series or deleted Part 4.",
    },
    {
        "id": "ISO-IEC-27050-REVIEW",
        "status": "under-review",
        "stage": "systematic-review-policy-observed",
        "reference": "https://www.iso.org/standard/66230.html",
        "reason": "Retain published Parts 2 and 4 while their reviews are open and promote replacements only after final publication.",
    },
    {
        "id": "ISO-31000-NEXT-EDITION",
        "status": "under-development",
        "stage": "committee-draft-policy-observed",
        "reference": "https://www.iso.org/standard/88574.html",
        "reason": "Retain ISO 31000:2018 as the approved risk-management baseline until the replacement is final, licensed, and governed through promotion.",
    },
    {
        "id": "TCG-DICE-ATTESTATION-ARCHITECTURE-1.3",
        "status": "public-review",
        "stage": "release-candidate-policy-observed",
        "reference": "https://trustedcomputinggroup.org/specifications-public-review/",
        "reason": "Retain DICE Attestation Architecture 1.2 plus published errata until 1.3 leaves public review and is approved for promotion.",
    },
    {
        "id": "OWASP-ISVS-1.0",
        "status": "release-status-ambiguous",
        "stage": "release-candidate-and-release-labels-conflict",
        "reference": "https://owasp.org/IoT-Security-Verification-Standard-ISVS/",
        "reason": "Do not claim ISVS conformance until OWASP exposes an unambiguous stable version and immutable release artifact; retain ISO 27400-series and ETSI baselines meanwhile.",
    },
    {
        "id": "ISO-IEC-IEEE-29119-14",
        "status": "under-development",
        "stage": "draft-policy-observed",
        "reference": "https://committee.iso.org/sites/jtc1sc7/home/projects/flagship-standards/isoiecieee-29119-series.html",
        "reason": "Keep data-migration testing guidance outside normative claims until ISO publishes a final edition and its requirements are pinned.",
    },
    {
        "id": "ISO-IEC-IEEE-15026-4-NEXT-EDITION",
        "status": "under-development",
        "stage": "draft-revision-policy-observed",
        "reference": "https://www.iso.org/standard/88477.html",
        "reason": "Retain ISO/IEC/IEEE 15026-4:2021 as the normative lifecycle-assurance baseline until its replacement is final and approved.",
    },
    {
        "id": "IEEE-P1012",
        "status": "under-development",
        "stage": "active-revision-project-policy-observed",
        "reference": "https://standards.ieee.org/ieee/1012/12536/",
        "reason": "Retain IEEE 1012-2024 as the normative V&V baseline while the approved revision project remains incomplete.",
    },
    {
        "id": "ISO-IEC-42105",
        "status": "under-development",
        "stage": "final-draft-policy-observed",
        "reference": "https://www.iso.org/standard/86902.html",
        "reason": "Use ISO/IEC TS 8200:2024 for controllability and keep human-oversight guidance outside conformity claims until ISO/IEC 42105 is published and governed through promotion.",
    },
    {
        "id": "ISO-IEC-24970",
        "status": "under-development",
        "stage": "final-draft-policy-observed",
        "reference": "https://www.iso.org/committee/6794475/x/catalogue/p/0/u/1/w/0/d/0",
        "reason": "Retain organization-approved AI logging controls while the ISO/IEC 24970 final draft remains unpublished; promote only a final, licensed, source-pinned edition.",
    },
    {
        "id": "ISO-IEC-42007",
        "status": "under-development",
        "stage": "draft-international-standard-policy-observed",
        "reference": "https://www.iso.org/standard/89967.html",
        "reason": "Keep AI conformity-assessment scheme guidance outside normative claims until the standard is final, licensed, source-pinned, and approved through promotion.",
    },
    {
        "id": "NIST-IR-8596",
        "status": "under-development",
        "stage": "initial-preliminary-draft-policy-observed",
        "reference": "https://www.nccoe.nist.gov/projects/cyber-ai-profile",
        "reason": "Use final CSF 2.0 and AI RMF baselines while the Cyber AI Profile remains a reviewed preliminary draft.",
    },
    {
        "id": "ISO-IEC-TR-24030-NEXT-EDITION",
        "status": "under-development",
        "stage": "new-project-policy-observed",
        "reference": "https://www.iso.org/standard/91832.html",
        "reason": "Retain ISO/IEC TR 24030:2024 as the use-case baseline until Edition 3 is published and approved.",
    },
    {
        "id": "MLCOMMONS-AILUMINATE-AGENTIC",
        "status": "forthcoming",
        "stage": "public-program-without-stable-corpus-contract",
        "reference": "https://mlcommons.org/ailuminate/",
        "reason": "Do not claim agentic benchmark comparability until MLCommons publishes a stable versioned corpus, evaluator, scoring method, and reproducible execution contract.",
    },
    {
        "id": "MLCOMMONS-AILUMINATE-MULTIMODAL",
        "status": "forthcoming",
        "stage": "public-program-without-stable-corpus-contract",
        "reference": "https://mlcommons.org/ailuminate/",
        "reason": "Do not claim multimodal benchmark comparability until the released tasks, modalities, scorers, reference systems, and official split are immutable and source-pinned.",
    },
    {
        "id": "MCP-SPECIFICATION-2026-RELEASE",
        "status": "release-candidate",
        "stage": "release-candidate-policy-observed",
        "reference": "https://blog.modelcontextprotocol.io/posts/2026-07-28-release-candidate/",
        "reason": "Retain the stable 2025-11-25 protocol revision until the stateless-core, extensions, applications, tasks, and authorization changes are final, source-pinned, and promoted with compatibility evidence.",
    },
    {
        "id": "MICROSOFT-CLOUD-SECURITY-BENCHMARK-V2",
        "status": "preview",
        "stage": "public-preview-policy-observed",
        "reference": "https://learn.microsoft.com/en-us/security/benchmark/azure/",
        "reason": "Use MCSB v1 for normative control claims while v2 remains preview; execute v2 only in an explicitly non-normative compatibility lane.",
    },
    {
        "id": "ISO-IEC-27003-NEXT-EDITION",
        "status": "under-development",
        "stage": "draft-international-standard-policy-observed",
        "reference": "https://www.iso.org/standard/85919.html",
        "reason": "Retain ISO/IEC 27003:2017 as informative implementation guidance until Edition 3 is final, licensed, source-pinned, and approved through governed promotion.",
    },
    {
        "id": "ISO-22316-NEXT-EDITION",
        "status": "under-development",
        "stage": "final-draft-policy-observed",
        "reference": "https://www.iso.org/standard/50053.html",
        "reason": "Retain ISO 22316:2017 while its revision is incomplete and promote only after final publication and organization approval.",
    },
    {
        "id": "W3C-CSP-LEVEL-3",
        "status": "under-development",
        "stage": "working-draft-2026-05-05",
        "reference": "https://www.w3.org/TR/CSP3/",
        "reason": "Use the stable CSP Level 2 Recommendation for normative claims and exercise Level 3 only as informative compatibility evidence until W3C publishes a Recommendation.",
    },
    {
        "id": "W3C-SUBRESOURCE-INTEGRITY-2",
        "status": "under-development",
        "stage": "working-draft-2026-03-20",
        "reference": "https://www.w3.org/TR/sri-2/",
        "reason": "Retain the 2016 SRI Recommendation as the normative baseline while SRI 2 remains a Working Draft.",
    },
    {
        "id": "W3C-TRUSTED-TYPES",
        "status": "under-development",
        "stage": "working-draft-2026-06-23",
        "reference": "https://www.w3.org/TR/trusted-types/",
        "reason": "Exercise Trusted Types as an informative browser defense without claiming W3C Recommendation conformance while the specification remains a Working Draft.",
    },
    {
        "id": "BSI-TR-03183-PARTS-1-AND-3",
        "status": "under-development",
        "stage": "community-draft-0.9.0",
        "reference": "https://www.bsi.bund.de/dok/TR-03183-en",
        "reason": "Use final CRA and SBOM baselines for normative claims while the general-requirements and vulnerability-reporting parts remain community drafts under revision.",
    },
    {
        "id": "W3C-VC-DATA-MODEL-2.1",
        "status": "under-development",
        "stage": "working-draft-2026-05-11",
        "reference": "https://www.w3.org/TR/vc-data-model-2.1/",
        "reason": "Retain the W3C Verifiable Credentials Data Model 2.0 Recommendation until 2.1 completes the Recommendation track and governed promotion.",
    },
    {
        "id": "OIDF-OPENID4VP-1.1",
        "status": "under-development",
        "stage": "working-group-draft-policy-observed",
        "reference": "https://github.com/openid/OpenID4VP/tree/master/1.1",
        "reason": "Use OpenID4VP 1.0 Final and HAIP 1.0 Final for normative and certification-suite claims while 1.1 remains under development.",
    },
    {
        "id": "VDA-ISA-2027",
        "status": "future-effective",
        "stage": "published-for-2027-transition",
        "reference": "https://enx.com/en-us/TISAX/downloads/",
        "reason": "Use ISA 6.0.3 for assessments opened in 2026 and keep ISA2027 non-normative until its stated 2027 applicability window and organization transition approval.",
    },
    {
        "id": "FIDO-CTAP-2.3",
        "status": "under-development",
        "stage": "working-draft-policy-observed",
        "reference": "https://fidoalliance.org/specifications/download/",
        "reason": "Use CTAP 2.2 Proposed Standard for governed conformance while 2.3 remains a Working Draft and its transport, authenticator, and certification behavior can still change.",
    },
    {
        "id": "ENISA-EUCS",
        "status": "candidate-scheme",
        "stage": "under-development-policy-observed",
        "reference": "https://www.enisa.europa.eu/topics/certification/eucs-cloud-services",
        "reason": "Do not claim EU cloud-services certification until the candidate scheme is adopted, effective, version-pinned, and supported by authorized conformity-assessment evidence.",
    },
    {
        "id": "ENISA-EUMSS",
        "status": "candidate-scheme",
        "stage": "under-development-policy-observed",
        "reference": "https://www.enisa.europa.eu/topics/certification",
        "reason": "Keep the managed-security-services candidate scheme outside normative claims until adoption and governed promotion.",
    },
    {
        "id": "ENISA-EUDIW-CERTIFICATION",
        "status": "candidate-scheme",
        "stage": "under-development-policy-observed",
        "reference": "https://www.enisa.europa.eu/topics/certification",
        "reason": "Use the final EUDI regulation, implementing acts, ARF, and functional conformance framework without implying certification under a candidate ENISA scheme.",
    },
    {
        "id": "ENISA-EU5G",
        "status": "candidate-scheme",
        "stage": "under-development-policy-observed",
        "reference": "https://www.enisa.europa.eu/topics/certification",
        "reason": "Retain NESAS and product-applicable 3GPP SCAS assurance while the European 5G certification scheme remains under development.",
    },
)

_BENCHMARKS: tuple[dict[str, Any], ...] = (
    {
        "id": "pysec-governed-holdout",
        "version": "2.0",
        "kind": "labeled-corpus",
        "source": "installed effectiveness corpus contract",
        "languages": ["multi"],
        "lane": "core-verified-report",
    },
    {
        "id": "owasp-benchmark",
        "version": "policy-pinned",
        "kind": "sast-dast",
        "source": "https://owasp.org/www-project-benchmark/",
        "languages": ["java", "python"],
        "lane": "authorized-companion",
    },
    {
        "id": "nist-sard-juliet",
        "version": "1.3",
        "kind": "sast",
        "source": "https://samate.nist.gov/SARD/",
        "languages": ["c", "cpp", "java", "csharp"],
        "lane": "authorized-companion",
    },
    {
        "id": "owasp-juice-shop",
        "version": "policy-pinned",
        "kind": "dast",
        "source": "https://owasp.org/www-project-juice-shop/",
        "languages": ["javascript"],
        "lane": "authorized-companion",
    },
    {
        "id": "owasp-webgoat",
        "version": "policy-pinned",
        "kind": "dast",
        "source": "https://owasp.org/www-project-webgoat/",
        "languages": ["java"],
        "lane": "authorized-companion",
    },
    {
        "id": "owasp-crapi",
        "version": "policy-pinned",
        "kind": "api-dast",
        "source": "https://owasp.org/www-project-crapi/",
        "languages": ["api"],
        "lane": "authorized-companion",
    },
    {
        "id": "cyberseceval-4",
        "version": "4",
        "kind": "llm-security",
        "source": "https://github.com/meta-llama/PurpleLlama/tree/main/CybersecurityBenchmarks",
        "languages": ["multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "mlcommons-ailuminate",
        "version": "policy-pinned",
        "kind": "ai-safety-security",
        "source": "https://mlcommons.org/ailuminate/",
        "languages": ["multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "python-real-world-holdout",
        "version": "organization-pinned",
        "kind": "real-world",
        "source": "organization-approved corpus",
        "languages": ["python"],
        "lane": "authorized-companion",
    },
    {
        "id": "python-cve-pairs",
        "version": "organization-pinned",
        "kind": "vulnerable-patched-pairs",
        "source": "organization-approved Python CVE commit-pair corpus",
        "languages": ["python"],
        "lane": "authorized-companion",
    },
    {
        "id": "iac-misconfiguration-holdout",
        "version": "organization-pinned",
        "kind": "iac-security",
        "source": "organization-approved IaC positive/negative corpus",
        "languages": ["terraform", "cloudformation", "kubernetes"],
        "lane": "authorized-companion",
    },
    {
        "id": "container-kubernetes-holdout",
        "version": "organization-pinned",
        "kind": "container-orchestration-security",
        "source": "organization-approved container and Kubernetes corpus",
        "languages": ["dockerfile", "kubernetes"],
        "lane": "authorized-companion",
    },
    {
        "id": "secret-detection-holdout",
        "version": "organization-pinned",
        "kind": "secret-detection",
        "source": "organization-approved synthetic and revoked-secret corpus",
        "languages": ["multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "sbom-sca-holdout",
        "version": "organization-pinned",
        "kind": "sbom-sca-accuracy",
        "source": "organization-approved dependency graph and advisory corpus",
        "languages": ["multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "malicious-package-holdout",
        "version": "organization-pinned",
        "kind": "malicious-package-detection",
        "source": "organization-approved inert malicious-package corpus",
        "languages": ["python"],
        "lane": "authorized-companion",
    },
    {
        "id": "fuzzing-crash-holdout",
        "version": "organization-pinned",
        "kind": "fuzzing-effectiveness",
        "source": "organization-approved seeded-defect and crash corpus",
        "languages": ["multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "agentic-security-holdout",
        "version": "organization-pinned",
        "kind": "agentic-ai-security",
        "source": "organization-approved tool-use and prompt-injection corpus",
        "languages": ["multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "architecture-quality-holdout",
        "version": "organization-pinned",
        "kind": "architecture-quality",
        "source": "organization-approved architecture-smell corpus",
        "languages": ["multi"],
        "lane": "authorized-companion",
    },
)

_BENCHMARKS += (
    {
        "id": "nist-acvp-cryptography",
        "version": "policy-pinned",
        "kind": "cryptographic-algorithm-conformance",
        "source": "https://github.com/usnistgov/ACVP-Server",
        "languages": ["multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "oidf-fapi-conformance",
        "version": "policy-pinned",
        "kind": "identity-protocol-conformance",
        "source": "https://www.certification.openid.net/",
        "languages": ["protocol"],
        "lane": "authorized-companion",
    },
    {
        "id": "w3c-wpt-webauthn",
        "version": "policy-pinned",
        "kind": "browser-authentication-conformance",
        "source": "https://github.com/web-platform-tests/wpt/tree/master/webauthn",
        "languages": ["javascript", "protocol"],
        "lane": "authorized-companion",
    },
    {
        "id": "mitre-attack-emulation",
        "version": "policy-pinned",
        "kind": "contained-attack-emulation",
        "source": "https://github.com/mitre/caldera",
        "languages": ["multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "openssf-scorecard",
        "version": "policy-pinned",
        "kind": "repository-security-posture",
        "source": "https://github.com/ossf/scorecard",
        "languages": ["multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "polyglot-cve-pairs",
        "version": "organization-pinned",
        "kind": "time-split-vulnerable-patched-pairs",
        "source": "organization-approved polyglot CVE commit-pair corpus",
        "languages": [
            "python",
            "javascript",
            "java",
            "c",
            "cpp",
            "csharp",
            "go",
            "rust",
        ],
        "lane": "authorized-companion",
    },
    {
        "id": "artifact-interoperability-conformance",
        "version": "organization-pinned",
        "kind": "semantic-artifact-conformance",
        "source": "organization-approved SARIF SPDX CycloneDX and OSCAL corpus",
        "languages": ["json", "xml"],
        "lane": "authorized-companion",
    },
    {
        "id": "scanner-scale-determinism",
        "version": "organization-pinned",
        "kind": "performance-and-repeatability",
        "source": "organization-approved repository scale and repeatability corpus",
        "languages": ["multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "recovery-resilience-holdout",
        "version": "organization-pinned",
        "kind": "failure-recovery-resilience",
        "source": "organization-approved dependency failure and recovery corpus",
        "languages": ["multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "protocol-evasion-holdout",
        "version": "organization-pinned",
        "kind": "protocol-evasion-and-parser-robustness",
        "source": "organization-approved encoded fragmented and ambiguous protocol corpus",
        "languages": ["protocol", "multi"],
        "lane": "authorized-companion",
    },
)

_BENCHMARKS += (
    {
        "id": "atomic-red-team",
        "version": "policy-pinned",
        "kind": "detection-control-validation",
        "source": "https://github.com/redcanaryco/atomic-red-team",
        "languages": ["multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "official-artifact-schema-conformance",
        "version": "policy-pinned",
        "kind": "official-schema-and-semantic-round-trip",
        "source": "official SARIF CSAF CycloneDX OSCAL STIX and VEX schemas",
        "languages": ["json", "xml"],
        "lane": "authorized-companion",
    },
    {
        "id": "defects4j",
        "version": "policy-pinned",
        "kind": "reproducible-functional-defects",
        "source": "https://github.com/rjust/defects4j",
        "languages": ["java"],
        "lane": "authorized-companion",
    },
    {
        "id": "swe-bench-verified",
        "version": "policy-pinned-time-split",
        "kind": "repository-level-functional-repair",
        "source": "https://github.com/SWE-bench/SWE-bench",
        "languages": ["python", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "google-fuzzbench",
        "version": "policy-pinned",
        "kind": "statistical-fuzzer-evaluation",
        "source": "https://github.com/google/fuzzbench",
        "languages": ["c", "cpp"],
        "lane": "authorized-companion",
    },
    {
        "id": "magma-ground-truth",
        "version": "policy-pinned",
        "kind": "ground-truth-fuzzing",
        "source": "https://hexhive.epfl.ch/magma/",
        "languages": ["c", "cpp"],
        "lane": "authorized-companion",
    },
    {
        "id": "owasp-mas-crackmes",
        "version": "policy-pinned",
        "kind": "mobile-security-behavior",
        "source": "https://mas.owasp.org/MASTG/apps/",
        "languages": ["android", "ios"],
        "lane": "authorized-companion",
    },
    {
        "id": "cloudgoat",
        "version": "policy-pinned",
        "kind": "cloud-attack-path-validation",
        "source": "https://github.com/RhinoSecurityLabs/cloudgoat",
        "languages": ["terraform", "cloud"],
        "lane": "authorized-companion",
    },
    {
        "id": "smartbugs-curated",
        "version": "policy-pinned",
        "kind": "smart-contract-vulnerability-detection",
        "source": "https://github.com/smartbugs/smartbugs-curated",
        "languages": ["solidity", "evm"],
        "lane": "authorized-companion",
    },
    {
        "id": "etsi-iot-conformance",
        "version": "TS-103-701-2.1.1",
        "kind": "consumer-iot-conformance",
        "source": "ETSI TS 103 701 assessment cases and approved product fixtures",
        "languages": ["firmware", "protocol", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "stix-taxii-interoperability",
        "version": "2.1-policy-pinned",
        "kind": "threat-intelligence-interoperability",
        "source": "OASIS STIX TAXII interoperability tests",
        "languages": ["json", "protocol"],
        "lane": "authorized-companion",
    },
    {
        "id": "secure-coding-rule-conformance",
        "version": "organization-pinned",
        "kind": "language-specific-secure-coding",
        "source": "organization-approved CERT MISRA and ISO rule examples",
        "languages": ["c", "cpp", "java"],
        "lane": "authorized-companion",
    },
)

_BENCHMARKS += (
    {
        "id": "vul4j",
        "version": "policy-pinned-reproducible-image",
        "kind": "java-real-world-vulnerability-reproduction",
        "source": "https://github.com/tuhh-softsec/vul4j",
        "languages": ["java"],
        "lane": "authorized-companion",
    },
    {
        "id": "bugsinpy",
        "version": "policy-pinned-reproducible-subset",
        "kind": "python-real-world-functional-defects",
        "source": "https://github.com/soarsmu/BugsInPy",
        "languages": ["python"],
        "lane": "authorized-companion",
    },
    {
        "id": "agentdojo",
        "version": "policy-pinned",
        "kind": "agent-prompt-injection-utility-under-attack",
        "source": "https://github.com/ethz-spylab/agentdojo",
        "languages": ["python", "llm", "agent"],
        "lane": "authorized-companion",
    },
    {
        "id": "oss-fuzz-clusterfuzzlite",
        "version": "policy-pinned",
        "kind": "continuous-fuzzing-integration-effectiveness",
        "source": "https://google.github.io/oss-fuzz/",
        "languages": ["c", "cpp", "go", "java", "python", "rust"],
        "lane": "authorized-companion",
    },
    {
        "id": "disa-stig-scap-conformance",
        "version": "policy-pinned-quarterly-release",
        "kind": "federal-configuration-conformance",
        "source": "https://public.cyber.mil/stigs/",
        "languages": ["scap", "xccdf", "oval", "configuration"],
        "lane": "authorized-companion",
    },
    {
        "id": "iec-62443-system-conformance",
        "version": "policy-pinned-test-report-form",
        "kind": "industrial-system-security-level-conformance",
        "source": "IEC 62443-3-3 approved test report forms and licensed requirements",
        "languages": ["ot", "protocol", "configuration"],
        "lane": "authorized-companion",
    },
    {
        "id": "threat-model-quality",
        "version": "organization-pinned",
        "kind": "expert-labeled-threat-model-completeness",
        "source": "organization-approved assets boundaries threats mitigations and drift corpus",
        "languages": ["architecture", "multi"],
        "lane": "authorized-companion",
    },
)

_BENCHMARKS += (
    {
        "id": "lifecycle-traceability-mutation",
        "version": "organization-pinned",
        "kind": "requirements-life-cycle-traceability",
        "source": "organization-approved requirements architecture code test operations and retirement mutation corpus",
        "languages": ["requirements", "architecture", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "architecture-evaluation-scenarios",
        "version": "organization-pinned",
        "kind": "expert-labeled-architecture-evaluation",
        "source": "organization-approved stakeholder concern quality attribute trade-off and risk scenarios",
        "languages": ["architecture", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "process-capability-assessor-agreement",
        "version": "organization-pinned",
        "kind": "independent-process-capability-assessment",
        "source": "organization-approved life-cycle process evidence and assessor labels",
        "languages": ["process", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "cwe-mapping-conformance",
        "version": "CWE-4.20",
        "kind": "weakness-taxonomy-mapping",
        "source": "https://cwe.mitre.org/data/index.html",
        "languages": ["multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "epss-kev-temporal-backtest",
        "version": "policy-pinned-point-in-time",
        "kind": "vulnerability-prioritization-calibration",
        "source": "digest-pinned historical FIRST EPSS and CISA KEV snapshots with future outcomes",
        "languages": ["vulnerability-data"],
        "lane": "authorized-companion",
    },
    {
        "id": "sv-comp",
        "version": "2026",
        "kind": "software-verification-competition",
        "source": "https://sv-comp.sosy-lab.org/2026/",
        "languages": ["c", "java", "sv-lib"],
        "lane": "authorized-companion",
    },
    {
        "id": "test-comp",
        "version": "2026",
        "kind": "automatic-test-generation-competition",
        "source": "https://test-comp.sosy-lab.org/2026/",
        "languages": ["c"],
        "lane": "authorized-companion",
    },
    {
        "id": "sigstore-client-conformance",
        "version": "policy-pinned",
        "kind": "software-signing-client-conformance",
        "source": "https://github.com/sigstore/sigstore-conformance",
        "languages": ["protocol", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "slsa-verifier-conformance",
        "version": "policy-pinned",
        "kind": "provenance-verifier-conformance",
        "source": "https://github.com/slsa-framework/slsa-verifier",
        "languages": ["provenance", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "nist-aria-inspect-evaluation",
        "version": "NIST-AI-700-2-policy-pinned-inspect",
        "kind": "scenario-red-team-field-ai-evaluation",
        "source": "NIST ARIA methods executed through a policy-pinned UK AISI Inspect evaluation",
        "languages": ["ai", "llm", "agent"],
        "lane": "authorized-companion",
    },
    {
        "id": "iec-62443-patch-management-exercise",
        "version": "policy-pinned",
        "kind": "iacs-patch-management-lifecycle",
        "source": "licensed IEC 62443-2-3 requirements and organization-approved patch fixtures",
        "languages": ["ot", "configuration"],
        "lane": "authorized-companion",
    },
    {
        "id": "do355-continuing-airworthiness-exercise",
        "version": "policy-pinned",
        "kind": "aircraft-security-continuing-airworthiness",
        "source": "licensed DO-355A procedures and organization-approved continuing-airworthiness scenarios",
        "languages": ["airborne", "process", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "iacs-maritime-cyber-conformance",
        "version": "policy-pinned-current-revisions",
        "kind": "ship-and-onboard-system-cyber-resilience",
        "source": "IACS UR E26 and E27 approved survey and system fixtures",
        "languages": ["maritime", "ot", "configuration"],
        "lane": "authorized-companion",
    },
    {
        "id": "swift-cscf-independent-assessment",
        "version": "2026",
        "kind": "financial-messaging-control-assessment",
        "source": "SWIFT CSCF 2026 and Independent Assessment Framework",
        "languages": ["financial-messaging", "configuration"],
        "lane": "authorized-companion",
    },
)

_BENCHMARKS += (
    {
        "id": "owasp-dsovs-maturity",
        "version": "policy-pinned",
        "kind": "devsecops-verification-maturity-assessment",
        "source": "OWASP DSOVS control evidence and independently reviewed ratings",
        "languages": ["process", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "owasp-dsomm-maturity",
        "version": "5.0.2",
        "kind": "devsecops-maturity-assessment",
        "source": "OWASP DSOMM 5.0.2 evidence and independently reviewed ratings",
        "languages": ["process", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "tmmi-assessment",
        "version": "2.0",
        "kind": "test-maturity-assessment",
        "source": "TMMi 2.0 evidence and independently reviewed ratings",
        "languages": ["test-process", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "bsimm-cmmi-cohort",
        "version": "organization-pinned",
        "kind": "external-maturity-cohort-comparison",
        "source": "licensed model requirements and organization-approved anonymized cohort",
        "languages": ["process", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "csa-star-caiq-conformance",
        "version": "policy-pinned",
        "kind": "cloud-independent-assurance-conformance",
        "source": "CSA STAR and CAIQ evidence package",
        "languages": ["cloud", "controls"],
        "lane": "authorized-companion",
    },
    {
        "id": "cacao-openc2-ocsf-interoperability",
        "version": "policy-pinned",
        "kind": "security-automation-round-trip-conformance",
        "source": "OASIS CACAO OpenC2 and OCSF schema and negative fixtures",
        "languages": ["json", "protocol"],
        "lane": "authorized-companion",
    },
    {
        "id": "mitre-attack-evaluations",
        "version": "policy-pinned",
        "kind": "detection-evaluation-ingestion-replay",
        "source": "MITRE ATT&CK Evaluations result set and replay manifest",
        "languages": ["detection", "telemetry"],
        "lane": "authorized-companion",
    },
    {
        "id": "ai-conformity-quality",
        "version": "policy-pinned",
        "kind": "ai-quality-bias-trust-conformity",
        "source": "ISO IEC 25059 TR 24027 TR 24028 and AICM evaluation corpus",
        "languages": ["ai", "llm", "controls"],
        "lane": "authorized-companion",
    },
    {
        "id": "psti-en18031-product-conformance",
        "version": "policy-pinned",
        "kind": "consumer-product-regulatory-conformance",
        "source": "UK PSTI and ETSI EN 18031 licensed requirements and product fixtures",
        "languages": ["iot", "radio", "configuration"],
        "lane": "authorized-companion",
    },
)

_BENCHMARKS += (
    {
        "id": "scitt-transparency-conformance",
        "version": "RFC-9942-9943",
        "kind": "supply-chain-transparency-receipt-conformance",
        "source": "IETF SCITT signed-statement, COSE receipt, consistency, replay, and equivocation fixtures",
        "languages": ["cbor", "cose", "protocol"],
        "lane": "authorized-companion",
    },
    {
        "id": "cloud-native-api-service-mesh-conformance",
        "version": "NIST-800-228-update-1-policy-pinned",
        "kind": "api-gateway-service-mesh-policy-adversarial",
        "source": "NIST SP 800-228, SP 800-204 family, SP 800-233, and NISTIR 8505 control-linked fixtures",
        "languages": ["api", "kubernetes", "service-mesh", "policy"],
        "lane": "authorized-companion",
    },
    {
        "id": "api-contract-spec-conformance",
        "version": "policy-pinned",
        "kind": "openapi-asyncapi-graphql-json-schema-conformance",
        "source": "official OpenAPI, AsyncAPI, GraphQL, and JSON Schema positive, negative, downgrade, and round-trip fixtures",
        "languages": ["json", "yaml", "graphql", "protocol"],
        "lane": "authorized-companion",
    },
    {
        "id": "opentelemetry-semantic-conformance",
        "version": "1.44.0-policy-pinned",
        "kind": "telemetry-semantic-and-trace-integrity",
        "source": "OpenTelemetry semantic-convention, trace-context, baggage, redaction, and round-trip fixtures",
        "languages": ["telemetry", "json", "protocol"],
        "lane": "authorized-companion",
    },
    {
        "id": "ai-agentic-testing-conformance",
        "version": "2026-policy-pinned",
        "kind": "risk-based-stochastic-agentic-testing",
        "source": "OWASP Agentic Top 10 2026 and licensed ISO IEC 29119-11 and 42119-2 control-linked corpus",
        "languages": ["ai", "llm", "agent", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "s2c2f-consumer-dependency-conformance",
        "version": "1.0-policy-pinned",
        "kind": "dependency-consumption-and-quarantine",
        "source": "OpenSSF S2C2F acquisition, inventory, update, substitution, quarantine, and compromise-response fixtures",
        "languages": ["package", "sbom", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "multicloud-kubernetes-attack-paths",
        "version": "organization-pinned",
        "kind": "aws-azure-gcp-kubernetes-attack-path-validation",
        "source": "organization-approved disposable multi-cloud identity, network, data, control-plane, and workload attack scenarios",
        "languages": ["aws", "azure", "gcp", "kubernetes", "terraform"],
        "lane": "authorized-companion",
    },
    {
        "id": "securitytxt-patch-operations-conformance",
        "version": "RFC-9116-NIST-800-40r4",
        "kind": "vulnerability-intake-and-patch-lifecycle",
        "source": "RFC 9116 syntax and NIST SP 800-40r4 inventory, prioritization, deployment, exception, and verification fixtures",
        "languages": ["http", "operations", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "regional-cyber-maturity-assessment",
        "version": "policy-pinned",
        "kind": "regional-baseline-assessor-agreement",
        "source": "NCSC CAF, Cyber Essentials, ASD Essential Eight, and CISA CPG evidence cases with independent assessor labels",
        "languages": ["controls", "process", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "automotive-software-update-conformance",
        "version": "ISO-24089-2023",
        "kind": "automotive-update-engineering-and-regulatory-conformance",
        "source": "licensed ISO 24089 requirements and approved UNECE R156 update, rollback, authenticity, safety, and recovery fixtures",
        "languages": ["automotive", "firmware", "process"],
        "lane": "authorized-companion",
    },
    {
        "id": "energy-product-security-conformance",
        "version": "policy-pinned",
        "kind": "power-protocol-and-product-cybersecurity-conformance",
        "source": "licensed IEC 62351 and UL 2900 requirements with approved power-protocol and product test fixtures",
        "languages": ["energy", "ot", "protocol", "firmware"],
        "lane": "authorized-companion",
    },
    {
        "id": "cisa-sbom-minimum-elements-conformance",
        "version": "CISA-2026-v2.1",
        "kind": "sbom-minimum-elements-conformance",
        "source": "CISA-led 2026 SBOM minimum-elements author-signature, format, version, generation, hash, license, relationship, known-unknown, freshness, and automation fixtures",
        "languages": ["cyclonedx", "spdx", "sbom"],
        "lane": "authorized-companion",
    },
    {
        "id": "enhanced-cui-oscal-conformance",
        "version": "NIST-800-172r3-172Ar3-53B-5.2.0",
        "kind": "enhanced-cui-control-and-assessment-conformance",
        "source": "NIST SP 800-172 Rev. 3, 800-172A Rev. 3, and OSCAL 1.2.2 control-linked assessment fixtures",
        "languages": ["oscal", "controls", "assessment"],
        "lane": "authorized-companion",
    },
    {
        "id": "nist-developer-verification-conformance",
        "version": "NISTIR-8397-2021",
        "kind": "developer-verification-technique-conformance",
        "source": "NISTIR 8397 technique-linked code, threat-model, review, test, fuzzing, and analysis fixtures",
        "languages": ["multi", "sast", "testing"],
        "lane": "authorized-companion",
    },
    {
        "id": "crypto-lifecycle-agility-conformance",
        "version": "NIST-800-57-227-CSWP39-update-1",
        "kind": "cryptographic-key-lifecycle-and-pqc-agility",
        "source": "NIST key lifecycle, KEM validation, cryptographic inventory, transition, rollover, downgrade, and recovery fixtures",
        "languages": ["cryptography", "pqc", "configuration"],
        "lane": "authorized-companion",
    },
    {
        "id": "iscm-program-assessment",
        "version": "NIST-800-137A-IR8212-policy-pinned",
        "kind": "continuous-monitoring-program-assessor-agreement",
        "source": "NIST SP 800-137A and NISTIR 8212 program elements, judgments, evidence cases, and blinded assessor labels",
        "languages": ["controls", "operations", "assessment"],
        "lane": "authorized-companion",
    },
    {
        "id": "ict-continuity-recovery-exercise",
        "version": "ISO-IEC-27031-2025-policy-pinned",
        "kind": "ict-continuity-readiness-and-recovery-conformance",
        "source": "licensed ISO IEC 27031 requirements and organization-approved disruption, failover, degraded-mode, restoration, and lessons-learned scenarios",
        "languages": ["resilience", "operations", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "digital-forensics-chain-of-custody",
        "version": "ISO-27037-27043-NIST-800-86-policy-pinned",
        "kind": "digital-evidence-method-and-chain-of-custody-conformance",
        "source": "licensed ISO IEC 27037, 27041, 27042, 27043 and NIST SP 800-86 evidence handling, method, analysis, reproducibility, and custody fixtures",
        "languages": ["forensics", "evidence", "incident-response"],
        "lane": "authorized-companion",
    },
    {
        "id": "wcag-accessibility-conformance",
        "version": "WCAG-2.2-EN301549-3.2.1",
        "kind": "accessibility-automated-and-manual-conformance",
        "source": "W3C WCAG 2.2, EN 301 549 V3.2.1, and Section 508 test rules, assistive-technology scenarios, and manual evaluation cases",
        "languages": ["html", "css", "javascript", "ict"],
        "lane": "authorized-companion",
    },
    {
        "id": "nist-cfreds-cftt",
        "version": "publisher-snapshot-pinned",
        "kind": "digital-forensics-reference-data-tool-testing",
        "source": "NIST CFReDS and Computer Forensic Tool Testing documented images, artifacts, methods, and expected observations",
        "languages": ["forensics", "disk-image", "mobile", "cloud"],
        "lane": "authorized-companion",
    },
    {
        "id": "w3c-act-rules-conformance",
        "version": "ACT-Rules-Format-1.1-WCAG-2.2",
        "kind": "accessibility-rule-and-implementation-conformance",
        "source": "W3C formally approved ACT rules with applicability, pass, fail, and inapplicable expectations",
        "languages": ["html", "css", "javascript", "accessibility-tree"],
        "lane": "authorized-companion",
    },
    {
        "id": "droidbench",
        "version": "3.0-development-policy-pinned",
        "kind": "android-static-dynamic-taint-analysis",
        "source": "Secure Software Engineering Group DroidBench source projects, APKs, labels, and Android-specific analysis cases",
        "languages": ["java", "android", "apk"],
        "lane": "authorized-companion",
    },
    {
        "id": "ghera-android-security",
        "version": "organization-pinned",
        "kind": "android-framework-security-benchmark",
        "source": "Ghera Android vulnerability benchmarks with policy-pinned commits, expected behavior, and emulator image",
        "languages": ["java", "kotlin", "android", "apk"],
        "lane": "authorized-companion",
    },
    {
        "id": "secbench-js",
        "version": "organization-pinned",
        "kind": "javascript-real-vulnerability-analysis",
        "source": "SecBench.js vulnerability-fix pairs with policy-pinned commits, labels, and dependency lockfiles",
        "languages": ["javascript", "typescript", "nodejs"],
        "lane": "authorized-companion",
    },
    {
        "id": "cloud-native-chaos-resilience",
        "version": "chaos-mesh-litmus-policy-pinned",
        "kind": "bounded-chaos-resilience-slo-conformance",
        "source": "Digest-pinned Chaos Mesh and Litmus experiments with steady-state, blast-radius, SLO, rollback, and cleanup assertions",
        "languages": ["kubernetes", "yaml", "resilience", "observability"],
        "lane": "authorized-companion",
    },
    {
        "id": "kubernetes-sonobuoy-conformance",
        "version": "kubernetes-release-pinned",
        "kind": "kubernetes-release-conformance",
        "source": "CNCF Kubernetes conformance suites executed through digest-pinned Sonobuoy plugins and cluster identities",
        "languages": ["kubernetes", "go", "configuration"],
        "lane": "authorized-companion",
    },
    {
        "id": "cis-cat-scap-platform-conformance",
        "version": "licensed-platform-benchmark-pinned",
        "kind": "technology-specific-configuration-conformance",
        "source": "Licensed CIS Benchmark and CIS-CAT or equivalent SCAP results pinned to product, edition, profile, and benchmark release",
        "languages": ["scap", "configuration", "operating-system", "cloud"],
        "lane": "authorized-companion",
    },
)

_BENCHMARKS += (
    {
        "id": "c2sp-wycheproof",
        "version": "organization-pinned-release",
        "kind": "cryptographic-implementation-negative-and-edge-case-testing",
        "source": "https://github.com/C2SP/wycheproof",
        "languages": ["cryptography", "json", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "tiber-eu-threat-led-red-team",
        "version": "TIBER-EU-2025-policy-pinned",
        "kind": "threat-intelligence-led-red-team-control-validation",
        "source": "TIBER-EU 2025 framework, approved threat intelligence, scoped systems, and restoration evidence",
        "languages": ["financial", "operations", "detection", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "nist-dioptra-ai-evaluation",
        "version": "1.1.0-policy-pinned",
        "kind": "reproducible-adversarial-ai-evaluation",
        "source": "https://pages.nist.gov/dioptra/",
        "languages": ["ai", "ml", "python", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "firmware-resilience-measured-boot",
        "version": "nist-800-193-tpm2-policy-pinned",
        "kind": "platform-firmware-protect-detect-recover-and-attestation",
        "source": "NIST SP 800-193, TCG TPM 2.0, and an approved signed firmware corpus",
        "languages": ["firmware", "tpm", "binary", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "access-control-policy-model-conformance",
        "version": "nist-800-192-policy-pinned",
        "kind": "access-control-policy-model-verification-and-mutation",
        "source": "NIST SP 800-192 with approved policy models, decision oracles, and mutation operators",
        "languages": ["policy", "authorization", "model", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "differential-privacy-implementation-evaluation",
        "version": "nist-800-226-policy-pinned",
        "kind": "differential-privacy-guarantee-hazard-and-utility-evaluation",
        "source": "NIST SP 800-226 with approved neighboring datasets, mechanisms, privacy budgets, and utility oracles",
        "languages": ["privacy", "statistics", "python", "r"],
        "lane": "authorized-companion",
    },
    {
        "id": "security-evaluator-calibration",
        "version": "iso-19896-policy-pinned",
        "kind": "security-assessor-and-evaluator-competence-calibration",
        "source": "ISO/IEC 19896 role-specific qualification criteria with blinded golden cases",
        "languages": ["assessment", "cryptography", "common-criteria", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "square-quality-measurement",
        "version": "iso-25012-25020-25024-25030-policy-pinned",
        "kind": "software-and-data-quality-measurement-conformance",
        "source": "ISO/IEC 25012, 25020, 25024, and 25030 with approved measures and reference datasets",
        "languages": ["quality", "data", "measurement", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "iso-29119-test-process-conformance",
        "version": "parts-2-4-2021-part-5-2024-policy-pinned",
        "kind": "test-process-documentation-technique-and-keyword-conformance",
        "source": "Licensed ISO/IEC/IEEE 29119 Parts 2 through 5 requirements with approved positive, negative, boundary, traceability, and omission cases",
        "languages": ["testing", "process", "documentation", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "square-quality-in-use-cloud",
        "version": "iso-25019-25052-policy-pinned",
        "kind": "quality-in-use-and-cloud-service-measurement-conformance",
        "source": "Licensed ISO/IEC 25019 and ISO/IEC TS 25052 quality models, measures, workloads, user contexts, and decision rules",
        "languages": ["quality", "cloud", "measurement", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "risk-technique-calibration",
        "version": "iso-31000-iec-31010-policy-pinned",
        "kind": "risk-technique-selection-and-assessor-calibration",
        "source": "Licensed ISO 31000 and IEC 31010 criteria with blinded risk scenarios, technique-selection oracles, uncertainty, and adjudication",
        "languages": ["risk", "assessment", "governance", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "tls-protocol-conformance",
        "version": "bogo-tlsfuzzer-organization-pinned",
        "kind": "tls-state-machine-alert-interoperability-and-negative-conformance",
        "source": "Immutable BoringSSL BoGo and tlsfuzzer revisions with supported-case manifest, shim identity, protocol matrix, and expected alerts",
        "languages": ["tls", "cryptography", "protocol", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "reproducible-build-variation",
        "version": "organization-pinned-environment-matrix",
        "kind": "controlled-build-environment-variation-and-artifact-equivalence",
        "source": "Reproducible Builds environment-variation plan with digest-pinned toolchains, source, build instructions, variation matrix, artifacts, and diff classification",
        "languages": ["build", "supply-chain", "provenance", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "cisa-secure-by-design-negative-assurance",
        "version": "cisa-2025-policy-pinned",
        "kind": "secure-default-product-property-and-bad-practice-negative-testing",
        "source": "CISA Secure by Design and Product Security Bad Practices mapped to approved product properties and misuse or insecure-default cases",
        "languages": ["product", "security", "identity", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "amtso-malware-protection-evaluation",
        "version": "amtso-1.3-policy-pinned",
        "kind": "transparent-safe-antimalware-control-evaluation",
        "source": "AMTSO Testing Protocol Standard with approved harmless EICAR checks, inert organization fixtures, clean negatives, test plan, vendor communication record, and restoration evidence",
        "languages": ["malware", "endpoint", "email", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "dice-attestation-conformance",
        "version": "tcg-dice-1.2-errata-policy-pinned",
        "kind": "device-identity-layering-evidence-and-verifier-conformance",
        "source": "TCG DICE Attestation Architecture 1.2 plus published errata with approved certificate, evidence, endorsement, freshness, mutation, and verifier-decision cases",
        "languages": ["dice", "attestation", "firmware", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "telecom-security-controls-conformance",
        "version": "iso-27011-2024-policy-pinned",
        "kind": "telecommunications-control-applicability-and-evidence-conformance",
        "source": "Licensed ISO/IEC 27011:2024 criteria with approved telecom scope, control, shared-responsibility, service, network, and evidence cases",
        "languages": ["telecommunications", "network", "controls", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "nice-workforce-coverage",
        "version": "nice-components-2.2.0",
        "kind": "cybersecurity-workforce-task-knowledge-skill-coverage",
        "source": "NICE Framework Components 2.2.0 with organization role mappings, evidence-backed task coverage, qualification scope, separation of duties, and gap or drift cases",
        "languages": ["workforce", "competence", "governance", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "penetration-test-engagement-quality",
        "version": "crest-2022-ptes-policy-pinned",
        "kind": "penetration-test-scope-execution-evidence-remediation-and-retest-quality",
        "source": "CREST and PTES engagement criteria with approved rules of engagement, authorization, methodology, evidence, safety, remediation, retest, and reporting cases",
        "languages": ["penetration-testing", "adversarial", "governance", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "dora-delivery-outcomes",
        "version": "five-metrics-2026-policy-pinned",
        "kind": "software-delivery-throughput-instability-recovery-and-rework-outcomes",
        "source": "DORA five-metric definitions with immutable deployment and incident records, service boundaries, time windows, exclusions, data-quality checks, and uncertainty",
        "languages": ["delivery", "operations", "reliability", "multi"],
        "lane": "authorized-companion",
    },
)

_BENCHMARKS += (
    {
        "id": "structured-assurance-case-conformance",
        "version": "iso-15026-2-sacm-2.3-policy-pinned",
        "kind": "claim-argument-evidence-structure-semantics-and-mutation-conformance",
        "source": "ISO/IEC/IEEE 15026-2:2022 and OMG SACM 2.3 with approved assurance-case fixtures, schemas, semantic rules, and mutation operators",
        "languages": ["assurance-case", "sacm", "xml", "json", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "integrity-vv-conformance",
        "version": "ieee-1012-2024-policy-pinned",
        "kind": "integrity-level-verification-validation-independence-and-evidence-conformance",
        "source": "IEEE 1012-2024 with approved system, software, hardware, interface, reuse, COTS, independence, and integrity-level cases",
        "languages": ["systems", "software", "hardware", "verification", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "cmvp-fips-140-3-validation",
        "version": "cmvp-current-scheme-policy-pinned",
        "kind": "fips-140-3-cmvp-module-evidence-and-validation-status-conformance",
        "source": "Current NIST CMVP management manual, implementation guidance, SP 800-140 series, certificate status, and scheme-referenced ISO editions",
        "languages": ["cryptography", "module", "cmvp", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "iso-19790-24759-module-conformance",
        "version": "iso-19790-2025-24759-2025-policy-pinned",
        "kind": "international-cryptographic-module-requirement-and-test-method-conformance",
        "source": "Licensed ISO/IEC 19790:2025 and ISO/IEC 24759:2025 requirements, vendor evidence, test methods, and approved positive, negative, fault, and boundary cases",
        "languages": ["cryptography", "module", "laboratory", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "biometric-performance-pad",
        "version": "iso-19795-1-30107-3-30107-4-policy-pinned",
        "kind": "biometric-comparison-presentation-attack-and-demographic-performance-evaluation",
        "source": "ISO/IEC 19795-1, ISO/IEC 30107-3, applicable ISO/IEC 30107-4 mobile profile, and approved sequestered bona-fide, impostor, and attack-instrument corpora",
        "languages": ["biometrics", "identity", "statistics", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "service-management-security-integration",
        "version": "iso-20000-1-2018-amd1-2024-27013-2021-amd1-2024",
        "kind": "integrated-service-and-information-security-management-conformance",
        "source": "Licensed ISO/IEC 20000-1 and ISO/IEC 27013 criteria with approved service, change, release, configuration, supplier, incident, capacity, continuity, and improvement cases",
        "languages": ["service-management", "security", "operations", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "interlaboratory-proficiency-testing",
        "version": "iso-17043-2023-policy-pinned",
        "kind": "blinded-interlaboratory-proficiency-agreement-bias-and-drift-evaluation",
        "source": "ISO/IEC 17043:2023 with approved blinded items, assigned values, participant scopes, statistical design, homogeneity and stability evidence, and adjudication rules",
        "languages": ["laboratory", "proficiency", "assessment", "multi"],
        "lane": "authorized-companion",
    },
)

_BENCHMARKS += (
    {
        "id": "harmbench",
        "version": "icml-2024-policy-pinned-revision",
        "kind": "llm-automated-red-teaming-and-robust-refusal",
        "source": "Microsoft Research HarmBench with immutable behavior, attack, classifier, template, and split revisions",
        "languages": ["llm", "red-team", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "agentharm",
        "version": "inspect-evals-6-B-2026-08-21",
        "kind": "agentic-harmfulness-and-refusal-generalization",
        "source": "UK AI Safety Institute Inspect Evals AgentHarm 6-B with immutable task, tool, scorer, split, license, and environment revisions",
        "languages": ["agentic", "llm", "tools", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "garak-llm-probe-conformance",
        "version": "policy-pinned-release-and-probe-manifest",
        "kind": "llm-vulnerability-probe-execution-conformance",
        "source": "NVIDIA garak with pinned release, plugins, probes, detectors, generators, configuration, and dependencies",
        "languages": ["llm", "agentic", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "owasp-cornucopia-threat-model",
        "version": "2026-companion-edition-policy-pinned",
        "kind": "threat-model-scenario-coverage-and-mutation",
        "source": "OWASP Cornucopia web, mobile, and Companion Edition decks with licensed immutable card and mapping manifests",
        "languages": ["threat-model", "architecture", "llm", "cloud", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "nist-8286-enterprise-risk-register",
        "version": "revision-1-series-2025",
        "kind": "enterprise-cyber-risk-register-schema-rollup-and-prioritization",
        "source": "NIST IR 8286 Rev. 1 series and official risk register and risk detail record schemas",
        "languages": ["risk", "governance", "json", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "cis-ram-attack-path-analysis",
        "version": "2.2-policy-pinned",
        "kind": "reasonable-security-risk-analysis-and-attack-path-calibration",
        "source": "CIS RAM 2.2, organization-approved risk criteria, CIS Controls, Community Attack Model, and VERIS evidence",
        "languages": ["risk", "controls", "attack-path", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "square-quality-governance",
        "version": "iso-iec-25001-2014-confirmed-2026",
        "kind": "quality-requirements-evaluation-planning-and-management-conformance",
        "source": "licensed ISO IEC 25001 requirements and organization-approved SQuaRE plans, methods, tools, competence, and decision records",
        "languages": ["quality", "process", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "iso-42106-differentiated-ai-benchmarking",
        "version": "2026-licensed-policy-pinned",
        "kind": "context-and-complexity-differentiated-ai-quality-benchmarking",
        "source": "licensed ISO IEC TR 42106 guidance with organization-approved complexity, context, strata, quality-characteristic, and decision criteria",
        "languages": ["ai", "benchmark", "quality", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "enterprise-architecture-governance",
        "version": "licensed-policy-pinned-framework-set",
        "kind": "enterprise-architecture-model-governance-and-risk-traceability",
        "source": "licensed TOGAF 10th Edition, ArchiMate 3.2, COBIT 2019, and Open FAIR 2.0 criteria with organization architecture and risk cases",
        "languages": ["architecture", "governance", "risk", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "pyrit-ai-red-team",
        "version": "policy-pinned-release-scenario-and-environment",
        "kind": "generative-ai-multi-turn-red-team-orchestration",
        "source": "Microsoft PyRIT with immutable release, scenarios, objectives, targets, converters, scorers, datasets, configuration, and dependencies",
        "languages": ["llm", "agentic", "red-team", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "owasp-aisvs-conformance",
        "version": "1.0",
        "kind": "ai-application-security-requirement-level-conformance",
        "source": "OWASP AISVS 1.0 immutable requirements and organization-approved AI application fixtures",
        "languages": ["ai", "llm", "agentic", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "iso-25058-ai-quality-evaluation",
        "version": "2024-licensed-policy-pinned",
        "kind": "ai-system-quality-model-evaluation-conformance",
        "source": "licensed ISO IEC TS 25058 criteria with pinned AI quality models, contexts, measures, datasets, and acceptance decisions",
        "languages": ["ai", "quality", "evaluation", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "eucc-scheme-assurance",
        "version": "2024-482-amended-2025",
        "kind": "eu-common-criteria-scheme-certificate-and-assurance-continuity-conformance",
        "source": "official EUCC scheme, amendments, state-of-the-art documents, certificate records, and approved Common Criteria evaluation evidence",
        "languages": ["certification", "common-criteria", "product", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "cisa-secure-software-attestation",
        "version": "common-form-policy-pinned",
        "kind": "federal-software-producer-attestation-evidence-conformance",
        "source": "official CISA common form with product scope, signatory authority, SSDF claims, exceptions, and evidence package",
        "languages": ["supply-chain", "procurement", "release", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "ieee-7000-ai-ethics-conformance",
        "version": "7000-7001-7002-7003-7009-policy-pinned",
        "kind": "ethical-design-transparency-privacy-bias-and-fail-safe-conformance",
        "source": "licensed IEEE 7000-series criteria and organization-approved affected-stakeholder, transparency, privacy, bias, and fail-safe scenarios",
        "languages": ["ai", "ethics", "privacy", "safety", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "ai-use-case-security-privacy",
        "version": "iso-24030-2024-27563-2023-policy-pinned",
        "kind": "domain-specific-ai-use-case-security-and-privacy-assurance",
        "source": "licensed ISO IEC TR 24030 and TR 27563 criteria with approved domain use cases, threats, privacy risks, controls, and adverse cases",
        "languages": ["ai", "security", "privacy", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "it-quality-governance-assessor-agreement",
        "version": "iso-38500-2024-9001-2026-policy-pinned",
        "kind": "governing-body-it-and-quality-management-assessor-agreement",
        "source": "licensed ISO IEC 38500 and ISO 9001 criteria with blinded governance, quality, risk, performance, conformance, and improvement cases",
        "languages": ["governance", "quality", "management", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "nist-csf-profile-gap-reassessment",
        "version": "csf-2.0-sp-1301-2024",
        "kind": "current-target-profile-gap-action-and-reassessment-conformance",
        "source": "NIST CSF 2.0 and SP 1301 with official identifiers and organization-approved current, target, gap, action, and reassessment fixtures",
        "languages": ["governance", "risk", "controls", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "mlcommons-ailuminate-safety",
        "version": "1.0-policy-pinned-official",
        "kind": "mlcommons-general-purpose-ai-safety-assessment",
        "source": "MLCommons AILuminate Safety official release, assessment standard, evaluator ensemble, public-private prompt split, locale, and reference-system policy",
        "languages": ["llm", "safety", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "mlcommons-ailuminate-jailbreak",
        "version": "0.5-policy-pinned-official",
        "kind": "mlcommons-ai-jailbreak-resistance-assessment",
        "source": "MLCommons AILuminate Jailbreak official release with attack set, safety baseline, evaluator ensemble, grade thresholds, and protected cases",
        "languages": ["llm", "security", "jailbreak", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "privacy-engineering-pet-conformance",
        "version": "iso-27561-27564-27565-policy-pinned",
        "kind": "privacy-operationalisation-model-and-zero-knowledge-proof-conformance",
        "source": "licensed ISO IEC 27561, TS 27564, and 27565 criteria with approved privacy models, unlinkability cases, ZKP statements, implementations, and verifier vectors",
        "languages": ["privacy", "cryptography", "architecture", "multi"],
        "lane": "authorized-companion",
    },
)

_BENCHMARKS += (
    {
        "id": "mcp-client-server-security-conformance",
        "version": "2025-11-25-with-owasp-security-cases",
        "kind": "model-context-protocol-interoperability-authorization-and-tool-security-conformance",
        "source": "MCP 2025-11-25 schemas and security requirements plus organization-approved OWASP-informed adversarial client, server, proxy, and tool fixtures",
        "languages": ["mcp", "json-rpc", "oauth", "agentic", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "aws-fsbp-securityhub-conformance",
        "version": "fsbp-1.0-control-snapshot-policy-pinned",
        "kind": "aws-security-hub-foundational-control-posture-conformance",
        "source": "AWS Security Hub FSBP control catalog, account and region inventory, findings export, suppressions, and organization-approved exceptions",
        "languages": ["aws", "cloudformation", "terraform", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "microsoft-mcsb-defender-conformance",
        "version": "mcsb-v1-control-snapshot-policy-pinned",
        "kind": "microsoft-cloud-security-benchmark-posture-conformance",
        "source": "MCSB v1 controls and baselines with Defender for Cloud assessments, Azure resource inventory, exemptions, and organization-approved applicability",
        "languages": ["azure", "bicep", "terraform", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "gcp-enterprise-foundations-conformance",
        "version": "blueprint-reviewed-2025-05-15-policy-pinned",
        "kind": "google-cloud-enterprise-foundation-policy-architecture-and-detection-conformance",
        "source": "Google Cloud Enterprise Foundations Blueprint, Terraform foundation revision, organization policy inventory, Security Command Center findings, and approved deviations",
        "languages": ["gcp", "terraform", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "first-csirt-psirt-maturity-assessment",
        "version": "csirt-2.1-psirt-1.1-maturity-policy-pinned",
        "kind": "incident-and-product-response-service-capability-assessor-agreement",
        "source": "FIRST CSIRT and PSIRT Services Frameworks, PSIRT Maturity criteria, service metrics, and organization-approved blinded operating scenarios",
        "languages": [
            "incident-response",
            "vulnerability-response",
            "governance",
            "multi",
        ],
        "lane": "authorized-companion",
    },
    {
        "id": "memory-safety-engineering-conformance",
        "version": "cisa-roadmap-2023-guidance-2025-policy-pinned",
        "kind": "memory-unsafe-inventory-hardening-testing-and-migration-conformance",
        "source": "CISA memory-safe roadmap and buffer-overflow guidance with repository-specific unsafe-language, FFI, hardening, sanitizer, fuzzing, and migration evidence",
        "languages": ["c", "cpp", "rust", "swift", "go", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "ieee-ai-governance-wellbeing-assessment",
        "version": "ieee-2863-2026-7010-2020-policy-pinned",
        "kind": "organizational-ai-governance-and-human-wellbeing-assessor-agreement",
        "source": "licensed IEEE 2863 and IEEE 7010 criteria with blinded governance, stakeholder, impact, indicator, tradeoff, monitoring, and escalation scenarios",
        "languages": ["ai", "governance", "human-impact", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "organizational-resilience-bia-exercise",
        "version": "iso-22316-2017-ts-22317-2021-policy-pinned",
        "kind": "organizational-resilience-and-business-impact-analysis-conformance",
        "source": "licensed ISO 22316 and ISO TS 22317 criteria with approved dependency, impact-tolerance, recovery-objective, disruption, restoration, and reassessment cases",
        "languages": ["resilience", "continuity", "architecture", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "openssf-best-practices-badge-conformance",
        "version": "baseline-and-metal-criteria-policy-pinned-2026-08-28",
        "kind": "open-source-project-practice-claim-and-evidence-conformance",
        "source": "OpenSSF Best Practices Badge baseline and metal criteria with project response export, repository evidence, automation proposals, and negative claim fixtures",
        "languages": ["open-source", "supply-chain", "quality", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "isms-implementation-process-assessment",
        "version": "iso-27003-2017-ts-27022-2021-policy-pinned",
        "kind": "isms-implementation-and-process-capability-assessor-agreement",
        "source": "licensed ISO IEC 27003 and ISO IEC TS 27022 criteria with organization-approved ISMS implementation, process, measurement, tailoring, and improvement cases",
        "languages": ["isms", "process", "governance", "multi"],
        "lane": "authorized-companion",
    },
)

_BENCHMARKS += (
    {
        "id": "a2a-protocol-security-conformance",
        "version": "1.0.0",
        "kind": "agent-to-agent-schema-binding-identity-authorization-and-task-conformance",
        "source": "A2A 1.0.0 normative protocol definition, official compatibility materials, and organization-approved adversarial agent fixtures",
        "languages": ["a2a", "protobuf", "json-rpc", "grpc", "http", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "sesip-iot-platform-evaluation-conformance",
        "version": "sesip-1.2-en-17927-2023-policy-pinned",
        "kind": "iot-platform-functional-process-and-assurance-evaluation-conformance",
        "source": "GlobalPlatform SESIP 1.2 and EN 17927:2023 with licensed criteria, approved profiles, reusable component evidence, and laboratory decisions",
        "languages": ["iot", "firmware", "hardware", "embedded", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "first-tlp-iep-information-handling-conformance",
        "version": "tlp-2.0-iep-2.0",
        "kind": "cybersecurity-information-marking-use-redistribution-and-policy-conformance",
        "source": "FIRST TLP 2.0 and IEP 2.0 definitions, JSON specification, standard policies, and organization-approved exchange fixtures",
        "languages": ["threat-intelligence", "stix", "taxii", "json", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "veris-incident-schema-conformance",
        "version": "veris-1.3.6-policy-pinned",
        "kind": "incident-classification-schema-quality-and-round-trip-conformance",
        "source": "Policy-pinned VERIS schema with public examples, organization-approved incident records, controlled vocabulary, and lossless round-trip oracles",
        "languages": ["incident", "json", "analytics", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "w3c-web-platform-defense-conformance",
        "version": "csp2-2016-sri1-2016",
        "kind": "browser-content-policy-and-subresource-integrity-conformance",
        "source": "W3C CSP Level 2 and Subresource Integrity Recommendations with pinned Web Platform Tests and application-owned negative fixtures",
        "languages": ["html", "javascript", "http", "browser", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "dora-level2-technical-standards-conformance",
        "version": "eu-1772-1774-2956-301-302-1190-policy-pinned",
        "kind": "financial-ict-risk-incident-register-reporting-and-tlpt-conformance",
        "source": "In-force DORA delegated and implementing technical acts with approved financial-entity applicability, reporting, register, and TLPT fixtures",
        "languages": ["financial", "risk", "incident", "tlpt", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "ffiec-it-handbook-assessment",
        "version": "dam-2024-aio-2021-information-security-2016",
        "kind": "us-financial-technology-examination-assessor-agreement",
        "source": "FFIEC Development Acquisition and Maintenance, Architecture Infrastructure and Operations, and Information Security booklets with approved examination cases",
        "languages": ["banking", "architecture", "operations", "security", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "bsi-c5-cloud-assurance-assessment",
        "version": "c5-2020-policy-pinned",
        "kind": "cloud-control-attestation-and-customer-control-assessor-agreement",
        "source": "BSI C5:2020 criteria and report-evaluation guidance with licensed criteria, service descriptions, audit reports, customer controls, and blinded cases",
        "languages": ["cloud", "audit", "governance", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "fcc-cyber-trust-mark-conformance",
        "version": "fcc-24-26-policy-pinned",
        "kind": "consumer-iot-label-testing-application-and-registry-conformance",
        "source": "FCC 24-26 IoT Labeling Program rules with approved baseline, recognized laboratory, product, application, registry, renewal, and misuse fixtures",
        "languages": ["iot", "consumer-product", "labeling", "multi"],
        "lane": "authorized-companion",
    },
)

_BENCHMARKS += (
    {
        "id": "openid-digital-credential-conformance",
        "version": "vc-2.0-openid4vp-1.0-openid4vci-1.0-haip-1.0",
        "kind": "credential-issuer-wallet-verifier-security-and-interoperability-conformance",
        "source": "W3C Verifiable Credentials 2.0 and final OpenID4VP OpenID4VCI and HAIP specifications with official conformance-suite profiles",
        "languages": ["identity", "oauth", "json-ld", "credential", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "cisa-scuba-saas-posture-conformance",
        "version": "2026-08-29-policy-snapshot",
        "kind": "m365-and-google-workspace-secure-configuration-conformance",
        "source": "CISA SCuBA M365 and Google Workspace baselines with pinned ScubaGear and ScubaGoggles releases and organization-approved tenant fixtures",
        "languages": ["m365", "google-workspace", "saas", "identity", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "cis-kubernetes-hardening-conformance",
        "version": "cis-kubernetes-2.0.1",
        "kind": "kubernetes-control-plane-node-and-policy-hardening-conformance",
        "source": "Licensed CIS Kubernetes Benchmark 2.0.1 requirements with approved CIS-CAT or equivalent normalized evidence and negative fixtures",
        "languages": ["kubernetes", "yaml", "container", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "linddun-privacy-threat-model-conformance",
        "version": "pro-2026-08-29-policy-snapshot",
        "kind": "privacy-dfd-threat-elicitation-and-mitigation-assessor-agreement",
        "source": "Policy-pinned LINDDUN PRO threat trees, mapping table, structured knowledge, DFDs, golden cases, and omission mutations",
        "languages": ["privacy", "threat-model", "dfd", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "owasp-benchmark-ast-modality-comparison",
        "version": "policy-pinned-cross-modality",
        "kind": "sast-dast-iast-matched-corpus-classification",
        "source": "Pinned OWASP Benchmark cases and expected results executed independently through SAST DAST and IAST lanes with matched scope",
        "languages": ["java", "python", "sast", "dast", "iast"],
        "lane": "authorized-companion",
    },
    {
        "id": "rasp-prevention-effectiveness",
        "version": "organization-pinned",
        "kind": "runtime-application-self-protection-detection-prevention-and-utility",
        "source": "Organization-approved benign and attack transaction corpus with instrumentation health, route coverage, prevention, latency, utility, and bypass oracles",
        "languages": ["runtime", "web", "api", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "gsma-nesas-scas-assurance",
        "version": "nesas-3.0-scas-product-policy-pinned",
        "kind": "telecom-vendor-process-and-network-product-security-assurance",
        "source": "GSMA NESAS 3.0 scheme documents and product-applicable 3GPP SCAS requirements with authorized laboratory evidence",
        "languages": ["telecom", "network-equipment", "firmware", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "tisax-vda-isa-assessment",
        "version": "isa-6.0.3-handbook-policy-pinned",
        "kind": "automotive-information-security-assessor-agreement",
        "source": "VDA ISA 6.0.3 and ENX TISAX process material with licensed criteria and blinded scope, objective, site, maturity, evidence, and result cases",
        "languages": ["automotive", "information-security", "assessment", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "c2pa-content-credentials-conformance",
        "version": "2.4",
        "kind": "media-provenance-manifest-trust-and-tamper-conformance",
        "source": "C2PA 2.4 specification, conformance assets, trust material, ingredients, assertions, soft bindings, and organization-approved adversarial fixtures",
        "languages": ["media", "json", "cbor", "cryptography", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "pci-payment-acceptance-conformance",
        "version": "mpoc-1.x-p2pe-3.2-policy-pinned",
        "kind": "mobile-payment-acceptance-and-point-to-point-encryption-conformance",
        "source": "Licensed PCI MPoC and P2PE requirements with approved SDK, application, device, key, encryption, decryption, monitoring, laboratory, and listing fixtures",
        "languages": ["payment", "mobile", "cryptography", "multi"],
        "lane": "authorized-companion",
    },
)

_BENCHMARKS += (
    {
        "id": "fedramp-20x-continuous-validation",
        "version": "consolidated-rules-2026-classes-a-b-c",
        "kind": "persistent-key-security-indicator-and-independent-validation-conformance",
        "source": "FedRAMP 20x Consolidated Rules for 2026 with class-specific Key Security Indicators, persistent certification data, independent validation, and marketplace status",
        "languages": ["cloud", "federal", "continuous-assurance", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "fido2-authenticator-conformance",
        "version": "ctap-2.2-mds-3.1-policy-pinned",
        "kind": "fido2-client-authenticator-metadata-and-certification-conformance",
        "source": "FIDO CTAP 2.2 Proposed Standard, Metadata Service 3.1, WebAuthn, functional certification tools, and authorized authenticator fixtures",
        "languages": ["fido2", "webauthn", "cbor", "hardware", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "eudi-wallet-functional-conformance",
        "version": "arf-3.0.0-fcaf-2026-07-23",
        "kind": "eudi-wallet-issuer-relying-party-functional-security-and-privacy-conformance",
        "source": "EUDI Regulation, consolidated implementing acts, ARF 3.0.0, Functional Conformance Assessment Framework, and reference implementation fixtures",
        "languages": ["identity", "wallet", "credential", "mobile", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "hitrust-csf-assessment",
        "version": "csf-11.8.0-handbook-1.2-policy-pinned",
        "kind": "hitrust-e1-i1-r2-scope-maturity-and-assessor-agreement",
        "source": "Licensed HITRUST CSF 11.8.0 and Assessment Handbook 1.2 with e1 i1 and r2 scope, maturity, evidence, sampling, quality review, and result cases",
        "languages": ["healthcare", "governance", "assessment", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "pci-secure-software-conformance",
        "version": "secure-software-2.0-secure-slc-1.1",
        "kind": "payment-software-product-and-lifecycle-validation-conformance",
        "source": "Licensed PCI Secure Software 2.0 and Secure SLC 1.1 requirements, program guides, sensitive-asset guidance, report templates, and assessor decisions",
        "languages": ["payment", "software", "lifecycle", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "nis2-implementing-regulation-conformance",
        "version": "eu-2024-2690-enisa-guidance-1.0-mapping-1.2",
        "kind": "nis2-technical-methodological-control-and-evidence-conformance",
        "source": "Commission Implementing Regulation EU 2024/2690 and ENISA technical implementation guidance with sector applicability and evidence mappings",
        "languages": ["regulation", "cloud", "managed-service", "risk", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "nist-supplier-due-diligence",
        "version": "sp-1326-2026",
        "kind": "supplier-cybersecurity-due-diligence-evidence-and-decision-conformance",
        "source": "NIST SP 1326 final quick-start guide with organization-approved supplier cases, authoritative-source evidence, risk decisions, and reassessment triggers",
        "languages": ["supplier", "supply-chain", "acquisition", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "owasp-samm-assessment-benchmark",
        "version": "samm-2.1.0-benchmark-policy-pinned",
        "kind": "software-assurance-maturity-assessor-agreement-and-cohort-comparison",
        "source": "OWASP SAMM 2.1 assessment toolbox, quality criteria, organization-approved blinded cases, and privacy-preserving benchmark cohort snapshot",
        "languages": ["software-assurance", "maturity", "governance", "multi"],
        "lane": "authorized-companion",
    },
)


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
            ],
            "procedures": [
                (
                    "DISA-STIG",
                    "STIG-SCAP-ASSESSMENT",
                    "Execute the pinned application, operating-system, container, Kubernetes, database, and platform checks against disposable representative targets and review manual checks.",
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
            ],
            "procedures": [
                (
                    "IEC-62443-2-3",
                    "PATCH-DEPLOYMENT-ROLLBACK-EXERCISE",
                    "Execute an authorized representative IACS patch assessment, staged deployment, failure detection, rollback, compensating-control, and restoration exercise.",
                    "dynamic",
                    True,
                    ["benchmark-scorecard.json", "operational-trend.json"],
                ),
            ],
        },
        "continuing-airworthiness-security": {
            "standards": ["RTCA-DO-355A", "RTCA-DO-326A", "RTCA-DO-356A"],
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
            ],
            "procedures": [
                (
                    "RTCA-DO-355A",
                    "IN-SERVICE-SECURITY-EVENT-EXERCISE",
                    "Exercise an authorized in-service vulnerability from intake through safety assessment, affected-configuration identification, mitigation approval, operator communication, and closure.",
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
            ],
            "procedures": [
                (
                    "SWIFT-CSCF",
                    "INDEPENDENT-CSCF-ASSESSMENT",
                    "Perform a policy-pinned independent assessment with architecture scope, sampling, evidence authenticity, control design and operation, exceptions, findings, and attestation handoff.",
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


def _validate_builtin_catalog(
    standards: tuple[dict[str, Any], ...] | None = None,
    profiles: dict[str, dict[str, Any]] | None = None,
    benchmarks: tuple[dict[str, Any], ...] | None = None,
) -> None:
    """Fail closed when built-in catalog identities or references are corrupt."""
    standards = _STANDARDS if standards is None else standards
    profiles = _ASSURANCE_PROFILES if profiles is None else profiles
    benchmarks = _BENCHMARKS if benchmarks is None else benchmarks

    standard_ids = [item.get("id") for item in standards]
    benchmark_ids = [item.get("id") for item in benchmarks]
    for label, identifiers in (
        ("standard", standard_ids),
        ("benchmark", benchmark_ids),
    ):
        if any(
            not isinstance(identifier, str) or not identifier
            for identifier in identifiers
        ):
            raise ValueError(f"built-in {label} catalog contains an invalid identifier")
        if len(identifiers) != len(set(identifiers)):
            raise ValueError(f"built-in {label} catalog contains duplicate identifiers")

    known_standards = set(standard_ids)
    for profile_id, profile in profiles.items():
        if not profile_id or not isinstance(profile, dict):
            raise ValueError("built-in assurance profile has an invalid identity")
        references = list(profile.get("standards", []))
        controls = profile.get("controls", [])
        procedures = profile.get("procedures", [])
        if not references or not controls or not procedures:
            raise ValueError(
                f"assurance profile {profile_id!r} is structurally incomplete"
            )
        for row_name, rows, minimum_size in (
            ("control", controls, 4),
            ("procedure", procedures, 6),
        ):
            for row in rows:
                if not isinstance(row, tuple) or len(row) < minimum_size:
                    raise ValueError(
                        f"assurance profile {profile_id!r} has an invalid {row_name}"
                    )
                references.append(row[0])
        unresolved = sorted(
            {
                reference
                for reference in references
                if not isinstance(reference, str) or reference not in known_standards
            },
            key=str,
        )
        if unresolved:
            raise ValueError(
                f"assurance profile {profile_id!r} references unknown standards: "
                + ", ".join(map(str, unresolved))
            )


_validate_builtin_catalog()


_INTEROPERABILITY = (
    ("SARIF", "2.1.0", ("results.sarif",)),
    ("CycloneDX", "1.7", ("sbom.cdx.json", "artifact-sbom.cdx.json")),
    ("SPDX", "2.x/3.x", ("reuse-compliance.json",)),
    ("CycloneDX-VEX", "1.7", ("risk-intelligence.json",)),
    ("OpenVEX", "0.2", ("risk-intelligence.json",)),
    ("CSAF-VEX", "2.0", ("risk-intelligence.json",)),
    ("SCAP", "1.4", ("scap-results.xml", "scap-results.json")),
    ("OSCAL", "1.2.2", ("oscal-assessment-results.json",)),
    ("STIX", "2.1", ("security-automation-interoperability.json",)),
    ("TAXII", "2.1", ("security-automation-interoperability.json",)),
    ("FIRST-TLP", "2.0", ("security-automation-interoperability.json",)),
    ("FIRST-IEP", "2.0", ("security-automation-interoperability.json",)),
    ("VERIS", "1.3.6-policy-pinned", ("security-automation-interoperability.json",)),
    ("A2A", "1.0.0", ("security-automation-interoperability.json",)),
    ("W3C-VC", "2.0", ("security-automation-interoperability.json",)),
    ("OpenID4VP", "1.0", ("security-automation-interoperability.json",)),
    ("OpenID4VCI", "1.0", ("security-automation-interoperability.json",)),
    ("C2PA", "2.4", ("trust-policy-attestation.json",)),
    ("CACAO", "2.0", ("security-automation-interoperability.json",)),
    ("OpenC2", "1.0", ("security-automation-interoperability.json",)),
    ("OCSF", "policy-pinned", ("security-automation-interoperability.json",)),
    ("SCITT", "RFC-9943", ("security-automation-interoperability.json",)),
    ("COSE-Receipts", "RFC-9942", ("security-automation-interoperability.json",)),
    ("OpenAPI", "3.1.1-policy-pinned", ("security-automation-interoperability.json",)),
    ("AsyncAPI", "3.0.0-policy-pinned", ("security-automation-interoperability.json",)),
    ("GraphQL", "september-2025", ("security-automation-interoperability.json",)),
    ("JSON-Schema", "2020-12", ("security-automation-interoperability.json",)),
    (
        "OpenTelemetry-SemConv",
        "1.44.0-policy-pinned",
        ("security-automation-interoperability.json",),
    ),
)


def _evidence_stage(
    identifier: str, required: tuple[str, ...], artifacts: dict[str, Any]
) -> dict[str, Any]:
    present = [name for name in required if _complete_artifact(artifacts.get(name))]
    missing = [name for name in required if name not in present]
    return {
        "id": identifier,
        "evidence_required": list(required),
        "evidence_present": present,
        "complete": bool(required) and not missing,
        "gaps": [f"missing or incomplete artifact: {name}" for name in missing],
    }


def _lifecycle_traceability(
    artifacts: dict[str, Any], source_sha256: str
) -> dict[str, Any]:
    stages = [
        _evidence_stage(
            "requirements", ("security-requirements-coverage.json",), artifacts
        ),
        _evidence_stage(
            "architecture",
            ("static-architecture.json", "architecture-history.json"),
            artifacts,
        ),
        _evidence_stage("implementation", ("source-inventory.json",), artifacts),
        _evidence_stage(
            "verification", ("test-evidence.json", "effectiveness.json"), artifacts
        ),
        _evidence_stage("release", ("release-readiness.json",), artifacts),
        _evidence_stage("operation", ("operational-trend.json",), artifacts),
        _evidence_stage("retirement", ("closure-plan.json",), artifacts),
    ]
    requirements = artifacts.get("security-requirements-coverage.json")
    applicable = (
        requirements.get("applicable_requirements", 0)
        if isinstance(requirements, dict)
        else 0
    )
    evidenced = (
        requirements.get("evidenced_requirements", 0)
        if isinstance(requirements, dict)
        else 0
    )
    trace_complete = bool(
        isinstance(applicable, int)
        and not isinstance(applicable, bool)
        and isinstance(evidenced, int)
        and not isinstance(evidenced, bool)
        and applicable > 0
        and evidenced == applicable
        and requirements.get("complete") is True
        if isinstance(requirements, dict)
        else False
    )
    graph = _lifecycle_trace_graph(artifacts, source_sha256)
    complete = (
        bool(source_sha256)
        and trace_complete
        and all(stage["complete"] for stage in stages)
        and graph["complete"] is True
    )
    gaps = [gap for stage in stages for gap in stage["gaps"]]
    if not source_sha256:
        gaps.append("source inventory digest is missing")
    if not trace_complete:
        gaps.append("bidirectional requirements evidence is incomplete")
    gaps.extend(graph["gaps"])
    return {
        "schema_version": "1.0",
        "analysis": "software-and-system-life-cycle-traceability",
        "complete": complete,
        "source_sha256": source_sha256,
        "stages_assessed": len(stages),
        "stages_complete": sum(stage["complete"] for stage in stages),
        "stages": stages,
        "requirements_traceability": {
            "applicable_requirements": applicable
            if isinstance(applicable, int) and not isinstance(applicable, bool)
            else 0,
            "evidenced_requirements": evidenced
            if isinstance(evidenced, int) and not isinstance(evidenced, bool)
            else 0,
            "bidirectional_trace_complete": trace_complete,
        },
        "graph_traceability": graph,
        "gaps": list(dict.fromkeys(gaps))[:100],
        "claim_boundary": (
            "Stage evidence and requirement counts establish an auditable traceability "
            "surface; they do not prove that every life-cycle decision is correct."
        ),
    }


def _lifecycle_trace_graph(
    artifacts: dict[str, Any], source_sha256: str
) -> dict[str, Any]:
    raw = artifacts.get("lifecycle-traceability-evidence.json")
    gaps: list[str] = []
    expected_root = {
        "schema_version",
        "source_sha256",
        "nodes",
        "links",
        "change_sets",
        "review",
    }
    if not isinstance(raw, dict):
        gaps.append("governed lifecycle trace graph is missing")
        raw = {}
    elif set(raw) != expected_root or raw.get("schema_version") != "1.0":
        gaps.append("lifecycle trace graph does not match the governed root contract")
    if raw.get("source_sha256") != source_sha256 or not _digest(source_sha256):
        gaps.append("lifecycle trace graph is not bound to the scanned source")

    stages = (
        "requirements",
        "architecture",
        "implementation",
        "verification",
        "release",
        "operation",
        "retirement",
    )
    stage_order = {stage: index for index, stage in enumerate(stages)}
    raw_nodes = raw.get("nodes")
    raw_links = raw.get("links")
    raw_changes = raw.get("change_sets")
    nodes = raw_nodes if isinstance(raw_nodes, list) else []
    links = raw_links if isinstance(raw_links, list) else []
    changes = raw_changes if isinstance(raw_changes, list) else []
    if not isinstance(raw_nodes, list):
        gaps.append("lifecycle nodes must be an array")
    if not isinstance(raw_links, list):
        gaps.append("lifecycle links must be an array")
    if not isinstance(raw_changes, list):
        gaps.append("lifecycle change sets must be an array")
    if len(nodes) > 50_000 or len(links) > 100_000 or len(changes) > 10_000:
        gaps.append("lifecycle trace graph exceeds a governed record limit")
    nodes = nodes[:50_000]
    links = links[:100_000]
    changes = changes[:10_000]

    node_ids: set[str] = set()
    node_stages: dict[str, str] = {}
    applicable_nodes: set[str] = set()
    stages_present: set[str] = set()
    for index, node in enumerate(nodes):
        if not isinstance(node, dict) or set(node) != {
            "id",
            "stage",
            "artifact",
            "sha256",
            "subject_sha256",
            "applicable",
        }:
            gaps.append(f"lifecycle node {index} does not match its governed contract")
            continue
        identifier = str(node.get("id") or "")
        stage = str(node.get("stage") or "")
        if (
            not _text(identifier, 200)
            or identifier in node_ids
            or stage not in stage_order
            or not _artifact_name(node.get("artifact"))
            or not _digest(str(node.get("sha256") or ""))
            or node.get("subject_sha256") != source_sha256
            or not isinstance(node.get("applicable"), bool)
        ):
            gaps.append(f"lifecycle node {index} is invalid or source-unbound")
            continue
        node_ids.add(identifier)
        node_stages[identifier] = stage
        stages_present.add(stage)
        if node["applicable"] is True:
            applicable_nodes.add(identifier)

    for stage in stages:
        if stage not in stages_present:
            gaps.append(f"lifecycle graph has no node for stage: {stage}")

    outgoing: dict[str, set[str]] = {identifier: set() for identifier in node_ids}
    incoming: dict[str, set[str]] = {identifier: set() for identifier in node_ids}
    seen_links: set[tuple[str, str, str]] = set()
    allowed_link_types = {
        "derives",
        "implements",
        "verifies",
        "releases",
        "operates",
        "retires",
        "impacts",
    }
    for index, link in enumerate(links):
        if not isinstance(link, dict) or set(link) != {
            "source",
            "target",
            "type",
            "evidence_sha256",
        }:
            gaps.append(f"lifecycle link {index} does not match its governed contract")
            continue
        source = str(link.get("source") or "")
        target = str(link.get("target") or "")
        relation = str(link.get("type") or "")
        identity = (source, target, relation)
        if (
            source not in node_ids
            or target not in node_ids
            or source == target
            or relation not in allowed_link_types
            or identity in seen_links
            or not _digest(str(link.get("evidence_sha256") or ""))
        ):
            gaps.append(f"lifecycle link {index} is dangling, duplicate, or invalid")
            continue
        if stage_order[node_stages[source]] >= stage_order[node_stages[target]]:
            gaps.append(
                f"lifecycle link reverses stage direction: {source} -> {target}"
            )
            continue
        seen_links.add(identity)
        outgoing[source].add(target)
        incoming[target].add(source)

    for identifier in sorted(applicable_nodes):
        stage = node_stages[identifier]
        if stage != "requirements" and not incoming[identifier]:
            gaps.append(
                f"applicable lifecycle node has no upstream trace: {identifier}"
            )
        if stage != "retirement" and not outgoing[identifier]:
            gaps.append(
                f"applicable lifecycle node has no downstream trace: {identifier}"
            )

    requirement_nodes = {
        identifier
        for identifier in applicable_nodes
        if node_stages[identifier] == "requirements"
    }
    if not requirement_nodes:
        gaps.append("lifecycle graph has no applicable requirement node")
    nodes_reaching_retirement: set[str] = set()
    for requirement in requirement_nodes:
        pending = [requirement]
        visited = {requirement}
        reached_stages = {"requirements"}
        while pending:
            current = pending.pop()
            for target in outgoing[current]:
                reached_stages.add(node_stages[target])
                if target not in visited:
                    visited.add(target)
                    pending.append(target)
        if set(stages) <= reached_stages:
            nodes_reaching_retirement.add(requirement)
        else:
            missing = ", ".join(
                stage for stage in stages if stage not in reached_stages
            )
            gaps.append(
                f"requirement lacks end-to-end lifecycle coverage: {requirement} ({missing})"
            )

    change_ids: set[str] = set()
    verified_changes = 0
    for index, change in enumerate(changes):
        if not isinstance(change, dict) or set(change) != {
            "id",
            "changed_node_ids",
            "impact_node_ids",
            "verified",
            "evidence_sha256",
        }:
            gaps.append(f"change set {index} does not match its governed contract")
            continue
        identifier = str(change.get("id") or "")
        changed = change.get("changed_node_ids")
        impacts = change.get("impact_node_ids")
        valid_nodes = (
            isinstance(changed, list)
            and bool(changed)
            and isinstance(impacts, list)
            and bool(impacts)
            and len(changed) == len(set(changed))
            and len(impacts) == len(set(impacts))
            and set(changed) <= node_ids
            and set(impacts) <= node_ids
        )
        if (
            not _text(identifier, 200)
            or identifier in change_ids
            or not valid_nodes
            or not isinstance(change.get("verified"), bool)
            or not _digest(str(change.get("evidence_sha256") or ""))
        ):
            gaps.append(f"change set {index} is invalid or references unknown nodes")
            continue
        change_ids.add(identifier)
        changed_ids = set(cast(list[str], changed))
        impact_ids = set(cast(list[str], impacts))
        expected_impacts: set[str] = set()
        pending = list(changed_ids)
        visited = set(changed_ids)
        while pending:
            current = pending.pop()
            for target in outgoing[current]:
                expected_impacts.add(target)
                if target not in visited:
                    visited.add(target)
                    pending.append(target)
        if changed_ids & impact_ids or impact_ids != expected_impacts:
            gaps.append(
                f"change set does not exactly cover downstream graph impact: {identifier}"
            )
        if change["verified"] is True:
            verified_changes += 1
        else:
            gaps.append(f"change impact is not independently verified: {identifier}")
    if not change_ids:
        gaps.append("lifecycle graph has no verified change-impact sample")

    review = raw.get("review")
    reviewer_count = 0
    approved = False
    if isinstance(review, dict):
        reviewers = review.get("independent_reviewers")
        reviewer_count = (
            len(reviewers)
            if isinstance(reviewers, list)
            and len(reviewers) == len(set(reviewers))
            and all(_text(value, 200) for value in reviewers)
            else 0
        )
        approved = review.get("approved") is True
    review_time_valid = bool(
        isinstance(review, dict) and _iso_timestamp(review.get("reviewed_at"))
    )
    if review_time_valid:
        try:
            review_record = cast(dict[str, Any], review)
            review_time_valid = datetime.fromisoformat(
                str(review_record["reviewed_at"]).replace("Z", "+00:00")
            ) <= datetime.now(UTC)
        except ValueError:
            review_time_valid = False
    if (
        not isinstance(review, dict)
        or set(review)
        != {"reviewed_at", "independent_reviewers", "approved", "approval_sha256"}
        or not review_time_valid
        or reviewer_count < 2
        or not approved
        or not _digest(str(review.get("approval_sha256") or ""))
    ):
        gaps.append("independent lifecycle trace review and approval are incomplete")

    unique_gaps = list(dict.fromkeys(gaps))[:100]
    return {
        "applicable": isinstance(
            artifacts.get("lifecycle-traceability-evidence.json"), dict
        ),
        "nodes": len(node_ids),
        "links": len(seen_links),
        "applicable_nodes": len(applicable_nodes),
        "requirements_with_end_to_end_trace": len(nodes_reaching_retirement),
        "change_sets": len(change_ids),
        "verified_change_sets": verified_changes,
        "independent_reviewers": reviewer_count,
        "approved": approved,
        "complete": not unique_gaps,
        "gaps": unique_gaps,
    }


def _architecture_evaluation(artifacts: dict[str, Any]) -> dict[str, Any]:
    criteria = [
        _evidence_stage("stakeholder-concerns", ("domain-assurance.json",), artifacts),
        _evidence_stage(
            "quality-attributes",
            ("static-architecture.json", "code-health.json"),
            artifacts,
        ),
        _evidence_stage("risk-and-threat-paths", ("risk-paths.json",), artifacts),
        _evidence_stage(
            "decisions-and-change", ("architecture-history.json",), artifacts
        ),
        _evidence_stage(
            "structural-corroboration", ("structural-synthesis.json",), artifacts
        ),
        _evidence_stage(
            "independent-review", ("audit-package-verification.json",), artifacts
        ),
    ]
    gaps = [gap for criterion in criteria for gap in criterion["gaps"]]
    return {
        "schema_version": "1.0",
        "analysis": "scenario-based-architecture-evaluation",
        "complete": all(criterion["complete"] for criterion in criteria),
        "criteria_assessed": len(criteria),
        "criteria_satisfied": sum(criterion["complete"] for criterion in criteria),
        "criteria": criteria,
        "gaps": list(dict.fromkeys(gaps))[:100],
        "claim_boundary": (
            "Evidence-surface completion supports architecture evaluation but does not "
            "replace stakeholder judgment or certify an architecture."
        ),
    }


def _process_capability_assessment(artifacts: dict[str, Any]) -> dict[str, Any]:
    definitions = (
        (
            "requirements",
            ("security-requirements-coverage.json", "lifecycle-traceability.json"),
        ),
        (
            "implementation-quality",
            ("code-health.json", "static-architecture.json"),
        ),
        ("verification", ("test-evidence.json", "effectiveness.json")),
        (
            "build-and-release",
            ("release-readiness.json", "security-passport.json"),
        ),
        (
            "vulnerability-response",
            ("risk-intelligence.json", "closure-plan.json"),
        ),
        (
            "incident-and-operation",
            ("operational-trend.json", "procedure-assessment.json"),
        ),
        (
            "governance-and-improvement",
            ("capability-manifest.json", "audit-package-verification.json"),
        ),
    )
    dimensions: list[dict[str, Any]] = []
    for identifier, required in definitions:
        present = [name for name in required if name in artifacts]
        complete_evidence = [
            name for name in required if _complete_artifact(artifacts.get(name))
        ]
        independent = _complete_artifact(
            artifacts.get("audit-package-verification.json")
        )
        level = (
            3
            if len(complete_evidence) == len(required) and independent
            else 2
            if len(complete_evidence) == len(required)
            else 1
            if present
            else 0
        )
        gaps = [
            f"missing or incomplete artifact: {name}"
            for name in required
            if name not in complete_evidence
        ]
        if level == 2:
            gaps.append("independent audit-package verification is missing")
        dimensions.append(
            {
                "id": identifier,
                "capability_level": level,
                "evidence_required": list(required),
                "evidence_present": complete_evidence,
                "gaps": gaps,
            }
        )
    minimum = min((int(item["capability_level"]) for item in dimensions), default=0)
    gaps = [str(gap) for item in dimensions for gap in item["gaps"]]
    return {
        "schema_version": "1.0",
        "analysis": "software-process-capability-assessment",
        "complete": minimum >= 2,
        "measurement_scale": "ISO-IEC-33020-inspired-bounded-levels-0-through-3",
        "minimum_capability_level": minimum,
        "dimensions_assessed": len(dimensions),
        "dimensions_level_2_or_higher": sum(
            item["capability_level"] >= 2 for item in dimensions
        ),
        "dimensions": dimensions,
        "gaps": list(dict.fromkeys(gaps))[:100],
        "claim_boundary": (
            "These bounded evidence levels are readiness indicators, not an ISO/IEC "
            "33000-series conformant assessment or maturity certification."
        ),
    }


def _prioritization_calibration(artifacts: dict[str, Any]) -> dict[str, Any]:
    value = artifacts.get("prioritization-calibration-evidence.json")
    gaps: list[str] = []
    metrics: dict[str, Any] = {}
    snapshots: dict[str, Any] = {}
    samples = 0
    hours: Any = None
    if not isinstance(value, dict):
        gaps.append("prioritization calibration evidence is missing")
    else:
        snapshots_value = value.get("snapshots")
        metrics_value = value.get("metrics")
        snapshots = snapshots_value if isinstance(snapshots_value, dict) else {}
        metrics = metrics_value if isinstance(metrics_value, dict) else {}
        samples_value = value.get("samples")
        samples = (
            samples_value
            if isinstance(samples_value, int)
            and not isinstance(samples_value, bool)
            and samples_value >= 1
            else 0
        )
        for name in ("corpus_sha256", "outcomes_sha256"):
            if not _digest(str(value.get(name) or "")):
                gaps.append(f"{name} is missing or invalid")
        for name in ("epss_sha256", "kev_sha256"):
            if not _digest(str(snapshots.get(name) or "")):
                gaps.append(f"snapshot {name} is missing or invalid")
        if value.get("point_in_time") is not True:
            gaps.append("point-in-time evaluation is not proven")
        if value.get("future_data_excluded") is not True:
            gaps.append("future-data exclusion is not proven")
        if value.get("replay_protected") is not True:
            gaps.append("replay protection is missing")
        authority = value.get("authority")
        if (
            not isinstance(authority, dict)
            or authority.get("organization_approved") is not True
        ):
            gaps.append("organization-approved outcome authority is missing")
        if samples < 100:
            gaps.append("fewer than 100 temporal observations were evaluated")
        for name in (
            "brier_score",
            "expected_calibration_error",
            "recall_at_budget",
            "effort",
        ):
            if not _ratio(metrics.get(name)):
                gaps.append(f"metric {name} is missing or invalid")
        hours = metrics.get("kev_time_to_prioritize_hours")
        if (
            isinstance(hours, bool)
            or not isinstance(hours, (int, float))
            or not math.isfinite(float(hours))
            or float(hours) < 0
        ):
            gaps.append("metric kev_time_to_prioritize_hours is missing or invalid")
    return {
        "schema_version": "1.0",
        "analysis": "point-in-time-vulnerability-prioritization-calibration",
        "complete": not gaps,
        "samples": samples,
        "point_in_time": bool(
            isinstance(value, dict) and value.get("point_in_time") is True
        ),
        "future_data_excluded": bool(
            isinstance(value, dict) and value.get("future_data_excluded") is True
        ),
        "replay_protected": bool(
            isinstance(value, dict) and value.get("replay_protected") is True
        ),
        "corpus_sha256": str(value.get("corpus_sha256") or "")
        if isinstance(value, dict)
        else "",
        "outcomes_sha256": str(value.get("outcomes_sha256") or "")
        if isinstance(value, dict)
        else "",
        "snapshots": {
            "epss_sha256": str(snapshots.get("epss_sha256") or ""),
            "kev_sha256": str(snapshots.get("kev_sha256") or ""),
        },
        "metrics": {
            "brier_score": metrics.get("brier_score")
            if _ratio(metrics.get("brier_score"))
            else None,
            "expected_calibration_error": metrics.get("expected_calibration_error")
            if _ratio(metrics.get("expected_calibration_error"))
            else None,
            "recall_at_budget": metrics.get("recall_at_budget")
            if _ratio(metrics.get("recall_at_budget"))
            else None,
            "effort": metrics.get("effort") if _ratio(metrics.get("effort")) else None,
            "kev_time_to_prioritize_hours": hours
            if isinstance(hours, (int, float))
            and not isinstance(hours, bool)
            and math.isfinite(float(hours))
            and float(hours) >= 0
            else None,
        },
        "gaps": gaps[:100],
        "claim_boundary": (
            "Calibration is valid only for the pinned observation window, snapshots, "
            "outcome authority, population, and remediation budget."
        ),
    }


def _applicable_profiles(policy: dict[str, Any]) -> set[str]:
    return {
        str(item["id"])
        for item in policy.get("profiles", [])
        if isinstance(item, dict) and item.get("applicable") is True
    }


def _governed_assessment_row(
    value: object, identifier: str, *, require_independence: bool = True
) -> tuple[dict[str, Any], list[str]]:
    row = value if isinstance(value, dict) else {}
    gaps: list[str] = []
    for name in ("scope_sha256", "evidence_sha256", "method_sha256", "report_sha256"):
        if not _digest(str(row.get(name) or "")):
            gaps.append(f"{identifier} {name} is missing or invalid")
    if not _text(row.get("version"), 100):
        gaps.append(f"{identifier} version is missing")
    assessor = row.get("assessor")
    if not isinstance(assessor, dict):
        gaps.append(f"{identifier} assessor identity is missing")
    else:
        if not _text(assessor.get("identity"), 300):
            gaps.append(f"{identifier} assessor identity is missing")
        if require_independence and assessor.get("independent") is not True:
            gaps.append(f"{identifier} assessor independence is not proven")
        if not _digest(str(assessor.get("competency_sha256") or "")):
            gaps.append(f"{identifier} assessor competency digest is missing")
    authority = row.get("authority")
    if (
        not isinstance(authority, dict)
        or authority.get("organization_approved") is not True
    ):
        gaps.append(f"{identifier} organization-approved authority is missing")
    if row.get("replay_protected") is not True:
        gaps.append(f"{identifier} replay protection is missing")
    return {
        "id": identifier,
        "version": str(row.get("version") or ""),
        "scope_sha256": str(row.get("scope_sha256") or ""),
        "evidence_sha256": str(row.get("evidence_sha256") or ""),
        "method_sha256": str(row.get("method_sha256") or ""),
        "report_sha256": str(row.get("report_sha256") or ""),
        "assessor": {
            "identity": str(assessor.get("identity") or "")
            if isinstance(assessor, dict)
            else "",
            "independent": bool(
                isinstance(assessor, dict) and assessor.get("independent") is True
            ),
            "competency_sha256": str(assessor.get("competency_sha256") or "")
            if isinstance(assessor, dict)
            else "",
        },
        "replay_protected": row.get("replay_protected") is True,
        "complete": not gaps,
        "gaps": gaps,
    }, gaps


def _maturity_model_assessment(
    artifacts: dict[str, Any], policy: dict[str, Any]
) -> dict[str, Any]:
    selected = _applicable_profiles(policy)
    required: list[str] = []
    for profile, models in {
        "devsecops-maturity": ("OWASP-DSOVS", "OWASP-DSOMM"),
        "test-maturity": ("TMMI",),
        "external-maturity-comparison": ("BSIMM", "CMMI-DEV"),
        "australian-essential-eight": ("ASD-ESSENTIAL-EIGHT",),
    }.items():
        if profile in selected:
            required.extend(models)
    raw = artifacts.get("maturity-model-evidence.json")
    supplied = raw.get("models", []) if isinstance(raw, dict) else []
    indexed = {str(item.get("id")): item for item in supplied if isinstance(item, dict)}
    rows: list[dict[str, Any]] = []
    gaps: list[str] = []
    for identifier in required:
        row, row_gaps = _governed_assessment_row(indexed.get(identifier), identifier)
        source = indexed.get(identifier)
        reviewers = (
            source.get("independent_reviewers") if isinstance(source, dict) else None
        )
        domains = source.get("domains") if isinstance(source, dict) else None
        if (
            isinstance(reviewers, bool)
            or not isinstance(reviewers, int)
            or reviewers < 2
        ):
            row_gaps.append(f"{identifier} requires at least two independent reviewers")
        if (
            not isinstance(domains, list)
            or not domains
            or not all(_text(item, 200) for item in domains)
        ):
            row_gaps.append(f"{identifier} assessed domains are missing")
        row["independent_reviewers"] = (
            reviewers
            if isinstance(reviewers, int) and not isinstance(reviewers, bool)
            else 0
        )
        row["domains"] = domains if isinstance(domains, list) else []
        row["complete"] = not row_gaps
        row["gaps"] = row_gaps
        rows.append(row)
        gaps.extend(row_gaps)
    return {
        "schema_version": "1.0",
        "analysis": "governed-maturity-model-assessment",
        "applicable": bool(required),
        "required_models": required,
        "models_assessed": len(rows),
        "models_complete": sum(item["complete"] for item in rows),
        "complete": not gaps,
        "models": rows,
        "gaps": gaps[:100],
        "claim_boundary": "Maturity ratings are evidence-bound point-in-time assessments, not certification or permission to reproduce licensed model text.",
    }


def _security_automation_interoperability(
    artifacts: dict[str, Any], policy: dict[str, Any]
) -> dict[str, Any]:
    selected = _applicable_profiles(policy)
    required: list[str] = []
    for profile, protocols in {
        "security-automation-interoperability": (
            "OASIS-CACAO",
            "OASIS-OPENC2",
            "OCSF",
        ),
        "security-data-interoperability": ("OASIS-STIX", "OASIS-TAXII"),
        "supply-chain-transparency-consumer": (
            "IETF-RFC-9942",
            "IETF-RFC-9943",
        ),
        "runtime-contract-interoperability": (
            "OPENAPI-SPECIFICATION",
            "ASYNCAPI-SPECIFICATION",
            "GRAPHQL-SPECIFICATION",
            "JSON-SCHEMA",
            "OPENTELEMETRY-SEMCONV",
        ),
    }.items():
        if profile in selected:
            required.extend(protocols)
    required = list(dict.fromkeys(required))
    applicable = bool(required)
    raw = artifacts.get("security-automation-evidence.json")
    supplied = raw.get("protocols", []) if isinstance(raw, dict) else []
    indexed = {str(item.get("id")): item for item in supplied if isinstance(item, dict)}
    rows: list[dict[str, Any]] = []
    gaps: list[str] = []
    for identifier in required:
        source = indexed.get(identifier, {})
        row_gaps: list[str] = []
        if not _text(source.get("version"), 100):
            row_gaps.append(f"{identifier} version is missing")
        for name in ("schema_sha256", "fixtures_sha256", "report_sha256"):
            if not _digest(str(source.get(name) or "")):
                row_gaps.append(f"{identifier} {name} is missing or invalid")
        for name in ("positive_cases", "negative_cases"):
            count = source.get(name)
            if isinstance(count, bool) or not isinstance(count, int) or count < 1:
                row_gaps.append(f"{identifier} {name} are missing")
        if source.get("round_trip_validated") is not True:
            row_gaps.append(f"{identifier} round-trip validation is missing")
        if source.get("semantic_equivalence_validated") is not True:
            row_gaps.append(f"{identifier} semantic-equivalence validation is missing")
        authority = source.get("authority")
        if (
            not isinstance(authority, dict)
            or authority.get("organization_approved") is not True
        ):
            row_gaps.append(f"{identifier} organization-approved authority is missing")
        if source.get("replay_protected") is not True:
            row_gaps.append(f"{identifier} replay protection is missing")
        rows.append(
            {
                "id": identifier,
                "version": str(source.get("version") or ""),
                "schema_sha256": str(source.get("schema_sha256") or ""),
                "fixtures_sha256": str(source.get("fixtures_sha256") or ""),
                "report_sha256": str(source.get("report_sha256") or ""),
                "positive_cases": source.get("positive_cases")
                if isinstance(source.get("positive_cases"), int)
                and not isinstance(source.get("positive_cases"), bool)
                else 0,
                "negative_cases": source.get("negative_cases")
                if isinstance(source.get("negative_cases"), int)
                and not isinstance(source.get("negative_cases"), bool)
                else 0,
                "round_trip_validated": source.get("round_trip_validated") is True,
                "semantic_equivalence_validated": source.get(
                    "semantic_equivalence_validated"
                )
                is True,
                "replay_protected": source.get("replay_protected") is True,
                "complete": not row_gaps,
                "gaps": row_gaps,
            }
        )
        gaps.extend(row_gaps)
    return {
        "schema_version": "1.0",
        "analysis": "security-automation-interoperability-conformance",
        "applicable": applicable,
        "protocols_required": required,
        "protocols_assessed": len(rows),
        "protocols_complete": sum(item["complete"] for item in rows),
        "complete": not gaps,
        "protocols": rows,
        "gaps": gaps[:100],
        "claim_boundary": "Conformance is limited to the pinned schemas, fixtures, implementations, and semantic assertions tested.",
    }


def _external_conformity_assessment(
    artifacts: dict[str, Any], policy: dict[str, Any]
) -> dict[str, Any]:
    selected = _applicable_profiles(policy)
    required: list[str] = []
    for profile, schemes in {
        "ai-conformity-quality": ("ISO-IEC-42006", "CSA-AICM"),
        "cloud-independent-assurance": ("CSA-STAR",),
        "federal-vulnerability-disclosure": ("NIST-SP-800-216",),
        "consumer-product-regulation": ("UK-PSTI", "ETSI-EN-18031"),
        "detection-product-evaluation": ("MITRE-ATTACK-EVALUATIONS",),
        "external-maturity-comparison": ("LICENSED-NORMATIVE-CATALOG",),
        "uk-cyber-resilience": ("NCSC-CAF", "NCSC-CYBER-ESSENTIALS"),
        "cisa-cross-sector-cpg": ("CISA-CPG",),
        "automotive-software-update": ("ISO-24089",),
        "energy-product-security": ("IEC-62351", "UL-2900"),
        "enhanced-cui-assurance": ("NIST-SP-800-172A",),
        "continuous-security-monitoring": ("NIST-SP-800-137A", "NISTIR-8212"),
        "digital-forensics-readiness": ("ISO-IEC-27037", "ISO-IEC-27041"),
        "accessibility-quality": ("W3C-WCAG", "ETSI-EN-301-549", "US-SECTION-508"),
        "audit-assessment-integrity": (
            "ISO-IEC-27006-1",
            "ISO-IEC-17021-1",
            "ISO-IEC-17029",
        ),
        "security-evaluator-competence": (
            "ISO-IEC-19896-1",
            "ISO-IEC-19896-2",
            "ISO-IEC-19896-3",
        ),
    }.items():
        if profile in selected:
            required.extend(schemes)
    raw = artifacts.get("external-conformity-evidence.json")
    supplied = raw.get("assessments", []) if isinstance(raw, dict) else []
    indexed = {str(item.get("id")): item for item in supplied if isinstance(item, dict)}
    rows: list[dict[str, Any]] = []
    gaps: list[str] = []
    for identifier in required:
        row, row_gaps = _governed_assessment_row(indexed.get(identifier), identifier)
        source = indexed.get(identifier)
        source = source if isinstance(source, dict) else {}
        if not _text(source.get("valid_at_assessment"), 100):
            row_gaps.append(f"{identifier} assessment validity date is missing")
        if not _text(source.get("applicability_basis"), 1000):
            row_gaps.append(f"{identifier} applicability basis is missing")
        credential = source.get("assessor_credential")
        if not isinstance(credential, dict):
            row_gaps.append(f"{identifier} assessor credential evidence is missing")
            credential = {}
        for name in (
            "credential_id_sha256",
            "registry_snapshot_sha256",
            "registry_signature_sha256",
        ):
            if not _digest(str(credential.get(name) or "")):
                row_gaps.append(
                    f"{identifier} assessor credential {name} is missing or invalid"
                )
        if not _text(credential.get("issuer"), 300) or not _text(
            credential.get("scheme"), 300
        ):
            row_gaps.append(
                f"{identifier} assessor credential issuer or scheme is missing"
            )
        if credential.get("status") != "active":
            row_gaps.append(f"{identifier} assessor credential is not active")
        if credential.get("revocation_checked") is not True:
            row_gaps.append(
                f"{identifier} assessor credential revocation was not checked"
            )
        if credential.get("signature_validated") is not True:
            row_gaps.append(
                f"{identifier} assessor registry signature is not validated"
            )
        for name in ("valid_from", "valid_until", "checked_at"):
            if not _iso_timestamp(credential.get(name)):
                row_gaps.append(
                    f"{identifier} assessor credential {name} is missing or invalid"
                )
        row["valid_at_assessment"] = str(source.get("valid_at_assessment") or "")
        row["applicability_basis"] = str(source.get("applicability_basis") or "")
        row["assessor_credential"] = {
            "issuer": str(credential.get("issuer") or ""),
            "scheme": str(credential.get("scheme") or ""),
            "credential_id_sha256": str(credential.get("credential_id_sha256") or ""),
            "registry_snapshot_sha256": str(
                credential.get("registry_snapshot_sha256") or ""
            ),
            "registry_signature_sha256": str(
                credential.get("registry_signature_sha256") or ""
            ),
            "status": str(credential.get("status") or ""),
            "valid_from": str(credential.get("valid_from") or ""),
            "valid_until": str(credential.get("valid_until") or ""),
            "checked_at": str(credential.get("checked_at") or ""),
            "revocation_checked": credential.get("revocation_checked") is True,
            "signature_validated": credential.get("signature_validated") is True,
        }
        row["complete"] = not row_gaps
        row["gaps"] = row_gaps
        rows.append(row)
        gaps.extend(row_gaps)
    return {
        "schema_version": "1.0",
        "analysis": "external-conformity-and-normative-evidence",
        "applicable": bool(required),
        "schemes_required": required,
        "schemes_assessed": len(rows),
        "schemes_complete": sum(item["complete"] for item in rows),
        "complete": not gaps,
        "assessments": rows,
        "gaps": gaps[:100],
        "claim_boundary": "The artifact records scoped evidence and assessor claims; only the issuing authority can confer certification, legal conformity, or registry status.",
    }


def _assurance_case_assessment(artifacts: dict[str, Any]) -> dict[str, Any]:
    raw = artifacts.get("structured-assurance-case.json")
    gaps: list[str] = []
    claims: list[Any] = []
    evidence: list[Any] = []
    relationships: list[Any] = []
    model: dict[str, Any] = {}
    review: dict[str, Any] = {}
    scope_sha256 = ""
    case_id = ""
    if not isinstance(raw, dict):
        gaps.append("structured-assurance-case.json is missing")
    else:
        case_id = str(raw.get("case_id") or "")
        scope_sha256 = str(raw.get("scope_sha256") or "")
        supplied_model = raw.get("model")
        supplied_claims = raw.get("claims")
        supplied_evidence = raw.get("evidence")
        supplied_relationships = raw.get("relationships")
        supplied_review = raw.get("review")
        model = supplied_model if isinstance(supplied_model, dict) else {}
        claims = supplied_claims if isinstance(supplied_claims, list) else []
        evidence = supplied_evidence if isinstance(supplied_evidence, list) else []
        relationships = (
            supplied_relationships if isinstance(supplied_relationships, list) else []
        )
        review = supplied_review if isinstance(supplied_review, dict) else {}
        if (
            set(raw)
            != {
                "schema_version",
                "case_id",
                "scope_sha256",
                "model",
                "claims",
                "evidence",
                "relationships",
                "review",
            }
            or raw.get("schema_version") != "1.0"
        ):
            gaps.append("assurance case envelope does not match schema version 1.0")
    if not _text(case_id, 200):
        gaps.append("assurance case identifier is missing or invalid")
    if not _digest(scope_sha256):
        gaps.append("assurance case scope digest is missing or invalid")
    expected_model = {
        "format",
        "version",
        "schema_sha256",
        "model_sha256",
        "schema_validated",
        "semantic_validated",
        "round_trip_validated",
    }
    if (
        set(model) != expected_model
        or model.get("format") != "OMG-SACM"
        or model.get("version") != "2.3"
        or not _digest(str(model.get("schema_sha256") or ""))
        or not _digest(str(model.get("model_sha256") or ""))
        or any(
            model.get(name) is not True
            for name in (
                "schema_validated",
                "semantic_validated",
                "round_trip_validated",
            )
        )
    ):
        gaps.append(
            "SACM 2.3 syntax, semantics, digest, or round-trip evidence is incomplete"
        )
    claim_ids: set[str] = set()
    top_level: set[str] = set()
    defeaters: set[str] = set()
    claim_status: dict[str, str] = {}
    minimum_confidence = review.get("minimum_confidence")
    valid_minimum = (
        isinstance(minimum_confidence, (int, float))
        and not isinstance(minimum_confidence, bool)
        and 0 <= float(minimum_confidence) <= 1
    )
    minimum_confidence_value = (
        float(cast(int | float, minimum_confidence)) if valid_minimum else 0.0
    )
    for index, claim in enumerate(claims[:20_000]):
        if not isinstance(claim, dict) or set(claim) != {
            "id",
            "type",
            "statement",
            "status",
            "confidence",
            "applicable",
            "top_level",
        }:
            gaps.append(f"claim {index} does not match the governed claim contract")
            continue
        identifier = str(claim.get("id") or "")
        claim_type = claim.get("type")
        status = claim.get("status")
        confidence = claim.get("confidence")
        confidence_is_number = isinstance(confidence, (int, float)) and not isinstance(
            confidence, bool
        )
        confidence_value = (
            float(cast(int | float, confidence)) if confidence_is_number else -1.0
        )
        if (
            not _text(identifier, 200)
            or identifier in claim_ids
            or claim_type
            not in {"claim", "assumption", "context", "justification", "defeater"}
            or status
            not in {"supported", "unsupported", "defeated", "resolved", "accepted-risk"}
            or not _text(claim.get("statement"), 4000)
            or not 0 <= confidence_value <= 1
            or not isinstance(claim.get("applicable"), bool)
            or not isinstance(claim.get("top_level"), bool)
        ):
            gaps.append(
                f"claim {index} identity, type, status, confidence, or text is invalid"
            )
            continue
        claim_ids.add(identifier)
        claim_status[identifier] = str(status)
        if claim["top_level"] is True and claim["applicable"] is True:
            top_level.add(identifier)
            if status not in {"supported", "accepted-risk"}:
                gaps.append(f"top-level claim is unresolved: {identifier}")
            if valid_minimum and confidence_value < minimum_confidence_value:
                gaps.append(f"top-level claim confidence is below policy: {identifier}")
        if claim_type == "defeater" and claim["applicable"] is True:
            defeaters.add(identifier)
            if status not in {"resolved", "accepted-risk"}:
                gaps.append(f"defeater is unresolved: {identifier}")
    if len(claims) > 20_000:
        gaps.append("assurance case exceeds the maximum claim count")
    if not top_level:
        gaps.append("assurance case has no applicable top-level claim")
    evidence_ids: set[str] = set()
    now = datetime.now(UTC)
    for index, item in enumerate(evidence[:100_000]):
        if not isinstance(item, dict) or set(item) != {
            "id",
            "artifact",
            "sha256",
            "subject_sha256",
            "collected_at",
            "valid_until",
            "verified",
        }:
            gaps.append(
                f"evidence {index} does not match the governed evidence contract"
            )
            continue
        identifier = str(item.get("id") or "")
        valid_until = item.get("valid_until")
        if (
            not _text(identifier, 200)
            or identifier in evidence_ids
            or identifier in claim_ids
            or not _artifact_name(item.get("artifact"))
            or not _digest(str(item.get("sha256") or ""))
            or not _digest(str(item.get("subject_sha256") or ""))
            or not _iso_timestamp(item.get("collected_at"))
            or (valid_until is not None and not _iso_timestamp(valid_until))
            or not isinstance(item.get("verified"), bool)
        ):
            gaps.append(
                f"evidence {index} identity, digest, time, or verification is invalid"
            )
            continue
        evidence_ids.add(identifier)
        if item["subject_sha256"] != scope_sha256:
            gaps.append(
                f"evidence subject is outside assurance-case scope: {identifier}"
            )
        if item["verified"] is not True:
            gaps.append(f"evidence is not independently verified: {identifier}")
        if valid_until is not None:
            try:
                expires = datetime.fromisoformat(
                    str(valid_until).replace("Z", "+00:00")
                )
                if expires <= now:
                    gaps.append(f"evidence is stale: {identifier}")
            except ValueError:
                pass
    if len(evidence) > 100_000:
        gaps.append("assurance case exceeds the maximum evidence count")
    known_nodes = claim_ids | evidence_ids
    incoming_support: set[str] = set()
    used_evidence: set[str] = set()
    support_graph: dict[str, set[str]] = {identifier: set() for identifier in claim_ids}
    relation_pairs: dict[tuple[str, str], set[str]] = {}
    seen_relationships: set[tuple[str, str, str]] = set()
    for index, relation in enumerate(relationships[:200_000]):
        if not isinstance(relation, dict) or set(relation) != {
            "source",
            "target",
            "type",
            "rationale",
        }:
            gaps.append(
                f"relationship {index} does not match the governed relationship contract"
            )
            continue
        source = str(relation.get("source") or "")
        target = str(relation.get("target") or "")
        relation_type = str(relation.get("type") or "")
        identity = (source, target, relation_type)
        if (
            source not in known_nodes
            or target not in claim_ids
            or source == target
            or relation_type
            not in {"supports", "challenges", "rebuts", "contextualizes", "assumes"}
            or identity in seen_relationships
            or not _text(relation.get("rationale"), 2000)
        ):
            gaps.append(
                f"relationship {index} is dangling, duplicated, self-referential, or invalid"
            )
            continue
        seen_relationships.add(identity)
        relation_pairs.setdefault((source, target), set()).add(relation_type)
        if source in evidence_ids:
            used_evidence.add(source)
        if relation_type == "supports":
            incoming_support.add(target)
            if source in claim_ids:
                support_graph[source].add(target)
    if len(relationships) > 200_000:
        gaps.append("assurance case exceeds the maximum relationship count")
    for (source, target), types in relation_pairs.items():
        if "supports" in types and types & {"challenges", "rebuts"}:
            gaps.append(f"contradictory relationship semantics: {source} -> {target}")
    for identifier in sorted(top_level):
        if (
            claim_status.get(identifier) == "supported"
            and identifier not in incoming_support
        ):
            gaps.append(
                f"supported top-level claim has no incoming support: {identifier}"
            )
    for identifier in sorted(evidence_ids - used_evidence):
        gaps.append(
            f"orphaned evidence is not cited by the assurance case: {identifier}"
        )
    indegree = {identifier: 0 for identifier in claim_ids}
    for targets in support_graph.values():
        for target in targets:
            indegree[target] += 1
    ready = sorted(identifier for identifier, degree in indegree.items() if degree == 0)
    processed = 0
    cursor = 0
    while cursor < len(ready):
        identifier = ready[cursor]
        cursor += 1
        processed += 1
        for target in sorted(support_graph.get(identifier, ())):
            indegree[target] -= 1
            if indegree[target] == 0:
                ready.append(target)
    if processed != len(claim_ids):
        gaps.append("claim support graph contains a cycle")
    if (
        set(review)
        != {
            "reviewed_at",
            "independent_reviewers",
            "minimum_confidence",
            "approved",
            "approval_sha256",
        }
        or not _iso_timestamp(review.get("reviewed_at"))
        or not _count(review.get("independent_reviewers"), 2)
        or not valid_minimum
        or review.get("approved") is not True
        or not _digest(str(review.get("approval_sha256") or ""))
    ):
        gaps.append(
            "independent review, confidence policy, or approval evidence is incomplete"
        )
    unique_gaps = list(dict.fromkeys(gaps))[:200]
    return {
        "schema_version": "1.0",
        "analysis": "structured-assurance-case-conformance",
        "applicable": isinstance(raw, dict),
        "case_id": case_id,
        "scope_sha256": scope_sha256,
        "model_format": str(model.get("format") or ""),
        "model_version": str(model.get("version") or ""),
        "claims_assessed": min(len(claims), 20_000),
        "top_level_claims": len(top_level),
        "defeaters_assessed": len(defeaters),
        "evidence_assessed": min(len(evidence), 100_000),
        "relationships_assessed": min(len(relationships), 200_000),
        "independent_reviewers": review.get("independent_reviewers")
        if _count(review.get("independent_reviewers"))
        else 0,
        "complete": not unique_gaps,
        "gaps": unique_gaps,
        "claim_boundary": "This assessment validates the supplied assurance-case structure, graph semantics, subject binding, freshness, and review evidence; it does not independently prove that the underlying system claims are true.",
    }


def _threat_model_assessment(
    artifacts: dict[str, Any], source_sha256: str
) -> dict[str, Any]:
    raw = artifacts.get("threat-model-evidence.json")
    gaps: list[str] = []
    expected_root = {
        "schema_version",
        "model_id",
        "source_sha256",
        "architecture_sha256",
        "methodology",
        "reviewed_at",
        "assets",
        "components",
        "trust_boundaries",
        "data_flows",
        "assumptions",
        "mitigations",
        "tests",
        "threats",
        "change_triggers",
        "review",
    }
    if not isinstance(raw, dict):
        gaps.append("threat-model evidence is missing")
        raw = {}
    elif set(raw) != expected_root or raw.get("schema_version") != "1.0":
        gaps.append("threat-model evidence does not match the governed root contract")

    def records(name: str, maximum: int = 10_000) -> list[Any]:
        value = raw.get(name)
        if not isinstance(value, list):
            gaps.append(f"{name} must be an array")
            return []
        if len(value) > maximum:
            gaps.append(f"{name} exceeds the maximum record count")
        return value[:maximum]

    def collect_ids(
        name: str, rows: list[Any], required: set[str]
    ) -> tuple[set[str], dict[str, dict[str, Any]]]:
        identifiers: set[str] = set()
        accepted: dict[str, dict[str, Any]] = {}
        for index, item in enumerate(rows):
            if not isinstance(item, dict) or set(item) != required:
                gaps.append(
                    f"{name} record {index} does not match its governed contract"
                )
                continue
            identifier = str(item.get("id") or "")
            if not _text(identifier, 200) or identifier in identifiers:
                gaps.append(f"{name} record {index} has an invalid or duplicate id")
                continue
            identifiers.add(identifier)
            accepted[identifier] = item
        return identifiers, accepted

    model_id = str(raw.get("model_id") or "")
    evidence_source = str(raw.get("source_sha256") or "")
    architecture_sha256 = str(raw.get("architecture_sha256") or "")
    if not _text(model_id, 200):
        gaps.append("model_id is missing or invalid")
    if not _digest(evidence_source) or evidence_source != source_sha256:
        gaps.append("threat-model source digest is missing or does not match the scan")
    if not _digest(architecture_sha256):
        gaps.append("architecture digest is missing or invalid")
    if not _text(raw.get("methodology"), 200):
        gaps.append("threat-model methodology is missing")
    model_reviewed_at = raw.get("reviewed_at")
    if not _iso_timestamp(model_reviewed_at):
        gaps.append("threat-model review timestamp is missing or invalid")
    else:
        try:
            if datetime.fromisoformat(
                str(model_reviewed_at).replace("Z", "+00:00")
            ) > datetime.now(UTC):
                gaps.append("threat-model review timestamp is in the future")
        except ValueError:
            pass

    asset_rows = records("assets")
    component_rows = records("components")
    boundary_rows = records("trust_boundaries")
    flow_rows = records("data_flows")
    assumption_rows = records("assumptions")
    mitigation_rows = records("mitigations")
    test_rows = records("tests")
    threat_rows = records("threats")
    trigger_rows = records("change_triggers", 2_000)

    asset_ids, assets = collect_ids(
        "asset",
        asset_rows,
        {"id", "title", "owner", "classification", "criticality"},
    )
    component_ids, components = collect_ids(
        "component", component_rows, {"id", "name", "kind", "zone", "owner"}
    )
    boundary_ids, boundaries = collect_ids(
        "trust-boundary",
        boundary_rows,
        {"id", "from_zone", "to_zone", "control_ids"},
    )
    flow_ids, flows = collect_ids(
        "data-flow",
        flow_rows,
        {
            "id",
            "source_component",
            "destination_component",
            "data_classes",
            "boundary_ids",
            "encrypted",
            "authenticated",
        },
    )
    assumption_ids, assumptions = collect_ids(
        "assumption",
        assumption_rows,
        {"id", "statement", "owner", "status", "expires_at"},
    )
    mitigation_ids, mitigations = collect_ids(
        "mitigation",
        mitigation_rows,
        {"id", "title", "owner", "status", "control_ids", "evidence"},
    )
    test_ids, tests = collect_ids(
        "test",
        test_rows,
        {
            "id",
            "threat_ids",
            "kind",
            "negative_case",
            "result",
            "evidence_sha256",
            "subject_sha256",
        },
    )
    threat_ids, threats = collect_ids(
        "threat",
        threat_rows,
        {
            "id",
            "title",
            "category",
            "asset_ids",
            "component_ids",
            "flow_ids",
            "boundary_ids",
            "preconditions",
            "attack_steps",
            "likelihood",
            "impact",
            "risk_score",
            "status",
            "mitigation_ids",
            "test_ids",
            "residual_risk",
            "owner",
            "acceptance",
        },
    )
    trigger_ids, triggers = collect_ids(
        "change-trigger",
        trigger_rows,
        {"id", "artifact", "sha256", "assessed"},
    )

    if not asset_ids:
        gaps.append("threat model has no assets")
    if not component_ids:
        gaps.append("threat model has no components")
    if not boundary_ids:
        gaps.append("threat model has no trust boundaries")
    if not flow_ids:
        gaps.append("threat model has no data flows")
    if not threat_ids:
        gaps.append("threat model has no threats")
    if not trigger_ids:
        gaps.append("threat model has no architecture change triggers")

    for identifier, item in assets.items():
        criticality = item.get("criticality")
        if (
            not _text(item.get("title"), 500)
            or not _text(item.get("owner"), 200)
            or item.get("classification")
            not in {"public", "internal", "confidential", "restricted"}
            or not isinstance(criticality, int)
            or isinstance(criticality, bool)
            or not 1 <= criticality <= 5
        ):
            gaps.append(f"asset metadata is incomplete or invalid: {identifier}")

    component_zones: dict[str, str] = {}
    for identifier, item in components.items():
        zone = str(item.get("zone") or "")
        if (
            not _text(item.get("name"), 500)
            or not _text(item.get("kind"), 200)
            or not _text(zone, 200)
            or not _text(item.get("owner"), 200)
        ):
            gaps.append(f"component metadata is incomplete: {identifier}")
        else:
            component_zones[identifier] = zone

    for identifier, item in boundaries.items():
        controls = item.get("control_ids")
        if (
            not _text(item.get("from_zone"), 200)
            or not _text(item.get("to_zone"), 200)
            or item.get("from_zone") == item.get("to_zone")
            or not isinstance(controls, list)
            or not controls
            or any(not _text(value, 200) for value in controls)
            or len(set(controls)) != len(controls)
        ):
            gaps.append(f"trust boundary is incomplete or invalid: {identifier}")

    sensitive_classes = {
        "credentials",
        "secrets",
        "personal",
        "health",
        "payment",
        "cryptographic-keys",
    }
    cross_boundary_flows: set[str] = set()
    modeled_cross_boundary_flows: set[str] = set()
    for identifier, item in flows.items():
        source = str(item.get("source_component") or "")
        destination = str(item.get("destination_component") or "")
        classes = item.get("data_classes")
        references = item.get("boundary_ids")
        valid_references = (
            isinstance(references, list)
            and len(references) == len(set(references))
            and all(value in boundary_ids for value in references)
        )
        if (
            source not in component_ids
            or destination not in component_ids
            or source == destination
            or not isinstance(classes, list)
            or not classes
            or any(not _text(value, 200) for value in classes)
            or not valid_references
            or not isinstance(item.get("encrypted"), bool)
            or not isinstance(item.get("authenticated"), bool)
        ):
            gaps.append(f"data flow is dangling or invalid: {identifier}")
            continue
        source_zone = component_zones.get(source)
        destination_zone = component_zones.get(destination)
        if source_zone != destination_zone:
            cross_boundary_flows.add(identifier)
            exact_boundaries = [
                value
                for value in cast(list[str], references)
                if boundaries.get(value, {}).get("from_zone") == source_zone
                and boundaries.get(value, {}).get("to_zone") == destination_zone
            ]
            if exact_boundaries:
                modeled_cross_boundary_flows.add(identifier)
            else:
                gaps.append(
                    f"cross-zone flow has no matching directional trust boundary: {identifier}"
                )
            if sensitive_classes & set(cast(list[str], classes)) and (
                item["encrypted"] is not True or item["authenticated"] is not True
            ):
                gaps.append(
                    f"sensitive cross-zone flow lacks authenticated encryption: {identifier}"
                )

    now = datetime.now(UTC)
    open_assumptions = 0
    for identifier, item in assumptions.items():
        status = item.get("status")
        expires_at = item.get("expires_at")
        if (
            not _text(item.get("statement"), 2000)
            or not _text(item.get("owner"), 200)
            or status not in {"validated", "open", "rejected"}
            or (expires_at is not None and not _iso_timestamp(expires_at))
        ):
            gaps.append(f"assumption is incomplete or invalid: {identifier}")
            continue
        if status != "validated":
            open_assumptions += 1
            gaps.append(f"assumption is unresolved: {identifier}")
        if expires_at is not None:
            try:
                if (
                    datetime.fromisoformat(str(expires_at).replace("Z", "+00:00"))
                    <= now
                ):
                    gaps.append(f"assumption is stale: {identifier}")
            except ValueError:
                pass

    verified_mitigations: set[str] = set()
    for identifier, item in mitigations.items():
        evidence = item.get("evidence")
        evidence_valid = isinstance(evidence, list) and bool(evidence)
        if evidence_valid:
            for record in cast(list[Any], evidence):
                if (
                    not isinstance(record, dict)
                    or set(record) != {"artifact", "sha256", "subject_sha256"}
                    or not _artifact_name(record.get("artifact"))
                    or not _digest(str(record.get("sha256") or ""))
                    or record.get("subject_sha256") != source_sha256
                ):
                    evidence_valid = False
                    break
        controls = item.get("control_ids")
        if (
            not _text(item.get("title"), 1000)
            or not _text(item.get("owner"), 200)
            or item.get("status") not in {"planned", "implemented", "verified"}
            or not isinstance(controls, list)
            or not controls
            or any(not _text(value, 200) for value in controls)
            or len(set(controls)) != len(controls)
            or (item.get("status") == "verified" and not evidence_valid)
        ):
            gaps.append(f"mitigation is incomplete or unsupported: {identifier}")
        elif item.get("status") == "verified":
            verified_mitigations.add(identifier)

    passed_negative_tests: set[str] = set()
    threat_tests: dict[str, set[str]] = {identifier: set() for identifier in threat_ids}
    for identifier, item in tests.items():
        linked = item.get("threat_ids")
        valid_links = (
            isinstance(linked, list)
            and bool(linked)
            and len(linked) == len(set(linked))
            and all(value in threat_ids for value in linked)
        )
        if (
            not valid_links
            or not _text(item.get("kind"), 200)
            or not isinstance(item.get("negative_case"), bool)
            or item.get("result") not in {"passed", "failed", "not-executed"}
            or not _digest(str(item.get("evidence_sha256") or ""))
            or item.get("subject_sha256") != source_sha256
        ):
            gaps.append(f"threat test is dangling, unbound, or invalid: {identifier}")
            continue
        for threat_id in cast(list[str], linked):
            threat_tests[threat_id].add(identifier)
        if item["negative_case"] is True and item["result"] == "passed":
            passed_negative_tests.add(identifier)

    assets_with_threats: set[str] = set()
    threats_with_mitigations: set[str] = set()
    threats_with_verification: set[str] = set()
    unresolved_high_risk = 0
    for identifier, item in threats.items():
        likelihood = item.get("likelihood")
        impact = item.get("impact")
        risk_score = item.get("risk_score")
        residual_risk = item.get("residual_risk")
        linked_assets = item.get("asset_ids")
        linked_components = item.get("component_ids")
        linked_flows = item.get("flow_ids")
        linked_boundaries = item.get("boundary_ids")
        linked_mitigations = item.get("mitigation_ids")
        linked_tests = item.get("test_ids")
        references = (
            ("asset", linked_assets, asset_ids, True),
            ("component", linked_components, component_ids, False),
            ("flow", linked_flows, flow_ids, False),
            ("boundary", linked_boundaries, boundary_ids, False),
            ("mitigation", linked_mitigations, mitigation_ids, False),
            ("test", linked_tests, test_ids, False),
        )
        valid_references = True
        for label, values, known, required in references:
            if (
                not isinstance(values, list)
                or (required and not values)
                or len(values) != len(set(values))
                or any(value not in known for value in values)
            ):
                gaps.append(f"threat {identifier} has invalid {label} references")
                valid_references = False
        valid_scores = (
            isinstance(likelihood, int)
            and not isinstance(likelihood, bool)
            and 1 <= likelihood <= 5
            and isinstance(impact, int)
            and not isinstance(impact, bool)
            and 1 <= impact <= 5
            and isinstance(risk_score, int)
            and not isinstance(risk_score, bool)
            and risk_score == likelihood * impact
            and isinstance(residual_risk, int)
            and not isinstance(residual_risk, bool)
            and 0 <= residual_risk <= risk_score
        )
        if (
            not _text(item.get("title"), 1000)
            or not _text(item.get("category"), 200)
            or not _text(item.get("owner"), 200)
            or item.get("status") not in {"open", "mitigated", "accepted"}
            or not isinstance(item.get("preconditions"), list)
            or not item.get("preconditions")
            or any(not _text(value, 1000) for value in item.get("preconditions", []))
            or not isinstance(item.get("attack_steps"), list)
            or not item.get("attack_steps")
            or any(not _text(value, 1000) for value in item.get("attack_steps", []))
            or not valid_scores
        ):
            gaps.append(
                f"threat semantics or risk calculation is invalid: {identifier}"
            )
        if valid_references and isinstance(linked_assets, list):
            assets_with_threats.update(cast(list[str], linked_assets))
        verified_links = (
            isinstance(linked_mitigations, list)
            and bool(linked_mitigations)
            and set(linked_mitigations) <= verified_mitigations
        )
        passed_links = (
            isinstance(linked_tests, list)
            and bool(linked_tests)
            and set(linked_tests) <= passed_negative_tests
            and set(linked_tests) <= threat_tests.get(identifier, set())
        )
        if linked_mitigations:
            threats_with_mitigations.add(identifier)
        if passed_links:
            threats_with_verification.add(identifier)
        status = item.get("status")
        if status == "mitigated" and (not verified_links or not passed_links):
            gaps.append(
                f"mitigated threat lacks verified controls or passing negative tests: {identifier}"
            )
        if status == "open":
            gaps.append(f"threat remains open: {identifier}")
        if status == "accepted":
            acceptance = item.get("acceptance")
            valid_acceptance = (
                isinstance(acceptance, dict)
                and set(acceptance) == {"approved_by", "expires_at", "evidence_sha256"}
                and _text(acceptance.get("approved_by"), 200)
                and _iso_timestamp(acceptance.get("expires_at"))
                and _digest(str(acceptance.get("evidence_sha256") or ""))
            )
            if valid_acceptance:
                try:
                    acceptance_record = cast(dict[str, Any], acceptance)
                    valid_acceptance = (
                        datetime.fromisoformat(
                            str(acceptance_record["expires_at"]).replace("Z", "+00:00")
                        )
                        > now
                    )
                except ValueError:
                    valid_acceptance = False
            if not valid_acceptance:
                gaps.append(f"accepted threat lacks current approval: {identifier}")
        elif item.get("acceptance") is not None:
            gaps.append(f"non-accepted threat carries risk acceptance: {identifier}")
        if isinstance(risk_score, int) and risk_score >= 15 and status == "open":
            unresolved_high_risk += 1

    for identifier in sorted(asset_ids - assets_with_threats):
        gaps.append(f"asset has no linked threat: {identifier}")
    for identifier in sorted(
        mitigation_ids
        - set().union(
            *(set(item.get("mitigation_ids", [])) for item in threats.values())
        )
    ):
        gaps.append(f"mitigation is orphaned: {identifier}")
    for identifier in sorted(test_ids - set().union(*threat_tests.values())):
        gaps.append(f"threat test is orphaned: {identifier}")

    assessed_triggers = 0
    architecture_artifacts = {
        "application-contract-analysis.json",
        "architecture-history.json",
        "boundary-graph.json",
        "domain-assurance.json",
        "source-inventory.json",
        "static-architecture.json",
    }
    for identifier, item in triggers.items():
        if (
            not _artifact_name(item.get("artifact"))
            or item.get("artifact") not in architecture_artifacts
            or not _digest(str(item.get("sha256") or ""))
            or not isinstance(item.get("assessed"), bool)
        ):
            gaps.append(f"architecture change trigger is invalid: {identifier}")
        elif item["assessed"] is True:
            assessed_triggers += 1
        else:
            gaps.append(
                f"architecture change has not been threat-modeled: {identifier}"
            )

    review = raw.get("review")
    independent_reviewers = 0
    approved = False
    if isinstance(review, dict):
        reviewers = review.get("independent_reviewers")
        independent_reviewers = (
            len(reviewers)
            if isinstance(reviewers, list)
            and len(reviewers) == len(set(reviewers))
            and all(_text(value, 200) for value in reviewers)
            else 0
        )
        approved = review.get("approved") is True
    owner_ids = {
        str(item.get("owner"))
        for collection in (assets, components, assumptions, mitigations, threats)
        for item in collection.values()
        if _text(item.get("owner"), 200)
    }
    reviewers_are_independent = bool(
        isinstance(review, dict)
        and isinstance(review.get("independent_reviewers"), list)
        and not (set(review["independent_reviewers"]) & owner_ids)
    )
    if (
        not isinstance(review, dict)
        or set(review)
        != {"reviewed_at", "independent_reviewers", "approved", "approval_sha256"}
        or not _iso_timestamp(review.get("reviewed_at"))
        or review.get("reviewed_at") != model_reviewed_at
        or independent_reviewers < 2
        or not reviewers_are_independent
        or not approved
        or not _digest(str(review.get("approval_sha256") or ""))
    ):
        gaps.append("independent threat-model review and approval are incomplete")

    unique_gaps = list(dict.fromkeys(gaps))[:200]
    return {
        "schema_version": "1.0",
        "analysis": "threat-model-quality-assessment",
        "applicable": isinstance(artifacts.get("threat-model-evidence.json"), dict),
        "model_id": model_id,
        "source_sha256": evidence_source if _digest(evidence_source) else "",
        "architecture_sha256": architecture_sha256
        if _digest(architecture_sha256)
        else "",
        "scope": {
            "assets": len(asset_ids),
            "components": len(component_ids),
            "trust_boundaries": len(boundary_ids),
            "data_flows": len(flow_ids),
            "assumptions": len(assumption_ids),
            "threats": len(threat_ids),
            "mitigations": len(mitigation_ids),
            "tests": len(test_ids),
            "change_triggers": len(trigger_ids),
        },
        "coverage": {
            "assets_with_threats": len(assets_with_threats),
            "cross_boundary_flows": len(cross_boundary_flows),
            "cross_boundary_flows_modeled": len(modeled_cross_boundary_flows),
            "threats_with_mitigations": len(threats_with_mitigations),
            "threats_with_verification": len(threats_with_verification),
            "verified_mitigations": len(verified_mitigations),
            "passed_negative_tests": len(passed_negative_tests),
            "open_assumptions": open_assumptions,
            "unresolved_high_risk": unresolved_high_risk,
            "change_triggers_assessed": assessed_triggers,
        },
        "review": {
            "independent_reviewers": independent_reviewers,
            "approved": approved,
        },
        "complete": not unique_gaps,
        "gaps": unique_gaps,
        "claim_boundary": (
            "This assessment checks threat-model structure, traceability, risk arithmetic, "
            "control and negative-test evidence, change coverage, and independent review. "
            "It does not prove that every possible threat was discovered or that controls "
            "remain effective outside the bound evidence."
        ),
    }


def _foundational_assurance_artifacts(
    artifacts: dict[str, Any], source_sha256: str, policy: dict[str, Any]
) -> dict[str, dict[str, Any]]:
    threat_model = _threat_model_assessment(artifacts, source_sha256)
    lifecycle = _lifecycle_traceability(artifacts, source_sha256)
    architecture = _architecture_evaluation(artifacts)
    intermediate = {
        **artifacts,
        "lifecycle-traceability.json": lifecycle,
        "architecture-evaluation.json": architecture,
    }
    capability = _process_capability_assessment(intermediate)
    prioritization = _prioritization_calibration(artifacts)
    maturity = _maturity_model_assessment(artifacts, policy)
    automation = _security_automation_interoperability(artifacts, policy)
    conformity = _external_conformity_assessment(artifacts, policy)
    assurance_case = _assurance_case_assessment(artifacts)
    return {
        "lifecycle-traceability.json": lifecycle,
        "architecture-evaluation.json": architecture,
        "process-capability-assessment.json": capability,
        "prioritization-calibration.json": prioritization,
        "maturity-model-assessment.json": maturity,
        "security-automation-interoperability.json": automation,
        "external-conformity-assessment.json": conformity,
        "assurance-case-assessment.json": assurance_case,
        "threat-model-assessment.json": threat_model,
    }


def build_industry_assurance(
    target: Path,
    artifacts: dict[str, Any],
    findings: list[Any] | None = None,
    *,
    receipt_trust_policy: dict[str, Any] | None = None,
) -> tuple[dict[str, dict[str, Any]], list[str]]:
    """Build bounded benchmark, procedure, standards, and OSCAL artifacts."""

    target = target.resolve()
    policy, errors = _load_policy(target)
    if (
        policy.get("schema_version") == "1.3"
        and any(item.get("enabled") is True for item in policy["benchmarks"])
        and receipt_trust_policy is None
    ):
        errors.append(
            "enabled protocol benchmarks require a root-signed deployment receipt "
            "authority policy outside the target workspace"
        )
    source_sha256 = _source_sha256(artifacts)
    foundational = _foundational_assurance_artifacts(artifacts, source_sha256, policy)
    profiles = _profile_registry(policy)
    enriched_artifacts = {**artifacts, **foundational}
    registry = _benchmark_registry(policy, source_sha256, receipt_trust_policy)
    scorecard = _benchmark_scorecard(
        target, enriched_artifacts, registry, source_sha256
    )
    delta = _benchmark_delta(target, policy, scorecard, errors)
    benchmark_artifacts = {
        "benchmark-registry.json": registry,
        "benchmark-scorecard.json": scorecard,
        "benchmark-delta.json": delta,
    }
    procedures = _procedure_assessment(
        policy, {**enriched_artifacts, **benchmark_artifacts}, errors
    )
    prioritization = _standardized_prioritization(findings or [])
    observed_artifacts = {
        **enriched_artifacts,
        **benchmark_artifacts,
        "procedure-assessment.json": procedures,
        "standardized-prioritization.json": prioritization,
    }
    initial_crosswalk = _crosswalk(observed_artifacts)
    assessment = _assessment(policy, observed_artifacts, initial_crosswalk, errors)
    oscal = _oscal_documents(assessment, procedures, source_sha256)
    generated_artifacts = {
        **observed_artifacts,
        "control-assessment.json": assessment,
        **oscal,
    }
    crosswalk = _crosswalk(generated_artifacts)
    industry = {
        "schema_version": "1.0",
        "analysis": "industry-standards-and-benchmark-assurance",
        "complete": not errors
        and assessment["complete"] is True
        and procedures["complete"] is True
        and (
            scorecard["benchmarks_enabled"] == 0
            or (scorecard["complete"] is True and scorecard["passed"] is True)
        ),
        "policy_present": policy["present"],
        "policy_path": _POLICY_PATH if policy["present"] else None,
        "standards_registered": len(crosswalk["catalogs"]),
        "benchmarks_registered": len(registry["benchmarks"]),
        "assurance_profiles_available": profiles["profiles_available"],
        "assurance_profiles_selected": profiles["profiles_selected"],
        "controls_assessed": assessment["controls_assessed"],
        "controls_satisfied": assessment["controls_satisfied"],
        "procedures_assessed": procedures["procedures_assessed"],
        "procedures_satisfied": procedures["procedures_satisfied"],
        "benchmarks_executed": scorecard["benchmarks_executed"],
        "oscal_models_emitted": len(oscal),
        "foundational_assurance": {
            name: value["complete"] for name, value in foundational.items()
        },
        "interoperability": _interoperability(generated_artifacts),
        "artifact_contracts": [
            "standards-crosswalk.json",
            "assurance-profile-registry.json",
            "control-assessment.json",
            "procedure-assessment.json",
            "standardized-prioritization.json",
            "benchmark-registry.json",
            "benchmark-scorecard.json",
            "benchmark-delta.json",
            "lifecycle-traceability.json",
            "architecture-evaluation.json",
            "process-capability-assessment.json",
            "prioritization-calibration.json",
            "maturity-model-assessment.json",
            "security-automation-interoperability.json",
            "external-conformity-assessment.json",
            "assurance-case-assessment.json",
            "threat-model-assessment.json",
            "oscal-catalog.json",
            "oscal-profile.json",
            "oscal-component-definition.json",
            "oscal-system-security-plan.json",
            "oscal-assessment-plan.json",
            "oscal-assessment-results.json",
            "oscal-poam.json",
        ],
        "parse_errors": errors[:100],
        "claim_boundary": (
            "Registration or evidence mapping is not certification. Benchmark scores "
            "apply only to the pinned corpus, tool set, source, and execution environment."
        ),
    }
    return {
        "industry-assurance.json": industry,
        "standards-crosswalk.json": crosswalk,
        "assurance-profile-registry.json": profiles,
        "control-assessment.json": assessment,
        "procedure-assessment.json": procedures,
        "standardized-prioritization.json": prioritization,
        "benchmark-registry.json": registry,
        "benchmark-scorecard.json": scorecard,
        "benchmark-delta.json": delta,
        **foundational,
        **oscal,
    }, errors


def _profile_registry(policy: dict[str, Any]) -> dict[str, Any]:
    selections = {str(item["id"]): item for item in policy.get("profiles", [])}
    profiles = []
    for identifier, profile in _ASSURANCE_PROFILES.items():
        selection = selections.get(identifier)
        profiles.append(
            {
                "id": identifier,
                "standards": list(profile["standards"]),
                "controls": len(profile["controls"]),
                "procedures": len(profile["procedures"]),
                "selected": selection is not None,
                "applicable": (
                    selection["applicable"] if selection is not None else None
                ),
                "procedure_execution": (
                    selection["procedure_execution"] if selection is not None else None
                ),
            }
        )
    return {
        "schema_version": "1.0",
        "analysis": "industry-assurance-profile-registry",
        "profiles_available": len(profiles),
        "profiles_selected": len(selections),
        "profiles": profiles,
        "claim_boundary": (
            "Selecting a profile expands evidence-backed controls and procedures; "
            "it does not establish certification, legal applicability, or assessor approval."
        ),
    }


def _load_policy(target: Path) -> tuple[dict[str, Any], list[str]]:
    default = {
        "present": False,
        "enforce": False,
        "profiles": [],
        "controls": [],
        "procedures": [],
        "benchmarks": [],
        "benchmark_baseline_path": None,
    }
    path = target / _POLICY_PATH
    if not path.is_file():
        return default, []
    try:
        _, payload = read_regular_file(
            path,
            "industry assurance policy",
            maximum_bytes=_MAX_POLICY_BYTES,
            boundary=target,
        )
        value = strict_loads(payload)
        _validate_policy(value)
        return {"present": True, **_expand_policy_profiles(value)}, []
    except (OSError, TypeError, ValueError) as exc:
        return {**default, "present": True}, [f"{_POLICY_PATH}: {type(exc).__name__}"]


def _validate_policy(value: object) -> None:
    version_1_0 = {
        "schema_version",
        "enforce",
        "controls",
        "benchmarks",
        "benchmark_baseline_path",
    }
    version_1_1 = {*version_1_0, "procedures"}
    version_1_2 = {*version_1_1, "profiles"}
    version_1_3 = version_1_2
    if not isinstance(value, dict):
        raise ValueError("invalid industry assurance policy")
    version = value.get("schema_version")
    expected = (
        version_1_0
        if version == "1.0"
        else version_1_1
        if version == "1.1"
        else version_1_2
        if version == "1.2"
        else version_1_3
    )
    if (
        version not in {"1.0", "1.1", "1.2", "1.3"}
        or set(value) != expected
        or not isinstance(value.get("enforce"), bool)
    ):
        raise ValueError("invalid industry assurance policy")
    controls = value.get("controls")
    procedures = value.get("procedures", [])
    profiles = value.get("profiles", [])
    benchmarks = value.get("benchmarks")
    if (
        not isinstance(controls, list)
        or len(controls) > 10_000
        or not isinstance(procedures, list)
        or len(procedures) > 20_000
        or not isinstance(profiles, list)
        or len(profiles) > len(_ASSURANCE_PROFILES)
        or not isinstance(benchmarks, list)
        or len(benchmarks) > len(_BENCHMARKS)
    ):
        raise ValueError("industry assurance policy collections are invalid")
    seen_profiles: set[str] = set()
    for profile in profiles:
        if not isinstance(profile, dict) or set(profile) != {
            "id",
            "applicable",
            "procedure_execution",
        }:
            raise ValueError("industry assurance profile fields are invalid")
        identifier = str(profile.get("id") or "")
        if (
            identifier not in _ASSURANCE_PROFILES
            or identifier in seen_profiles
            or not isinstance(profile.get("applicable"), bool)
            or profile.get("procedure_execution") not in {"planned", "executed"}
        ):
            raise ValueError("industry assurance profile is invalid")
        seen_profiles.add(identifier)
    known_standards = {item["id"] for item in _STANDARDS}
    known_benchmarks = {item["id"] for item in _BENCHMARKS}
    identities: set[tuple[str, str]] = set()
    for control in controls:
        if not isinstance(control, dict) or set(control) != {
            "standard",
            "control_id",
            "objective",
            "applicable",
            "evidence_artifacts",
        }:
            raise ValueError("industry assurance control fields are invalid")
        identity = (str(control.get("standard")), str(control.get("control_id")))
        evidence = control.get("evidence_artifacts")
        if (
            identity[0] not in known_standards
            or identity in identities
            or not _text(identity[1], 160)
            or not _text(control.get("objective"), 1000)
            or not isinstance(control.get("applicable"), bool)
            or not isinstance(evidence, list)
            or len(evidence) > 100
            or not all(_artifact_name(item) for item in evidence)
        ):
            raise ValueError("industry assurance control is invalid")
        identities.add(identity)
    procedure_identities: set[tuple[str, str]] = set()
    for procedure in procedures:
        required_procedure_fields = {
            "standard",
            "procedure_id",
            "objective",
            "applicable",
            "execution",
            "test_type",
            "authorization_required",
            "evidence_artifacts",
        }
        if (
            not isinstance(procedure, dict)
            or set(procedure) != required_procedure_fields
        ):
            raise ValueError("industry assurance procedure fields are invalid")
        identity = (
            str(procedure.get("standard")),
            str(procedure.get("procedure_id")),
        )
        evidence = procedure.get("evidence_artifacts")
        if (
            identity[0] not in known_standards
            or identity in procedure_identities
            or not _text(identity[1], 160)
            or not _text(procedure.get("objective"), 1000)
            or not isinstance(procedure.get("applicable"), bool)
            or procedure.get("execution") not in {"planned", "executed"}
            or procedure.get("test_type")
            not in {"examine", "interview", "test", "static", "dynamic", "manual"}
            or not isinstance(procedure.get("authorization_required"), bool)
            or not isinstance(evidence, list)
            or len(evidence) > 100
            or not all(_artifact_name(item) for item in evidence)
        ):
            raise ValueError("industry assurance procedure is invalid")
        procedure_identities.add(identity)
    seen: set[str] = set()
    for benchmark in benchmarks:
        legacy_benchmark_fields = {
            "id",
            "enabled",
            "corpus_sha256",
            "evidence_artifact",
            "minimum_precision",
            "minimum_recall",
            "minimum_f1",
            "maximum_false_positive_rate",
        }
        protocol_benchmark_fields = {
            "id",
            "enabled",
            "corpus_sha256",
            "evidence_artifact",
            "thresholds",
            "adapter_manifest",
        }
        allowed_fields = (
            {frozenset(protocol_benchmark_fields)}
            if version == "1.3"
            else {
                frozenset(legacy_benchmark_fields),
                frozenset({*legacy_benchmark_fields, "adapter_manifest"}),
            }
        )
        if not isinstance(benchmark, dict) or set(benchmark) not in allowed_fields:
            raise ValueError("industry benchmark fields are invalid")
        identifier = str(benchmark.get("id") or "")
        digest = str(benchmark.get("corpus_sha256") or "")
        if (
            identifier not in known_benchmarks
            or identifier in seen
            or not isinstance(benchmark.get("enabled"), bool)
            or not _digest(digest)
            or not _artifact_name(benchmark.get("evidence_artifact"))
            or (
                benchmark.get("adapter_manifest") is not None
                and not _safe_relative(benchmark.get("adapter_manifest"))
            )
        ):
            raise ValueError("industry benchmark declaration is invalid")
        if version == "1.3":
            threshold_gaps = validate_protocol_thresholds(
                _benchmark_protocol(identifier), benchmark.get("thresholds")
            )
            if threshold_gaps:
                raise ValueError("; ".join(threshold_gaps))
        else:
            for name in (
                "minimum_precision",
                "minimum_recall",
                "minimum_f1",
                "maximum_false_positive_rate",
            ):
                if not _ratio(benchmark.get(name)):
                    raise ValueError("industry benchmark threshold is invalid")
        seen.add(identifier)
    baseline = value.get("benchmark_baseline_path")
    if baseline is not None and not _safe_relative(baseline):
        raise ValueError("benchmark baseline path is unsafe")


def _expand_policy_profiles(value: dict[str, Any]) -> dict[str, Any]:
    expanded = {
        **value,
        "profiles": list(value.get("profiles", [])),
        "controls": [dict(item) for item in value["controls"]],
        "procedures": [dict(item) for item in value.get("procedures", [])],
    }
    control_identities = {
        (str(item["standard"]), str(item["control_id"]))
        for item in expanded["controls"]
    }
    procedure_identities = {
        (str(item["standard"]), str(item["procedure_id"]))
        for item in expanded["procedures"]
    }
    for selection in expanded["profiles"]:
        profile = _ASSURANCE_PROFILES[str(selection["id"])]
        applicable = selection["applicable"] is True
        for standard, control_id, objective, evidence in profile["controls"]:
            identity = (standard, control_id)
            if identity in control_identities:
                raise ValueError("profile control duplicates an explicit control")
            expanded["controls"].append(
                {
                    "standard": standard,
                    "control_id": control_id,
                    "objective": objective,
                    "applicable": applicable,
                    "evidence_artifacts": list(evidence),
                }
            )
            control_identities.add(identity)
        for (
            standard,
            procedure_id,
            objective,
            test_type,
            authorization_required,
            evidence,
        ) in profile["procedures"]:
            identity = (standard, procedure_id)
            if identity in procedure_identities:
                raise ValueError("profile procedure duplicates an explicit procedure")
            expanded["procedures"].append(
                {
                    "standard": standard,
                    "procedure_id": procedure_id,
                    "objective": objective,
                    "applicable": applicable,
                    "execution": selection["procedure_execution"],
                    "test_type": test_type,
                    "authorization_required": authorization_required,
                    "evidence_artifacts": list(evidence),
                }
            )
            procedure_identities.add(identity)
    if len(expanded["controls"]) > 10_000 or len(expanded["procedures"]) > 20_000:
        raise ValueError("expanded industry assurance policy is too large")
    return expanded


def _crosswalk(artifacts: dict[str, Any]) -> dict[str, Any]:
    catalogs = []
    mappings = []
    raw_lifecycle = artifacts.get("standards-lifecycle-evidence.json")
    supplied_records = (
        raw_lifecycle.get("records", []) if isinstance(raw_lifecycle, dict) else []
    )
    supplied_ids = [
        str(item.get("id"))
        for item in supplied_records
        if isinstance(item, dict) and item.get("id")
    ]
    known_catalog_ids = {str(item["id"]) for item in _STANDARDS}
    duplicate_ids = sorted(
        identifier for identifier, count in Counter(supplied_ids).items() if count > 1
    )
    unknown_ids = sorted(set(supplied_ids) - known_catalog_ids)
    lifecycle_input_gaps = [
        *(f"duplicate lifecycle record: {identifier}" for identifier in duplicate_ids),
        *(f"unknown lifecycle record: {identifier}" for identifier in unknown_ids),
    ]
    lifecycle_index = {
        str(item.get("id")): item
        for item in supplied_records
        if isinstance(item, dict) and item.get("id")
    }
    lifecycle_records: list[dict[str, Any]] = []
    for standard in _STANDARDS:
        present = [name for name in standard["evidence"] if name in artifacts]
        catalogs.append(
            {key: value for key, value in standard.items() if key != "evidence"}
        )
        mappings.append(
            {
                "standard": standard["id"],
                "evidence_artifacts": list(standard["evidence"]),
                "evidence_present": present,
                "mapping_status": "evidence-surface-present"
                if present
                else "not-observed",
            }
        )
        expected = standard.get("lifecycle")
        expected = expected if isinstance(expected, dict) else {}
        supplied = lifecycle_index.get(str(standard["id"]))
        supplied = supplied if isinstance(supplied, dict) else {}
        lifecycle_gaps: list[str] = []
        for field in (
            "source_sha256",
            "signature_sha256",
            "change_report_sha256",
        ):
            if not _digest(str(supplied.get(field) or "")):
                lifecycle_gaps.append(f"{field} is missing or invalid")
        if supplied.get("source_reference") != standard["reference"]:
            lifecycle_gaps.append(
                "source_reference does not match the catalog publisher reference"
            )
        if supplied.get("signature_validated") is not True or not _text(
            supplied.get("signer_identity"), 500
        ):
            lifecycle_gaps.append(
                "source signature validation or signer identity is missing"
            )
        if supplied.get("publisher_identity_validated") is not True:
            lifecycle_gaps.append("publisher identity validation is missing")
        if not _iso_timestamp(supplied.get("observed_at")):
            lifecycle_gaps.append("observed_at is missing or invalid")
        if not _text(supplied.get("approved_by"), 300) or not _iso_timestamp(
            supplied.get("approved_at")
        ):
            lifecycle_gaps.append(
                "human approval identity or time is missing or invalid"
            )
        if supplied.get("human_approved") is not True:
            lifecycle_gaps.append("human promotion approval is missing")
        supplied_status = str(supplied.get("edition_status") or "")
        expected_status = str(
            expected.get("edition_status") or supplied_status or "unreviewed"
        )
        if expected and supplied and supplied_status != expected_status:
            lifecycle_gaps.append("edition status does not match the catalog")
        elif supplied and supplied_status not in {
            "final",
            "historical",
            "final-under-review",
            "policy-pinned",
        }:
            lifecycle_gaps.append("edition status is missing or invalid")
        published = str(expected.get("published") or supplied.get("published") or "")
        if supplied and not _text(published, 100):
            lifecycle_gaps.append("publication date or policy pin is missing")
        lifecycle_records.append(
            {
                "id": standard["id"],
                "edition_status": expected_status,
                "published": published,
                "catalog_observed_at": str(expected.get("observed_at") or ""),
                "evidence_observed_at": str(supplied.get("observed_at") or ""),
                "source_sha256": str(supplied.get("source_sha256") or ""),
                "source_reference": str(supplied.get("source_reference") or ""),
                "signature_sha256": str(supplied.get("signature_sha256") or ""),
                "signature_validated": supplied.get("signature_validated") is True,
                "signer_identity": str(supplied.get("signer_identity") or ""),
                "publisher_identity_validated": supplied.get(
                    "publisher_identity_validated"
                )
                is True,
                "change_report_sha256": str(supplied.get("change_report_sha256") or ""),
                "human_approved": supplied.get("human_approved") is True,
                "approved_by": str(supplied.get("approved_by") or ""),
                "approved_at": str(supplied.get("approved_at") or ""),
                "supersedes": list(expected.get("supersedes", [])),
                "superseded_by": list(expected.get("superseded_by", [])),
                "complete": not lifecycle_gaps,
                "gaps": lifecycle_gaps,
            }
        )
    lifecycle_complete = sum(item["complete"] for item in lifecycle_records)
    return {
        "schema_version": "1.0",
        "analysis": "versioned-industry-standards-crosswalk",
        "catalogs_registered": len(catalogs),
        "catalogs": catalogs,
        "mappings": mappings,
        "watchlist": [dict(item) for item in _STANDARDS_WATCHLIST],
        "lifecycle_governance": {
            "evidence_artifact": "standards-lifecycle-evidence.json",
            "catalogs_assessed": len(lifecycle_records),
            "catalogs_complete": lifecycle_complete,
            "input_records": len(supplied_records),
            "input_gaps": lifecycle_input_gaps,
            "complete": lifecycle_complete == len(lifecycle_records)
            and not lifecycle_input_gaps,
            "promotion_requires_human_approval": True,
            "signed_source_snapshot_required": True,
            "source_digest_required": True,
            "publisher_change_report_required": True,
            "records": lifecycle_records,
            "claim_boundary": "Catalog registration is not a current-edition claim until a signed, digest-bound publisher snapshot, change report, observation time, and human promotion approval are complete.",
        },
        "claim_boundary": "A crosswalk identifies related evidence surfaces; it does not establish control conformance or certification.",
    }


def _assessment(
    policy: dict[str, Any],
    artifacts: dict[str, Any],
    crosswalk: dict[str, Any],
    errors: list[str],
) -> dict[str, Any]:
    controls = []
    for value in policy["controls"]:
        evidence = list(value["evidence_artifacts"])
        present = [name for name in evidence if _complete_artifact(artifacts.get(name))]
        missing = [name for name in evidence if name not in present]
        applicable = value["applicable"] is True
        status = (
            "not-applicable"
            if not applicable
            else "satisfied"
            if evidence and not missing
            else "gap"
        )
        controls.append(
            {
                "standard": value["standard"],
                "control_id": value["control_id"],
                "objective": value["objective"],
                "applicable": applicable,
                "status": status,
                "evidence_required": evidence,
                "evidence_present": present,
                "gaps": [f"missing or incomplete artifact: {name}" for name in missing],
            }
        )
    counts = Counter(item["status"] for item in controls)
    applicable_count = sum(item["applicable"] for item in controls)
    satisfied = counts["satisfied"]
    complete = not errors and (not policy["enforce"] or satisfied == applicable_count)
    return {
        "schema_version": "1.0",
        "analysis": "evidence-backed-industry-control-assessment",
        "complete": complete,
        "policy_present": policy["present"],
        "enforced": policy["enforce"],
        "catalogs_registered": crosswalk["catalogs_registered"],
        "controls_assessed": len(controls),
        "applicable_controls": applicable_count,
        "controls_satisfied": satisfied,
        "status_counts": {
            name: counts.get(name, 0) for name in ("satisfied", "gap", "not-applicable")
        },
        "controls": controls,
        "parse_errors": errors[:100],
        "claim_boundary": "Only declared controls with complete named evidence are satisfied; assessment is not third-party certification.",
    }


def _procedure_assessment(
    policy: dict[str, Any], artifacts: dict[str, Any], errors: list[str]
) -> dict[str, Any]:
    procedures = []
    for value in policy.get("procedures", []):
        evidence = list(value["evidence_artifacts"])
        present = [name for name in evidence if _complete_artifact(artifacts.get(name))]
        missing = [name for name in evidence if name not in present]
        applicable = value["applicable"] is True
        executed = value["execution"] == "executed"
        authorization = (
            "not-required"
            if value["authorization_required"] is False
            else "validated"
            if any(_authorization_validated(artifacts.get(name)) for name in present)
            else "required-not-proven"
        )
        status = "not-applicable"
        gaps: list[str] = []
        if applicable and not executed:
            status = "planned"
            gaps.append("procedure is applicable but has not been executed")
        elif applicable and (missing or not evidence):
            status = "evidence-gap"
            gaps.extend(f"missing or incomplete artifact: {name}" for name in missing)
            if not evidence:
                gaps.append("procedure has no declared evidence artifact")
        elif applicable and authorization == "required-not-proven":
            status = "authorization-gap"
            gaps.append(
                "authorized execution is required but not proven by retained evidence"
            )
        elif applicable:
            status = "satisfied"
        procedures.append(
            {
                "standard": value["standard"],
                "procedure_id": value["procedure_id"],
                "objective": value["objective"],
                "applicable": applicable,
                "execution": value["execution"],
                "test_type": value["test_type"],
                "authorization_required": value["authorization_required"],
                "authorization_status": authorization,
                "status": status,
                "evidence_required": evidence,
                "evidence_present": present,
                "gaps": gaps,
            }
        )
    counts = Counter(item["status"] for item in procedures)
    applicable_count = sum(item["applicable"] for item in procedures)
    satisfied = counts["satisfied"]
    complete = not errors and (not policy["enforce"] or satisfied == applicable_count)
    return {
        "schema_version": "1.0",
        "analysis": "versioned-security-test-procedure-assessment",
        "complete": complete,
        "policy_present": policy["present"],
        "enforced": policy["enforce"],
        "procedures_assessed": len(procedures),
        "applicable_procedures": applicable_count,
        "procedures_satisfied": satisfied,
        "status_counts": {
            name: counts.get(name, 0)
            for name in (
                "satisfied",
                "planned",
                "evidence-gap",
                "authorization-gap",
                "not-applicable",
            )
        },
        "procedures": procedures,
        "parse_errors": errors[:100],
        "claim_boundary": (
            "A procedure is satisfied only when it was declared executed, every named "
            "artifact is complete, and required authorization is explicitly proven."
        ),
    }


def _authorization_validated(value: object) -> bool:
    if not isinstance(value, dict):
        return False
    if value.get("authorization_validated") is True or value.get("authorized") is True:
        return True
    evidence = value.get("evidence")
    execution = value.get("execution")
    return bool(
        isinstance(evidence, dict)
        and evidence.get("execution_complete") is True
        and isinstance(execution, dict)
        and execution.get("authorization_validated") is True
    )


def _standardized_prioritization(findings: list[Any]) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    for finding in findings[:1_000_000]:
        evidence = getattr(finding, "evidence", {})
        evidence = evidence if isinstance(evidence, dict) else {}
        classifications = getattr(finding, "classifications", [])
        classifications = classifications if isinstance(classifications, list) else []
        severity = str(getattr(finding, "severity", "unknown"))
        intelligence = evidence.get("risk_intelligence")
        intelligence = intelligence if isinstance(intelligence, dict) else {}
        validation = evidence.get("validation")
        validation = validation if isinstance(validation, dict) else {}
        cvss = _validated_cvss(evidence.get("cvss"))
        ssvc = _ssvc_decision(severity, intelligence, validation, evidence.get("ssvc"))
        rows.append(
            {
                "finding_id": str(getattr(finding, "finding_id", "")),
                "native_severity": severity,
                "operational_priority": finding_priority(
                    severity=severity,
                    classifications=classifications,
                    evidence=evidence,
                ),
                "cvss": cvss,
                "ssvc": ssvc,
            }
        )
    rows.sort(key=lambda item: item["finding_id"])
    return {
        "schema_version": "1.0",
        "analysis": "cvss-4-and-ssvc-compatible-prioritization",
        "findings": len(rows),
        "cvss_scored": sum(item["cvss"]["status"] == "scored" for item in rows),
        "ssvc_decided": sum(item["ssvc"]["status"] == "decided" for item in rows),
        "records": rows,
        "claim_boundary": (
            "CVSS vectors are retained only when supplied as complete source evidence. "
            "SSVC outcomes remain undecided unless every decision factor is explicit; "
            "native severity is never converted into a fabricated CVSS vector."
        ),
    }


def _validated_cvss(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {
            "version": "4.0",
            "status": "not-scored",
            "vector": None,
            "score": None,
            "reason": "complete CVSS v4 source evidence was not supplied",
        }
    vector = str(value.get("vector") or "")
    score = value.get("score")
    if (
        vector.startswith("CVSS:4.0/")
        and isinstance(score, (int, float))
        and not isinstance(score, bool)
        and math.isfinite(float(score))
        and 0 <= float(score) <= 10
    ):
        return {
            "version": "4.0",
            "status": "scored",
            "vector": vector[:500],
            "score": round(float(score), 1),
            "reason": "retained source-provided CVSS v4 vector and score",
        }
    return {
        "version": "4.0",
        "status": "invalid-source-evidence",
        "vector": None,
        "score": None,
        "reason": "CVSS evidence did not contain a valid v4 vector and bounded score",
    }


def _ssvc_decision(
    severity: str,
    intelligence: dict[str, Any],
    validation: dict[str, Any],
    supplied: object,
) -> dict[str, Any]:
    supplied_factors = supplied if isinstance(supplied, dict) else {}
    factors = {
        "exploitation": supplied_factors.get("exploitation"),
        "automatable": supplied_factors.get("automatable"),
        "technical_impact": supplied_factors.get("technical_impact"),
        "mission_prevalence": supplied_factors.get("mission_prevalence"),
    }
    if factors["exploitation"] is None:
        if intelligence.get("known_exploited"):
            factors["exploitation"] = "active"
        elif validation.get("status") == "reproduced":
            factors["exploitation"] = "poc"
    if factors["technical_impact"] is None and severity in {"critical", "high"}:
        factors["technical_impact"] = "total"
    allowed = {
        "exploitation": {"none", "poc", "active"},
        "automatable": {"no", "yes"},
        "technical_impact": {"partial", "total"},
        "mission_prevalence": {"minimal", "support", "essential"},
    }
    complete = all(factors[name] in allowed[name] for name in factors)
    outcome = supplied_factors.get("outcome") if complete else None
    if outcome not in {"defer", "scheduled", "out-of-cycle", "immediate"}:
        outcome = None
    return {
        "model": "CISA-SSVC",
        "status": "decided" if complete and outcome else "insufficient-context",
        "factors": factors,
        "outcome": outcome,
        "reason": (
            "all decision factors and the source outcome were retained"
            if complete and outcome
            else "one or more SSVC decision factors or the source outcome are missing"
        ),
    }


def _benchmark_registry(
    policy: dict[str, Any],
    source_sha256: str,
    receipt_trust_policy: dict[str, Any] | None = None,
) -> dict[str, Any]:
    declarations = {item["id"]: item for item in policy["benchmarks"]}
    receipt_authorities, receipt_policy_identity = receipt_authority_projection(
        receipt_trust_policy
    )
    benchmarks = []
    tasks = []
    for registered in _BENCHMARKS:
        declaration = declarations.get(registered["id"])
        enabled = bool(declaration and declaration["enabled"])
        entry = {
            **registered,
            "runner_contract": _benchmark_runner_contract(registered),
            "enabled": enabled,
            "corpus_sha256": declaration["corpus_sha256"] if declaration else None,
            "evidence_artifact": declaration["evidence_artifact"]
            if declaration
            else None,
            "adapter_manifest": declaration.get("adapter_manifest")
            if declaration
            else None,
            "trusted_receipt_signer_key_ids": (
                [item["key_id"] for item in receipt_authorities] if enabled else []
            ),
            "trusted_receipt_authorities": (
                [dict(item) for item in receipt_authorities] if enabled else []
            ),
            "thresholds": (
                declaration["thresholds"]
                if declaration and policy["schema_version"] == "1.3"
                else {}
                if declaration
                and _benchmark_protocol(str(registered["id"])) != "classification"
                else {
                    name: declaration[name]
                    for name in (
                        "minimum_precision",
                        "minimum_recall",
                        "minimum_f1",
                        "maximum_false_positive_rate",
                    )
                }
                if declaration
                else None
            ),
        }
        benchmarks.append(entry)
        if enabled:
            if declaration is None:  # pragma: no cover - established by enabled
                raise AssertionError("enabled benchmark lacks a declaration")
            adapter_manifest = declaration.get("adapter_manifest")
            command = (
                [
                    "pysec",
                    "benchmark-run",
                    adapter_manifest,
                    "--workspace",
                    "${PYSEC_BENCHMARK_WORKSPACE}",
                    "--output",
                    declaration["evidence_artifact"],
                ]
                if adapter_manifest
                else [
                    "pysec",
                    "benchmark",
                    "${PYSEC_BENCHMARK_REPORT}",
                    "--corpus",
                    "${PYSEC_BENCHMARK_CORPUS}",
                    "--corpus-sha256",
                    declaration["corpus_sha256"],
                    "--format",
                    "json",
                    "--output",
                    declaration["evidence_artifact"],
                ]
            )
            tasks.append(
                {
                    "benchmark_id": registered["id"],
                    "lane": registered["lane"],
                    "command": command,
                    "execution_mode": "adapter"
                    if adapter_manifest
                    else "report-scoring",
                    "requires_operator_authorization": bool(adapter_manifest),
                    "authorization_flag": "--authorize-execution"
                    if adapter_manifest
                    else None,
                    "network_policy": "deny",
                    "disposable_target_required": registered["lane"]
                    == "authorized-companion",
                    "source_bound": bool(source_sha256),
                    "runner_contract": _benchmark_runner_contract(registered),
                }
            )
    return {
        "schema_version": "1.0",
        "analysis": "industry-benchmark-registry",
        "source_sha256": source_sha256,
        "receipt_authority_policy": receipt_policy_identity,
        "benchmarks_registered": len(benchmarks),
        "benchmarks_enabled": sum(item["enabled"] for item in benchmarks),
        "benchmarks": benchmarks,
        "tasks": tasks,
        "required_metrics": [
            "precision",
            "recall",
            "specificity",
            "f1",
            "mcc",
            "balanced_accuracy",
            "false_positive_rate",
            "youden_j",
        ],
        "required_strata": [
            "cwe",
            "language",
            "parser_variant",
            "boundary_type",
            "severity",
            "mutation_operator",
        ],
        "claim_boundary": "External vulnerable applications and corpora execute only in separately authorized disposable companion lanes.",
    }


def _benchmark_protocol(identifier: str) -> str:
    protocols = {
        "temporal-calibration": {"epss-kev-temporal-backtest"},
        "verification-competition": {"sv-comp"},
        "test-generation": {"test-comp"},
        "fuzzing-statistical": {
            "google-fuzzbench",
            "magma-ground-truth",
            "oss-fuzz-clusterfuzzlite",
            "fuzzing-crash-holdout",
        },
        "stochastic-adversarial": {
            "cyberseceval-4",
            "mlcommons-ailuminate",
            "agentic-security-holdout",
            "agentdojo",
            "harmbench",
            "agentharm",
            "garak-llm-probe-conformance",
            "nist-aria-inspect-evaluation",
            "ai-conformity-quality",
            "ai-agentic-testing-conformance",
            "nist-dioptra-ai-evaluation",
            "pyrit-ai-red-team",
            "mlcommons-ailuminate-safety",
            "mlcommons-ailuminate-jailbreak",
        },
        "assessor-agreement": {
            "architecture-evaluation-scenarios",
            "process-capability-assessor-agreement",
            "owasp-dsovs-maturity",
            "owasp-dsomm-maturity",
            "tmmi-assessment",
            "bsimm-cmmi-cohort",
            "regional-cyber-maturity-assessment",
            "iscm-program-assessment",
            "security-evaluator-calibration",
            "risk-technique-calibration",
            "cis-ram-attack-path-analysis",
            "enterprise-architecture-governance",
            "it-quality-governance-assessor-agreement",
            "first-csirt-psirt-maturity-assessment",
            "ieee-ai-governance-wellbeing-assessment",
            "isms-implementation-process-assessment",
            "ffiec-it-handbook-assessment",
            "bsi-c5-cloud-assurance-assessment",
            "linddun-privacy-threat-model-conformance",
            "tisax-vda-isa-assessment",
            "hitrust-csf-assessment",
            "nist-supplier-due-diligence",
            "owasp-samm-assessment-benchmark",
        },
        "biometric-performance": {"biometric-performance-pad"},
        "proficiency-testing": {"interlaboratory-proficiency-testing"},
        "detection-evaluation": {
            "atomic-red-team",
            "mitre-caldera",
            "mitre-attack-evaluations",
            "tiber-eu-threat-led-red-team",
            "amtso-malware-protection-evaluation",
            "rasp-prevention-effectiveness",
        },
        "conformance": {
            "sigstore-client-conformance",
            "slsa-verifier-conformance",
            "nist-acvp-cryptography",
            "w3c-wpt-webauthn",
            "disa-stig-scap-conformance",
            "iec-62443-system-conformance",
            "iec-62443-patch-management-exercise",
            "do355-continuing-airworthiness-exercise",
            "iacs-maritime-cyber-conformance",
            "swift-cscf-independent-assessment",
            "cwe-mapping-conformance",
            "csa-star-caiq-conformance",
            "cacao-openc2-ocsf-interoperability",
            "psti-en18031-product-conformance",
            "scitt-transparency-conformance",
            "cloud-native-api-service-mesh-conformance",
            "api-contract-spec-conformance",
            "opentelemetry-semantic-conformance",
            "s2c2f-consumer-dependency-conformance",
            "multicloud-kubernetes-attack-paths",
            "securitytxt-patch-operations-conformance",
            "automotive-software-update-conformance",
            "energy-product-security-conformance",
            "cisa-sbom-minimum-elements-conformance",
            "enhanced-cui-oscal-conformance",
            "nist-developer-verification-conformance",
            "crypto-lifecycle-agility-conformance",
            "ict-continuity-recovery-exercise",
            "digital-forensics-chain-of-custody",
            "wcag-accessibility-conformance",
            "w3c-act-rules-conformance",
            "cloud-native-chaos-resilience",
            "kubernetes-sonobuoy-conformance",
            "firmware-resilience-measured-boot",
            "access-control-policy-model-conformance",
            "differential-privacy-implementation-evaluation",
            "square-quality-measurement",
            "cis-cat-scap-platform-conformance",
            "c2sp-wycheproof",
            "nist-cfreds-cftt",
            "iso-29119-test-process-conformance",
            "square-quality-in-use-cloud",
            "tls-protocol-conformance",
            "reproducible-build-variation",
            "cisa-secure-by-design-negative-assurance",
            "dice-attestation-conformance",
            "telecom-security-controls-conformance",
            "nice-workforce-coverage",
            "penetration-test-engagement-quality",
            "dora-delivery-outcomes",
            "structured-assurance-case-conformance",
            "integrity-vv-conformance",
            "cmvp-fips-140-3-validation",
            "iso-19790-24759-module-conformance",
            "service-management-security-integration",
            "owasp-cornucopia-threat-model",
            "nist-8286-enterprise-risk-register",
            "square-quality-governance",
            "iso-42106-differentiated-ai-benchmarking",
            "owasp-aisvs-conformance",
            "iso-25058-ai-quality-evaluation",
            "eucc-scheme-assurance",
            "cisa-secure-software-attestation",
            "ieee-7000-ai-ethics-conformance",
            "ai-use-case-security-privacy",
            "nist-csf-profile-gap-reassessment",
            "privacy-engineering-pet-conformance",
            "mcp-client-server-security-conformance",
            "aws-fsbp-securityhub-conformance",
            "microsoft-mcsb-defender-conformance",
            "gcp-enterprise-foundations-conformance",
            "memory-safety-engineering-conformance",
            "organizational-resilience-bia-exercise",
            "openssf-best-practices-badge-conformance",
            "a2a-protocol-security-conformance",
            "sesip-iot-platform-evaluation-conformance",
            "first-tlp-iep-information-handling-conformance",
            "veris-incident-schema-conformance",
            "w3c-web-platform-defense-conformance",
            "dora-level2-technical-standards-conformance",
            "fcc-cyber-trust-mark-conformance",
            "openid-digital-credential-conformance",
            "cisa-scuba-saas-posture-conformance",
            "cis-kubernetes-hardening-conformance",
            "gsma-nesas-scas-assurance",
            "c2pa-content-credentials-conformance",
            "pci-payment-acceptance-conformance",
            "oidf-fapi-conformance",
            "fedramp-20x-continuous-validation",
            "fido2-authenticator-conformance",
            "eudi-wallet-functional-conformance",
            "pci-secure-software-conformance",
            "nis2-implementing-regulation-conformance",
        },
    }
    for protocol, identifiers in protocols.items():
        if identifier in identifiers:
            return protocol
    return "classification"


def _finite_number(value: object, minimum: float | None = None) -> bool:
    return bool(
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(float(value))
        and (minimum is None or float(value) >= minimum)
    )


def _count(value: object, minimum: int = 0) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= minimum


def _benchmark_scorecard(
    target: Path,
    artifacts: dict[str, Any],
    registry: dict[str, Any],
    source_sha256: str,
) -> dict[str, Any]:
    rows = []
    for benchmark in registry["benchmarks"]:
        if not benchmark["enabled"]:
            continue
        value = artifacts.get(benchmark["evidence_artifact"])
        evidence_source = "governed-artifact" if isinstance(value, dict) else "missing"
        if not isinstance(value, dict):
            try:
                _, payload = read_regular_file(
                    target / benchmark["evidence_artifact"],
                    "benchmark evidence",
                    maximum_bytes=_MAX_POLICY_BYTES,
                    boundary=target,
                )
                loaded = strict_loads(payload)
                value = loaded if isinstance(loaded, dict) else None
                evidence_source = "sealed-snapshot" if value is not None else "invalid"
            except (OSError, TypeError, ValueError):
                value = None
        valid = _benchmark_evidence(value, benchmark)
        reproducibility_gaps = _benchmark_reproducibility_gaps(value, benchmark)
        reproducibility_complete = not reproducibility_gaps
        metrics = value.get("metrics", {}) if valid and isinstance(value, dict) else {}
        protocol_metrics = (
            value.get("protocol_metrics", {})
            if valid and isinstance(value, dict)
            else {}
        )
        protocol = _benchmark_protocol(str(benchmark["id"]))
        thresholds = benchmark["thresholds"] or {}
        passed = bool(
            valid
            and reproducibility_complete
            and (
                _meets_thresholds(metrics, thresholds)
                if protocol == "classification"
                else _protocol_metrics_valid(protocol, protocol_metrics)
                and _protocol_acceptance(value)
                and (
                    not thresholds
                    or _meets_protocol_thresholds(protocol_metrics, thresholds)
                )
            )
        )
        rows.append(
            {
                "benchmark_id": benchmark["id"],
                "benchmark_protocol": protocol,
                "corpus_sha256": benchmark["corpus_sha256"],
                "evidence_artifact": benchmark["evidence_artifact"],
                "evidence_source": evidence_source,
                "evidence_present": isinstance(value, dict),
                "evidence_valid": valid,
                "reproducibility_complete": reproducibility_complete,
                "passed": passed,
                "metrics": {
                    name: metrics.get(name) for name in registry["required_metrics"]
                },
                "protocol_metrics": protocol_metrics,
                "gaps": (
                    []
                    if passed
                    else [
                        *_benchmark_gaps(
                            value,
                            valid,
                            metrics,
                            thresholds,
                            protocol,
                            protocol_metrics,
                        ),
                        *reproducibility_gaps,
                    ]
                ),
            }
        )
    executed = sum(item["evidence_valid"] for item in rows)
    passed_count = sum(item["passed"] for item in rows)
    benchmark_scope = [
        {
            "benchmark_id": item["benchmark_id"],
            "benchmark_protocol": item["benchmark_protocol"],
            "corpus_sha256": item["corpus_sha256"],
        }
        for item in rows
    ]
    return {
        "schema_version": "1.0",
        "analysis": "industry-benchmark-scorecard",
        "source_sha256": source_sha256,
        "benchmarks_enabled": len(rows),
        "benchmarks_executed": executed,
        "benchmarks_passed": passed_count,
        "complete": executed == len(rows),
        "passed": bool(rows) and passed_count == len(rows),
        "benchmarks": rows,
        "benchmark_scope": benchmark_scope,
        "aggregate_metrics": _aggregate_metrics(rows),
        "claim_boundary": "Scores are corpus-specific measurements and do not prove absence of vulnerabilities in other software.",
    }


def _benchmark_evidence(value: object, benchmark: dict[str, Any]) -> bool:
    if not isinstance(value, dict) or value.get("verdict") not in {"pass", "fail"}:
        return False
    corpus = value.get("corpus")
    protocol = _benchmark_protocol(str(benchmark["id"]))
    metrics = value.get("metrics")
    scoring_valid = (
        isinstance(metrics, dict)
        and all(
            name in metrics for name in ("precision", "recall", "specificity", "f1")
        )
        if protocol == "classification"
        else _protocol_metrics_valid(protocol, value.get("protocol_metrics"))
        and _protocol_acceptance(value)
    )
    return bool(
        isinstance(corpus, dict)
        and corpus.get("sha256") == benchmark["corpus_sha256"]
        and scoring_valid
        and value.get("replay_protected") is True
        and isinstance(corpus.get("authority"), dict)
        and corpus["authority"].get("organization_approved") is True
    )


_LABORATORY_QUALIFIED_BENCHMARKS = frozenset(
    {
        "disa-stig-scap-conformance",
        "iec-62443-system-conformance",
        "process-capability-assessor-agreement",
        "architecture-evaluation-scenarios",
        "iec-62443-patch-management-exercise",
        "do355-continuing-airworthiness-exercise",
        "iacs-maritime-cyber-conformance",
        "swift-cscf-independent-assessment",
        "regional-cyber-maturity-assessment",
        "automotive-software-update-conformance",
        "energy-product-security-conformance",
        "enhanced-cui-oscal-conformance",
        "ict-continuity-recovery-exercise",
        "digital-forensics-chain-of-custody",
        "nist-cfreds-cftt",
        "w3c-act-rules-conformance",
        "cis-cat-scap-platform-conformance",
        "iso-29119-test-process-conformance",
        "square-quality-in-use-cloud",
        "risk-technique-calibration",
        "tls-protocol-conformance",
        "reproducible-build-variation",
        "cisa-secure-by-design-negative-assurance",
        "amtso-malware-protection-evaluation",
        "dice-attestation-conformance",
        "telecom-security-controls-conformance",
        "nice-workforce-coverage",
        "penetration-test-engagement-quality",
        "dora-delivery-outcomes",
        "cmvp-fips-140-3-validation",
        "iso-19790-24759-module-conformance",
        "biometric-performance-pad",
        "interlaboratory-proficiency-testing",
        "eucc-scheme-assurance",
        "mcp-client-server-security-conformance",
        "aws-fsbp-securityhub-conformance",
        "microsoft-mcsb-defender-conformance",
        "gcp-enterprise-foundations-conformance",
        "first-csirt-psirt-maturity-assessment",
        "memory-safety-engineering-conformance",
        "ieee-ai-governance-wellbeing-assessment",
        "organizational-resilience-bia-exercise",
        "openssf-best-practices-badge-conformance",
        "isms-implementation-process-assessment",
        "a2a-protocol-security-conformance",
        "sesip-iot-platform-evaluation-conformance",
        "w3c-web-platform-defense-conformance",
        "dora-level2-technical-standards-conformance",
        "ffiec-it-handbook-assessment",
        "bsi-c5-cloud-assurance-assessment",
        "fcc-cyber-trust-mark-conformance",
        "openid-digital-credential-conformance",
        "cisa-scuba-saas-posture-conformance",
        "cis-kubernetes-hardening-conformance",
        "linddun-privacy-threat-model-conformance",
        "rasp-prevention-effectiveness",
        "gsma-nesas-scas-assurance",
        "tisax-vda-isa-assessment",
        "c2pa-content-credentials-conformance",
        "pci-payment-acceptance-conformance",
        "oidf-fapi-conformance",
        "fedramp-20x-continuous-validation",
        "fido2-authenticator-conformance",
        "eudi-wallet-functional-conformance",
        "hitrust-csf-assessment",
        "pci-secure-software-conformance",
        "nis2-implementing-regulation-conformance",
        "nist-supplier-due-diligence",
        "owasp-samm-assessment-benchmark",
    }
)


def _benchmark_runner_contract(benchmark: dict[str, Any]) -> dict[str, Any]:
    identifier = str(benchmark["id"])
    protocol = _benchmark_protocol(identifier)
    stochastic = identifier in {
        "cyberseceval-4",
        "mlcommons-ailuminate",
        "agentic-security-holdout",
        "agentdojo",
        "harmbench",
        "agentharm",
        "garak-llm-probe-conformance",
        "nist-aria-inspect-evaluation",
        "ai-agentic-testing-conformance",
        "pyrit-ai-red-team",
        "mlcommons-ailuminate-safety",
        "mlcommons-ailuminate-jailbreak",
    }
    continuous_fuzzing = identifier == "oss-fuzz-clusterfuzzlite"
    laboratory_qualified = identifier in _LABORATORY_QUALIFIED_BENCHMARKS
    required_execution_evidence = [
        "verified-report-checksum",
        "corpus-revision",
        "dataset-license-digest",
        "label-authority-digest",
        "contamination-manifest",
        "split-strategy",
        "runner-identity",
        "target-or-fixture-digest",
        "tool-and-query-versions",
        "environment-fingerprint",
        "oracle-manifest",
        "negative-controls",
        "isolation-receipt",
        "runner-oci-image-digest",
        "runner-sbom-digest",
        "runner-provenance-digest",
        "runner-image-sbom-provenance-subject-binding",
        "resource-limit-receipt",
        "resource-limit-enforcement",
        "network-policy-digest",
        "egress-transcript-digest",
        "network-and-egress-enforcement",
        "target-cleanup-destruction-receipt",
        "cleanup-validation",
        "trusted-time",
        "replay-protection",
    ]
    required_execution_evidence.append(
        "confusion-matrix" if protocol == "classification" else "protocol-metrics"
    )
    if protocol != "classification":
        required_execution_evidence.append("acceptance-criteria-digest")
    if laboratory_qualified:
        required_execution_evidence.extend(
            [
                "method-validation-digest",
                "evaluator-competency-digest",
                "impartiality-review-digest",
                "measurement-traceability-digest",
            ]
        )
    if identifier == "epss-kev-temporal-backtest":
        required_execution_evidence.extend(
            [
                "point-in-time-snapshot-digests",
                "future-data-exclusion",
                "outcome-authority-digest",
                "calibration-and-budget-metrics",
            ]
        )
    if identifier in {"sv-comp", "test-comp"}:
        required_execution_evidence.extend(
            [
                "competition-task-definition-digest",
                "validated-witness-or-test-suite-digest",
                "resource-limit-receipt",
            ]
        )
    if identifier in {"sigstore-client-conformance", "slsa-verifier-conformance"}:
        required_execution_evidence.extend(
            [
                "conformance-suite-digest",
                "trust-root-digest",
                "identity-policy-digest",
                "negative-verification-cases",
            ]
        )
    if identifier == "scitt-transparency-conformance":
        required_execution_evidence.extend(
            [
                "scitt-registration-policy-digest",
                "cose-trust-root-digest",
                "signed-statement-and-receipt-fixtures",
                "inclusion-and-consistency-proofs",
                "equivocation-and-replay-negative-cases",
            ]
        )
    if identifier in {
        "cloud-native-api-service-mesh-conformance",
        "multicloud-kubernetes-attack-paths",
    }:
        required_execution_evidence.extend(
            [
                "disposable-cloud-target-receipt",
                "tenant-and-workload-identity-map",
                "gateway-and-service-mesh-policy-digest",
                "control-plane-and-data-plane-observations",
                "destructive-action-authorization",
            ]
        )
    if identifier in {
        "api-contract-spec-conformance",
        "opentelemetry-semantic-conformance",
    }:
        required_execution_evidence.extend(
            [
                "official-schema-or-specification-digest",
                "positive-negative-and-downgrade-fixtures",
                "round-trip-semantic-equivalence-report",
                "unknown-field-and-version-drift-results",
            ]
        )
    if identifier == "ai-agentic-testing-conformance":
        required_execution_evidence.extend(
            [
                "model-and-agent-configuration-digest",
                "tool-authority-and-memory-boundary-manifest",
                "stochastic-seed-and-sampling-policy",
                "test-oracle-and-human-review-digest",
                "utility-and-security-confidence-intervals",
            ]
        )
    if identifier in {
        "harmbench",
        "agentharm",
        "garak-llm-probe-conformance",
        "pyrit-ai-red-team",
        "mlcommons-ailuminate-safety",
        "mlcommons-ailuminate-jailbreak",
    }:
        required_execution_evidence.extend(
            [
                "target-and-evaluator-model-configuration-digests",
                "attack-probe-detector-and-template-manifest",
                "seed-sampling-temperature-and-repetition-policy",
                "harmful-output-handling-and-human-adjudication-policy",
                "scorer-prompt-injection-and-manipulation-negative-tests",
                "public-corpus-contamination-assessment",
                "private-holdout-security-and-utility-results",
                "attack-success-and-utility-confidence-intervals",
            ]
        )
    if identifier == "agentharm":
        required_execution_evidence.extend(
            [
                "tool-authority-and-side-effect-boundary-manifest",
                "synthetic-secret-account-and-resource-manifest",
                "step-budget-kill-switch-reset-and-destruction-receipts",
            ]
        )
    if identifier == "garak-llm-probe-conformance":
        required_execution_evidence.extend(
            [
                "garak-lock-plugin-allowlist-and-dependency-digests",
                "probe-detector-compatibility-and-calibration-results",
                "generator-rate-token-cost-and-credential-boundary-receipts",
            ]
        )
    if identifier == "pyrit-ai-red-team":
        required_execution_evidence.extend(
            [
                "pyrit-release-lock-and-environment-digest",
                "scenario-objective-technique-and-converter-manifest",
                "target-scorer-memory-and-authority-boundary-manifest",
                "scorer-calibration-and-cross-evaluator-results",
                "step-token-time-spend-kill-switch-reset-and-cleanup-receipts",
            ]
        )
    if identifier == "nist-8286-enterprise-risk-register":
        required_execution_evidence.extend(
            [
                "nist-8286-series-and-schema-digests",
                "risk-register-and-detail-record-validation-results",
                "estimation-prioritization-and-response-reperformance",
                "risk-rollup-lineage-correlation-and-unit-analysis",
                "business-impact-appetite-tolerance-and-mutation-results",
            ]
        )
    if identifier == "cis-ram-attack-path-analysis":
        required_execution_evidence.extend(
            [
                "cis-ram-edition-license-and-risk-criteria-digests",
                "control-attack-model-veris-and-asset-scope-digests",
                "blinded-assessor-labels-and-agreement",
                "expectancy-impact-safeguard-and-treatment-reperformance",
                "sensitivity-adjudication-and-risk-acceptance-ledger",
            ]
        )
    if identifier == "square-quality-governance":
        required_execution_evidence.extend(
            [
                "licensed-25001-requirement-set-digest",
                "quality-plan-method-tool-and-measurement-digests",
                "competence-independence-and-resource-records",
                "evaluation-decision-and-feedback-trace",
                "management-fault-injection-results",
            ]
        )
    if identifier == "iso-42106-differentiated-ai-benchmarking":
        required_execution_evidence.extend(
            [
                "licensed-42106-guidance-and-quality-model-digests",
                "complexity-context-stakeholder-and-strata-design",
                "sample-repetition-uncertainty-and-aggregation-plan",
                "metamorphic-rank-stability-and-evaluator-robustness-results",
                "differentiated-threshold-decision-and-claim-boundary-record",
            ]
        )
    if identifier == "enterprise-architecture-governance":
        required_execution_evidence.extend(
            [
                "licensed-framework-edition-and-requirement-map-digests",
                "architecture-model-exchange-and-semantic-validation",
                "stakeholder-concern-decision-waiver-and-roadmap-trace",
                "blinded-assessor-agreement-and-adjudication",
                "quantitative-risk-sensitivity-and-claim-boundary-record",
            ]
        )
    additional_contract_evidence = {
        "owasp-aisvs-conformance": (
            "aisvs-release-requirement-and-level-digests",
            "ai-system-boundary-and-applicability-map",
            "requirement-control-test-evidence-trace",
            "prompt-data-model-tool-and-memory-negative-cases",
            "mutation-independent-review-and-adjudication-results",
        ),
        "iso-25058-ai-quality-evaluation": (
            "licensed-25058-criteria-and-quality-model-digests",
            "context-stakeholder-measure-and-threshold-plan",
            "dataset-strata-uncertainty-and-limitation-manifest",
            "reperformance-metamorphic-and-adverse-case-results",
            "independent-decision-and-monitoring-record",
        ),
        "eucc-scheme-assurance": (
            "eucc-regulation-amendment-and-sota-digests",
            "cc-cem-protection-profile-and-security-target-map",
            "itsef-certification-body-accreditation-and-authority-record",
            "certificate-product-version-configuration-and-registry-binding",
            "assurance-continuity-vulnerability-and-change-results",
        ),
        "cisa-secure-software-attestation": (
            "common-form-and-ssdf-claim-map-digests",
            "producer-product-version-and-release-subject-binding",
            "signatory-authority-signature-time-and-revocation-record",
            "practice-evidence-exception-and-compensating-control-trace",
            "forgery-replay-staleness-and-change-trigger-results",
        ),
        "ieee-7000-ai-ethics-conformance": (
            "licensed-ieee-7000-series-criteria-digests",
            "stakeholder-value-harm-and-requirement-trace",
            "transparency-privacy-bias-and-boundary-test-plan",
            "fail-safe-intervention-recovery-and-appeal-results",
            "subgroup-uncertainty-tradeoff-and-adjudication-record",
        ),
        "ai-use-case-security-privacy": (
            "licensed-24030-27563-criteria-and-use-case-digests",
            "domain-context-stakeholder-data-and-boundary-model",
            "security-privacy-risk-control-and-assurance-plan",
            "normal-adverse-out-of-domain-and-misuse-results",
            "residual-risk-limitation-and-independent-review-record",
        ),
        "it-quality-governance-assessor-agreement": (
            "licensed-38500-9001-requirement-map-digests",
            "governance-quality-risk-and-performance-case-set",
            "blinded-assessor-labels-agreement-and-competence",
            "nonconformity-corrective-action-and-improvement-trace",
            "adjudication-decision-and-claim-boundary-record",
        ),
        "nist-csf-profile-gap-reassessment": (
            "csf-2-core-sp-1301-and-informative-reference-digests",
            "organizational-scope-current-and-target-profile-digests",
            "gap-risk-priority-action-owner-and-dependency-trace",
            "identifier-mutation-regression-and-reassessment-results",
            "approval-exception-expiry-and-progress-record",
        ),
        "mlcommons-ailuminate-safety": (
            "ailuminate-safety-release-and-assessment-standard-digests",
            "sut-locale-persona-hazard-and-prompt-split-manifest",
            "evaluator-ensemble-calibration-and-reference-system-digests",
            "public-private-contamination-and-grading-results",
            "harmful-output-utility-uncertainty-and-claim-boundary-record",
        ),
        "mlcommons-ailuminate-jailbreak": (
            "ailuminate-jailbreak-release-attack-and-baseline-digests",
            "sut-attack-scenario-locale-and-protected-split-manifest",
            "evaluator-ensemble-calibration-and-reference-system-digests",
            "naive-versus-jailbreak-safety-and-grading-results",
            "contamination-variance-utility-and-claim-boundary-record",
        ),
        "privacy-engineering-pet-conformance": (
            "licensed-27561-27564-27565-criteria-digests",
            "privacy-objective-model-data-flow-and-attacker-boundary",
            "zkp-statement-relation-setup-parameter-and-implementation-digests",
            "malformed-replay-linkability-composition-and-differential-results",
            "cryptographic-review-residual-risk-and-agility-record",
        ),
        "mcp-client-server-security-conformance": (
            "mcp-2025-11-25-schema-security-and-feature-digests",
            "client-server-proxy-transport-and-capability-matrix",
            "oauth-discovery-resource-scope-token-and-redirect-results",
            "tool-resource-prompt-elicitation-sampling-and-task-policy-trace",
            "malformed-drift-confused-deputy-ssrf-injection-replay-and-cleanup-results",
        ),
        "aws-fsbp-securityhub-conformance": (
            "fsbp-control-snapshot-and-securityhub-model-digests",
            "aws-account-ou-region-resource-and-coverage-inventory",
            "securityhub-finding-suppression-exception-and-remediation-trace",
            "independent-inventory-drift-and-negative-case-results",
            "cloudtrail-cleanup-rescan-and-claim-boundary-record",
        ),
        "microsoft-mcsb-defender-conformance": (
            "mcsb-v1-control-and-service-baseline-digests",
            "azure-tenant-management-group-subscription-and-resource-inventory",
            "defender-assessment-exemption-and-remediation-trace",
            "resource-graph-drift-and-negative-case-results",
            "activity-log-cleanup-rescan-and-preview-separation-record",
        ),
        "gcp-enterprise-foundations-conformance": (
            "gcp-foundation-guide-and-terraform-revision-digests",
            "gcp-organization-folder-project-resource-and-identity-inventory",
            "organization-policy-architecture-scc-deviation-and-remediation-trace",
            "asset-inventory-drift-and-negative-case-results",
            "audit-log-cleanup-rescan-and-claim-boundary-record",
        ),
        "first-csirt-psirt-maturity-assessment": (
            "first-framework-maturity-and-metric-digests",
            "mandate-constituency-service-role-and-competence-map",
            "incident-vulnerability-disclosure-coordination-and-outcome-results",
            "blinded-assessor-agreement-conflict-and-adjudication-record",
            "capability-gap-owner-milestone-and-reassessment-trace",
        ),
        "memory-safety-engineering-conformance": (
            "unsafe-language-construct-ffi-dependency-and-reachability-inventory",
            "production-build-toolchain-hardening-and-mitigation-digests",
            "static-sanitizer-fuzz-crash-and-regression-results",
            "privilege-exposure-consequence-exception-and-residual-risk-trace",
            "migration-roadmap-parity-performance-and-reassessment-record",
        ),
        "ieee-ai-governance-wellbeing-assessment": (
            "licensed-ieee-2863-and-7010-criteria-digests",
            "ai-governance-authority-role-lifecycle-and-provider-map",
            "stakeholder-domain-indicator-baseline-and-impact-results",
            "blinded-reviewer-agreement-tradeoff-and-adjudication-record",
            "monitoring-appeal-incident-retirement-and-improvement-trace",
        ),
        "organizational-resilience-bia-exercise": (
            "licensed-22316-and-22317-criteria-digests",
            "product-service-activity-resource-and-dependency-model",
            "impact-tolerance-rto-rpo-capacity-and-assumption-record",
            "disruption-degradation-failover-restoration-and-reconciliation-results",
            "safety-cleanup-variance-improvement-and-reassessment-trace",
        ),
        "openssf-best-practices-badge-conformance": (
            "openssf-baseline-and-metal-criteria-digests",
            "project-identity-response-export-and-repository-snapshot",
            "criterion-applicability-answer-source-and-freshness-map",
            "stale-link-disabled-control-inflated-level-and-identity-results",
            "recomputed-level-independent-sample-and-claim-boundary-record",
        ),
        "isms-implementation-process-assessment": (
            "licensed-27003-and-27022-criteria-digests",
            "isms-scope-process-interface-control-measure-and-record-map",
            "implementation-tailoring-capability-and-improvement-results",
            "blinded-assessor-agreement-conflict-and-adjudication-record",
            "conformity-capability-and-certification-claim-boundary-review",
        ),
        "a2a-protocol-security-conformance": (
            "a2a-1.0.0-proto-specification-tck-and-sdk-digests",
            "agent-card-jws-provider-endpoint-version-binding-and-tenant-results",
            "principal-skill-task-message-artifact-and-subscription-authorization-trace",
            "http-json-jsonrpc-grpc-stream-and-webhook-interoperability-results",
            "downgrade-cross-tenant-credential-ssrf-replay-race-and-cleanup-results",
        ),
        "sesip-iot-platform-evaluation-conformance": (
            "sesip-1.2-en17927-criteria-profile-and-mapping-digests",
            "toe-platform-part-product-version-configuration-and-asset-boundary",
            "sfr-spp-sar-assurance-level-threat-and-environment-trace",
            "composition-certificate-vulnerability-change-and-expiry-results",
            "scheme-laboratory-evaluator-authority-and-negative-claim-record",
        ),
        "first-tlp-iep-information-handling-conformance": (
            "first-tlp-2.0-iep-2.0-framework-json-and-policy-digests",
            "label-recipient-community-action-attribution-and-redistribution-results",
            "stix-taxii-json-roundtrip-and-semantic-equivalence-report",
            "policy-reference-immutability-overlap-date-and-unknown-policy-results",
            "downgrade-removal-unauthorized-sharing-and-audit-negative-cases",
        ),
        "veris-incident-schema-conformance": (
            "veris-1.3.6-schema-vocabulary-and-example-digests",
            "deidentified-incident-and-golden-classification-set-digests",
            "actor-action-asset-attribute-timeline-impact-and-unknown-results",
            "roundtrip-aggregate-deidentification-and-analytic-equivalence-results",
            "schema-validity-versus-incident-truth-claim-boundary-record",
        ),
        "w3c-web-platform-defense-conformance": (
            "w3c-csp2-sri1-and-web-platform-test-digests",
            "browser-policy-header-resource-origin-and-engine-manifest",
            "nonce-hash-source-frame-form-base-connect-report-and-integrity-results",
            "redirect-cors-cdn-substitution-multi-policy-and-fallback-results",
            "cross-engine-block-report-recovery-and-limitation-record",
        ),
        "dora-level2-technical-standards-conformance": (
            "eu-1772-1774-2956-301-302-1190-consolidated-act-digests",
            "entity-applicability-ict-risk-control-critical-function-and-dependency-map",
            "incident-classification-timeline-template-and-secure-channel-results",
            "entity-group-provider-contract-function-location-and-register-results",
            "tlpt-scope-tester-safety-finding-remediation-closure-and-claim-record",
        ),
        "ffiec-it-handbook-assessment": (
            "ffiec-dam-2024-aio-2021-information-security-2016-digests",
            "institution-service-provider-scope-risk-and-applicability-record",
            "development-architecture-operations-security-and-incident-results",
            "blinded-examiner-agreement-competence-conflict-and-adjudication-record",
            "retired-cat-exclusion-and-handbook-claim-boundary-review",
        ),
        "bsi-c5-cloud-assurance-assessment": (
            "bsi-c5-2020-criteria-and-evaluation-guidance-digests",
            "cloud-service-boundary-location-subservice-and-description-map",
            "control-customer-responsibility-deviation-and-incident-results",
            "blinded-assessor-agreement-independence-conflict-and-adjudication-record",
            "attestation-versus-certification-claim-boundary-review",
        ),
        "fcc-cyber-trust-mark-conformance": (
            "fcc-24-26-baseline-test-procedure-and-program-digests",
            "iot-product-component-software-support-and-configuration-boundary",
            "recognized-laboratory-test-report-remediation-and-renewal-results",
            "applicant-authorization-qr-registry-and-consumer-information-trace",
            "forgery-copied-label-redirect-expiry-withdrawal-and-overclaim-results",
        ),
        "openid-digital-credential-conformance": (
            "vc-data-model-data-integrity-status-openid-and-haip-specification-digests",
            "issuer-wallet-verifier-format-cryptosuite-and-trust-policy-matrix",
            "issuance-presentation-selective-disclosure-status-and-holder-binding-results",
            "malformed-replay-downgrade-confusion-correlation-and-privacy-negative-cases",
            "official-conformance-suite-report-and-certification-claim-boundary-record",
        ),
        "cisa-scuba-saas-posture-conformance": (
            "scuba-m365-gws-baseline-assessment-tool-and-policy-snapshot-digests",
            "tenant-service-license-identity-resource-and-api-coverage-inventory",
            "read-only-posture-result-exception-owner-expiry-and-remediation-trace",
            "independent-drift-unassessed-resource-and-regression-results",
            "authorization-minimization-cleanup-and-production-mutation-claim-record",
        ),
        "cis-kubernetes-hardening-conformance": (
            "licensed-cis-kubernetes-2.0.1-criteria-and-tool-digests",
            "cluster-version-role-control-plane-node-workload-and-applicability-map",
            "automated-and-manual-check-evidence-exception-and-remediation-trace",
            "admission-runtime-network-rbac-secret-and-audit-negative-cases",
            "independent-rescan-drift-and-no-certification-claim-record",
        ),
        "linddun-privacy-threat-model-conformance": (
            "linddun-pro-methodology-taxonomy-and-template-digests",
            "data-flow-entity-trust-boundary-asset-purpose-and-data-subject-model",
            "threat-tree-elicitation-misuse-case-mitigation-and-test-trace",
            "blinded-assessor-labels-agreement-omission-mutation-and-adjudication-results",
            "residual-privacy-risk-approval-expiry-and-reassessment-record",
        ),
        "owasp-benchmark-ast-modality-comparison": (
            "owasp-benchmark-release-label-and-category-digests",
            "sast-dast-iast-tool-version-configuration-and-capability-manifest",
            "matched-corpus-target-build-request-and-observation-boundary",
            "per-modality-confusion-matrices-overlap-latency-and-resource-results",
            "unsupported-language-runtime-and-rasp-separation-claim-boundary-record",
        ),
        "rasp-prevention-effectiveness": (
            "rasp-agent-policy-runtime-and-application-fixture-digests",
            "attack-technique-route-data-flow-and-protection-coverage-manifest",
            "blocked-observed-bypassed-false-positive-latency-and-stability-results",
            "instrumentation-health-tamper-bypass-fail-open-and-fail-closed-cases",
            "kill-switch-reset-cleanup-and-non-production-claim-boundary-record",
        ),
        "gsma-nesas-scas-assurance": (
            "nesas-3.0-scas-release-and-product-applicability-digests",
            "vendor-development-security-process-and-network-product-boundary",
            "accredited-laboratory-evaluator-method-tool-and-competency-record",
            "scas-functional-robustness-penetration-vulnerability-and-retest-results",
            "scheme-report-vulnerability-change-and-no-certification-claim-record",
        ),
        "tisax-vda-isa-assessment": (
            "licensed-vda-isa-6.0.3-and-tisax-handbook-criteria-digests",
            "scope-locations-objectives-protection-needs-participant-and-provider-map",
            "control-maturity-evidence-finding-corrective-action-and-follow-up-trace",
            "blinded-assessor-agreement-independence-conflict-and-adjudication-results",
            "result-sharing-label-expiry-and-no-suite-issued-label-claim-record",
        ),
        "c2pa-content-credentials-conformance": (
            "c2pa-2.4-specification-schema-test-and-trust-list-digests",
            "asset-manifest-claim-assertion-ingredient-signature-and-trust-policy-map",
            "create-read-validate-roundtrip-edit-redaction-and-revocation-results",
            "tamper-unknown-signer-replay-misbinding-parser-and-resource-negative-cases",
            "provenance-versus-content-truth-and-identity-claim-boundary-record",
        ),
        "pci-payment-acceptance-conformance": (
            "licensed-mpoc-p2pe-program-requirement-and-test-procedure-digests",
            "solution-component-payment-flow-account-data-key-and-applicability-map",
            "laboratory-control-domain-test-evidence-exception-and-remediation-trace",
            "tamper-overlay-debug-rooting-key-substitution-decryption-and-update-cases",
            "synthetic-data-cleanup-and-no-pci-listing-or-validation-claim-record",
        ),
        "oidf-fapi-conformance": (
            "fapi-2.0-final-attacker-model-message-signing-and-suite-digests",
            "authorization-server-client-resource-server-profile-and-key-boundary",
            "par-jarm-dpop-or-mtls-token-issuer-audience-and-replay-results",
            "downgrade-algorithm-confusion-key-substitution-ssrf-and-misbinding-cases",
            "official-suite-report-and-no-certification-claim-boundary-record",
        ),
        "fedramp-20x-continuous-validation": (
            "fedramp-20x-class-rule-ksi-and-validation-code-digests",
            "cloud-service-offering-boundary-goal-measure-and-owner-map",
            "independent-validation-sample-and-continuous-monitoring-results",
            "stale-evidence-boundary-drift-measure-gaming-and-failure-cases",
            "marketplace-status-agency-decision-and-no-authorization-claim-record",
        ),
        "fido2-authenticator-conformance": (
            "ctap-2.2-webauthn-mds-and-functional-suite-digests",
            "client-authenticator-rp-origin-credential-transport-and-aaguid-map",
            "functional-transport-user-verification-and-metadata-results",
            "malformed-cbor-downgrade-replay-revocation-and-recovery-cases",
            "official-suite-report-and-no-fido-certification-claim-record",
        ),
        "eudi-wallet-functional-conformance": (
            "eudi-acts-arf-3.0.0-fcaf-and-reference-fixture-digests",
            "wallet-unit-provider-issuer-rp-trust-list-pid-and-eaa-boundary",
            "issuance-presentation-wallet-to-wallet-and-lifecycle-results",
            "over-request-replay-downgrade-registration-recovery-and-privacy-cases",
            "member-state-certification-and-no-legal-conformity-claim-record",
        ),
        "hitrust-csf-assessment": (
            "licensed-hitrust-csf-11.8.0-and-assurance-program-digests",
            "assessment-type-scope-factor-requirement-and-inheritance-map",
            "blinded-assessor-agreement-quality-assurance-and-scoring-results",
            "scope-drift-stale-evidence-maturity-inflation-and-conflict-cases",
            "report-validity-corrective-action-and-no-certification-claim-record",
        ),
        "pci-secure-software-conformance": (
            "licensed-pci-secure-software-2.0-secure-slc-1.1-and-program-digests",
            "product-sdk-module-sensitive-asset-lifecycle-and-listing-boundary",
            "product-lifecycle-delta-vulnerability-and-annual-attestation-results",
            "scope-omission-change-tier-api-component-and-stale-listing-cases",
            "assessor-authority-synthetic-data-and-no-pci-validation-claim-record",
        ),
        "nis2-implementing-regulation-conformance": (
            "nis2-implementing-regulation-2024-2690-and-enisa-guidance-digests",
            "entity-service-sector-member-state-measure-and-evidence-map",
            "technical-control-effectiveness-incident-and-supply-chain-results",
            "applicability-asset-continuity-threshold-timing-and-exception-cases",
            "legal-guidance-boundary-and-no-regulatory-notification-claim-record",
        ),
        "nist-supplier-due-diligence": (
            "nist-sp-1326-and-csrm-source-snapshot-digests",
            "supplier-product-ownership-provenance-dependency-and-source-map",
            "blinded-risk-decision-contract-monitoring-and-reassessment-results",
            "alias-ownership-staleness-conflict-concentration-and-deception-cases",
            "confidence-gaps-and-no-absence-of-adverse-data-assurance-record",
        ),
        "owasp-samm-assessment-benchmark": (
            "owasp-samm-2.1.0-model-assessment-toolbox-and-dataset-digests",
            "organization-scope-practice-activity-quality-criteria-and-evidence-map",
            "blinded-assessor-agreement-roadmap-and-reassessment-results",
            "partial-criteria-stale-evidence-scope-drift-and-level-inflation-cases",
            "cohort-size-privacy-representativeness-and-no-certification-claim-record",
        ),
    }
    required_execution_evidence.extend(additional_contract_evidence.get(identifier, ()))
    if identifier == "owasp-cornucopia-threat-model":
        required_execution_evidence.extend(
            [
                "cornucopia-edition-language-license-and-card-digests",
                "architecture-boundary-and-applicability-map",
                "card-threat-control-test-and-risk-trace",
                "omission-mutation-and-negative-case-results",
                "blinded-independent-review-and-adjudication",
            ]
        )
    if identifier == "s2c2f-consumer-dependency-conformance":
        required_execution_evidence.extend(
            [
                "dependency-admission-policy-digest",
                "package-origin-and-integrity-receipts",
                "substitution-and-quarantine-negative-cases",
                "compromise-response-exercise",
            ]
        )
    if identifier == "securitytxt-patch-operations-conformance":
        required_execution_evidence.extend(
            [
                "security-txt-parser-and-http-transcript",
                "asset-and-patch-inventory-digest",
                "risk-prioritization-and-exception-records",
                "rollback-and-post-deployment-verification",
            ]
        )
    if identifier in {
        "automotive-software-update-conformance",
        "energy-product-security-conformance",
    }:
        required_execution_evidence.extend(
            [
                "licensed-requirement-set-digest",
                "representative-product-configuration",
                "safety-and-availability-impact-review",
                "negative-case-and-recovery-transcript",
            ]
        )
    if identifier in {
        "architecture-evaluation-scenarios",
        "process-capability-assessor-agreement",
        "cis-ram-attack-path-analysis",
        "enterprise-architecture-governance",
        "it-quality-governance-assessor-agreement",
    }:
        required_execution_evidence.extend(
            ["blinded-assessor-labels", "inter-rater-agreement"]
        )
    if identifier == "cwe-mapping-conformance":
        required_execution_evidence.extend(
            ["cwe-release-digest", "mapping-abstraction-policy-digest"]
        )
    if identifier == "structured-assurance-case-conformance":
        required_execution_evidence.extend(
            [
                "sacm-metamodel-and-schema-digest",
                "claim-argument-evidence-graph-digest",
                "defeater-and-confidence-policy-digest",
                "graph-mutation-and-semantic-validation-results",
                "independent-assurance-case-review",
            ]
        )
    if identifier == "integrity-vv-conformance":
        required_execution_evidence.extend(
            [
                "ieee-1012-requirement-set-digest",
                "integrity-level-classification-record",
                "vv-independence-and-competence-record",
                "system-software-hardware-interface-trace",
                "reuse-cots-and-anomaly-disposition-evidence",
            ]
        )
    if identifier == "cmvp-fips-140-3-validation":
        required_execution_evidence.extend(
            [
                "cmvp-scheme-publication-snapshot-digest",
                "cmvp-referenced-edition-map",
                "module-security-policy-and-boundary-digest",
                "algorithm-and-module-certificate-status-snapshot",
                "implementation-guidance-and-test-decision-trace",
            ]
        )
    if identifier == "iso-19790-24759-module-conformance":
        required_execution_evidence.extend(
            [
                "licensed-19790-24759-requirement-set-digest",
                "module-level-boundary-and-configuration-digest",
                "vendor-evidence-and-test-assertion-trace",
                "calibration-uncertainty-and-deviation-record",
                "fault-and-non-invasive-test-authorization",
            ]
        )
    if identifier == "biometric-performance-pad":
        required_execution_evidence.extend(
            [
                "consent-privacy-and-retention-governance",
                "sample-size-and-demographic-analysis-plan",
                "locked-threshold-and-sensor-configuration-digest",
                "presentation-attack-instrument-manifest",
                "stratified-confidence-interval-report",
            ]
        )
    if identifier == "service-management-security-integration":
        required_execution_evidence.extend(
            [
                "licensed-20000-1-27013-requirement-map-digest",
                "service-configuration-and-ownership-baseline",
                "change-release-deployment-trace",
                "incident-problem-supplier-continuity-trace",
                "fault-recovery-and-corrective-action-results",
            ]
        )
    if identifier == "interlaboratory-proficiency-testing":
        required_execution_evidence.extend(
            [
                "proficiency-scheme-plan-digest",
                "homogeneity-stability-and-assigned-value-evidence",
                "participant-scope-blinding-and-confidentiality-record",
                "agreement-bias-drift-and-outlier-analysis",
                "appeal-adjudication-and-corrective-action-ledger",
            ]
        )
    return {
        "adapter": identifier,
        "protocol": protocol,
        "expected_results": (
            "organization-approved-labels"
            if benchmark["version"] == "organization-pinned"
            else "official-corpus-labels"
        ),
        "minimum_repetitions": 5 if stochastic else 3 if continuous_fuzzing else 1,
        "required_execution_evidence": list(dict.fromkeys(required_execution_evidence)),
        "score_semantics": (
            [
                "precision",
                "recall",
                "false-positive-rate",
                "youden-j",
                "wilson-95-percent-confidence-interval",
            ]
            if protocol == "classification"
            else [
                protocol,
                "protocol-specific-acceptance-criteria",
                "reproducibility-evidence",
            ]
        ),
    }


def _benchmark_reproducibility_gaps(
    value: object, benchmark: dict[str, Any] | None = None
) -> list[str]:
    if not isinstance(value, dict):
        return []
    report = value.get("report")
    matrix = value.get("confusion_matrix")
    corpus = value.get("corpus")
    time_authority = value.get("time_authority")
    gaps = []
    if value.get("schema_version") in {"1.1", "1.2"}:
        authorities = (
            benchmark.get("trusted_receipt_authorities")
            if isinstance(benchmark, dict)
            else None
        )
        if not isinstance(authorities, list) or not authorities:
            gaps.append(
                "benchmark execution receipt signature lacks lifecycle-aware trusted-party admission"
            )
        else:
            try:
                authority_index = {
                    ("execution-receipt", str(item["key_id"])): item
                    for item in authorities
                }
                verify_execution_receipt_signature(
                    value,
                    {
                        "schema_version": "1.1",
                        "authority_index": authority_index,
                    },
                )
            except BenchmarkAssuranceError:
                gaps.append("benchmark execution receipt signature is invalid")
    sufficiency = value.get("statistical_sufficiency")
    if isinstance(sufficiency, dict) and sufficiency.get("enforced") is True:
        if sufficiency.get("complete") is not True:
            gaps.append("benchmark statistical sufficiency is incomplete")
        execution = value.get("execution_context")
        if not isinstance(execution, dict):
            gaps.append("benchmark statistical design evidence is missing")
        else:
            for name in (
                "power_analysis_sha256",
                "leakage_check_sha256",
                "duplicate_check_sha256",
            ):
                if not _digest(str(execution.get(name) or "")):
                    gaps.append(f"benchmark {name} is missing or invalid")
            if execution.get("holdout_sequestered") is not True:
                gaps.append("benchmark holdout sequestration is not proven")
            repetitions = execution.get("repetitions")
            if (
                isinstance(repetitions, bool)
                or not isinstance(repetitions, int)
                or repetitions < 3
            ):
                gaps.append("benchmark repeated-run evidence is insufficient")
    if not isinstance(report, dict) or not _digest(
        str(report.get("checksums_sha256") or "")
    ):
        gaps.append("verified report checksum is missing")
    protocol = (
        _benchmark_protocol(str(benchmark.get("id")))
        if isinstance(benchmark, dict)
        else "classification"
    )
    if protocol == "classification" and (
        not isinstance(matrix, dict)
        or any(
            not isinstance(matrix.get(name), int) or isinstance(matrix.get(name), bool)
            for name in (
                "true_positive",
                "true_negative",
                "false_positive",
                "false_negative",
            )
        )
    ):
        gaps.append("complete confusion matrix is missing")
    if protocol != "classification":
        if not _protocol_metrics_valid(protocol, value.get("protocol_metrics")):
            gaps.append(f"valid {protocol} protocol metrics are missing")
        if not _protocol_acceptance(value):
            gaps.append(
                "approved protocol-specific acceptance criteria are missing or unmet"
            )
    if not isinstance(corpus, dict) or not _text(corpus.get("revision"), 200):
        gaps.append("corpus revision is missing")
    if (
        not isinstance(time_authority, dict)
        or time_authority.get("validated") is not True
    ):
        gaps.append("trusted evaluation time is not validated")
    if value.get("replay_protected") is not True:
        gaps.append("evaluation replay protection is missing")
    contract = benchmark.get("runner_contract") if isinstance(benchmark, dict) else None
    requires_qualified_context = isinstance(benchmark, dict) and (
        benchmark.get("version") == "organization-pinned"
        or benchmark.get("lane") == "authorized-companion"
    )
    if requires_qualified_context:
        execution = value.get("execution_context")
        if not isinstance(execution, dict):
            gaps.append("qualified benchmark execution context is missing")
        else:
            for name in (
                "target_sha256",
                "environment_sha256",
                "toolset_sha256",
                "oracle_sha256",
                "isolation_receipt_sha256",
                "runner_oci_image_sha256",
                "runner_sbom_sha256",
                "runner_provenance_sha256",
                "resource_limits_sha256",
                "network_policy_sha256",
                "egress_transcript_sha256",
                "cleanup_receipt_sha256",
                "dataset_license_sha256",
                "label_authority_sha256",
                "contamination_manifest_sha256",
            ):
                if not _digest(str(execution.get(name) or "")):
                    gaps.append(f"benchmark execution {name} is missing or invalid")
            if not _text(execution.get("runner_identity"), 300) or not _text(
                execution.get("runner_version"), 100
            ):
                gaps.append("benchmark runner identity or version is missing")
            if execution.get("isolation_validated") is not True:
                gaps.append("benchmark execution isolation is not validated")
            if execution.get("network_isolation_validated") is not True:
                gaps.append("benchmark network isolation is not validated")
            if execution.get("target_destroyed") is not True:
                gaps.append("benchmark target cleanup and destruction is not proven")
            for field, description in (
                ("runner_image_pinned", "runner OCI image pinning"),
                ("runner_sbom_matches_image", "runner SBOM subject binding"),
                ("runner_provenance_verified", "runner provenance verification"),
                (
                    "provenance_subject_matches_image",
                    "runner provenance subject binding",
                ),
                ("resource_limits_enforced", "resource-limit enforcement"),
                ("network_policy_enforced", "network-policy enforcement"),
                ("egress_transcript_complete", "egress transcript completeness"),
                ("cleanup_validated", "target cleanup validation"),
            ):
                if execution.get(field) is not True:
                    gaps.append(f"benchmark {description} is not proven")
            for name in ("positive_controls", "negative_controls"):
                count = execution.get(name)
                if isinstance(count, bool) or not isinstance(count, int) or count < 1:
                    gaps.append(f"benchmark {name} are missing")
            if execution.get("split_strategy") not in {
                "official-fixed",
                "project-split",
                "time-split",
            }:
                gaps.append("benchmark split strategy is missing or invalid")
            if (
                isinstance(benchmark, dict)
                and benchmark.get("version") == "organization-pinned"
            ):
                reviewers = execution.get("independent_reviewers")
                if (
                    isinstance(reviewers, bool)
                    or not isinstance(reviewers, int)
                    or reviewers < 2
                ):
                    gaps.append("benchmark requires at least two independent reviewers")
            if (
                isinstance(benchmark, dict)
                and benchmark.get("id") == "scanner-scale-determinism"
            ):
                for name in ("wall_time_ms", "peak_memory_bytes"):
                    measurement = execution.get(name)
                    if (
                        isinstance(measurement, bool)
                        or not isinstance(measurement, int)
                        or measurement < 1
                    ):
                        gaps.append(f"benchmark {name} measurement is missing")
                deterministic_runs = execution.get("deterministic_runs")
                if (
                    isinstance(deterministic_runs, bool)
                    or not isinstance(deterministic_runs, int)
                    or deterministic_runs < 3
                ):
                    gaps.append("benchmark requires at least three deterministic runs")
            if (
                isinstance(benchmark, dict)
                and benchmark.get("id") in _LABORATORY_QUALIFIED_BENCHMARKS
            ):
                for name in (
                    "method_validation_sha256",
                    "evaluator_competency_sha256",
                    "impartiality_review_sha256",
                    "measurement_traceability_sha256",
                ):
                    if not _digest(str(execution.get(name) or "")):
                        gaps.append(
                            f"laboratory qualification {name} is missing or invalid"
                        )
            identifier = benchmark.get("id") if isinstance(benchmark, dict) else None
            if identifier == "epss-kev-temporal-backtest":
                for name in (
                    "epss_snapshot_sha256",
                    "kev_snapshot_sha256",
                    "outcome_authority_sha256",
                ):
                    if not _digest(str(execution.get(name) or "")):
                        gaps.append(f"temporal benchmark {name} is missing or invalid")
                if execution.get("point_in_time") is not True:
                    gaps.append(
                        "temporal benchmark point-in-time execution is not proven"
                    )
                if execution.get("future_data_excluded") is not True:
                    gaps.append(
                        "temporal benchmark future-data exclusion is not proven"
                    )
                for name in (
                    "brier_score",
                    "expected_calibration_error",
                    "recall_at_budget",
                    "effort",
                ):
                    if not _ratio(execution.get(name)):
                        gaps.append(f"temporal benchmark {name} is missing or invalid")
            if identifier in {"sv-comp", "test-comp"}:
                for name in (
                    "task_definition_sha256",
                    "validated_witness_sha256",
                    "resource_limits_sha256",
                ):
                    if not _digest(str(execution.get(name) or "")):
                        gaps.append(
                            f"competition benchmark {name} is missing or invalid"
                        )
            if identifier in {
                "sigstore-client-conformance",
                "slsa-verifier-conformance",
            }:
                for name in (
                    "conformance_suite_sha256",
                    "trust_root_sha256",
                    "identity_policy_sha256",
                ):
                    if not _digest(str(execution.get(name) or "")):
                        gaps.append(f"signing conformance {name} is missing or invalid")
                negative_cases = execution.get("negative_verification_cases")
                if (
                    isinstance(negative_cases, bool)
                    or not isinstance(negative_cases, int)
                    or negative_cases < 1
                ):
                    gaps.append("signing conformance negative cases are missing")
            if identifier in {
                "architecture-evaluation-scenarios",
                "process-capability-assessor-agreement",
                "it-quality-governance-assessor-agreement",
            }:
                agreement = execution.get("inter_rater_agreement")
                if not (
                    _ratio(agreement)
                    and isinstance(agreement, (int, float))
                    and not isinstance(agreement, bool)
                    and float(agreement) >= 0.8
                ):
                    gaps.append(
                        "independent assessor agreement is missing or below 0.8"
                    )
                if execution.get("assessors_blinded") is not True:
                    gaps.append("independent assessors were not blinded")
            if identifier == "cwe-mapping-conformance":
                for name in (
                    "cwe_release_sha256",
                    "mapping_policy_sha256",
                ):
                    if not _digest(str(execution.get(name) or "")):
                        gaps.append(f"CWE mapping {name} is missing or invalid")
            specialized_digests = {
                "structured-assurance-case-conformance": (
                    "sacm_schema_sha256",
                    "assurance_graph_sha256",
                    "defeater_policy_sha256",
                    "mutation_report_sha256",
                    "independent_review_sha256",
                ),
                "integrity-vv-conformance": (
                    "ieee_1012_requirements_sha256",
                    "integrity_classification_sha256",
                    "vv_independence_sha256",
                    "interface_trace_sha256",
                    "anomaly_disposition_sha256",
                ),
                "cmvp-fips-140-3-validation": (
                    "cmvp_scheme_snapshot_sha256",
                    "referenced_edition_map_sha256",
                    "module_security_policy_sha256",
                    "certificate_status_snapshot_sha256",
                    "test_decision_trace_sha256",
                ),
                "iso-19790-24759-module-conformance": (
                    "licensed_requirements_sha256",
                    "module_claims_sha256",
                    "test_assertion_trace_sha256",
                    "calibration_uncertainty_sha256",
                    "fault_test_authorization_sha256",
                ),
                "biometric-performance-pad": (
                    "privacy_governance_sha256",
                    "analysis_plan_sha256",
                    "locked_threshold_sha256",
                    "attack_instrument_manifest_sha256",
                    "stratified_report_sha256",
                ),
                "service-management-security-integration": (
                    "licensed_requirement_map_sha256",
                    "service_baseline_sha256",
                    "change_trace_sha256",
                    "incident_continuity_trace_sha256",
                    "corrective_action_sha256",
                ),
                "interlaboratory-proficiency-testing": (
                    "proficiency_plan_sha256",
                    "assigned_value_evidence_sha256",
                    "participant_blinding_sha256",
                    "statistical_analysis_sha256",
                    "corrective_action_ledger_sha256",
                ),
                "nist-8286-enterprise-risk-register": (
                    "nist_8286_schema_set_sha256",
                    "risk_register_validation_sha256",
                    "risk_estimation_reperformance_sha256",
                    "risk_rollup_analysis_sha256",
                    "bia_appetite_mutation_sha256",
                ),
                "cis-ram-attack-path-analysis": (
                    "cis_ram_criteria_sha256",
                    "attack_model_scope_sha256",
                    "assessor_labels_sha256",
                    "risk_reperformance_sha256",
                    "adjudication_ledger_sha256",
                ),
                "square-quality-governance": (
                    "licensed_25001_requirements_sha256",
                    "quality_plan_methods_sha256",
                    "competence_resources_sha256",
                    "evaluation_decision_trace_sha256",
                    "fault_injection_results_sha256",
                ),
                "iso-42106-differentiated-ai-benchmarking": (
                    "licensed_42106_guidance_sha256",
                    "differentiation_design_sha256",
                    "sampling_uncertainty_plan_sha256",
                    "metamorphic_stability_results_sha256",
                    "claim_boundary_record_sha256",
                ),
                "enterprise-architecture-governance": (
                    "licensed_framework_map_sha256",
                    "model_semantics_validation_sha256",
                    "architecture_decision_trace_sha256",
                    "assessor_adjudication_sha256",
                    "risk_sensitivity_record_sha256",
                ),
                "pyrit-ai-red-team": (
                    "pyrit_environment_lock_sha256",
                    "scenario_technique_manifest_sha256",
                    "target_authority_boundary_sha256",
                    "scorer_calibration_sha256",
                    "execution_cleanup_receipts_sha256",
                ),
                "owasp-aisvs-conformance": (
                    "aisvs_release_sha256",
                    "ai_boundary_applicability_sha256",
                    "requirement_evidence_trace_sha256",
                    "negative_case_results_sha256",
                    "mutation_adjudication_sha256",
                ),
                "iso-25058-ai-quality-evaluation": (
                    "licensed_25058_criteria_sha256",
                    "quality_evaluation_plan_sha256",
                    "dataset_uncertainty_manifest_sha256",
                    "metamorphic_results_sha256",
                    "independent_decision_sha256",
                ),
                "eucc-scheme-assurance": (
                    "eucc_scheme_sota_sha256",
                    "cc_cem_security_target_map_sha256",
                    "laboratory_authority_sha256",
                    "certificate_subject_binding_sha256",
                    "assurance_continuity_results_sha256",
                ),
                "cisa-secure-software-attestation": (
                    "common_form_ssdf_map_sha256",
                    "release_subject_binding_sha256",
                    "signatory_authority_sha256",
                    "practice_exception_trace_sha256",
                    "forgery_replay_results_sha256",
                ),
                "ieee-7000-ai-ethics-conformance": (
                    "licensed_ieee_criteria_sha256",
                    "stakeholder_value_trace_sha256",
                    "transparency_privacy_bias_plan_sha256",
                    "failsafe_appeal_results_sha256",
                    "subgroup_adjudication_sha256",
                ),
                "ai-use-case-security-privacy": (
                    "licensed_use_case_criteria_sha256",
                    "domain_boundary_model_sha256",
                    "security_privacy_assurance_plan_sha256",
                    "adverse_use_case_results_sha256",
                    "residual_risk_review_sha256",
                ),
                "it-quality-governance-assessor-agreement": (
                    "licensed_governance_quality_map_sha256",
                    "assessment_case_set_sha256",
                    "assessor_agreement_sha256",
                    "corrective_action_trace_sha256",
                    "adjudication_record_sha256",
                ),
                "nist-csf-profile-gap-reassessment": (
                    "csf_sp1301_source_sha256",
                    "current_target_profiles_sha256",
                    "gap_action_trace_sha256",
                    "reassessment_results_sha256",
                    "approval_exception_record_sha256",
                ),
                "mlcommons-ailuminate-safety": (
                    "ailuminate_release_sha256",
                    "hazard_prompt_split_sha256",
                    "evaluator_calibration_sha256",
                    "contamination_grading_sha256",
                    "uncertainty_claim_record_sha256",
                ),
                "mlcommons-ailuminate-jailbreak": (
                    "ailuminate_jailbreak_release_sha256",
                    "attack_protected_split_sha256",
                    "evaluator_calibration_sha256",
                    "jailbreak_grading_sha256",
                    "variance_claim_record_sha256",
                ),
                "privacy-engineering-pet-conformance": (
                    "licensed_privacy_criteria_sha256",
                    "privacy_attacker_model_sha256",
                    "zkp_implementation_parameters_sha256",
                    "pet_adversarial_results_sha256",
                    "cryptographic_review_sha256",
                ),
            }
            for name in specialized_digests.get(str(identifier), ()):
                if not _digest(str(execution.get(name) or "")):
                    gaps.append(f"{identifier} execution {name} is missing or invalid")
            if identifier == "biometric-performance-pad":
                if execution.get("threshold_locked_before_test") is not True:
                    gaps.append(
                        "biometric decision threshold was not locked before test"
                    )
                if execution.get("consent_and_privacy_validated") is not True:
                    gaps.append(
                        "biometric consent and privacy governance is not validated"
                    )
                if execution.get("operator_blinded") is not True:
                    gaps.append("biometric evaluation operator is not blinded")
            if identifier == "interlaboratory-proficiency-testing":
                if execution.get("assigned_values_sequestered") is not True:
                    gaps.append("proficiency assigned values were not sequestered")
                if execution.get("participants_blinded") is not True:
                    gaps.append("proficiency participants were not blinded")
                if execution.get("collusion_controls_validated") is not True:
                    gaps.append("proficiency collusion controls are not validated")
    if isinstance(contract, dict):
        repetitions = value.get("execution_context", {}).get("repetitions")
        minimum = contract.get("minimum_repetitions")
        if (
            isinstance(minimum, int)
            and minimum > 1
            and (
                isinstance(repetitions, bool)
                or not isinstance(repetitions, int)
                or repetitions < minimum
            )
        ):
            gaps.append(f"benchmark repetitions are below required minimum {minimum}")
    return gaps


def _meets_thresholds(metrics: dict[str, Any], thresholds: dict[str, Any]) -> bool:
    return (
        all(
            isinstance(metrics.get(name), (int, float))
            and float(metrics[name]) >= float(thresholds[threshold])
            for name, threshold in (
                ("precision", "minimum_precision"),
                ("recall", "minimum_recall"),
                ("f1", "minimum_f1"),
            )
        )
        and isinstance(metrics.get("false_positive_rate"), (int, float))
        and float(metrics["false_positive_rate"])
        <= float(thresholds["maximum_false_positive_rate"])
    )


def _benchmark_gaps(
    value: object,
    valid: bool,
    metrics: dict[str, Any],
    thresholds: dict[str, Any],
    protocol: str = "classification",
    protocol_metrics: object = None,
) -> list[str]:
    if not isinstance(value, dict):
        return ["benchmark evidence is missing"]
    if not valid:
        return [
            "benchmark evidence lacks approved corpus authority, replay protection, or digest binding"
        ]
    if protocol != "classification":
        gaps = []
        if not _protocol_metrics_valid(protocol, protocol_metrics):
            gaps.append(f"{protocol} protocol metrics are invalid")
        if not _protocol_acceptance(value):
            gaps.append(
                "protocol-specific acceptance criteria are missing, unapproved, or unmet"
            )
        if thresholds and not _meets_protocol_thresholds(protocol_metrics, thresholds):
            gaps.append("protocol metrics do not meet the declared thresholds")
        return gaps
    gaps = []
    for metric, threshold, direction in (
        ("precision", "minimum_precision", "minimum"),
        ("recall", "minimum_recall", "minimum"),
        ("f1", "minimum_f1", "minimum"),
        ("false_positive_rate", "maximum_false_positive_rate", "maximum"),
    ):
        observed = metrics.get(metric)
        limit = thresholds[threshold]
        if (
            not isinstance(observed, (int, float))
            or (direction == "minimum" and observed < limit)
            or (direction == "maximum" and observed > limit)
        ):
            gaps.append(f"{metric} does not meet {threshold}={limit}")
    return gaps


def _aggregate_metrics(rows: list[dict[str, Any]]) -> dict[str, float | None]:
    result: dict[str, float | None] = {}
    for name in (
        "precision",
        "recall",
        "specificity",
        "f1",
        "mcc",
        "balanced_accuracy",
        "false_positive_rate",
        "youden_j",
    ):
        values = [
            float(row["metrics"][name])
            for row in rows
            if row["evidence_valid"]
            and isinstance(row["metrics"].get(name), (int, float))
        ]
        result[name] = round(sum(values) / len(values), 6) if values else None
    return result


def _benchmark_delta(
    target: Path, policy: dict[str, Any], scorecard: dict[str, Any], errors: list[str]
) -> dict[str, Any]:
    path_value = policy.get("benchmark_baseline_path")
    baseline: dict[str, Any] | None = None
    if path_value:
        try:
            path = target / str(path_value)
            _, payload = read_regular_file(
                path,
                "benchmark baseline",
                maximum_bytes=_MAX_POLICY_BYTES,
                boundary=target,
            )
            loaded = strict_loads(payload)
            if (
                not isinstance(loaded, dict)
                or loaded.get("analysis") != "industry-benchmark-scorecard"
            ):
                raise ValueError("invalid benchmark baseline")
            baseline = loaded
        except (OSError, TypeError, ValueError) as exc:
            errors.append(f"{path_value}: {type(exc).__name__}")
    current = scorecard["aggregate_metrics"]
    previous = baseline.get("aggregate_metrics", {}) if baseline else {}
    deltas = {
        name: round(float(current[name]) - float(previous[name]), 6)
        if isinstance(current.get(name), (int, float))
        and isinstance(previous.get(name), (int, float))
        else None
        for name in current
    }
    regressions = [
        name
        for name, value in deltas.items()
        if isinstance(value, float)
        and (
            (name == "false_positive_rate" and value > 0)
            or (name != "false_positive_rate" and value < 0)
        )
    ]
    current_protocol = {
        str(row["benchmark_id"]): {
            str(name): float(value)
            for name, value in row.get("protocol_metrics", {}).items()
            if _finite_number(value)
        }
        for row in scorecard.get("benchmarks", [])
        if isinstance(row, dict) and row.get("benchmark_protocol") != "classification"
    }
    baseline_protocol = {
        str(row["benchmark_id"]): {
            str(name): float(value)
            for name, value in row.get("protocol_metrics", {}).items()
            if _finite_number(value)
        }
        for row in (baseline.get("benchmarks", []) if baseline else [])
        if isinstance(row, dict) and row.get("benchmark_protocol") != "classification"
    }
    protocol_metric_deltas = {
        identifier: {
            name: round(value - baseline_protocol[identifier][name], 6)
            if identifier in baseline_protocol and name in baseline_protocol[identifier]
            else None
            for name, value in metrics.items()
        }
        for identifier, metrics in current_protocol.items()
    }
    baseline_pass = {
        str(row.get("benchmark_id")): row.get("passed") is True
        for row in (baseline.get("benchmarks", []) if baseline else [])
        if isinstance(row, dict)
    }
    current_pass = {
        str(row.get("benchmark_id")): row.get("passed") is True
        for row in scorecard.get("benchmarks", [])
        if isinstance(row, dict)
    }
    protocol_regressions = sorted(
        identifier
        for identifier, passed in current_pass.items()
        if baseline_pass.get(identifier) is True and not passed
    )
    return {
        "schema_version": "1.0",
        "analysis": "industry-benchmark-delta",
        "baseline_present": baseline is not None,
        "comparable": baseline is not None
        and baseline.get("benchmark_scope") == scorecard.get("benchmark_scope"),
        "current_metrics": current,
        "baseline_metrics": previous,
        "metric_deltas": deltas,
        "regressions": regressions,
        "current_protocol_metrics": current_protocol,
        "baseline_protocol_metrics": baseline_protocol,
        "protocol_metric_deltas": protocol_metric_deltas,
        "protocol_regressions": protocol_regressions,
        "claim_boundary": "A delta is comparable only for the same benchmark families and pinned corpus digests.",
    }


def _oscal_documents(
    assessment: dict[str, Any], procedures: dict[str, Any], source_sha256: str
) -> dict[str, dict[str, Any]]:
    identity = uuid.uuid5(
        uuid.NAMESPACE_URL, f"pysec:{source_sha256 or 'unknown'}:industry-assessment"
    )
    now = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    metadata = {
        "title": "Python Security Suite industry assurance package",
        "last-modified": now,
        "version": "1.0",
        "oscal-version": "1.2.2",
    }
    controls = [
        {
            "standard": item["standard"],
            "control_id": item["control_id"],
            "objective": item["objective"],
            "status": item["status"],
            "evidence_present": item["evidence_present"],
            "gaps": item["gaps"],
        }
        for item in assessment["controls"]
    ]
    controls.extend(
        {
            "standard": item["standard"],
            "control_id": item["procedure_id"],
            "objective": item["objective"],
            "status": item["status"],
            "evidence_present": item["evidence_present"],
            "gaps": item["gaps"],
        }
        for item in procedures["procedures"]
    )
    if not controls:
        controls.append(
            {
                "standard": "PYSEC",
                "control_id": "assurance-package",
                "objective": (
                    "Describe the suite assurance component and its repository-scoped "
                    "assessment boundary without asserting an external control outcome."
                ),
                "status": "satisfied",
                "evidence_present": [],
                "gaps": [],
            }
        )
    oscal_ids = {
        (item["standard"], item["control_id"]): _oscal_control_id(
            item["standard"], item["control_id"]
        )
        for item in controls
    }
    catalog = {
        "catalog": {
            "uuid": str(uuid.uuid5(identity, "catalog")),
            "metadata": {**metadata, "title": "Repository assurance control catalog"},
            "groups": [
                {
                    "id": "pysec-assurance",
                    "title": "Repository-scoped assurance objectives",
                    "controls": [
                        {
                            "id": oscal_ids[(item["standard"], item["control_id"])],
                            "title": f"{item['standard']} {item['control_id']}",
                            "props": [
                                {
                                    "name": "source-standard",
                                    "value": item["standard"],
                                },
                                {
                                    "name": "source-control-id",
                                    "value": item["control_id"],
                                },
                            ],
                            "parts": [
                                {
                                    "id": oscal_ids[
                                        (item["standard"], item["control_id"])
                                    ]
                                    + "-statement",
                                    "name": "statement",
                                    "prose": item["objective"],
                                }
                            ],
                        }
                        for item in controls
                    ],
                }
            ],
        }
    }
    profile = {
        "profile": {
            "uuid": str(uuid.uuid5(identity, "profile")),
            "metadata": {**metadata, "title": "Repository assurance profile"},
            "imports": [{"href": "oscal-catalog.json", "include-all": {}}],
            "merge": {"as-is": True},
        }
    }
    implemented = []
    for item in controls:
        implementation = {
            "uuid": str(
                uuid.uuid5(
                    identity, f"implemented:{item['standard']}:{item['control_id']}"
                )
            ),
            "control-id": oscal_ids[(item["standard"], item["control_id"])],
            "description": item["objective"],
            "props": [{"name": "assessment-status", "value": item["status"]}],
        }
        if item["evidence_present"]:
            implementation["links"] = [
                {"href": name, "rel": "evidence"} for name in item["evidence_present"]
            ]
        implemented.append(implementation)
    component = {
        "component-definition": {
            "uuid": str(uuid.uuid5(identity, "component-definition")),
            "metadata": {**metadata, "title": "Suite component definition"},
            "components": [
                {
                    "uuid": str(uuid.uuid5(identity, "component")),
                    "type": "software",
                    "title": "Python Security Suite",
                    "description": "Repository-scoped security and quality assurance evidence producer.",
                    "control-implementations": [
                        {
                            "uuid": str(uuid.uuid5(identity, "control-implementation")),
                            "source": "oscal-profile.json",
                            "description": "Evidence-backed implementation statements.",
                            "implemented-requirements": implemented,
                        }
                    ],
                }
            ],
        }
    }
    ssp_implemented = [
        {name: value for name, value in item.items() if name != "description"}
        for item in implemented
    ]
    system_id = source_sha256 or str(identity)
    ssp = {
        "system-security-plan": {
            "uuid": str(uuid.uuid5(identity, "ssp")),
            "metadata": {**metadata, "title": "Repository system security plan"},
            "import-profile": {"href": "oscal-profile.json"},
            "system-characteristics": {
                "system-ids": [
                    {
                        "identifier-type": "urn:project-py-security-suite:source-sha256",
                        "id": system_id,
                    }
                ],
                "system-name": "Scanned repository",
                "description": "The digest-bound repository and retained assurance evidence.",
                "security-sensitivity-level": "moderate",
                "system-information": {
                    "information-types": [
                        {
                            "uuid": str(uuid.uuid5(identity, "information-type")),
                            "title": "Repository assurance evidence",
                            "description": (
                                "Source, scanner, benchmark, and governance evidence "
                                "bound to the assessed repository digest."
                            ),
                        }
                    ]
                },
                "security-impact-level": {
                    "security-objective-confidentiality": "moderate",
                    "security-objective-integrity": "moderate",
                    "security-objective-availability": "moderate",
                },
                "status": {"state": "operational"},
                "authorization-boundary": {
                    "description": "Limited to the source digest and named evidence artifacts."
                },
            },
            "system-implementation": {
                "components": [
                    {
                        "uuid": str(uuid.uuid5(identity, "system-component")),
                        "type": "software",
                        "title": "Python Security Suite",
                        "description": "Assurance evidence producer.",
                        "status": {"state": "operational"},
                    }
                ],
            },
            "control-implementation": {
                "description": "Repository-owned implementations and evidence mappings.",
                "implemented-requirements": ssp_implemented,
            },
        }
    }
    reviewed_controls = {
        "control-selections": [
            {
                "description": "Policy-declared controls and procedures",
                "include-controls": [
                    {"control-id": oscal_ids[(item["standard"], item["control_id"])]}
                    for item in controls
                ],
            }
        ]
    }
    assessment_plan = {
        "assessment-plan": {
            "uuid": str(uuid.uuid5(identity, "assessment-plan")),
            "metadata": {**metadata, "title": "Repository assurance assessment plan"},
            "import-ssp": {"href": "oscal-system-security-plan.json"},
            "reviewed-controls": reviewed_controls,
            "assessment-subjects": [
                {
                    "type": "component",
                    "include-subjects": [
                        {
                            "subject-uuid": str(
                                uuid.uuid5(identity, "system-component")
                            ),
                            "type": "component",
                        }
                    ],
                }
            ],
        }
    }
    findings = []
    observations = []
    for index, control in enumerate(controls):
        observation_uuid = str(
            uuid.uuid5(
                identity,
                f"observation:{index}:{control['standard']}:{control['control_id']}",
            )
        )
        observation = {
            "uuid": observation_uuid,
            "title": control["objective"],
            "description": "; ".join(control["evidence_present"])
            or "No retained evidence",
            "methods": ["EXAMINE"],
            "collected": now,
        }
        if control["evidence_present"]:
            observation["relevant-evidence"] = [
                {"description": name, "href": name}
                for name in control["evidence_present"]
            ]
        observations.append(observation)
        if control["status"] not in {"satisfied", "not-applicable"}:
            findings.append(
                {
                    "uuid": str(uuid.uuid5(identity, f"finding:{index}")),
                    "title": f"{control['standard']} {control['control_id']} evidence gap",
                    "description": "; ".join(control["gaps"]),
                    "target": {
                        "type": "objective-id",
                        "target-id": oscal_ids[
                            (control["standard"], control["control_id"])
                        ],
                        "status": {"state": "not-satisfied"},
                    },
                    "related-observations": [{"observation-uuid": observation_uuid}],
                }
            )
    result_record = {
        "uuid": str(uuid.uuid5(identity, "result")),
        "title": "Evidence-backed industry standards assessment",
        "description": assessment["claim_boundary"],
        "start": now,
        "reviewed-controls": reviewed_controls,
        "observations": observations,
    }
    if findings:
        result_record["findings"] = findings
    results = {
        "assessment-results": {
            "uuid": str(identity),
            "metadata": {
                **metadata,
                "title": "Repository assurance assessment results",
            },
            "import-ap": {"href": "oscal-assessment-plan.json"},
            "results": [result_record],
        }
    }
    poam_items = [
        {
            "uuid": str(
                uuid.uuid5(identity, f"poam:{item['standard']}:{item['control_id']}")
            ),
            "title": f"Resolve {item['standard']} {item['control_id']} assurance gap",
            "description": "; ".join(item["gaps"]),
            "related-observations": [
                {
                    "observation-uuid": str(
                        uuid.uuid5(
                            identity,
                            f"observation:{index}:{item['standard']}:{item['control_id']}",
                        )
                    )
                }
            ],
        }
        for index, item in enumerate(controls)
        if item["status"] not in {"satisfied", "not-applicable"}
    ]
    if not poam_items:
        poam_items.append(
            {
                "uuid": str(uuid.uuid5(identity, "poam:continuous-reassessment")),
                "title": "Maintain repository assurance evidence",
                "description": (
                    "Reassess the digest-bound repository when its source, policy, "
                    "scanner portfolio, or governed benchmark corpus changes."
                ),
                "props": [
                    {
                        "name": "item-kind",
                        "value": "continuous-reassessment",
                    }
                ],
            }
        )
    poam: dict[str, Any] = {
        "plan-of-action-and-milestones": {
            "uuid": str(uuid.uuid5(identity, "poam")),
            "metadata": {**metadata, "title": "Repository assurance POA&M"},
            "import-ssp": {"href": "oscal-system-security-plan.json"},
            "system-id": {
                "identifier-type": "urn:project-py-security-suite:source-sha256",
                "id": system_id,
            },
        }
    }
    poam["plan-of-action-and-milestones"]["poam-items"] = poam_items
    return {
        "oscal-catalog.json": catalog,
        "oscal-profile.json": profile,
        "oscal-component-definition.json": component,
        "oscal-system-security-plan.json": ssp,
        "oscal-assessment-plan.json": assessment_plan,
        "oscal-assessment-results.json": results,
        "oscal-poam.json": poam,
    }


def _oscal_control_id(standard: str, control_id: str) -> str:
    raw = f"{standard}-{control_id}".casefold()
    normalized = "".join(character if character.isalnum() else "-" for character in raw)
    normalized = "-".join(part for part in normalized.split("-") if part)
    digest = uuid.uuid5(uuid.NAMESPACE_URL, f"{standard}:{control_id}").hex[:10]
    return f"{normalized[:100]}-{digest}"


def _interoperability(artifacts: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    intelligence = artifacts.get("risk-intelligence.json")
    vex_formats = (
        set(intelligence.get("vex_formats", []))
        if isinstance(intelligence, dict)
        and isinstance(intelligence.get("vex_formats"), list)
        else set()
    )
    vex_versions = (
        intelligence.get("vex_versions", {})
        if isinstance(intelligence, dict)
        and isinstance(intelligence.get("vex_versions"), dict)
        else {}
    )
    automation = artifacts.get("security-automation-interoperability.json")
    protocol_rows = (
        automation.get("protocols", [])
        if isinstance(automation, dict)
        and isinstance(automation.get("protocols"), list)
        else []
    )
    protocol_index = {
        str(item.get("id")): item for item in protocol_rows if isinstance(item, dict)
    }
    interoperability_protocol_ids = {
        "STIX": "OASIS-STIX",
        "TAXII": "OASIS-TAXII",
        "CACAO": "OASIS-CACAO",
        "OpenC2": "OASIS-OPENC2",
        "OCSF": "OCSF",
        "SCITT": "IETF-RFC-9943",
        "COSE-Receipts": "IETF-RFC-9942",
        "OpenAPI": "OPENAPI-SPECIFICATION",
        "AsyncAPI": "ASYNCAPI-SPECIFICATION",
        "GraphQL": "GRAPHQL-SPECIFICATION",
        "JSON-Schema": "JSON-SCHEMA",
        "OpenTelemetry-SemConv": "OPENTELEMETRY-SEMCONV",
    }
    for name, version, evidence in _INTEROPERABILITY:
        present = any(item in artifacts for item in evidence)
        observed_versions: list[str] = []
        if name == "CycloneDX":
            observed_versions = sorted(
                {
                    str(value.get("specVersion"))
                    for artifact_name in evidence
                    if isinstance((value := artifacts.get(artifact_name)), dict)
                    and value.get("specVersion")
                }
            )
            present = version in observed_versions
        if name in {"CycloneDX-VEX", "OpenVEX", "CSAF-VEX"}:
            format_name = name.casefold().replace("-vex", "")
            versions = vex_versions.get(format_name, [])
            observed_versions = (
                sorted(str(item) for item in versions)
                if isinstance(versions, list)
                else []
            )
            present = format_name in vex_formats and version in observed_versions
        if name == "OSCAL":
            document = artifacts.get("oscal-assessment-results.json")
            root = (
                document.get("assessment-results")
                if isinstance(document, dict)
                else None
            )
            metadata = root.get("metadata") if isinstance(root, dict) else None
            observed = (
                metadata.get("oscal-version") if isinstance(metadata, dict) else None
            )
            observed_versions = [str(observed)] if observed else []
            present = version in observed_versions
        protocol_id = interoperability_protocol_ids.get(name)
        if protocol_id:
            protocol = protocol_index.get(protocol_id)
            observed = protocol.get("version") if isinstance(protocol, dict) else None
            observed_versions = [str(observed)] if observed else []
            present = bool(
                isinstance(protocol, dict) and protocol.get("complete") is True
            )
        rows.append(
            {
                "format": name,
                "version": version,
                "status": "supported" if present else "not-observed",
                "observed_versions": observed_versions,
                "evidence_artifacts": list(evidence),
            }
        )
    return rows


def _source_sha256(artifacts: dict[str, Any]) -> str:
    value = artifacts.get("source-inventory.json")
    digest = str(value.get("source_sha256") or "") if isinstance(value, dict) else ""
    return digest if _digest(digest) else ""


def _complete_artifact(value: object) -> bool:
    return isinstance(value, dict) and value.get("complete") is not False


def _artifact_name(value: object) -> bool:
    return (
        _text(value, 200)
        and Path(str(value)).name == str(value)
        and str(value).endswith(".json")
    )


def _safe_relative(value: object) -> bool:
    if not _text(value, 500):
        return False
    path = Path(str(value))
    return not path.is_absolute() and ".." not in path.parts


def _digest(value: str) -> bool:
    return len(value) == 64 and all(character in _DIGEST for character in value)


def _ratio(value: object) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(float(value))
        and 0 <= float(value) <= 1
    )


def _iso_timestamp(value: object) -> bool:
    if not _text(value, 100):
        return False
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return False
    return parsed.tzinfo is not None


def _text(value: object, maximum: int) -> bool:
    return isinstance(value, str) and 0 < len(value) <= maximum
