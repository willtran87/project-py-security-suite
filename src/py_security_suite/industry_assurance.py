from __future__ import annotations

import math
import uuid
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

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
        "version": "2.x",
        "kind": "payment-software-security",
        "reference": "https://www.pcisecuritystandards.org/standards/secure-software/",
        "evidence": [
            "security-requirements-coverage.json",
            "procedure-assessment.json",
        ],
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
        "version": "2.0-policy-pinned",
        "kind": "high-assurance-api-authorization",
        "reference": "https://openid.net/wg/fapi/specifications/",
        "evidence": ["application-contract-analysis.json", "procedure-assessment.json"],
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
        "version": "2011-policy-pinned-amendments",
        "kind": "privacy-framework",
        "reference": "https://www.iso.org/standard/45123.html",
        "evidence": ["data-exposure.json", "control-assessment.json"],
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
        "version": "licensed-policy-pinned",
        "kind": "healthcare-assurance-framework",
        "reference": "https://hitrustalliance.net/hitrust-framework",
        "evidence": ["control-assessment.json", "audit-package-verification.json"],
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

_STANDARDS_WATCHLIST: tuple[dict[str, str], ...] = (
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
    complete = (
        bool(source_sha256)
        and trace_complete
        and all(stage["complete"] for stage in stages)
    )
    gaps = [gap for stage in stages for gap in stage["gaps"]]
    if not source_sha256:
        gaps.append("source inventory digest is missing")
    if not trace_complete:
        gaps.append("bidirectional requirements evidence is incomplete")
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
        "gaps": list(dict.fromkeys(gaps))[:100],
        "claim_boundary": (
            "Stage evidence and requirement counts establish an auditable traceability "
            "surface; they do not prove that every life-cycle decision is correct."
        ),
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


def _foundational_assurance_artifacts(
    artifacts: dict[str, Any], source_sha256: str, policy: dict[str, Any]
) -> dict[str, dict[str, Any]]:
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
    }


def build_industry_assurance(
    target: Path,
    artifacts: dict[str, Any],
    findings: list[Any] | None = None,
) -> tuple[dict[str, dict[str, Any]], list[str]]:
    """Build bounded benchmark, procedure, standards, and OSCAL artifacts."""

    target = target.resolve()
    policy, errors = _load_policy(target)
    source_sha256 = _source_sha256(artifacts)
    foundational = _foundational_assurance_artifacts(artifacts, source_sha256, policy)
    profiles = _profile_registry(policy)
    enriched_artifacts = {**artifacts, **foundational}
    registry = _benchmark_registry(policy, source_sha256)
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
    if not isinstance(value, dict):
        raise ValueError("invalid industry assurance policy")
    version = value.get("schema_version")
    expected = (
        version_1_0
        if version == "1.0"
        else version_1_1
        if version == "1.1"
        else version_1_2
    )
    if (
        version not in {"1.0", "1.1", "1.2"}
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
        required_benchmark_fields = {
            "id",
            "enabled",
            "corpus_sha256",
            "evidence_artifact",
            "minimum_precision",
            "minimum_recall",
            "minimum_f1",
            "maximum_false_positive_rate",
        }
        if not isinstance(benchmark, dict) or set(benchmark) not in {
            frozenset(required_benchmark_fields),
            frozenset({*required_benchmark_fields, "adapter_manifest"}),
        }:
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


def _benchmark_registry(policy: dict[str, Any], source_sha256: str) -> dict[str, Any]:
    declarations = {item["id"]: item for item in policy["benchmarks"]}
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
            "thresholds": (
                {
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
            "nist-aria-inspect-evaluation",
            "ai-conformity-quality",
            "ai-agentic-testing-conformance",
            "nist-dioptra-ai-evaluation",
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
        },
        "biometric-performance": {"biometric-performance-pad"},
        "proficiency-testing": {"interlaboratory-proficiency-testing"},
        "detection-evaluation": {
            "atomic-red-team",
            "mitre-caldera",
            "mitre-attack-evaluations",
            "tiber-eu-threat-led-red-team",
            "amtso-malware-protection-evaluation",
        },
        "conformance": {
            "sigstore-client-conformance",
            "slsa-verifier-conformance",
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


def _protocol_metrics_valid(protocol: str, metrics: object) -> bool:
    if not isinstance(metrics, dict):
        return False
    if protocol == "temporal-calibration":
        return all(
            _ratio(metrics.get(name))
            for name in (
                "brier_score",
                "expected_calibration_error",
                "recall_at_budget",
                "effort",
            )
        ) and _count(metrics.get("observations"), 100)
    if protocol == "verification-competition":
        return all(
            _count(metrics.get(name)) for name in ("correct", "incorrect", "unknown")
        ) and _finite_number(metrics.get("score"))
    if protocol == "test-generation":
        return (
            _ratio(metrics.get("coverage"))
            and _count(metrics.get("faults_detected"))
            and _count(metrics.get("valid_tests"), 1)
            and _finite_number(metrics.get("score"))
        )
    if protocol == "fuzzing-statistical":
        return (
            _count(metrics.get("trials"), 10)
            and _finite_number(metrics.get("median_edges"), 0)
            and _finite_number(metrics.get("effect_size"))
            and -1 <= float(metrics["effect_size"]) <= 1
            and _ratio(metrics.get("p_value"))
        )
    if protocol == "stochastic-adversarial":
        return _count(metrics.get("repetitions"), 5) and all(
            _ratio(metrics.get(name))
            for name in ("attack_success_rate", "utility_retention", "variance")
        )
    if protocol == "assessor-agreement":
        return (
            _count(metrics.get("reviewers"), 2)
            and _count(metrics.get("cases"), 1)
            and _ratio(metrics.get("inter_rater_agreement"))
            and float(metrics["inter_rater_agreement"]) >= 0.8
        )
    if protocol == "biometric-performance":
        return (
            _count(metrics.get("genuine_attempts"), 1)
            and _count(metrics.get("impostor_attempts"), 1)
            and _count(metrics.get("attack_attempts"), 1)
            and _count(metrics.get("demographic_groups"), 1)
            and metrics.get("threshold_locked") is True
            and all(
                _ratio(metrics.get(name))
                for name in (
                    "false_match_rate",
                    "false_non_match_rate",
                    "iapar",
                    "fmr_wilson_upper_95",
                    "fnmr_wilson_upper_95",
                    "iapar_wilson_upper_95",
                    "worst_group_fmr_wilson_upper_95",
                    "worst_group_fnmr_wilson_upper_95",
                )
            )
        )
    if protocol == "proficiency-testing":
        agreement = metrics.get("chance_corrected_agreement")
        agreement_value = (
            float(agreement)
            if isinstance(agreement, (int, float)) and not isinstance(agreement, bool)
            else -2.0
        )
        return (
            _count(metrics.get("participants"), 2)
            and _count(metrics.get("cases"), 1)
            and _count(metrics.get("rounds"), 1)
            and metrics.get("blinded") is True
            and _ratio(metrics.get("agreement"))
            and _ratio(metrics.get("reference_accuracy"))
            and _finite_number(agreement)
            and -1 <= agreement_value <= 1
        )
    if protocol == "conformance":
        return (
            _count(metrics.get("passed_cases"), 1)
            and _count(metrics.get("failed_cases"))
            and _count(metrics.get("negative_cases"), 1)
            and _ratio(metrics.get("conformance_rate"))
        )
    if protocol == "detection-evaluation":
        return (
            _count(metrics.get("techniques"), 1)
            and _count(metrics.get("detections"))
            and _ratio(metrics.get("analytic_coverage"))
            and _ratio(metrics.get("false_positive_rate"))
            and _finite_number(metrics.get("latency_ms"), 0)
        )
    return False


def _protocol_acceptance(value: object) -> bool:
    if not isinstance(value, dict):
        return False
    acceptance = value.get("acceptance")
    return bool(
        isinstance(acceptance, dict)
        and _digest(str(acceptance.get("criteria_sha256") or ""))
        and acceptance.get("met") is True
        and isinstance(acceptance.get("authority"), dict)
        and acceptance["authority"].get("organization_approved") is True
    )


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
        "nist-aria-inspect-evaluation",
        "ai-agentic-testing-conformance",
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
