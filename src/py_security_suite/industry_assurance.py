from __future__ import annotations

import math
import uuid
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

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


_ASSURANCE_PROFILES: dict[str, dict[str, Any]] = {
    "enterprise-security": {
        "standards": ["ISO-IEC-27001", "ISO-IEC-27002", "ISO-IEC-27034-1"],
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
        "standards": ["ISO-IEC-27701", "NIST-PRIVACY-FRAMEWORK"],
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

_INTEROPERABILITY = (
    ("SARIF", "2.1.0", ("results.sarif",)),
    ("CycloneDX", "1.7", ("sbom.cdx.json", "artifact-sbom.cdx.json")),
    ("SPDX", "2.x/3.x", ("reuse-compliance.json",)),
    ("CycloneDX-VEX", "1.7", ("risk-intelligence.json",)),
    ("OpenVEX", "0.2", ("risk-intelligence.json",)),
    ("CSAF-VEX", "2.0", ("risk-intelligence.json",)),
    ("SCAP", "1.4", ("scap-results.xml", "scap-results.json")),
    ("OSCAL", "1.2.2", ("oscal-assessment-results.json",)),
)


def build_industry_assurance(
    target: Path,
    artifacts: dict[str, Any],
    findings: list[Any] | None = None,
) -> tuple[dict[str, dict[str, Any]], list[str]]:
    """Build bounded benchmark, procedure, standards, and OSCAL artifacts."""

    target = target.resolve()
    policy, errors = _load_policy(target)
    source_sha256 = _source_sha256(artifacts)
    profiles = _profile_registry(policy)
    procedures = _procedure_assessment(policy, artifacts, errors)
    prioritization = _standardized_prioritization(findings or [])
    observed_artifacts = {
        **artifacts,
        "procedure-assessment.json": procedures,
        "standardized-prioritization.json": prioritization,
    }
    initial_crosswalk = _crosswalk(observed_artifacts)
    assessment = _assessment(policy, observed_artifacts, initial_crosswalk, errors)
    registry = _benchmark_registry(policy, source_sha256)
    scorecard = _benchmark_scorecard(
        target, observed_artifacts, registry, source_sha256
    )
    delta = _benchmark_delta(target, policy, scorecard, errors)
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
        or len(benchmarks) > 100
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
        if not isinstance(benchmark, dict) or set(benchmark) != {
            "id",
            "enabled",
            "corpus_sha256",
            "evidence_artifact",
            "minimum_precision",
            "minimum_recall",
            "minimum_f1",
            "maximum_false_positive_rate",
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
    return {
        "schema_version": "1.0",
        "analysis": "versioned-industry-standards-crosswalk",
        "catalogs_registered": len(catalogs),
        "catalogs": catalogs,
        "mappings": mappings,
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
            tasks.append(
                {
                    "benchmark_id": registered["id"],
                    "lane": registered["lane"],
                    "command": [
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
                    ],
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
        thresholds = benchmark["thresholds"] or {}
        passed = bool(
            valid
            and reproducibility_complete
            and _meets_thresholds(metrics, thresholds)
        )
        rows.append(
            {
                "benchmark_id": benchmark["id"],
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
                "gaps": (
                    []
                    if passed
                    else [
                        *_benchmark_gaps(value, valid, metrics, thresholds),
                        *reproducibility_gaps,
                    ]
                ),
            }
        )
    executed = sum(item["evidence_valid"] for item in rows)
    passed_count = sum(item["passed"] for item in rows)
    benchmark_scope = [
        {"benchmark_id": item["benchmark_id"], "corpus_sha256": item["corpus_sha256"]}
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
    metrics = value.get("metrics")
    return bool(
        isinstance(corpus, dict)
        and corpus.get("sha256") == benchmark["corpus_sha256"]
        and isinstance(metrics, dict)
        and all(
            name in metrics for name in ("precision", "recall", "specificity", "f1")
        )
        and value.get("replay_protected") is True
        and isinstance(corpus.get("authority"), dict)
        and corpus["authority"].get("organization_approved") is True
    )


def _benchmark_runner_contract(benchmark: dict[str, Any]) -> dict[str, Any]:
    identifier = str(benchmark["id"])
    stochastic = identifier in {
        "cyberseceval-4",
        "mlcommons-ailuminate",
        "agentic-security-holdout",
    }
    return {
        "adapter": identifier,
        "expected_results": (
            "organization-approved-labels"
            if benchmark["version"] == "organization-pinned"
            else "official-corpus-labels"
        ),
        "minimum_repetitions": 5 if stochastic else 1,
        "required_execution_evidence": [
            "verified-report-checksum",
            "confusion-matrix",
            "corpus-revision",
            "runner-identity",
            "target-or-fixture-digest",
            "tool-and-query-versions",
            "environment-fingerprint",
            "oracle-manifest",
            "negative-controls",
            "isolation-receipt",
            "trusted-time",
            "replay-protection",
        ],
        "score_semantics": [
            "precision",
            "recall",
            "false-positive-rate",
            "youden-j",
            "wilson-95-percent-confidence-interval",
        ],
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
    if not isinstance(matrix, dict) or any(
        not isinstance(matrix.get(name), int) or isinstance(matrix.get(name), bool)
        for name in (
            "true_positive",
            "true_negative",
            "false_positive",
            "false_negative",
        )
    ):
        gaps.append("complete confusion matrix is missing")
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
    if (
        isinstance(benchmark, dict)
        and benchmark.get("version") == "organization-pinned"
    ):
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
            ):
                if not _digest(str(execution.get(name) or "")):
                    gaps.append(f"benchmark execution {name} is missing or invalid")
            if not _text(execution.get("runner_identity"), 300) or not _text(
                execution.get("runner_version"), 100
            ):
                gaps.append("benchmark runner identity or version is missing")
            if execution.get("isolation_validated") is not True:
                gaps.append("benchmark execution isolation is not validated")
            for name in ("positive_controls", "negative_controls"):
                count = execution.get(name)
                if isinstance(count, bool) or not isinstance(count, int) or count < 1:
                    gaps.append(f"benchmark {name} are missing")
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
    value: object, valid: bool, metrics: dict[str, Any], thresholds: dict[str, Any]
) -> list[str]:
    if not isinstance(value, dict):
        return ["benchmark evidence is missing"]
    if not valid:
        return [
            "benchmark evidence lacks approved corpus authority, replay protection, or digest binding"
        ]
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


def _text(value: object, maximum: int) -> bool:
    return isinstance(value, str) and 0 < len(value) <= maximum
