from __future__ import annotations

import ast
import re
from collections import Counter
from pathlib import Path
from typing import Any

from .adapters.staging import maintained_repository_files
from .models import (
    Citation,
    Confidence,
    Finding,
    Location,
    Severity,
    Source,
    finding_identity,
)
from .path_safety import read_regular_file, resolve_unlinked_path
from .repository_surfaces import classify_repository_surfaces
from .strict_json import loads as strict_loads


_POLICY_PATH = "security/domain-assurance-policy.json"
_MAX_FILES = 50_000
_MAX_FILE_BYTES = 4 * 1024 * 1024
_MAX_TOTAL_SOURCE_BYTES = 256 * 1024 * 1024
_MAX_SIGNALS_PER_DOMAIN = 100
_MAX_REQUIREMENTS = 2_000

_DOMAINS = (
    "business-logic",
    "privacy-lifecycle",
    "resilience",
    "detection-engineering",
    "cryptographic-agility",
    "notebook-security",
    "messaging-security",
    "desktop-client-security",
    "firmware-iot-security",
    "web3-security",
    "graphql-security",
    "identity-assurance",
    "tenant-isolation",
    "abuse-resistance",
    "workload-identity",
    "integration-security",
    "incident-response-recovery",
    "data-integrity-lineage",
    "serverless-edge-security",
    "external-asset-communication",
    "ot-ics-safety",
    "privileged-control-plane",
    "distributed-temporal-correctness",
    "secure-human-interaction",
    "ml-model-data-supply-chain",
    "credential-secret-lifecycle",
    "observability-integrity",
    "developer-environment-security",
    "parser-content-security",
    "trust-safety",
    "confidential-computing-side-channels",
    "regulated-transaction-integrity",
    "physical-environmental-security",
)

_REQUIREMENT_KINDS = {
    "state-transition",
    "value-conservation",
    "quota",
    "idempotency",
    "concurrency",
    "eligibility",
    "collection-purpose",
    "consent",
    "minimization",
    "retention",
    "residency",
    "deletion",
    "export",
    "processor-boundary",
    "latency-budget",
    "error-budget",
    "resource-budget",
    "recovery",
    "amplification",
    "backpressure",
    "log-source",
    "alert-rule",
    "canary-replay",
    "false-positive-budget",
    "incident-routing",
    "algorithm-inventory",
    "key-lifecycle",
    "certificate-lifecycle",
    "protocol-policy",
    "migration-plan",
    "notebook-code",
    "notebook-output",
    "notebook-dependency",
    "notebook-provenance",
    "message-authorization",
    "delivery-semantics",
    "schema-evolution",
    "poison-message",
    "dead-letter",
    "local-ipc",
    "update-integrity",
    "credential-storage",
    "protocol-handler",
    "secure-boot",
    "firmware-update",
    "device-identity",
    "hardware-boundary",
    "contract-invariant",
    "upgradeability",
    "oracle-dependency",
    "transaction-ordering",
    "resolver-authorization",
    "query-cost",
    "batching-limit",
    "field-exposure",
    "identity-proofing",
    "authenticator-lifecycle",
    "account-recovery",
    "federation-assertion",
    "session-lifecycle",
    "step-up-authentication",
    "tenant-context",
    "tenant-data-isolation",
    "tenant-cache-isolation",
    "tenant-key-isolation",
    "tenant-lifecycle",
    "tenant-audit",
    "credential-abuse",
    "automation-resistance",
    "inventory-fairness",
    "fraud-control",
    "cost-amplification",
    "promotion-integrity",
    "workload-attestation",
    "workload-credential-rotation",
    "service-authorization",
    "trust-domain",
    "service-egress",
    "workload-federation",
    "webhook-authenticity",
    "webhook-replay",
    "oauth-scope",
    "provider-egress",
    "provider-schema",
    "provider-failure",
    "evidence-preservation",
    "containment",
    "recovery-exercise",
    "forensic-logging",
    "playbook-routing",
    "post-incident-validation",
    "record-integrity",
    "lineage",
    "reconciliation",
    "audit-immutability",
    "transformation-invariant",
    "unauthorized-mutation",
    "trigger-authorization",
    "function-identity",
    "event-source-trust",
    "concurrency-budget",
    "edge-cache-isolation",
    "secret-bootstrap",
    "domain-ownership",
    "dnssec",
    "dangling-record",
    "email-authentication",
    "certificate-domain-binding",
    "link-workflow",
    "command-authorization",
    "fail-safe-state",
    "safety-interlock",
    "protocol-segmentation",
    "engineering-workstation",
    "physical-process-invariant",
    "admin-authorization",
    "support-impersonation",
    "break-glass",
    "privileged-session",
    "dual-control",
    "control-plane-audit",
    "leader-election",
    "quorum",
    "lease-expiry",
    "clock-skew",
    "partition-recovery",
    "duplicate-reordering",
    "security-confirmation",
    "consent-comprehension",
    "recovery-redress",
    "phishing-resistance",
    "accessible-security",
    "high-risk-friction",
    "model-provenance",
    "dataset-provenance",
    "model-deserialization",
    "model-registry",
    "training-integrity",
    "model-deployment",
    "secret-inventory",
    "secret-rotation",
    "secret-revocation",
    "token-scope",
    "dormant-credential",
    "emergency-rotation",
    "telemetry-authenticity",
    "log-integrity",
    "collector-isolation",
    "time-synchronization",
    "sensitive-telemetry",
    "alert-delivery",
    "ide-extension",
    "build-plugin",
    "dev-container",
    "local-hook",
    "package-execution",
    "workstation-secret",
    "input-polyglot",
    "archive-expansion",
    "parser-differential",
    "active-content",
    "document-macro",
    "media-metadata",
    "content-abuse",
    "moderation-evasion",
    "coordinated-behavior",
    "reporting-redress",
    "age-assurance",
    "recommender-safety",
    "enclave-attestation",
    "side-channel",
    "memory-confidentiality",
    "debug-interface",
    "key-release",
    "rollback-protection",
    "transaction-authorization",
    "sanctions-screening",
    "ledger-reconciliation",
    "non-repudiation",
    "maker-checker",
    "regulatory-retention",
    "facility-access",
    "environmental-monitoring",
    "hardware-tamper",
    "media-disposal",
    "asset-custody",
    "disaster-site",
}

_BEHAVIORAL_REQUIREMENTS = {
    "state-transition",
    "value-conservation",
    "quota",
    "idempotency",
    "concurrency",
    "eligibility",
    "consent",
    "deletion",
    "export",
    "latency-budget",
    "error-budget",
    "resource-budget",
    "recovery",
    "amplification",
    "backpressure",
    "canary-replay",
    "false-positive-budget",
    "message-authorization",
    "delivery-semantics",
    "schema-evolution",
    "poison-message",
    "dead-letter",
    "local-ipc",
    "update-integrity",
    "credential-storage",
    "protocol-handler",
    "secure-boot",
    "firmware-update",
    "device-identity",
    "hardware-boundary",
    "contract-invariant",
    "upgradeability",
    "oracle-dependency",
    "transaction-ordering",
    "resolver-authorization",
    "query-cost",
    "batching-limit",
    "field-exposure",
    "identity-proofing",
    "authenticator-lifecycle",
    "account-recovery",
    "federation-assertion",
    "session-lifecycle",
    "step-up-authentication",
    "tenant-context",
    "tenant-data-isolation",
    "tenant-cache-isolation",
    "tenant-key-isolation",
    "tenant-lifecycle",
    "tenant-audit",
    "credential-abuse",
    "automation-resistance",
    "inventory-fairness",
    "fraud-control",
    "cost-amplification",
    "promotion-integrity",
    "workload-attestation",
    "workload-credential-rotation",
    "service-authorization",
    "trust-domain",
    "service-egress",
    "workload-federation",
    "webhook-authenticity",
    "webhook-replay",
    "oauth-scope",
    "provider-egress",
    "provider-schema",
    "provider-failure",
    "evidence-preservation",
    "containment",
    "recovery-exercise",
    "forensic-logging",
    "playbook-routing",
    "post-incident-validation",
    "record-integrity",
    "lineage",
    "reconciliation",
    "audit-immutability",
    "transformation-invariant",
    "unauthorized-mutation",
    "trigger-authorization",
    "function-identity",
    "event-source-trust",
    "concurrency-budget",
    "edge-cache-isolation",
    "secret-bootstrap",
    "domain-ownership",
    "dnssec",
    "dangling-record",
    "email-authentication",
    "certificate-domain-binding",
    "link-workflow",
    "command-authorization",
    "fail-safe-state",
    "safety-interlock",
    "protocol-segmentation",
    "engineering-workstation",
    "physical-process-invariant",
    "admin-authorization",
    "support-impersonation",
    "break-glass",
    "privileged-session",
    "dual-control",
    "control-plane-audit",
    "leader-election",
    "quorum",
    "lease-expiry",
    "clock-skew",
    "partition-recovery",
    "duplicate-reordering",
    "security-confirmation",
    "consent-comprehension",
    "recovery-redress",
    "phishing-resistance",
    "accessible-security",
    "high-risk-friction",
    "model-deserialization",
    "training-integrity",
    "model-deployment",
    "secret-rotation",
    "secret-revocation",
    "token-scope",
    "dormant-credential",
    "emergency-rotation",
    "telemetry-authenticity",
    "log-integrity",
    "collector-isolation",
    "time-synchronization",
    "sensitive-telemetry",
    "alert-delivery",
    "ide-extension",
    "build-plugin",
    "dev-container",
    "local-hook",
    "package-execution",
    "workstation-secret",
    "input-polyglot",
    "archive-expansion",
    "parser-differential",
    "active-content",
    "document-macro",
    "media-metadata",
    "content-abuse",
    "moderation-evasion",
    "coordinated-behavior",
    "reporting-redress",
    "age-assurance",
    "recommender-safety",
    "enclave-attestation",
    "side-channel",
    "memory-confidentiality",
    "debug-interface",
    "key-release",
    "rollback-protection",
    "transaction-authorization",
    "sanctions-screening",
    "ledger-reconciliation",
    "non-repudiation",
    "maker-checker",
    "facility-access",
    "environmental-monitoring",
    "hardware-tamper",
    "media-disposal",
    "asset-custody",
    "disaster-site",
}

_DOMAIN_DEFAULT_EVIDENCE = {
    "business-logic": (
        "application-contract-analysis.json",
        "authorization-security-summary.json",
        "hypothesis-summary.json",
    ),
    "privacy-lifecycle": (
        "data-exposure.json",
        "evidence-fusion.json",
        "runtime-trace-correlation.json",
    ),
    "resilience": (
        "authorization-security-summary.json",
        "event-security-summary.json",
        "database-security-summary.json",
        "restler-summary.json",
        "runtime-trace-correlation.json",
    ),
    "detection-engineering": (
        "falco-summary.json",
        "ruleset-regression-summary.json",
        "runtime-trace-correlation.json",
    ),
    "cryptographic-agility": (
        "sbom.cdx.json",
        "artifact-sbom.cdx.json",
        "tls-scan-summary.json",
        "artifact-manifest.json",
        "in-toto-summary.json",
    ),
    "notebook-security": (
        "boundary-graph.json",
        "polyglot-summary.json",
    ),
    "messaging-security": (
        "event-security-summary.json",
        "protocol-security-summary.json",
        "runtime-trace-correlation.json",
    ),
    "desktop-client-security": (
        "browser-security-summary.json",
        "polyglot-summary.json",
        "native-sanitizers-summary.json",
    ),
    "firmware-iot-security": (
        "polyglot-summary.json",
        "native-sanitizers-summary.json",
        "artifact-sbom.cdx.json",
    ),
    "web3-security": (
        "polyglot-summary.json",
        "ruleset-regression-summary.json",
    ),
    "graphql-security": (
        "schemathesis-summary.json",
        "authorization-security-summary.json",
        "application-contract-analysis.json",
        "browser-security-summary.json",
    ),
    "identity-assurance": (
        "authorization-security-summary.json",
        "browser-security-summary.json",
        "application-contract-analysis.json",
        "tls-scan-summary.json",
    ),
    "tenant-isolation": (
        "authorization-security-summary.json",
        "database-security-summary.json",
        "event-security-summary.json",
        "ai-security-summary.json",
        "data-exposure.json",
    ),
    "abuse-resistance": (
        "authorization-security-summary.json",
        "browser-security-summary.json",
        "restler-summary.json",
        "hypothesis-summary.json",
        "ruleset-regression-summary.json",
    ),
    "workload-identity": (
        "cloud-attack-path-summary.json",
        "kubescape-summary.json",
        "falco-summary.json",
        "tls-scan-summary.json",
        "surface-inventory-summary.json",
    ),
    "integration-security": (
        "protocol-security-summary.json",
        "browser-security-summary.json",
        "oast-summary.json",
        "application-contract-analysis.json",
        "surface-inventory-summary.json",
    ),
    "incident-response-recovery": (
        "falco-summary.json",
        "ruleset-regression-summary.json",
        "runtime-trace-correlation.json",
        "database-security-summary.json",
    ),
    "data-integrity-lineage": (
        "database-security-summary.json",
        "event-security-summary.json",
        "data-exposure.json",
        "runtime-trace-correlation.json",
        "application-contract-analysis.json",
    ),
    "serverless-edge-security": (
        "checkov-iac.json",
        "kics-iac.json",
        "prowler-summary.json",
        "cloud-attack-path-summary.json",
        "event-security-summary.json",
        "surface-inventory-summary.json",
    ),
    "external-asset-communication": (
        "tls-scan-summary.json",
        "prowler-summary.json",
        "checkov-iac.json",
        "surface-inventory-summary.json",
        "oast-summary.json",
    ),
    "ot-ics-safety": (
        "protocol-security-summary.json",
        "native-sanitizers-summary.json",
        "polyglot-summary.json",
        "falco-summary.json",
    ),
    "privileged-control-plane": (
        "authorization-security-summary.json",
        "browser-security-summary.json",
        "cloud-attack-path-summary.json",
        "database-security-summary.json",
        "runtime-trace-correlation.json",
    ),
    "distributed-temporal-correctness": (
        "event-security-summary.json",
        "database-security-summary.json",
        "protocol-security-summary.json",
        "hypothesis-summary.json",
        "runtime-trace-correlation.json",
    ),
    "secure-human-interaction": (
        "browser-security-summary.json",
        "authorization-security-summary.json",
        "application-contract-analysis.json",
        "data-exposure.json",
    ),
    "ml-model-data-supply-chain": (
        "ai-security-summary.json",
        "sbom.cdx.json",
        "artifact-sbom.cdx.json",
        "artifact-manifest.json",
        "in-toto-summary.json",
        "data-exposure.json",
    ),
    "credential-secret-lifecycle": (
        "secret-verification-summary.json",
        "authorization-security-summary.json",
        "cloud-attack-path-summary.json",
        "artifact-manifest.json",
        "runtime-trace-correlation.json",
    ),
    "observability-integrity": (
        "falco-summary.json",
        "ruleset-regression-summary.json",
        "runtime-trace-correlation.json",
        "data-exposure.json",
        "tls-scan-summary.json",
    ),
    "developer-environment-security": (
        "sbom.cdx.json",
        "scancode-inventory.json",
        "artifact-manifest.json",
        "secret-verification-summary.json",
        "trust-policy-attestation.json",
    ),
    "parser-content-security": (
        "polyglot-summary.json",
        "native-sanitizers-summary.json",
        "hypothesis-summary.json",
        "ruleset-regression-summary.json",
        "resource-limits.json",
    ),
    "trust-safety": (
        "ai-security-summary.json",
        "ruleset-regression-summary.json",
        "browser-security-summary.json",
        "data-exposure.json",
    ),
    "confidential-computing-side-channels": (
        "cloud-attack-path-summary.json",
        "kubescape-summary.json",
        "native-sanitizers-summary.json",
        "artifact-manifest.json",
        "tls-scan-summary.json",
    ),
    "regulated-transaction-integrity": (
        "authorization-security-summary.json",
        "database-security-summary.json",
        "event-security-summary.json",
        "application-contract-analysis.json",
        "runtime-trace-correlation.json",
    ),
    "physical-environmental-security": (
        "protocol-security-summary.json",
        "artifact-manifest.json",
        "falco-summary.json",
        "runtime-trace-correlation.json",
    ),
}

_DOMAIN_RECOMMENDATIONS = {
    "business-logic": "Declare state, value, quota, eligibility, idempotency, and concurrency invariants and bind them to adversarial tests.",
    "privacy-lifecycle": "Declare purpose, minimization, retention, residency, processor, deletion, and export obligations for every sensitive data class.",
    "resilience": "Retain a source-bound workload model with correctness checks, resource budgets, amplification limits, recovery objectives, and backpressure tests.",
    "detection-engineering": "Inventory log sources and detection rules, then retain synthetic canary replay, false-positive budget, and incident-routing evidence.",
    "cryptographic-agility": "Inventory algorithms, protocols, keys, certificates, owners, expiry, deprecated use, and migration obligations in a CBOM-compatible control set.",
    "notebook-security": "Bind notebook cells, outputs, dependencies, and execution provenance to notebook-capable SAST, typing, secret, and quality evidence rather than crediting module-only scanner runs.",
    "messaging-security": "Test producer/consumer authorization, delivery semantics, ordering, deduplication, schema evolution, poison messages, and dead-letter isolation.",
    "desktop-client-security": "Test local IPC, credential storage, update signatures, protocol handlers, sandboxing, and extension or desktop privilege boundaries.",
    "firmware-iot-security": "Retain firmware inventory plus secure boot, update, device identity, hardware-boundary, and protocol test evidence.",
    "web3-security": "Bind contract invariants, transaction ordering, oracle dependencies, privileges, and upgradeability to chain-specific static and dynamic evidence.",
    "graphql-security": "Test resolver and field authorization, query cost/depth, batching limits, introspection policy, and excessive field exposure.",
    "identity-assurance": "Test proofing, enrollment, authenticator binding and recovery, federation assertions, step-up decisions, session rotation, revocation, logout, and assurance-level policy.",
    "tenant-isolation": "Propagate authenticated tenant context through APIs, databases, caches, files, queues, search/vector stores, keys, lifecycle operations, and audit records, with cross-tenant denial tests at every boundary.",
    "abuse-resistance": "Model valid-functionality abuse including credential attacks, automation, scraping, inventory denial, fraud, promotion manipulation, and cost amplification with bounded adversarial campaigns.",
    "workload-identity": "Inventory service identities and trust domains; test workload attestation, short-lived credential rotation, service authorization, egress, federation, and confused-deputy boundaries.",
    "integration-security": "Test webhook authenticity and replay, OAuth scope, provider egress, response/schema trust, credential separation, confused-deputy behavior, and degraded-provider failure modes.",
    "incident-response-recovery": "Retain exercised containment, evidence preservation, forensic logging, playbook routing, system recovery objectives, and post-incident validation rather than detection evidence alone.",
    "data-integrity-lineage": "Bind records and transformations to lineage, reconciliation, immutability, mutation authorization, and end-to-end integrity invariants across operational and analytical stores.",
    "serverless-edge-security": "Test trigger and event-source authorization, function identity, least privilege, concurrency and cost budgets, secret bootstrap, retries, and tenant-safe edge caching.",
    "external-asset-communication": "Inventory domain and certificate ownership; test DNSSEC and dangling records, SPF/DKIM/DMARC, inbound link or callback workflows, and certificate-to-domain bindings.",
    "ot-ics-safety": "Test industrial command authorization, protocol segmentation, engineering-workstation trust, fail-safe states, safety interlocks, and physical-process invariants in an authorized simulation or hardware-in-the-loop lane.",
    "privileged-control-plane": "Inventory every administrative and support path; test scoped authorization, impersonation disclosure, break-glass expiry, privileged session recording, dual control, and immutable audit behavior.",
    "distributed-temporal-correctness": "Exercise partitions, clock skew, duplicate and reordered delivery, lease expiry, quorum loss, leader changes, and recovery while checking safety and liveness invariants.",
    "secure-human-interaction": "Test understandable confirmation, phishing-resistant high-risk actions, accessible security controls, consent comprehension, and timely recovery and redress without leaking account state.",
    "ml-model-data-supply-chain": "Bind datasets, training code, model artifacts, registries, evaluation, deserialization, approvals, and deployment identities to immutable provenance and adversarial tests.",
    "credential-secret-lifecycle": "Inventory human, workload, CI, recovery, and emergency credentials; test least scope, issuance, rotation, revocation, dormancy, leak response, and emergency rollover.",
    "observability-integrity": "Authenticate telemetry sources and collectors; test log integrity, time synchronization, collector isolation, sensitive-data filtering, alert delivery, and telemetry-poisoning resistance.",
    "developer-environment-security": "Govern IDE extensions, build plugins, developer containers, hooks, package lifecycle execution, workstation secrets, and bootstrap scripts as production supply-chain inputs.",
    "parser-content-security": "Use differential, fuzz, resource-budget, archive-bomb, active-content, macro, metadata, and polyglot tests for every untrusted document, media, archive, and protocol parser.",
    "trust-safety": "For products with user-generated or recommended content, test abuse taxonomies, evasion, coordinated behavior, reporting, redress, age controls, and recommender safety with governed outcome metrics.",
    "confidential-computing-side-channels": "For enclave or high-assurance cryptographic workloads, test attestation, key release, rollback and debug controls, memory confidentiality, and timing/cache/size side-channel budgets.",
    "regulated-transaction-integrity": "For regulated value flows, bind authorization, screening, maker-checker approval, reconciliation, non-repudiation, and retention to jurisdiction-specific owners and evidence.",
    "physical-environmental-security": "For systems with facility or hardware custody assumptions, test access, tamper evidence, asset custody, media disposal, environmental monitoring, and disaster-site recovery.",
}
_DOMAIN_STANDARDS = {
    "resilience": (
        "NIST-SP-800-160-V2R1",
        "NIST Developing Cyber-Resilient Systems",
        "https://csrc.nist.gov/pubs/sp/800/160/v2/r1/final",
    ),
    "identity-assurance": (
        "NIST-SP-800-63-4",
        "NIST Digital Identity Guidelines",
        "https://pages.nist.gov/800-63-4/",
    ),
    "tenant-isolation": (
        "OWASP-MULTI-TENANT",
        "OWASP Multi-Tenant Security Cheat Sheet",
        "https://cheatsheetseries.owasp.org/cheatsheets/Multi_Tenant_Security_Cheat_Sheet.html",
    ),
    "abuse-resistance": (
        "OWASP-AUTOMATED-THREATS",
        "OWASP Automated Threats to Web Applications",
        "https://owasp.org/www-project-automated-threats-to-web-applications/",
    ),
    "workload-identity": (
        "NIST-SP-800-207A",
        "NIST Zero Trust for Cloud-Native Applications",
        "https://csrc.nist.gov/pubs/sp/800/207/a/final",
    ),
    "integration-security": (
        "OWASP-API10-2023",
        "OWASP Unsafe Consumption of APIs",
        "https://owasp.org/API-Security/editions/2023/en/0xaa-unsafe-consumption-of-apis/",
    ),
    "incident-response-recovery": (
        "NIST-SP-800-61R3",
        "NIST Incident Response Recommendations",
        "https://csrc.nist.gov/pubs/sp/800/61/r3/final",
    ),
    "serverless-edge-security": (
        "OWASP-SERVERLESS-TOP-10",
        "OWASP Serverless Top 10",
        "https://owasp.org/www-project-serverless-top-10/",
    ),
    "ot-ics-safety": (
        "NIST-SP-800-82R3",
        "NIST Guide to Operational Technology Security",
        "https://csrc.nist.gov/pubs/sp/800/82/r3/final",
    ),
    "privileged-control-plane": (
        "NIST-SP-800-53R5-AC",
        "NIST SP 800-53 Rev. 5 Access Control",
        "https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final",
    ),
    "distributed-temporal-correctness": (
        "NIST-SP-800-160-V1R1",
        "NIST Systems Security Engineering",
        "https://csrc.nist.gov/pubs/sp/800/160/v1/r1/final",
    ),
    "secure-human-interaction": (
        "NIST-SP-800-63B-4",
        "NIST Authentication and Authenticator Management",
        "https://pages.nist.gov/800-63-4/sp800-63b.html",
    ),
    "ml-model-data-supply-chain": (
        "NIST-AI-100-1",
        "NIST AI Risk Management Framework",
        "https://www.nist.gov/itl/ai-risk-management-framework",
    ),
    "credential-secret-lifecycle": (
        "NIST-SP-800-57-P1R5",
        "NIST Recommendation for Key Management",
        "https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final",
    ),
    "observability-integrity": (
        "NIST-SP-800-92",
        "NIST Guide to Computer Security Log Management",
        "https://csrc.nist.gov/pubs/sp/800/92/final",
    ),
    "developer-environment-security": (
        "SLSA-V1.2",
        "Supply-chain Levels for Software Artifacts",
        "https://slsa.dev/spec/v1.2/",
    ),
    "parser-content-security": (
        "CWE-20",
        "CWE Improper Input Validation",
        "https://cwe.mitre.org/data/definitions/20.html",
    ),
    "trust-safety": (
        "NIST-AI-100-1",
        "NIST AI Risk Management Framework",
        "https://www.nist.gov/itl/ai-risk-management-framework",
    ),
    "confidential-computing-side-channels": (
        "NIST-SP-800-53R5-SC",
        "NIST SP 800-53 Rev. 5 System and Communications Protection",
        "https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final",
    ),
    "regulated-transaction-integrity": (
        "NIST-CSF-2.0",
        "NIST Cybersecurity Framework 2.0",
        "https://www.nist.gov/cyberframework",
    ),
    "physical-environmental-security": (
        "NIST-SP-800-53R5-PE",
        "NIST SP 800-53 Rev. 5 Physical and Environmental Protection",
        "https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final",
    ),
}

_SENSITIVE_PATTERN = re.compile(
    r"(?i)(?:email|phone|address|birth|patient|medical|health|ssn|social.?security|national.?id|card|cvv|biometric|location|ip.?address|user.?id)"
)
_CRYPTO_IMPORTS = {
    "cryptography",
    "hashlib",
    "hmac",
    "jose",
    "jwt",
    "nacl",
    "openssl",
    "secrets",
    "ssl",
}
_DESKTOP_IMPORTS = {
    "cefpython3",
    "eel",
    "kivy",
    "pyqt5",
    "pyqt6",
    "pyside2",
    "pyside6",
    "tkinter",
    "wx",
}
_WEB3_IMPORTS = {"ape", "brownie", "eth_account", "eth_utils", "vyper", "web3"}
_IOT_IMPORTS = {"adafruit", "machine", "micropython", "paho.mqtt", "serial"}
_IDENTITY_IMPORTS = {
    "authlib",
    "django.contrib.auth",
    "fastapi.security",
    "flask_login",
    "oauthlib",
    "onelogin",
    "pysaml2",
    "social_core",
    "webauthn",
}
_ABUSE_IMPORTS = {"flask_limiter", "limits", "slowapi"}
_WORKLOAD_IDENTITY_IMPORTS = {"spiffe", "spiffe_tls"}
_INTEGRATION_IMPORTS = {
    "aiohttp",
    "boto3",
    "google.cloud",
    "httpx",
    "requests",
    "stripe",
    "twilio",
    "urllib3",
}
_DATA_PIPELINE_IMPORTS = {
    "airflow",
    "dagster",
    "dbt",
    "pandas",
    "prefect",
    "pyspark",
}
_SERVERLESS_IMPORTS = {"azure.functions", "chalice", "functions_framework", "zappa"}
_EXTERNAL_COMMUNICATION_IMPORTS = {"dns", "sendgrid", "smtplib"}
_OT_ICS_IMPORTS = {"asyncua", "opcua", "pycomm3", "pymodbus", "snap7"}
_PRIVILEGED_CONTROL_IMPORTS = {"django.contrib.admin", "flask_admin", "sqladmin"}
_DISTRIBUTED_SYSTEM_IMPORTS = {"consul", "etcd3", "kazoo", "pysyncobj", "raftos"}
_ML_SUPPLY_CHAIN_IMPORTS = {
    "datasets",
    "huggingface_hub",
    "joblib",
    "mlflow",
    "pickle",
    "sklearn",
    "tensorflow",
    "torch",
    "transformers",
}
_SECRET_LIFECYCLE_IMPORTS = {
    "azure.keyvault",
    "google.cloud.secretmanager",
    "hvac",
    "keyring",
}
_OBSERVABILITY_IMPORTS = {
    "opentelemetry",
    "prometheus_client",
    "sentry_sdk",
    "structlog",
}
_PARSER_CONTENT_IMPORTS = {
    "defusedxml",
    "fitz",
    "lxml",
    "pil",
    "pillow",
    "pypdf",
    "tarfile",
    "yaml",
    "zipfile",
}
_TRUST_SAFETY_IMPORTS = {"detoxify", "presidio_analyzer", "perspective"}
_CONFIDENTIAL_COMPUTING_IMPORTS = {"gramine", "openenclave", "sgx"}
_PHYSICAL_SECURITY_IMPORTS = {"bacpypes", "bacpypes3"}
_CONFIG_SUFFIXES = frozenset(
    {".conf", ".ini", ".json", ".toml", ".tf", ".xml", ".yaml", ".yml"}
)
_NON_RUNTIME_ROOTS = frozenset(
    {"docs", "example", "examples", "fixture", "fixtures", "test", "tests"}
)
_TEXT_DOMAIN_PATTERNS = {
    "identity-assurance": re.compile(
        r"(?i)(?:oauth2?|openid|oidc|saml|webauthn|passkey|identity.?provider|account.?recovery|session.?revocation)"
    ),
    "tenant-isolation": re.compile(
        r"(?i)(?:multi.?tenant|tenant[_-]?id|tenant.?context|row.?level.?security|cross.?tenant)"
    ),
    "abuse-resistance": re.compile(
        r"(?i)(?:credential.?stuff|captcha|bot.?detect|fraud|scalping|scraping|inventory.?denial|promotion.?abuse|rate.?limit)"
    ),
    "workload-identity": re.compile(
        r"(?i)(?:spiffe|spire|service.?mesh|peer.?authentication|service.?identity|trust.?domain|workload.?attest)"
    ),
    "integration-security": re.compile(
        r"(?i)(?:webhook|callback.?signature|third.?party|provider.?api|oauth.?scope|egress.?allow)"
    ),
    "incident-response-recovery": re.compile(
        r"(?i)(?:incident.?response|forensic|containment|recovery.?exercise|post.?incident|evidence.?preserv)"
    ),
    "data-integrity-lineage": re.compile(
        r"(?i)(?:data.?lineage|audit.?immut|event.?sourc|reconciliation|transformation.?invariant|tamper.?evident)"
    ),
    "serverless-edge-security": re.compile(
        r"(?i)(?:aws.?lambda|azure.?function|cloud.?function|edge.?function|serverless|lambda.?handler|cloudflare.?worker)"
    ),
    "external-asset-communication": re.compile(
        r"(?i)(?:dnssec|dmarc|dkim|domain.?ownership|dangling.?dns|route53|certificate.?domain|email.?authentication)"
    ),
    "ot-ics-safety": re.compile(
        r"(?i)(?:modbus|opc.?ua|profinet|ethernet.?ip|scada|programmable.?logic|safety.?interlock|fail.?safe.?state)"
    ),
    "privileged-control-plane": re.compile(
        r"(?i)(?:admin.?console|support.?impersonat|break.?glass|privileged.?access|superuser|dual.?control|sudoers|pam.?policy)"
    ),
    "distributed-temporal-correctness": re.compile(
        r"(?i)(?:leader.?elect|quorum|lease.?expir|clock.?skew|network.?partition|split.?brain|vector.?clock|consensus)"
    ),
    "secure-human-interaction": re.compile(
        r"(?i)(?:security.?confirm|transaction.?confirm|consent.?comprehen|account.?redress|phishing.?resistan|accessible.?security|high.?risk.?friction)"
    ),
    "ml-model-data-supply-chain": re.compile(
        r"(?i)(?:model.?registry|dataset.?provenance|model.?provenance|training.?pipeline|model.?artifact|safe.?tensor|model.?deserializ)"
    ),
    "credential-secret-lifecycle": re.compile(
        r"(?i)(?:secret.?manager|vault.?transit|credential.?rotat|token.?revok|dormant.?credential|emergency.?rotat|kms.?key)"
    ),
    "observability-integrity": re.compile(
        r"(?i)(?:opentelemetry|telemetry.?auth|log.?integrity|collector.?isolat|time.?synchron|audit.?pipeline|telemetry.?poison)"
    ),
    "developer-environment-security": re.compile(
        r"(?i)(?:dev.?container|ide.?extension|build.?plugin|pre.?commit.?hook|package.?lifecycle|workstation.?secret|bootstrap.?script)"
    ),
    "parser-content-security": re.compile(
        r"(?i)(?:archive.?bomb|zip.?bomb|parser.?differential|active.?content|document.?macro|polyglot.?file|media.?metadata|decompression.?limit)"
    ),
    "trust-safety": re.compile(
        r"(?i)(?:content.?moderation|moderation.?evasion|coordinated.?behavio|user.?reporting|age.?assurance|recommender.?safety|trust.?and.?safety)"
    ),
    "confidential-computing-side-channels": re.compile(
        r"(?i)(?:confidential.?comput|secure.?enclave|enclave.?attest|side.?channel|cache.?timing|memory.?confidential|sgx|sev.?snp)"
    ),
    "regulated-transaction-integrity": re.compile(
        r"(?i)(?:sanctions.?screen|maker.?checker|transaction.?non.?repudiation|regulated.?transaction|financial.?ledger|payment.?reconciliation)"
    ),
    "physical-environmental-security": re.compile(
        r"(?i)(?:facility.?access|environmental.?monitor|hardware.?tamper|media.?disposal|asset.?custody|disaster.?site|data.?center.?physical)"
    ),
}


def analyze_domain_assurance(
    target: Path, artifacts: dict[str, Any]
) -> tuple[list[Finding], dict[str, Any]]:
    target = target.resolve()
    policy, policy_error = _load_policy(target)
    files = maintained_repository_files(target)
    signals, parse_errors, byte_budget_exhausted = _domain_signals(
        target, files[:_MAX_FILES], artifacts
    )
    truncated = len(files) > _MAX_FILES or byte_budget_exhausted
    if policy_error:
        parse_errors.insert(0, policy_error)
    declared = {str(item["name"]): item for item in policy.get("domains", [])}
    passing_test_ids = _passing_test_ids(artifacts)
    domains: list[dict[str, Any]] = []
    findings: list[Finding] = []
    for name in _DOMAINS:
        declaration = declared.get(name)
        inferred = bool(signals[name])
        declared_applicable = (
            bool(declaration["applicable"]) if declaration is not None else None
        )
        conflict = declared_applicable is False and inferred
        applicable = inferred or declared_applicable is True
        requirements = (
            _requirements(target, declaration, artifacts, passing_test_ids)
            if declaration is not None
            else []
        )
        missing_default_evidence = [
            artifact
            for artifact in _DOMAIN_DEFAULT_EVIDENCE[name]
            if artifact not in artifacts
        ]
        gaps: list[str] = []
        if conflict:
            gaps.append(
                "declared non-applicability conflicts with a detected repository surface"
            )
        if applicable and declaration is None:
            gaps.append("applicable domain has no governed policy declaration")
        if declaration is not None and declared_applicable is True and not requirements:
            gaps.append("declared applicable domain has no assurance requirements")
        for requirement in requirements:
            gaps.extend(f"{requirement['id']}: {gap}" for gap in requirement["gaps"])
        if not applicable:
            status = "not-applicable"
        elif declaration is None:
            status = "unmodeled"
        elif gaps:
            status = "partial"
        else:
            status = "covered"
        record = {
            "name": name,
            "applicable": applicable,
            "applicability": (
                "declared-and-inferred"
                if inferred and declared_applicable is True
                else "declared"
                if declared_applicable is not None
                else "inferred"
                if inferred
                else "not-applicable"
            ),
            "signals": signals[name][:_MAX_SIGNALS_PER_DOMAIN],
            "policy_present": declaration is not None,
            "owner": declaration.get("owner") if declaration is not None else None,
            "requirements_detected": len(requirements),
            "requirements_satisfied": sum(
                item["status"] == "satisfied" for item in requirements
            ),
            "requirements": requirements,
            "available_default_evidence": [
                artifact
                for artifact in _DOMAIN_DEFAULT_EVIDENCE[name]
                if artifact in artifacts
            ],
            "missing_default_evidence": missing_default_evidence,
            "status": status,
            "gaps": gaps[:100],
            "recommendation": _DOMAIN_RECOMMENDATIONS[name],
        }
        domains.append(record)
        enforce = declaration is not None or bool(policy["enforce_inferred_domains"])
        if applicable and status != "covered" and enforce:
            findings.append(_gap_finding(record, conflict=conflict))
    if policy_error:
        findings.append(_policy_finding(policy_error))
    counts = Counter(str(item["status"]) for item in domains)
    applicable_domains = [item for item in domains if item["applicable"]]
    satisfied = sum(item["status"] == "covered" for item in applicable_domains)
    score = (
        round(100 * satisfied / len(applicable_domains)) if applicable_domains else 100
    )
    return findings, {
        "schema_version": "1.0",
        "analysis": "cross-domain-applicability-policy-and-evidence-coverage",
        "complete": not parse_errors and not truncated,
        "coverage_complete": all(
            item["status"] in {"covered", "not-applicable"} for item in domains
        ),
        "coverage_score": score,
        "policy_path": _POLICY_PATH if policy["present"] else None,
        "policy_present": bool(policy["present"]),
        "enforce_inferred_domains": bool(policy["enforce_inferred_domains"]),
        "files_analyzed": min(len(files), _MAX_FILES),
        "domains_detected": len(domains),
        "applicable_domains": len(applicable_domains),
        "covered_domains": satisfied,
        "status_counts": dict(sorted(counts.items())),
        "domains": domains,
        "parse_errors": parse_errors[:100],
        "truncated": truncated,
        "claim_boundary": (
            "Detected surfaces establish applicability, not vulnerability. Repository policy "
            "declares intended controls; a requirement is satisfied only when every named "
            "artifact is retained and every named test has a passing bounded observation. "
            "Static enforcement points and evidence names do not prove runtime behavior, "
            "identity assurance, tenant isolation, privacy compliance, resilience, recovery, "
            "model provenance, telemetry integrity, human outcomes, regulatory compliance, "
            "physical safety, side-channel resistance, exploitability, or absence of defects."
        ),
    }


def _requirements(
    target: Path,
    declaration: dict[str, Any],
    artifacts: dict[str, Any],
    passing_test_ids: set[str],
) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for item in declaration["requirements"][:_MAX_REQUIREMENTS]:
        evidence = [str(value) for value in item["evidence_artifacts"]]
        tests = [str(value) for value in item["test_ids"]]
        enforcement_points = [str(value) for value in item["enforcement_points"]]
        missing_evidence = [value for value in evidence if value not in artifacts]
        incomplete_evidence = [
            value
            for value in evidence
            if value in artifacts
            and isinstance(artifacts[value], dict)
            and "complete" in artifacts[value]
            and artifacts[value].get("complete") is not True
        ]
        missing_tests = [value for value in tests if value not in passing_test_ids]
        missing_enforcement = [
            value
            for value in enforcement_points
            if not _enforcement_point_exists(target, value)
        ]
        gaps: list[str] = []
        if not evidence and not tests and not enforcement_points:
            gaps.append("requirement has no evidence, test, or enforcement binding")
        if str(item["kind"]) in _BEHAVIORAL_REQUIREMENTS and not tests:
            gaps.append("behavioral requirement has no adversarial test identity")
        if missing_evidence:
            gaps.append("missing artifacts: " + ", ".join(missing_evidence))
        if incomplete_evidence:
            gaps.append("incomplete artifacts: " + ", ".join(incomplete_evidence))
        if missing_tests:
            gaps.append("missing passing tests: " + ", ".join(missing_tests))
        if missing_enforcement:
            gaps.append("missing enforcement points: " + ", ".join(missing_enforcement))
        result.append(
            {
                "id": str(item["id"]),
                "kind": str(item["kind"]),
                "objective": str(item["objective"]),
                "subjects": [str(value) for value in item["subjects"]],
                "evidence_artifacts": evidence,
                "test_ids": tests,
                "enforcement_points": enforcement_points,
                "missing_evidence_artifacts": missing_evidence,
                "incomplete_evidence_artifacts": incomplete_evidence,
                "missing_test_ids": missing_tests,
                "missing_enforcement_points": missing_enforcement,
                "status": "satisfied" if not gaps else "gap",
                "gaps": gaps,
            }
        )
    return result


def _load_policy(target: Path) -> tuple[dict[str, Any], str | None]:
    default = {
        "present": False,
        "enforce_inferred_domains": False,
        "domains": [],
    }
    path = target / _POLICY_PATH
    if not path.is_file():
        return default, None
    try:
        _, payload = read_regular_file(
            path,
            "domain assurance policy",
            maximum_bytes=2 * 1024 * 1024,
            boundary=target,
        )
        value = strict_loads(payload)
        _validate_policy(value)
        return {
            "present": True,
            "enforce_inferred_domains": value["enforce_inferred_domains"],
            "domains": value["domains"],
        }, None
    except (OSError, TypeError, ValueError) as exc:
        default["present"] = True
        return default, f"{_POLICY_PATH}: {type(exc).__name__}"


def _validate_policy(value: object) -> None:
    if (
        not isinstance(value, dict)
        or set(value) != {"schema_version", "enforce_inferred_domains", "domains"}
        or value.get("schema_version") != "1.0"
        or not isinstance(value.get("enforce_inferred_domains"), bool)
        or not isinstance(value.get("domains"), list)
        or len(value["domains"]) > len(_DOMAINS)
    ):
        raise ValueError("invalid domain assurance policy")
    seen_domains: set[str] = set()
    requirement_count = 0
    for domain in value["domains"]:
        if (
            not isinstance(domain, dict)
            or set(domain) != {"name", "applicable", "owner", "requirements"}
            or domain.get("name") not in _DOMAINS
            or domain["name"] in seen_domains
            or not isinstance(domain.get("applicable"), bool)
            or not _bounded_string(domain.get("owner"), 200)
            or not isinstance(domain.get("requirements"), list)
        ):
            raise ValueError("invalid domain assurance declaration")
        seen_domains.add(str(domain["name"]))
        requirement_count += len(domain["requirements"])
        if requirement_count > _MAX_REQUIREMENTS:
            raise ValueError("domain assurance requirements exceed limit")
        seen_requirements: set[str] = set()
        for requirement in domain["requirements"]:
            if (
                not isinstance(requirement, dict)
                or set(requirement)
                != {
                    "id",
                    "kind",
                    "objective",
                    "subjects",
                    "evidence_artifacts",
                    "test_ids",
                    "enforcement_points",
                }
                or not _bounded_string(requirement.get("id"), 200)
                or requirement["id"] in seen_requirements
                or requirement.get("kind") not in _REQUIREMENT_KINDS
                or not _bounded_string(requirement.get("objective"), 1_000)
            ):
                raise ValueError("invalid domain assurance requirement")
            seen_requirements.add(str(requirement["id"]))
            for field, maximum, pattern in (
                ("subjects", 100, None),
                ("test_ids", 100, None),
                ("enforcement_points", 100, None),
                ("evidence_artifacts", 50, r"^[a-z0-9][a-z0-9._-]{0,199}\.json$"),
            ):
                items = requirement.get(field)
                if (
                    not isinstance(items, list)
                    or len(items) > maximum
                    or len(set(items)) != len(items)
                    or not all(_bounded_string(item, 1_000) for item in items)
                    or (
                        pattern is not None
                        and not all(re.fullmatch(pattern, str(item)) for item in items)
                    )
                ):
                    raise ValueError(f"invalid requirement field: {field}")


def _domain_signals(
    target: Path, files: list[Path], artifacts: dict[str, Any]
) -> tuple[dict[str, list[str]], list[str], bool]:
    signals: dict[str, set[str]] = {name: set() for name in _DOMAINS}
    errors: list[str] = []
    remaining_bytes = _MAX_TOTAL_SOURCE_BYTES
    byte_budget_exhausted = False
    surfaces = classify_repository_surfaces(target)
    for surface in sorted(surfaces):
        if surface in {"service", "authorization", "database", "event"}:
            signals["business-logic"].add(f"surface:{surface}")
        if surface in {"service", "event", "database", "ai"}:
            signals["resilience"].add(f"surface:{surface}")
        if surface == "event":
            signals["messaging-security"].add("surface:event")
            signals["data-integrity-lineage"].add("surface:event")
        if surface == "database":
            signals["data-integrity-lineage"].add("surface:database")
    if (
        "falco-summary.json" in artifacts
        or "ruleset-regression-summary.json" in artifacts
    ):
        signals["detection-engineering"].add("artifact:detection-evidence")
        signals["incident-response-recovery"].add("artifact:detection-evidence")
    if "cloud-attack-path-summary.json" in artifacts:
        signals["workload-identity"].add("artifact:cloud-attack-path")
    if "database-security-summary.json" in artifacts:
        signals["tenant-isolation"].add("artifact:database-security")
    for path in files:
        relative = path.relative_to(target).as_posix()
        lower = relative.casefold()
        name = path.name.casefold()
        suffix = path.suffix.casefold()
        parts = lower.split("/")
        if parts and parts[0] in _NON_RUNTIME_ROOTS:
            continue
        if suffix == ".ipynb":
            signals["notebook-security"].add(relative)
        if suffix in {".sol", ".vy"} or name in {
            "foundry.toml",
            "hardhat.config.js",
            "hardhat.config.ts",
            "truffle-config.js",
        }:
            signals["web3-security"].add(relative)
        if (
            suffix == ".ino"
            or name
            in {
                "platformio.ini",
                "sdkconfig",
                "west.yml",
                "zephyrproject.yml",
            }
            or any(part in {"firmware", "embedded"} for part in parts)
        ):
            signals["firmware-iot-security"].add(relative)
        if suffix in {".awl", ".lad", ".l5x", ".scl", ".st"} or any(
            part in {"ics", "ot", "plc", "scada"} for part in parts
        ):
            signals["ot-ics-safety"].add(relative)
        if (
            name in {"manifest.json", "electron-builder.yml", "electron-builder.yaml"}
            or "electron" in lower
        ):
            signals["desktop-client-security"].add(relative)
        if (
            suffix in {".sigma", ".rules"}
            or "detections/" in lower
            or "sigma/" in lower
        ):
            signals["detection-engineering"].add(relative)
        if suffix in {".pem", ".crt", ".cer", ".key", ".p12", ".pfx"}:
            signals["cryptographic-agility"].add(relative)
        if name in {
            "serverless.yml",
            "serverless.yaml",
            "template.yaml",
            "template.yml",
            "wrangler.toml",
            "vercel.json",
        } or any(part in {"functions", "lambda"} for part in parts):
            signals["serverless-edge-security"].add(relative)
        if any(part in {"incidents", "playbooks", "runbooks"} for part in parts):
            signals["incident-response-recovery"].add(relative)
        if suffix in {".zone", ".dns"} or any(
            part in {"dns", "email-security"} for part in parts
        ):
            signals["external-asset-communication"].add(relative)
        if name in {
            ".pre-commit-config.yaml",
            ".pre-commit-config.yml",
            "devcontainer.json",
            "extensions.json",
        } or any(
            part in {".devcontainer", ".vscode", "build-plugins"} for part in parts
        ):
            signals["developer-environment-security"].add(relative)
        if any(
            part in {"admin", "backoffice", "control-plane", "support-tools"}
            for part in parts
        ):
            signals["privileged-control-plane"].add(relative)
        if any(part in {"model-registry", "training", "datasets"} for part in parts):
            signals["ml-model-data-supply-chain"].add(relative)
        if any(
            part in {"parsers", "documents", "uploads", "media-processing"}
            for part in parts
        ):
            signals["parser-content-security"].add(relative)
        if any(
            part in {"moderation", "trust-safety", "user-reports"} for part in parts
        ):
            signals["trust-safety"].add(relative)
        if any(part in {"enclave", "confidential-computing", "tee"} for part in parts):
            signals["confidential-computing-side-channels"].add(relative)
        if any(
            part in {"facilities", "physical-security", "data-centers"}
            for part in parts
        ):
            signals["physical-environmental-security"].add(relative)
        if suffix not in _CONFIG_SUFFIXES and suffix != ".py":
            continue
        try:
            size = path.stat().st_size
            if size > _MAX_FILE_BYTES:
                errors.append(f"{relative}: file exceeds analysis limit")
                continue
            if size > remaining_bytes:
                byte_budget_exhausted = True
                continue
            _, payload = read_regular_file(
                path,
                "domain assurance source or configuration",
                maximum_bytes=_MAX_FILE_BYTES,
                boundary=target,
            )
            remaining_bytes -= len(payload)
            text = payload.decode("utf-8")
            if suffix in _CONFIG_SUFFIXES:
                _add_text_signals(text, relative, signals)
                continue
            tree = ast.parse(text, filename=relative)
        except (OSError, SyntaxError, UnicodeError, ValueError) as exc:
            errors.append(f"{relative}: {type(exc).__name__}")
            continue
        imports = _imports(tree)
        if imports & _CRYPTO_IMPORTS:
            signals["cryptographic-agility"].add(relative)
        if imports & _DESKTOP_IMPORTS:
            signals["desktop-client-security"].add(relative)
        if imports & _WEB3_IMPORTS:
            signals["web3-security"].add(relative)
        if imports & _IOT_IMPORTS:
            signals["firmware-iot-security"].add(relative)
        if imports & _IDENTITY_IMPORTS:
            signals["identity-assurance"].add(relative)
        if imports & _ABUSE_IMPORTS:
            signals["abuse-resistance"].add(relative)
        if imports & _WORKLOAD_IDENTITY_IMPORTS:
            signals["workload-identity"].add(relative)
        if imports & _INTEGRATION_IMPORTS:
            signals["integration-security"].add(relative)
        if imports & _DATA_PIPELINE_IMPORTS:
            signals["data-integrity-lineage"].add(relative)
        if imports & _SERVERLESS_IMPORTS:
            signals["serverless-edge-security"].add(relative)
        if imports & _EXTERNAL_COMMUNICATION_IMPORTS:
            signals["external-asset-communication"].add(relative)
        if imports & _OT_ICS_IMPORTS:
            signals["ot-ics-safety"].add(relative)
        if imports & _PRIVILEGED_CONTROL_IMPORTS:
            signals["privileged-control-plane"].add(relative)
        if imports & _DISTRIBUTED_SYSTEM_IMPORTS:
            signals["distributed-temporal-correctness"].add(relative)
        if imports & _ML_SUPPLY_CHAIN_IMPORTS:
            signals["ml-model-data-supply-chain"].add(relative)
        if imports & _SECRET_LIFECYCLE_IMPORTS:
            signals["credential-secret-lifecycle"].add(relative)
        if imports & _OBSERVABILITY_IMPORTS:
            signals["observability-integrity"].add(relative)
        if imports & _PARSER_CONTENT_IMPORTS:
            signals["parser-content-security"].add(relative)
        if imports & _TRUST_SAFETY_IMPORTS:
            signals["trust-safety"].add(relative)
        if imports & _CONFIDENTIAL_COMPUTING_IMPORTS:
            signals["confidential-computing-side-channels"].add(relative)
        if imports & _PHYSICAL_SECURITY_IMPORTS:
            signals["physical-environmental-security"].add(relative)
        if any(value == "graphql" or value.startswith("graphql.") for value in imports):
            signals["graphql-security"].add(relative)
        if _SENSITIVE_PATTERN.search(text):
            signals["privacy-lifecycle"].add(relative)
        _add_text_signals(text, relative, signals)
    framework = artifacts.get("framework-model-coverage.json")
    if isinstance(framework, dict):
        frameworks = framework.get("frameworks") or framework.get("frameworks_detected")
        if "graphql" in str(frameworks).casefold():
            signals["graphql-security"].add("artifact:framework-model-coverage")
    if byte_budget_exhausted:
        errors.append("domain assurance source byte budget exhausted")
    return (
        {
            name: sorted(values)[:_MAX_SIGNALS_PER_DOMAIN]
            for name, values in signals.items()
        },
        errors,
        byte_budget_exhausted,
    )


def _add_text_signals(text: str, relative: str, signals: dict[str, set[str]]) -> None:
    for domain, pattern in _TEXT_DOMAIN_PATTERNS.items():
        if pattern.search(text):
            signals[domain].add(relative)


def _imports(tree: ast.AST) -> set[str]:
    values: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            values.update(alias.name.casefold() for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            values.add(node.module.casefold())
    roots = set(values)
    roots.update(value.partition(".")[0] for value in values)
    return roots


def _passing_test_ids(artifacts: dict[str, Any]) -> set[str]:
    result: set[str] = set()
    inventory = artifacts.get("source-inventory.json")
    source_sha256 = (
        str(inventory.get("source_sha256") or "") if isinstance(inventory, dict) else ""
    )
    for artifact_name in (
        "junit-summary.json",
        "hypothesis-summary.json",
        "schemathesis-summary.json",
    ):
        document = artifacts.get(artifact_name)
        if (
            not isinstance(document, dict)
            or not source_sha256
            or document.get("source_sha256") != source_sha256
        ):
            continue
        cases = document.get("test_cases")
        if not isinstance(cases, list):
            continue
        for case in cases[:100_000]:
            if not isinstance(case, dict) or str(case.get("result")) != "passed":
                continue
            for candidate in (
                case.get("id"),
                case.get("nodeid"),
                case.get("name"),
                case.get("test_id"),
            ):
                if isinstance(candidate, str) and candidate:
                    result.add(candidate[:1_000])
    contracts = artifacts.get("application-contract-analysis.json")
    if isinstance(contracts, dict):
        observed_test_cases = contracts.get("observed_test_cases")
        if isinstance(observed_test_cases, list):
            for case in observed_test_cases[:10_000]:
                if (
                    isinstance(case, dict)
                    and case.get("result") == "passed"
                    and case.get("source_bound") is True
                    and isinstance(case.get("id"), str)
                    and case["id"]
                ):
                    result.add(str(case["id"])[:1_000])
    return result


def _enforcement_point_exists(target: Path, value: str) -> bool:
    relative = value.partition("#")[0].partition(":")[0]
    candidate = Path(relative)
    if not relative or candidate.is_absolute() or ".." in candidate.parts:
        return False
    try:
        resolved = resolve_unlinked_path(
            target / candidate, "domain assurance enforcement point", boundary=target
        )
        return resolved.is_file()
    except (OSError, ValueError):
        return False


def _gap_finding(record: dict[str, Any], *, conflict: bool) -> Finding:
    name = str(record["name"])
    signals = record["signals"]
    path = next(
        (
            str(item)
            for item in signals
            if isinstance(item, str) and not item.startswith(("surface:", "artifact:"))
        ),
        _POLICY_PATH,
    )
    description = "; ".join(record["gaps"][:10])
    finding_id, fingerprint = finding_identity(
        tool="domain-assurance",
        rule_id=f"DOMAIN-{name.upper()}",
        path=path,
        start_line=1,
    )
    standard = _DOMAIN_STANDARDS.get(
        name,
        (
            "NIST-SSDF",
            "Secure Software Development Framework",
            "https://csrc.nist.gov/Projects/ssdf",
        ),
    )
    return Finding(
        finding_id=finding_id,
        fingerprint=fingerprint,
        title=f"{name.replace('-', ' ').title()} assurance is incomplete",
        description=description,
        impact="An applicable security domain can regress or remain untested even when conventional source scanners report clean results.",
        remediation=str(record["recommendation"]),
        severity=Severity.HIGH if conflict else Severity.MEDIUM,
        confidence=Confidence.HIGH if record["policy_present"] else Confidence.MEDIUM,
        area="cross-domain-assurance",
        domain="security",
        classifications=["DOMAIN-ASSURANCE-GAP", f"DOMAIN-{name.upper()}"],
        locations=[Location(path=path, start_line=1)],
        sources=[
            Source(
                tool="domain-assurance",
                rule_id=f"DOMAIN-{name.upper()}",
                message=description,
            )
        ],
        citations=[
            Citation(
                kind="standard",
                identifier=standard[0],
                title=standard[1],
                uri=standard[2],
            )
        ],
        evidence={"domain_assurance": record},
    )


def _policy_finding(error: str) -> Finding:
    finding_id, fingerprint = finding_identity(
        tool="domain-assurance",
        rule_id="DOMAIN-POLICY-INVALID",
        path=_POLICY_PATH,
        start_line=1,
    )
    return Finding(
        finding_id=finding_id,
        fingerprint=fingerprint,
        title="Domain assurance policy is invalid",
        description=error,
        impact="Malformed assurance declarations can hide intended domain obligations or bind them to ambiguous evidence.",
        remediation="Correct the strict domain-assurance policy before relying on its coverage result.",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        area="cross-domain-assurance",
        classifications=["DOMAIN-ASSURANCE-POLICY-INVALID"],
        locations=[Location(path=_POLICY_PATH, start_line=1)],
        sources=[
            Source(
                tool="domain-assurance", rule_id="DOMAIN-POLICY-INVALID", message=error
            )
        ],
        evidence={"domain_assurance": {"policy_error": error}},
    )


def _bounded_string(value: object, maximum: int) -> bool:
    return isinstance(value, str) and 0 < len(value) <= maximum
