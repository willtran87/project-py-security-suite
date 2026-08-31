from __future__ import annotations

from typing import Any


OPEN_SOURCE_STANDARDS: tuple[dict[str, Any], ...] = (
    {
        "id": "OPENSSF-OSS-CRS",
        "version": "2026-08-30-policy-pinned",
        "kind": "autonomous-vulnerability-research-orchestration-framework",
        "reference": "https://github.com/ossf/oss-crs",
        "evidence": ["benchmark-scorecard.json", "audit-package-verification.json"],
        "lifecycle": {
            "edition_status": "policy-pinned",
            "published": "2026",
            "observed_at": "2026-08-30",
        },
    },
    {
        "id": "OPENSSF-SECURITY-INSIGHTS",
        "version": "1.0.0",
        "kind": "repository-security-metadata-schema",
        "reference": "https://github.com/ossf/security-insights-spec",
        "evidence": ["software-supply-chain.json", "audit-package-verification.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2023-10-02",
            "observed_at": "2026-08-30",
        },
    },
    {
        "id": "OPENSSF-GUAC",
        "version": "1.0",
        "kind": "software-supply-chain-knowledge-graph-interoperability",
        "reference": "https://guac.sh/",
        "evidence": ["software-supply-chain.json", "dependency-surface.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2025-06-12",
            "observed_at": "2026-08-30",
        },
    },
    {
        "id": "OPENSSF-GITTUF",
        "version": "beta-policy-pinned-2025-06-06",
        "kind": "source-repository-policy-and-transparency-log",
        "reference": "https://gittuf.dev/",
        "evidence": ["audit-package-verification.json", "software-supply-chain.json"],
        "lifecycle": {
            "edition_status": "policy-pinned",
            "published": "2025-06-06",
            "observed_at": "2026-08-30",
        },
    },
    {
        "id": "OPENSSF-PACKAGE-ANALYSIS",
        "version": "2026-08-30-feed-policy-pinned",
        "kind": "malicious-package-runtime-behavior-analysis",
        "reference": "https://github.com/ossf/package-analysis",
        "evidence": ["dependency-surface.json", "benchmark-scorecard.json"],
        "lifecycle": {
            "edition_status": "policy-pinned",
            "published": "2026",
            "observed_at": "2026-08-30",
        },
    },
    {
        "id": "OWASP-KUBERNETES-TOP-10",
        "version": "2025",
        "kind": "kubernetes-security-risk-taxonomy",
        "reference": "https://owasp.org/www-project-kubernetes-top-ten/",
        "evidence": ["domain-assurance.json", "risk-paths.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2025",
            "observed_at": "2026-08-30",
        },
    },
    {
        "id": "OWASP-CICD-TOP-10",
        "version": "1.0-2022",
        "kind": "cicd-security-risk-taxonomy",
        "reference": "https://owasp.org/www-project-top-10-ci-cd-security-risks/",
        "evidence": ["domain-assurance.json", "software-supply-chain.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2022",
            "observed_at": "2026-08-30",
        },
    },
    {
        "id": "SBOMIT",
        "version": "2026-08-30-policy-pinned",
        "kind": "build-observed-sbom-attestation-framework",
        "reference": "https://github.com/SBOMit/spec",
        "evidence": ["software-supply-chain.json", "audit-package-verification.json"],
        "lifecycle": {
            "edition_status": "policy-pinned",
            "published": "2026",
            "observed_at": "2026-08-30",
        },
    },
    {
        "id": "OWASP-MOBILE-TOP-10",
        "version": "2024",
        "kind": "mobile-application-security-risk-taxonomy",
        "reference": "https://owasp.org/www-project-mobile-top-10/",
        "evidence": ["security-requirements-coverage.json", "benchmark-scorecard.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2024",
            "observed_at": "2026-08-30",
        },
    },
    {
        "id": "OWASP-SMART-CONTRACT-TOP-10",
        "version": "2026",
        "kind": "smart-contract-security-risk-taxonomy",
        "reference": "https://owasp.org/www-project-smart-contract-top-10/",
        "evidence": ["domain-assurance.json", "benchmark-scorecard.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2026",
            "observed_at": "2026-08-30",
        },
    },
    {
        "id": "CNCF-CLOUD-NATIVE-SECURITY-CONTROLS",
        "version": "2022-05-policy-pinned",
        "kind": "cloud-native-lifecycle-security-control-catalog",
        "reference": "https://tag-security.cncf.io/community/publications/",
        "evidence": ["domain-assurance.json", "architecture-evaluation.json"],
        "lifecycle": {
            "edition_status": "policy-pinned",
            "published": "2022-05",
            "observed_at": "2026-08-30",
        },
    },
    {
        "id": "MITRE-EMB3D",
        "version": "2.0.2",
        "kind": "embedded-device-property-threat-and-mitigation-model",
        "reference": "https://emb3d.mitre.org/",
        "evidence": ["threat-model-assessment.json", "domain-assurance.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2026-06-01",
            "observed_at": "2026-08-30",
        },
    },
    {
        "id": "OWASP-BUSINESS-LOGIC-ABUSE-TOP-10",
        "version": "2025-second-release",
        "kind": "business-logic-abuse-risk-taxonomy",
        "reference": "https://owasp.org/www-project-top-10-for-business-logic-abuse/",
        "evidence": ["application-contract-analysis.json", "benchmark-scorecard.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2025-08-02",
            "observed_at": "2026-08-30",
        },
    },
    {
        "id": "CNCF-SOFTWARE-SUPPLY-CHAIN-BEST-PRACTICES",
        "version": "v2-2025-policy-pinned",
        "kind": "software-supply-chain-persona-and-lifecycle-guidance",
        "reference": "https://tag-security.cncf.io/community/working-groups/supply-chain-security/supply-chain-security-paper-v2/",
        "evidence": ["software-supply-chain.json", "audit-package-verification.json"],
        "lifecycle": {
            "edition_status": "policy-pinned",
            "published": "2025-03",
            "observed_at": "2026-08-30",
        },
    },
)


OPEN_SOURCE_BENCHMARKS: tuple[dict[str, Any], ...] = (
    {
        "id": "oss-crs-crsbench",
        "version": "2026-08-30-corpus-policy-pinned",
        "kind": "autonomous-vulnerability-discovery-patch-and-pov-effectiveness",
        "source": "OpenSSF OSS-CRS CRSBench immutable corpus revision, challenge manifests, proof-of-vulnerability and functional-test oracles",
        "languages": ["c", "c++", "java", "python", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "openssf-security-insights-conformance",
        "version": "security-insights-1.0.0",
        "kind": "repository-security-metadata-schema-identity-and-freshness-conformance",
        "source": "OpenSSF Security Insights 1.0.0 schema, signed repository-bound fixtures, expiration cases and consumer query oracles",
        "languages": ["metadata", "repository", "supply-chain", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "guac-interoperability",
        "version": "guac-1.0-policy-pinned",
        "kind": "supply-chain-knowledge-graph-ingest-identity-query-and-roundtrip-conformance",
        "source": "GUAC 1.0 immutable release, CycloneDX, SPDX, SLSA, VEX and scorecard fixtures with graph and query oracles",
        "languages": ["graph", "sbom", "provenance", "vex", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "gittuf-source-policy-conformance",
        "version": "gittuf-beta-2025-06-06-policy-pinned",
        "kind": "repository-root-policy-reference-state-and-transparency-log-conformance",
        "source": "gittuf immutable beta release with test roots, delegated policies, reference states and tamper/replay/downgrade fixtures",
        "languages": ["git", "policy", "provenance", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "openssf-package-analysis-malicious-packages",
        "version": "2026-08-30-feed-snapshot",
        "kind": "malicious-package-runtime-behavior-classification-and-feed-validation",
        "source": "OpenSSF Package Analysis immutable feed snapshot plus consented malicious and clean package fixtures with runtime-behavior oracles",
        "languages": ["package", "runtime", "malware", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "owasp-kubernetes-top10-conformance",
        "version": "2025-taxonomy-policy-pinned",
        "kind": "kubernetes-top-ten-control-coverage-and-mutation-detection-conformance",
        "source": "OWASP Kubernetes Top 10 2025 risk identifiers, representative manifests, admission/runtime evidence and safe mutations",
        "languages": ["kubernetes", "yaml", "cloud-native", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "owasp-cicd-top10-conformance",
        "version": "1.0-2022-policy-pinned",
        "kind": "cicd-top-ten-attack-path-control-and-mutation-detection-conformance",
        "source": "OWASP CI/CD Top 10 v1 risk identifiers, synthetic pipeline graphs, identity/artifact boundaries and safe attack mutations",
        "languages": ["cicd", "pipeline", "supply-chain", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "sbomit-build-observed-sbom",
        "version": "2026-08-30-spec-policy-pinned",
        "kind": "build-observed-sbom-completeness-provenance-and-reconciliation-conformance",
        "source": "SBOMit immutable specification revision, in-toto witness attestations and declared-versus-observed dependency fixtures",
        "languages": ["sbom", "build", "in-toto", "provenance", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "primevul-real-world-vulnerability-detection",
        "version": "primevul-v0.1-policy-pinned",
        "kind": "deduplicated-real-world-vulnerable-function-classification",
        "source": "PrimeVul immutable release with CVE, fixing-commit, vulnerable/fixed pair, CWE, project and chronological split metadata",
        "languages": ["c", "c++"],
        "lane": "authorized-companion",
    },
    {
        "id": "diversevul-unseen-project-generalization",
        "version": "diversevul-raid-2023-policy-pinned",
        "kind": "cross-project-real-world-vulnerability-generalization",
        "source": "DiverseVul immutable release with verified source revisions, CWE labels, project-separated holdout and independently audited label samples",
        "languages": ["c", "c++"],
        "lane": "authorized-companion",
    },
    {
        "id": "cvefixes-chronological-fix-pair-validation",
        "version": "2026-08-30-policy-pinned-snapshot",
        "kind": "chronological-cve-vulnerable-fixed-commit-pair-classification",
        "source": "CVEfixes immutable database snapshot with CVE records, repository identities, parent/fix commits, code changes and independently replayed fix evidence",
        "languages": ["multi", "c", "c++", "java", "python", "javascript"],
        "lane": "authorized-companion",
    },
    {
        "id": "owasp-mobile-top10-conformance",
        "version": "2024-taxonomy-policy-pinned",
        "kind": "mobile-top-ten-control-coverage-and-behavioral-mutation-conformance",
        "source": "OWASP Mobile Top 10 2024 risk identifiers mapped to MASVS, MASTG, DroidBench, Ghera and MAS Crackmes behavior oracles",
        "languages": ["android", "ios", "java", "kotlin", "swift", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "owasp-smart-contract-top10-conformance",
        "version": "2026-taxonomy-policy-pinned",
        "kind": "smart-contract-top-ten-exploit-and-invariant-conformance",
        "source": "OWASP Smart Contract Top 10 2026, SCWE and SCSTG mappings with SmartBugs and organization-approved economic invariant fixtures",
        "languages": ["solidity", "vyper", "evm", "web3"],
        "lane": "authorized-companion",
    },
    {
        "id": "cncf-cloud-native-security-controls-conformance",
        "version": "2022-05-catalog-policy-pinned",
        "kind": "cloud-native-build-distribute-deploy-runtime-control-conformance",
        "source": "CNCF Cloud Native Security Controls Catalog and Cloud Native Security Whitepaper v2 mapped to NIST SP 800-53 Rev. 5 with architecture and mutation fixtures",
        "languages": ["cloud-native", "kubernetes", "oci", "policy", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "reposvul-repository-context-validation",
        "version": "2024-release-policy-pinned",
        "kind": "repository-file-function-line-vulnerability-context-classification",
        "source": "ReposVul immutable release with untangled fixes, repository snapshots, multi-granularity labels, interprocedural dependency graphs and trace-filtered patch identities",
        "languages": ["c", "c++", "java", "python", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "vuleval-repository-dependency-evaluation",
        "version": "2024-release-policy-pinned",
        "kind": "function-dependency-and-repository-vulnerability-evaluation",
        "source": "VulEval immutable release with function detection, vulnerability-related dependency prediction and repository-level interprocedural detection tasks",
        "languages": ["c", "c++", "repository", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "mitre-emb3d-property-threat-conformance",
        "version": "emb3d-2.0.2",
        "kind": "embedded-device-property-threat-mitigation-and-stix-conformance",
        "source": "MITRE EMB3D 2.0.2 property, threat, mitigation and STIX releases with representative embedded-device manifests and mapping oracles",
        "languages": ["embedded", "firmware", "hardware", "stix", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "owasp-business-logic-abuse-top10-conformance",
        "version": "2025-second-release-policy-pinned",
        "kind": "business-logic-state-transition-and-abuse-mutation-conformance",
        "source": "OWASP Business Logic Abuse Top 10 2025 risk identifiers with state-machine, concurrency, quota, artifact-lifecycle, access-control and hidden-function oracles",
        "languages": ["api", "workflow", "state-machine", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "cncf-supply-chain-best-practices-v2-conformance",
        "version": "v2-2025-policy-pinned",
        "kind": "software-supply-chain-persona-lifecycle-and-control-conformance",
        "source": "CNCF Software Supply Chain Best Practices v2 mapped to NIST SSDF, SLSA and OpenSSF S2C2F with producer, consumer and operator fixtures",
        "languages": ["supply-chain", "build", "distribution", "deployment", "multi"],
        "lane": "authorized-companion",
    },
)


OPEN_SOURCE_PROFILES: dict[str, dict[str, Any]] = {
    "autonomous-vulnerability-research": {
        "standards": ["OPENSSF-OSS-CRS"],
        "controls": [
            (
                "OPENSSF-OSS-CRS",
                "CRS-SCOPE-BUDGET-ISOLATION-AND-ORACLES",
                "Bind each challenge to an immutable source revision, authorization, resource budget, isolated runner, proof-of-vulnerability oracle, functional regression suite and protected evaluation split.",
                ["benchmark-scorecard.json", "audit-package-verification.json"],
            )
        ],
        "procedures": [
            (
                "OPENSSF-OSS-CRS",
                "CRSBENCH-REPEATED-DISCOVERY-PATCH-AND-POV",
                "Run at least three independently seeded trials per challenge, validate every proof and patch outside the agent boundary, reject hidden-test leakage, and retain exact compute/time budgets and confidence bounds.",
                "automated",
                True,
                ["benchmark-scorecard.json", "audit-package-verification.json"],
            )
        ],
    },
    "open-source-security-metadata-graph": {
        "standards": ["OPENSSF-SECURITY-INSIGHTS", "OPENSSF-GUAC"],
        "controls": [
            (
                "OPENSSF-SECURITY-INSIGHTS",
                "SECURITY-INSIGHTS-SCHEMA-REPOSITORY-IDENTITY-AND-FRESHNESS",
                "Validate the released schema, bind metadata to the repository and revision that published it, enforce expiry, and retain unsupported future fields without treating them as approved claims.",
                ["software-supply-chain.json", "audit-package-verification.json"],
            ),
            (
                "OPENSSF-GUAC",
                "GUAC-IDENTITY-PROVENANCE-QUERY-AND-ROUNDTRIP",
                "Preserve source-document digests and provenance, reconcile package identities without silent collapse, validate graph queries against golden answers, and prove loss-bounded round trips across supported formats.",
                ["software-supply-chain.json", "dependency-surface.json"],
            ),
        ],
        "procedures": [
            (
                "OPENSSF-GUAC",
                "GUAC-CROSS-FORMAT-INTEROPERABILITY-NEGATIVE-CASES",
                "Ingest signed CycloneDX, SPDX, SLSA, VEX and scorecard fixtures, exercise conflicting identities and stale metadata, compare canonical graph queries and require zero unexplained identity conflicts.",
                "automated",
                False,
                ["benchmark-scorecard.json", "software-supply-chain.json"],
            )
        ],
    },
    "forge-independent-source-integrity": {
        "standards": ["OPENSSF-GITTUF"],
        "controls": [
            (
                "OPENSSF-GITTUF",
                "GITTUF-ROOT-POLICY-REFERENCE-STATE-AND-LOG",
                "Verify trusted root and delegated policy thresholds, bind accepted references to repository state, and validate the append-only log before a source revision is admitted to a release.",
                ["audit-package-verification.json", "software-supply-chain.json"],
            )
        ],
        "procedures": [
            (
                "OPENSSF-GITTUF",
                "GITTUF-TAMPER-REPLAY-DOWNGRADE-AND-RECOVERY",
                "Exercise unauthorized reference updates, stale roots, threshold failures, log forks, rollback and recovery using test keys; require every unsafe state to fail closed.",
                "automated",
                False,
                ["benchmark-scorecard.json", "audit-package-verification.json"],
            )
        ],
    },
    "malicious-package-behavior": {
        "standards": ["OPENSSF-PACKAGE-ANALYSIS"],
        "controls": [
            (
                "OPENSSF-PACKAGE-ANALYSIS",
                "PACKAGE-ANALYSIS-FEED-IDENTITY-SANDBOX-AND-BEHAVIOR",
                "Pin package, ecosystem, feed and analyzer identities; collect bounded file, process and network behavior in a disposable sandbox; and distinguish observation from a malware verdict.",
                ["dependency-surface.json", "benchmark-scorecard.json"],
            )
        ],
        "procedures": [
            (
                "OPENSSF-PACKAGE-ANALYSIS",
                "PACKAGE-ANALYSIS-MALICIOUS-CLEAN-AND-EVASION-CORPUS",
                "Evaluate consented malicious, clean, delayed, environment-sensitive and evasive fixtures with protected labels, independent behavior oracles, per-run reset and no execution on developer or production hosts.",
                "automated",
                True,
                ["benchmark-scorecard.json", "audit-package-verification.json"],
            )
        ],
    },
    "cloud-native-delivery-risk-taxonomies": {
        "standards": ["OWASP-KUBERNETES-TOP-10", "OWASP-CICD-TOP-10"],
        "controls": [
            (
                "OWASP-KUBERNETES-TOP-10",
                "K8S-TOP10-DESIGN-ADMISSION-RUNTIME-AND-RECOVERY",
                "Map all ten current Kubernetes risks to design, manifest, admission, identity, runtime, telemetry and recovery evidence, retaining non-applicability rationale and residual risk.",
                ["domain-assurance.json", "risk-paths.json"],
            ),
            (
                "OWASP-CICD-TOP-10",
                "CICD-TOP10-IDENTITY-SOURCE-BUILD-ARTIFACT-AND-DEPLOYMENT",
                "Map all ten CI/CD risks across identities, source policy, dependency retrieval, build isolation, secrets, artifact promotion, deployment authority and audit boundaries.",
                ["domain-assurance.json", "software-supply-chain.json"],
            ),
        ],
        "procedures": [
            (
                "OWASP-CICD-TOP-10",
                "CLOUD-DELIVERY-TOP10-SAFE-MUTATION-CONFORMANCE",
                "Apply safe manifest and synthetic pipeline mutations for every risk identifier and require independently verified detection, prevention or explicitly governed acceptance without mutating production.",
                "automated",
                True,
                ["benchmark-scorecard.json", "domain-assurance.json"],
            )
        ],
    },
    "build-observed-sbom-assurance": {
        "standards": ["SBOMIT"],
        "controls": [
            (
                "SBOMIT",
                "BUILD-OBSERVED-DEPENDENCY-PROVENANCE-AND-RECONCILIATION",
                "Bind in-toto build observations to the subject, builder and source; reconcile filesystem, process and network observations with the declared SBOM; and fail on unexplained material dependencies.",
                ["software-supply-chain.json", "audit-package-verification.json"],
            )
        ],
        "procedures": [
            (
                "SBOMIT",
                "SBOMIT-DECLARED-OBSERVED-OMISSION-AND-TAMPER-CASES",
                "Replay signed build observations, compare declared and observed dependencies, inject omissions, undeclared fetches, subject misbinding and attestation tampering, and require exact fail-closed verdicts.",
                "automated",
                False,
                ["benchmark-scorecard.json", "software-supply-chain.json"],
            )
        ],
    },
    "real-world-vulnerability-generalization": {
        "standards": ["NIST-SSDF", "CWE-TOP-25"],
        "controls": [
            (
                "NIST-SSDF",
                "REAL-WORLD-CORPUS-LABEL-SPLIT-CONTAMINATION-AND-CONTEXT",
                "Evaluate vulnerability detection against source-pinned real fixes with verified labels, deduplication, protected project and chronological holdouts, training-overlap disclosure, repository context and uncertainty-aware CWE-stratified results.",
                ["benchmark-scorecard.json", "finding-validation.json"],
            )
        ],
        "procedures": [
            (
                "CWE-TOP-25",
                "PRIMEVUL-DIVERSEVUL-CVEFIXES-INDEPENDENT-REPLAY",
                "Acquire immutable licensed corpus snapshots, independently replay sampled fixes, remove exact and near duplicates before splitting, prohibit project and future-data leakage, execute protected holdouts, and publish confusion matrices and confidence intervals by CWE, project and age.",
                "automated",
                True,
                ["benchmark-scorecard.json", "audit-package-verification.json"],
            )
        ],
    },
    "mobile-risk-taxonomy-assurance": {
        "standards": ["OWASP-MOBILE-TOP-10", "OWASP-MASVS", "OWASP-MASTG"],
        "controls": [
            (
                "OWASP-MOBILE-TOP-10",
                "MOBILE-TOP10-REQUIREMENT-BEHAVIOR-AND-BINARY-COVERAGE",
                "Map every 2024 mobile risk to MASVS requirements, MASTG procedures, source and binary analysis, device behavior, privacy evidence and explicit non-applicability decisions.",
                ["security-requirements-coverage.json", "benchmark-scorecard.json"],
            )
        ],
        "procedures": [
            (
                "OWASP-MASTG",
                "MOBILE-TOP10-POSITIVE-NEGATIVE-DEVICE-AND-BINARY-CASES",
                "Exercise all ten risks using pinned DroidBench, Ghera and MAS Crackmes fixtures on disposable emulators or devices, validate source-to-binary identity, and retain prevention, detection, residual-risk and cleanup evidence.",
                "automated",
                True,
                ["benchmark-scorecard.json", "procedure-assessment.json"],
            )
        ],
    },
    "smart-contract-security-assurance": {
        "standards": ["OWASP-SMART-CONTRACT-TOP-10"],
        "controls": [
            (
                "OWASP-SMART-CONTRACT-TOP-10",
                "SMART-CONTRACT-TOP10-STATE-ECONOMIC-ORACLE-AND-UPGRADE-INVARIANTS",
                "Map all 2026 smart-contract risks to authorization, state-transition, economic, pricing, callback, arithmetic, initialization, proxy and upgrade invariants with explicit chain and protocol assumptions.",
                ["domain-assurance.json", "risk-paths.json"],
            )
        ],
        "procedures": [
            (
                "OWASP-SMART-CONTRACT-TOP-10",
                "SMART-CONTRACT-TOP10-EXPLOIT-REPLAY-AND-INVARIANT-CONFORMANCE",
                "Run inert exploit reproductions and property tests against pinned SmartBugs and economic fixtures on a disposable local chain, require every risk mutation to violate a named oracle, and prove state reset, test-key destruction and zero live-value interaction.",
                "automated",
                True,
                ["benchmark-scorecard.json", "audit-package-verification.json"],
            )
        ],
    },
    "cloud-native-lifecycle-control-assurance": {
        "standards": ["CNCF-CLOUD-NATIVE-SECURITY-CONTROLS", "NIST-SP-800-53"],
        "controls": [
            (
                "CNCF-CLOUD-NATIVE-SECURITY-CONTROLS",
                "CLOUD-NATIVE-BUILD-DISTRIBUTE-DEPLOY-RUNTIME-CONTROL-CLOSURE",
                "Trace applicable CNCF controls and their NIST SP 800-53 mappings across source, build, registry, admission, identity, workload, network, observability, response and recovery boundaries without substituting configuration checks for architecture evidence.",
                ["domain-assurance.json", "architecture-evaluation.json"],
            )
        ],
        "procedures": [
            (
                "CNCF-CLOUD-NATIVE-SECURITY-CONTROLS",
                "CNCF-CONTROL-LIFECYCLE-MAPPING-AND-SAFE-MUTATION-CONFORMANCE",
                "Validate catalog identity and mappings, exercise representative safe control-loss and bypass mutations in each lifecycle phase, reconcile CIS and Kubernetes results, and require independent disposition of every uncovered or inapplicable control.",
                "automated",
                True,
                ["benchmark-scorecard.json", "architecture-evaluation.json"],
            )
        ],
    },
    "repository-level-vulnerability-context": {
        "standards": ["NIST-SSDF", "CWE-TOP-25"],
        "controls": [
            (
                "NIST-SSDF",
                "REPOSITORY-CONTEXT-DEPENDENCY-LABEL-AND-HOLDOUT-INTEGRITY",
                "Evaluate vulnerability detection with immutable repository snapshots, untangled fixes, line/function/file/repository labels, interprocedural dependency context, project and chronological holdouts, training-overlap disclosure and independently replayed fix oracles.",
                ["benchmark-scorecard.json", "finding-validation.json"],
            )
        ],
        "procedures": [
            (
                "CWE-TOP-25",
                "REPOSVUL-VULEVAL-MULTI-GRANULARITY-INDEPENDENT-REPLAY",
                "Validate source and license identities, replay sampled fixes, audit tangled and stale patches, verify dependency graphs and multi-granularity labels, sequester projects and future commits, and report task-specific confidence intervals without collapsing repository results into function scores.",
                "automated",
                True,
                ["benchmark-scorecard.json", "audit-package-verification.json"],
            )
        ],
    },
    "embedded-device-threat-assurance": {
        "standards": ["MITRE-EMB3D", "NIST-SP-800-193"],
        "controls": [
            (
                "MITRE-EMB3D",
                "EMBEDDED-PROPERTY-THREAT-MITIGATION-AND-RESIDUAL-RISK-CLOSURE",
                "Inventory physical, hardware, firmware, boot, update, debug, storage, network, operating-system and application properties; map every applicable property to EMB3D threats and mitigations; and retain applicability, verification and residual-risk decisions.",
                ["threat-model-assessment.json", "domain-assurance.json"],
            )
        ],
        "procedures": [
            (
                "MITRE-EMB3D",
                "EMB3D-PROPERTY-THREAT-MITIGATION-STIX-AND-MUTATION-CONFORMANCE",
                "Validate the 2.0.2 model and STIX identities, replay representative property-to-threat and threat-to-mitigation mappings, inject omissions and stale identifiers, and require independent review without interpreting taxonomy coverage as device certification.",
                "automated",
                False,
                ["benchmark-scorecard.json", "threat-model-assessment.json"],
            )
        ],
    },
    "business-logic-abuse-assurance": {
        "standards": ["OWASP-BUSINESS-LOGIC-ABUSE-TOP-10", "OWASP-ASVS"],
        "controls": [
            (
                "OWASP-BUSINESS-LOGIC-ABUSE-TOP-10",
                "BUSINESS-LOGIC-STATE-TRANSITION-QUOTA-ARTIFACT-AND-AUTHORITY",
                "Model business assets, states, transitions, concurrency, quotas, artifact lifetimes, access-control decisions, hidden functions and termination conditions with explicit invariants and authorization boundaries.",
                ["application-contract-analysis.json", "risk-paths.json"],
            )
        ],
        "procedures": [
            (
                "OWASP-BUSINESS-LOGIC-ABUSE-TOP-10",
                "BUSINESS-LOGIC-TOP10-STATEFUL-MUTATION-CONFORMANCE",
                "Exercise all ten 2025 risks against synthetic stateful workflows using step-skipping, concurrent ordering, stale-artifact replay, quota, state-disclosure and shadow-function mutations, requiring deterministic business oracles and post-case restoration.",
                "automated",
                True,
                ["benchmark-scorecard.json", "application-contract-analysis.json"],
            )
        ],
    },
    "cncf-supply-chain-practices-assurance": {
        "standards": [
            "CNCF-SOFTWARE-SUPPLY-CHAIN-BEST-PRACTICES",
            "NIST-SSDF",
            "SLSA",
            "OPENSSF-S2C2F",
        ],
        "controls": [
            (
                "CNCF-SOFTWARE-SUPPLY-CHAIN-BEST-PRACTICES",
                "SUPPLY-CHAIN-PERSONA-SOURCE-BUILD-DISTRIBUTION-DEPLOYMENT-OPERATION",
                "Assign producer, consumer and operator responsibilities across source, dependency, build, provenance, artifact, distribution, deployment and operation boundaries, reconciling every applicable practice with SSDF, SLSA and S2C2F evidence.",
                ["software-supply-chain.json", "audit-package-verification.json"],
            )
        ],
        "procedures": [
            (
                "CNCF-SOFTWARE-SUPPLY-CHAIN-BEST-PRACTICES",
                "CNCF-SUPPLY-CHAIN-V2-PERSONA-LIFECYCLE-MUTATION-CONFORMANCE",
                "Validate the policy-pinned v2 publication, exercise responsibility gaps, untrusted source, dependency substitution, builder compromise, provenance misbinding, registry tamper and unsafe deployment cases, and require independent disposition of uncovered practices.",
                "automated",
                True,
                ["benchmark-scorecard.json", "software-supply-chain.json"],
            )
        ],
    },
    "public-vulnerable-application-testing": {
        "standards": ["OWASP-ASVS", "OWASP-WSTG", "OWASP-API-TOP-10"],
        "controls": [
            (
                "OWASP-ASVS",
                "VULNERABLE-TARGET-IDENTITY-LABEL-ROUTE-AND-STATE-INTEGRITY",
                "Bind each deliberately vulnerable application to an immutable release and image, authoritative positive and clean labels, reachable routes, roles, sessions, prerequisites, multi-step state and deterministic reset without exposing the target beyond its isolated laboratory.",
                ["benchmark-scorecard.json", "application-contract-analysis.json"],
            )
        ],
        "procedures": [
            (
                "OWASP-WSTG",
                "JUICE-SHOP-WEBGOAT-CRAPI-ASTF-CROSS-TARGET-EVALUATION",
                "Execute independently normalized scanners against pinned Juice Shop, WebGoat/WebWolf, crAPI, VAmPI, DVGA and clean controls; replay challenge and authorization oracles, measure per-target precision, recall and route coverage, block external egress, reset all state and reject inherited coverage claims.",
                "dynamic",
                True,
                ["benchmark-scorecard.json", "test-evidence.json"],
            )
        ],
    },
    "statistical-fuzzing-evaluation": {
        "standards": ["NISTIR-8397", "ISO-IEC-IEEE-29119-4", "NIST-SSDF"],
        "controls": [
            (
                "NISTIR-8397",
                "FUZZER-TARGET-BUILD-SEED-RESOURCE-AND-ORACLE-EQUIVALENCE",
                "Pin fuzzer, target, builder, toolchain, sanitizer, seed, dictionary and ground-truth identities; allocate equal resources; retain raw trial data; and distinguish reach, trigger, crash, coverage, deduplication and continuous-integration outcomes.",
                ["benchmark-scorecard.json", "test-evidence.json"],
            )
        ],
        "procedures": [
            (
                "ISO-IEC-IEEE-29119-4",
                "FUZZBENCH-MAGMA-OSS-FUZZ-REPEATED-STATISTICAL-REPLAY",
                "Run FuzzBench for at least twenty matched trials, Magma for at least ten and ClusterFuzzLite for at least three; include baseline and deliberately broken controls, replay sampled corpora and bugs independently, report uncertainty and drift, and avoid universal fuzzer rankings.",
                "dynamic",
                True,
                ["benchmark-scorecard.json", "audit-package-verification.json"],
            )
        ],
    },
    "sbom-build-truth-validation": {
        "standards": ["CISA-SBOM-MINIMUM-ELEMENTS", "SPDX", "ECMA-424"],
        "controls": [
            (
                "CISA-SBOM-MINIMUM-ELEMENTS",
                "SBOM-SOURCE-RESOLVER-BUILD-INSTALLED-AND-LAYER-TRUTH",
                "Reconcile source locks, package-manager resolver graphs, build observations, installed artifacts and container layers to component, version, identifier, hash, supplier, scope and dependency-relationship labels across protected ecosystems and time windows.",
                ["dependency-surface.json", "software-supply-chain.json"],
            )
        ],
        "procedures": [
            (
                "ECMA-424",
                "SBOM-SCA-COMPONENT-RELATIONSHIP-AND-ADVISORY-DIFFERENTIAL",
                "Generate and consume SPDX and CycloneDX artifacts across at least three ecosystems, compare them with independent build truth, inject omitted transitive dependencies, aliases, version drift, known unknowns and false advisory matches, and report field, component, relationship and vulnerability precision and recall separately.",
                "automated",
                True,
                ["benchmark-scorecard.json", "audit-package-verification.json"],
            )
        ],
    },
    "architecture-fitness-validation": {
        "standards": ["ISO-IEC-IEEE-42010", "ISO-IEC-5055", "CISQ-QUALITY"],
        "controls": [
            (
                "ISO-IEC-IEEE-42010",
                "ARCHITECTURE-RULE-SCENARIO-HISTORY-OWNERSHIP-AND-DRIFT",
                "Bind architectural components, layers, boundaries, permitted dependencies, quality scenarios, change history and ownership to independently reviewed rules and clean baselines, with protected system and chronological holdouts.",
                ["architecture-evaluation.json", "static-architecture.json"],
            )
        ],
        "procedures": [
            (
                "ISO-IEC-5055",
                "ARCHITECTURE-CYCLE-LAYERING-COUPLING-OWNERSHIP-AND-DRIFT-MUTATIONS",
                "Inject dependency cycles, forbidden layer edges, unstable dependencies, change-coupled hotspots, ownership concentration and architecture drift; require deterministic detection, clean-baseline controls, training-overlap analysis, independent label adjudication and rule-specific precision and recall.",
                "automated",
                False,
                ["benchmark-scorecard.json", "architecture-evaluation.json"],
            )
        ],
    },
}


# Identity lifecycle, workload identity, model-artifact, automotive-update, and
# evaluation-calibration extensions. Rolling publisher material is policy-pinned
# so a later upstream edit cannot silently change an accepted assurance claim.
OPEN_SOURCE_STANDARDS += (
    {
        "id": "IETF-SCIM-CORE-RFC7643",
        "version": "RFC7643-2015-09",
        "kind": "system-for-cross-domain-identity-management-core-schema",
        "reference": "https://www.rfc-editor.org/rfc/rfc7643.html",
        "evidence": ["identity-assurance.json", "benchmark-scorecard.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2015-09",
            "observed_at": "2026-08-31",
        },
    },
    {
        "id": "IETF-SCIM-PROTOCOL-RFC7644",
        "version": "RFC7644-2015-09",
        "kind": "system-for-cross-domain-identity-management-protocol",
        "reference": "https://www.rfc-editor.org/rfc/rfc7644.html",
        "evidence": ["identity-assurance.json", "benchmark-scorecard.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2015-09",
            "observed_at": "2026-08-31",
        },
    },
    {
        "id": "IETF-SCIM-CURSOR-RFC9865",
        "version": "RFC9865-2025-10",
        "kind": "scim-cursor-based-pagination-extension",
        "reference": "https://www.rfc-editor.org/rfc/rfc9865.html",
        "evidence": ["identity-assurance.json", "benchmark-scorecard.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2025-10",
            "observed_at": "2026-08-31",
        },
    },
    {
        "id": "IETF-SCIM-SET-RFC9967",
        "version": "RFC9967-2026-03",
        "kind": "scim-security-event-token-profile",
        "reference": "https://www.rfc-editor.org/rfc/rfc9967.html",
        "evidence": ["identity-assurance.json", "benchmark-scorecard.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2026-03",
            "observed_at": "2026-08-31",
        },
    },
    {
        "id": "OPENID-SSF-1.0",
        "version": "1.0-final-2025-09-02",
        "kind": "shared-signals-framework",
        "reference": "https://openid.net/specs/openid-sharedsignals-framework-1_0-final.html",
        "evidence": ["identity-assurance.json", "benchmark-scorecard.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2025-09-02",
            "observed_at": "2026-08-31",
        },
    },
    {
        "id": "OPENID-CAEP-1.0",
        "version": "1.0-final-2025-09-02",
        "kind": "continuous-access-evaluation-profile",
        "reference": "https://openid.net/specs/openid-caep-1_0-final.html",
        "evidence": ["identity-assurance.json", "benchmark-scorecard.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2025-09-02",
            "observed_at": "2026-08-31",
        },
    },
    {
        "id": "OPENID-RISC-1.0",
        "version": "1.0-final-2025-09-02",
        "kind": "risk-incident-sharing-and-coordination-profile",
        "reference": "https://openid.net/specs/openid-risc-1_0-final.html",
        "evidence": ["identity-assurance.json", "benchmark-scorecard.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2025-09-02",
            "observed_at": "2026-08-31",
        },
    },
    {
        "id": "SPIFFE-STANDARD",
        "version": "2026-08-31-stable-specs-policy-pinned",
        "kind": "secure-production-identity-framework-for-everyone",
        "reference": "https://spiffe.io/docs/latest/spiffe-specs/",
        "evidence": ["identity-assurance.json", "architecture-evaluation.json"],
        "lifecycle": {
            "edition_status": "policy-pinned",
            "published": "2026",
            "observed_at": "2026-08-31",
        },
    },
    {
        "id": "OPENSSF-MODEL-SIGNING",
        "version": "1.0",
        "kind": "machine-learning-model-signing-and-verification",
        "reference": "https://github.com/ossf/model-signing-spec",
        "evidence": ["software-supply-chain.json", "audit-package-verification.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2025",
            "observed_at": "2026-08-31",
        },
    },
    {
        "id": "CYCLONEDX-MLBOM",
        "version": "1.7",
        "kind": "machine-learning-bill-of-materials-and-model-card",
        "reference": "https://cyclonedx.org/capabilities/mlbom/",
        "evidence": ["software-supply-chain.json", "audit-package-verification.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2026",
            "observed_at": "2026-08-31",
        },
    },
    {
        "id": "UPTANE-STANDARD",
        "version": "2.1.0",
        "kind": "secure-automotive-software-update-framework",
        "reference": "https://uptane.org/docs/latest/all-versions",
        "evidence": ["software-supply-chain.json", "domain-assurance.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2025",
            "observed_at": "2026-08-31",
        },
    },
    {
        "id": "OPENSSF-CRITICALITY-SCORE",
        "version": "2026-08-31-algorithm-policy-pinned",
        "kind": "open-source-project-criticality-prioritization-signal",
        "reference": "https://openssf.org/projects/criticality-score/",
        "evidence": ["dependency-surface.json", "benchmark-scorecard.json"],
        "lifecycle": {
            "edition_status": "policy-pinned",
            "published": "2026",
            "observed_at": "2026-08-31",
        },
    },
)


OPEN_SOURCE_BENCHMARKS += (
    {
        "id": "scim-lifecycle-security-conformance",
        "version": "rfc7643-rfc7644-rfc9865-rfc9967",
        "kind": "identity-schema-protocol-lifecycle-cursor-and-event-security-conformance",
        "source": "RFC 7643, RFC 7644, RFC 9865 and RFC 9967 with organization-owned lifecycle, authorization, cursor, replay and negative fixtures",
        "languages": ["scim", "json", "http", "identity"],
        "lane": "authorized-companion",
    },
    {
        "id": "openid-shared-signals-conformance",
        "version": "ssf-caep-risc-1.0-final",
        "kind": "shared-signals-transmitter-receiver-and-continuous-access-conformance",
        "source": "OpenID SSF, CAEP and RISC 1.0 Final specifications with alpha-upstream-conformance acknowledgement and suite-owned push, poll, replay and subject-confusion oracles",
        "languages": ["ssf", "caep", "risc", "set", "identity"],
        "lane": "authorized-companion",
    },
    {
        "id": "spiffe-workload-identity-conformance",
        "version": "2026-08-31-stable-specs-policy-pinned",
        "kind": "workload-api-svid-trust-bundle-attestation-and-federation-conformance",
        "source": "Digest-pinned stable SPIFFE specifications and Workload API fixtures; experimental remote Workload API is explicitly excluded",
        "languages": ["spiffe", "x509", "jwt", "grpc", "workload-identity"],
        "lane": "authorized-companion",
    },
    {
        "id": "openssf-model-signing-conformance",
        "version": "oms-1.0",
        "kind": "model-manifest-signature-bundle-and-verifier-vector-conformance",
        "source": "OpenSSF Model Signing 1.0 specification, schemas and official verifier vectors with multi-file, partial-bundle, path, canonicalization and tamper cases",
        "languages": ["model", "sigstore", "dsse", "in-toto", "supply-chain"],
        "lane": "authorized-companion",
    },
    {
        "id": "cyclonedx-mlbom-conformance",
        "version": "cyclonedx-1.7",
        "kind": "mlbom-model-card-dataset-provenance-and-roundtrip-conformance",
        "source": "CycloneDX 1.7 schemas with machine-learning-model components, model cards, datasets, dependencies, provenance and BOM-Link fixtures",
        "languages": ["cyclonedx", "mlbom", "json", "xml", "supply-chain"],
        "lane": "authorized-companion",
    },
    {
        "id": "uptane-ota-security-conformance",
        "version": "uptane-2.1.0",
        "kind": "automotive-director-image-repository-ecu-and-rollback-security-conformance",
        "source": "Uptane 2.1.0 with Director and Image repositories, full and partial verification ECUs, POUF-bound metadata and rollback, freeze, mix-and-match, expiry and recovery fixtures",
        "languages": ["uptane", "automotive", "metadata", "ecu", "ota"],
        "lane": "authorized-companion",
    },
    {
        "id": "darpa-aixcc-autonomous-vulnerability-remediation",
        "version": "2025-scoring-pipeline-corpus-policy-pinned",
        "kind": "autonomous-vulnerability-discovery-proof-patch-and-functional-correctness-evaluation",
        "source": "Organization-approved immutable AIxCC challenge corpus, scoring pipeline, vulnerability proofs, functional tests and contamination manifest; public upstream readiness is never inferred",
        "languages": ["c", "c++", "java", "autonomous", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "openssf-criticality-score-calibration",
        "version": "2026-08-31-algorithm-policy-pinned",
        "kind": "project-criticality-signal-reproduction-sensitivity-and-calibration",
        "source": "Digest-pinned OpenSSF Criticality Score algorithm and raw source signals with freshness, alias, missing-data, sensitivity and downstream calibration fixtures",
        "languages": ["open-source", "metadata", "risk", "calibration"],
        "lane": "authorized-companion",
    },
)


OPEN_SOURCE_PROFILES.update(
    {
        "identity-lifecycle-continuous-access": {
            "standards": [
                "IETF-SCIM-CORE-RFC7643",
                "IETF-SCIM-PROTOCOL-RFC7644",
                "IETF-SCIM-CURSOR-RFC9865",
                "IETF-SCIM-SET-RFC9967",
                "OPENID-SSF-1.0",
                "OPENID-CAEP-1.0",
                "OPENID-RISC-1.0",
            ],
            "controls": [
                (
                    "IETF-SCIM-PROTOCOL-RFC7644",
                    "SCIM-LIFECYCLE-AUTHORIZATION-CURSOR-AND-EVENT-INTEGRITY",
                    "Bind schema, resource, tenant, role and lifecycle state; enforce mutability, uniqueness, ETags, filters, bulk limits and cursor integrity; and reject stale, replayed or subject-confused security events.",
                    ["identity-assurance.json", "benchmark-scorecard.json"],
                ),
                (
                    "OPENID-SSF-1.0",
                    "SSF-TRANSMITTER-RECEIVER-STREAM-AND-SET-TRUST",
                    "Validate transmitter and receiver metadata, stream lifecycle, push and poll delivery, signature and audience, issuer, jti, iat and subject identifiers while measuring revocation-event latency.",
                    ["identity-assurance.json", "benchmark-scorecard.json"],
                ),
            ],
            "procedures": [
                (
                    "OPENID-CAEP-1.0",
                    "SCIM-SSF-CAEP-RISC-NEGATIVE-CONFORMANCE",
                    "Replay create-through-deprovision lifecycle, cursor tamper and expiry, cross-tenant access, SET replay and subject confusion, stream removal and out-of-order events in synthetic tenants; acknowledge alpha upstream conformance and make no OpenID certification claim.",
                    "dynamic",
                    True,
                    ["benchmark-scorecard.json", "test-evidence.json"],
                ),
            ],
        },
        "workload-identity-federation": {
            "standards": ["SPIFFE-STANDARD", "NIST-SP-800-207A"],
            "controls": [
                (
                    "SPIFFE-STANDARD",
                    "SPIFFE-ATTESTATION-SVID-BUNDLE-ROTATION-AND-FEDERATION",
                    "Pin the stable SPIFFE specification snapshot; verify node and workload attestation, selector isolation, X.509 and JWT SVID issuance, Workload API authorization, trust bundles, rotation, revocation and trust-domain federation.",
                    ["identity-assurance.json", "architecture-evaluation.json"],
                )
            ],
            "procedures": [
                (
                    "SPIFFE-STANDARD",
                    "SPIFFE-WORKLOAD-IDENTITY-FAIL-CLOSED-CONFORMANCE",
                    "Exercise workload and node impersonation, selector collision, stale bundles, trust-domain substitution, JWT replay, rotation and federation failures; exclude experimental remote Workload API behavior from compliance claims.",
                    "dynamic",
                    True,
                    ["benchmark-scorecard.json", "test-evidence.json"],
                )
            ],
        },
        "ai-ml-artifact-supply-chain": {
            "standards": ["OPENSSF-MODEL-SIGNING", "CYCLONEDX-MLBOM", "SLSA"],
            "controls": [
                (
                    "OPENSSF-MODEL-SIGNING",
                    "MODEL-MANIFEST-SIGNATURE-IDENTITY-AND-COMPLETENESS",
                    "Bind every model file and manifest to approved digests, signer identity, detached Sigstore or DSSE/in-toto evidence and verifier vectors; distinguish artifact integrity and authenticity from model safety, quality or fitness.",
                    ["software-supply-chain.json", "audit-package-verification.json"],
                ),
                (
                    "CYCLONEDX-MLBOM",
                    "MLBOM-MODEL-CARD-DATASET-DEPENDENCY-AND-PROVENANCE",
                    "Validate CycloneDX 1.7 model components, model cards, datasets, training parameters, dependencies, provenance, external references and BOM-Link relationships without treating inventory completeness as a safety or fairness proof.",
                    ["software-supply-chain.json", "audit-package-verification.json"],
                ),
            ],
            "procedures": [
                (
                    "OPENSSF-MODEL-SIGNING",
                    "OMS-MLBOM-ROUNDTRIP-TAMPER-AND-OMISSION-CONFORMANCE",
                    "Run official OMS schemas and verifier vectors plus multi-file, partial bundle, duplicate path, traversal, canonicalization, signer, tamper and ML-BOM omission/roundtrip cases; independently replay every verdict.",
                    "automated",
                    True,
                    ["benchmark-scorecard.json", "audit-package-verification.json"],
                )
            ],
        },
        "automotive-secure-update-protocol": {
            "standards": ["UPTANE-STANDARD", "ISO-SAE-21434", "UNECE-R156"],
            "controls": [
                (
                    "UPTANE-STANDARD",
                    "UPTANE-REPOSITORY-METADATA-ECU-TIME-AND-RECOVERY",
                    "Bind Director and Image repositories, trusted roots and signed root, timestamp, snapshot and targets metadata to ECU verification capabilities, secure time, key custody, POUF assumptions and recovery authority.",
                    ["software-supply-chain.json", "domain-assurance.json"],
                )
            ],
            "procedures": [
                (
                    "UPTANE-STANDARD",
                    "UPTANE-ROLLBACK-FREEZE-MIX-AND-MATCH-COMPROMISE-CONFORMANCE",
                    "Exercise full and partial verification ECUs against rollback, freeze, mix-and-match, wrong-vehicle, expiry, threshold-key compromise and recovery fixtures in a simulated fleet; make no certification claim.",
                    "dynamic",
                    True,
                    ["benchmark-scorecard.json", "test-evidence.json"],
                )
            ],
        },
        "open-source-criticality-prioritization": {
            "standards": ["OPENSSF-CRITICALITY-SCORE", "NIST-SSDF"],
            "controls": [
                (
                    "OPENSSF-CRITICALITY-SCORE",
                    "CRITICALITY-SIGNAL-PROVENANCE-FRESHNESS-AND-CLAIM-BOUNDARY",
                    "Retain raw source signals, provenance, collection time, aliases, missing-data treatment, algorithm revision and deterministic recomputation; use criticality only to prioritize review, never as a security pass/fail or vulnerability-likelihood score.",
                    ["dependency-surface.json", "benchmark-scorecard.json"],
                )
            ],
            "procedures": [
                (
                    "OPENSSF-CRITICALITY-SCORE",
                    "CRITICALITY-REPRODUCTION-SENSITIVITY-AND-CALIBRATION",
                    "Reproduce official scores from pinned signals, test missing and stale inputs and repository aliases, publish sensitivity and downstream calibration, and keep criticality separate from exploitability, reachability and maintenance-health evidence.",
                    "automated",
                    False,
                    ["benchmark-scorecard.json", "dependency-surface.json"],
                )
            ],
        },
    }
)
