from __future__ import annotations

from typing import Any

import hashlib

from .strict_json import canonical_bytes


_COMMON = {
    "immutable_revision_required": True,
    "corpus_digest_required": True,
    "license_digest_required": True,
    "label_authority_digest_required": True,
    "golden_positive_required": True,
    "golden_negative_required": True,
    "signed_provenance_required": True,
    "replay_ledger_required": True,
}


BUILTIN_ADAPTER_SPECS: tuple[dict[str, Any], ...] = (
    {
        "benchmark_id": "nist-cfreds-cftt",
        "protocol": "conformance",
        "upstream": "https://cfreds.nist.gov/",
        "acquisition": {**_COMMON, "license": "publisher-and-dataset-specific"},
        "normalizer": "cftt-observation-conformance-v1",
        "required_inputs": [
            "test-plan",
            "reference-image",
            "expected-observations",
            "tool-version",
        ],
        "isolation": "read-only evidence media and disposable analysis workspace",
    },
    {
        "benchmark_id": "w3c-act-rules-conformance",
        "protocol": "conformance",
        "upstream": "https://www.w3.org/WAI/standards-guidelines/act/rules/",
        "acquisition": {**_COMMON, "license": "W3C-document-and-rule-license"},
        "normalizer": "act-applicability-outcome-v1",
        "required_inputs": [
            "approved-rules",
            "applicability-cases",
            "expected-outcomes",
            "implementation-version",
        ],
        "isolation": "digest-pinned browser and accessibility tree",
    },
    {
        "benchmark_id": "droidbench",
        "protocol": "classification",
        "upstream": "https://github.com/secure-software-engineering/DroidBench",
        "acquisition": {**_COMMON, "license": "upstream-repository-license"},
        "normalizer": "android-source-sink-classification-v1",
        "required_inputs": [
            "source-projects",
            "apk-set",
            "source-sink-labels",
            "android-image",
        ],
        "isolation": "disposable emulator or no-network static analysis container",
    },
    {
        "benchmark_id": "ghera-android-security",
        "protocol": "classification",
        "upstream": "https://bitbucket.org/secure-it-i/android-app-vulnerability-benchmarks/",
        "acquisition": {**_COMMON, "license": "upstream-repository-license"},
        "normalizer": "ghera-vulnerability-behavior-v1",
        "required_inputs": [
            "benchmark-apps",
            "expected-behavior",
            "android-image",
            "instrumentation-plan",
        ],
        "isolation": "disposable emulator with target-only network policy",
    },
    {
        "benchmark_id": "secbench-js",
        "protocol": "classification",
        "upstream": "https://github.com/cristianstaicu/SecBench.js",
        "acquisition": {
            **_COMMON,
            "license": "upstream-repository-and-package-license",
        },
        "normalizer": "vulnerable-fixed-pair-classification-v1",
        "required_inputs": [
            "vulnerable-commits",
            "fixed-commits",
            "lockfiles",
            "labels",
        ],
        "isolation": "no-network container with quarantined package cache",
    },
    {
        "benchmark_id": "cloud-native-chaos-resilience",
        "protocol": "conformance",
        "upstream": "https://chaos-mesh.org/ and https://litmuschaos.io/",
        "acquisition": {**_COMMON, "license": "Apache-2.0"},
        "normalizer": "steady-state-recovery-conformance-v1",
        "required_inputs": [
            "experiment-manifests",
            "steady-state-probes",
            "slo-thresholds",
            "cleanup-assertions",
        ],
        "isolation": "dedicated disposable cluster with bounded blast radius",
    },
    {
        "benchmark_id": "kubernetes-sonobuoy-conformance",
        "protocol": "conformance",
        "upstream": "https://github.com/vmware-tanzu/sonobuoy",
        "acquisition": {**_COMMON, "license": "Apache-2.0"},
        "normalizer": "sonobuoy-e2e-conformance-v1",
        "required_inputs": [
            "kubernetes-release",
            "plugin-images",
            "cluster-identity",
            "e2e-results",
        ],
        "isolation": "dedicated disposable cluster and digest-only plugin images",
    },
    {
        "benchmark_id": "cis-cat-scap-platform-conformance",
        "protocol": "conformance",
        "upstream": "https://www.cisecurity.org/cis-cat-pro and https://csrc.nist.gov/projects/security-content-automation-protocol/",
        "acquisition": {**_COMMON, "license": "licensed-CIS-or-publisher-specific"},
        "normalizer": "xccdf-oval-control-outcome-v1",
        "required_inputs": [
            "benchmark-edition",
            "profile",
            "platform-cpe",
            "xccdf-or-cis-cat-results",
        ],
        "isolation": "approved assessor host or read-only target snapshot",
    },
    {
        "benchmark_id": "c2sp-wycheproof",
        "protocol": "conformance",
        "upstream": "https://github.com/C2SP/wycheproof",
        "acquisition": {**_COMMON, "license": "Apache-2.0"},
        "normalizer": "wycheproof-valid-invalid-acceptable-v1",
        "required_inputs": [
            "test-vectors",
            "schema-version",
            "algorithm-implementation",
            "expected-results",
        ],
        "isolation": "no-network container with resource limits",
    },
    {
        "benchmark_id": "tiber-eu-threat-led-red-team",
        "protocol": "detection-evaluation",
        "upstream": "https://www.ecb.europa.eu/paym/cyber-resilience/tiber-eu/html/index.en.html",
        "acquisition": {**_COMMON, "license": "framework-and-engagement-specific"},
        "normalizer": "tiber-objective-detection-restoration-v1",
        "required_inputs": [
            "approved-scope",
            "threat-intelligence",
            "attack-objectives",
            "detection-and-restoration-evidence",
        ],
        "isolation": "authorized production-safe engagement with kill switches and restoration plan",
    },
    {
        "benchmark_id": "nist-dioptra-ai-evaluation",
        "protocol": "stochastic-adversarial",
        "upstream": "https://pages.nist.gov/dioptra/",
        "acquisition": {**_COMMON, "license": "NIST-software-and-corpus-specific"},
        "normalizer": "dioptra-repeated-attack-utility-v1",
        "required_inputs": [
            "experiment-plan",
            "model-digest",
            "dataset-digest",
            "attack-and-defense-plugins",
            "random-seeds",
        ],
        "isolation": "no-egress accelerator worker with digest-pinned images, bounded resources, and per-run reset",
    },
    {
        "benchmark_id": "firmware-resilience-measured-boot",
        "protocol": "conformance",
        "upstream": "https://csrc.nist.gov/pubs/sp/800/193/final and https://trustedcomputinggroup.org/resource/tpm-library-specification/",
        "acquisition": {**_COMMON, "license": "publisher-and-firmware-corpus-specific"},
        "normalizer": "firmware-protect-detect-recover-attestation-v1",
        "required_inputs": [
            "signed-firmware-corpus",
            "platform-profile",
            "event-log",
            "pcr-policy",
            "recovery-oracle",
        ],
        "isolation": "dedicated hardware laboratory or approved emulator with physical recovery, network isolation, and destructive-test authorization",
    },
    {
        "benchmark_id": "access-control-policy-model-conformance",
        "protocol": "conformance",
        "upstream": "https://csrc.nist.gov/pubs/sp/800/192/final",
        "acquisition": {**_COMMON, "license": "NIST-and-policy-corpus-specific"},
        "normalizer": "access-control-decision-and-mutation-conformance-v1",
        "required_inputs": [
            "policy-models",
            "subject-object-environment-cases",
            "decision-oracles",
            "mutation-set",
        ],
        "isolation": "no-network decision-engine container with immutable policy fixtures and resource limits",
    },
    {
        "benchmark_id": "differential-privacy-implementation-evaluation",
        "protocol": "conformance",
        "upstream": "https://csrc.nist.gov/pubs/sp/800/226/final",
        "acquisition": {**_COMMON, "license": "NIST-and-dataset-specific"},
        "normalizer": "differential-privacy-guarantee-hazard-utility-v1",
        "required_inputs": [
            "neighboring-datasets",
            "mechanism-version",
            "privacy-accountant",
            "privacy-budget",
            "utility-oracles",
        ],
        "isolation": "no-egress statistical worker with deterministic seeds, bounded repetitions, and isolated result storage",
    },
    {
        "benchmark_id": "security-evaluator-calibration",
        "protocol": "assessor-agreement",
        "upstream": "https://www.iso.org/standard/84987.html",
        "acquisition": {
            **_COMMON,
            "license": "licensed-ISO-criteria-and-case-specific",
        },
        "normalizer": "blinded-evaluator-qualification-and-agreement-v1",
        "required_inputs": [
            "role-profile",
            "qualification-criteria",
            "blinded-cases",
            "golden-decisions",
            "conflict-of-interest-records",
        ],
        "isolation": "blinded assessment workspace with separated answer key, reviewer identities, and adjudication ledger",
    },
    {
        "benchmark_id": "square-quality-measurement",
        "protocol": "conformance",
        "upstream": "https://www.iso.org/committee/356290.html",
        "acquisition": {
            **_COMMON,
            "license": "licensed-ISO-measures-and-reference-data-specific",
        },
        "normalizer": "square-requirement-measure-result-conformance-v1",
        "required_inputs": [
            "quality-requirements",
            "measure-definitions",
            "reference-datasets",
            "expected-results",
            "measurement-environment",
        ],
        "isolation": "read-only reference datasets and a digest-pinned measurement worker with deterministic resource accounting",
    },
    {
        "benchmark_id": "iso-29119-test-process-conformance",
        "protocol": "conformance",
        "upstream": "https://www.iso.org/standard/79428.html",
        "acquisition": {
            **_COMMON,
            "license": "licensed-ISO-requirements-and-case-corpus-specific",
        },
        "normalizer": "iso-29119-process-document-technique-conformance-v1",
        "required_inputs": [
            "licensed-requirement-map",
            "test-basis",
            "process-and-document-cases",
            "technique-oracles",
            "traceability-breaks",
        ],
        "isolation": "read-only licensed criteria and a digest-pinned test-management worker with protected answer keys",
    },
    {
        "benchmark_id": "square-quality-in-use-cloud",
        "protocol": "conformance",
        "upstream": "https://www.iso.org/standard/78177.html",
        "acquisition": {
            **_COMMON,
            "license": "licensed-ISO-model-measure-and-workload-specific",
        },
        "normalizer": "square-context-workload-measure-conformance-v1",
        "required_inputs": [
            "quality-in-use-contexts",
            "cloud-service-quality-model",
            "measure-definitions",
            "workload-set",
            "decision-oracles",
        ],
        "isolation": "disposable target environment with read-only measures, bounded workload generation, and controlled telemetry",
    },
    {
        "benchmark_id": "risk-technique-calibration",
        "protocol": "assessor-agreement",
        "upstream": "https://webstore.iec.ch/en/publication/59809",
        "acquisition": {
            **_COMMON,
            "license": "licensed-ISO-IEC-criteria-and-scenario-specific",
        },
        "normalizer": "risk-technique-selection-agreement-v1",
        "required_inputs": [
            "risk-context",
            "technique-selection-criteria",
            "blinded-scenarios",
            "golden-assessments",
            "adjudication-policy",
        ],
        "isolation": "blinded assessment workspace with separated answer key, independent reviewers, and adjudication ledger",
    },
    {
        "benchmark_id": "tls-protocol-conformance",
        "protocol": "conformance",
        "upstream": "https://github.com/google/boringssl and https://github.com/tlsfuzzer/tlsfuzzer",
        "acquisition": {**_COMMON, "license": "ISC-GPL-and-case-specific"},
        "normalizer": "tls-state-alert-interoperability-conformance-v1",
        "required_inputs": [
            "bogo-and-tlsfuzzer-revisions",
            "supported-case-manifest",
            "shim-or-endpoint-identity",
            "protocol-capability-matrix",
            "expected-alerts-and-transcripts",
        ],
        "isolation": "no-egress loopback-only protocol laboratory with disposable endpoints, bounded handshakes, and no production credentials",
    },
    {
        "benchmark_id": "reproducible-build-variation",
        "protocol": "conformance",
        "upstream": "https://reproducible-builds.org/docs/plans/",
        "acquisition": {
            **_COMMON,
            "license": "project-source-toolchain-and-guidance-specific",
        },
        "normalizer": "build-variation-artifact-equivalence-v1",
        "required_inputs": [
            "source-and-dependency-lock",
            "build-instructions",
            "builder-images-and-toolchains",
            "environment-variation-matrix",
            "artifact-and-diff-oracles",
        ],
        "isolation": "no-egress disposable builders with immutable inputs, independent workspaces, bounded resources, and isolated artifact storage",
    },
    {
        "benchmark_id": "cisa-secure-by-design-negative-assurance",
        "protocol": "conformance",
        "upstream": "https://www.cisa.gov/securebydesign",
        "acquisition": {**_COMMON, "license": "US-government-guidance"},
        "normalizer": "secure-default-product-property-conformance-v1",
        "required_inputs": [
            "product-property-map",
            "clean-install-images",
            "insecure-default-cases",
            "identity-logging-update-oracles",
            "exception-and-risk-records",
        ],
        "isolation": "disposable product environment with synthetic identities, inert dependencies, target-only networking, and restoration proof",
    },
    {
        "benchmark_id": "amtso-malware-protection-evaluation",
        "protocol": "detection-evaluation",
        "upstream": "https://www.amtso.org/standards/",
        "acquisition": {
            **_COMMON,
            "license": "AMTSO-EICAR-and-organization-fixture-specific",
        },
        "normalizer": "amtso-protection-visibility-remediation-v1",
        "required_inputs": [
            "approved-test-plan",
            "harmless-eicar-and-inert-fixtures",
            "clean-negative-set",
            "product-configuration",
            "safety-restoration-and-dispute-records",
        ],
        "isolation": "dedicated disposable malware laboratory with no production data, no external egress, harmless or inert fixtures, kill switch, and destruction receipt",
    },
    {
        "benchmark_id": "dice-attestation-conformance",
        "protocol": "conformance",
        "upstream": "https://trustedcomputinggroup.org/resource/dice-attestation-architecture/",
        "acquisition": {**_COMMON, "license": "TCG-and-platform-case-specific"},
        "normalizer": "dice-layer-evidence-verifier-conformance-v1",
        "required_inputs": [
            "dice-profile-and-errata",
            "device-and-layer-fixtures",
            "certificate-evidence-endorsement-cases",
            "freshness-and-mutation-set",
            "verifier-decision-oracles",
        ],
        "isolation": "dedicated hardware laboratory or approved emulator with synthetic device secrets, network isolation, reset, and recovery proof",
    },
    {
        "benchmark_id": "telecom-security-controls-conformance",
        "protocol": "conformance",
        "upstream": "https://www.iso.org/standard/80584.html",
        "acquisition": {
            **_COMMON,
            "license": "licensed-ISO-control-and-telecom-case-specific",
        },
        "normalizer": "telecom-control-applicability-evidence-conformance-v1",
        "required_inputs": [
            "licensed-control-map",
            "telecom-service-scope",
            "shared-responsibility-model",
            "control-evidence-cases",
            "non-applicability-oracles",
        ],
        "isolation": "read-only assessment workspace or disposable telecom laboratory with synthetic subscribers and no public-network signaling",
    },
    {
        "benchmark_id": "nice-workforce-coverage",
        "protocol": "conformance",
        "upstream": "https://www.nist.gov/itl/applied-cybersecurity/nice/nice-framework-resource-center/nice-framework-current-versions",
        "acquisition": {**_COMMON, "license": "NIST-and-organization-record-specific"},
        "normalizer": "nice-task-knowledge-skill-coverage-v1",
        "required_inputs": [
            "nice-component-release",
            "organization-role-map",
            "task-knowledge-skill-evidence",
            "separation-of-duty-rules",
            "coverage-and-drift-oracles",
        ],
        "isolation": "access-controlled assessment workspace with minimized personnel data, blinded scenarios, and independent review",
    },
    {
        "benchmark_id": "penetration-test-engagement-quality",
        "protocol": "conformance",
        "upstream": "https://www.crest-approved.org/wp-content/uploads/2023/04/A-Guide-to-Penetration-Testing-2022.pdf",
        "acquisition": {
            **_COMMON,
            "license": "CREST-PTES-and-engagement-record-specific",
        },
        "normalizer": "penetration-engagement-evidence-quality-v1",
        "required_inputs": [
            "signed-authorization-and-scope",
            "rules-of-engagement",
            "method-and-competence-records",
            "finding-evidence-and-remediation",
            "cleanup-retest-and-closure-receipts",
        ],
        "isolation": "authorized disposable target or production-safe engagement with target allowlist, kill switches, evidence controls, cleanup, restoration, and retest approval",
    },
    {
        "benchmark_id": "dora-delivery-outcomes",
        "protocol": "conformance",
        "upstream": "https://dora.dev/guides/dora-metrics/",
        "acquisition": {
            **_COMMON,
            "license": "DORA-guidance-and-organization-event-specific",
        },
        "normalizer": "dora-five-metric-data-contract-conformance-v1",
        "required_inputs": [
            "service-and-deployment-boundaries",
            "immutable-change-deployment-events",
            "incident-recovery-and-rework-events",
            "observation-window-and-exclusions",
            "metric-and-data-quality-oracles",
        ],
        "isolation": "read-only analytics workspace with pseudonymized events, immutable source snapshots, bounded windows, and independent recomputation",
    },
    {
        "benchmark_id": "structured-assurance-case-conformance",
        "protocol": "conformance",
        "upstream": "https://www.iso.org/standard/80625.html and https://www.omg.org/spec/SACM/2.3",
        "acquisition": {
            **_COMMON,
            "license": "licensed-ISO-requirements-OMG-specification-and-organization-case-specific",
        },
        "normalizer": "sacm-claim-argument-evidence-mutation-conformance-v1",
        "required_inputs": [
            "licensed-assurance-case-criteria",
            "sacm-2.3-machine-readable-metamodel",
            "positive-and-negative-assurance-cases",
            "graph-semantic-rules",
            "mutation-and-decision-oracles",
        ],
        "isolation": "no-egress validation worker with read-only schemas, sequestered answer keys, bounded graph resources, and independent adjudication",
    },
    {
        "benchmark_id": "integrity-vv-conformance",
        "protocol": "conformance",
        "upstream": "https://standards.ieee.org/ieee/1012/12536/",
        "acquisition": {
            **_COMMON,
            "license": "licensed-IEEE-requirements-and-organization-case-specific",
        },
        "normalizer": "ieee-1012-integrity-vv-task-evidence-conformance-v1",
        "required_inputs": [
            "licensed-vv-requirements",
            "integrity-level-decision-rules",
            "system-software-hardware-interface-cases",
            "reuse-cots-and-independence-cases",
            "task-evidence-and-verdict-oracles",
        ],
        "isolation": "read-only independent V&V workspace with blinded expected decisions, immutable lifecycle evidence, and separated adjudication",
    },
    {
        "benchmark_id": "cmvp-fips-140-3-validation",
        "protocol": "conformance",
        "upstream": "https://csrc.nist.gov/Projects/cryptographic-module-validation-program",
        "acquisition": {
            **_COMMON,
            "license": "NIST-CMVP-scheme-and-module-evidence-specific",
        },
        "normalizer": "cmvp-scheme-module-evidence-certificate-status-v1",
        "required_inputs": [
            "scheme-publication-and-implementation-guidance-snapshot",
            "scheme-referenced-standard-edition-map",
            "module-boundary-security-policy-and-configurations",
            "algorithm-prerequisite-and-certificate-status-snapshot",
            "test-and-validation-decision-oracles",
        ],
        "isolation": "accredited or approved cryptographic laboratory with controlled module custody, calibrated equipment, no production keys, bounded fault testing, and signed destruction or return receipt",
    },
    {
        "benchmark_id": "iso-19790-24759-module-conformance",
        "protocol": "conformance",
        "upstream": "https://www.iso.org/standard/82423.html and https://www.iso.org/standard/82424.html",
        "acquisition": {
            **_COMMON,
            "license": "licensed-ISO-module-requirements-test-methods-and-laboratory-fixture-specific",
        },
        "normalizer": "iso-19790-24759-security-level-test-assertion-v1",
        "required_inputs": [
            "licensed-19790-and-24759-requirements",
            "module-boundary-level-and-configuration-claims",
            "vendor-evidence-and-test-assertions",
            "calibrated-fixtures-fault-and-boundary-cases",
            "expected-results-uncertainty-and-decision-oracles",
        ],
        "isolation": "qualified cryptographic laboratory with module custody, calibrated equipment, synthetic keys, authorized non-invasive or fault testing, recovery controls, and signed destruction or return receipt",
    },
    {
        "benchmark_id": "biometric-performance-pad",
        "protocol": "biometric-performance",
        "upstream": "https://www.iso.org/standard/73515.html and https://www.iso.org/standard/79520.html",
        "acquisition": {
            **_COMMON,
            "license": "licensed-ISO-methods-consented-biometric-data-and-attack-instrument-specific",
        },
        "normalizer": "biometric-fmr-fnmr-iapar-stratified-confidence-v1",
        "required_inputs": [
            "approved-test-plan-and-sample-size-rationale",
            "consent-privacy-retention-and-demographic-governance",
            "sequestered-bona-fide-and-impostor-trials",
            "presentation-attack-instruments-and-species",
            "locked-thresholds-sensors-environments-and-decision-oracles",
        ],
        "isolation": "access-controlled biometric laboratory with informed consent, minimized identifiers, encrypted sequestered corpora, locked thresholds, operator blinding, attack-instrument safety, and governed destruction",
    },
    {
        "benchmark_id": "service-management-security-integration",
        "protocol": "conformance",
        "upstream": "https://www.iso.org/standard/70636.html and https://www.iso.org/standard/78752.html",
        "acquisition": {
            **_COMMON,
            "license": "licensed-ISO-service-security-criteria-and-organization-record-specific",
        },
        "normalizer": "service-security-lifecycle-trace-conformance-v1",
        "required_inputs": [
            "licensed-service-and-security-requirement-map",
            "service-catalog-ownership-and-configuration-baseline",
            "change-release-deployment-and-supplier-records",
            "incident-problem-continuity-and-recovery-records",
            "fault-injection-traceability-and-improvement-oracles",
        ],
        "isolation": "read-only service evidence workspace plus authorized disposable service twin for fault injection, rollback, recovery, and cleanup verification",
    },
    {
        "benchmark_id": "interlaboratory-proficiency-testing",
        "protocol": "proficiency-testing",
        "upstream": "https://www.iso.org/standard/80864.html",
        "acquisition": {
            **_COMMON,
            "license": "licensed-ISO-requirements-and-proficiency-item-specific",
        },
        "normalizer": "blinded-interlaboratory-reference-agreement-v1",
        "required_inputs": [
            "approved-proficiency-scheme-plan",
            "homogeneity-stability-and-assigned-value-evidence",
            "blinded-positive-negative-ambiguous-boundary-items",
            "participant-scope-environment-and-confidentiality-map",
            "statistical-adjudication-appeal-and-corrective-action-rules",
        ],
        "isolation": "blinded proficiency provider workspace with separated assigned values, collusion controls, participant pseudonyms, immutable submissions, and independent statistical review",
    },
    {
        "benchmark_id": "harmbench",
        "protocol": "stochastic-adversarial",
        "upstream": "https://github.com/centerforaisafety/HarmBench",
        "acquisition": {
            **_COMMON,
            "license": "MIT-and-model-dataset-provider-specific",
        },
        "normalizer": "harmbench-behavior-attack-refusal-utility-v1",
        "required_inputs": [
            "harmbench-revision-and-behavior-manifest",
            "attack-method-and-template-digests",
            "target-and-evaluator-model-digests",
            "classifier-and-human-adjudication-policy",
            "classifier-prompt-injection-negative-cases",
            "seeds-sampling-policy-and-private-holdout",
        ],
        "isolation": "no-egress disposable model worker with least-privilege credentials, synthetic targets, prompt and response quarantine, bounded spend, per-run reset, and human-reviewed harmful-output handling",
    },
    {
        "benchmark_id": "agentharm",
        "protocol": "stochastic-adversarial",
        "upstream": "https://github.com/UKGovernmentBEIS/inspect_evals/tree/main/src/inspect_evals/agentharm",
        "acquisition": {
            **_COMMON,
            "license": "MIT-with-AgentHarm-safety-and-security-use-clause-and-model-tool-provider-specific",
        },
        "normalizer": "agentharm-task-harm-refusal-utility-v1",
        "required_inputs": [
            "inspect-evals-agentharm-6-B-revision-task-and-split-manifest",
            "tool-schema-and-authority-boundary-manifest",
            "target-and-evaluator-model-digests",
            "classifier-and-human-adjudication-policy",
            "seeds-sampling-policy-and-private-holdout",
        ],
        "isolation": "no-egress disposable agent sandbox with inert tools, synthetic secrets and accounts, deny-by-default authority, bounded steps and spend, per-case reset, kill switch, and destruction receipt",
    },
    {
        "benchmark_id": "garak-llm-probe-conformance",
        "protocol": "stochastic-adversarial",
        "upstream": "https://github.com/NVIDIA/garak",
        "acquisition": {
            **_COMMON,
            "license": "Apache-2.0-and-model-provider-specific",
        },
        "normalizer": "garak-probe-detector-generator-result-v1",
        "required_inputs": [
            "garak-release-and-environment-lock",
            "probe-detector-generator-plugin-manifest",
            "target-model-and-generation-configuration",
            "detector-calibration-and-human-adjudication-policy",
            "seeds-repetitions-and-private-regression-set",
        ],
        "isolation": "no-egress disposable model worker with plugin allowlist, least-privilege credentials, bounded prompts tokens and spend, quarantined outputs, per-probe reset, and no production tools",
    },
    {
        "benchmark_id": "owasp-cornucopia-threat-model",
        "protocol": "conformance",
        "upstream": "https://cornucopia.owasp.org/",
        "acquisition": {
            **_COMMON,
            "license": "upstream-deck-localization-and-release-specific",
        },
        "normalizer": "cornucopia-card-threat-control-test-trace-v1",
        "required_inputs": [
            "deck-edition-language-and-card-manifest",
            "application-architecture-and-trust-boundary-model",
            "card-to-threat-control-test-mapping",
            "positive-negative-and-omission-cases",
            "independent-review-and-adjudication-policy",
        ],
        "isolation": "read-only threat-model assessment workspace with licensed immutable decks, protected answer keys, blinded reviewers, bounded mutation cases, and no production interaction",
    },
    {
        "benchmark_id": "pyrit-ai-red-team",
        "protocol": "stochastic-adversarial",
        "upstream": "https://github.com/microsoft/PyRIT",
        "acquisition": {
            **_COMMON,
            "license": "MIT-and-scenario-dataset-model-target-provider-specific",
        },
        "normalizer": "pyrit-scenario-attack-scorer-utility-v1",
        "required_inputs": [
            "pyrit-release-and-environment-lock",
            "scenario-objective-technique-converter-and-dataset-manifest",
            "target-scorer-memory-and-authority-boundary-manifest",
            "scorer-calibration-cross-evaluator-and-human-adjudication-policy",
            "seeds-repetitions-step-token-time-spend-and-private-holdout-policy",
        ],
        "isolation": "no-egress disposable AI target sandbox with scenario and plugin allowlists, synthetic identities secrets and tools, least-privilege credentials, quarantined memory and outputs, bounded steps tokens time and spend, kill switch, per-case reset, and signed cleanup destruction receipt",
    },
    {
        "benchmark_id": "owasp-aisvs-conformance",
        "protocol": "conformance",
        "upstream": "https://github.com/OWASP/AISVS",
        "acquisition": {
            **_COMMON,
            "license": "CC-BY-SA-4.0-and-organization-fixture-specific",
        },
        "normalizer": "aisvs-requirement-level-control-test-evidence-v1",
        "required_inputs": [
            "aisvs-1.0-release-requirement-and-level-manifest",
            "ai-system-lifecycle-boundary-and-applicability-map",
            "model-data-prompt-retrieval-tool-memory-and-provider-inventory",
            "positive-negative-boundary-and-mutation-fixtures",
            "evidence-authority-independent-review-and-adjudication-policy",
        ],
        "isolation": "no-egress disposable AI application sandbox with synthetic tenants identities data models tools secrets and memory, deny-by-default authority, bounded prompts steps tokens time and spend, harmful-output quarantine, kill switch, per-case reset, and signed cleanup destruction receipt",
    },
    {
        "benchmark_id": "eucc-scheme-assurance",
        "protocol": "conformance",
        "upstream": "https://certification.enisa.europa.eu/certification-library/eucc-certification-scheme_en",
        "acquisition": {
            **_COMMON,
            "license": "official-EUCC-public-documents-and-licensed-evaluation-evidence-specific",
        },
        "normalizer": "eucc-certificate-product-scope-authority-continuity-v1",
        "required_inputs": [
            "eucc-regulation-amendments-sota-transition-and-guidance-manifest",
            "cc-cem-protection-profile-security-target-and-assurance-map",
            "itsef-certification-body-accreditation-and-authorization-records",
            "certificate-product-series-version-configuration-and-registry-snapshot",
            "change-vulnerability-assurance-continuity-and-withdrawal-cases",
        ],
        "isolation": "read-only certification evidence workspace with licensed evidence access controls, public-registry snapshot pinning, blinded product and certificate mutations, separated laboratory and certification authority roles, immutable decisions, and no production target interaction",
    },
    {
        "benchmark_id": "cisa-secure-software-attestation",
        "protocol": "conformance",
        "upstream": "https://www.cisa.gov/resources-tools/resources/secure-software-development-attestation-form",
        "acquisition": {
            **_COMMON,
            "license": "United-States-government-work-and-producer-evidence-specific",
        },
        "normalizer": "cisa-common-form-product-signatory-ssdf-evidence-v1",
        "required_inputs": [
            "common-form-revision-and-ssdf-practice-map",
            "producer-product-version-delivery-and-release-subject-manifest",
            "signatory-identity-authority-signature-time-and-revocation-evidence",
            "practice-evidence-exception-compensating-control-and-expiry-ledger",
            "forgery-replay-stale-scope-and-change-trigger-negative-cases",
        ],
        "isolation": "read-only attestation verification workspace with synthetic producer and agency identities, test-only signing roots, revoked and unauthorized signers, immutable release subjects, replay ledger, no production credentials, and quarantined evidence",
    },
    {
        "benchmark_id": "nist-csf-profile-gap-reassessment",
        "protocol": "conformance",
        "upstream": "https://csrc.nist.gov/pubs/sp/1301/final",
        "acquisition": {
            **_COMMON,
            "license": "NIST-publication-and-organization-profile-specific",
        },
        "normalizer": "csf-current-target-gap-action-reassessment-v1",
        "required_inputs": [
            "csf-2.0-core-sp-1301-and-informative-reference-manifest",
            "organization-scope-mission-current-and-target-profile-snapshots",
            "gap-risk-priority-action-owner-dependency-and-acceptance-ledger",
            "evidence-exception-expiry-progress-and-reassessment-records",
            "identifier-semantic-orphan-cycle-staleness-and-regression-cases",
        ],
        "isolation": "read-only governance evidence workspace with source-pinned CSF identifiers, synthetic profile mutations, separated profile author and approver roles, immutable reassessment snapshots, and no automatic production control changes",
    },
    {
        "benchmark_id": "mlcommons-ailuminate-safety",
        "protocol": "stochastic-adversarial",
        "upstream": "https://mlcommons.org/ailuminate/safety/",
        "acquisition": {
            **_COMMON,
            "license": "MLCommons-assessment-corpus-evaluator-model-and-provider-specific",
        },
        "normalizer": "ailuminate-safety-hazard-grade-utility-v1",
        "required_inputs": [
            "ailuminate-safety-release-assessment-standard-and-locale-lock",
            "sut-persona-hazard-public-private-prompt-split-manifest",
            "evaluator-ensemble-reference-system-and-calibration-digests",
            "seeds-sampling-repetitions-grading-and-human-adjudication-policy",
            "contamination-scorer-manipulation-utility-and-confidence-analysis",
        ],
        "isolation": "no-egress disposable model worker with synthetic identities, least-privilege model credentials, immutable public-private split separation, evaluator prompt-injection controls, harmful-output quarantine, bounded prompts tokens time spend and repetitions, kill switch, reset, and destruction receipt",
    },
    {
        "benchmark_id": "mlcommons-ailuminate-jailbreak",
        "protocol": "stochastic-adversarial",
        "upstream": "https://ailuminate.mlcommons.org/benchmarks/security/0.5-en_us-official-ensemble",
        "acquisition": {
            **_COMMON,
            "license": "MLCommons-jailbreak-corpus-evaluator-model-and-provider-specific",
        },
        "normalizer": "ailuminate-jailbreak-naive-baseline-attack-grade-v1",
        "required_inputs": [
            "ailuminate-jailbreak-release-attack-set-baseline-and-locale-lock",
            "sut-attack-scenario-public-private-protected-split-manifest",
            "evaluator-ensemble-reference-system-and-calibration-digests",
            "seeds-sampling-repetitions-grading-and-human-adjudication-policy",
            "contamination-scorer-manipulation-utility-variance-and-confidence-analysis",
        ],
        "isolation": "no-egress disposable model worker with synthetic identities, least-privilege model credentials, protected attack-set separation, evaluator prompt-injection controls, harmful-output quarantine, bounded prompts tokens time spend and repetitions, kill switch, per-case reset, and signed destruction receipt",
    },
    {
        "benchmark_id": "mcp-client-server-security-conformance",
        "protocol": "conformance",
        "upstream": "https://modelcontextprotocol.io/specification/2025-11-25/ and https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html",
        "acquisition": {
            **_COMMON,
            "license": "MCP-specification-schema-OWASP-guidance-and-fixture-specific",
        },
        "normalizer": "mcp-message-capability-auth-task-tool-security-conformance-v1",
        "required_inputs": [
            "mcp-2025-11-25-schema-and-security-requirement-manifest",
            "client-server-proxy-transport-and-capability-matrix",
            "oauth-discovery-resource-scope-token-and-redirect-oracles",
            "tool-resource-prompt-elicitation-sampling-and-task-policy",
            "malformed-drift-confused-deputy-ssrf-injection-replay-and-isolation-cases",
        ],
        "isolation": "no-egress disposable MCP laboratory with synthetic authorization servers identities tokens resources prompts tools tasks and secrets, loopback or target-only transports, deny-by-default tool authority, bounded messages content steps time and spend, per-case reset, kill switch, and signed cleanup destruction receipt",
    },
    {
        "benchmark_id": "aws-fsbp-securityhub-conformance",
        "protocol": "conformance",
        "upstream": "https://docs.aws.amazon.com/securityhub/latest/userguide/fsbp-standard.html",
        "acquisition": {
            **_COMMON,
            "license": "AWS-documentation-control-catalog-and-customer-evidence-specific",
        },
        "normalizer": "aws-fsbp-account-region-resource-finding-exception-v1",
        "required_inputs": [
            "fsbp-control-snapshot-and-securityhub-api-model",
            "organization-account-ou-region-and-resource-inventory",
            "securityhub-findings-aggregation-and-control-status-export",
            "suppression-exception-owner-expiry-and-remediation-ledger",
            "independent-inventory-drift-negative-cases-and-rescan-receipts",
        ],
        "isolation": "read-only short-lived AWS assessment role scoped to approved organizations accounts and regions, separate evidence store, no production mutation, CloudTrail audit, plus disposable test accounts for synthetic misconfiguration injection cleanup and rescan proof",
    },
    {
        "benchmark_id": "microsoft-mcsb-defender-conformance",
        "protocol": "conformance",
        "upstream": "https://learn.microsoft.com/en-us/security/benchmark/azure/overview-mcsb-v1",
        "acquisition": {
            **_COMMON,
            "license": "Microsoft-documentation-benchmark-and-customer-evidence-specific",
        },
        "normalizer": "mcsb-tenant-subscription-resource-assessment-exemption-v1",
        "required_inputs": [
            "mcsb-v1-control-and-service-baseline-snapshot",
            "tenant-management-group-subscription-and-resource-inventory",
            "defender-assessment-initiative-and-regulatory-data-export",
            "exemption-shared-responsibility-owner-expiry-and-remediation-ledger",
            "independent-resource-graph-drift-negative-cases-and-rescan-receipts",
        ],
        "isolation": "read-only short-lived Azure assessment identity scoped to approved tenants and subscriptions, separate evidence store, no production mutation, activity-log audit, plus disposable subscriptions for synthetic misconfiguration injection cleanup and rescan proof",
    },
    {
        "benchmark_id": "gcp-enterprise-foundations-conformance",
        "protocol": "conformance",
        "upstream": "https://docs.cloud.google.com/architecture/blueprints/security-foundations",
        "acquisition": {
            **_COMMON,
            "license": "Google-documentation-Terraform-blueprint-and-customer-evidence-specific",
        },
        "normalizer": "gcp-foundation-org-policy-architecture-finding-drift-v1",
        "required_inputs": [
            "enterprise-foundations-guide-and-terraform-revision",
            "organization-folder-project-resource-and-identity-inventory",
            "organization-policy-logging-network-key-secret-and-scc-export",
            "deviation-inheritance-owner-expiry-and-remediation-ledger",
            "independent-asset-inventory-drift-negative-cases-and-rescan-receipts",
        ],
        "isolation": "read-only short-lived Google Cloud assessment identity scoped to approved organizations folders and projects, separate evidence store, no production mutation, audit-log capture, plus disposable projects for synthetic policy and architecture drift cleanup and rescan proof",
    },
    {
        "benchmark_id": "first-csirt-psirt-maturity-assessment",
        "protocol": "assessor-agreement",
        "upstream": "https://www.first.org/standards/frameworks/",
        "acquisition": {
            **_COMMON,
            "license": "FIRST-framework-maturity-metric-and-organization-case-specific",
        },
        "normalizer": "first-service-function-capability-outcome-agreement-v1",
        "required_inputs": [
            "csirt-2.1-psirt-1.1-maturity-and-metrics-manifest",
            "mandate-constituency-service-catalog-role-and-competence-map",
            "incident-vulnerability-disclosure-and-coordination-scenario-set",
            "service-level-outcome-capacity-handoff-and-improvement-evidence",
            "blinded-assessors-golden-decisions-conflict-and-adjudication-policy",
        ],
        "isolation": "blinded response-assessment workspace with synthetic products constituents researchers suppliers incidents and vulnerabilities, minimized personnel data, separated answer keys, immutable submissions, independent adjudication, and no production incident activation",
    },
    {
        "benchmark_id": "memory-safety-engineering-conformance",
        "protocol": "conformance",
        "upstream": "https://www.cisa.gov/resources-tools/resources/case-memory-safe-roadmaps",
        "acquisition": {
            **_COMMON,
            "license": "United-States-government-guidance-toolchain-and-repository-specific",
        },
        "normalizer": "memory-unsafe-footprint-hardening-sanitizer-fuzz-migration-v1",
        "required_inputs": [
            "unsafe-language-construct-ffi-dependency-and-reachability-inventory",
            "production-build-toolchain-hardening-and-mitigation-manifest",
            "static-sanitizer-fuzz-crash-regression-and-negative-control-results",
            "privilege-exposure-consequence-risk-and-exception-ledger",
            "migration-roadmap-milestone-parity-performance-and-reassessment-evidence",
        ],
        "isolation": "no-egress disposable native-code builders and runners with digest-pinned toolchains dependencies and release flags, synthetic inputs, sanitizer and fuzz resource limits, crash quarantine, no production secrets, per-case reset, and signed artifact destruction receipt",
    },
    {
        "benchmark_id": "ieee-ai-governance-wellbeing-assessment",
        "protocol": "assessor-agreement",
        "upstream": "https://standards.ieee.org/ieee/2863/10142/ and https://standards.ieee.org/ieee/7010/7718/",
        "acquisition": {
            **_COMMON,
            "license": "licensed-IEEE-criteria-and-stakeholder-scenario-specific",
        },
        "normalizer": "ai-governance-wellbeing-impact-assessor-agreement-v1",
        "required_inputs": [
            "licensed-2863-and-7010-criteria-map",
            "ai-system-governance-authority-role-and-lifecycle-boundary",
            "stakeholder-domain-indicator-baseline-and-impact-evidence",
            "blinded-tradeoff-harm-gaming-monitoring-appeal-and-retirement-cases",
            "reviewer-qualification-independence-golden-decisions-and-adjudication-policy",
        ],
        "isolation": "blinded human-impact assessment workspace with synthetic or consented minimized stakeholder data, separated answer keys, protected vulnerable-population strata, immutable submissions, independent adjudication, and no automated production decision changes",
    },
    {
        "benchmark_id": "organizational-resilience-bia-exercise",
        "protocol": "conformance",
        "upstream": "https://www.iso.org/standard/50053.html and https://www.iso.org/standard/79000.html",
        "acquisition": {
            **_COMMON,
            "license": "licensed-ISO-resilience-BIA-and-organization-exercise-specific",
        },
        "normalizer": "resilience-bia-dependency-impact-recovery-reassessment-v1",
        "required_inputs": [
            "licensed-22316-and-22317-criteria-map",
            "product-service-activity-resource-and-dependency-model",
            "impact-category-time-profile-tolerance-rto-rpo-and-capacity-oracles",
            "disruption-degradation-failover-restoration-and-reconciliation-cases",
            "safety-blast-radius-authorization-observation-and-improvement-ledger",
        ],
        "isolation": "authorized disposable service twin or bounded exercise environment with synthetic data and dependencies, explicit blast radius, observer and operator separation, communication controls, kill switches, restoration validation, cleanup, and no unapproved production disruption",
    },
    {
        "benchmark_id": "openssf-best-practices-badge-conformance",
        "protocol": "conformance",
        "upstream": "https://openssf.org/projects/best-practices-badge/",
        "acquisition": {
            **_COMMON,
            "license": "OpenSSF-criteria-project-response-and-repository-specific",
        },
        "normalizer": "openssf-criterion-answer-evidence-level-conformance-v1",
        "required_inputs": [
            "baseline-and-metal-criteria-revision",
            "project-identity-and-bestpractices-response-export",
            "immutable-repository-release-test-and-security-evidence-snapshot",
            "criterion-applicability-answer-source-and-freshness-map",
            "stale-link-disabled-control-inflated-level-and-identity-negative-cases",
        ],
        "isolation": "read-only project and repository assessment workspace with immutable public or authorized snapshots, no credential-bearing links, synthetic negative mutations, independent sampled review, and no automatic badge or upstream project modification",
    },
    {
        "benchmark_id": "isms-implementation-process-assessment",
        "protocol": "assessor-agreement",
        "upstream": "https://www.iso.org/standard/63417.html and https://www.iso.org/standard/61004.html",
        "acquisition": {
            **_COMMON,
            "license": "licensed-ISO-ISMS-guidance-process-model-and-case-specific",
        },
        "normalizer": "isms-implementation-process-capability-assessor-agreement-v1",
        "required_inputs": [
            "licensed-27003-and-27022-criteria-map",
            "isms-scope-process-interface-control-measure-and-record-map",
            "implementation-tailoring-capability-and-improvement-evidence",
            "blinded-scope-risk-measure-control-audit-and-corrective-action-cases",
            "assessor-qualification-independence-golden-decisions-and-adjudication-policy",
        ],
        "isolation": "blinded ISMS assessment workspace with licensed criteria access controls, minimized organization records, separated answer keys, conflict-of-interest controls, immutable submissions, independent adjudication, and no certification claim",
    },
    {
        "benchmark_id": "a2a-protocol-security-conformance",
        "protocol": "conformance",
        "upstream": "https://a2a-protocol.org/latest/specification/",
        "acquisition": {
            **_COMMON,
            "license": "A2A-specification-TCK-SDK-and-fixture-specific",
        },
        "normalizer": "a2a-card-binding-auth-task-artifact-security-conformance-v1",
        "required_inputs": [
            "a2a-1.0.0-proto-specification-tck-and-sdk-lock",
            "agent-card-jws-provider-endpoint-version-binding-and-tenant-oracles",
            "principal-skill-task-message-artifact-and-subscription-authorization-policy",
            "http-json-jsonrpc-grpc-stream-and-webhook-interoperability-matrix",
            "malformed-downgrade-cross-tenant-credential-ssrf-replay-race-and-cleanup-cases",
        ],
        "isolation": "no-egress disposable A2A laboratory with synthetic agents tenants identities OAuth issuers credentials tasks messages artifacts skills streams and webhooks, loopback or target-only bindings, deny-by-default delegated authority, callback sinkhole, bounded parts messages steps time and spend, per-case reset, kill switch, and signed cleanup destruction receipt",
    },
    {
        "benchmark_id": "sesip-iot-platform-evaluation-conformance",
        "protocol": "conformance",
        "upstream": "https://globalplatform.org/specs-library/sesip-methodology/",
        "acquisition": {
            **_COMMON,
            "license": "GlobalPlatform-SESIP-EN17927-profile-certificate-and-laboratory-specific",
        },
        "normalizer": "sesip-toe-sfr-spp-sar-composition-certificate-conformance-v1",
        "required_inputs": [
            "sesip-1.2-en17927-licensed-criteria-profile-and-mapping-digests",
            "toe-platform-part-product-version-configuration-and-asset-boundary",
            "sfr-spp-sar-assurance-level-threat-and-operational-environment-map",
            "component-composition-certificate-vulnerability-change-and-expiry-ledger",
            "scheme-certification-body-laboratory-evaluator-authority-and-negative-claim-cases",
        ],
        "isolation": "separated IoT evaluation laboratory with licensed criteria access controls, representative non-production hardware or emulators, synthetic secrets and identities, calibrated tools, fault and penetration authorization, immutable evaluator observations, certificate-status snapshots, independent adjudication, destructive-test containment, and no suite-issued certification claim",
    },
    {
        "benchmark_id": "first-tlp-iep-information-handling-conformance",
        "protocol": "conformance",
        "upstream": "https://www.first.org/tlp/ and https://www.first.org/iep/",
        "acquisition": {
            **_COMMON,
            "license": "FIRST-TLP-IEP-standard-policy-and-fixture-specific",
        },
        "normalizer": "tlp-label-iep-policy-use-redistribution-roundtrip-v1",
        "required_inputs": [
            "first-tlp-2.0-iep-2.0-framework-json-and-standard-policy-lock",
            "label-recipient-community-action-attribution-storage-and-redistribution-oracles",
            "stix-taxii-json-embed-reference-display-export-and-roundtrip-matrix",
            "policy-reference-cache-immutability-overlap-date-and-unknown-policy-cases",
            "deprecated-label-downgrade-removal-unauthorized-sharing-and-audit-negative-cases",
        ],
        "isolation": "no-egress disposable information-exchange laboratory with synthetic producers recipients communities intelligence and policies, approved immutable policy snapshots, recipient-specific views, transport and storage encryption, disclosure sinkholes, minimized content, per-case reset, immutable audit, and no delivery to real external recipients",
    },
    {
        "benchmark_id": "veris-incident-schema-conformance",
        "protocol": "conformance",
        "upstream": "https://verisframework.org/",
        "acquisition": {
            **_COMMON,
            "license": "VERIS-schema-vocabulary-example-and-organization-incident-specific",
        },
        "normalizer": "veris-schema-vocabulary-provenance-analytic-equivalence-v1",
        "required_inputs": [
            "veris-1.3.6-schema-vocabulary-and-example-lock",
            "organization-approved-deidentified-incident-and-golden-classification-set",
            "actor-action-asset-attribute-timeline-impact-and-unknown-value-oracles",
            "parse-normalize-roundtrip-aggregate-and-deidentification-invariants",
            "malformed-enumeration-cardinality-date-identity-sensitive-data-and-truth-claim-cases",
        ],
        "isolation": "no-egress read-only incident-classification workspace with deidentified or synthetic records, schema and vocabulary snapshots, protected golden labels, field-level minimization, deterministic export, aggregate disclosure controls, independent sample review, and no claim that schema validity proves incident facts",
    },
    {
        "benchmark_id": "w3c-web-platform-defense-conformance",
        "protocol": "conformance",
        "upstream": "https://www.w3.org/TR/CSP2/ and https://www.w3.org/TR/2016/REC-SRI-20160623/",
        "acquisition": {
            **_COMMON,
            "license": "W3C-specification-WPT-browser-and-application-fixture-specific",
        },
        "normalizer": "csp2-sri1-browser-policy-block-report-integrity-v1",
        "required_inputs": [
            "w3c-csp2-sri1-recommendation-and-web-platform-test-revision-lock",
            "browser-engine-version-policy-header-resource-and-origin-manifest",
            "nonce-hash-source-frame-form-base-connect-report-and-integrity-oracles",
            "positive-negative-redirect-cors-cdn-substitution-and-multi-policy-cases",
            "observed-browser-block-report-fallback-recovery-and-cross-engine-results",
        ],
        "isolation": "no-egress disposable browser laboratory with synthetic origins certificates CDN resources collectors and content, loopback-only services, digest-pinned browsers and Web Platform Tests, no third-party scripts or reports, bounded navigation and storage, per-case profile reset, and signed cleanup receipt",
    },
    {
        "benchmark_id": "dora-level2-technical-standards-conformance",
        "protocol": "conformance",
        "upstream": "https://www.eba.europa.eu/activities/direct-supervision-and-oversight/digital-operational-resilience-act",
        "acquisition": {
            **_COMMON,
            "license": "EU-legal-act-regulatory-guidance-organization-and-exercise-specific",
        },
        "normalizer": "dora-risk-incident-register-report-tlpt-conformance-v1",
        "required_inputs": [
            "eu-1772-1774-2956-301-302-1190-consolidated-act-digests",
            "entity-applicability-ict-risk-control-critical-function-and-dependency-map",
            "incident-classification-awareness-timeline-template-and-secure-channel-oracles",
            "entity-group-provider-contract-function-location-and-register-template-set",
            "tlpt-scope-tester-intelligence-safety-finding-remediation-closure-and-negative-cases",
        ],
        "isolation": "legally reviewed financial-resilience assessment workspace with synthetic entity provider contract incident report and register records plus a separately authorized disposable TLPT service twin, qualified tester and control-team separation, production kill switches and rollback where applicable, protected threat intelligence, data minimization, immutable chronology, supervisory fields withheld from real channels, and signed cleanup receipt",
    },
    {
        "benchmark_id": "ffiec-it-handbook-assessment",
        "protocol": "assessor-agreement",
        "upstream": "https://ithandbook.ffiec.gov/it-booklets/",
        "acquisition": {
            **_COMMON,
            "license": "United-States-government-handbook-and-organization-case-specific",
        },
        "normalizer": "ffiec-dam-aio-information-security-examiner-agreement-v1",
        "required_inputs": [
            "ffiec-dam-2024-aio-2021-information-security-2016-edition-lock",
            "institution-service-provider-scope-risk-and-applicability-record",
            "development-acquisition-maintenance-architecture-infrastructure-operations-evidence",
            "security-governance-risk-operations-incident-assurance-and-outcome-cases",
            "blinded-examiners-golden-decisions-competence-conflict-and-adjudication-policy",
        ],
        "isolation": "blinded financial-technology examination workspace with synthetic institutions services acquisitions infrastructure incidents and third parties, minimized supervisory and customer data, separated answer keys, examiner independence and conflict controls, immutable submissions, independent adjudication, no production changes, and explicit exclusion of the retired FFIEC CAT",
    },
    {
        "benchmark_id": "bsi-c5-cloud-assurance-assessment",
        "protocol": "assessor-agreement",
        "upstream": "https://www.bsi.bund.de/dok/C5",
        "acquisition": {
            **_COMMON,
            "license": "BSI-C5-licensed-criteria-attestation-report-and-service-specific",
        },
        "normalizer": "c5-service-control-audit-customer-responsibility-agreement-v1",
        "required_inputs": [
            "bsi-c5-2020-licensed-criteria-and-evaluation-guidance-digests",
            "cloud-service-boundary-location-architecture-subservice-and-description-map",
            "control-design-operation-customer-control-deviation-and-incident-evidence",
            "assurance-standard-practitioner-period-sample-opinion-and-report-validity-cases",
            "blinded-assessors-golden-decisions-independence-conflict-and-adjudication-policy",
        ],
        "isolation": "blinded cloud-assurance report workspace with licensed criteria access controls, synthetic or minimized service and customer evidence, separated answer keys, practitioner independence checks, immutable submissions, independent adjudication, no provider mutation, and explicit distinction between C5 attestation and BSI certification",
    },
    {
        "benchmark_id": "fcc-cyber-trust-mark-conformance",
        "protocol": "conformance",
        "upstream": "https://docs.fcc.gov/public/attachments/FCC-24-26A1.pdf",
        "acquisition": {
            **_COMMON,
            "license": "United-States-government-rule-program-baseline-laboratory-and-product-specific",
        },
        "normalizer": "fcc-iot-baseline-lab-application-label-registry-conformance-v1",
        "required_inputs": [
            "fcc-24-26-approved-baseline-test-procedure-and-program-revision-lock",
            "iot-product-component-interface-software-support-and-configuration-boundary",
            "recognized-laboratory-test-report-remediation-and-renewal-evidence",
            "applicant-label-administrator-authorization-qr-registry-and-consumer-information-map",
            "firmware-substitution-forgery-copied-label-redirect-expiry-withdrawal-and-overclaim-cases",
        ],
        "isolation": "separated consumer-IoT conformance laboratory with representative non-production devices or emulators, synthetic accounts networks updates QR endpoints and registry, recognized-laboratory authority snapshots, destructive-test authorization and containment, no real label application or registry publication, misuse sinkholes, cleanup, and no suite-issued mark authorization",
    },
    {
        "benchmark_id": "openid-digital-credential-conformance",
        "protocol": "conformance",
        "upstream": "https://openid.net/certification/ and https://www.w3.org/TR/vc-data-model-2.0/",
        "acquisition": {
            **_COMMON,
            "license": "W3C-OpenID-specification-suite-and-fixture-specific",
        },
        "normalizer": "vc-issuer-wallet-verifier-openid-haip-conformance-v1",
        "required_inputs": [
            "vc-data-model-data-integrity-status-openid-and-haip-release-lock",
            "synthetic-issuer-wallet-verifier-and-trust-policy-fixtures",
            "credential-format-cryptosuite-disclosure-status-and-binding-oracles",
            "issuance-presentation-cross-device-and-wallet-interoperability-cases",
            "malformed-replay-downgrade-confusion-correlation-and-revocation-cases",
        ],
        "isolation": "no-egress disposable issuer-wallet-verifier laboratory with synthetic people organizations credentials identifiers keys and status lists, test trust roots, bounded redirects, callback sinkholes, per-case reset, signed destruction receipt, and no real wallet enrollment or certification claim",
    },
    {
        "benchmark_id": "cisa-scuba-saas-posture-conformance",
        "protocol": "conformance",
        "upstream": "https://github.com/cisagov/ScubaGear and https://www.cisa.gov/resources-tools/services/secure-cloud-business-applications-scuba-project",
        "acquisition": {
            **_COMMON,
            "license": "CISA-government-code-baseline-and-authorized-tenant-specific",
        },
        "normalizer": "scuba-m365-gws-baseline-posture-conformance-v1",
        "required_inputs": [
            "scubagear-and-m365-gws-baseline-policy-snapshot",
            "authorized-tenant-service-license-and-api-coverage-inventory",
            "short-lived-read-only-identity-and-permission-manifest",
            "posture-result-exception-owner-expiry-and-remediation-oracles",
            "drift-unassessed-resource-regression-and-cleanup-cases",
        ],
        "isolation": "read-only least-privilege tenant assessment with short-lived workload identity, explicit API allowlist, identifier minimization, encrypted evidence, no production configuration mutation, access revocation, local cleanup, and auditable deletion receipt",
    },
    {
        "benchmark_id": "cis-kubernetes-hardening-conformance",
        "protocol": "conformance",
        "upstream": "https://www.cisecurity.org/benchmark/kubernetes",
        "acquisition": {
            **_COMMON,
            "license": "licensed-CIS-benchmark-tool-cluster-and-evidence-specific",
        },
        "normalizer": "cis-kubernetes-2.0.1-control-evidence-conformance-v1",
        "required_inputs": [
            "licensed-cis-kubernetes-2.0.1-criteria-and-tool-lock",
            "cluster-version-role-control-plane-node-and-workload-inventory",
            "automated-manual-check-applicability-and-evidence-map",
            "rbac-admission-network-secret-audit-and-runtime-negative-cases",
            "exception-remediation-rescan-drift-and-review-record",
        ],
        "isolation": "disposable representative clusters for active checks and immutable read-only production snapshots for observation, synthetic workloads and secrets, no automated production remediation, bounded credentials, cleanup validation, and no CIS certification claim",
    },
    {
        "benchmark_id": "linddun-privacy-threat-model-conformance",
        "protocol": "assessor-agreement",
        "upstream": "https://linddun.org/",
        "acquisition": {
            **_COMMON,
            "license": "LINDDUN-PRO-methodology-template-and-case-specific",
        },
        "normalizer": "linddun-dfd-threat-mitigation-assessor-agreement-v1",
        "required_inputs": [
            "linddun-pro-methodology-taxonomy-and-template-lock",
            "synthetic-or-deidentified-data-flow-and-purpose-models",
            "protected-threat-tree-misuse-case-and-mitigation-golden-labels",
            "omission-mutation-linkability-disclosure-and-noncompliance-cases",
            "blinded-assessor-competence-independence-and-adjudication-policy",
        ],
        "isolation": "blinded privacy-model assessment workspace with synthetic or deidentified flows, minimized data-subject context, protected answer keys, immutable submissions, independent adjudication, controlled licensed-material access, and no production data processing changes",
    },
    {
        "benchmark_id": "owasp-benchmark-ast-modality-comparison",
        "protocol": "classification",
        "upstream": "https://owasp.org/www-project-benchmark/",
        "acquisition": {
            **_COMMON,
            "license": "OWASP-benchmark-and-tool-license-specific",
        },
        "normalizer": "owasp-benchmark-matched-sast-dast-iast-classification-v1",
        "required_inputs": [
            "owasp-benchmark-release-label-and-category-lock",
            "matched-sast-dast-iast-tool-version-and-configuration-manifest",
            "identical-target-build-route-request-and-reset-fixtures",
            "per-modality-finding-identity-location-and-ground-truth-mapping",
            "modality-overlap-latency-resource-and-unsupported-capability-results",
        ],
        "isolation": "separate no-egress static runner and disposable target-bound dynamic and instrumented runners with identical corpus builds, synthetic traffic, deterministic reset, per-modality identities and scorecards, no union score, and explicit exclusion of RASP prevention claims",
    },
    {
        "benchmark_id": "rasp-prevention-effectiveness",
        "protocol": "detection-evaluation",
        "upstream": "https://owasp.org/www-community/controls/Runtime_Application_Self-Protection",
        "acquisition": {
            **_COMMON,
            "license": "OWASP-guidance-product-agent-and-fixture-specific",
        },
        "normalizer": "rasp-attack-block-observe-bypass-effectiveness-v1",
        "required_inputs": [
            "rasp-agent-policy-runtime-and-application-fixture-lock",
            "attack-technique-route-data-flow-and-protection-coverage-map",
            "blocked-observed-bypassed-false-positive-and-latency-oracles",
            "instrumentation-health-tamper-bypass-fail-open-and-fail-closed-cases",
            "step-time-resource-kill-switch-reset-and-cleanup-policy",
        ],
        "isolation": "no-egress disposable instrumented application with synthetic accounts data and traffic, target-only attack bindings, bounded requests and resources, continuous agent-health observation, independent kill switch, per-case reset, signed cleanup receipt, and no production attack execution",
    },
    {
        "benchmark_id": "gsma-nesas-scas-assurance",
        "protocol": "conformance",
        "upstream": "https://www.gsma.com/solutions-and-impact/technologies/security/network-equipment-security-assurance-scheme/",
        "acquisition": {
            **_COMMON,
            "license": "GSMA-NESAS-3GPP-SCAS-vendor-laboratory-and-product-specific",
        },
        "normalizer": "nesas-development-process-scas-product-assurance-v1",
        "required_inputs": [
            "nesas-3.0-scas-release-and-applicability-lock",
            "vendor-development-process-and-network-product-boundary",
            "authorized-laboratory-evaluator-method-tool-and-competence-record",
            "functional-robustness-penetration-vulnerability-and-retest-cases",
            "product-version-configuration-change-and-vulnerability-ledger",
        ],
        "isolation": "authorized ISO-IEC-17025-aligned telecommunications laboratory with representative non-production equipment, segmented test networks, synthetic subscribers credentials and traffic, calibrated tools, destructive-test containment, immutable observations, cleanup, and explicit recognition that NESAS is an assurance scheme rather than suite-issued certification",
    },
    {
        "benchmark_id": "tisax-vda-isa-assessment",
        "protocol": "assessor-agreement",
        "upstream": "https://enx.com/en-us/TISAX/downloads/",
        "acquisition": {
            **_COMMON,
            "license": "licensed-VDA-ISA-TISAX-handbook-participant-and-provider-specific",
        },
        "normalizer": "tisax-vda-isa-scope-maturity-assessor-agreement-v1",
        "required_inputs": [
            "licensed-vda-isa-6.0.3-and-tisax-handbook-lock",
            "scope-location-objective-protection-need-and-applicability-map",
            "control-maturity-evidence-finding-and-corrective-action-cases",
            "result-sharing-provider-independence-conflict-and-expiry-policy",
            "blinded-assessor-golden-decisions-competence-and-adjudication-record",
        ],
        "isolation": "blinded automotive assurance workspace with licensed criteria access controls, minimized participant evidence, separated answer keys, assessment-provider independence and conflict checks, immutable submissions, independent adjudication, no ENX portal mutation, and no suite-issued TISAX label",
    },
    {
        "benchmark_id": "c2pa-content-credentials-conformance",
        "protocol": "conformance",
        "upstream": "https://spec.c2pa.org/specifications/",
        "acquisition": {
            **_COMMON,
            "license": "C2PA-specification-test-asset-SDK-and-trust-list-specific",
        },
        "normalizer": "c2pa-manifest-claim-assertion-signature-validation-v1",
        "required_inputs": [
            "c2pa-2.4-specification-schema-test-and-sdk-lock",
            "synthetic-media-manifest-ingredient-claim-assertion-and-signature-fixtures",
            "test-trust-root-certificate-status-revocation-and-time-policy",
            "create-read-validate-roundtrip-edit-redaction-and-recovery-cases",
            "tamper-unknown-signer-replay-misbinding-parser-and-resource-limit-cases",
        ],
        "isolation": "no-egress content-provenance laboratory with inert synthetic media, test identities certificates keys trust roots and timestamps, parser resource limits, no biometric or real creator identity, per-case reset, key destruction, and explicit separation of provenance validity from content truth",
    },
    {
        "benchmark_id": "pci-payment-acceptance-conformance",
        "protocol": "conformance",
        "upstream": "https://www.pcisecuritystandards.org/standards/mobile-payments-on-cots-mpoc/ and https://www.pcisecuritystandards.org/standards/point-to-point-encryption-p2pe/",
        "acquisition": {
            **_COMMON,
            "license": "licensed-PCI-MPoC-P2PE-program-laboratory-and-solution-specific",
        },
        "normalizer": "pci-mpoc-p2pe-component-flow-laboratory-conformance-v1",
        "required_inputs": [
            "licensed-mpoc-p2pe-requirement-and-test-procedure-lock",
            "solution-component-payment-flow-account-data-key-and-scope-map",
            "authorized-laboratory-evaluator-device-app-backend-and-hsm-fixtures",
            "tamper-overlay-debug-rooting-key-substitution-decryption-and-update-cases",
            "synthetic-account-data-test-key-cleanup-and-adjudication-policy",
        ],
        "isolation": "authorized payment security laboratory with representative non-production devices applications backends and HSM partitions, synthetic account and transaction data only, test keys, no PAN or live payment networks, destructive-test containment, key and data destruction receipts, and no suite-issued PCI listing or validation claim",
    },
    {
        "benchmark_id": "oidf-fapi-conformance",
        "protocol": "conformance",
        "upstream": "https://openid.net/certification/",
        "acquisition": {
            **_COMMON,
            "license": "OpenID-official-conformance-suite-specification-and-fixture-specific",
        },
        "normalizer": "fapi-2-final-attacker-model-message-signing-conformance-v1",
        "required_inputs": [
            "fapi-2.0-final-attacker-model-message-signing-and-suite-lock",
            "synthetic-authorization-server-client-resource-server-and-key-fixtures",
            "par-jarm-dpop-mtls-token-issuer-audience-and-replay-oracles",
            "downgrade-confusion-key-substitution-ssrf-misbinding-and-expiry-cases",
            "test-certificate-trust-root-callback-cleanup-and-report-policy",
        ],
        "isolation": "no-egress disposable authorization-server client and resource-server laboratory with synthetic identities accounts consent tokens certificates and keys, loopback or target-only callbacks, test trust roots, bounded requests, per-case reset, signed key destruction receipt, and no OpenID certification claim",
    },
)


def _adapter_contract(
    benchmark_id: str,
    protocol: str,
    upstream: str,
    license_name: str,
    normalizer: str,
    required_inputs: tuple[str, ...],
    isolation: str,
) -> dict[str, Any]:
    return {
        "benchmark_id": benchmark_id,
        "protocol": protocol,
        "upstream": upstream,
        "acquisition": {**_COMMON, "license": license_name},
        "normalizer": normalizer,
        "required_inputs": list(required_inputs),
        "isolation": isolation,
    }


BUILTIN_ADAPTER_SPECS += (
    _adapter_contract(
        "fedramp-20x-continuous-validation",
        "conformance",
        "https://www.fedramp.gov/20x",
        "FedRAMP-public-rules-evidence-and-assessor-specific",
        "fedramp-20x-class-ksi-continuous-validation-v1",
        (
            "fedramp-20x-class-rule-ksi-and-validation-code-lock",
            "cloud-service-offering-boundary-goal-measure-and-owner-map",
            "independent-validation-and-continuous-monitoring-fixtures",
            "stale-evidence-boundary-drift-and-measure-gaming-cases",
            "marketplace-status-agency-decision-and-claim-boundary-policy",
        ),
        "authorized isolated cloud-service evidence workspace with read-only telemetry, synthetic failures, independent validation, immutable package snapshots, and no FedRAMP certification or agency authorization claim",
    ),
    _adapter_contract(
        "fido2-authenticator-conformance",
        "conformance",
        "https://fidoalliance.org/specifications/download/",
        "FIDO-specification-suite-metadata-and-device-specific",
        "fido-ctap22-webauthn-mds31-conformance-v1",
        (
            "ctap-2.2-webauthn-mds-and-functional-suite-lock",
            "client-authenticator-rp-origin-credential-transport-and-aaguid-map",
            "test-authenticator-client-rp-roots-keys-and-metadata-fixtures",
            "malformed-cbor-downgrade-replay-revocation-and-recovery-cases",
            "functional-report-certification-status-and-claim-boundary-policy",
        ),
        "no-egress FIDO laboratory with test authenticators relying parties identities roots and credentials, transport containment, per-case reset, key destruction, and no FIDO certification claim",
    ),
    _adapter_contract(
        "eudi-wallet-functional-conformance",
        "conformance",
        "https://github.com/eu-digital-identity-wallet/eudi-doc-architecture-and-reference-framework",
        "EU-public-acts-ARF-FCAF-and-member-state-specific",
        "eudi-arf3-fcaf-wallet-functional-conformance-v1",
        (
            "eudi-acts-arf-3.0.0-fcaf-and-reference-fixture-lock",
            "wallet-unit-provider-issuer-rp-trust-list-pid-and-eaa-boundary",
            "synthetic-wallet-issuer-rp-identity-key-and-trust-fixtures",
            "over-request-replay-downgrade-registration-recovery-and-privacy-cases",
            "member-state-certification-legal-status-and-claim-boundary-policy",
        ),
        "no-egress cross-wallet laboratory using synthetic persons credentials issuers relying parties keys and trust lists, minimized logs, deterministic cleanup, and no legal conformity or certification claim",
    ),
    _adapter_contract(
        "hitrust-csf-assessment",
        "assessor-agreement",
        "https://hitrustalliance.net/csf",
        "licensed-HITRUST-CSF-assurance-program-and-case-specific",
        "hitrust-csf118-e1-i1-r2-assessor-agreement-v1",
        (
            "licensed-hitrust-csf-11.8.0-and-assurance-program-lock",
            "assessment-type-scope-factor-requirement-and-inheritance-map",
            "blinded-e1-i1-r2-cases-golden-decisions-and-scoring-policy",
            "scope-drift-stale-evidence-maturity-inflation-and-conflict-cases",
            "assessor-competence-independence-adjudication-and-claim-policy",
        ),
        "blinded licensed assessment workspace with separated answer keys, qualified independent reviewers, immutable submissions, adjudication, restricted evidence, and no suite-issued HITRUST certification",
    ),
    _adapter_contract(
        "pci-secure-software-conformance",
        "conformance",
        "https://www.pcisecuritystandards.org/standards/software-security-framework/",
        "licensed-PCI-SSF-program-assessor-product-and-laboratory-specific",
        "pci-secure-software20-secure-slc11-conformance-v1",
        (
            "licensed-pci-secure-software-2.0-secure-slc-1.1-and-program-lock",
            "product-sdk-module-sensitive-asset-lifecycle-and-listing-boundary",
            "authorized-assessor-product-platform-and-synthetic-payment-fixtures",
            "scope-omission-change-tier-api-component-and-stale-listing-cases",
            "assessment-report-annual-attestation-cleanup-and-claim-policy",
        ),
        "authorized payment software laboratory with synthetic account and transaction data, test keys, representative non-production platforms, destructive-test containment, cleanup receipts, and no PCI listing or validation claim",
    ),
    _adapter_contract(
        "nis2-implementing-regulation-conformance",
        "conformance",
        "https://www.enisa.europa.eu/publications/nis2-technical-implementation-guidance",
        "EU-law-ENISA-guidance-member-state-and-entity-specific",
        "nis2-2024-2690-control-incident-conformance-v1",
        (
            "nis2-implementing-regulation-2024-2690-and-enisa-guidance-lock",
            "entity-service-sector-member-state-measure-and-evidence-map",
            "representative-control-effectiveness-incident-and-supplier-fixtures",
            "applicability-asset-continuity-threshold-timing-and-exception-cases",
            "legal-guidance-notification-authority-and-claim-boundary-policy",
        ),
        "authorized exercise environment with synthetic incidents suppliers and notifications, read-only production evidence, bounded disruption, restoration proof, and no transmission to a competent authority",
    ),
    _adapter_contract(
        "nist-supplier-due-diligence",
        "assessor-agreement",
        "https://csrc.nist.gov/Projects/cyber-supply-chain-risk-management/publications",
        "NIST-publication-source-data-and-supplier-specific",
        "nist-sp1326-supplier-due-diligence-agreement-v1",
        (
            "nist-sp-1326-and-csrm-source-snapshot-lock",
            "supplier-product-ownership-provenance-dependency-and-source-map",
            "blinded-cases-golden-risk-decisions-and-contract-conditions",
            "alias-ownership-staleness-conflict-concentration-and-deception-cases",
            "confidence-gap-reassessment-adjudication-and-claim-policy",
        ),
        "blinded due-diligence workspace using immutable authoritative-source snapshots, protected identities where required, independent adjudication, no procurement mutation, and no assurance inferred from absent adverse data",
    ),
    _adapter_contract(
        "owasp-samm-assessment-benchmark",
        "assessor-agreement",
        "https://owaspsamm.org/assessment/",
        "CC-BY-SA-4.0-and-assessment-dataset-specific",
        "owasp-samm21-assessor-cohort-benchmark-v1",
        (
            "owasp-samm-2.1.0-model-toolbox-and-dataset-lock",
            "organization-scope-practice-activity-quality-criteria-and-evidence-map",
            "blinded-cases-golden-levels-roadmaps-and-reassessment-policy",
            "partial-criteria-stale-evidence-scope-drift-and-inflation-cases",
            "cohort-size-strata-privacy-representativeness-and-claim-policy",
        ),
        "blinded maturity-assessment workspace with protected answer keys and submissions, independent adjudication, k-anonymous cohort reporting, explicit small-sample limits, and no certification claim",
    ),
    _adapter_contract(
        "owasp-benchmark",
        "classification",
        "https://owasp.org/www-project-benchmark/",
        "GNU-GPL-2.0-and-tool-specific",
        "owasp-benchmark-ground-truth-classification-v1",
        (
            "release-and-label-lock",
            "tool-and-rule-configuration",
            "target-build-and-route-map",
            "finding-to-test-case-map",
            "negative-control-and-score-policy",
        ),
        "no-egress static runner or disposable target-bound dynamic runner with synthetic traffic, deterministic reset, and modality-specific results",
    ),
    _adapter_contract(
        "nist-sard-juliet",
        "classification",
        "https://samate.nist.gov/SARD/",
        "NIST-SARD-corpus-and-toolchain-specific",
        "juliet-cwe-good-bad-classification-v1",
        (
            "suite-release-and-manifest",
            "cwe-label-authority",
            "compiler-and-runtime-lock",
            "good-bad-variant-map",
            "unsupported-case-policy",
        ),
        "no-egress digest-pinned build and analysis workers with inert fixtures, bounded resources, and per-language result separation",
    ),
    _adapter_contract(
        "nist-acvp-cryptography",
        "conformance",
        "https://pages.nist.gov/ACVP/",
        "NIST-ACVP-specification-server-and-implementation-specific",
        "nist-acvp-vector-response-conformance-v1",
        (
            "acvp-spec-and-vector-set-lock",
            "algorithm-capability-registration",
            "implementation-and-platform-identity",
            "expected-response-and-verdict-map",
            "session-and-certificate-claim-policy",
        ),
        "isolated cryptographic test worker using test keys and vectors, bounded sessions, no production key material, and no validation certificate claim",
    ),
    _adapter_contract(
        "w3c-wpt-webauthn",
        "conformance",
        "https://github.com/web-platform-tests/wpt",
        "W3C-WPT-and-browser-license-specific",
        "wpt-webauthn-browser-conformance-v1",
        (
            "wpt-revision-and-manifest",
            "browser-driver-platform-lock",
            "virtual-authenticator-fixtures",
            "expected-test-outcomes",
            "flakiness-retry-and-unsupported-policy",
        ),
        "no-egress digest-pinned browsers with virtual test authenticators, synthetic origins and credentials, deterministic profiles, and per-run cleanup",
    ),
    _adapter_contract(
        "disa-stig-scap-conformance",
        "conformance",
        "https://public.cyber.mil/stigs/scap/",
        "DISA-STIG-SCAP-content-and-platform-specific",
        "disa-stig-scap-xccdf-oval-conformance-v1",
        (
            "stig-scap-release-and-signature",
            "profile-platform-cpe-map",
            "xccdf-oval-engine-lock",
            "automated-manual-check-evidence",
            "exception-remediation-and-rescan-policy",
        ),
        "approved assessor host or disposable representative target with read-only production snapshots, bounded credentials, and no automatic remediation",
    ),
    _adapter_contract(
        "sigstore-client-conformance",
        "conformance",
        "https://github.com/sigstore/sigstore-conformance",
        "Apache-2.0-and-service-fixture-specific",
        "sigstore-client-trust-root-conformance-v1",
        (
            "suite-and-trust-root-lock",
            "client-version-capability-map",
            "test-identity-certificate-and-log-fixtures",
            "positive-negative-verification-cases",
            "offline-online-replay-and-cleanup-policy",
        ),
        "isolated conformance environment with test Fulcio Rekor identities and roots, no production signing credentials, bounded network endpoints, and key cleanup",
    ),
    _adapter_contract(
        "slsa-verifier-conformance",
        "conformance",
        "https://github.com/slsa-framework/slsa-verifier",
        "Apache-2.0-and-provenance-fixture-specific",
        "slsa-verifier-provenance-policy-conformance-v1",
        (
            "verifier-and-slsa-version-lock",
            "artifact-provenance-fixtures",
            "builder-source-workflow-policy",
            "tamper-replay-misbinding-cases",
            "expected-verdict-and-claim-policy",
        ),
        "no-egress verifier worker with synthetic artifacts identities and provenance, test roots, immutable fixtures, and no production release authorization",
    ),
    _adapter_contract(
        "sv-comp",
        "verification-competition",
        "https://sv-comp.sosy-lab.org/",
        "SV-COMP-benchmark-definition-and-tool-specific",
        "sv-comp-witness-score-normalization-v1",
        (
            "competition-year-and-task-lock",
            "benchmark-and-property-manifest",
            "tool-container-and-configuration",
            "witness-validator-and-oracles",
            "resource-scoring-and-disqualification-policy",
        ),
        "no-egress resource-metered verification workers with digest-pinned images, validated witnesses, deterministic limits, and separated tasks",
    ),
    _adapter_contract(
        "test-comp",
        "test-generation",
        "https://test-comp.sosy-lab.org/",
        "Test-Comp-benchmark-definition-and-tool-specific",
        "test-comp-coverage-validation-score-v1",
        (
            "competition-year-and-task-lock",
            "benchmark-property-and-harness-manifest",
            "tool-container-and-configuration",
            "generated-test-validator",
            "coverage-resource-and-disqualification-policy",
        ),
        "no-egress resource-metered test-generation workers with digest-pinned images, sandboxed generated tests, deterministic limits, and validator isolation",
    ),
    _adapter_contract(
        "mitre-attack-evaluations",
        "detection-evaluation",
        "https://attackevals.mitre-engenuity.org/",
        "MITRE-ATTACK-evaluation-and-product-data-specific",
        "mitre-attack-evaluation-technique-detection-v1",
        (
            "evaluation-round-and-scenario-lock",
            "technique-substep-and-telemetry-map",
            "product-configuration-and-sensor-boundary",
            "detection-delay-visibility-and-miss-results",
            "vendor-context-and-comparison-policy",
        ),
        "authorized isolated emulation range with synthetic identities and data, target-only traffic, kill switches, restoration plan, and no unsupported product ranking",
    ),
    _adapter_contract(
        "atomic-red-team",
        "detection-evaluation",
        "https://github.com/redcanaryco/atomic-red-team",
        "MIT-and-atomic-dependency-specific",
        "atomic-red-team-technique-detection-v1",
        (
            "atomic-revision-and-test-allowlist",
            "technique-platform-prerequisite-map",
            "sensor-and-detection-oracles",
            "authorization-kill-switch-and-timeout",
            "cleanup-validation-and-residual-risk-policy",
        ),
        "authorized disposable range with harmless fixtures, explicit test allowlist, target binding, bounded privileges, kill switches, and signed cleanup validation",
    ),
    _adapter_contract(
        "defects4j",
        "classification",
        "https://github.com/rjust/defects4j",
        "Defects4J-project-and-dependency-specific",
        "defects4j-bug-fix-localization-v1",
        (
            "corpus-version-and-project-lock",
            "buggy-fixed-commit-map",
            "triggering-and-regression-tests",
            "toolchain-dependency-cache",
            "leakage-split-and-score-policy",
        ),
        "no-egress build workers with quarantined dependency cache, per-project toolchains, time and memory limits, immutable buggy/fixed pairs, and clean reset",
    ),
    _adapter_contract(
        "swe-bench-verified",
        "classification",
        "https://www.swebench.com/",
        "SWE-bench-dataset-repository-and-model-specific",
        "swe-bench-verified-patch-resolution-v1",
        (
            "dataset-release-and-instance-lock",
            "repository-base-commit-and-image",
            "problem-statement-and-test-patch",
            "fail-to-pass-pass-to-pass-oracles",
            "contamination-model-and-score-policy",
        ),
        "no-egress per-instance repository containers with quarantined caches, untrusted patch sandboxing, bounded resources, hidden test separation, and reset",
    ),
    _adapter_contract(
        "vul4j",
        "classification",
        "https://github.com/tuhh-softsec/vul4j",
        "Vul4J-repository-and-dependency-specific",
        "vul4j-vulnerability-fix-detection-v1",
        (
            "dataset-version-and-cve-lock",
            "vulnerable-fixed-commit-map",
            "triggering-test-and-patch-oracles",
            "java-toolchain-dependency-cache",
            "leakage-split-and-score-policy",
        ),
        "no-egress Java build workers with quarantined dependencies, inert exploits, bounded resources, immutable vulnerable/fixed pairs, and clean reset",
    ),
    _adapter_contract(
        "bugsinpy",
        "classification",
        "https://github.com/soarsmu/BugsInPy",
        "BugsInPy-repository-and-dependency-specific",
        "bugsinpy-bug-fix-localization-v1",
        (
            "dataset-version-and-project-lock",
            "buggy-fixed-commit-map",
            "failing-passing-test-oracles",
            "python-toolchain-dependency-cache",
            "leakage-split-and-score-policy",
        ),
        "no-egress Python build workers with quarantined dependencies, per-project environments, bounded resources, immutable buggy/fixed pairs, and clean reset",
    ),
    _adapter_contract(
        "openssf-scorecard",
        "classification",
        "https://github.com/ossf/scorecard",
        "Apache-2.0-provider-API-and-repository-specific",
        "openssf-scorecard-check-evidence-v1",
        (
            "scorecard-release-and-check-lock",
            "repository-commit-and-owner-map",
            "provider-api-snapshot-and-permissions",
            "raw-check-evidence-and-reasons",
            "rate-limit-staleness-and-no-certification-policy",
        ),
        "read-only short-lived repository and provider access with minimized scopes, immutable API snapshots, no repository mutation, and no security certification claim",
    ),
)


def _validate_builtin_adapter_specs(
    specs: tuple[dict[str, Any], ...] | None = None,
) -> None:
    """Reject ambiguous or incomplete maintained adapter contracts at import."""
    specs = BUILTIN_ADAPTER_SPECS if specs is None else specs
    raw_identifiers = [item.get("benchmark_id") for item in specs]
    if any(
        not isinstance(identifier, str) or not identifier
        for identifier in raw_identifiers
    ):
        raise ValueError("maintained adapter catalog contains an invalid identifier")
    identifiers: list[str] = [item["benchmark_id"] for item in specs]
    if len(identifiers) != len(set(identifiers)):
        raise ValueError("maintained adapter catalog contains duplicate identifiers")
    required_acquisition = set(_COMMON)
    for item in specs:
        acquisition = item.get("acquisition")
        inputs = item.get("required_inputs")
        if (
            not isinstance(acquisition, dict)
            or not required_acquisition <= set(acquisition)
            or not acquisition.get("license")
            or any(acquisition[key] is not True for key in required_acquisition)
            or not isinstance(inputs, list)
            or len(inputs) < 4
            or len(inputs) != len(set(inputs))
            or not item.get("protocol")
            or not item.get("upstream")
            or not item.get("normalizer")
            or not item.get("isolation")
        ):
            raise ValueError(
                f"maintained adapter {item.get('benchmark_id')!r} is incomplete"
            )
    from .industry_assurance import _BENCHMARKS, _benchmark_protocol

    registered = {item["id"] for item in _BENCHMARKS}
    unresolved = sorted(set(identifiers) - registered)
    if unresolved:
        raise ValueError(
            "maintained adapters reference unknown benchmarks: " + ", ".join(unresolved)
        )
    mismatched = sorted(
        item["benchmark_id"]
        for item in specs
        if item["protocol"] != _benchmark_protocol(item["benchmark_id"])
    )
    if mismatched:
        raise ValueError(
            "maintained adapters have registry protocol mismatches: "
            + ", ".join(mismatched)
        )


_validate_builtin_adapter_specs()


def benchmark_adapter_specs() -> list[dict[str, Any]]:
    """Return detached copies of the maintained external adapter contracts."""
    return [
        {
            **item,
            "acquisition": dict(item["acquisition"]),
            "required_inputs": list(item["required_inputs"]),
        }
        for item in BUILTIN_ADAPTER_SPECS
    ]


def benchmark_adapter_spec(benchmark_id: str) -> dict[str, Any]:
    """Return one adapter contract or fail closed for an unmaintained identifier."""
    for item in benchmark_adapter_specs():
        if item["benchmark_id"] == benchmark_id:
            return item
    raise ValueError(f"no maintained benchmark adapter specification: {benchmark_id}")


def benchmark_adapter_spec_sha256(benchmark_id: str) -> str:
    """Return the canonical digest used to bind a maintained execution manifest."""
    return hashlib.sha256(
        canonical_bytes(benchmark_adapter_spec(benchmark_id))
    ).hexdigest()


def benchmark_execution_contracts() -> dict[str, dict[str, Any]]:
    """Join benchmark registry safety requirements to maintained adapter identities."""
    from .industry_assurance import (
        _BENCHMARKS,
        _LABORATORY_QUALIFIED_BENCHMARKS,
        _benchmark_protocol,
    )

    specs = {item["benchmark_id"]: item for item in benchmark_adapter_specs()}
    contracts: dict[str, dict[str, Any]] = {}
    for benchmark in _BENCHMARKS:
        identifier = str(benchmark["id"])
        spec = specs.get(identifier)
        if spec is None:
            continue
        contracts[identifier] = {
            "id": identifier,
            "version": benchmark["version"],
            "lane": benchmark["lane"],
            "protocol": _benchmark_protocol(identifier),
            "laboratory_qualified": identifier in _LABORATORY_QUALIFIED_BENCHMARKS,
            "adapter_spec_sha256": hashlib.sha256(canonical_bytes(spec)).hexdigest(),
            "normalizer": spec["normalizer"],
            "required_inputs": list(spec["required_inputs"]),
        }
    return contracts
