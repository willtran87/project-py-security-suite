from __future__ import annotations

from typing import Any


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
        "required_inputs": ["test-plan", "reference-image", "expected-observations", "tool-version"],
        "isolation": "read-only evidence media and disposable analysis workspace",
    },
    {
        "benchmark_id": "w3c-act-rules-conformance",
        "protocol": "conformance",
        "upstream": "https://www.w3.org/WAI/standards-guidelines/act/rules/",
        "acquisition": {**_COMMON, "license": "W3C-document-and-rule-license"},
        "normalizer": "act-applicability-outcome-v1",
        "required_inputs": ["approved-rules", "applicability-cases", "expected-outcomes", "implementation-version"],
        "isolation": "digest-pinned browser and accessibility tree",
    },
    {
        "benchmark_id": "droidbench",
        "protocol": "classification",
        "upstream": "https://github.com/secure-software-engineering/DroidBench",
        "acquisition": {**_COMMON, "license": "upstream-repository-license"},
        "normalizer": "android-source-sink-classification-v1",
        "required_inputs": ["source-projects", "apk-set", "source-sink-labels", "android-image"],
        "isolation": "disposable emulator or no-network static analysis container",
    },
    {
        "benchmark_id": "ghera-android-security",
        "protocol": "classification",
        "upstream": "https://bitbucket.org/secure-it-i/android-app-vulnerability-benchmarks/",
        "acquisition": {**_COMMON, "license": "upstream-repository-license"},
        "normalizer": "ghera-vulnerability-behavior-v1",
        "required_inputs": ["benchmark-apps", "expected-behavior", "android-image", "instrumentation-plan"],
        "isolation": "disposable emulator with target-only network policy",
    },
    {
        "benchmark_id": "secbench-js",
        "protocol": "classification",
        "upstream": "https://github.com/cristianstaicu/SecBench.js",
        "acquisition": {**_COMMON, "license": "upstream-repository-and-package-license"},
        "normalizer": "vulnerable-fixed-pair-classification-v1",
        "required_inputs": ["vulnerable-commits", "fixed-commits", "lockfiles", "labels"],
        "isolation": "no-network container with quarantined package cache",
    },
    {
        "benchmark_id": "cloud-native-chaos-resilience",
        "protocol": "conformance",
        "upstream": "https://chaos-mesh.org/ and https://litmuschaos.io/",
        "acquisition": {**_COMMON, "license": "Apache-2.0"},
        "normalizer": "steady-state-recovery-conformance-v1",
        "required_inputs": ["experiment-manifests", "steady-state-probes", "slo-thresholds", "cleanup-assertions"],
        "isolation": "dedicated disposable cluster with bounded blast radius",
    },
    {
        "benchmark_id": "kubernetes-sonobuoy-conformance",
        "protocol": "conformance",
        "upstream": "https://github.com/vmware-tanzu/sonobuoy",
        "acquisition": {**_COMMON, "license": "Apache-2.0"},
        "normalizer": "sonobuoy-e2e-conformance-v1",
        "required_inputs": ["kubernetes-release", "plugin-images", "cluster-identity", "e2e-results"],
        "isolation": "dedicated disposable cluster and digest-only plugin images",
    },
    {
        "benchmark_id": "cis-cat-scap-platform-conformance",
        "protocol": "conformance",
        "upstream": "https://www.cisecurity.org/cis-cat-pro and https://csrc.nist.gov/projects/security-content-automation-protocol/",
        "acquisition": {**_COMMON, "license": "licensed-CIS-or-publisher-specific"},
        "normalizer": "xccdf-oval-control-outcome-v1",
        "required_inputs": ["benchmark-edition", "profile", "platform-cpe", "xccdf-or-cis-cat-results"],
        "isolation": "approved assessor host or read-only target snapshot",
    },
    {
        "benchmark_id": "c2sp-wycheproof",
        "protocol": "conformance",
        "upstream": "https://github.com/C2SP/wycheproof",
        "acquisition": {**_COMMON, "license": "Apache-2.0"},
        "normalizer": "wycheproof-valid-invalid-acceptable-v1",
        "required_inputs": ["test-vectors", "schema-version", "algorithm-implementation", "expected-results"],
        "isolation": "no-network container with resource limits",
    },
    {
        "benchmark_id": "tiber-eu-threat-led-red-team",
        "protocol": "detection-evaluation",
        "upstream": "https://www.ecb.europa.eu/paym/cyber-resilience/tiber-eu/html/index.en.html",
        "acquisition": {**_COMMON, "license": "framework-and-engagement-specific"},
        "normalizer": "tiber-objective-detection-restoration-v1",
        "required_inputs": ["approved-scope", "threat-intelligence", "attack-objectives", "detection-and-restoration-evidence"],
        "isolation": "authorized production-safe engagement with kill switches and restoration plan",
    },
)


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
