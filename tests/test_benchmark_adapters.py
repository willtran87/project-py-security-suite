from __future__ import annotations

import pytest

from py_security_suite.benchmark_adapters import (
    BUILTIN_ADAPTER_SPECS,
    _validate_builtin_adapter_specs,
    benchmark_adapter_spec,
    benchmark_adapter_specs,
)
from py_security_suite.industry_assurance import (
    _BENCHMARKS,
    _benchmark_protocol,
    _benchmark_runner_contract,
)


def test_maintained_adapter_specs_are_registered_and_protocol_aligned() -> None:
    registered = {item["id"] for item in _BENCHMARKS}
    identifiers = [item["benchmark_id"] for item in BUILTIN_ADAPTER_SPECS]
    assert len(identifiers) == 192
    assert len(identifiers) == len(set(identifiers))
    assert set(identifiers) <= registered
    for item in BUILTIN_ADAPTER_SPECS:
        assert item["protocol"] == _benchmark_protocol(item["benchmark_id"])
        assert item["acquisition"]["immutable_revision_required"] is True
        assert item["acquisition"]["golden_negative_required"] is True
        assert item["required_inputs"]


def test_adapter_catalog_returns_detached_values_and_fails_closed() -> None:
    values = benchmark_adapter_specs()
    values[0]["required_inputs"].append("mutation")
    assert "mutation" not in BUILTIN_ADAPTER_SPECS[0]["required_inputs"]
    assert benchmark_adapter_spec("c2sp-wycheproof")["normalizer"].startswith(
        "wycheproof-"
    )
    with pytest.raises(ValueError, match="no maintained"):
        benchmark_adapter_spec("unknown")

    duplicate = (BUILTIN_ADAPTER_SPECS[0], BUILTIN_ADAPTER_SPECS[0])
    with pytest.raises(ValueError, match="duplicate"):
        _validate_builtin_adapter_specs(duplicate)


def test_currency_and_real_world_adapters_have_professional_boundaries() -> None:
    expected = {
        "fedramp-20x-continuous-validation": "no FedRAMP certification",
        "fido2-authenticator-conformance": "no FIDO certification claim",
        "eudi-wallet-functional-conformance": "no legal conformity",
        "hitrust-csf-assessment": "no suite-issued HITRUST certification",
        "pci-secure-software-conformance": "no PCI listing",
        "nis2-implementing-regulation-conformance": "no transmission",
        "nist-supplier-due-diligence": "no assurance inferred",
        "owasp-samm-assessment-benchmark": "small-sample limits",
    }
    for identifier, boundary in expected.items():
        adapter = benchmark_adapter_spec(identifier)
        assert len(adapter["required_inputs"]) == 5
        assert boundary in adapter["isolation"]

    for identifier in (
        "owasp-benchmark",
        "nist-sard-juliet",
        "nist-acvp-cryptography",
        "w3c-wpt-webauthn",
        "disa-stig-scap-conformance",
        "sigstore-client-conformance",
        "slsa-verifier-conformance",
        "sv-comp",
        "test-comp",
        "mitre-attack-evaluations",
        "atomic-red-team",
        "defects4j",
        "swe-bench-verified",
        "vul4j",
        "bugsinpy",
        "openssf-scorecard",
    ):
        assert benchmark_adapter_spec(identifier)["required_inputs"]


def test_open_source_extension_adapters_have_professional_boundaries() -> None:
    expected = {
        "oss-crs-crsbench": "production vulnerability completeness",
        "openssf-security-insights-conformance": "metadata presence proves security",
        "guac-interoperability": "graph presence proves artifact trust",
        "gittuf-source-policy-conformance": "production repositories",
        "openssf-package-analysis-malicious-packages": "developer or production hosts",
        "owasp-kubernetes-top10-conformance": "production clusters",
        "owasp-cicd-top10-conformance": "no production deployment",
        "sbomit-build-observed-sbom": "universal SBOM completeness",
        "primevul-real-world-vulnerability-detection": "production vulnerability completeness",
        "diversevul-unseen-project-generalization": "unseen-project generalization limits",
        "cvefixes-chronological-fix-pair-validation": "every changed function is vulnerable",
        "owasp-mobile-top10-conformance": "OWASP certification",
        "owasp-smart-contract-top10-conformance": "public RPC access",
        "cncf-cloud-native-security-controls-conformance": "CNCF or NIST certification",
        "reposvul-repository-context-validation": "production vulnerability completeness",
        "vuleval-repository-dependency-evaluation": "aggregate score",
        "mitre-emb3d-property-threat-conformance": "certifies an embedded device",
        "owasp-business-logic-abuse-top10-conformance": "production mutation",
        "cncf-supply-chain-best-practices-v2-conformance": "CNCF certification",
        "owasp-juice-shop": "production vulnerability completeness",
        "owasp-webgoat": "corporate network access",
        "owasp-crapi": "OWASP certification",
        "owasp-api-security-testing-framework": "inherited 100-percent coverage",
        "google-fuzzbench": "universal fuzzer superiority",
        "magma-ground-truth": "production bug-discovery completeness",
        "oss-fuzz-clusterfuzzlite": "OSS-Fuzz project acceptance",
        "sbom-sca-holdout": "SBOM or SCA completeness",
        "architecture-quality-holdout": "architecture certification",
        "epss-kev-temporal-backtest": "individual exploitation event",
        "scim-lifecycle-security-conformance": "no interoperability certification claim",
        "openid-shared-signals-conformance": "no OpenID certification claim",
        "spiffe-workload-identity-conformance": "experimental remote API excluded",
        "openssf-model-signing-conformance": "no claim of model safety",
        "cyclonedx-mlbom-conformance": "no claim that ML-BOM validity proves safety",
        "uptane-ota-security-conformance": "no certification claim",
        "darpa-aixcc-autonomous-vulnerability-remediation": "no inference that fragmented public materials form a ready benchmark",
        "openssf-criticality-score-calibration": "no treatment of criticality as security quality",
        "authzen-authorization-api-conformance": "no OpenID certification claim",
        "openid-federation-conformance": "no OpenID certification claim",
        "nist-hpc-ai-infrastructure-assurance": "no NIST certification claim",
        "iso-24760-identity-management-assurance": "no suite-issued ISO certification claim",
        "iso-5259-6-data-quality-visualization": "no conformance or ISO certification claim",
    }
    for identifier, boundary in expected.items():
        adapter = benchmark_adapter_spec(identifier)
        assert len(adapter["required_inputs"]) == 5
        assert boundary in adapter["isolation"]
        assert "policy" in " ".join(adapter["required_inputs"])
        benchmark = next(item for item in _BENCHMARKS if item["id"] == identifier)
        required = _benchmark_runner_contract(benchmark)["required_execution_evidence"]
        assert "suite-owned-extension-evidence" in required

    crs = next(item for item in _BENCHMARKS if item["id"] == "oss-crs-crsbench")
    assert _benchmark_runner_contract(crs)["minimum_repetitions"] == 3

    primevul = next(
        item
        for item in _BENCHMARKS
        if item["id"] == "primevul-real-world-vulnerability-detection"
    )
    primevul_evidence = _benchmark_runner_contract(primevul)[
        "required_execution_evidence"
    ]
    assert "independent-label-audit-report" in primevul_evidence
    assert "project-and-chronological-split-manifest" in primevul_evidence
    assert "training-overlap-assessment" in primevul_evidence

    reposvul = next(
        item
        for item in _BENCHMARKS
        if item["id"] == "reposvul-repository-context-validation"
    )
    repository_evidence = _benchmark_runner_contract(reposvul)[
        "required_execution_evidence"
    ]
    assert "repository-snapshot-manifest" in repository_evidence
    assert "dependency-context-oracle" in repository_evidence
    assert "tangled-patch-audit" in repository_evidence
    assert "multi-granularity-label-map" in repository_evidence

    fuzzbench = next(item for item in _BENCHMARKS if item["id"] == "google-fuzzbench")
    fuzzbench_evidence = _benchmark_runner_contract(fuzzbench)[
        "required_execution_evidence"
    ]
    assert "repeated-trial-raw-data" in fuzzbench_evidence
    assert "equal-resource-manifest" in fuzzbench_evidence
    assert _benchmark_runner_contract(fuzzbench)["minimum_repetitions"] == 20

    crapi = next(item for item in _BENCHMARKS if item["id"] == "owasp-crapi")
    crapi_evidence = _benchmark_runner_contract(crapi)["required_execution_evidence"]
    assert "target-label-authority-map" in crapi_evidence
    assert "deterministic-target-reset" in crapi_evidence

    temporal = next(
        item for item in _BENCHMARKS if item["id"] == "epss-kev-temporal-backtest"
    )
    temporal_evidence = _benchmark_runner_contract(temporal)[
        "required_execution_evidence"
    ]
    assert "dated-snapshot-manifest" in temporal_evidence
    assert "future-data-exclusion-report" in temporal_evidence


def test_high_risk_adapters_encode_domain_specific_safety_boundaries() -> None:
    tls = benchmark_adapter_spec("tls-protocol-conformance")
    assert "loopback-only" in tls["isolation"]
    assert "no production credentials" in tls["isolation"]

    malware = benchmark_adapter_spec("amtso-malware-protection-evaluation")
    assert "harmless or inert fixtures" in malware["isolation"]
    assert "destruction receipt" in malware["isolation"]
    assert "harmless-eicar-and-inert-fixtures" in malware["required_inputs"]

    penetration = benchmark_adapter_spec("penetration-test-engagement-quality")
    assert "authorized" in penetration["isolation"]
    assert "kill switches" in penetration["isolation"]
    assert "signed-authorization-and-scope" in penetration["required_inputs"]

    reproducible = benchmark_adapter_spec("reproducible-build-variation")
    assert "no-egress" in reproducible["isolation"]
    assert "environment-variation-matrix" in reproducible["required_inputs"]

    biometric = benchmark_adapter_spec("biometric-performance-pad")
    assert biometric["protocol"] == "biometric-performance"
    assert "informed consent" in biometric["isolation"]
    assert (
        "locked-thresholds-sensors-environments-and-decision-oracles"
        in biometric["required_inputs"]
    )

    proficiency = benchmark_adapter_spec("interlaboratory-proficiency-testing")
    assert proficiency["protocol"] == "proficiency-testing"
    assert "collusion controls" in proficiency["isolation"]

    cmvp = benchmark_adapter_spec("cmvp-fips-140-3-validation")
    international = benchmark_adapter_spec("iso-19790-24759-module-conformance")
    assert "scheme-referenced-standard-edition-map" in cmvp["required_inputs"]
    assert "licensed-19790-and-24759-requirements" in international["required_inputs"]


def test_llm_and_threat_model_adapters_fail_closed_on_identity_and_safety() -> None:
    harmbench = benchmark_adapter_spec("harmbench")
    agentharm = benchmark_adapter_spec("agentharm")
    garak = benchmark_adapter_spec("garak-llm-probe-conformance")
    cornucopia = benchmark_adapter_spec("owasp-cornucopia-threat-model")
    pyrit = benchmark_adapter_spec("pyrit-ai-red-team")

    assert harmbench["protocol"] == "stochastic-adversarial"
    assert "private-holdout" in " ".join(harmbench["required_inputs"])
    assert "harmful-output handling" in harmbench["isolation"]
    assert "inert tools" in agentharm["isolation"]
    assert "destruction receipt" in agentharm["isolation"]
    assert "inspect_evals" in agentharm["upstream"]
    assert "safety-and-security-use-clause" in agentharm["acquisition"]["license"]
    assert "classifier-prompt-injection-negative-cases" in harmbench["required_inputs"]
    assert "plugin allowlist" in garak["isolation"]
    assert "garak-release-and-environment-lock" in garak["required_inputs"]
    assert cornucopia["protocol"] == "conformance"
    assert "protected answer keys" in cornucopia["isolation"]
    assert pyrit["protocol"] == "stochastic-adversarial"
    assert "scenario and plugin allowlists" in pyrit["isolation"]
    assert "signed cleanup destruction receipt" in pyrit["isolation"]
    assert "pyrit-release-and-environment-lock" in pyrit["required_inputs"]
    assert "cross-evaluator" in " ".join(pyrit["required_inputs"])


def test_ai_certification_attestation_and_profile_adapters_fail_closed() -> None:
    aisvs = benchmark_adapter_spec("owasp-aisvs-conformance")
    eucc = benchmark_adapter_spec("eucc-scheme-assurance")
    attestation = benchmark_adapter_spec("cisa-secure-software-attestation")
    csf = benchmark_adapter_spec("nist-csf-profile-gap-reassessment")
    safety = benchmark_adapter_spec("mlcommons-ailuminate-safety")
    jailbreak = benchmark_adapter_spec("mlcommons-ailuminate-jailbreak")

    assert "synthetic tenants" in aisvs["isolation"]
    assert "kill switch" in aisvs["isolation"]
    assert "mutation-fixtures" in " ".join(aisvs["required_inputs"])
    assert "separated laboratory" in eucc["isolation"]
    assert "accreditation-and-authorization" in " ".join(eucc["required_inputs"])
    assert "test-only signing roots" in attestation["isolation"]
    assert "revoked and unauthorized signers" in attestation["isolation"]
    assert "no automatic production control changes" in csf["isolation"]
    assert safety["protocol"] == "stochastic-adversarial"
    assert jailbreak["protocol"] == "stochastic-adversarial"
    assert "public-private split separation" in safety["isolation"]
    assert "protected attack-set separation" in jailbreak["isolation"]
    assert "scorer-manipulation" in " ".join(safety["required_inputs"])


def test_protocol_cloud_response_memory_and_resilience_adapters_fail_closed() -> None:
    mcp = benchmark_adapter_spec("mcp-client-server-security-conformance")
    assert "synthetic authorization servers" in mcp["isolation"]
    assert "deny-by-default tool authority" in mcp["isolation"]
    assert "confused-deputy" in " ".join(mcp["required_inputs"])

    for identifier, provider, boundary in (
        ("aws-fsbp-securityhub-conformance", "AWS", "CloudTrail"),
        ("microsoft-mcsb-defender-conformance", "Azure", "activity-log"),
        ("gcp-enterprise-foundations-conformance", "Google Cloud", "audit-log"),
    ):
        adapter = benchmark_adapter_spec(identifier)
        assert f"read-only short-lived {provider}" in adapter["isolation"]
        assert boundary in adapter["isolation"]
        assert "no production mutation" in adapter["isolation"]
        assert "rescan-receipts" in " ".join(adapter["required_inputs"])

    response = benchmark_adapter_spec("first-csirt-psirt-maturity-assessment")
    assert response["protocol"] == "assessor-agreement"
    assert "no production incident activation" in response["isolation"]

    memory = benchmark_adapter_spec("memory-safety-engineering-conformance")
    assert "digest-pinned toolchains" in memory["isolation"]
    assert "sanitizer" in " ".join(memory["required_inputs"])
    assert "migration-roadmap" in " ".join(memory["required_inputs"])

    resilience = benchmark_adapter_spec("organizational-resilience-bia-exercise")
    assert "explicit blast radius" in resilience["isolation"]
    assert "no unapproved production disruption" in resilience["isolation"]

    badge = benchmark_adapter_spec("openssf-best-practices-badge-conformance")
    assert "no automatic badge" in badge["isolation"]
    assert "inflated-level" in " ".join(badge["required_inputs"])


def test_agent_iot_information_web_and_sector_adapters_fail_closed() -> None:
    a2a = benchmark_adapter_spec("a2a-protocol-security-conformance")
    assert "synthetic agents tenants" in a2a["isolation"]
    assert "deny-by-default delegated authority" in a2a["isolation"]
    assert "callback sinkhole" in a2a["isolation"]

    sesip = benchmark_adapter_spec("sesip-iot-platform-evaluation-conformance")
    assert "no suite-issued certification claim" in sesip["isolation"]
    assert "scheme-certification-body-laboratory" in " ".join(sesip["required_inputs"])

    handling = benchmark_adapter_spec("first-tlp-iep-information-handling-conformance")
    assert "no delivery to real external recipients" in handling["isolation"]
    assert "downgrade-removal" in " ".join(handling["required_inputs"])

    veris = benchmark_adapter_spec("veris-incident-schema-conformance")
    assert "deidentified or synthetic records" in veris["isolation"]
    assert "no claim that schema validity proves incident facts" in veris["isolation"]

    web = benchmark_adapter_spec("w3c-web-platform-defense-conformance")
    assert "synthetic origins" in web["isolation"]
    assert "digest-pinned browsers" in web["isolation"]

    dora = benchmark_adapter_spec("dora-level2-technical-standards-conformance")
    assert "qualified tester" in dora["isolation"]
    assert "protected threat intelligence" in dora["isolation"]
    assert "withheld from real channels" in dora["isolation"]

    ffiec = benchmark_adapter_spec("ffiec-it-handbook-assessment")
    assert ffiec["protocol"] == "assessor-agreement"
    assert "explicit exclusion of the retired FFIEC CAT" in ffiec["isolation"]

    c5 = benchmark_adapter_spec("bsi-c5-cloud-assurance-assessment")
    assert c5["protocol"] == "assessor-agreement"
    assert "distinction between C5 attestation and BSI certification" in c5["isolation"]

    trust_mark = benchmark_adapter_spec("fcc-cyber-trust-mark-conformance")
    assert "recognized-laboratory authority" in trust_mark["isolation"]
    assert "no suite-issued mark authorization" in trust_mark["isolation"]
    assert "qr-registry" in " ".join(trust_mark["required_inputs"])


def test_credentials_cloud_ast_privacy_and_sector_adapters_fail_closed() -> None:
    credentials = benchmark_adapter_spec("openid-digital-credential-conformance")
    assert "synthetic people" in credentials["isolation"]
    assert (
        "no real wallet enrollment or certification claim" in credentials["isolation"]
    )

    scuba = benchmark_adapter_spec("cisa-scuba-saas-posture-conformance")
    assert "read-only least-privilege" in scuba["isolation"]
    assert "no production configuration mutation" in scuba["isolation"]

    kubernetes = benchmark_adapter_spec("cis-kubernetes-hardening-conformance")
    assert "no automated production remediation" in kubernetes["isolation"]
    assert "no CIS certification claim" in kubernetes["isolation"]

    linddun = benchmark_adapter_spec("linddun-privacy-threat-model-conformance")
    assert linddun["protocol"] == "assessor-agreement"
    assert "protected answer keys" in linddun["isolation"]

    modalities = benchmark_adapter_spec("owasp-benchmark-ast-modality-comparison")
    assert modalities["protocol"] == "classification"
    assert "no union score" in modalities["isolation"]

    rasp = benchmark_adapter_spec("rasp-prevention-effectiveness")
    assert rasp["protocol"] == "detection-evaluation"
    assert "no production attack execution" in rasp["isolation"]

    nesas = benchmark_adapter_spec("gsma-nesas-scas-assurance")
    assert (
        "assurance scheme rather than suite-issued certification" in nesas["isolation"]
    )

    tisax = benchmark_adapter_spec("tisax-vda-isa-assessment")
    assert tisax["protocol"] == "assessor-agreement"
    assert "no suite-issued TISAX label" in tisax["isolation"]

    c2pa = benchmark_adapter_spec("c2pa-content-credentials-conformance")
    assert "separation of provenance validity from content truth" in c2pa["isolation"]

    pci = benchmark_adapter_spec("pci-payment-acceptance-conformance")
    assert "no PAN or live payment networks" in pci["isolation"]
    assert "no suite-issued PCI listing or validation claim" in pci["isolation"]

    fapi = benchmark_adapter_spec("oidf-fapi-conformance")
    assert "fapi-2.0-final" in " ".join(fapi["required_inputs"])
    assert "no OpenID certification claim" in fapi["isolation"]
