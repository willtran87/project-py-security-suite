from __future__ import annotations

import hashlib
import base64
import json
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from py_security_suite.benchmark_execution import (
    BenchmarkExecutionError,
    _benchmark_subject_sha256,
    _score_normalized_result,
    _stage_argv,
    execute_benchmark_manifest,
)
from py_security_suite.industry_assurance import _benchmark_registry, _validate_policy


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _manifest(workspace: Path) -> dict[str, object]:
    executable = Path(sys.executable).resolve()
    return {
        "schema_version": "1.0",
        "benchmark_id": "droidbench",
        "benchmark_version": "test-corpus",
        "adapter_version": "1.0.0",
        "protocol": "classification",
        "corpus": {
            "path": "corpus.bin",
            "sha256": _sha256(workspace / "corpus.bin"),
            "license_sha256": "1" * 64,
            "label_authority_sha256": "2" * 64,
            "organization_approved": True,
        },
        "stages": [
            {
                "name": "run",
                "executable": str(executable),
                "executable_sha256": _sha256(executable),
                "arguments": [str(workspace / "adapter.py")],
                "environment": {},
                "timeout_seconds": 10,
                "expected_exit_codes": [0],
            }
        ],
        "normalized_result": {"path": "normalized-result.json", "sha256": None},
        "thresholds": {
            "minimum_precision": 0.5,
            "minimum_recall": 0.5,
            "minimum_f1": 0.5,
            "maximum_false_positive_rate": 0.5,
        },
        "isolation": {
            "mode": "process",
            "network_policy": "inherited",
            "disposable_target": False,
            "external_receipt_sha256": None,
            "oci": None,
        },
        "attestations": {},
    }


def _write_attestations(workspace: Path, manifest: dict[str, object]) -> None:
    key = Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    (workspace / "attestation.pub.pem").write_bytes(public)
    subject = _benchmark_subject_sha256(
        manifest,
        manifest["corpus"]["sha256"],  # type: ignore[index]
    )
    claims = {
        "trusted_time": {
            "rfc3161_verified": True,
            "monotonic_state_verified": True,
            "trusted_time_receipt_sha256": "a" * 64,
        },
        "replay_protection": {
            "ledger_consumed": True,
            "nonce_unique": True,
            "ledger_receipt_sha256": "b" * 64,
            "nonce_sha256": "c" * 64,
        },
        "contamination_manifest": {"checked": True, "contaminated": False},
        "runner_sbom": {"validated": True, "format": "CycloneDX-1.6"},
        "runner_provenance": {
            "signature_verified": True,
            "predicate_type": "https://slsa.dev/provenance/v1",
        },
        "environment": {"captured": True, "hermetic": False},
    }
    kinds = {
        "trusted_time": "trusted-time",
        "replay_protection": "replay-protection",
        "contamination_manifest": "contamination-manifest",
        "runner_sbom": "runner-sbom",
        "runner_provenance": "runner-provenance",
        "environment": "environment",
    }
    references = {}
    for name, kind in kinds.items():
        payload = json.dumps(
            {
                "schema_version": "1.0",
                "kind": kind,
                "subject_sha256": subject,
                "valid": True,
                "claims": claims[name],
            },
            sort_keys=True,
        ).encode()
        artifact = workspace / f"{name}.json"
        signature = workspace / f"{name}.sig"
        artifact.write_bytes(payload)
        signature.write_bytes(base64.b64encode(key.sign(payload)))
        references[name] = {
            "path": artifact.name,
            "sha256": hashlib.sha256(payload).hexdigest(),
            "media_type": "application/vnd.pysec.attestation+json;version=1.0",
            "public_key_path": "attestation.pub.pem",
            "public_key_sha256": hashlib.sha256(public).hexdigest(),
            "signature_path": signature.name,
        }
    manifest["attestations"] = references


def test_executes_digest_pinned_adapter_and_scores_cases(tmp_path: Path) -> None:
    (tmp_path / "corpus.bin").write_bytes(b"pinned corpus")
    normalized = {
        "schema_version": "1.0",
        "benchmark_id": "droidbench",
        "protocol": "classification",
        "cases": [
            {
                "id": "tp",
                "expected_positive": True,
                "observed_positive": True,
                "strata": {"cwe": "CWE-200"},
            },
            {
                "id": "tn",
                "expected_positive": False,
                "observed_positive": False,
                "strata": {"cwe": "CWE-200"},
            },
        ],
    }
    (tmp_path / "adapter.py").write_text(
        "import json\nfrom pathlib import Path\n"
        f"Path('normalized-result.json').write_text({json.dumps(json.dumps(normalized))}, encoding='utf-8')\n",
        encoding="utf-8",
    )
    manifest_path = tmp_path / "manifest.json"
    manifest_value = _manifest(tmp_path)
    _write_attestations(tmp_path, manifest_value)
    manifest_path.write_text(json.dumps(manifest_value), encoding="utf-8")

    receipt = execute_benchmark_manifest(
        manifest_path,
        tmp_path,
        authorized=True,
        known_benchmark_ids={"droidbench"},
    )

    assert receipt["decision"] == "pass"
    assert receipt["verdict"] == "pass"
    assert receipt["case_count"] == 2
    assert receipt["metrics"]["precision"] == 1.0
    assert receipt["metrics"]["recall"] == 1.0
    assert receipt["stages"][0]["status"] == "passed"
    assert receipt["replay_protected"] is True
    assert receipt["attestations"]["runner_provenance"]["signature_verified"] is True
    assert len(receipt["receipt_sha256"]) == 64


def test_requires_explicit_execution_authorization(tmp_path: Path) -> None:
    with pytest.raises(BenchmarkExecutionError, match="authorize-execution"):
        execute_benchmark_manifest(
            tmp_path / "missing.json", tmp_path, authorized=False
        )


def test_rejects_process_network_isolation_claim(tmp_path: Path) -> None:
    (tmp_path / "corpus.bin").write_bytes(b"pinned corpus")
    (tmp_path / "adapter.py").write_text("pass\n", encoding="utf-8")
    manifest = _manifest(tmp_path)
    _write_attestations(tmp_path, manifest)
    manifest["isolation"]["network_policy"] = "deny"  # type: ignore[index]
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(BenchmarkExecutionError, match="cannot claim"):
        execute_benchmark_manifest(
            manifest_path,
            tmp_path,
            authorized=True,
            known_benchmark_ids={"droidbench"},
        )


def test_rejects_signed_attestation_for_a_different_subject(tmp_path: Path) -> None:
    (tmp_path / "corpus.bin").write_bytes(b"pinned corpus")
    (tmp_path / "adapter.py").write_text("pass\n", encoding="utf-8")
    manifest = _manifest(tmp_path)
    _write_attestations(tmp_path, manifest)
    manifest["benchmark_version"] = "changed-after-attestation"
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(BenchmarkExecutionError, match="detached"):
        execute_benchmark_manifest(path, tmp_path, authorized=True)


def test_scores_protocol_specific_conformance_and_stochastic_results() -> None:
    conformance = _score_normalized_result(
        {
            "schema_version": "1.0",
            "benchmark_id": "w3c-act-rules-conformance",
            "protocol": "conformance",
            "cases": [
                {
                    "id": "rule-1",
                    "expected_outcome": "pass",
                    "observed_outcome": "pass",
                    "strata": {},
                },
                {
                    "id": "rule-2",
                    "expected_outcome": "not-applicable",
                    "observed_outcome": "not-applicable",
                    "strata": {},
                },
            ],
        },
        benchmark_id="w3c-act-rules-conformance",
        protocol="conformance",
    )
    stochastic = _score_normalized_result(
        {
            "schema_version": "1.0",
            "benchmark_id": "agentdojo",
            "protocol": "stochastic-adversarial",
            "cases": [
                {
                    "id": "trial-1",
                    "attacked": True,
                    "compromised": False,
                    "utility": 0.9,
                    "strata": {},
                },
                {
                    "id": "trial-2",
                    "attacked": True,
                    "compromised": True,
                    "utility": 0.7,
                    "strata": {},
                },
            ],
        },
        benchmark_id="agentdojo",
        protocol="stochastic-adversarial",
    )
    assert conformance["outcome_accuracy"] == 1.0
    assert conformance["conformance_rate"] == 1.0
    assert stochastic["attack_success_rate"] == 0.5
    assert stochastic["attack_success_rate_wilson_upper_95"] > 0.5


def test_scores_biometric_and_proficiency_results_with_stratified_contracts() -> None:
    biometric = _score_normalized_result(
        {
            "schema_version": "1.0",
            "benchmark_id": "biometric-performance-pad",
            "protocol": "biometric-performance",
            "cases": [
                {
                    "id": "genuine-a",
                    "trial_type": "genuine",
                    "accepted": True,
                    "strata": {"demographic": "group-a"},
                },
                {
                    "id": "impostor-a",
                    "trial_type": "impostor",
                    "accepted": False,
                    "strata": {"demographic": "group-a"},
                },
                {
                    "id": "genuine-b",
                    "trial_type": "genuine",
                    "accepted": False,
                    "strata": {"demographic": "group-b"},
                },
                {
                    "id": "impostor-b",
                    "trial_type": "impostor",
                    "accepted": False,
                    "strata": {"demographic": "group-b"},
                },
                {
                    "id": "attack-print",
                    "trial_type": "presentation-attack",
                    "accepted": False,
                    "strata": {"attack_instrument": "print"},
                },
            ],
        },
        benchmark_id="biometric-performance-pad",
        protocol="biometric-performance",
    )
    assert biometric["false_match_rate"] == 0.0
    assert biometric["false_non_match_rate"] == 0.5
    assert biometric["iapar"] == 0.0
    assert biometric["demographic_groups"] == 2
    assert (
        biometric["worst_group_fnmr_wilson_upper_95"]
        >= biometric["fnmr_wilson_upper_95"]
    )

    proficiency = _score_normalized_result(
        {
            "schema_version": "1.0",
            "benchmark_id": "interlaboratory-proficiency-testing",
            "protocol": "proficiency-testing",
            "cases": [
                {
                    "id": "item-1",
                    "assigned_value": "pass",
                    "participant_results": ["pass", "pass", "pass"],
                    "round": 1,
                    "strata": {"case_type": "positive"},
                },
                {
                    "id": "item-2",
                    "assigned_value": "fail",
                    "participant_results": ["fail", "fail", "pass"],
                    "round": 2,
                    "strata": {"case_type": "negative"},
                },
            ],
        },
        benchmark_id="interlaboratory-proficiency-testing",
        protocol="proficiency-testing",
    )
    assert proficiency["participants"] == 3
    assert proficiency["rounds"] == 2
    assert proficiency["reference_accuracy"] == pytest.approx(5 / 6)
    assert -1 <= proficiency["chance_corrected_agreement"] <= 1

    with pytest.raises(ValueError, match="attack_instrument"):
        _score_normalized_result(
            {
                "schema_version": "1.0",
                "benchmark_id": "biometric-performance-pad",
                "protocol": "biometric-performance",
                "cases": [
                    {
                        "id": "attack-missing-strata",
                        "trial_type": "presentation-attack",
                        "accepted": False,
                        "strata": {},
                    }
                ],
            },
            benchmark_id="biometric-performance-pad",
            protocol="biometric-performance",
        )


def test_builds_hardened_digest_only_oci_command(tmp_path: Path) -> None:
    (tmp_path / "corpus.bin").write_bytes(b"pinned corpus")
    executable = Path(sys.executable).resolve()
    stage = _manifest(tmp_path)["stages"][0]  # type: ignore[index]
    isolation = {
        "mode": "oci",
        "network_policy": "deny",
        "disposable_target": True,
        "external_receipt_sha256": None,
        "oci": {
            "runtime": str(executable),
            "runtime_sha256": _sha256(executable),
            "image": "registry.example/adapter@sha256:" + "d" * 64,
            "memory_bytes": 536870912,
            "cpu_count": 2,
            "pids_limit": 128,
            "seccomp_profile": None,
            "apparmor_profile": "pysec-benchmark",
        },
    }
    argv, runtime_digest = _stage_argv(
        executable, stage, isolation, tmp_path, tmp_path / "corpus.bin"
    )
    assert runtime_digest == _sha256(executable)
    assert "--read-only" in argv
    assert "--cap-drop=ALL" in argv
    assert "--network=none" in argv
    assert argv[-2] == "/pysec/stage-executable"


def test_policy_emits_fail_closed_adapter_execution_task() -> None:
    policy = {
        "schema_version": "1.2",
        "enforce": True,
        "profiles": [],
        "controls": [],
        "procedures": [],
        "benchmarks": [
            {
                "id": "droidbench",
                "enabled": True,
                "corpus_sha256": "a" * 64,
                "evidence_artifact": "droidbench-score.json",
                "minimum_precision": 0.8,
                "minimum_recall": 0.8,
                "minimum_f1": 0.8,
                "maximum_false_positive_rate": 0.2,
                "adapter_manifest": "security/benchmark-adapters/droidbench.json",
            }
        ],
        "benchmark_baseline_path": None,
    }

    _validate_policy(policy)
    registry = _benchmark_registry(policy, "b" * 64)
    task = registry["tasks"][0]

    assert task["execution_mode"] == "adapter"
    assert task["requires_operator_authorization"] is True
    assert task["authorization_flag"] == "--authorize-execution"
    assert "--authorize-execution" not in task["command"]
