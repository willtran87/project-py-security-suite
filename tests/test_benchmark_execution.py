from __future__ import annotations

import hashlib
import base64
import json
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jsonschema import Draft202012Validator

from py_security_suite.benchmark_execution import (
    BenchmarkExecutionError,
    _benchmark_subject_sha256,
    _enforce_authority_policy,
    _oci_output_gaps,
    _score_normalized_result,
    _stage_argv,
    _threshold_failures,
    _validate_attestation_document,
    _runtime_input_integrity_gaps,
    _trusted_attestation_time,
    execute_benchmark_manifest,
)
from py_security_suite.benchmark_adapters import benchmark_execution_contracts
from py_security_suite.benchmark_compiler import compile_benchmark_manifest
from py_security_suite.benchmark_input_validation import validate_benchmark_input
from py_security_suite.benchmark_protocols import protocol_sufficiency_gaps
from py_security_suite.benchmark_semantic_evidence import (
    CANONICALIZATION,
    SIMILARITY_ALGORITHM,
    canonicalizer_identity,
    semantic_fingerprint,
)
from py_security_suite.benchmark_statistical_evidence import (
    compute_power,
    compute_protocol_power,
    compute_standardized_mean_power,
)
from py_security_suite.benchmark_runtime import (
    _OCI_REQUIRED_RUN_OPTIONS,
    verify_oci_runtime_capabilities,
)
from py_security_suite.bounded_subprocess import BoundedProcessResult
from py_security_suite.strict_json import canonical_bytes
from py_security_suite.industry_assurance import (
    _benchmark_registry,
    _benchmark_reproducibility_gaps,
    _validate_policy,
)
from py_security_suite.report_inspection import read_bundled_schema


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _semantic_record(workspace: Path, name: str, argument_count: int) -> dict[str, str]:
    payload = (
        "result = call(" + ", ".join(["value"] * argument_count) + ")\n"
    ).encode()
    path = f"semantic-corpus/{name}.py"
    destination = workspace / path
    destination.parent.mkdir(exist_ok=True)
    destination.write_bytes(payload)
    return {
        "path": path,
        "language": "python",
        "subject_sha256": hashlib.sha256(payload).hexdigest(),
        "semantic_sha256": semantic_fingerprint(payload, language="python"),
    }


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


def _strong_evaluation() -> dict[str, object]:
    return {
        "minimum_cases": 20,
        "split_strategy": "official-fixed",
        "positive_controls": 5,
        "negative_controls": 5,
        "acceptance_criteria_sha256": "3" * 64,
        "independent_reviewers": 2,
        "random_seeds": [17],
        "required_strata": ["cwe"],
        "power_analysis_sha256": "4" * 64,
        "minimum_power": 0.8,
        "confidence_level": 0.95,
        "maximum_confidence_interval_width": 0.5,
        "minimum_repetitions": 3,
        "leakage_check_sha256": "5" * 64,
        "duplicate_check_sha256": "6" * 64,
        "holdout_sequestered": True,
    }


def _authority_policy() -> dict[str, object]:
    return {
        "minimum_distinct_signers": 4,
        "minimum_distinct_organizations": 2,
        "key_separation_groups": [
            ["trusted_time", "replay_protection"],
            ["runner_sbom", "runner_provenance"],
            ["acceptance_criteria", "adapter_conformance"],
            ["external_isolation", "cleanup_capability"],
        ],
        "organization_separation_groups": [
            ["acceptance_criteria", "runner_provenance"],
            ["external_isolation", "cleanup_capability"],
        ],
    }


def _write_attestations(workspace: Path, manifest: dict[str, object]) -> None:
    raw_evidence: dict[str, tuple[str, dict[str, object]]] = {}
    raw_digests: dict[str, str] = {}
    if manifest.get("schema_version") in {"1.1", "1.2"}:
        strict_design = manifest.get("schema_version") == "1.2"
        evaluation = manifest["evaluation"]  # type: ignore[assignment]
        minimum_cases = int(evaluation["minimum_cases"])
        hypothesis_count = len(manifest["thresholds"])  # type: ignore[arg-type]
        adjusted_alpha = 0.05 / hypothesis_count
        analysis_plan_path = "analysis-plan.json"
        analysis_plan_sha256 = "8" * 64
        if strict_design:
            analysis_plan = {
                "schema_version": "1.0",
                "protocol": manifest["protocol"],
                "method": "exact-binomial-equal-tail-two-sided-bonferroni",
                "alpha": 0.05,
                "hypothesis_count": hypothesis_count,
                "adjusted_alpha": adjusted_alpha,
                "design_effect": 1.0,
                "sample_size": minimum_cases,
                "null_rate": 0.1,
                "alternative_rate": 0.9,
                "effect_source_sha256": "7" * 64,
            }
            analysis_plan_payload = json.dumps(analysis_plan, sort_keys=True).encode()
            (workspace / analysis_plan_path).write_bytes(analysis_plan_payload)
            analysis_plan_sha256 = hashlib.sha256(analysis_plan_payload).hexdigest()
        power = (
            compute_protocol_power(
                protocol=str(manifest["protocol"]),
                alpha=adjusted_alpha,
                null_rate=0.1,
                alternative_rate=0.9,
                sample_size=minimum_cases,
            )
            if strict_design
            else compute_power(
                alpha=0.05,
                null_rate=0.1,
                alternative_rate=0.9,
                sample_size=minimum_cases,
            )
        )
        canonicalizer_sha256 = canonicalizer_identity({"python"})["identity_sha256"]
        training_records = [
            _semantic_record(workspace, f"training-{index}", index)
            for index in range(1, 4)
        ]
        holdout_records = [
            _semantic_record(workspace, f"holdout-{index}", index)
            for index in range(11, 14)
        ]
        case_records = [
            _semantic_record(workspace, f"case-{index}", index + 20)
            for index in range(minimum_cases)
        ]
        benchmark_records = [_semantic_record(workspace, "benchmark", 200)]
        contamination_training_records = [
            _semantic_record(workspace, "contamination-training", 300)
        ]
        raw_evidence = {
            "power": (
                "power-analysis.json",
                {
                    "schema_version": "1.2" if strict_design else "1.0",
                    "method": (
                        "exact-binomial-equal-tail-two-sided-bonferroni"
                        if strict_design
                        else "normal-two-proportion-two-sided"
                    ),
                    "alpha": 0.05,
                    "null_rate": 0.1,
                    "alternative_rate": 0.9,
                    "sample_size": minimum_cases,
                    "achieved_power": power,
                    **(
                        {
                            "protocol": manifest["protocol"],
                            "hypothesis_count": hypothesis_count,
                            "adjusted_alpha": adjusted_alpha,
                            "design_effect": 1.0,
                            "analysis_plan_path": analysis_plan_path,
                            "analysis_plan_sha256": analysis_plan_sha256,
                            "effect_source_sha256": "7" * 64,
                            "sensitivity_power": (
                                compute_protocol_power(
                                    protocol=str(manifest["protocol"]),
                                    alpha=adjusted_alpha,
                                    null_rate=0.1,
                                    alternative_rate=0.74,
                                    sample_size=minimum_cases,
                                )
                                if manifest["protocol"]
                                not in {
                                    "temporal-calibration",
                                    "stochastic-adversarial",
                                    "fuzzing-statistical",
                                }
                                else compute_standardized_mean_power(
                                    alpha=adjusted_alpha,
                                    standardized_effect=0.64,
                                    sample_size=minimum_cases,
                                )
                            ),
                        }
                        if strict_design
                        else {}
                    ),
                },
            ),
            "leakage": (
                "leakage-analysis.json",
                {
                    "schema_version": "1.2" if strict_design else "1.0",
                    "algorithm": (
                        "parser-derived-sha256-set-intersection"
                        if strict_design
                        else "sha256-set-intersection"
                    ),
                    "overlap_count": 0,
                    **(
                        {
                            "canonicalization": CANONICALIZATION,
                            "canonicalizer_sha256": canonicalizer_sha256,
                            "training_records": training_records,
                            "holdout_records": holdout_records,
                            "semantic_overlap_count": 0,
                            "similarity_algorithm": SIMILARITY_ALGORITHM,
                            "similarity_threshold": 0.8,
                            "near_duplicate_count": 0,
                        }
                        if strict_design
                        else {
                            "training_subject_sha256": [
                                f"{index:064x}" for index in range(1, 4)
                            ],
                            "holdout_subject_sha256": [
                                f"{index:064x}" for index in range(11, 14)
                            ],
                        }
                    ),
                },
            ),
            "duplicates": (
                "duplicate-analysis.json",
                {
                    "schema_version": "1.2" if strict_design else "1.0",
                    "algorithm": "parser-derived-sha256" if strict_design else "sha256",
                    "duplicate_count": 0,
                    **(
                        {
                            "canonicalization": CANONICALIZATION,
                            "canonicalizer_sha256": canonicalizer_sha256,
                            "case_records": case_records,
                            "semantic_duplicate_count": 0,
                            "similarity_algorithm": SIMILARITY_ALGORITHM,
                            "similarity_threshold": 0.8,
                            "near_duplicate_count": 0,
                        }
                        if strict_design
                        else {
                            "case_sha256": [
                                f"{index + 100:064x}" for index in range(minimum_cases)
                            ]
                        }
                    ),
                },
            ),
            "contamination": (
                "contamination-analysis.json",
                {
                    "schema_version": "1.2" if strict_design else "1.0",
                    "algorithm": (
                        "parser-derived-sha256-set-intersection"
                        if strict_design
                        else "sha256-set-intersection"
                    ),
                    "overlap_count": 0,
                    **(
                        {
                            "canonicalization": CANONICALIZATION,
                            "canonicalizer_sha256": canonicalizer_sha256,
                            "training_records": contamination_training_records,
                            "benchmark_records": benchmark_records,
                            "semantic_overlap_count": 0,
                            "similarity_algorithm": SIMILARITY_ALGORITHM,
                            "similarity_threshold": 0.8,
                            "near_duplicate_count": 0,
                        }
                        if strict_design
                        else {
                            "training_artifact_sha256": ["a" * 64],
                            "benchmark_artifact_sha256": ["b" * 64],
                        }
                    ),
                },
            ),
            "environment": (
                "environment-capture.json",
                {
                    "schema_version": "1.0",
                    "runtime": "python",
                    "runtime_version": (
                        f"{sys.version_info.major}.{sys.version_info.minor}"
                    ),
                    "platform_sha256": "c" * 64,
                    "toolset_sha256": (
                        hashlib.sha256(
                            canonical_bytes(
                                [
                                    {
                                        "name": item["name"],
                                        "sha256": item["executable_sha256"],
                                    }
                                    for item in manifest["stages"]  # type: ignore[union-attr]
                                ]
                            )
                        ).hexdigest()
                        if strict_design
                        else "d" * 64
                    ),
                    "network_policy_sha256": hashlib.sha256(
                        canonical_bytes(manifest["isolation"]["network_policy"])  # type: ignore[index]
                    ).hexdigest(),
                    "hermetic": False,
                },
            ),
        }
        for name, (filename, document) in raw_evidence.items():
            evidence_payload = json.dumps(document, sort_keys=True).encode()
            (workspace / filename).write_bytes(evidence_payload)
            raw_digests[name] = hashlib.sha256(evidence_payload).hexdigest()
        evaluation["power_analysis_sha256"] = raw_digests["power"]
        evaluation["leakage_check_sha256"] = raw_digests["leakage"]
        evaluation["duplicate_check_sha256"] = raw_digests["duplicates"]
    subject = _benchmark_subject_sha256(
        manifest,
        manifest["corpus"]["sha256"],  # type: ignore[index]
    )
    claims = {
        "trusted_time": {
            "rfc3161_verified": True,
            "monotonic_state_verified": True,
            "trusted_time_receipt_sha256": "a" * 64,
            "trusted_time_sha256": "0" * 64,
            "observed_at": datetime.now(UTC).isoformat(),
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
        "external_isolation": {
            "isolation_enforced": True,
            "network_policy_enforced": True,
            "disposable_target": True,
            "receipt_subject_verified": True,
            "runner_image_pinned": True,
            "runner_sbom_matches_image": True,
            "runner_provenance_verified": True,
            "provenance_subject_matches_image": True,
            "resource_limits_enforced": True,
            "egress_transcript_complete": True,
            "runner_image_sha256": "d" * 64,
            "resource_limits_sha256": "e" * 64,
            "network_policy_sha256": "f" * 64,
            "egress_transcript_sha256": "9" * 64,
            "target_sha256": manifest["corpus"]["sha256"],  # type: ignore[index]
        },
        "cleanup_capability": {
            "cleanup_plan_validated": True,
            "destructive_scope_validated": True,
            "target_destroyed": True,
            "cleanup_validated": True,
            "cleanup_receipt_sha256": "8" * 64,
            "target_sha256": manifest["corpus"]["sha256"],  # type: ignore[index]
            "destruction_probe_sha256": "7" * 64,
        },
    }
    if manifest.get("schema_version") in {"1.1", "1.2"}:
        evaluation = manifest["evaluation"]  # type: ignore[assignment]
        adapter_contract = manifest["adapter_contract"]  # type: ignore[assignment]
        run_stage = next(
            item
            for item in manifest["stages"]  # type: ignore[union-attr]
            if item["name"] == "run"
        )
        isolation = manifest["isolation"]  # type: ignore[assignment]
        oci = isolation.get("oci")
        image_sha256 = (
            str(oci["image"]).rsplit("@sha256:", 1)[-1]
            if isinstance(oci, dict)
            else "d" * 64
        )
        thresholds_sha256 = hashlib.sha256(
            canonical_bytes(manifest["thresholds"])
        ).hexdigest()
        environment_sha256 = raw_digests["environment"]
        network_policy_sha256 = hashlib.sha256(
            canonical_bytes(isolation["network_policy"])
        ).hexdigest()
        claims["runner_sbom"].update(
            {
                "runner_image_sha256": image_sha256,
                "sbom_subject_sha256": image_sha256,
                "sbom_document_sha256": "5" * 64,
            }
        )
        claims["runner_provenance"].update(
            {
                "runner_image_sha256": image_sha256,
                "provenance_subject_sha256": image_sha256,
                "provenance_document_sha256": "4" * 64,
                "builder_id": "https://builder.example/pysec-test",
                "builder_organization_id": "builder.example",
                **(
                    {
                        "build_type": "https://example.test/build/v1",
                        "source_repository_uri": "https://example.test/source",
                        "source_revision_sha256": "a" * 64,
                        "resolved_dependencies_sha256": hashlib.sha256(
                            canonical_bytes(
                                [
                                    {
                                        "uri": "https://example.test/source",
                                        "sha256": "a" * 64,
                                    }
                                ]
                            )
                        ).hexdigest(),
                        "resolved_dependencies_count": 1,
                    }
                    if strict_design
                    else {}
                ),
            }
        )
        claims["environment"].update(
            {
                "environment_sha256": environment_sha256,
                "environment_document_path": raw_evidence["environment"][0],
                "environment_document_sha256": environment_sha256,
            }
        )
        claims["contamination_manifest"].update(
            {
                "contamination_manifest_path": raw_evidence["contamination"][0],
                "contamination_manifest_sha256": raw_digests["contamination"],
            }
        )
        claims["external_isolation"].update(
            {
                "runner_image_sha256": image_sha256,
                "network_policy_sha256": network_policy_sha256,
                "target_sha256": manifest["corpus"]["sha256"],  # type: ignore[index]
            }
        )
        claims["acceptance_criteria"] = {
            "pre_registered": True,
            "approved": True,
            "criteria_sha256": evaluation["acceptance_criteria_sha256"],
            "thresholds_sha256": thresholds_sha256,
            "protocol": manifest["protocol"],
            "approved_before_execution": True,
            "approval_record_sha256": "3" * 64,
        }
        claims["adapter_conformance"] = {
            "passed": True,
            "parser_negative_controls_passed": True,
            "semantic_inversion_controls_passed": True,
            "adapter_spec_sha256": adapter_contract["sha256"],
            "runner_executable_sha256": run_stage["executable_sha256"],
            "normalizer": adapter_contract["normalizer"],
            "semantic_oracle_identity": "tests:expected-equals-observed:v1",
            "semantic_oracle_sha256": "4" * 64,
            "deterministic_runs": 3,
            "fixture_counts": {"golden": 3, "malformed": 3, "label_inverted": 3},
            "fixture_set_sha256": "2" * 64,
            "output_sha256": "f" * 64,
        }
        if manifest["schema_version"] == "1.1":
            claims["adapter_conformance"] = {
                "passed": True,
                "golden_passed": True,
                "malformed_rejected": True,
                "label_inversion_detected": True,
                "adapter_spec_sha256": adapter_contract["sha256"],
                "runner_executable_sha256": run_stage["executable_sha256"],
                "normalizer": adapter_contract["normalizer"],
                "deterministic_runs": 3,
                "golden_fixture_sha256": "2" * 64,
                "malformed_fixture_sha256": "1" * 64,
            }
        claims["runtime_observation"] = {
            "resource_limits_observed": True,
            "network_policy_observed": True,
            "egress_transcript_complete": True,
            "isolation_mode": isolation["mode"],
            "target_sha256": manifest["corpus"]["sha256"],  # type: ignore[index]
            "runner_image_sha256": image_sha256,
            "network_policy_sha256": network_policy_sha256,
            "resource_limits_sha256": "e" * 64,
            "egress_transcript_sha256": "9" * 64,
            "environment_sha256": environment_sha256,
            "minimum_repetitions": evaluation["minimum_repetitions"],
            "power_analysis_path": raw_evidence["power"][0],
            "power_analysis_sha256": evaluation["power_analysis_sha256"],
            "leakage_check_path": raw_evidence["leakage"][0],
            "leakage_check_sha256": evaluation["leakage_check_sha256"],
            "duplicate_check_path": raw_evidence["duplicates"][0],
            "duplicate_check_sha256": evaluation["duplicate_check_sha256"],
            "holdout_sequestered": True,
            "achieved_power": raw_evidence["power"][1]["achieved_power"],
            "leakage_detected": False,
            "duplicate_count": 0,
        }
        sbom_document = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "metadata": {
                "component": {
                    "type": "container",
                    "name": "benchmark-runner",
                    "hashes": [{"alg": "SHA-256", "content": image_sha256}],
                }
            },
            "components": [],
        }
        provenance_document = {
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [
                {"name": "benchmark-runner", "digest": {"sha256": image_sha256}}
            ],
            "predicateType": "https://slsa.dev/provenance/v1",
            "predicate": {
                "buildDefinition": {
                    "buildType": "https://example.test/build/v1",
                    "externalParameters": {
                        "source_repository_uri": "https://example.test/source",
                        "source_revision_sha256": "a" * 64,
                    },
                    "internalParameters": {},
                    "resolvedDependencies": [
                        {
                            "uri": "https://example.test/source",
                            "digest": {"sha256": "a" * 64},
                        }
                    ],
                },
                "runDetails": {
                    "builder": {"id": "https://builder.example/pysec-test"},
                    "metadata": {
                        "invocationId": "test-build-1",
                        "startedOn": "2026-08-29T00:00:00+00:00",
                        "finishedOn": "2026-08-29T00:01:00+00:00",
                    },
                },
            },
        }
        conformance_document = {
            "schema_version": "1.1",
            "adapter_spec_sha256": claims["adapter_conformance"]["adapter_spec_sha256"],
            "runner_executable_sha256": claims["adapter_conformance"][
                "runner_executable_sha256"
            ],
            "normalizer": claims["adapter_conformance"]["normalizer"],
            "semantic_oracle_identity": claims["adapter_conformance"].get(
                "semantic_oracle_identity", "legacy"
            ),
            "semantic_oracle_sha256": claims["adapter_conformance"].get(
                "semantic_oracle_sha256", "0" * 64
            ),
            "deterministic_runs": 3,
            "fixture_counts": claims["adapter_conformance"].get(
                "fixture_counts", {"golden": 3, "malformed": 3, "label_inverted": 3}
            ),
            "fixture_set_sha256": claims["adapter_conformance"].get(
                "fixture_set_sha256", "0" * 64
            ),
            "output_sha256": claims["adapter_conformance"].get(
                "output_sha256", "0" * 64
            ),
            "parser_negative_controls_passed": True,
            "semantic_inversion_controls_passed": True,
        }
        if manifest["schema_version"] == "1.1":
            conformance_document = {
                "schema_version": "1.0",
                "adapter_spec_sha256": claims["adapter_conformance"][
                    "adapter_spec_sha256"
                ],
                "runner_executable_sha256": claims["adapter_conformance"][
                    "runner_executable_sha256"
                ],
                "normalizer": claims["adapter_conformance"]["normalizer"],
                "golden_fixture_sha256": claims["adapter_conformance"][
                    "golden_fixture_sha256"
                ],
                "malformed_fixture_sha256": claims["adapter_conformance"][
                    "malformed_fixture_sha256"
                ],
                "deterministic_runs": 3,
                "golden_passed": True,
                "malformed_rejected": True,
                "label_inversion_detected": True,
                "runs": [
                    {
                        "run": run,
                        "golden_passed": True,
                        "malformed_rejected": True,
                        "label_inversion_detected": True,
                        "output_sha256": "f" * 64,
                    }
                    for run in range(1, 4)
                ],
            }
        evidence_documents = {
            "runner_sbom": ("runner-sbom.document.json", sbom_document),
            "runner_provenance": (
                "runner-provenance.document.json",
                provenance_document,
            ),
            "adapter_conformance": (
                "adapter-conformance.report.json",
                conformance_document,
            ),
        }
        for name, (filename, evidence_document) in evidence_documents.items():
            evidence_payload = json.dumps(evidence_document, sort_keys=True).encode()
            (workspace / filename).write_bytes(evidence_payload)
            path_field, digest_field = {
                "runner_sbom": ("sbom_document_path", "sbom_document_sha256"),
                "runner_provenance": (
                    "provenance_document_path",
                    "provenance_document_sha256",
                ),
                "adapter_conformance": (
                    "conformance_report_path",
                    "conformance_report_sha256",
                ),
            }[name]
            claims[name][path_field] = filename
            claims[name][digest_field] = hashlib.sha256(evidence_payload).hexdigest()
        provenance_key = Ed25519PrivateKey.generate()
        provenance_public = provenance_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        provenance_payload = canonical_bytes(provenance_document)
        provenance_type = "application/vnd.in-toto+json"
        provenance_pae = (
            b"DSSEv1 "
            + str(len(provenance_type.encode())).encode()
            + b" "
            + provenance_type.encode()
            + b" "
            + str(len(provenance_payload)).encode()
            + b" "
            + provenance_payload
        )
        provenance_key_id = hashlib.sha256(
            provenance_key.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
        ).hexdigest()
        provenance_signature = canonical_bytes(
            {
                "payloadType": provenance_type,
                "payload": base64.b64encode(provenance_payload).decode(),
                "signatures": [
                    {
                        "keyid": provenance_key_id,
                        "sig": base64.b64encode(
                            provenance_key.sign(provenance_pae)
                        ).decode(),
                    }
                ],
            }
        )
        provenance_public_path = "runner-provenance.pub.pem"
        provenance_signature_path = "runner-provenance.document.sig"
        (workspace / provenance_public_path).write_bytes(provenance_public)
        (workspace / provenance_signature_path).write_bytes(provenance_signature)
        claims["runner_provenance"].update(
            {
                "provenance_signature_format": "dsse-ed25519",
                "provenance_public_key_path": provenance_public_path,
                "provenance_public_key_sha256": hashlib.sha256(
                    provenance_public
                ).hexdigest(),
                "provenance_signature_path": provenance_signature_path,
                "provenance_signature_sha256": hashlib.sha256(
                    provenance_signature
                ).hexdigest(),
            }
        )
        observation_claims = dict(claims["runtime_observation"])
        samples = [
            {
                "repetition": repetition,
                **{
                    field: observation_claims[field]
                    for field in (
                        "target_sha256",
                        "runner_image_sha256",
                        "network_policy_sha256",
                        "resource_limits_sha256",
                        "egress_transcript_sha256",
                        "environment_sha256",
                    )
                },
                "completed": True,
            }
            for repetition in range(
                1, int(observation_claims["minimum_repetitions"]) + 1
            )
        ]
        observation_payload = json.dumps(
            {
                "schema_version": "1.0",
                "observations": observation_claims,
                "samples": samples,
            },
            sort_keys=True,
        ).encode()
        observation_path = "runtime-observation.report.json"
        (workspace / observation_path).write_bytes(observation_payload)
        claims["runtime_observation"].update(
            {
                "observation_report_path": observation_path,
                "observation_report_sha256": hashlib.sha256(
                    observation_payload
                ).hexdigest(),
            }
        )
        cleanup_document = {
            "schema_version": "1.0",
            "target_sha256": claims["cleanup_capability"]["target_sha256"],
            "destruction_probe_sha256": claims["cleanup_capability"][
                "destruction_probe_sha256"
            ],
            "target_destroyed": True,
            "cleanup_validated": True,
            "probes": [
                {"probe": "lookup", "target_absent": True},
                {"probe": "access", "target_absent": True},
            ],
        }
        cleanup_payload = json.dumps(cleanup_document, sort_keys=True).encode()
        cleanup_path = "cleanup.receipt.json"
        (workspace / cleanup_path).write_bytes(cleanup_payload)
        claims["cleanup_capability"].update(
            {
                "cleanup_receipt_path": cleanup_path,
                "cleanup_receipt_sha256": hashlib.sha256(cleanup_payload).hexdigest(),
            }
        )
    kinds = {
        "trusted_time": "trusted-time",
        "replay_protection": "replay-protection",
        "contamination_manifest": "contamination-manifest",
        "runner_sbom": "runner-sbom",
        "runner_provenance": "runner-provenance",
        "environment": "environment",
        "acceptance_criteria": "acceptance-criteria",
        "adapter_conformance": "adapter-conformance",
        "runtime_observation": "runtime-observation",
        "external_isolation": "external-isolation",
        "cleanup_capability": "cleanup-capability",
    }
    references = {}
    requested = set(manifest.get("attestations", {}))
    selected = requested or {
        "trusted_time",
        "replay_protection",
        "contamination_manifest",
        "runner_sbom",
        "runner_provenance",
        "environment",
    }
    for name, kind in kinds.items():
        if name not in selected:
            continue
        key = Ed25519PrivateKey.generate()
        public = key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        public_path = workspace / f"{name}.pub.pem"
        public_path.write_bytes(public)
        enhanced = manifest.get("schema_version") in {"1.1", "1.2"}
        document = {
            "schema_version": str(manifest["schema_version"]) if enhanced else "1.0",
            "kind": kind,
            "subject_sha256": subject,
            "valid": True,
            "claims": claims[name],
        }
        if enhanced:
            issued = datetime.now(UTC) - timedelta(minutes=1)
            document["authority"] = {
                "organization_id": f"test-authority-{name}",
                "role": kind,
                "issued_at": issued.isoformat(),
                "expires_at": (issued + timedelta(days=30)).isoformat(),
                "revocation_status_sha256": "a" * 64,
            }
        payload = json.dumps(
            document,
            sort_keys=True,
        ).encode()
        artifact = workspace / f"{name}.json"
        signature = workspace / f"{name}.sig"
        artifact.write_bytes(payload)
        signature.write_bytes(base64.b64encode(key.sign(payload)))
        references[name] = {
            "path": artifact.name,
            "sha256": hashlib.sha256(payload).hexdigest(),
            "media_type": (
                f"application/vnd.pysec.attestation+json;version={manifest['schema_version']}"
                if enhanced
                else "application/vnd.pysec.attestation+json;version=1.0"
            ),
            "public_key_path": public_path.name,
            "public_key_sha256": hashlib.sha256(public).hexdigest(),
            "signature_path": signature.name,
        }
    manifest["attestations"] = references


def _write_deployment_trust_policy(
    workspace: Path, manifest: dict[str, object]
) -> dict[str, object]:
    authorities = []
    for reference in manifest["attestations"].values():  # type: ignore[union-attr]
        document = json.loads(
            (workspace / reference["path"]).read_text(encoding="utf-8")
        )
        authorities.append(
            {
                "role": document["kind"],
                "organization_id": document["authority"]["organization_id"],
                "public_key_sha256": hashlib.sha256(
                    serialization.load_pem_public_key(
                        (workspace / reference["public_key_path"]).read_bytes()
                    ).public_bytes(
                        encoding=serialization.Encoding.Raw,
                        format=serialization.PublicFormat.Raw,
                    )
                ).hexdigest(),
                "revocation_status_sha256": document["authority"][
                    "revocation_status_sha256"
                ],
                "status": "active",
            }
        )
    provenance_reference = manifest["attestations"]["runner_provenance"]  # type: ignore[index]
    provenance_document = json.loads(
        (workspace / provenance_reference["path"]).read_text(encoding="utf-8")
    )
    builder_public = serialization.load_pem_public_key(
        (
            workspace / provenance_document["claims"]["provenance_public_key_path"]
        ).read_bytes()
    )
    authorities.append(
        {
            "role": "provenance-builder",
            "organization_id": provenance_document["claims"]["builder_organization_id"],
            "public_key_sha256": hashlib.sha256(
                builder_public.public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw,
                )
            ).hexdigest(),
            "revocation_status_sha256": "c" * 64,
            "status": "active",
        }
    )
    receipt_key = Ed25519PrivateKey.generate()
    receipt_key_payload = receipt_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    receipt_key_path = workspace.parent / f"{workspace.name}-receipt-key.pem"
    receipt_key_path.write_bytes(receipt_key_payload)
    receipt_key_id = hashlib.sha256(
        receipt_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    ).hexdigest()
    authorities.append(
        {
            "role": "execution-receipt",
            "organization_id": "test-receipt-authority",
            "public_key_sha256": receipt_key_id,
            "revocation_status_sha256": "b" * 64,
            "status": "active",
        }
    )
    issued = datetime.now(UTC) - timedelta(minutes=1)
    policy = {
        "schema_version": "1.0",
        "policy_id": "test-benchmark-authority",
        "issued_at": issued.isoformat(),
        "expires_at": (issued + timedelta(days=30)).isoformat(),
        "minimum_distinct_signers": 4,
        "minimum_distinct_organizations": 2,
        "authorities": authorities,
    }
    payload = json.dumps(policy, sort_keys=True).encode()
    policy_path = workspace.parent / f"{workspace.name}-authority-policy.json"
    policy_path.write_bytes(payload)
    root_key = Ed25519PrivateKey.generate()
    root_payload = root_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    root_path = workspace.parent / f"{workspace.name}-authority-root.pem"
    root_path.write_bytes(root_payload)
    signature_path = workspace.parent / f"{workspace.name}-authority-policy.sig"
    signature_path.write_bytes(base64.b64encode(root_key.sign(payload)))
    trusted_time_path = workspace.parent / f"{workspace.name}-trusted-time.json"
    trusted_time_payload = json.dumps(
        {"schema_version": "1.0", "trusted_time": {}}, sort_keys=True
    ).encode()
    trusted_time_path.write_bytes(trusted_time_payload)
    ledger = workspace.parent / f"{workspace.name}-benchmark-replay.sqlite3"
    checkpoint_state = workspace.parent / f"{workspace.name}-replay-checkpoint.json"
    return {
        "authority_trust_policy": policy_path,
        "authority_trust_policy_sha256": hashlib.sha256(payload).hexdigest(),
        "authority_trust_policy_signature": signature_path,
        "authority_trust_root": root_path,
        "authority_trust_root_sha256": hashlib.sha256(root_payload).hexdigest(),
        "trusted_time_context": trusted_time_path,
        "trusted_time_context_sha256": hashlib.sha256(trusted_time_payload).hexdigest(),
        "replay_ledger": ledger,
        "replay_checkpoint_state": checkpoint_state,
        "initialize_replay_checkpoint": True,
        "receipt_signing_key": receipt_key_path,
        "receipt_signing_key_sha256": hashlib.sha256(receipt_key_payload).hexdigest(),
    }


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
        allow_legacy_unregistered=True,
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
    events: list[dict[str, object]] = []
    with pytest.raises(BenchmarkExecutionError, match="authorize-execution"):
        execute_benchmark_manifest(
            tmp_path / "missing.json",
            tmp_path,
            authorized=False,
            security_event_sink=events.append,
        )
    assert [event["control"] for event in events] == [
        "execution-authorization",
        "benchmark-execution",
    ]
    assert all(event["outcome"] == "failed" for event in events)


def test_rejects_process_network_isolation_claim(tmp_path: Path) -> None:
    (tmp_path / "corpus.bin").write_bytes(b"pinned corpus")
    (tmp_path / "adapter.py").write_text("pass\n", encoding="utf-8")
    manifest = _manifest(tmp_path)
    manifest["benchmark_version"] = benchmark_execution_contracts()["droidbench"][
        "version"
    ]
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
            allow_legacy_unregistered=True,
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
        execute_benchmark_manifest(
            path, tmp_path, authorized=True, allow_legacy_unregistered=True
        )


def test_default_registry_contract_rejects_legacy_process_for_high_risk_lane(
    tmp_path: Path,
) -> None:
    (tmp_path / "corpus.bin").write_bytes(b"pinned corpus")
    (tmp_path / "adapter.py").write_text("pass\n", encoding="utf-8")
    manifest = _manifest(tmp_path)
    manifest["benchmark_version"] = benchmark_execution_contracts()["droidbench"][
        "version"
    ]
    _write_attestations(tmp_path, manifest)
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(BenchmarkExecutionError, match="schema 1.1"):
        execute_benchmark_manifest(
            path,
            tmp_path,
            authorized=True,
        )


def test_compiler_binds_maintained_inputs_and_registry_safety(tmp_path: Path) -> None:
    executable = Path(sys.executable).resolve()
    (tmp_path / "corpus.bin").write_bytes(b"pinned corpus")
    for name in ("source-projects", "apk-set", "source-sink-labels", "android-image"):
        (tmp_path / name).write_text(name, encoding="utf-8")
    reference = {
        "path": "pending.json",
        "sha256": "0" * 64,
        "media_type": "application/vnd.pysec.attestation+json;version=1.2",
        "public_key_path": "pending.pem",
        "public_key_sha256": "0" * 64,
        "signature_path": "pending.sig",
    }
    request = {
        "schema_version": "1.0",
        "benchmark_id": "droidbench",
        "adapter_version": "1.0.0",
        "corpus": {
            "path": "corpus.bin",
            "license_sha256": "1" * 64,
            "label_authority_sha256": "2" * 64,
            "organization_approved": True,
        },
        "required_inputs": {
            name: name
            for name in (
                "source-projects",
                "apk-set",
                "source-sink-labels",
                "android-image",
            )
        },
        "stages": [
            {
                "name": name,
                "executable": str(executable),
                "arguments": ["-c", "pass"],
                "environment": {},
                "timeout_seconds": 10,
                "expected_exit_codes": [0],
            }
            for name in ("run", "cleanup")
        ],
        "normalized_result": {"path": "normalized-result.json", "sha256": None},
        "thresholds": {
            "minimum_precision": 0.8,
            "minimum_recall": 0.8,
            "minimum_f1": 0.8,
            "maximum_false_positive_rate": 0.1,
        },
        "evaluation": _strong_evaluation(),
        "authority_policy": _authority_policy(),
        "isolation": {
            "mode": "external-sandbox",
            "network_policy": "authorized-target-only",
            "disposable_target": True,
            "external_receipt_sha256": "0" * 64,
            "oci": None,
        },
        "attestations": {
            name: dict(reference)
            for name in (
                "trusted_time",
                "replay_protection",
                "contamination_manifest",
                "runner_sbom",
                "runner_provenance",
                "environment",
                "acceptance_criteria",
                "adapter_conformance",
                "runtime_observation",
                "external_isolation",
                "cleanup_capability",
            )
        },
    }
    request_path = tmp_path / "request.json"
    request_path.write_text(json.dumps(request), encoding="utf-8")

    result = compile_benchmark_manifest(request_path, tmp_path)
    manifest = result["manifest"]

    assert manifest["schema_version"] == "1.2"
    assert (
        manifest["benchmark_version"]
        == benchmark_execution_contracts()["droidbench"]["version"]
    )
    assert len(manifest["adapter_contract"]["required_inputs"]) == 4
    assert all(
        len(item["sha256"]) == 64
        for item in manifest["adapter_contract"]["required_inputs"]
    )
    assert manifest["isolation"]["disposable_target"] is True
    assert {stage["name"] for stage in manifest["stages"]} == {"run", "cleanup"}


def test_protocol_sufficiency_rejects_tiny_or_unbalanced_samples() -> None:
    tiny = [
        {"expected_positive": True},
        {"expected_positive": False},
    ]
    gaps = protocol_sufficiency_gaps("classification", tiny)
    assert "protocol requires at least 20 cases" in gaps
    assert "classification protocol requires at least five positive cases" in gaps
    assert "classification protocol requires at least five negative cases" in gaps


def test_authority_policy_rejects_shared_keys_and_organizations() -> None:
    results = {
        name: {
            "signer_key_id": "a" * 64,
            "authority": {"organization_id": "shared-authority"},
        }
        for name in ("trusted_time", "replay_protection")
    }
    policy = {
        "minimum_distinct_signers": 1,
        "minimum_distinct_organizations": 1,
        "key_separation_groups": [["trusted_time", "replay_protection"]],
        "organization_separation_groups": [["trusted_time", "replay_protection"]],
    }

    with pytest.raises(BenchmarkExecutionError, match="separation"):
        _enforce_authority_policy(results, policy)


def test_conservative_thresholds_use_confidence_bounds() -> None:
    metrics = _score_normalized_result(
        {
            "schema_version": "1.0",
            "benchmark_id": "droidbench",
            "protocol": "classification",
            "cases": [
                {
                    "id": f"case-{index}",
                    "expected_positive": index < 10,
                    "observed_positive": index < 10,
                    "strata": {},
                }
                for index in range(20)
            ],
        },
        benchmark_id="droidbench",
        protocol="classification",
    )
    metrics.pop("case_count")

    assert (
        _threshold_failures(
            metrics,
            {
                "minimum_precision": 0.9,
                "minimum_recall": 0.9,
                "minimum_f1": 0.9,
                "maximum_false_positive_rate": 0.1,
            },
            conservative=False,
        )
        == []
    )
    assert _threshold_failures(
        metrics,
        {
            "minimum_precision": 0.9,
            "minimum_recall": 0.9,
            "minimum_f1": 0.9,
            "maximum_false_positive_rate": 0.1,
        },
        conservative=True,
    )


@pytest.mark.parametrize("schema_version", ["1.1", "1.2"])
def test_registry_bound_receipt_is_direct_scorecard_evidence(
    tmp_path: Path, schema_version: str
) -> None:
    (tmp_path / "corpus.bin").write_bytes(b"pinned corpus")
    contracts = benchmark_execution_contracts()
    contract = contracts["droidbench"]
    for name in contract["required_inputs"]:
        (tmp_path / name).write_text(name, encoding="utf-8")
    cases = [
        {
            "id": f"positive-{index}",
            "expected_positive": True,
            "observed_positive": True,
            "strata": {"cwe": "CWE-200"},
        }
        for index in range(10)
    ] + [
        {
            "id": f"negative-{index}",
            "expected_positive": False,
            "observed_positive": False,
            "strata": {"cwe": "CWE-200"},
        }
        for index in range(10)
    ]
    normalized = {
        "schema_version": "1.0",
        "benchmark_id": "droidbench",
        "protocol": "classification",
        "cases": cases,
    }
    (tmp_path / "adapter.py").write_text(
        "import json\nfrom pathlib import Path\n"
        f"Path('normalized-result.json').write_text({json.dumps(json.dumps(normalized))}, encoding='utf-8')\n",
        encoding="utf-8",
    )
    manifest = _manifest(tmp_path)
    manifest.update(
        {
            "schema_version": schema_version,
            "benchmark_version": contract["version"],
            "adapter_contract": {
                "id": "droidbench",
                "version": "1.0",
                "sha256": contract["adapter_spec_sha256"],
                "normalizer": contract["normalizer"],
                "required_inputs": [
                    {
                        "name": name,
                        "path": name,
                        "sha256": _sha256(tmp_path / name),
                        "validation": validate_benchmark_input(tmp_path / name),
                    }
                    for name in contract["required_inputs"]
                ],
            },
            "evaluation": _strong_evaluation(),
            "authority_policy": _authority_policy(),
            "isolation": {
                "mode": "external-sandbox",
                "network_policy": "authorized-target-only",
                "disposable_target": True,
                "external_receipt_sha256": "0" * 64,
                "oci": None,
            },
        }
    )
    manifest["stages"].append(  # type: ignore[union-attr]
        {
            "name": "cleanup",
            "executable": str(Path(sys.executable).resolve()),
            "executable_sha256": _sha256(Path(sys.executable).resolve()),
            "arguments": ["-c", "pass"],
            "environment": {},
            "timeout_seconds": 10,
            "expected_exit_codes": [0],
        }
    )
    manifest["attestations"] = {
        name: {}
        for name in (
            "trusted_time",
            "replay_protection",
            "contamination_manifest",
            "runner_sbom",
            "runner_provenance",
            "environment",
            "acceptance_criteria",
            "adapter_conformance",
            "runtime_observation",
            "external_isolation",
            "cleanup_capability",
        )
    }
    _write_attestations(tmp_path, manifest)
    deployment = _write_deployment_trust_policy(tmp_path, manifest)
    manifest["isolation"]["external_receipt_sha256"] = manifest["attestations"][  # type: ignore[index]
        "external_isolation"
    ]["sha256"]
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")

    trusted_claims = json.loads(
        (tmp_path / manifest["attestations"]["trusted_time"]["path"]).read_text()
    )["claims"]
    trusted_result = {
        "trusted_time_sha256": trusted_claims["trusted_time_sha256"],
        "trusted_time_observed_at": trusted_claims["observed_at"],
        "trusted_time_receipt_sha256": trusted_claims["trusted_time_receipt_sha256"],
        "trusted_time_signer_sha256": "f" * 64,
    }
    with (
        patch.dict(
            "os.environ",
            {
                "PYSEC_TRUSTED_TIME_STATE_PATH": str(
                    tmp_path.parent / "trusted-time-state.sqlite3"
                )
            },
        ),
        patch(
            "py_security_suite.benchmark_evidence.verify_rfc3161",
            return_value=trusted_result,
        ),
    ):
        receipt = execute_benchmark_manifest(
            path,
            tmp_path,
            authorized=True,
            benchmark_contracts=contracts,
            **deployment,
        )
        with pytest.raises(BenchmarkExecutionError, match="already consumed"):
            execute_benchmark_manifest(
                path,
                tmp_path,
                authorized=True,
                benchmark_contracts=contracts,
                **deployment,
            )
    policy = {
        "schema_version": "1.3",
        "enforce": True,
        "profiles": [],
        "controls": [],
        "procedures": [],
        "benchmarks": [
            {
                "id": "droidbench",
                "enabled": True,
                "corpus_sha256": manifest["corpus"]["sha256"],  # type: ignore[index]
                "evidence_artifact": "droidbench.json",
                "thresholds": dict(manifest["thresholds"]),  # type: ignore[arg-type]
                "adapter_manifest": "security/benchmark-adapters/droidbench.json",
            }
        ],
        "benchmark_baseline_path": None,
    }
    authority_policy = {
        "policy_id": "test-receipt-authorities",
        "sha256": "c" * 64,
        "trust_root_key_id": "d" * 64,
        "issued_at": (datetime.now(UTC) - timedelta(days=1)).isoformat(),
        "expires_at": (datetime.now(UTC) + timedelta(days=1)).isoformat(),
        "execution_receipt_authorities": [
            {
                "role": "execution-receipt",
                "public_key_sha256": receipt["receipt_signature"]["signer_key_id"],
                "organization_id": receipt["receipt_signature"]["organization_id"],
                "key_version": receipt["receipt_signature"]["key_version"],
                "status": "active",
                "valid_from": (datetime.now(UTC) - timedelta(days=1)).isoformat(),
                "valid_until": (datetime.now(UTC) + timedelta(days=1)).isoformat(),
                "revoked_at": None,
            }
        ],
    }
    registered = next(
        item
        for item in _benchmark_registry(policy, "b" * 64, authority_policy)[
            "benchmarks"
        ]
        if item["id"] == "droidbench"
    )

    assert receipt["decision"] == "pass"
    assert receipt["statistical_sufficiency"]["complete"] is True
    assert receipt["input_integrity"]["verified_after_execution"] is True
    assert receipt["evidence_documents"]["verified"] is True
    assert receipt["receipt_signature"]["algorithm"] == "Ed25519"
    receipt_schema = json.loads(
        read_bundled_schema(f"benchmark-execution-receipt-{schema_version}")
    )
    Draft202012Validator(receipt_schema).validate(receipt)
    attestation_schema = json.loads(
        read_bundled_schema(f"benchmark-attestation-{schema_version}")
    )
    for reference in manifest["attestations"].values():  # type: ignore[union-attr]
        document = json.loads(
            (tmp_path / reference["path"]).read_text(encoding="utf-8")
        )
        Draft202012Validator(attestation_schema).validate(document)
    assert _benchmark_reproducibility_gaps(receipt, registered) == []
    unanchored = {**registered, "trusted_receipt_authorities": []}
    assert (
        "benchmark execution receipt signature lacks lifecycle-aware trusted-party admission"
        in _benchmark_reproducibility_gaps(receipt, unanchored)
    )
    revoked_authority = {
        **registered["trusted_receipt_authorities"][0],
        "status": "revoked",
        "revoked_at": (datetime.now(UTC) - timedelta(minutes=1)).isoformat(),
    }
    assert "benchmark execution receipt signature is invalid" in (
        _benchmark_reproducibility_gaps(
            receipt, {**registered, "trusted_receipt_authorities": [revoked_authority]}
        )
    )
    wrong_anchor = {
        **registered,
        "trusted_receipt_authorities": [
            {**registered["trusted_receipt_authorities"][0], "key_id": "f" * 64}
        ],
    }
    assert "benchmark execution receipt signature is invalid" in (
        _benchmark_reproducibility_gaps(receipt, wrong_anchor)
    )
    tampered_receipt = {**receipt, "decision": "fail", "verdict": "fail"}
    assert "benchmark execution receipt signature is invalid" in (
        _benchmark_reproducibility_gaps(tampered_receipt, registered)
    )


def test_enhanced_attestation_runtime_rejects_surplus_claims() -> None:
    now = datetime.now(UTC)
    document = {
        "schema_version": "1.1",
        "kind": "trusted-time",
        "subject_sha256": "a" * 64,
        "valid": True,
        "authority": {
            "organization_id": "time-authority",
            "role": "trusted-time",
            "issued_at": (now - timedelta(minutes=1)).isoformat(),
            "expires_at": (now + timedelta(days=1)).isoformat(),
            "revocation_status_sha256": "b" * 64,
        },
        "claims": {
            "rfc3161_verified": True,
            "monotonic_state_verified": True,
            "trusted_time_receipt_sha256": "c" * 64,
            "observed_at": now.isoformat(),
            "unreviewed_assertion": True,
        },
    }

    with pytest.raises(BenchmarkExecutionError, match="violates schema"):
        _validate_attestation_document(
            document,
            "trusted-time",
            "a" * 64,
            require_authority=True,
        )


def test_post_execution_integrity_detects_mutated_corpus_and_evidence(
    tmp_path: Path,
) -> None:
    corpus = tmp_path / "corpus.bin"
    corpus.write_bytes(b"approved corpus")
    evidence = tmp_path / "evidence.json"
    evidence.write_text("{}", encoding="utf-8")
    manifest = _manifest(tmp_path)
    snapshot = {str(evidence): _sha256(evidence)}

    corpus.write_bytes(b"mutated corpus")
    evidence.write_text('{"altered":true}', encoding="utf-8")

    gaps = _runtime_input_integrity_gaps(manifest, tmp_path, corpus, snapshot)

    assert "benchmark corpus changed during execution" in gaps
    assert "immutable evidence changed during execution: evidence.json" in gaps


def test_trusted_time_rejects_future_observation() -> None:
    with pytest.raises(BenchmarkExecutionError, match="stale or in the future"):
        _trusted_attestation_time(
            {"observed_at": (datetime.now(UTC) + timedelta(minutes=2)).isoformat()}
        )


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
    stage["environment"] = {"BENCHMARK_SEED": "17"}
    (tmp_path / ".pysec-output").mkdir()
    isolation = {
        "mode": "oci",
        "network_policy": "deny",
        "disposable_target": True,
        "external_receipt_sha256": None,
        "oci": {
            "runtime": str(executable),
            "runtime_sha256": _sha256(executable),
            "runtime_name": "docker",
            "runtime_version": "27.0.0",
            "runtime_capabilities_sha256": "a" * 64,
            "runtime_trust_sha256": "b" * 64,
            "image": "registry.example/adapter@sha256:" + "d" * 64,
            "memory_bytes": 536870912,
            "cpu_count": 2,
            "pids_limit": 128,
            "seccomp_profile": None,
            "seccomp_profile_sha256": None,
            "apparmor_profile": "pysec-benchmark",
            "maximum_output_bytes": 536870912,
            "maximum_output_files": 10000,
        },
    }
    argv, runtime_digest = _stage_argv(
        executable, stage, isolation, tmp_path, tmp_path / "corpus.bin"
    )
    assert runtime_digest == _sha256(executable)
    assert "--read-only" in argv
    assert "--cap-drop=ALL" in argv
    assert "--network=none" in argv
    assert "--pull=never" in argv
    assert "--init" in argv
    assert "--ulimit=nofile=1024:1024" in argv
    assert f"--volume={tmp_path}:/workspace:ro" in argv
    assert f"--volume={tmp_path / '.pysec-output'}:/workspace/.pysec-output:rw" in argv
    assert "--env=BENCHMARK_SEED" in argv
    workspace_environment = "--env=PYSEC_BENCHMARK_WORKSPACE=/workspace"  # pragma: allowlist secret
    assert workspace_environment in argv
    assert argv[-2] == "/pysec/stage-executable"


def test_actively_verifies_and_pins_oci_runtime_capabilities(tmp_path: Path) -> None:
    runtime = tmp_path / "docker"
    runtime.write_bytes(b"runtime")
    version = "Docker version 27.0.0"
    run_help = "usage: run " + " ".join(_OCI_REQUIRED_RUN_OPTIONS)
    proof = {
        "schema_version": "1.0",
        "runtime_name": "docker",
        "runtime_sha256": _sha256(runtime),
        "runtime_version": "27.0.0",
        "required_run_options": list(_OCI_REQUIRED_RUN_OPTIONS),
        "version_output_sha256": hashlib.sha256(version.encode()).hexdigest(),
        "run_help_sha256": hashlib.sha256(run_help.encode()).hexdigest(),
    }
    capabilities_sha256 = hashlib.sha256(canonical_bytes(proof)).hexdigest()
    oci = {
        "runtime": str(runtime),
        "runtime_sha256": _sha256(runtime),
        "runtime_name": "docker",
        "runtime_version": "27.0.0",
        "runtime_capabilities_sha256": capabilities_sha256,
    }
    responses = [
        BoundedProcessResult(0, version.encode(), b""),
        BoundedProcessResult(0, run_help.encode(), b""),
    ]
    with patch(
        "py_security_suite.benchmark_runtime.run_bounded_subprocess",
        side_effect=responses,
    ):
        result = verify_oci_runtime_capabilities(oci)
    assert result == {**proof, "runtime_capabilities_sha256": capabilities_sha256}


def test_oci_runtime_probe_rejects_missing_containment_option(tmp_path: Path) -> None:
    runtime = tmp_path / "docker"
    runtime.write_bytes(b"runtime")
    responses = [
        BoundedProcessResult(0, b"Docker version 27.0.0", b""),
        BoundedProcessResult(0, b"--read-only --network", b""),
    ]
    with (
        patch(
            "py_security_suite.benchmark_runtime.run_bounded_subprocess",
            side_effect=responses,
        ),
        pytest.raises(ValueError, match="lacks required containment options"),
    ):
        verify_oci_runtime_capabilities(
            {
                "runtime": str(runtime),
                "runtime_sha256": _sha256(runtime),
                "runtime_name": "docker",
                "runtime_version": "27.0.0",
                "runtime_capabilities_sha256": "a" * 64,
            }
        )


def test_oci_rejects_changed_seccomp_profile_and_bounded_output(
    tmp_path: Path,
) -> None:
    corpus = tmp_path / "corpus.bin"
    corpus.write_bytes(b"pinned corpus")
    executable = Path(sys.executable).resolve()
    stage = _manifest(tmp_path)["stages"][0]  # type: ignore[index]
    profile = tmp_path / "seccomp.json"
    profile.write_text('{"defaultAction":"SCMP_ACT_ERRNO"}', encoding="utf-8")
    isolation = {
        "mode": "oci",
        "network_policy": "deny",
        "disposable_target": True,
        "external_receipt_sha256": None,
        "oci": {
            "runtime": str(executable),
            "runtime_sha256": _sha256(executable),
            "runtime_name": "docker",
            "runtime_version": "27.0.0",
            "runtime_capabilities_sha256": "a" * 64,
            "runtime_trust_sha256": "b" * 64,
            "image": "registry.example/adapter@sha256:" + "d" * 64,
            "memory_bytes": 536870912,
            "cpu_count": 2,
            "pids_limit": 128,
            "seccomp_profile": str(profile),
            "seccomp_profile_sha256": "0" * 64,
            "apparmor_profile": None,
            "maximum_output_bytes": 1,
            "maximum_output_files": 1,
        },
    }
    with pytest.raises(BenchmarkExecutionError, match="seccomp profile digest"):
        _stage_argv(executable, stage, isolation, tmp_path, corpus)

    output = tmp_path / ".pysec-output"
    output.mkdir()
    (output / "one").write_bytes(b"12")
    (output / "two").write_bytes(b"3")
    gaps = _oci_output_gaps(output, isolation["oci"])
    assert "OCI output file count exceeds the manifest limit" in gaps
    assert "OCI output bytes exceed the manifest limit" in gaps


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


def test_policy_1_3_uses_protocol_specific_threshold_contracts() -> None:
    benchmark = {
        "id": "w3c-act-rules-conformance",
        "enabled": True,
        "corpus_sha256": "a" * 64,
        "evidence_artifact": "w3c-conformance.json",
        "thresholds": {
            "minimum_outcome_accuracy": 0.95,
            "minimum_conformance_rate": 0.9,
        },
        "adapter_manifest": "security/benchmark-adapters/w3c.json",
    }
    policy = {
        "schema_version": "1.3",
        "enforce": True,
        "profiles": [],
        "controls": [],
        "procedures": [],
        "benchmarks": [benchmark],
        "benchmark_baseline_path": None,
    }

    _validate_policy(policy)
    registry = _benchmark_registry(policy, "b" * 64)
    registered = next(
        item
        for item in registry["benchmarks"]
        if item["id"] == "w3c-act-rules-conformance"
    )
    assert registered["thresholds"] == benchmark["thresholds"]

    benchmark["thresholds"] = {
        "minimum_precision": 0.9,
        "minimum_recall": 0.9,
        "minimum_f1": 0.9,
        "maximum_false_positive_rate": 0.1,
    }
    with pytest.raises(ValueError, match="thresholds must contain exactly"):
        _validate_policy(policy)
