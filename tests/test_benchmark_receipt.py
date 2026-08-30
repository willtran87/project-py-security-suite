from __future__ import annotations

from py_security_suite.benchmark_receipt import build_benchmark_execution_receipt


def test_receipt_builder_preserves_trust_replay_and_failure_boundaries() -> None:
    manifest = {
        "schema_version": "1.2",
        "benchmark_id": "benchmark-1",
        "protocol": "classification",
        "benchmark_version": "2026.08",
        "adapter_version": "1.0",
        "corpus": {
            "organization_approved": True,
            "license_sha256": "1" * 64,
            "label_authority_sha256": "2" * 64,
        },
        "thresholds": {"minimum_recall": 0.9},
        "isolation": {"mode": "oci"},
    }
    trust_policy = {
        "policy_id": "deployment-policy",
        "sha256": "3" * 64,
        "minimum_distinct_signers": 2,
        "minimum_distinct_organizations": 2,
        "trust_root_key_id": "4" * 64,
    }
    receipt = build_benchmark_execution_receipt(
        manifest=manifest,
        execution_id="5" * 64,
        manifest_sha256="6" * 64,
        manifest_path="manifest.json",
        corpus_sha256="7" * 64,
        normalized_result_sha256="8" * 64,
        started_at="2026-08-30T12:00:00+00:00",
        case_count=20,
        metrics={"recall": 0.8},
        statistical_sufficiency={"enforced": True, "complete": True, "gaps": []},
        input_integrity_gaps=["corpus changed"],
        subject_sha256="9" * 64,
        attestations={"replay_protection": {"replay_protected": True}},
        evidence_documents={"verified": True},
        replay_receipt={"sequence": 4},
        replay_checkpoint_state={"sequence": 4},
        trust_policy=trust_policy,
        trusted_time_proof={"trusted_time_sha256": "a" * 64},
        stages=[{"name": "run", "status": "passed"}],
        isolation_runtime_proof={"verified": True},
        decision="fail",
        failure_reason="corpus changed",
    )

    assert receipt["schema_version"] == "1.2"
    assert receipt["verdict"] == receipt["decision"] == "fail"
    assert receipt["input_integrity"]["verified_after_execution"] is False
    assert receipt["replay_protected"] is True
    assert receipt["authority_trust_policy"] == trust_policy
    assert receipt["completed_at"].endswith("+00:00")


def test_receipt_builder_supports_legacy_unsigned_trust_fields() -> None:
    manifest = {
        "schema_version": "1.0",
        "benchmark_id": "legacy",
        "protocol": "classification",
        "benchmark_version": "1",
        "adapter_version": "1",
        "corpus": {
            "organization_approved": True,
            "license_sha256": "1" * 64,
            "label_authority_sha256": "2" * 64,
        },
        "thresholds": {},
        "isolation": {"mode": "process"},
    }
    receipt = build_benchmark_execution_receipt(
        manifest=manifest,
        execution_id="3" * 64,
        manifest_sha256="4" * 64,
        manifest_path="manifest.json",
        corpus_sha256="5" * 64,
        normalized_result_sha256=None,
        started_at="2026-08-30T12:00:00+00:00",
        case_count=0,
        metrics=None,
        statistical_sufficiency={"enforced": False, "complete": True, "gaps": []},
        input_integrity_gaps=[],
        subject_sha256="6" * 64,
        attestations={"replay_protection": {"replay_protected": False}},
        evidence_documents=None,
        replay_receipt=None,
        replay_checkpoint_state=None,
        trust_policy=None,
        trusted_time_proof=None,
        stages=[],
        isolation_runtime_proof=None,
        decision="pass",
        failure_reason=None,
    )
    assert receipt["authority_trust_policy"] is None
    assert receipt["input_integrity"]["verified_after_execution"] is True
