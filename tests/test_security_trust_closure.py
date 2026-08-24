from __future__ import annotations

from datetime import UTC, datetime, timedelta
import hashlib
import base64
import gzip
import io
import json
import tarfile
from unittest.mock import patch
from pathlib import Path
import sqlite3
from contextlib import closing

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from py_security_suite.artifact_validation import (
    _OPERATION_STATE_GENESIS_SHA256,
    _contains_operation_receipt,
    _consume_operation_receipts,
    _validate_operation_receipt_graph,
)
from py_security_suite.requirements_coverage import _procedure_manifests_valid
from py_security_suite.requirements_coverage import _runtime_sbom_covers_closure
from py_security_suite.requirements_coverage import _oci_manifest_valid
from py_security_suite.requirements_coverage import _safe_oci_layer
from py_security_suite.checkpoint_authority import publish_checkpoint
from py_security_suite.attestation_formats import verify_format_evidence
from py_security_suite.failure_domain import (
    _verify_consistency,
    verify_registered_failure_domain,
)
from py_security_suite.operation_receipt import verify_operation_receipt
from py_security_suite.boundary_graph import _canary_results_valid
from py_security_suite.native_evidence import _provider_audit_readback
from py_security_suite.strict_json import canonical_bytes
from py_security_suite.runtime_trace import _verify_raw_spans
from py_security_suite.trust_policy import (
    _advance_policy_state,
    capture_trust_environment,
)
from py_security_suite.trusted_time import (
    _TRUSTED_TIME_STATE_GENESIS_SHA256,
    _advance_time_state,
)
from tests.deployment_authority import effective_policy_attestation, operation_receipt


def test_explicit_policy_state_is_anchored_before_local_advance(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = tmp_path / "policy-state.sqlite3"
    monkeypatch.setenv("PYSEC_EXPLICIT_TRUST_POLICY_STATE_PATH", str(state))
    monkeypatch.setenv("PYSEC_REQUIRE_EXTERNAL_POLICY_STATE_CHECKPOINT", "1")
    captured: list[tuple[str, dict[str, object], bool]] = []

    def checkpoint(
        prefix: str, subject: dict[str, object], *, required: bool
    ) -> dict[str, object]:
        captured.append((prefix, subject, required))
        return {"accepted": True}

    with patch("py_security_suite.checkpoint_authority.publish_checkpoint", checkpoint):
        _advance_policy_state(
            {"generation": 1, "previous_policy_sha256": ""},
            "a" * 64,
            required=True,
        )
    assert captured == [
        (
            "PYSEC_TRUST_POLICY_STATE_CHECKPOINT",
            {
                "schema_version": "1.0",
                "namespace": "explicit-trust-policy",
                "previous": {"generation": 0, "policy_sha256": ""},
                "proposed": {"generation": 1, "policy_sha256": "a" * 64},
            },
            True,
        )
    ]


def test_operation_receipt_graph_rejects_forked_roots() -> None:
    key = Ed25519PrivateKey.generate()
    receipts = [
        operation_receipt(
            {"run": index},
            purpose="test-operation",
            operation_id=f"run-{index}",
            private_key=key,
        )[0]
        for index in range(2)
    ]
    with pytest.raises(ValueError, match="exactly one root"):
        _validate_operation_receipt_graph({"receipts": receipts})


def test_operation_receipt_validator_discovery_is_structural() -> None:
    receipt, _ = operation_receipt(
        {"run": 1}, purpose="test-operation", operation_id="discover-1"
    )
    assert _contains_operation_receipt({"nested": [{"receipt": receipt}]}) is True
    assert (
        _contains_operation_receipt(
            {
                "payloadType": "application/vnd.in-toto+json",
                "payload": "e30=",
                "signatures": [{"keyid": "builder", "sig": "c2ln"}],
            }
        )
        is True
    )
    assert (
        _contains_operation_receipt(
            {
                "payload": "e30=",
                "signatures": [{"protected": "e30=", "signature": "c2ln"}],
            }
        )
        is True
    )
    assert _contains_operation_receipt({"cose_sign1_base64": "0oRDoQEmoA=="}) is True
    assert _contains_operation_receipt({"nested": [{"receipt": {}}]}) is False
    receipt["revision_metadata"] = {"format": "v2"}
    assert _contains_operation_receipt({"nested": [{"receipt": receipt}]}) is True


def test_external_checkpoint_fails_closed_when_required(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("PYSEC_TEST_CHECKPOINT_COMMAND_JSON", raising=False)
    with pytest.raises(ValueError, match="unavailable"):
        publish_checkpoint(
            "PYSEC_TEST_CHECKPOINT",
            {"schema_version": "1.0", "checkpoint_sha256": "a" * 64},
            required=True,
        )


def test_external_checkpoint_quorum_fails_when_threshold_is_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(
        "PYSEC_TEST_CHECKPOINT_QUORUM_PREFIXES_JSON",
        '["PYSEC_CHECKPOINT_A","PYSEC_CHECKPOINT_B"]',
    )
    monkeypatch.setenv("PYSEC_TEST_CHECKPOINT_QUORUM_THRESHOLD", "2")
    with pytest.raises(ValueError, match="quorum threshold"):
        publish_checkpoint(
            "PYSEC_TEST_CHECKPOINT",
            {"schema_version": "1.0", "checkpoint_sha256": "a" * 64},
            required=True,
        )


def test_external_checkpoint_retained_receipt_is_fully_reverified(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prefix = "PYSEC_TEST_CHECKPOINT"
    domain = {
        "organization": "checkpoint-provider",
        "host_identity_sha256": "1" * 64,
        "control_plane_sha256": "2" * 64,
        "implementation_sha256": "3" * 64,
    }
    private = Ed25519PrivateKey.generate()
    subject = {"schema_version": "1.0", "checkpoint_sha256": "a" * 64}

    def response(
        request_or_prefix: dict[str, object] | str,
        command_request: dict[str, object] | None = None,
    ) -> dict[str, object]:
        request = (
            request_or_prefix
            if isinstance(request_or_prefix, dict)
            else command_request
        )
        assert isinstance(request, dict)
        request["command_context"] = {}
        receipt_subject = {
            **request,
            "execution_nonce": "fixture-execution-nonce",
            "failure_domain": domain,
        }
        receipt, key = operation_receipt(
            receipt_subject,
            purpose="state-checkpoint-publish",
            private_key=private,
        )
        return {
            "schema_version": "1.0",
            "accepted": True,
            "checkpoint_authority_key_sha256": key,
            "execution_nonce": "fixture-execution-nonce",
            "checkpoint_operation_receipt": receipt,
            "failure_domain": domain,
            "_effective_policy_attestation": effective_policy_attestation(domain),
        }

    expected = response(
        {
            **subject,
            "idempotency_key_sha256": hashlib.sha256(
                canonical_bytes(subject)
            ).hexdigest(),
        }
    )["checkpoint_authority_key_sha256"]
    monkeypatch.setenv(f"{prefix}_COMMAND_JSON", '["checkpoint"]')
    monkeypatch.setenv(f"{prefix}_AUTHORITY_KEY_SHA256", str(expected))
    monkeypatch.setenv(f"{prefix}_FAILURE_DOMAIN_JSON", json.dumps(domain))
    monkeypatch.setenv("PYSEC_SCAN_TIME_CHALLENGE_SHA256", "c" * 64)
    monkeypatch.setenv("PYSEC_SCAN_TIME_CONTEXT_SHA256", "e" * 64)
    with patch(
        "py_security_suite.checkpoint_authority.run_pinned_json_command",
        side_effect=response,
    ):
        retained = publish_checkpoint(prefix, subject, required=True)
    assert retained is not None
    from py_security_suite.checkpoint_authority import verify_retained_checkpoint

    verify_retained_checkpoint(prefix, retained, subject)
    retained["execution_nonce"] = "spliced-execution"
    with pytest.raises(ValueError, match="execution binding"):
        verify_retained_checkpoint(prefix, retained, subject)


def test_operation_receipt_requires_deployment_owned_time_root(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    subject = {"run": 1}
    receipt, key = operation_receipt(subject, purpose="test-operation")
    monkeypatch.delenv("PYSEC_SCAN_TIME_CONTEXT_SHA256", raising=False)
    with pytest.raises(ValueError, match="trust binding"):
        verify_operation_receipt(
            subject,
            receipt,
            purpose="test-operation",
            observed_at=datetime.now(UTC),
            challenge_sha256="c" * 64,
            expected_key_sha256=key,
        )


def test_tpm_attestation_rejects_opaque_or_unverified_quote() -> None:
    with pytest.raises(ValueError, match="canonical JSON"):
        verify_format_evidence(
            b"opaque-tpm-quote",
            format_name="tpm2-quote",
            challenge_sha256="c" * 64,
            host_identity_sha256="h" * 64,
            pcrs_sha256="p" * 64,
            implementation_sha256="i" * 64,
        )
    evidence = {
        "schema_version": "1.0",
        "format": "tpm2-quote",
        "challenge_sha256": "c" * 64,
        "host_identity_sha256": "a" * 64,
        "pcrs_sha256": "b" * 64,
        "secure_boot": True,
        "measured_boot": True,
        "claims": {
            "quote_type": "TPM_ST_ATTEST_QUOTE",
            "hash_algorithm": "sha256",
            "pcr_selection": [0, 7],
            "event_log_sha256": "d" * 64,
            "ak_certificate_chain_sha256": "e" * 64,
            "signature_verified": False,
            "certificate_chain_verified": True,
            "revocation_checked": True,
            "event_log_replayed": True,
            "trust_root_sha256": "f" * 64,
            "verifier_implementation_sha256": "9" * 64,
        },
    }
    with pytest.raises(ValueError, match="TPM2 quote"):
        verify_format_evidence(
            canonical_bytes(evidence),
            format_name="tpm2-quote",
            challenge_sha256="c" * 64,
            host_identity_sha256="a" * 64,
            pcrs_sha256="b" * 64,
            implementation_sha256="9" * 64,
        )


def test_tpm_attestation_requires_and_verifies_independent_raw_replay(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private = Ed25519PrivateKey.generate()
    public_bytes = private.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    key_sha256 = hashlib.sha256(public_bytes).hexdigest()
    raw = b"raw-tpm2-quote-and-signature"
    normalized_authority_key = "1" * 64
    normalized_domain = {
        "organization": "normalized-attestation-org",
        "host_identity_sha256": "2" * 64,
        "control_plane_sha256": "3" * 64,
        "implementation_sha256": "9" * 64,
    }
    replay_domain = {
        "organization": "raw-replay-org",
        "host_identity_sha256": "4" * 64,
        "control_plane_sha256": "5" * 64,
        "implementation_sha256": "6" * 64,
    }
    claims = {
        "quote_type": "TPM_ST_ATTEST_QUOTE",
        "hash_algorithm": "sha256",
        "pcr_selection": [0, 7],
        "event_log_sha256": "d" * 64,
        "ak_certificate_chain_sha256": "e" * 64,
        "signature_verified": True,
        "certificate_chain_verified": True,
        "revocation_checked": True,
        "event_log_replayed": True,
        "trust_root_sha256": "f" * 64,
        "verifier_implementation_sha256": "9" * 64,
    }
    statement = {
        "schema_version": "1.0",
        "format": "tpm2-quote",
        "challenge_sha256": "c" * 64,
        "host_identity_sha256": "a" * 64,
        "pcrs_sha256": "b" * 64,
        "raw_evidence_sha256": hashlib.sha256(raw).hexdigest(),
        "normalized_claims_sha256": hashlib.sha256(canonical_bytes(claims)).hexdigest(),
        "normalized_authority_key_sha256": normalized_authority_key,
        "verification_method": "tpm2-checkquote-and-eventlog-v1",
        "verifier_executable_sha256": "9" * 64,
        "verifier_runtime_sha256": "7" * 64,
        "verifier_configuration_sha256": "8" * 64,
        "verification_transcript_sha256": "a" * 64,
        "trust_root_sha256": "f" * 64,
        "failure_domain": replay_domain,
        "signature_verified": True,
        "certificate_chain_verified": True,
        "revocation_checked": True,
    }
    evidence = {
        "schema_version": "1.0",
        "format": "tpm2-quote",
        "challenge_sha256": "c" * 64,
        "host_identity_sha256": "a" * 64,
        "pcrs_sha256": "b" * 64,
        "secure_boot": True,
        "measured_boot": True,
        "claims": {
            **claims,
            "raw_evidence_base64": base64.b64encode(raw).decode(),
            "raw_evidence_sha256": hashlib.sha256(raw).hexdigest(),
            "replay_statement": statement,
            "replay_signature_base64": base64.b64encode(
                private.sign(canonical_bytes(statement))
            ).decode(),
            "replay_public_key_pem_base64": base64.b64encode(public_bytes).decode(),
            "replay_failure_domain": replay_domain,
        },
    }
    monkeypatch.setenv("PYSEC_REQUIRE_RAW_ATTESTATION_REPLAY", "1")
    monkeypatch.setenv("PYSEC_RAW_ATTESTATION_REPLAY_KEY_SHA256", key_sha256)
    monkeypatch.setattr(
        "py_security_suite.pinned_command.command_configured", lambda prefix: True
    )

    def native_replay(
        prefix: str, request: dict[str, object], **_: object
    ) -> dict[str, object]:
        expected = request["expected_statement"]
        assert isinstance(expected, dict)
        return {
            "schema_version": "1.0",
            "verified": True,
            "format": expected["format"],
            "raw_evidence_sha256": expected["raw_evidence_sha256"],
            "normalized_claims_sha256": expected["normalized_claims_sha256"],
            "verification_statement_sha256": request["expected_statement_sha256"],
            "verification_method": expected["verification_method"],
            "trust_root_sha256": expected["trust_root_sha256"],
            "_effective_policy_attestation": {
                "subject": {"executable_sha256": "9" * 64}
            },
        }

    monkeypatch.setattr(
        "py_security_suite.pinned_command.run_pinned_json_command", native_replay
    )
    monkeypatch.setattr(
        "py_security_suite.pinned_command.remote_attested_failure_domain",
        lambda value: replay_domain,
    )
    verify_format_evidence(
        canonical_bytes(evidence),
        format_name="tpm2-quote",
        challenge_sha256="c" * 64,
        host_identity_sha256="a" * 64,
        pcrs_sha256="b" * 64,
        implementation_sha256="9" * 64,
        normalized_authority_key_sha256=normalized_authority_key,
        normalized_failure_domain=normalized_domain,
    )
    evidence["claims"]["raw_evidence_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="replay binding"):
        verify_format_evidence(
            canonical_bytes(evidence),
            format_name="tpm2-quote",
            challenge_sha256="c" * 64,
            host_identity_sha256="a" * 64,
            pcrs_sha256="b" * 64,
            implementation_sha256="9" * 64,
            normalized_authority_key_sha256=normalized_authority_key,
            normalized_failure_domain=normalized_domain,
        )


def test_failure_domain_registry_rejects_revoked_authority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    key = "a" * 64
    domain = {
        "organization": "independent-provider",
        "host_identity_sha256": "b" * 64,
        "control_plane_sha256": "c" * 64,
        "implementation_sha256": "d" * 64,
    }
    registry = {
        "schema_version": "1.0",
        "generation": 1,
        "authorities": [
            {
                "authority_key_sha256": key,
                "failure_domain": domain,
                "implementation_artifact_sha256": domain["implementation_sha256"],
                "status": "revoked",
            }
        ],
    }
    path = tmp_path / "failure-domains.json"
    path.write_bytes(canonical_bytes(registry))
    monkeypatch.setenv("PYSEC_FAILURE_DOMAIN_REGISTRY_PATH", str(path))
    monkeypatch.setenv(
        "PYSEC_FAILURE_DOMAIN_REGISTRY_SHA256",
        hashlib.sha256(path.read_bytes()).hexdigest(),
    )
    with pytest.raises(ValueError, match="not actively registered"):
        verify_registered_failure_domain(domain, key, "test authority")


def test_failure_domain_registry_requires_fresh_threshold_transparency(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    authority_key = "a" * 64
    domain = {
        "organization": "independent-provider",
        "host_identity_sha256": "b" * 64,
        "control_plane_sha256": "c" * 64,
        "implementation_sha256": "d" * 64,
    }
    signed = {
        "generation": 7,
        "issued_at": (datetime.now(UTC) - timedelta(minutes=1)).isoformat(),
        "expires_at": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
        "authorities": [
            {
                "authority_key_sha256": authority_key,
                "failure_domain": domain,
                "implementation_artifact_sha256": domain["implementation_sha256"],
                "status": "active",
            }
        ],
    }
    roots = [Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()]
    root_records = []
    signatures = []
    for private in roots:
        public = private.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        digest = hashlib.sha256(public).hexdigest()
        root_records.append(
            {
                "key_sha256": digest,
                "public_key_pem_base64": base64.b64encode(public).decode(),
            }
        )
        signatures.append(
            {
                "key_sha256": digest,
                "signature_base64": base64.b64encode(
                    private.sign(canonical_bytes(signed))
                ).decode(),
            }
        )
    log_root = hashlib.sha256(b"\x00" + canonical_bytes(signed)).hexdigest()
    witness_records = []
    witness_keys = [Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()]
    checkpoint_subject = {
        "schema_version": "1.0",
        "log_id": "deployment-security-log",
        "tree_size": 1,
        "root_sha256": log_root,
        "generation": 7,
        "previous_tree_size": 0,
        "previous_root_sha256": "",
    }
    checkpoint_signatures = []
    for private in witness_keys:
        public = private.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        digest = hashlib.sha256(public).hexdigest()
        witness_records.append(
            {
                "key_sha256": digest,
                "public_key_pem_base64": base64.b64encode(public).decode(),
            }
        )
        checkpoint_signatures.append(
            {
                "key_sha256": digest,
                "signature_base64": base64.b64encode(
                    private.sign(canonical_bytes(checkpoint_subject))
                ).decode(),
            }
        )
    registry = {
        "schema_version": "2.0",
        "signed": signed,
        "signatures": signatures,
        "transparency": {
            "log_id": "deployment-security-log",
            "log_index": 0,
            "tree_size": 1,
            "audit_path": [],
            "root_sha256": log_root,
            "consistency_path": [],
            "checkpoint": {
                "signed": checkpoint_subject,
                "signatures": checkpoint_signatures,
            },
        },
    }
    path = tmp_path / "failure-domains-v2.json"
    path.write_bytes(canonical_bytes(registry))
    monkeypatch.setenv("PYSEC_FAILURE_DOMAIN_REGISTRY_PATH", str(path))
    monkeypatch.setenv(
        "PYSEC_FAILURE_DOMAIN_REGISTRY_SHA256",
        hashlib.sha256(path.read_bytes()).hexdigest(),
    )
    monkeypatch.setenv("PYSEC_REQUIRE_FRESH_FAILURE_DOMAIN_REGISTRY", "1")
    monkeypatch.setenv("PYSEC_FAILURE_DOMAIN_REGISTRY_MIN_GENERATION", "7")
    monkeypatch.setenv(
        "PYSEC_FAILURE_DOMAIN_REGISTRY_ROOT_KEYS_JSON", json.dumps(root_records)
    )
    monkeypatch.setenv("PYSEC_FAILURE_DOMAIN_REGISTRY_SIGNATURE_THRESHOLD", "2")
    monkeypatch.setenv("PYSEC_FAILURE_DOMAIN_LOG_ROOT_SHA256", log_root)
    monkeypatch.setenv(
        "PYSEC_FAILURE_DOMAIN_LOG_WITNESS_KEYS_JSON", json.dumps(witness_records)
    )
    monkeypatch.setenv("PYSEC_FAILURE_DOMAIN_LOG_WITNESS_THRESHOLD", "2")
    monkeypatch.setenv(
        "PYSEC_FAILURE_DOMAIN_REGISTRY_STATE_PATH", str(tmp_path / "registry.sqlite3")
    )
    assert verify_registered_failure_domain(domain, authority_key, "test") == domain

    registry["transparency"]["tree_size"] = 2
    path.write_bytes(canonical_bytes(registry))
    monkeypatch.setenv(
        "PYSEC_FAILURE_DOMAIN_REGISTRY_SHA256",
        hashlib.sha256(path.read_bytes()).hexdigest(),
    )
    with pytest.raises(ValueError, match="inclusion proof|detached"):
        verify_registered_failure_domain(domain, authority_key, "test")


def test_failure_domain_consistency_proof_binds_registry_growth() -> None:
    old_root = hashlib.sha256(b"\x00registry-generation-1").hexdigest()
    next_leaf = hashlib.sha256(b"\x00registry-generation-2").hexdigest()
    new_root = hashlib.sha256(
        b"\x01" + bytes.fromhex(old_root) + bytes.fromhex(next_leaf)
    ).hexdigest()

    assert _verify_consistency(1, 2, old_root, new_root, [next_leaf])
    assert not _verify_consistency(1, 2, old_root, "0" * 64, [next_leaf])
    assert not _verify_consistency(2, 1, new_root, old_root, [next_leaf])


def test_explicit_trust_policy_rejects_ambient_conflicts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    private_keys = [Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()]
    roots = []
    signatures = []
    signed = {
        "schema_version": "2.0",
        "generation": 3,
        "issued_at": (datetime.now(UTC) - timedelta(minutes=1)).isoformat(),
        "expires_at": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
        "previous_policy_sha256": "",
        "variables": {
            "PYSEC_REQUIRE_RAW_ATTESTATION_REPLAY": "1",
            "PYSEC_SCAN_TIME_CHALLENGE_SHA256": "a" * 64,
            "PYSEC_SCAN_TIME_CONTEXT_PATH": str(tmp_path / "time.json"),
            "PYSEC_SCAN_TIME_CONTEXT_SHA256": "b" * 64,
        },
    }
    for private in private_keys:
        public = private.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        key_sha256 = hashlib.sha256(public).hexdigest()
        roots.append(
            {
                "key_sha256": key_sha256,
                "public_key_pem_base64": base64.b64encode(public).decode(),
            }
        )
        signatures.append(
            {
                "key_sha256": key_sha256,
                "signature_base64": base64.b64encode(
                    private.sign(canonical_bytes(signed))
                ).decode(),
            }
        )
    document = {
        "signed": signed,
        "signatures": signatures,
    }
    path = tmp_path / "trust-policy.json"
    path.write_bytes(canonical_bytes(document))
    monkeypatch.setenv("PYSEC_EXPLICIT_TRUST_POLICY_PATH", str(path))
    monkeypatch.setenv(
        "PYSEC_EXPLICIT_TRUST_POLICY_SHA256",
        hashlib.sha256(path.read_bytes()).hexdigest(),
    )
    monkeypatch.setenv("PYSEC_REQUIRE_EXPLICIT_TRUST_POLICY", "1")
    monkeypatch.setenv("PYSEC_EXPLICIT_TRUST_POLICY_ROOT_KEYS_JSON", json.dumps(roots))
    monkeypatch.setenv("PYSEC_EXPLICIT_TRUST_POLICY_SIGNATURE_THRESHOLD", "2")
    monkeypatch.setenv(
        "PYSEC_EXPLICIT_TRUST_POLICY_STATE_PATH", str(tmp_path / "policy.sqlite3")
    )
    with patch(
        "py_security_suite.trusted_observation.scan_observed_at",
        return_value=datetime.now(UTC),
    ):
        with monkeypatch.context() as unsigned_environment:
            unsigned_environment.setenv("PYSEC_REQUIRE_KERNEL_RUNTIME_EVENTS", "1")
            with pytest.raises(ValueError, match="absent from signed policy"):
                capture_trust_environment()
        captured = capture_trust_environment()
        assert captured["PYSEC_REQUIRE_RAW_ATTESTATION_REPLAY"] == "1"
        with monkeypatch.context() as conflict_environment:
            conflict_environment.setenv("PYSEC_REQUIRE_RAW_ATTESTATION_REPLAY", "0")
            with pytest.raises(ValueError, match="conflicts"):
                capture_trust_environment()


def test_required_kms_audit_readback_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prefix = "PYSEC_RAW_EVIDENCE_PROVIDER_AUDIT_READBACK"
    monkeypatch.setenv(f"{prefix}_REQUIRED", "1")
    monkeypatch.delenv(f"{prefix}_COMMAND_JSON", raising=False)
    with pytest.raises(ValueError, match="readback is unavailable"):
        _provider_audit_readback(
            {"provider": "kms", "audit_event_id": "event-1"},
            {
                "organization": "provider",
                "host_identity_sha256": "a" * 64,
                "control_plane_sha256": "b" * 64,
                "implementation_sha256": "c" * 64,
            },
            "d" * 64,
        )


def test_requirements_sbom_must_cover_exact_runtime_closure() -> None:
    closure = [
        {
            "path": "runtime/library.bin",
            "sha256": "a" * 64,
            "content_base64": "",
        }
    ]
    empty_sbom = canonical_bytes(
        {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []}
    )
    assert _runtime_sbom_covers_closure(empty_sbom, closure) is False
    detached_graph = canonical_bytes(
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "components": [
                {
                    "type": "file",
                    "name": "runtime/library.bin",
                    "bom-ref": "runtime-file",
                    "properties": [
                        {"name": "pysec:closure-path", "value": "runtime/library.bin"}
                    ],
                    "hashes": [{"alg": "SHA-256", "content": "a" * 64}],
                }
            ],
            "dependencies": [
                {"ref": "runtime-file", "dependsOn": ["missing-component"]}
            ],
        }
    )
    assert _runtime_sbom_covers_closure(detached_graph, closure) is False


def test_oci_manifest_reconstructs_layers_and_rejects_traversal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def layer(name: str) -> bytes:
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w") as archive:
            info = tarfile.TarInfo(name)
            info.size = 1
            archive.addfile(info, io.BytesIO(b"x"))
        return stream.getvalue()

    unpacked = layer("app/main.py")
    compressed = gzip.compress(unpacked)
    config = canonical_bytes(
        {"rootfs": {"diff_ids": [f"sha256:{hashlib.sha256(unpacked).hexdigest()}"]}}
    )
    config_descriptor = {
        "mediaType": "application/vnd.oci.image.config.v1+json",
        "size": len(config),
        "digest": f"sha256:{hashlib.sha256(config).hexdigest()}",
    }
    layer_descriptor = {
        "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
        "size": len(compressed),
        "digest": f"sha256:{hashlib.sha256(compressed).hexdigest()}",
    }
    source = "https://example.invalid/repo"
    image_subject = {
        "config": config_descriptor,
        "layers": [layer_descriptor],
        "source": source,
    }
    image_subject_sha256 = hashlib.sha256(canonical_bytes(image_subject)).hexdigest()
    provenance = canonical_bytes(
        {
            "schema_version": "1.0",
            "predicate_type": "https://slsa.dev/provenance/v1",
            "builder_id": "test-builder",
            "build_type": "test-build",
            "source_uri": source,
            "image_subject_sha256": image_subject_sha256,
            "materials_sha256": hashlib.sha256(
                canonical_bytes([config_descriptor, layer_descriptor])
            ).hexdigest(),
        }
    )
    signature_subject = {
        "schema_version": "1.0",
        "image_subject_sha256": image_subject_sha256,
        "provenance_sha256": hashlib.sha256(provenance).hexdigest(),
        "builder_id": "test-builder",
    }
    signature_receipt, signature_key = operation_receipt(
        signature_subject, purpose="requirements-oci-image-signature"
    )
    signature = canonical_bytes(
        {"subject": signature_subject, "operation_receipt": signature_receipt}
    )
    blobs = [config, compressed, signature, provenance]
    manifest = canonical_bytes(
        {
            "schemaVersion": 2,
            "config": config_descriptor,
            "layers": [layer_descriptor],
            "annotations": {
                "org.opencontainers.image.source": source,
                "pysec.signature-envelope-sha256": hashlib.sha256(
                    signature
                ).hexdigest(),
                "pysec.provenance-sha256": hashlib.sha256(provenance).hexdigest(),
            },
        }
    )
    closure = [
        {
            "path": f"blobs/{index}",
            "sha256": hashlib.sha256(blob).hexdigest(),
            "content_base64": base64.b64encode(blob).decode(),
        }
        for index, blob in enumerate(blobs)
    ]
    monkeypatch.setenv("PYSEC_REQUIREMENTS_OCI_BUILDER_ID", "test-builder")
    monkeypatch.setenv("PYSEC_REQUIREMENTS_OCI_SIGNATURE_KEY_SHA256", signature_key)
    monkeypatch.setenv("PYSEC_SCAN_TIME_CHALLENGE_SHA256", "c" * 64)
    monkeypatch.setenv("PYSEC_SCAN_TIME_CONTEXT_SHA256", "e" * 64)
    assert _oci_manifest_valid(manifest, closure) is True

    unsafe = layer("../escape")
    assert _safe_oci_layer(unsafe) is False
    unsafe_compressed = gzip.compress(unsafe)
    unsafe_config = canonical_bytes(
        {"rootfs": {"diff_ids": [f"sha256:{hashlib.sha256(unsafe).hexdigest()}"]}}
    )
    unsafe_manifest = canonical_bytes(
        {
            **json.loads(manifest),
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "size": len(unsafe_config),
                "digest": f"sha256:{hashlib.sha256(unsafe_config).hexdigest()}",
            },
            "layers": [
                {
                    "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                    "size": len(unsafe_compressed),
                    "digest": f"sha256:{hashlib.sha256(unsafe_compressed).hexdigest()}",
                }
            ],
        }
    )
    unsafe_blobs = [unsafe_config, unsafe_compressed, signature, provenance]
    unsafe_closure = [
        {
            "path": f"unsafe/{index}",
            "sha256": hashlib.sha256(blob).hexdigest(),
            "content_base64": base64.b64encode(blob).decode(),
        }
        for index, blob in enumerate(unsafe_blobs)
    ]
    assert _oci_manifest_valid(unsafe_manifest, unsafe_closure) is False


def test_operation_receipt_state_rejects_cross_report_replay(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    receipt, _ = operation_receipt(
        {"run": 1}, purpose="test-operation", operation_id="global-run-1"
    )
    monkeypatch.setenv(
        "PYSEC_OPERATION_RECEIPT_STATE_PATH", str(tmp_path / "operations.sqlite")
    )
    monkeypatch.setenv("PYSEC_OPERATION_RECEIPT_MIN_SEQUENCE", "0")
    monkeypatch.setenv(
        "PYSEC_OPERATION_RECEIPT_CHECKPOINT_SHA256",
        _OPERATION_STATE_GENESIS_SHA256,
    )
    _consume_operation_receipts([receipt], {"report": 1})
    _consume_operation_receipts([receipt], {"report": 1})
    with pytest.raises(ValueError, match="replay across reports"):
        _consume_operation_receipts([receipt], {"report": 2})


def test_operation_receipt_state_reverifies_persisted_checkpoint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "operations.sqlite"
    monkeypatch.setenv("PYSEC_OPERATION_RECEIPT_STATE_PATH", str(path))
    monkeypatch.setenv("PYSEC_OPERATION_RECEIPT_MIN_SEQUENCE", "0")
    monkeypatch.setenv(
        "PYSEC_OPERATION_RECEIPT_CHECKPOINT_SHA256",
        _OPERATION_STATE_GENESIS_SHA256,
    )
    receipt, _ = operation_receipt(
        {"run": 1}, purpose="test-operation", operation_id="checkpoint-readback"
    )
    _consume_operation_receipts([receipt], {"report": 1})
    with closing(sqlite3.connect(path)) as connection:
        connection.execute(
            "UPDATE operation_receipt_checkpoint SET external_receipt = ?",
            (canonical_bytes({}),),
        )
        connection.commit()
    with pytest.raises(ValueError, match="retained external checkpoint"):
        _consume_operation_receipts([receipt], {"report": 1})


def test_compiler_canaries_require_multiple_rule_families() -> None:
    value = {
        "positive_fixture_sha256": "a" * 64,
        "negative_fixture_sha256": "b" * 64,
        "positive_detected": True,
        "negative_clean": True,
        "cases": [
            {
                "id": f"case-{index}",
                "rule_family": "injection",
                "fixture_sha256": f"{index + 1}" * 64,
                "expected_detected": index % 2 == 0,
                "detected": index % 2 == 0,
            }
            for index in range(4)
        ],
    }
    assert _canary_results_valid(value) is False


def test_operation_receipt_anchor_detects_deleted_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "operations.sqlite"
    monkeypatch.setenv("PYSEC_OPERATION_RECEIPT_STATE_PATH", str(path))
    monkeypatch.setenv("PYSEC_OPERATION_RECEIPT_MIN_SEQUENCE", "0")
    monkeypatch.setenv(
        "PYSEC_OPERATION_RECEIPT_CHECKPOINT_SHA256",
        _OPERATION_STATE_GENESIS_SHA256,
    )
    first, _ = operation_receipt(
        {"run": 1}, purpose="test-operation", operation_id="anchor-1"
    )
    _consume_operation_receipts([first], {"report": 1})
    with closing(sqlite3.connect(path)) as connection:
        sequence, checkpoint = connection.execute(
            "SELECT sequence, checkpoint_sha256 FROM operation_receipt_checkpoint"
        ).fetchone()
    path.unlink()
    monkeypatch.setenv("PYSEC_OPERATION_RECEIPT_MIN_SEQUENCE", str(sequence))
    monkeypatch.setenv("PYSEC_OPERATION_RECEIPT_CHECKPOINT_SHA256", checkpoint)
    second, _ = operation_receipt(
        {"run": 2}, purpose="test-operation", operation_id="anchor-2"
    )
    with pytest.raises(ValueError, match="deletion or rollback"):
        _consume_operation_receipts([second], {"report": 2})


def test_requirements_executor_rejects_raw_environment_values() -> None:
    execution = {
        "environment": {"TOKEN": "secret"},
        "runtime_manifest": {},
        "assets_manifest": [],
        "sandbox_policy": {},
    }
    assert _procedure_manifests_valid(execution) is False


def test_raw_runtime_spans_reject_missing_parent() -> None:
    trace = {"trace_id": "trace-1234567890", "operation": "read", "span_count": 1}
    span = {
        "trace_id": trace["trace_id"],
        "span_id": "span-1",
        "parent_span_id": "missing",
        "process_identity_sha256": "a" * 64,
        "operation": "read",
    }
    with pytest.raises(ValueError, match="parent is missing"):
        _verify_raw_spans([span], [trace])


def test_trusted_time_state_rejects_rollback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(
        "PYSEC_TRUSTED_TIME_STATE_PATH", str(tmp_path / "trusted-time.sqlite")
    )
    monkeypatch.setenv("PYSEC_TRUSTED_TIME_MIN_SEQUENCE", "0")
    monkeypatch.setenv(
        "PYSEC_TRUSTED_TIME_CHECKPOINT_SHA256", _TRUSTED_TIME_STATE_GENESIS_SHA256
    )
    now = datetime.now(UTC)
    current = {
        "trusted_time_observed_at": now.isoformat(),
        "trusted_time_sha256": "a" * 64,
    }
    older = {
        "trusted_time_observed_at": (now - timedelta(seconds=1)).isoformat(),
        "trusted_time_sha256": "b" * 64,
    }
    _advance_time_state("c" * 64, current)
    with pytest.raises(ValueError, match="rollback or fork"):
        _advance_time_state("d" * 64, older)


def test_trusted_time_anchor_detects_deleted_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "trusted-time.sqlite"
    monkeypatch.setenv("PYSEC_TRUSTED_TIME_STATE_PATH", str(path))
    monkeypatch.setenv("PYSEC_TRUSTED_TIME_MIN_SEQUENCE", "0")
    monkeypatch.setenv(
        "PYSEC_TRUSTED_TIME_CHECKPOINT_SHA256", _TRUSTED_TIME_STATE_GENESIS_SHA256
    )
    now = datetime.now(UTC)
    _advance_time_state(
        "c" * 64,
        {"trusted_time_observed_at": now.isoformat(), "trusted_time_sha256": "a" * 64},
    )
    with closing(sqlite3.connect(path)) as connection:
        sequence, checkpoint = connection.execute(
            "SELECT sequence, checkpoint_sha256 FROM trusted_time_state"
        ).fetchone()
    path.unlink()
    monkeypatch.setenv("PYSEC_TRUSTED_TIME_MIN_SEQUENCE", str(sequence))
    monkeypatch.setenv("PYSEC_TRUSTED_TIME_CHECKPOINT_SHA256", checkpoint)
    with pytest.raises(ValueError, match="deletion or rollback"):
        _advance_time_state(
            "d" * 64,
            {
                "trusted_time_observed_at": (now + timedelta(seconds=1)).isoformat(),
                "trusted_time_sha256": "b" * 64,
            },
        )
