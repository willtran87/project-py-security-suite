from __future__ import annotations

import hashlib
import base64
import json
import sqlite3
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from py_security_suite.benchmark_assurance import (
    BENCHMARK_REPLAY_GENESIS_SHA256,
    BenchmarkAssuranceError,
    BenchmarkReplayLease,
    consume_benchmark_replay,
    load_authority_trust_policy,
    load_benchmark_replay_checkpoint,
    load_benchmark_replay_intent,
    recover_benchmark_replay_intent,
    reconcile_completed_benchmark_replay_intent,
    remove_benchmark_replay_intent,
    sign_execution_receipt,
    sign_execution_receipt_with_provider,
    validate_trusted_authority,
    verify_execution_receipt_signature,
    write_benchmark_replay_checkpoint,
    write_benchmark_replay_intent,
)
from py_security_suite.strict_json import canonical_bytes
from py_security_suite.benchmark_signing import ExternalEd25519SigningProvider


def _policy_payload(public_key_sha256: str) -> bytes:
    issued = datetime.now(UTC) - timedelta(minutes=1)
    roles = (
        "trusted-time",
        "replay-protection",
        "acceptance-criteria",
        "runtime-observation",
    )
    value = {
        "schema_version": "1.0",
        "policy_id": "deployment-benchmark-authority",
        "issued_at": issued.isoformat(),
        "expires_at": (issued + timedelta(days=30)).isoformat(),
        "minimum_distinct_signers": 4,
        "minimum_distinct_organizations": 2,
        "authorities": [
            {
                "role": role,
                "organization_id": f"organization-{index % 2}",
                "public_key_sha256": (
                    public_key_sha256 if index == 0 else f"{index + 1:x}" * 64
                ),
                "revocation_status_sha256": f"{index + 5:x}" * 64,
                "status": "active",
            }
            for index, role in enumerate(roles)
        ],
    }
    return json.dumps(value, sort_keys=True).encode()


def _signed_policy_files(directory: Path, payload: bytes) -> tuple[Path, Path, str]:
    root = Ed25519PrivateKey.generate()
    root_payload = root.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    root_path = directory / "authority-root.pem"
    signature_path = directory / "authority-policy.sig"
    root_path.write_bytes(root_payload)
    signature_path.write_bytes(base64.b64encode(root.sign(payload)))
    return root_path, signature_path, hashlib.sha256(root_payload).hexdigest()


def test_deployment_policy_anchors_authority_keys_outside_workspace(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    key = Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    public_sha256 = hashlib.sha256(
        key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    ).hexdigest()
    payload = _policy_payload(public_sha256)
    policy_path = tmp_path / "authority-policy.json"
    policy_path.write_bytes(payload)
    root_path, signature_path, root_sha256 = _signed_policy_files(tmp_path, payload)
    policy = load_authority_trust_policy(
        policy_path,
        hashlib.sha256(payload).hexdigest(),
        signature_path=signature_path,
        trust_root_path=root_path,
        trust_root_sha256=root_sha256,
        workspace=workspace,
        manifest_policy={
            "minimum_distinct_signers": 4,
            "minimum_distinct_organizations": 2,
        },
    )

    key_id = validate_trusted_authority(
        kind="trusted-time",
        public_key_payload=public,
        authority={
            "organization_id": "organization-0",
            "revocation_status_sha256": "5" * 64,
        },
        trust_policy=policy,
    )

    assert key_id == public_sha256
    with pytest.raises(BenchmarkAssuranceError, match="not admitted"):
        validate_trusted_authority(
            kind="runner-sbom",
            public_key_payload=public,
            authority={
                "organization_id": "organization-0",
                "revocation_status_sha256": "5" * 64,
            },
            trust_policy=policy,
        )


def test_authority_policy_and_replay_ledger_cannot_live_in_workspace(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    payload = _policy_payload("1" * 64)
    inside = workspace / "authority-policy.json"
    inside.write_bytes(payload)
    root_path, signature_path, root_sha256 = _signed_policy_files(tmp_path, payload)

    with pytest.raises(BenchmarkAssuranceError, match="outside"):
        load_authority_trust_policy(
            inside,
            hashlib.sha256(payload).hexdigest(),
            signature_path=signature_path,
            trust_root_path=root_path,
            trust_root_sha256=root_sha256,
            workspace=workspace,
            manifest_policy={
                "minimum_distinct_signers": 4,
                "minimum_distinct_organizations": 2,
            },
        )
    with pytest.raises(BenchmarkAssuranceError, match="outside"):
        consume_benchmark_replay(
            workspace / "replay.sqlite3",
            workspace=workspace,
            nonce_sha256="a" * 64,
            subject_sha256="b" * 64,
            signer_key_id="c" * 64,
        )


def test_deployment_replay_ledger_consumes_nonce_once(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    ledger = tmp_path / "replay.sqlite3"
    arguments = {
        "workspace": workspace,
        "nonce_sha256": "a" * 64,
        "subject_sha256": "b" * 64,
        "signer_key_id": "c" * 64,
    }

    receipt = consume_benchmark_replay(ledger, **arguments)

    assert receipt["backend"] == "deployment-sqlite"
    assert receipt["sequence"] == 1
    assert receipt["previous_checkpoint_sha256"] != receipt["checkpoint_sha256"]
    with pytest.raises(BenchmarkAssuranceError, match="already consumed"):
        consume_benchmark_replay(ledger, **arguments)


def test_replay_ledger_detects_tampering_and_rollback(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    ledger = tmp_path / "replay.sqlite3"
    first = consume_benchmark_replay(
        ledger,
        workspace=workspace,
        nonce_sha256="a" * 64,
        subject_sha256="b" * 64,
        signer_key_id="c" * 64,
    )
    second = consume_benchmark_replay(
        ledger,
        workspace=workspace,
        nonce_sha256="d" * 64,
        subject_sha256="b" * 64,
        signer_key_id="c" * 64,
        minimum_sequence=1,
        expected_checkpoint_sha256=first["checkpoint_sha256"],
    )

    with pytest.raises(BenchmarkAssuranceError, match="rollback detected"):
        consume_benchmark_replay(
            tmp_path / "empty-replay.sqlite3",
            workspace=workspace,
            nonce_sha256="e" * 64,
            subject_sha256="b" * 64,
            signer_key_id="c" * 64,
            minimum_sequence=second["sequence"],
            expected_checkpoint_sha256=second["checkpoint_sha256"],
        )

    with sqlite3.connect(ledger) as connection:
        connection.execute(
            "UPDATE consumed_benchmarks SET subject_sha256 = ? WHERE sequence = 1",
            ("f" * 64,),
        )
    with pytest.raises(BenchmarkAssuranceError, match="hash chain is invalid"):
        consume_benchmark_replay(
            ledger,
            workspace=workspace,
            nonce_sha256="e" * 64,
            subject_sha256="b" * 64,
            signer_key_id="c" * 64,
            expected_checkpoint_sha256=BENCHMARK_REPLAY_GENESIS_SHA256,
        )


def test_replay_ledger_strict_head_rejects_forward_injection(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    ledger = tmp_path / "replay.sqlite3"
    first = consume_benchmark_replay(
        ledger,
        workspace=workspace,
        nonce_sha256="a" * 64,
        subject_sha256="b" * 64,
        signer_key_id="c" * 64,
    )
    consume_benchmark_replay(
        ledger,
        workspace=workspace,
        nonce_sha256="d" * 64,
        subject_sha256="b" * 64,
        signer_key_id="c" * 64,
        minimum_sequence=first["sequence"],
        expected_checkpoint_sha256=first["checkpoint_sha256"],
    )

    with pytest.raises(BenchmarkAssuranceError, match="advanced beyond"):
        consume_benchmark_replay(
            ledger,
            workspace=workspace,
            nonce_sha256="e" * 64,
            subject_sha256="b" * 64,
            signer_key_id="c" * 64,
            minimum_sequence=first["sequence"],
            expected_checkpoint_sha256=first["checkpoint_sha256"],
            require_current_head=True,
        )


def test_replay_ledger_serializes_concurrent_consumers(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    ledger = tmp_path / "replay.sqlite3"

    def consume(index: int) -> int:
        receipt = consume_benchmark_replay(
            ledger,
            workspace=workspace,
            nonce_sha256=f"{index + 1:064x}",
            subject_sha256="b" * 64,
            signer_key_id="c" * 64,
        )
        return int(receipt["sequence"])

    with ThreadPoolExecutor(max_workers=8) as executor:
        sequences = list(executor.map(consume, range(8)))

    assert sorted(sequences) == list(range(1, 9))


def test_deployment_policy_quorum_counts_only_active_authorities(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    value = json.loads(_policy_payload("1" * 64))
    value["authorities"][3]["status"] = "revoked"
    payload = json.dumps(value, sort_keys=True).encode()
    policy_path = tmp_path / "authority-policy.json"
    policy_path.write_bytes(payload)
    root_path, signature_path, root_sha256 = _signed_policy_files(tmp_path, payload)

    with pytest.raises(BenchmarkAssuranceError, match="signer quorum"):
        load_authority_trust_policy(
            policy_path,
            hashlib.sha256(payload).hexdigest(),
            signature_path=signature_path,
            trust_root_path=root_path,
            trust_root_sha256=root_sha256,
            workspace=workspace,
            manifest_policy={
                "minimum_distinct_signers": 4,
                "minimum_distinct_organizations": 2,
            },
        )


def test_authority_policy_rejects_invalid_root_signature(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    payload = _policy_payload("1" * 64)
    policy_path = tmp_path / "authority-policy.json"
    policy_path.write_bytes(payload)
    root_path, signature_path, root_sha256 = _signed_policy_files(tmp_path, payload)
    signature_path.write_bytes(base64.b64encode(b"invalid-signature"))

    with pytest.raises(BenchmarkAssuranceError, match="signature is invalid"):
        load_authority_trust_policy(
            policy_path,
            hashlib.sha256(payload).hexdigest(),
            signature_path=signature_path,
            trust_root_path=root_path,
            trust_root_sha256=root_sha256,
            workspace=workspace,
            manifest_policy={
                "minimum_distinct_signers": 4,
                "minimum_distinct_organizations": 2,
            },
        )


def test_execution_receipt_requires_admitted_signing_key(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    key = Ed25519PrivateKey.generate()
    key_payload = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    key_path = tmp_path / "receipt-key.pem"
    key_path.write_bytes(key_payload)
    key_id = hashlib.sha256(
        key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    ).hexdigest()
    trust_policy = {
        "authority_index": {
            ("execution-receipt", key_id): {
                "organization_id": "receipt-authority",
                "status": "active",
            }
        }
    }

    receipt = {"analysis": "test"}
    receipt["receipt_sha256"] = hashlib.sha256(canonical_bytes(receipt)).hexdigest()
    result = sign_execution_receipt(
        receipt,
        signing_key_path=key_path,
        signing_key_sha256=hashlib.sha256(key_payload).hexdigest(),
        workspace=workspace,
        trust_policy=trust_policy,
    )

    assert result["algorithm"] == "Ed25519"
    assert result["signer_key_id"] == key_id
    receipt["receipt_signature"] = result
    assert verify_execution_receipt_signature(receipt, trust_policy) == key_id
    assert (
        verify_execution_receipt_signature(
            receipt, trusted_signer_key_ids=frozenset({key_id})
        )
        == key_id
    )
    with pytest.raises(BenchmarkAssuranceError, match="relying party"):
        verify_execution_receipt_signature(
            receipt, trusted_signer_key_ids=frozenset({"f" * 64})
        )

    receipt["analysis"] = "tampered"
    with pytest.raises(BenchmarkAssuranceError, match="self-hash is invalid"):
        verify_execution_receipt_signature(receipt, trust_policy)


def test_external_signing_provider_metadata_is_cryptographically_bound() -> None:
    key = Ed25519PrivateKey.generate()
    key_id = hashlib.sha256(
        key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    ).hexdigest()

    class Provider:
        provider_id = "pkcs11"
        key_version = "token-key-2026-08"

        def public_key_bytes(self) -> bytes:
            return key.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )

        def sign(self, payload: bytes) -> bytes:
            return key.sign(payload)

    trust_policy = {
        "authority_index": {
            ("execution-receipt", key_id): {
                "organization_id": "receipt-authority",
                "status": "active",
            }
        }
    }
    receipt = {"analysis": "provider-test"}
    receipt["receipt_sha256"] = hashlib.sha256(canonical_bytes(receipt)).hexdigest()
    receipt["receipt_signature"] = sign_execution_receipt_with_provider(
        receipt, provider=Provider(), trust_policy=trust_policy
    )
    assert receipt["receipt_signature"]["key_provider"] == "pkcs11"
    assert verify_execution_receipt_signature(receipt, trust_policy) == key_id

    receipt["receipt_signature"]["key_version"] = "token-key-2026-09"
    with pytest.raises(BenchmarkAssuranceError, match="signature is invalid"):
        verify_execution_receipt_signature(receipt, trust_policy)

    class InvalidProvider(Provider):
        def sign(self, payload: bytes) -> bytes:
            return b"\x00" * 64

    clean_receipt = {"analysis": "provider-test"}
    clean_receipt["receipt_sha256"] = hashlib.sha256(
        canonical_bytes(clean_receipt)
    ).hexdigest()
    with pytest.raises(BenchmarkAssuranceError, match="invalid signature"):
        sign_execution_receipt_with_provider(
            clean_receipt, provider=InvalidProvider(), trust_policy=trust_policy
        )


def test_receipt_admission_enforces_key_lifecycle_at_completion_time() -> None:
    key = Ed25519PrivateKey.generate()
    key_id = hashlib.sha256(
        key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    ).hexdigest()
    completed = datetime.now(UTC)

    class Provider:
        provider_id = "kms"
        key_version = "key-2026-08"

        def public_key_bytes(self) -> bytes:
            return key.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )

        def sign(self, payload: bytes) -> bytes:
            return key.sign(payload)

    authority = {
        "organization_id": "receipt-authority",
        "status": "active",
        "key_version": "key-2026-08",
        "valid_from": (completed - timedelta(hours=1)).isoformat(),
        "valid_until": (completed + timedelta(hours=1)).isoformat(),
        "revoked_at": None,
    }
    trust_policy = {
        "schema_version": "1.1",
        "authority_index": {("execution-receipt", key_id): authority},
    }
    receipt = {"analysis": "lifecycle-test", "completed_at": completed.isoformat()}
    receipt["receipt_sha256"] = hashlib.sha256(canonical_bytes(receipt)).hexdigest()
    receipt["receipt_signature"] = sign_execution_receipt_with_provider(
        receipt, provider=Provider(), trust_policy=trust_policy
    )

    assert verify_execution_receipt_signature(receipt, trust_policy) == key_id

    authority["valid_until"] = (completed - timedelta(seconds=1)).isoformat()
    with pytest.raises(BenchmarkAssuranceError, match="not valid"):
        verify_execution_receipt_signature(receipt, trust_policy)


def test_external_signer_output_is_bounded_while_process_runs() -> None:
    executable = Path(sys.executable).resolve()
    key = Ed25519PrivateKey.generate()
    provider = ExternalEd25519SigningProvider(
        executable=executable,
        executable_sha256=hashlib.sha256(executable.read_bytes()).hexdigest(),
        arguments=("-c", "import sys;sys.stdout.buffer.write(b'x'*1000000)"),
        public_key=key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        ),
        provider_id="test-kms",
        key_version="version-1",
        timeout_seconds=5,
    )

    with pytest.raises(ValueError, match="output exceeded"):
        provider.sign(b"payload")


def test_signed_replay_checkpoint_detects_retained_state_tampering(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    ledger = tmp_path / "replay.sqlite3"
    ledger.touch()
    state_path = tmp_path / "checkpoint.json"
    key = Ed25519PrivateKey.generate()
    key_payload = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    key_path = tmp_path / "receipt-key.pem"
    key_path.write_bytes(key_payload)
    key_id = hashlib.sha256(
        key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    ).hexdigest()
    trust_policy = {
        "authority_index": {
            ("execution-receipt", key_id): {
                "organization_id": "receipt-authority",
                "status": "active",
            }
        }
    }
    written = write_benchmark_replay_checkpoint(
        state_path,
        {"sequence": 7, "checkpoint_sha256": "a" * 64},
        ledger=ledger,
        signing_key_path=key_path,
        signing_key_sha256=hashlib.sha256(key_payload).hexdigest(),
        workspace=workspace,
        trust_policy=trust_policy,
    )
    assert (
        load_benchmark_replay_checkpoint(
            state_path,
            ledger=ledger,
            workspace=workspace,
            trust_policy=trust_policy,
        )
        == written
    )

    tampered = json.loads(state_path.read_text(encoding="utf-8"))
    tampered["sequence"] = 6
    state_path.write_text(json.dumps(tampered), encoding="utf-8")
    with pytest.raises(BenchmarkAssuranceError, match="self-hash is invalid"):
        load_benchmark_replay_checkpoint(
            state_path,
            ledger=ledger,
            workspace=workspace,
            trust_policy=trust_policy,
        )


def test_signed_replay_intent_recovers_exactly_one_committed_advance(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    ledger = tmp_path / "replay.sqlite3"
    intent_path = tmp_path / "checkpoint.json.intent"
    key = Ed25519PrivateKey.generate()
    key_payload = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    key_path = tmp_path / "receipt-key.pem"
    key_path.write_bytes(key_payload)
    key_id = hashlib.sha256(
        key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    ).hexdigest()
    trust_policy = {
        "authority_index": {
            ("execution-receipt", key_id): {
                "organization_id": "receipt-authority",
                "status": "active",
            }
        }
    }
    arguments = {
        "sequence": 0,
        "checkpoint_sha256": BENCHMARK_REPLAY_GENESIS_SHA256,
        "nonce_sha256": "a" * 64,
        "subject_sha256": "b" * 64,
        "signer_key_id": "c" * 64,
    }
    written = write_benchmark_replay_intent(
        intent_path,
        ledger=ledger,
        signing_key_path=key_path,
        signing_key_sha256=hashlib.sha256(key_payload).hexdigest(),
        workspace=workspace,
        trust_policy=trust_policy,
        **arguments,
    )
    loaded = load_benchmark_replay_intent(
        intent_path,
        ledger=ledger,
        workspace=workspace,
        trust_policy=trust_policy,
        **arguments,
    )
    assert loaded == written
    assert (
        recover_benchmark_replay_intent(written, ledger=ledger, workspace=workspace)
        is None
    )

    consumed = consume_benchmark_replay(
        ledger,
        workspace=workspace,
        nonce_sha256=arguments["nonce_sha256"],
        subject_sha256=arguments["subject_sha256"],
        signer_key_id=arguments["signer_key_id"],
        require_current_head=True,
    )
    recovered = recover_benchmark_replay_intent(
        written, ledger=ledger, workspace=workspace
    )
    assert recovered == consumed
    remove_benchmark_replay_intent(intent_path, workspace=workspace)
    assert not intent_path.exists()


def test_replay_transition_lease_excludes_concurrent_writer(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    path = tmp_path / "checkpoint.lock"
    first = BenchmarkReplayLease(path, workspace=workspace, timeout_seconds=0.1)
    second = BenchmarkReplayLease(path, workspace=workspace, timeout_seconds=0.1)

    first.acquire()
    try:
        with pytest.raises(BenchmarkAssuranceError, match="already in progress"):
            second.acquire()
    finally:
        first.release()

    second.acquire()
    second.release()


def test_completed_replay_intent_is_reconciled_after_checkpoint_crash_window(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    ledger = tmp_path / "replay.sqlite3"
    intent_path = tmp_path / "checkpoint.json.intent"
    checkpoint_path = tmp_path / "checkpoint.json"
    key = Ed25519PrivateKey.generate()
    key_payload = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    key_path = tmp_path / "receipt-key.pem"
    key_path.write_bytes(key_payload)
    key_id = hashlib.sha256(
        key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    ).hexdigest()
    trust_policy = {
        "authority_index": {
            ("execution-receipt", key_id): {
                "organization_id": "receipt-authority",
                "status": "active",
            }
        }
    }
    intent = write_benchmark_replay_intent(
        intent_path,
        ledger=ledger,
        sequence=0,
        checkpoint_sha256=BENCHMARK_REPLAY_GENESIS_SHA256,
        nonce_sha256="a" * 64,
        subject_sha256="b" * 64,
        signer_key_id="c" * 64,
        signing_key_path=key_path,
        signing_key_sha256=hashlib.sha256(key_payload).hexdigest(),
        workspace=workspace,
        trust_policy=trust_policy,
    )
    consumed = consume_benchmark_replay(
        ledger,
        workspace=workspace,
        nonce_sha256=str(intent["nonce_sha256"]),
        subject_sha256=str(intent["subject_sha256"]),
        signer_key_id=str(intent["signer_key_id"]),
        require_current_head=True,
    )
    checkpoint = write_benchmark_replay_checkpoint(
        checkpoint_path,
        consumed,
        ledger=ledger,
        signing_key_path=key_path,
        signing_key_sha256=hashlib.sha256(key_payload).hexdigest(),
        workspace=workspace,
        trust_policy=trust_policy,
    )

    assert reconcile_completed_benchmark_replay_intent(
        intent_path,
        ledger=ledger,
        workspace=workspace,
        trust_policy=trust_policy,
        retained_checkpoint=checkpoint,
    )
    assert not intent_path.exists()
