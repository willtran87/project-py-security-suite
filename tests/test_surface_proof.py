from __future__ import annotations

import base64
import hashlib
from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from py_security_suite.strict_json import canonical_bytes
from py_security_suite.surface_proof import verify_surface_proof


def _receipt(
    private: Ed25519PrivateKey,
    *,
    purpose: str,
    subject: object,
    collector_id: str,
    observed_at: datetime,
) -> tuple[dict[str, object], str]:
    public = private.public_key()
    raw_public = public.public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    pem_public = public.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    signer_id = hashlib.sha256(raw_public).hexdigest()
    statement = {
        "schema_version": "1.0",
        "purpose": purpose,
        "subject_sha256": hashlib.sha256(canonical_bytes(subject)).hexdigest(),
        "signer_id": signer_id,
        "collector_id": collector_id,
        "signed_at": (observed_at - timedelta(minutes=1)).isoformat(),
        "expires_at": (observed_at + timedelta(minutes=1)).isoformat(),
    }
    signature = private.sign(canonical_bytes(statement))
    receipt_subject = {
        "schema_version": "1.0",
        "statement": statement,
        "public_key_pem_base64": base64.b64encode(pem_public).decode(),
        "public_key_sha256": hashlib.sha256(pem_public).hexdigest(),
        "signature_base64": base64.b64encode(signature).decode(),
        "signature_sha256": hashlib.sha256(signature).hexdigest(),
    }
    return {
        **receipt_subject,
        "receipt_sha256": hashlib.sha256(canonical_bytes(receipt_subject)).hexdigest(),
    }, signer_id


def _proof() -> dict[str, object]:
    observed_at = datetime(2026, 8, 24, 12, tzinfo=UTC)
    sources = []
    for index, kind in enumerate(("runtime", "gateway"), start=1):
        page_record_sha256s = [hashlib.sha256(f"record-{index}".encode()).hexdigest()]
        snapshot_records_sha256 = hashlib.sha256(
            canonical_bytes(page_record_sha256s)
        ).hexdigest()
        page_receipts = canonical_bytes(
            [
                {
                    "page_number": 1,
                    "request_sha256": "4" * 64,
                    "response_sha256": "5" * 64,
                    "continuation_in_sha256": "",
                    "continuation_out_sha256": "",
                    "record_count": 1,
                    "record_sha256s": page_record_sha256s,
                }
            ]
        )
        collector_subject = {
            "kind": kind,
            "sha256": f"{index}" * 64,
            "collector_organization": f"collector-org-{index}",
            "adapter_sha256": "a" * 64,
            "endpoint_identity_sha256": "b" * 64,
            "query_sha256": "c" * 64,
            "pages_expected": 1,
            "pages_observed": 1,
            "collection_complete": True,
            "collected_at": observed_at.isoformat(),
            "page_receipts_sha256": hashlib.sha256(page_receipts).hexdigest(),
            "snapshot_records_sha256": snapshot_records_sha256,
            "server_total_records": 1,
        }
        server_subject = {
            **collector_subject,
            "liveness_probes": 1,
            "server_organization": f"server-org-{index}",
        }
        collector_receipt, collector_signer = _receipt(
            Ed25519PrivateKey.generate(),
            purpose=f"surface-inventory:{kind}",
            subject=collector_subject,
            collector_id=f"collector-{index}",
            observed_at=observed_at,
        )
        server_receipt, server_signer = _receipt(
            Ed25519PrivateKey.generate(),
            purpose=f"surface-server-response:{kind}",
            subject=server_subject,
            collector_id=f"server-{index}",
            observed_at=observed_at,
        )
        sources.append(
            {
                "kind": kind,
                "snapshot_sha256": f"{index}" * 64,
                "collector_id": f"collector-{index}",
                "collector_signer_id": collector_signer,
                "collector_organization": f"collector-org-{index}",
                "adapter_sha256": "a" * 64,
                "endpoint_identity_sha256": "b" * 64,
                "query_sha256": "c" * 64,
                "pages_expected": 1,
                "pages_observed": 1,
                "page_receipts_sha256": hashlib.sha256(page_receipts).hexdigest(),
                "page_receipts_base64": base64.b64encode(page_receipts).decode(),
                "snapshot_records_sha256": snapshot_records_sha256,
                "server_total_records": 1,
                "records_observed": 1,
                "liveness_probes": 1,
                "server_collector_id": f"server-{index}",
                "server_signer_id": server_signer,
                "server_organization": f"server-org-{index}",
                "collected_at": observed_at.isoformat(),
                "collector_subject": collector_subject,
                "collector_receipt": collector_receipt,
                "server_subject": server_subject,
                "server_receipt": server_receipt,
            }
        )
    subject = {
        "schema_version": "1.0",
        "declared_sha256": "e" * 64,
        "history_sha256": "f" * 64,
        "trusted_time_sha256": "0" * 64,
        "sources": sources,
    }
    return {
        **subject,
        "proof_sha256": hashlib.sha256(canonical_bytes(subject)).hexdigest(),
    }


def test_surface_proof_replays_portable_collector_and_server_receipts() -> None:
    proof = _proof()
    assert verify_surface_proof({"surface_proof": proof}) == proof

    source = proof["sources"][0]  # type: ignore[index]
    source["server_receipt"]["signature_base64"] = base64.b64encode(b"invalid").decode()  # type: ignore[index]
    proof_subject = {
        name: value for name, value in proof.items() if name != "proof_sha256"
    }
    proof["proof_sha256"] = hashlib.sha256(canonical_bytes(proof_subject)).hexdigest()
    with pytest.raises(TypeError, match="receipt"):
        verify_surface_proof({"surface_proof": proof})
