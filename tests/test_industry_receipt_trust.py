from __future__ import annotations

import base64
import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from py_security_suite.industry_receipt_trust import (
    load_industry_receipt_trust,
    receipt_authority_projection,
)


def _deployment_policy(tmp_path: Path) -> dict[str, str]:
    issued = datetime.now(UTC) - timedelta(minutes=1)
    expires = issued + timedelta(days=30)
    authorities = []
    for index in range(4):
        authorities.append(
            {
                "role": "execution-receipt",
                "organization_id": f"receipt-org-{index % 2}",
                "public_key_sha256": f"{index + 1:x}" * 64,
                "revocation_status_sha256": f"{index + 5:x}" * 64,
                "status": "active",
                "key_version": f"key-{index + 1}",
                "valid_from": issued.isoformat(),
                "valid_until": expires.isoformat(),
                "revoked_at": None,
            }
        )
    value = {
        "schema_version": "1.1",
        "policy_id": "industry-receipt-authorities",
        "issued_at": issued.isoformat(),
        "expires_at": expires.isoformat(),
        "minimum_distinct_signers": 4,
        "minimum_distinct_organizations": 2,
        "authorities": authorities,
    }
    payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    policy = tmp_path / "receipt-authorities.json"
    policy.write_bytes(payload)
    root = Ed25519PrivateKey.generate()
    root_payload = root.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    root_path = tmp_path / "receipt-root.pem"
    signature = tmp_path / "receipt-authorities.sig"
    root_path.write_bytes(root_payload)
    signature.write_bytes(base64.b64encode(root.sign(payload)))
    return {
        "PYSEC_INDUSTRY_RECEIPT_AUTHORITY_POLICY": str(policy),
        "PYSEC_INDUSTRY_RECEIPT_AUTHORITY_POLICY_SHA256": hashlib.sha256(
            payload
        ).hexdigest(),
        "PYSEC_INDUSTRY_RECEIPT_AUTHORITY_POLICY_SIGNATURE": str(signature),
        "PYSEC_INDUSTRY_RECEIPT_AUTHORITY_TRUST_ROOT": str(root_path),
        "PYSEC_INDUSTRY_RECEIPT_AUTHORITY_TRUST_ROOT_SHA256": hashlib.sha256(
            root_payload
        ).hexdigest(),
    }


def test_industry_receipt_trust_is_external_signed_and_projected(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    policy, errors = load_industry_receipt_trust(
        workspace, environment=_deployment_policy(tmp_path)
    )

    assert errors == []
    assert policy is not None
    authorities, identity = receipt_authority_projection(policy)
    assert len(authorities) == 4
    assert identity is not None
    assert identity["policy_id"] == "industry-receipt-authorities"
    assert authorities[0]["key_id"] == "1" * 64


def test_industry_receipt_trust_rejects_partial_or_repository_configuration(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    policy, errors = load_industry_receipt_trust(
        workspace,
        environment={"PYSEC_INDUSTRY_RECEIPT_AUTHORITY_POLICY": "policy.json"},
    )
    assert policy is None
    assert "incomplete" in errors[0]

    environment = _deployment_policy(tmp_path)
    inside = workspace / "receipt-authorities.json"
    inside.write_bytes(
        Path(environment["PYSEC_INDUSTRY_RECEIPT_AUTHORITY_POLICY"]).read_bytes()
    )
    environment["PYSEC_INDUSTRY_RECEIPT_AUTHORITY_POLICY"] = str(inside)
    policy, errors = load_industry_receipt_trust(workspace, environment=environment)
    assert policy is None
    assert "outside" in errors[0]


def test_unconfigured_industry_receipt_trust_is_explicitly_absent(
    tmp_path: Path,
) -> None:
    assert load_industry_receipt_trust(tmp_path, environment={}) == (None, [])
    assert receipt_authority_projection(None) == ([], None)
