from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from py_security_suite.governance_quorum import (
    verify_authority_quorum,
    verify_governance_quorum,
)
from py_security_suite.strict_json import canonical_bytes, dumps as strict_dumps


def _authority(
    root: Path,
    *,
    name: str,
    subject: object,
    purpose: str,
    now: datetime,
    algorithm: str = "ed25519",
    collector: str | None = None,
) -> tuple[dict[str, object], object]:
    key: Any
    if algorithm == "ed25519":
        key = Ed25519PrivateKey.generate()
        version = "1.0"
    else:
        key = ec.generate_private_key(ec.SECP256R1())
        version = "2.0"
    public_key = key.public_key()
    public_pem = public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    if algorithm == "ed25519":
        identity_bytes = public_key.public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
    else:
        identity_bytes = public_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    signer = hashlib.sha256(identity_bytes).hexdigest()
    signed_at = now - timedelta(minutes=1)
    expires_at = now + timedelta(hours=1)
    statement = {
        "schema_version": version,
        "purpose": purpose,
        "subject_sha256": hashlib.sha256(canonical_bytes(subject)).hexdigest(),
        "signer_id": signer,
        "collector_id": collector or f"collector-{name}",
        "signed_at": signed_at.isoformat(),
        "expires_at": expires_at.isoformat(),
    }
    if version == "2.0":
        statement["algorithm"] = algorithm
    if algorithm == "ed25519":
        signature = key.sign(canonical_bytes(statement))
    else:
        signature = key.sign(canonical_bytes(statement), ec.ECDSA(hashes.SHA256()))
    public_name = f"{name}.pem"
    signature_name = f"{name}.sig"
    (root / public_name).write_bytes(public_pem)
    (root / signature_name).write_bytes(signature)
    authority: dict[str, object] = {
        "schema_version": version,
        "signer_id": signer,
        "collector_id": statement["collector_id"],
        "signed_at": signed_at.isoformat(),
        "expires_at": expires_at.isoformat(),
        "public_key_file": public_name,
        "public_key_sha256": hashlib.sha256(public_pem).hexdigest(),
        "signature_file": signature_name,
        "signature_sha256": hashlib.sha256(signature).hexdigest(),
    }
    if version == "2.0":
        authority["algorithm"] = algorithm
    return authority, key


def _environment(
    authorities: list[dict[str, object]],
    *,
    purpose: str,
    now: datetime,
) -> dict[str, str]:
    signers = [str(authority["signer_id"]) for authority in authorities]
    return {
        "PYSEC_TRUSTED_AUTHORITY_KEY_SHA256": ",".join(signers),
        "PYSEC_TRUSTED_AUTHORITY_ROLES": strict_dumps(
            {signer: [purpose] for signer in signers}
        ),
        "PYSEC_AUTHORITY_ORGANIZATIONS": strict_dumps(
            {signer: f"organization-{index}" for index, signer in enumerate(signers)}
        ),
        "PYSEC_AUTHORITY_KEY_LIFECYCLE": strict_dumps(
            {
                signer: {
                    "not_before": (now - timedelta(days=1)).isoformat(),
                    "not_after": (now + timedelta(days=1)).isoformat(),
                    "revoked_at": None,
                }
                for signer in signers
            }
        ),
    }


def test_governance_quorum_accepts_independent_ed25519_and_p256_signers(
    tmp_path: Path,
) -> None:
    now = datetime.now(UTC)
    subject = {"policy": "production"}
    purpose = "execution-policy"
    authorities = [
        _authority(
            tmp_path,
            name="ed",
            subject=subject,
            purpose=purpose,
            now=now,
        )[0],
        _authority(
            tmp_path,
            name="p256",
            subject=subject,
            purpose=purpose,
            now=now,
            algorithm="ecdsa-p256-sha256",
        )[0],
    ]
    result = verify_governance_quorum(
        tmp_path / "policy.json",
        authorities,
        subject,
        2,
        now,
        purpose=purpose,
        trust_environment=_environment(authorities, purpose=purpose, now=now),
    )
    assert {item[3] for item in result} == {"ed25519", "ecdsa-p256-sha256"}
    assert len({item[2] for item in result}) == 2


@pytest.mark.parametrize(
    ("values", "threshold", "environment", "message"),
    [
        (None, 1, {}, "enough authorities"),
        ([], 1, {}, "enough authorities"),
        ([{}] * 17, 1, {}, "enough authorities"),
        ([{}], 1, {}, "trust anchors"),
        ([{}], 1, {"PYSEC_TRUSTED_AUTHORITY_KEY_SHA256": "x" * 64}, "trust anchors"),
    ],
)
def test_quorum_rejects_invalid_bounds_and_trust_roots(
    tmp_path: Path,
    values: object,
    threshold: int,
    environment: dict[str, str],
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        verify_authority_quorum(
            tmp_path / "policy.json",
            values,
            {},
            threshold,
            datetime.now(UTC),
            purpose="test",
            trust_environment=environment,
        )


@pytest.mark.parametrize("roles", ["{", "[]"])
def test_quorum_rejects_invalid_role_policy(tmp_path: Path, roles: str) -> None:
    environment = {
        "PYSEC_TRUSTED_AUTHORITY_KEY_SHA256": "a" * 64,
        "PYSEC_TRUSTED_AUTHORITY_ROLES": roles,
    }
    with pytest.raises(ValueError, match="role policy"):
        verify_authority_quorum(
            tmp_path / "policy.json",
            [{}],
            {},
            1,
            datetime.now(UTC),
            purpose="test",
            trust_environment=environment,
        )


def test_quorum_rejects_malformed_authority_fields_and_algorithms(
    tmp_path: Path,
) -> None:
    now = datetime.now(UTC)
    subject = {"policy": "production"}
    authority, _ = _authority(
        tmp_path, name="authority", subject=subject, purpose="test", now=now
    )
    environment = _environment([authority], purpose="test", now=now)
    for malformed, message in (
        ("authority", "fields"),
        ({**authority, "unexpected": True}, "fields"),
        ({**authority, "schema_version": "3.0"}, "fields"),
        (
            {**authority, "schema_version": "2.0", "algorithm": "rsa"},
            "unsupported",
        ),
        ({**authority, "collector_id": "bad value"}, "collector_id"),
        ({**authority, "signed_at": "bad"}, "signed_at"),
        ({**authority, "signed_at": now.replace(tzinfo=None).isoformat()}, "timezone"),
        (
            {
                **authority,
                "signed_at": (now - timedelta(days=32)).isoformat(),
            },
            "validity window",
        ),
    ):
        with pytest.raises(ValueError, match=message):
            verify_authority_quorum(
                tmp_path / "policy.json",
                [malformed],
                subject,
                1,
                now,
                purpose="test",
                trust_environment=environment,
            )


def test_quorum_rejects_detached_artifacts_keys_roles_and_signatures(
    tmp_path: Path,
) -> None:
    now = datetime.now(UTC)
    subject = {"policy": "production"}
    authority, _ = _authority(
        tmp_path, name="authority", subject=subject, purpose="test", now=now
    )
    environment = _environment([authority], purpose="test", now=now)

    cases: list[tuple[dict[str, object], dict[str, str], str]] = [
        ({**authority, "public_key_file": "../authority.pem"}, environment, "sibling"),
        ({**authority, "public_key_file": "missing.pem"}, environment, "artifact"),
        ({**authority, "public_key_sha256": "0" * 64}, environment, "digest"),
        ({**authority, "signer_id": "0" * 64}, environment, "deployment-trusted"),
        (
            authority,
            {**environment, "PYSEC_TRUSTED_AUTHORITY_ROLES": "{}"},
            "deployment role",
        ),
    ]
    for candidate, candidate_environment, message in cases:
        with pytest.raises(ValueError, match=message):
            verify_authority_quorum(
                tmp_path / "policy.json",
                [candidate],
                subject,
                1,
                now,
                purpose="test",
                trust_environment=candidate_environment,
            )

    public_path = tmp_path / str(authority["public_key_file"])
    original_public = public_path.read_bytes()
    public_path.write_text("not a key", encoding="utf-8")
    authority["public_key_sha256"] = hashlib.sha256(
        public_path.read_bytes()
    ).hexdigest()
    with pytest.raises(ValueError, match="public key is invalid"):
        verify_authority_quorum(
            tmp_path / "policy.json",
            [authority],
            subject,
            1,
            now,
            purpose="test",
            trust_environment=environment,
        )
    public_path.write_bytes(original_public)
    authority["public_key_sha256"] = hashlib.sha256(original_public).hexdigest()

    signature_path = tmp_path / str(authority["signature_file"])
    signature_path.write_bytes(b"invalid")
    authority["signature_sha256"] = hashlib.sha256(b"invalid").hexdigest()
    with pytest.raises(ValueError, match="signature verification"):
        verify_authority_quorum(
            tmp_path / "policy.json",
            [authority],
            subject,
            1,
            now,
            purpose="test",
            trust_environment=environment,
        )


def test_governance_quorum_rejects_organization_lifecycle_and_independence_gaps(
    tmp_path: Path,
) -> None:
    now = datetime.now(UTC)
    subject = {"policy": "production"}
    authorities = [
        _authority(
            tmp_path,
            name=str(index),
            subject=subject,
            purpose="test",
            now=now,
            collector="shared-collector",
        )[0]
        for index in range(2)
    ]
    environment = _environment(authorities, purpose="test", now=now)
    with pytest.raises(ValueError, match="independent"):
        verify_governance_quorum(
            tmp_path / "policy.json",
            authorities,
            subject,
            2,
            now,
            purpose="test",
            trust_environment=environment,
        )

    single = [authorities[0]]
    base = _environment(single, purpose="test", now=now)
    signer = str(single[0]["signer_id"])
    invalid_environments = [
        ({**base, "PYSEC_AUTHORITY_ORGANIZATIONS": "{"}, "mapping"),
        ({**base, "PYSEC_AUTHORITY_ORGANIZATIONS": "{}"}, "not configured"),
        (
            {**base, "PYSEC_AUTHORITY_ORGANIZATIONS": strict_dumps({"bad": "org"})},
            "invalid signer",
        ),
        ({**base, "PYSEC_AUTHORITY_KEY_LIFECYCLE": "{"}, "lifecycle"),
        ({**base, "PYSEC_AUTHORITY_KEY_LIFECYCLE": "{}"}, "not configured"),
        (
            {
                **base,
                "PYSEC_AUTHORITY_KEY_LIFECYCLE": strict_dumps(
                    {
                        signer: {
                            "not_before": (now - timedelta(days=1)).isoformat(),
                            "not_after": (now + timedelta(days=1)).isoformat(),
                            "revoked_at": (now - timedelta(minutes=2)).isoformat(),
                        }
                    }
                ),
            },
            "outside its lifecycle",
        ),
    ]
    for candidate, message in invalid_environments:
        with pytest.raises(ValueError, match=message):
            verify_governance_quorum(
                tmp_path / "policy.json",
                single,
                subject,
                1,
                now,
                purpose="test",
                trust_environment=candidate,
            )
