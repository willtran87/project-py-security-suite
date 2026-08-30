from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

import pytest

from py_security_suite.config import TrustConfig
from py_security_suite.organization_policy_attestation import (
    validate_organization_policy_attestation,
)
from py_security_suite.trust_attestation import validate_trust_policy_attestation


NOW = datetime(2026, 8, 30, 12, tzinfo=UTC)
POLICY_SHA256 = "a" * 64


def _attestation(**overrides: object) -> dict[str, object]:
    value: dict[str, object] = {
        "schema_version": "1.0",
        "policy_sha256": POLICY_SHA256,
        "generation": 3,
        "issued_at": (NOW - timedelta(minutes=5)).isoformat(),
        "expires_at": (NOW + timedelta(minutes=5)).isoformat(),
        "nonce": "deployment-nonce-0001",
        "minimum_authority_signatures": 2,
        "authorities": [{"signature": "one"}, {"signature": "two"}],
    }
    value.update(overrides)
    return value


def _write(path: Path, value: object) -> str:
    payload = json.dumps(value, separators=(",", ":")).encode()
    path.write_bytes(payload)
    return hashlib.sha256(payload).hexdigest()


def test_trust_attestation_absence_respects_requirement() -> None:
    optional = validate_trust_policy_attestation(
        TrustConfig(),
        {"policy_sha256": POLICY_SHA256},
        observed_at=NOW,
        trust_environment={},
    )
    required = validate_trust_policy_attestation(
        TrustConfig(require_signed_policy=True),
        {"policy_sha256": POLICY_SHA256},
        observed_at=NOW,
        trust_environment={},
    )

    assert optional.errors == []
    assert required.errors == [
        "production execution trust policy requires external quorum signatures"
    ]
    assert required.artifact["validated"] is False


def test_trust_attestation_verifies_quorum_and_consumes_replay(tmp_path: Path) -> None:
    path = tmp_path / "trust-attestation.json"
    digest = _write(path, _attestation())
    config = TrustConfig(
        policy_path=path,
        policy_sha256=digest,
        replay_ledger_path=tmp_path / "replay.sqlite3",
        require_signed_policy=True,
    )
    verified = [
        ("signer-b", "collector-b", "org-b", "ed25519"),
        ("signer-a", "collector-a", "org-a", "ed25519"),
    ]

    with (
        patch(
            "py_security_suite.trust_attestation.verify_governance_quorum",
            return_value=verified,
        ) as quorum,
        patch(
            "py_security_suite.trust_attestation.consume_governance_replay",
            return_value={"replay_sequence": 9},
        ) as replay,
    ):
        result = validate_trust_policy_attestation(
            config,
            {"policy_sha256": POLICY_SHA256},
            observed_at=NOW,
            trust_environment={"PYSEC_GOVERNANCE_MIN_GENERATION": "2"},
        )

    assert result.errors == []
    assert result.artifact["validated"] is True
    assert result.artifact["authority_signers"] == ["signer-a", "signer-b"]
    assert result.artifact["authority_organizations"] == ["org-a", "org-b"]
    assert result.artifact["replay_sequence"] == 9
    assert quorum.call_args.kwargs["purpose"] == "execution-trust-policy"
    assert replay.call_args.args[1] == digest


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ({"generation": True}, "generation is invalid"),
        ({"generation": 0}, "below deployment policy"),
        ({"minimum_authority_signatures": 1}, "threshold is invalid"),
        ({"nonce": "short"}, "nonce is invalid"),
        ({"expires_at": (NOW - timedelta(minutes=1)).isoformat()}, "validity window"),
        ({"policy_sha256": "b" * 64}, "detached"),
    ],
)
def test_trust_attestation_rejects_invalid_security_contracts(
    tmp_path: Path, mutation: dict[str, object], message: str
) -> None:
    path = tmp_path / "trust-attestation.json"
    digest = _write(path, _attestation(**mutation))
    result = validate_trust_policy_attestation(
        TrustConfig(policy_path=path, policy_sha256=digest, require_signed_policy=True),
        {"policy_sha256": POLICY_SHA256},
        observed_at=NOW,
        trust_environment={},
    )

    assert result.artifact["validated"] is False
    assert message in result.errors[0]


def test_organization_attestation_verifies_quorum_and_remote_replay(
    tmp_path: Path,
) -> None:
    path = tmp_path / "organization-attestation.json"
    digest = _write(path, _attestation())
    environment = {
        "PYSEC_ORGANIZATION_POLICY_ATTESTATION": str(path),
        "PYSEC_ORGANIZATION_POLICY_ATTESTATION_SHA256": digest.upper(),
        "PYSEC_GOVERNANCE_MIN_GENERATION": "2",
        "PYSEC_GOVERNANCE_REPLAY_REQUIRE_REMOTE": "true",
    }

    with (
        patch(
            "py_security_suite.organization_policy_attestation.verify_governance_quorum"
        ) as quorum,
        patch(
            "py_security_suite.organization_policy_attestation.consume_governance_replay"
        ) as replay,
    ):
        validate_organization_policy_attestation(
            POLICY_SHA256, observed_at=NOW, environment=environment
        )

    assert quorum.call_args.kwargs["purpose"] == "organization-policy"
    assert replay.call_args.args[1] == digest


@pytest.mark.parametrize(
    ("environment_update", "mutation", "message"),
    [
        ({"PYSEC_GOVERNANCE_MIN_GENERATION": "not-an-int"}, {}, "minimum generation"),
        ({}, {"generation": True}, "generation is invalid"),
        ({}, {"minimum_authority_signatures": 17}, "threshold is invalid"),
        ({}, {"nonce": "short"}, "nonce is invalid"),
        (
            {},
            {"issued_at": (NOW + timedelta(minutes=1)).isoformat()},
            "validity window",
        ),
    ],
)
def test_organization_attestation_rejects_invalid_contracts(
    tmp_path: Path,
    environment_update: dict[str, str],
    mutation: dict[str, object],
    message: str,
) -> None:
    path = tmp_path / "organization-attestation.json"
    digest = _write(path, _attestation(**mutation))
    environment = {
        "PYSEC_ORGANIZATION_POLICY_ATTESTATION": str(path),
        "PYSEC_ORGANIZATION_POLICY_ATTESTATION_SHA256": digest,
        **environment_update,
    }
    with pytest.raises(ValueError, match=message):
        validate_organization_policy_attestation(
            POLICY_SHA256, observed_at=NOW, environment=environment
        )


def test_organization_attestation_requires_deployment_configuration() -> None:
    with pytest.raises(ValueError, match="requires a signed policy attestation"):
        validate_organization_policy_attestation(
            POLICY_SHA256, observed_at=NOW, environment={}
        )
