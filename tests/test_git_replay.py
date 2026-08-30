from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

import pytest

from py_security_suite.git_replay import (
    _digest,
    _primary_failure_domain,
    _sha256_file,
    externalize_and_reverify_bundle,
)


def _domain(seed: str) -> dict[str, str]:
    return {
        "organization": f"organization-{seed}",
        "host_identity_sha256": hashlib.sha256(f"host-{seed}".encode()).hexdigest(),
        "control_plane_sha256": hashlib.sha256(f"control-{seed}".encode()).hexdigest(),
        "implementation_sha256": hashlib.sha256(
            f"implementation-{seed}".encode()
        ).hexdigest(),
    }


def _responses(bundle: Path) -> tuple[dict[str, object], dict[str, object]]:
    digest = _sha256_file(bundle)
    storage: dict[str, object] = {
        "schema_version": "1.0",
        "object_id": f"sha256:{digest}",
        "object_version": "version-1",
        "immutable_uri": f"cas://bundles/{digest}",
        "retention_until": (datetime.now(UTC) + timedelta(days=45)).isoformat(),
        "bundle_sha256": digest,
        "bundle_size_bytes": bundle.stat().st_size,
        "authority_key_sha256": "a" * 64,
        "execution_nonce": "storage-nonce",
        "failure_domain": _domain("storage"),
        "operation_receipt": {"receipt": "storage"},
        "effective_policy_attestation": {"attestation": "storage"},
    }
    secondary: dict[str, object] = {
        "schema_version": "1.0",
        "bundle_sha256": digest,
        "bundle_size_bytes": bundle.stat().st_size,
        "reachable_objects_sha256": "b" * 64,
        "signature_ledger_sha256": hashlib.sha256(b"{}").hexdigest(),
        "allowed_signers_sha256": "c" * 64,
        "verified_commits": 2,
        "verified_tags": 1,
        "cas_object_id": storage["object_id"],
        "cas_object_version": storage["object_version"],
        "cas_bundle_read_sha256": digest,
        "authority_key_sha256": "d" * 64,
        "execution_nonce": "secondary-nonce",
        "failure_domain": _domain("secondary"),
        "operation_receipt": {"receipt": "secondary"},
        "effective_policy_attestation": {"attestation": "secondary"},
    }
    return storage, secondary


def _primary_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    domain = _domain("primary")
    monkeypatch.setenv("PYSEC_GIT_PRIMARY_ORGANIZATION", domain["organization"])
    monkeypatch.setenv(
        "PYSEC_GIT_PRIMARY_HOST_IDENTITY_SHA256", domain["host_identity_sha256"]
    )
    monkeypatch.setenv(
        "PYSEC_GIT_PRIMARY_CONTROL_PLANE_SHA256",
        domain["control_plane_sha256"],
    )
    monkeypatch.setenv(
        "PYSEC_GIT_PRIMARY_IMPLEMENTATION_SHA256",
        domain["implementation_sha256"],
    )


def test_external_replay_binds_cas_and_independent_verifier(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundle = tmp_path / "repository.bundle"
    bundle.write_bytes(b"sealed-git-bundle")
    _primary_environment(monkeypatch)
    storage, secondary = _responses(bundle)

    with patch(
        "py_security_suite.git_replay._invoke", side_effect=[storage, secondary]
    ):
        result = externalize_and_reverify_bundle(
            bundle,
            reachable_objects_sha256="b" * 64,
            signature_ledger={},
            allowed_signers_sha256="c" * 64,
            verified_commits=2,
            verified_tags=1,
        )

    assert result["bundle_storage"] is storage
    assert result["secondary_verification"] is secondary
    assert result["primary_failure_domain"] == _domain("primary")


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("read-digest", "did not read"),
        ("detached-count", "detached"),
        ("retention", "not immutable"),
        ("shared-domain", "independent failure domains"),
    ],
)
def test_external_replay_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
    message: str,
) -> None:
    bundle = tmp_path / "repository.bundle"
    bundle.write_bytes(b"sealed-git-bundle")
    _primary_environment(monkeypatch)
    storage, secondary = _responses(bundle)
    if mutation == "read-digest":
        secondary["cas_bundle_read_sha256"] = "e" * 64
    elif mutation == "detached-count":
        secondary["verified_commits"] = 3
    elif mutation == "retention":
        storage["retention_until"] = datetime.now(UTC).isoformat()
    else:
        secondary["failure_domain"] = storage["failure_domain"]

    with (
        patch("py_security_suite.git_replay._invoke", side_effect=[storage, secondary]),
        pytest.raises(ValueError, match=message),
    ):
        externalize_and_reverify_bundle(
            bundle,
            reachable_objects_sha256="b" * 64,
            signature_ledger={},
            allowed_signers_sha256="c" * 64,
            verified_commits=2,
            verified_tags=1,
        )


def test_git_replay_digest_and_primary_identity_validation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    payload = tmp_path / "payload"
    payload.write_bytes(b"payload")
    assert _sha256_file(payload) == hashlib.sha256(b"payload").hexdigest()
    assert _digest("a" * 64)
    assert not _digest("A" * 64)
    assert not _digest("a" * 63)
    with pytest.raises(ValueError, match="identity is invalid"):
        _primary_failure_domain()
    _primary_environment(monkeypatch)
    assert _primary_failure_domain() == _domain("primary")
