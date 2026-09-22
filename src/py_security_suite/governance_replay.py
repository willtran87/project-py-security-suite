from __future__ import annotations

import hashlib
import sqlite3
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .path_safety import read_regular_file
from .strict_json import canonical_bytes


def consume_governance_replay(
    document: dict[str, Any],
    digest: str,
    ledger: Path | None,
    purpose: str,
    *,
    trust_environment: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Consume governance evidence through local or remote monotonic state."""

    environment = trust_environment or {}
    service = environment.get("PYSEC_GOVERNANCE_REPLAY_SERVICE_URL", "")
    if service:
        return _consume_remote_governance_replay(document, digest, purpose, environment)
    if environment.get("PYSEC_GOVERNANCE_REPLAY_REQUIRE_REMOTE", "").casefold() in {
        "1",
        "true",
        "yes",
    }:
        raise ValueError("production governance requires remote monotonic replay")
    if ledger is None:
        raise ValueError("production governance v2 requires a replay ledger")
    resolved = ledger.expanduser().absolute()
    if resolved.is_symlink() or (resolved.exists() and not resolved.is_file()):
        raise ValueError("governance replay ledger is not a regular file")
    if not resolved.parent.is_dir() or resolved.parent.is_symlink():
        raise ValueError("governance replay ledger parent is not a regular directory")
    token = hashlib.sha256(
        canonical_bytes(
            {
                "purpose": purpose,
                "evidence_sha256": digest,
                "generation": document["generation"],
                "nonce": document["nonce"],
            }
        )
    ).hexdigest()
    connection: sqlite3.Connection | None = None
    try:
        connection = sqlite3.connect(resolved, timeout=10.0)
        with connection:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS consumed_governance ("
                "token TEXT PRIMARY KEY, purpose TEXT NOT NULL, consumed_at TEXT NOT NULL)"
            )
            connection.execute(
                "INSERT INTO consumed_governance(token, purpose, consumed_at) VALUES (?, ?, ?)",
                (token, purpose, datetime.now(UTC).isoformat()),
            )
    except sqlite3.IntegrityError as exc:
        raise ValueError("governance evidence replay was detected") from exc
    except sqlite3.Error as exc:
        raise ValueError("governance replay ledger could not be updated") from exc
    finally:
        if connection is not None:
            connection.close()
    return {
        "replay_backend": "local-sqlite",
        "replay_token_sha256": token,
        "trusted_consumed_at": None,
    }


def _consume_remote_governance_replay(
    document: dict[str, Any],
    digest: str,
    purpose: str,
    environment: Mapping[str, str],
) -> dict[str, Any]:
    from .evidence_ingest import _consume_replay_service

    required = {
        "token_env": "PYSEC_GOVERNANCE_REPLAY_SERVICE_TOKEN_ENV",
        "ca": "PYSEC_GOVERNANCE_REPLAY_SERVICE_CA",
        "receipt_key": "PYSEC_GOVERNANCE_REPLAY_SERVICE_RECEIPT_KEY",
        "client_cert": "PYSEC_GOVERNANCE_REPLAY_SERVICE_CLIENT_CERT",
        "client_key": "PYSEC_GOVERNANCE_REPLAY_SERVICE_CLIENT_KEY",  # pragma: allowlist secret
    }
    values = {
        name: environment.get(variable, "") for name, variable in required.items()
    }
    if any(not value for value in values.values()):
        raise ValueError("remote governance replay configuration is incomplete")
    for name in ("ca", "receipt_key", "client_cert", "client_key"):
        digest_name = f"PYSEC_GOVERNANCE_REPLAY_SERVICE_{name.upper()}_SHA256"
        expected = environment.get(digest_name, "").casefold()
        _, payload = read_regular_file(
            Path(values[name]),
            f"governance replay {name.replace('_', ' ')}",
            maximum_bytes=1024 * 1024,
        )
        if not expected or hashlib.sha256(payload).hexdigest() != expected:
            raise ValueError(f"remote governance replay {name} is not digest-pinned")
    identity_document = {
        "run_id": str(document["nonce"]),
        "kind": purpose,
        "source_sha256": digest,
        "environment_sha256": hashlib.sha256(canonical_bytes(environment)).hexdigest(),
        "context": {"generation": document["generation"]},
        "provenance": {"purpose": purpose},
        "evidence_binding": {
            "authenticated": True,
            "evidence_sha256": digest,
            "attestation": {
                "key_id": str(document.get("trust_root_sha256") or purpose)
            },
        },
    }
    state_text = environment.get("PYSEC_GOVERNANCE_REPLAY_SERVICE_STATE_FILE", "")
    if not state_text:
        raise ValueError(
            "remote governance replay requires a deployment-owned checkpoint state file"
        )
    receipt = _consume_replay_service(
        identity_document,
        environment["PYSEC_GOVERNANCE_REPLAY_SERVICE_URL"],
        token_env=values["token_env"],
        ca_path=Path(values["ca"]),
        receipt_public_key=Path(values["receipt_key"]),
        client_cert=Path(values["client_cert"]),
        client_key=Path(values["client_key"]),
        receipt_state_path=Path(state_text),
    )
    trusted_time = _timestamp(receipt["consumed_at"], "remote replay consumed_at")
    valid_from = document.get("valid_from", document.get("issued_at"))
    valid_until = document.get("valid_until", document.get("expires_at"))
    if (
        valid_from is not None
        and valid_until is not None
        and not (
            _timestamp(valid_from, "valid_from")
            <= trusted_time
            <= _timestamp(valid_until, "valid_until")
        )
    ):
        raise ValueError("governance evidence is invalid at trusted replay time")
    return {
        "replay_backend": "remote-mtls-monotonic",
        "replay_receipt_sequence": receipt["sequence"],
        "replay_receipt_sha256": receipt["receipt_sha256"],
        "replay_receipt_key_id": receipt["key_id"],
        "trusted_consumed_at": receipt["consumed_at"],
    }


def _timestamp(value: object, label: str) -> datetime:
    if not isinstance(value, str) or not value or len(value) > 500:
        raise ValueError(f"{label} must be non-empty and at most 500 characters")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{label} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{label} must include a timezone")
    return parsed.astimezone(UTC)
