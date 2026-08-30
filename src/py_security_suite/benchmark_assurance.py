from __future__ import annotations

import base64
import hashlib
import os
import re
import sqlite3
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .benchmark_signing import LocalEd25519SigningProvider, ReceiptSigningProvider
from .atomic_file import atomic_write_bytes
from .path_safety import read_regular_file, resolve_unlinked_path
from .strict_json import canonical_bytes, loads as strict_loads


_MAX_POLICY_BYTES = 2 * 1024 * 1024
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9._-]{1,127}$")
_ROLES = {
    "trusted-time",
    "replay-protection",
    "contamination-manifest",
    "runner-sbom",
    "runner-provenance",
    "environment",
    "acceptance-criteria",
    "adapter-conformance",
    "runtime-observation",
    "external-isolation",
    "cleanup-capability",
    "execution-receipt",
    "provenance-builder",
    "security-event-anchor",
}
BENCHMARK_REPLAY_GENESIS_SHA256 = hashlib.sha256(
    b"pysec-benchmark-replay-genesis-v1"
).hexdigest()


class BenchmarkAssuranceError(ValueError):
    """Raised when deployment-owned benchmark assurance cannot be established."""


class BenchmarkReplayLease:
    """Cross-process exclusive lease for a replay checkpoint transition.

    The operating system releases the advisory lock when a process exits, so a
    crash cannot strand a permanent lock.  The lock is held across intent, ledger,
    and checkpoint operations, closing the race between otherwise atomic files.
    """

    def __init__(
        self, path: Path, *, workspace: Path, timeout_seconds: float = 30.0
    ) -> None:
        if not 0.1 <= timeout_seconds <= 60.0:
            raise BenchmarkAssuranceError("benchmark replay lease timeout is invalid")
        self._path = _replay_state_destination(
            path, workspace, "benchmark replay transition lease"
        )
        self._timeout_seconds = timeout_seconds
        self._descriptor: int | None = None

    def acquire(self) -> None:
        if self._descriptor is not None:
            raise BenchmarkAssuranceError("benchmark replay lease is already held")
        try:
            descriptor = os.open(self._path, os.O_RDWR | os.O_CREAT, 0o600)
            if os.fstat(descriptor).st_size == 0:
                os.write(descriptor, b"0")
            os.lseek(descriptor, 0, os.SEEK_SET)
        except OSError as exc:
            raise BenchmarkAssuranceError(
                "benchmark replay transition lease could not be opened"
            ) from exc
        deadline = time.monotonic() + self._timeout_seconds
        while True:
            try:
                _lock_descriptor(descriptor)
                self._descriptor = descriptor
                return
            except OSError as exc:
                if time.monotonic() >= deadline:
                    os.close(descriptor)
                    raise BenchmarkAssuranceError(
                        "benchmark replay transition is already in progress"
                    ) from exc
                time.sleep(0.05)

    def release(self) -> None:
        descriptor = self._descriptor
        if descriptor is None:
            return
        self._descriptor = None
        try:
            _unlock_descriptor(descriptor)
        finally:
            os.close(descriptor)

    def __enter__(self) -> BenchmarkReplayLease:
        self.acquire()
        return self

    def __exit__(self, *_: object) -> None:
        self.release()


def load_authority_trust_policy(
    path: Path,
    expected_sha256: str,
    *,
    signature_path: Path,
    trust_root_path: Path,
    trust_root_sha256: str,
    workspace: Path,
    manifest_policy: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Load a root-signed authority policy outside the target workspace."""
    if not _DIGEST.fullmatch(expected_sha256):
        raise BenchmarkAssuranceError("authority trust policy digest is invalid")
    requested = path.expanduser().absolute()
    boundary = workspace.expanduser().absolute().resolve()
    _require_outside_workspace(
        requested,
        boundary,
        "authority trust policy",
    )
    try:
        resolved, payload = read_regular_file(
            requested,
            "authority trust policy",
            maximum_bytes=_MAX_POLICY_BYTES,
        )
    except (OSError, ValueError) as exc:
        raise BenchmarkAssuranceError(
            "authority trust policy is not a safe regular file"
        ) from exc
    _require_outside_workspace(resolved, boundary, "authority trust policy")
    if hashlib.sha256(payload).hexdigest() != expected_sha256:
        raise BenchmarkAssuranceError("authority trust policy digest does not match")
    trust_root_id = _verify_policy_signature(
        payload,
        signature_path=signature_path,
        trust_root_path=trust_root_path,
        trust_root_sha256=trust_root_sha256,
        workspace=workspace,
    )
    try:
        value = strict_loads(payload)
    except (TypeError, ValueError) as exc:
        raise BenchmarkAssuranceError("authority trust policy is invalid JSON") from exc
    required = {
        "schema_version",
        "policy_id",
        "issued_at",
        "expires_at",
        "minimum_distinct_signers",
        "minimum_distinct_organizations",
        "authorities",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise BenchmarkAssuranceError("authority trust policy contract is invalid")
    if (
        value["schema_version"] not in {"1.0", "1.1"}
        or not isinstance(value["policy_id"], str)
        or not _IDENTIFIER.fullmatch(value["policy_id"])
    ):
        raise BenchmarkAssuranceError("authority trust policy identity is invalid")
    _validate_policy_time(value)
    for field, minimum in (
        ("minimum_distinct_signers", 4),
        ("minimum_distinct_organizations", 2),
    ):
        item = value[field]
        if (
            not isinstance(item, int)
            or isinstance(item, bool)
            or not minimum <= item <= 32
        ):
            raise BenchmarkAssuranceError(f"authority trust policy {field} is invalid")
        if manifest_policy is not None and manifest_policy[field] < item:
            raise BenchmarkAssuranceError(
                f"manifest authority policy weakens deployment {field}"
            )
    authorities = value["authorities"]
    if not isinstance(authorities, list) or not 4 <= len(authorities) <= 256:
        raise BenchmarkAssuranceError("authority trust policy entries are invalid")
    identities: set[tuple[str, str]] = set()
    active_signers: set[str] = set()
    active_organizations: set[str] = set()
    roles: set[str] = set()
    for entry in authorities:
        _validate_authority_entry(entry, policy=value)
        identity = (entry["role"], entry["public_key_sha256"])
        if identity in identities:
            raise BenchmarkAssuranceError("authority trust policy contains duplicates")
        identities.add(identity)
        if entry["status"] == "active":
            active_signers.add(entry["public_key_sha256"])
            active_organizations.add(entry["organization_id"])
        roles.add(entry["role"])
    if len(active_signers) < value["minimum_distinct_signers"]:
        raise BenchmarkAssuranceError("authority trust policy signer quorum is invalid")
    if len(active_organizations) < value["minimum_distinct_organizations"]:
        raise BenchmarkAssuranceError(
            "authority trust policy organization quorum is invalid"
        )
    return {
        **value,
        "sha256": expected_sha256,
        "path": str(resolved),
        "trust_root_key_id": trust_root_id,
        "authority_index": {
            (entry["role"], entry["public_key_sha256"]): entry for entry in authorities
        },
        "roles": roles,
    }


def validate_trusted_authority(
    *,
    kind: str,
    public_key_payload: bytes,
    authority: dict[str, Any],
    trust_policy: dict[str, Any],
) -> str:
    """Require an attestation signer to be admitted by deployment policy."""
    try:
        key = serialization.load_pem_public_key(public_key_payload)
    except (TypeError, ValueError) as exc:
        raise BenchmarkAssuranceError("attestation public key is invalid") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise BenchmarkAssuranceError("attestation key must use Ed25519")
    key_sha256 = _public_key_id(key)
    entry = trust_policy["authority_index"].get((kind, key_sha256))
    if not isinstance(entry, dict):
        raise BenchmarkAssuranceError(
            f"{kind} signer is not admitted by deployment authority policy"
        )
    for field in ("organization_id", "revocation_status_sha256"):
        if authority.get(field) != entry[field]:
            raise BenchmarkAssuranceError(
                f"{kind} authority {field} does not match deployment policy"
            )
    if entry["status"] != "active":
        raise BenchmarkAssuranceError(f"{kind} authority is not active")
    return key_sha256


def consume_benchmark_replay(
    ledger: Path,
    *,
    workspace: Path,
    nonce_sha256: str,
    subject_sha256: str,
    signer_key_id: str,
    minimum_sequence: int = 0,
    expected_checkpoint_sha256: str = BENCHMARK_REPLAY_GENESIS_SHA256,
    require_current_head: bool = False,
) -> dict[str, Any]:
    """Atomically consume a nonce in a checkpointed deployment SQLite ledger."""
    for value, label in (
        (nonce_sha256, "nonce"),
        (subject_sha256, "subject"),
        (signer_key_id, "signer"),
    ):
        if not _DIGEST.fullmatch(value):
            raise BenchmarkAssuranceError(f"benchmark replay {label} is invalid")
    if (
        not isinstance(minimum_sequence, int)
        or isinstance(minimum_sequence, bool)
        or minimum_sequence < 0
        or not _DIGEST.fullmatch(expected_checkpoint_sha256)
    ):
        raise BenchmarkAssuranceError("benchmark replay checkpoint policy is invalid")
    requested = ledger.expanduser().absolute()
    boundary = workspace.expanduser().absolute().resolve()
    _require_outside_workspace(
        requested,
        boundary,
        "benchmark replay ledger",
    )
    try:
        parent = resolve_unlinked_path(
            requested.parent, "benchmark replay ledger parent"
        )
    except (OSError, ValueError) as exc:
        raise BenchmarkAssuranceError(
            "benchmark replay ledger parent must be an existing regular directory"
        ) from exc
    if not parent.is_dir():
        raise BenchmarkAssuranceError(
            "benchmark replay ledger parent must be an existing regular directory"
        )
    resolved = parent / requested.name
    _require_outside_workspace(resolved, boundary, "benchmark replay ledger")
    if requested.is_symlink() or (resolved.exists() and not resolved.is_file()):
        raise BenchmarkAssuranceError("benchmark replay ledger is unsafe")
    if not resolved.exists():
        try:
            descriptor = os.open(resolved, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.close(descriptor)
        except FileExistsError:
            pass
        except OSError as exc:
            raise BenchmarkAssuranceError(
                "benchmark replay ledger could not be created"
            ) from exc
    consumed_at = datetime.now(UTC).isoformat()
    token = _replay_token(nonce_sha256, subject_sha256, signer_key_id)
    connection: sqlite3.Connection | None = None
    try:
        connection = sqlite3.connect(resolved, timeout=30, isolation_level=None)
        connection.execute("PRAGMA busy_timeout=30000")
        _enable_replay_wal(connection)
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(
            "CREATE TABLE IF NOT EXISTS consumed_benchmarks ("
            "sequence INTEGER PRIMARY KEY AUTOINCREMENT, token TEXT UNIQUE NOT NULL, "
            "nonce_sha256 TEXT UNIQUE NOT NULL, subject_sha256 TEXT NOT NULL, "
            "signer_key_id TEXT NOT NULL, consumed_at TEXT NOT NULL, "
            "previous_checkpoint_sha256 TEXT NOT NULL DEFAULT '', "
            "checkpoint_sha256 TEXT NOT NULL DEFAULT '')"
        )
        _migrate_replay_checkpoints(connection)
        latest = connection.execute(
            "SELECT sequence, checkpoint_sha256 FROM consumed_benchmarks "
            "ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        latest_sequence = int(latest[0]) if latest is not None else 0
        latest_checkpoint = (
            str(latest[1]) if latest is not None else BENCHMARK_REPLAY_GENESIS_SHA256
        )
        if minimum_sequence == 0:
            retained_checkpoint = BENCHMARK_REPLAY_GENESIS_SHA256
        else:
            retained = connection.execute(
                "SELECT checkpoint_sha256 FROM consumed_benchmarks WHERE sequence = ?",
                (minimum_sequence,),
            ).fetchone()
            if retained is None:
                connection.execute("ROLLBACK")
                raise BenchmarkAssuranceError(
                    "benchmark replay ledger deletion or rollback detected"
                )
            retained_checkpoint = str(retained[0])
        if retained_checkpoint != expected_checkpoint_sha256:
            connection.execute("ROLLBACK")
            raise BenchmarkAssuranceError(
                "benchmark replay ledger checkpoint does not match deployment state"
            )
        if require_current_head and (
            latest_sequence != minimum_sequence
            or latest_checkpoint != expected_checkpoint_sha256
        ):
            connection.execute("ROLLBACK")
            raise BenchmarkAssuranceError(
                "benchmark replay ledger advanced beyond the retained deployment "
                "checkpoint"
            )
        previous_checkpoint = latest_checkpoint
        sequence = latest_sequence + 1
        checkpoint = _replay_checkpoint(
            sequence=sequence,
            previous_checkpoint_sha256=previous_checkpoint,
            token=token,
            nonce_sha256=nonce_sha256,
            subject_sha256=subject_sha256,
            signer_key_id=signer_key_id,
            consumed_at=consumed_at,
        )
        cursor = connection.execute(
            "INSERT INTO consumed_benchmarks("
            "token, nonce_sha256, subject_sha256, signer_key_id, consumed_at, "
            "previous_checkpoint_sha256, checkpoint_sha256"
            ") VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                token,
                nonce_sha256,
                subject_sha256,
                signer_key_id,
                consumed_at,
                previous_checkpoint,
                checkpoint,
            ),
        )
        if cursor.lastrowid is None:
            raise BenchmarkAssuranceError(
                "benchmark replay ledger did not return a sequence"
            )
        sequence = int(cursor.lastrowid)
        connection.execute("COMMIT")
    except sqlite3.IntegrityError as exc:
        if connection is not None:
            connection.execute("ROLLBACK")
        raise BenchmarkAssuranceError(
            "benchmark replay nonce was already consumed"
        ) from exc
    except sqlite3.Error as exc:
        if connection is not None and connection.in_transaction:
            connection.execute("ROLLBACK")
        raise BenchmarkAssuranceError(
            "benchmark replay ledger could not be updated"
        ) from exc
    finally:
        if connection is not None:
            connection.close()
    receipt = {
        "schema_version": "1.0",
        "backend": "deployment-sqlite",
        "sequence": sequence,
        "token": token,
        "nonce_sha256": nonce_sha256,
        "subject_sha256": subject_sha256,
        "signer_key_id": signer_key_id,
        "consumed_at": consumed_at,
        "previous_checkpoint_sha256": previous_checkpoint,
        "checkpoint_sha256": checkpoint,
    }
    receipt["receipt_sha256"] = hashlib.sha256(canonical_bytes(receipt)).hexdigest()
    return receipt


def load_benchmark_replay_checkpoint(
    path: Path,
    *,
    ledger: Path,
    workspace: Path,
    trust_policy: dict[str, Any],
) -> dict[str, Any] | None:
    """Load and verify a deployment-retained signed replay checkpoint."""
    requested = path.expanduser().absolute()
    boundary = workspace.expanduser().absolute().resolve()
    _require_outside_workspace(requested, boundary, "benchmark replay checkpoint")
    if not requested.exists():
        return None
    try:
        resolved, payload = read_regular_file(
            requested,
            "benchmark replay checkpoint",
            maximum_bytes=128 * 1024,
        )
    except (OSError, ValueError) as exc:
        raise BenchmarkAssuranceError(
            "benchmark replay checkpoint is not a safe regular file"
        ) from exc
    _require_outside_workspace(resolved, boundary, "benchmark replay checkpoint")
    try:
        value = strict_loads(payload)
    except (TypeError, ValueError) as exc:
        raise BenchmarkAssuranceError(
            "benchmark replay checkpoint is invalid JSON"
        ) from exc
    required = {
        "schema_version",
        "analysis",
        "ledger_identity_sha256",
        "sequence",
        "checkpoint_sha256",
        "updated_at",
        "receipt_sha256",
        "receipt_signature",
    }
    if (
        not isinstance(value, dict)
        or set(value) != required
        or value["schema_version"] != "1.0"
        or value["analysis"] != "benchmark-replay-checkpoint"
        or value["ledger_identity_sha256"] != _ledger_identity(ledger)
        or not isinstance(value["sequence"], int)
        or isinstance(value["sequence"], bool)
        or value["sequence"] < 1
        or not isinstance(value["checkpoint_sha256"], str)
        or not _DIGEST.fullmatch(value["checkpoint_sha256"])
        or not _is_utc_timestamp(value["updated_at"])
    ):
        raise BenchmarkAssuranceError("benchmark replay checkpoint contract is invalid")
    verify_execution_receipt_signature(value, trust_policy)
    return value


def load_benchmark_replay_intent(
    path: Path,
    *,
    ledger: Path,
    workspace: Path,
    trust_policy: dict[str, Any],
    sequence: int,
    checkpoint_sha256: str,
    nonce_sha256: str,
    subject_sha256: str,
    signer_key_id: str,
) -> dict[str, Any] | None:
    """Load a signed write-ahead intent and bind it to the requested transition."""
    destination = _replay_state_destination(path, workspace, "benchmark replay intent")
    if not destination.exists():
        return None
    try:
        _, payload = read_regular_file(
            destination, "benchmark replay intent", maximum_bytes=128 * 1024
        )
        value = strict_loads(payload)
    except (OSError, TypeError, ValueError) as exc:
        raise BenchmarkAssuranceError("benchmark replay intent is invalid") from exc
    required = {
        "schema_version",
        "analysis",
        "ledger_identity_sha256",
        "sequence",
        "checkpoint_sha256",
        "nonce_sha256",
        "subject_sha256",
        "signer_key_id",
        "created_at",
        "receipt_sha256",
        "receipt_signature",
    }
    if (
        not isinstance(value, dict)
        or set(value) != required
        or value.get("schema_version") != "1.0"
        or value.get("analysis") != "benchmark-replay-intent"
        or value.get("ledger_identity_sha256") != _ledger_identity(ledger)
        or value.get("sequence") != sequence
        or value.get("checkpoint_sha256") != checkpoint_sha256
        or value.get("nonce_sha256") != nonce_sha256
        or value.get("subject_sha256") != subject_sha256
        or value.get("signer_key_id") != signer_key_id
        or not _is_utc_timestamp(value.get("created_at"))
    ):
        raise BenchmarkAssuranceError(
            "benchmark replay intent does not match the requested transition"
        )
    verify_execution_receipt_signature(value, trust_policy)
    return value


def recover_benchmark_replay_intent(
    intent: dict[str, Any], *, ledger: Path, workspace: Path
) -> dict[str, Any] | None:
    """Recover exactly one ledger advance authorized by a signed intent."""
    destination = ledger.expanduser().absolute()
    boundary = workspace.expanduser().absolute().resolve()
    _require_outside_workspace(destination, boundary, "benchmark replay ledger")
    if not destination.exists():
        return None
    if destination.is_symlink() or not destination.is_file():
        raise BenchmarkAssuranceError("benchmark replay ledger is unsafe")
    expected_sequence = int(intent["sequence"]) + 1
    token = _replay_token(
        str(intent["nonce_sha256"]),
        str(intent["subject_sha256"]),
        str(intent["signer_key_id"]),
    )
    try:
        with sqlite3.connect(
            destination, timeout=30, isolation_level=None
        ) as connection:
            connection.execute("BEGIN IMMEDIATE")
            _migrate_replay_checkpoints(connection)
            latest = connection.execute(
                "SELECT sequence FROM consumed_benchmarks ORDER BY sequence DESC LIMIT 1"
            ).fetchone()
            if latest is None or int(latest[0]) == int(intent["sequence"]):
                connection.execute("ROLLBACK")
                return None
            if int(latest[0]) != expected_sequence:
                connection.execute("ROLLBACK")
                raise BenchmarkAssuranceError(
                    "benchmark replay ledger advanced beyond the signed intent"
                )
            row = connection.execute(
                "SELECT sequence, token, nonce_sha256, subject_sha256, signer_key_id, "
                "consumed_at, previous_checkpoint_sha256, checkpoint_sha256 "
                "FROM consumed_benchmarks WHERE sequence = ?",
                (expected_sequence,),
            ).fetchone()
            connection.execute("ROLLBACK")
    except sqlite3.Error as exc:
        raise BenchmarkAssuranceError(
            "benchmark replay intent recovery failed"
        ) from exc
    if row is None:
        raise BenchmarkAssuranceError("benchmark replay intent record is absent")
    expected = (
        expected_sequence,
        token,
        intent["nonce_sha256"],
        intent["subject_sha256"],
        intent["signer_key_id"],
        row[5],
        intent["checkpoint_sha256"],
        row[7],
    )
    if tuple(row) != expected or row[7] != _replay_checkpoint(
        sequence=expected_sequence,
        previous_checkpoint_sha256=str(intent["checkpoint_sha256"]),
        token=token,
        nonce_sha256=str(intent["nonce_sha256"]),
        subject_sha256=str(intent["subject_sha256"]),
        signer_key_id=str(intent["signer_key_id"]),
        consumed_at=str(row[5]),
    ):
        raise BenchmarkAssuranceError(
            "benchmark replay ledger does not match the signed recovery intent"
        )
    receipt = {
        "schema_version": "1.0",
        "backend": "deployment-sqlite",
        "sequence": expected_sequence,
        "token": token,
        "nonce_sha256": intent["nonce_sha256"],
        "subject_sha256": intent["subject_sha256"],
        "signer_key_id": intent["signer_key_id"],
        "consumed_at": row[5],
        "previous_checkpoint_sha256": intent["checkpoint_sha256"],
        "checkpoint_sha256": row[7],
    }
    receipt["receipt_sha256"] = hashlib.sha256(canonical_bytes(receipt)).hexdigest()
    return receipt


def write_benchmark_replay_checkpoint(
    path: Path,
    replay_receipt: dict[str, Any],
    *,
    ledger: Path,
    signing_key_path: Path | None,
    signing_key_sha256: str,
    workspace: Path,
    trust_policy: dict[str, Any],
    signing_provider: ReceiptSigningProvider | None = None,
) -> dict[str, Any]:
    """Atomically advance a signed deployment replay checkpoint."""
    requested = path.expanduser().absolute()
    boundary = workspace.expanduser().absolute().resolve()
    _require_outside_workspace(requested, boundary, "benchmark replay checkpoint")
    try:
        parent = resolve_unlinked_path(
            requested.parent, "benchmark replay checkpoint parent"
        )
    except (OSError, ValueError) as exc:
        raise BenchmarkAssuranceError(
            "benchmark replay checkpoint parent is unsafe"
        ) from exc
    destination = parent / requested.name
    if requested.is_symlink() or (destination.exists() and not destination.is_file()):
        raise BenchmarkAssuranceError("benchmark replay checkpoint is unsafe")
    state: dict[str, Any] = {
        "schema_version": "1.0",
        "analysis": "benchmark-replay-checkpoint",
        "ledger_identity_sha256": _ledger_identity(ledger),
        "sequence": replay_receipt["sequence"],
        "checkpoint_sha256": replay_receipt["checkpoint_sha256"],
        "updated_at": datetime.now(UTC).isoformat(),
    }
    state["receipt_sha256"] = hashlib.sha256(canonical_bytes(state)).hexdigest()
    if signing_provider is not None:
        state["receipt_signature"] = sign_execution_receipt_with_provider(
            state, provider=signing_provider, trust_policy=trust_policy
        )
    elif signing_key_path is not None:
        state["receipt_signature"] = sign_execution_receipt(
            state,
            signing_key_path=signing_key_path,
            signing_key_sha256=signing_key_sha256,
            workspace=workspace,
            trust_policy=trust_policy,
        )
    else:
        raise BenchmarkAssuranceError("receipt signing provider is unavailable")
    _atomic_write_replay_state(destination, state)
    return state


def write_benchmark_replay_intent(
    path: Path,
    *,
    ledger: Path,
    sequence: int,
    checkpoint_sha256: str,
    nonce_sha256: str,
    subject_sha256: str,
    signer_key_id: str,
    signing_key_path: Path | None,
    signing_key_sha256: str,
    workspace: Path,
    trust_policy: dict[str, Any],
    signing_provider: ReceiptSigningProvider | None = None,
) -> dict[str, Any]:
    """Persist a signed write-ahead intent before advancing the replay ledger."""
    if (
        not isinstance(sequence, int)
        or isinstance(sequence, bool)
        or sequence < 0
        or any(
            not _DIGEST.fullmatch(value)
            for value in (
                checkpoint_sha256,
                nonce_sha256,
                subject_sha256,
                signer_key_id,
            )
        )
    ):
        raise BenchmarkAssuranceError("benchmark replay intent transition is invalid")
    destination = _replay_state_destination(path, workspace, "benchmark replay intent")
    state: dict[str, Any] = {
        "schema_version": "1.0",
        "analysis": "benchmark-replay-intent",
        "ledger_identity_sha256": _ledger_identity(ledger),
        "sequence": sequence,
        "checkpoint_sha256": checkpoint_sha256,
        "nonce_sha256": nonce_sha256,
        "subject_sha256": subject_sha256,
        "signer_key_id": signer_key_id,
        "created_at": datetime.now(UTC).isoformat(),
    }
    state["receipt_sha256"] = hashlib.sha256(canonical_bytes(state)).hexdigest()
    if signing_provider is not None:
        state["receipt_signature"] = sign_execution_receipt_with_provider(
            state, provider=signing_provider, trust_policy=trust_policy
        )
    elif signing_key_path is not None:
        state["receipt_signature"] = sign_execution_receipt(
            state,
            signing_key_path=signing_key_path,
            signing_key_sha256=signing_key_sha256,
            workspace=workspace,
            trust_policy=trust_policy,
        )
    else:
        raise BenchmarkAssuranceError("receipt signing provider is unavailable")
    _atomic_write_replay_state(destination, state)
    return state


def remove_benchmark_replay_intent(path: Path, *, workspace: Path) -> None:
    """Remove a committed replay intent without following links."""
    destination = _replay_state_destination(path, workspace, "benchmark replay intent")
    if destination.exists():
        destination.unlink()


def reconcile_completed_benchmark_replay_intent(
    path: Path,
    *,
    ledger: Path,
    workspace: Path,
    trust_policy: dict[str, Any],
    retained_checkpoint: dict[str, Any] | None,
) -> bool:
    """Remove only an intent whose exact ledger advance is durably checkpointed."""
    if retained_checkpoint is None:
        return False
    destination = _replay_state_destination(path, workspace, "benchmark replay intent")
    if not destination.exists():
        return False
    try:
        _, payload = read_regular_file(
            destination, "benchmark replay intent", maximum_bytes=128 * 1024
        )
        value = strict_loads(payload)
    except (OSError, TypeError, ValueError) as exc:
        raise BenchmarkAssuranceError("benchmark replay intent is invalid") from exc
    required = {
        "schema_version",
        "analysis",
        "ledger_identity_sha256",
        "sequence",
        "checkpoint_sha256",
        "nonce_sha256",
        "subject_sha256",
        "signer_key_id",
        "created_at",
        "receipt_sha256",
        "receipt_signature",
    }
    if (
        not isinstance(value, dict)
        or set(value) != required
        or value.get("schema_version") != "1.0"
        or value.get("analysis") != "benchmark-replay-intent"
        or value.get("ledger_identity_sha256") != _ledger_identity(ledger)
        or not isinstance(value.get("sequence"), int)
        or isinstance(value.get("sequence"), bool)
        or not all(
            isinstance(value.get(field), str) and _DIGEST.fullmatch(str(value[field]))
            for field in (
                "checkpoint_sha256",
                "nonce_sha256",
                "subject_sha256",
                "signer_key_id",
            )
        )
        or not _is_utc_timestamp(value.get("created_at"))
    ):
        raise BenchmarkAssuranceError("benchmark replay intent contract is invalid")
    verify_execution_receipt_signature(value, trust_policy)
    if int(value["sequence"]) + 1 != int(retained_checkpoint["sequence"]):
        return False
    recovered = recover_benchmark_replay_intent(
        value, ledger=ledger, workspace=workspace
    )
    if recovered is None or (
        recovered["sequence"] != retained_checkpoint["sequence"]
        or recovered["checkpoint_sha256"] != retained_checkpoint["checkpoint_sha256"]
    ):
        raise BenchmarkAssuranceError(
            "benchmark replay intent is not bound to the retained checkpoint"
        )
    remove_benchmark_replay_intent(path, workspace=workspace)
    return True


def _replay_state_destination(path: Path, workspace: Path, label: str) -> Path:
    requested = path.expanduser().absolute()
    boundary = workspace.expanduser().absolute().resolve()
    _require_outside_workspace(requested, boundary, label)
    try:
        parent = resolve_unlinked_path(requested.parent, f"{label} parent")
    except (OSError, ValueError) as exc:
        raise BenchmarkAssuranceError(f"{label} parent is unsafe") from exc
    destination = parent / requested.name
    if requested.is_symlink() or (destination.exists() and not destination.is_file()):
        raise BenchmarkAssuranceError(f"{label} is unsafe")
    return destination


def _lock_descriptor(descriptor: int) -> None:
    if os.name == "nt":
        import msvcrt

        msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
        return
    import fcntl

    fcntl_api: Any = fcntl
    fcntl_api.flock(descriptor, fcntl_api.LOCK_EX | fcntl_api.LOCK_NB)


def _unlock_descriptor(descriptor: int) -> None:
    os.lseek(descriptor, 0, os.SEEK_SET)
    if os.name == "nt":
        import msvcrt

        msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
        return
    import fcntl

    fcntl_api: Any = fcntl
    fcntl_api.flock(descriptor, fcntl_api.LOCK_UN)


def _atomic_write_replay_state(destination: Path, state: dict[str, Any]) -> None:
    atomic_write_bytes(
        destination,
        canonical_bytes(state) + b"\n",
        label="benchmark replay state",
    )


def sign_execution_receipt(
    receipt: dict[str, Any],
    *,
    signing_key_path: Path,
    signing_key_sha256: str,
    workspace: Path,
    trust_policy: dict[str, Any],
) -> dict[str, str]:
    """Sign a canonical execution receipt with an admitted deployment key."""
    if not _DIGEST.fullmatch(signing_key_sha256):
        raise BenchmarkAssuranceError("receipt signing key digest is invalid")
    requested = signing_key_path.expanduser().absolute()
    boundary = workspace.expanduser().absolute().resolve()
    _require_outside_workspace(
        requested,
        boundary,
        "receipt signing key",
    )
    try:
        resolved, payload = read_regular_file(
            requested,
            "receipt signing key",
            maximum_bytes=64 * 1024,
        )
    except (OSError, ValueError) as exc:
        raise BenchmarkAssuranceError(
            "receipt signing key is not a safe regular file"
        ) from exc
    _require_outside_workspace(resolved, boundary, "receipt signing key")
    if hashlib.sha256(payload).hexdigest() != signing_key_sha256:
        raise BenchmarkAssuranceError("receipt signing key digest does not match")
    try:
        key = serialization.load_pem_private_key(payload, password=None)
    except (TypeError, ValueError) as exc:
        raise BenchmarkAssuranceError("receipt signing key is invalid") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise BenchmarkAssuranceError("receipt signing key must use Ed25519")
    return sign_execution_receipt_with_provider(
        receipt,
        provider=LocalEd25519SigningProvider(key),
        trust_policy=trust_policy,
    )


def sign_execution_receipt_with_provider(
    receipt: dict[str, Any],
    *,
    provider: ReceiptSigningProvider,
    trust_policy: dict[str, Any],
) -> dict[str, str]:
    """Sign with a policy-admitted provider, including HSM/KMS adapters."""
    if (
        not isinstance(provider, ReceiptSigningProvider)
        or not _IDENTIFIER.fullmatch(provider.provider_id)
        or not _IDENTIFIER.fullmatch(provider.key_version)
    ):
        raise BenchmarkAssuranceError("receipt signing provider identity is invalid")
    try:
        public_bytes = provider.public_key_bytes()
        key = Ed25519PublicKey.from_public_bytes(public_bytes)
    except (TypeError, ValueError) as exc:
        raise BenchmarkAssuranceError(
            "receipt signing provider public key is invalid"
        ) from exc
    public_key_id = _public_key_id(key)
    authority = trust_policy["authority_index"].get(
        ("execution-receipt", public_key_id)
    )
    if not isinstance(authority, dict) or authority["status"] != "active":
        raise BenchmarkAssuranceError(
            "receipt signer is not admitted by deployment authority policy"
        )
    protected = {
        "algorithm": "Ed25519",
        "signer_key_id": public_key_id,
        "organization_id": str(authority["organization_id"]),
        "key_provider": provider.provider_id,
        "key_version": provider.key_version,
    }
    try:
        signature_payload = _receipt_signature_payload(receipt, protected)
        signature = provider.sign(signature_payload)
        key.verify(signature, signature_payload)
    except InvalidSignature as exc:
        raise BenchmarkAssuranceError(
            "receipt signing provider returned an invalid signature"
        ) from exc
    except Exception as exc:
        raise BenchmarkAssuranceError("receipt signing provider failed") from exc
    return {
        **protected,
        "public_key": base64.b64encode(public_bytes).decode("ascii"),
        "signature": base64.b64encode(signature).decode("ascii"),
    }


def verify_execution_receipt_signature(
    receipt: dict[str, Any],
    trust_policy: dict[str, Any] | None = None,
    *,
    trusted_signer_key_ids: frozenset[str] | None = None,
) -> str:
    """Verify a receipt's self-hash, signature, and independent admission anchor."""
    signature_value = receipt.get("receipt_signature")
    if not isinstance(signature_value, dict) or set(signature_value) != {
        "algorithm",
        "signer_key_id",
        "organization_id",
        "key_provider",
        "key_version",
        "public_key",
        "signature",
    }:
        raise BenchmarkAssuranceError("execution receipt signature is invalid")
    unsigned = dict(receipt)
    unsigned.pop("receipt_signature", None)
    retained_sha256 = unsigned.pop("receipt_sha256", None)
    if (
        not isinstance(retained_sha256, str)
        or hashlib.sha256(canonical_bytes(unsigned)).hexdigest() != retained_sha256
    ):
        raise BenchmarkAssuranceError("execution receipt self-hash is invalid")
    unsigned["receipt_sha256"] = retained_sha256
    try:
        public_bytes = base64.b64decode(signature_value["public_key"], validate=True)
        signature = base64.b64decode(signature_value["signature"], validate=True)
        key = Ed25519PublicKey.from_public_bytes(public_bytes)
        protected = {
            field: signature_value[field]
            for field in (
                "algorithm",
                "signer_key_id",
                "organization_id",
                "key_provider",
                "key_version",
            )
        }
        key.verify(signature, _receipt_signature_payload(unsigned, protected))
    except (InvalidSignature, TypeError, ValueError) as exc:
        raise BenchmarkAssuranceError("execution receipt signature is invalid") from exc
    key_id = _public_key_id(key)
    if (
        signature_value.get("algorithm") != "Ed25519"
        or signature_value.get("signer_key_id") != key_id
        or not isinstance(signature_value.get("key_provider"), str)
        or not _IDENTIFIER.fullmatch(signature_value["key_provider"])
        or not isinstance(signature_value.get("key_version"), str)
        or not _IDENTIFIER.fullmatch(signature_value["key_version"])
    ):
        raise BenchmarkAssuranceError("execution receipt signer identity is invalid")
    if trust_policy is not None:
        authority = trust_policy["authority_index"].get(("execution-receipt", key_id))
        if (
            not isinstance(authority, dict)
            or authority["status"] != "active"
            or authority["organization_id"] != signature_value.get("organization_id")
        ):
            raise BenchmarkAssuranceError(
                "execution receipt signer is not admitted by deployment policy"
            )
        if trust_policy.get("schema_version") == "1.1":
            _validate_receipt_authority_lifecycle(receipt, signature_value, authority)
    if trusted_signer_key_ids is not None:
        if (
            not trusted_signer_key_ids
            or any(not _DIGEST.fullmatch(item) for item in trusted_signer_key_ids)
            or key_id not in trusted_signer_key_ids
        ):
            raise BenchmarkAssuranceError(
                "execution receipt signer is not admitted by the relying party"
            )
    return key_id


def _receipt_signature_payload(
    receipt: dict[str, Any], protected: dict[str, str]
) -> bytes:
    return canonical_bytes(
        {
            "schema_version": "1.0",
            "protected": protected,
            "receipt": receipt,
        }
    )


def _verify_policy_signature(
    payload: bytes,
    *,
    signature_path: Path,
    trust_root_path: Path,
    trust_root_sha256: str,
    workspace: Path,
) -> str:
    if not _DIGEST.fullmatch(trust_root_sha256):
        raise BenchmarkAssuranceError("authority trust root digest is invalid")
    root_path = trust_root_path.expanduser().absolute()
    detached_path = signature_path.expanduser().absolute()
    boundary = workspace.expanduser().absolute().resolve()
    _require_outside_workspace(root_path, boundary, "authority trust root")
    _require_outside_workspace(detached_path, boundary, "authority policy signature")
    try:
        resolved_root, root_payload = read_regular_file(
            root_path, "authority trust root", maximum_bytes=64 * 1024
        )
        resolved_signature, signature_payload = read_regular_file(
            detached_path, "authority policy signature", maximum_bytes=4096
        )
    except (OSError, ValueError) as exc:
        raise BenchmarkAssuranceError(
            "authority policy trust material is not a safe regular file"
        ) from exc
    _require_outside_workspace(resolved_root, boundary, "authority trust root")
    _require_outside_workspace(
        resolved_signature, boundary, "authority policy signature"
    )
    if hashlib.sha256(root_payload).hexdigest() != trust_root_sha256:
        raise BenchmarkAssuranceError("authority trust root digest does not match")
    try:
        key = serialization.load_pem_public_key(root_payload)
        if not isinstance(key, Ed25519PublicKey):
            raise TypeError("not Ed25519")
        signature = base64.b64decode(signature_payload.strip(), validate=True)
        key.verify(signature, payload)
    except (InvalidSignature, TypeError, ValueError) as exc:
        raise BenchmarkAssuranceError(
            "authority trust policy signature is invalid"
        ) from exc
    return _public_key_id(key)


def _public_key_id(key: Ed25519PublicKey) -> str:
    return hashlib.sha256(
        key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    ).hexdigest()


def _migrate_replay_checkpoints(connection: sqlite3.Connection) -> None:
    columns = {
        str(row[1])
        for row in connection.execute("PRAGMA table_info(consumed_benchmarks)")
    }
    for column in ("previous_checkpoint_sha256", "checkpoint_sha256"):
        if column not in columns:
            connection.execute(
                f"ALTER TABLE consumed_benchmarks ADD COLUMN {column} "
                "TEXT NOT NULL DEFAULT ''"
            )
    previous = BENCHMARK_REPLAY_GENESIS_SHA256
    rows = connection.execute(
        "SELECT sequence, token, nonce_sha256, subject_sha256, signer_key_id, "
        "consumed_at, previous_checkpoint_sha256, checkpoint_sha256 "
        "FROM consumed_benchmarks ORDER BY sequence"
    ).fetchall()
    for row in rows:
        sequence = int(row[0])
        expected = _replay_checkpoint(
            sequence=sequence,
            previous_checkpoint_sha256=previous,
            token=str(row[1]),
            nonce_sha256=str(row[2]),
            subject_sha256=str(row[3]),
            signer_key_id=str(row[4]),
            consumed_at=str(row[5]),
        )
        retained_previous = str(row[6])
        retained = str(row[7])
        if retained_previous or retained:
            if retained_previous != previous or retained != expected:
                raise BenchmarkAssuranceError(
                    "benchmark replay ledger hash chain is invalid"
                )
        else:
            connection.execute(
                "UPDATE consumed_benchmarks SET previous_checkpoint_sha256 = ?, "
                "checkpoint_sha256 = ? WHERE sequence = ?",
                (previous, expected, sequence),
            )
        previous = expected


def _enable_replay_wal(connection: sqlite3.Connection) -> None:
    """Converge concurrent first-open connections on WAL journal mode."""
    deadline = time.monotonic() + 30
    while True:
        try:
            mode = connection.execute("PRAGMA journal_mode=WAL").fetchone()
            if mode is None or str(mode[0]).casefold() != "wal":
                raise BenchmarkAssuranceError(
                    "benchmark replay ledger could not enable durable WAL mode"
                )
            return
        except sqlite3.OperationalError as exc:
            if "locked" not in str(exc).casefold() or time.monotonic() >= deadline:
                raise
            time.sleep(0.025)


def _replay_token(nonce_sha256: str, subject_sha256: str, signer_key_id: str) -> str:
    return hashlib.sha256(
        canonical_bytes(
            {
                "nonce_sha256": nonce_sha256,
                "subject_sha256": subject_sha256,
                "signer_key_id": signer_key_id,
            }
        )
    ).hexdigest()


def _replay_checkpoint(
    *,
    sequence: int,
    previous_checkpoint_sha256: str,
    token: str,
    nonce_sha256: str,
    subject_sha256: str,
    signer_key_id: str,
    consumed_at: str,
) -> str:
    return hashlib.sha256(
        canonical_bytes(
            {
                "schema_version": "1.0",
                "sequence": sequence,
                "previous_checkpoint_sha256": previous_checkpoint_sha256,
                "token": token,
                "nonce_sha256": nonce_sha256,
                "subject_sha256": subject_sha256,
                "signer_key_id": signer_key_id,
                "consumed_at": consumed_at,
            }
        )
    ).hexdigest()


def _ledger_identity(ledger: Path) -> str:
    """Return a stable, non-secret identity for a deployment ledger location."""
    requested = ledger.expanduser().absolute()
    try:
        parent = resolve_unlinked_path(
            requested.parent, "benchmark replay ledger parent"
        )
    except (OSError, ValueError) as exc:
        raise BenchmarkAssuranceError(
            "benchmark replay ledger parent is unsafe"
        ) from exc
    normalized = os.path.normcase(str(parent / requested.name))
    return hashlib.sha256(
        canonical_bytes({"schema_version": "1.0", "ledger_path": normalized})
    ).hexdigest()


def _is_utc_timestamp(value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return parsed.tzinfo is not None and parsed.utcoffset() == UTC.utcoffset(parsed)


def _validate_policy_time(value: dict[str, Any]) -> None:
    try:
        issued = datetime.fromisoformat(str(value["issued_at"]).replace("Z", "+00:00"))
        expires = datetime.fromisoformat(
            str(value["expires_at"]).replace("Z", "+00:00")
        )
    except ValueError as exc:
        raise BenchmarkAssuranceError("authority trust policy time is invalid") from exc
    now = datetime.now(UTC)
    if (
        issued.tzinfo is None
        or expires.tzinfo is None
        or issued > now
        or expires <= now
        or expires <= issued
        or (expires - issued).total_seconds() > 31 * 24 * 60 * 60
    ):
        raise BenchmarkAssuranceError("authority trust policy is not currently valid")


def _validate_authority_entry(
    value: object, *, policy: dict[str, Any] | None = None
) -> None:
    required = {
        "role",
        "organization_id",
        "public_key_sha256",
        "revocation_status_sha256",
        "status",
    }
    lifecycle = isinstance(policy, dict) and policy.get("schema_version") == "1.1"
    if lifecycle:
        required |= {"key_version", "valid_from", "valid_until", "revoked_at"}
    if not isinstance(value, dict) or set(value) != required:
        raise BenchmarkAssuranceError("authority trust policy entry is invalid")
    if value["role"] not in _ROLES:
        raise BenchmarkAssuranceError("authority trust policy role is invalid")
    if not isinstance(value["organization_id"], str) or not _IDENTIFIER.fullmatch(
        value["organization_id"]
    ):
        raise BenchmarkAssuranceError("authority trust organization is invalid")
    for field in ("public_key_sha256", "revocation_status_sha256"):
        if not isinstance(value[field], str) or not _DIGEST.fullmatch(value[field]):
            raise BenchmarkAssuranceError(f"authority trust {field} is invalid")
    if value["status"] not in {"active", "revoked", "suspended"}:
        raise BenchmarkAssuranceError("authority trust status is invalid")
    if lifecycle:
        if policy is None:
            raise BenchmarkAssuranceError(
                "authority trust lifecycle policy is unavailable"
            )
        if (
            not isinstance(value["key_version"], str)
            or not _IDENTIFIER.fullmatch(value["key_version"])
            or not _is_utc_timestamp(value["valid_from"])
            or not _is_utc_timestamp(value["valid_until"])
        ):
            raise BenchmarkAssuranceError(
                "authority trust lifecycle identity is invalid"
            )
        valid_from = datetime.fromisoformat(value["valid_from"].replace("Z", "+00:00"))
        valid_until = datetime.fromisoformat(
            value["valid_until"].replace("Z", "+00:00")
        )
        issued = datetime.fromisoformat(str(policy["issued_at"]).replace("Z", "+00:00"))
        expires = datetime.fromisoformat(
            str(policy["expires_at"]).replace("Z", "+00:00")
        )
        revoked_at = value["revoked_at"]
        if (
            valid_from < issued
            or valid_until > expires
            or valid_until <= valid_from
            or (revoked_at is not None and not _is_utc_timestamp(revoked_at))
            or (value["status"] == "active" and revoked_at is not None)
            or (value["status"] == "revoked" and revoked_at is None)
        ):
            raise BenchmarkAssuranceError("authority trust lifecycle window is invalid")
        if revoked_at is not None:
            revoked = datetime.fromisoformat(revoked_at.replace("Z", "+00:00"))
            if revoked < valid_from or revoked > valid_until:
                raise BenchmarkAssuranceError(
                    "authority trust revocation time is invalid"
                )


def _validate_receipt_authority_lifecycle(
    receipt: dict[str, Any], signature: dict[str, Any], authority: dict[str, Any]
) -> None:
    completed_at = receipt.get("completed_at")
    if not _is_utc_timestamp(completed_at):
        raise BenchmarkAssuranceError(
            "execution receipt lacks a trusted lifecycle evaluation time"
        )
    completed = datetime.fromisoformat(str(completed_at).replace("Z", "+00:00"))
    valid_from = datetime.fromisoformat(authority["valid_from"].replace("Z", "+00:00"))
    valid_until = datetime.fromisoformat(
        authority["valid_until"].replace("Z", "+00:00")
    )
    revoked_at = authority.get("revoked_at")
    if (
        signature.get("key_version") != authority.get("key_version")
        or not valid_from <= completed < valid_until
        or (
            isinstance(revoked_at, str)
            and completed >= datetime.fromisoformat(revoked_at.replace("Z", "+00:00"))
        )
    ):
        raise BenchmarkAssuranceError(
            "execution receipt signer was not valid at completion time"
        )


def _require_outside_workspace(path: Path, workspace: Path, label: str) -> None:
    try:
        path.relative_to(workspace)
    except ValueError:
        return
    raise BenchmarkAssuranceError(
        f"{label} must remain outside the benchmark workspace"
    )
