from __future__ import annotations

import hashlib
import base64
import os
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .benchmark_signing import ReceiptSigningProvider
from .path_safety import read_regular_file, resolve_unlinked_path
from .strict_json import canonical_bytes
from .strict_json import loads as strict_loads


SecurityEventSink = Callable[[dict[str, Any]], None]
_GENESIS_EVENT_SHA256 = hashlib.sha256(b"pysec-security-events-v1").hexdigest()
SECURITY_EVENT_ANCHOR_GENESIS_SHA256 = hashlib.sha256(
    b"pysec-security-event-anchor-genesis-v1"
).hexdigest()
_MAX_EVENT_LOG_BYTES = 256 * 1024 * 1024
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")


class DurableJsonlSecurityEventSink:
    """Append fsync'd, hash-chained security events to deployment-owned JSONL."""

    def __init__(self, path: Path, *, workspace: Path | None = None) -> None:
        requested = path.expanduser().absolute()
        parent = resolve_unlinked_path(requested.parent, "security event log parent")
        self._path = parent / requested.name
        if requested.is_symlink() or (self._path.exists() and not self._path.is_file()):
            raise ValueError("security event log is unsafe")
        if workspace is not None:
            boundary = workspace.expanduser().absolute().resolve()
            try:
                self._path.resolve().relative_to(boundary)
            except ValueError:
                pass
            else:
                raise ValueError(
                    "security event log must be outside the target workspace"
                )

    def __call__(self, event: dict[str, Any]) -> None:
        _validate_security_event(event)
        descriptor = os.open(self._path, os.O_RDWR | os.O_APPEND | os.O_CREAT, 0o600)
        try:
            _lock_event_log(descriptor)
            stat = os.fstat(descriptor)
            if stat.st_size > _MAX_EVENT_LOG_BYTES:
                raise ValueError("security event log exceeds its retention limit")
            previous, log_sequence = _last_event_state(descriptor, stat.st_size)
            record: dict[str, Any] = {
                "schema_version": "1.1",
                "log_sequence": log_sequence,
                "previous_event_sha256": previous,
                "event": event,
            }
            record["event_sha256"] = hashlib.sha256(canonical_bytes(record)).hexdigest()
            encoded = canonical_bytes(record) + b"\n"
            if stat.st_size + len(encoded) > _MAX_EVENT_LOG_BYTES:
                raise ValueError("security event log exceeds its retention limit")
            os.write(descriptor, encoded)
            os.fsync(descriptor)
        finally:
            try:
                _unlock_event_log(descriptor)
            finally:
                os.close(descriptor)


class BenchmarkSecurityEventRecorder:
    """Create bounded, secret-minimized benchmark security audit events."""

    def __init__(self, sink: SecurityEventSink | None = None) -> None:
        self._sink = sink
        self._events: list[dict[str, Any]] = []

    def record(
        self, control: str, outcome: str, *, details: dict[str, Any] | None = None
    ) -> None:
        if outcome not in {"passed", "failed", "observed"}:
            raise ValueError("benchmark security event outcome is invalid")
        event = {
            "sequence": len(self._events) + 1,
            "occurred_at": datetime.now(UTC).isoformat(),
            "control": control,
            "outcome": outcome,
            "details_sha256": hashlib.sha256(
                canonical_bytes(details or {})
            ).hexdigest(),
        }
        self._events.append(event)
        if self._sink is not None:
            self._sink(dict(event))

    def export(self) -> list[dict[str, Any]]:
        return [dict(event) for event in self._events]


def verify_durable_security_event_log(path: Path) -> dict[str, Any]:
    """Verify every JSONL record and link, returning a portable head receipt."""
    try:
        _, payload = read_regular_file(
            path, "security event log", maximum_bytes=_MAX_EVENT_LOG_BYTES
        )
    except (OSError, ValueError) as exc:
        raise ValueError("security event log is not a safe regular file") from exc
    return _verify_security_event_log_payload(payload)


def _verify_security_event_log_payload(
    payload: bytes, *, record_limit: int | None = None
) -> dict[str, Any]:
    lines = payload.splitlines(keepends=True)
    if not lines:
        raise ValueError("security event log is empty")
    if record_limit is not None:
        if not 1 <= record_limit <= len(lines):
            raise ValueError("security event anchor record count is invalid")
        lines = lines[:record_limit]
        payload = b"".join(lines)
    previous = _GENESIS_EVENT_SHA256
    expected_log_sequence = 1
    for sequence, line in enumerate(lines, start=1):
        try:
            record = strict_loads(line)
        except (TypeError, ValueError) as exc:
            raise ValueError(
                f"security event log record {sequence} is invalid JSON"
            ) from exc
        retained = _validated_event_record_hash(
            record,
            expected_previous=previous,
            expected_log_sequence=expected_log_sequence,
        )
        previous = retained
        expected_log_sequence += 1
    return {
        "schema_version": "1.0",
        "analysis": "benchmark-security-event-log-verification",
        "records": len(lines),
        "head_event_sha256": previous,
        "log_sha256": hashlib.sha256(payload).hexdigest(),
    }


def sign_security_event_log_head(
    path: Path,
    *,
    provider: ReceiptSigningProvider,
    organization_id: str,
    trusted_time_observed_at: str,
    trusted_time_receipt_sha256: str,
    previous_anchor_sha256: str = SECURITY_EVENT_ANCHOR_GENESIS_SHA256,
    anchor_sequence: int = 1,
) -> dict[str, Any]:
    """Sign a portable log-head checkpoint for independent retention."""
    if (
        not _IDENTIFIER.fullmatch(organization_id)
        or not _DIGEST.fullmatch(previous_anchor_sha256)
        or not _DIGEST.fullmatch(trusted_time_receipt_sha256)
        or not isinstance(anchor_sequence, int)
        or isinstance(anchor_sequence, bool)
        or anchor_sequence < 1
        or (anchor_sequence == 1)
        != (previous_anchor_sha256 == SECURITY_EVENT_ANCHOR_GENESIS_SHA256)
    ):
        raise ValueError("security event anchor identity is invalid")
    trusted_time = _utc_timestamp(trusted_time_observed_at, "trusted time")
    if abs((datetime.now(UTC) - trusted_time).total_seconds()) > 15 * 60:
        raise ValueError("security event anchor trusted time is stale or in the future")
    verification = verify_durable_security_event_log(path)
    public_key = provider.public_key_bytes()
    key = Ed25519PublicKey.from_public_bytes(public_key)
    key_id = hashlib.sha256(public_key).hexdigest()
    protected: dict[str, Any] = {
        **verification,
        "schema_version": "1.1",
        "anchored_at": datetime.now(UTC).isoformat(),
        "trusted_time_observed_at": trusted_time_observed_at,
        "trusted_time_receipt_sha256": trusted_time_receipt_sha256,
        "anchor_sequence": anchor_sequence,
        "previous_anchor_sha256": previous_anchor_sha256,
        "organization_id": organization_id,
        "key_provider": provider.provider_id,
        "key_version": provider.key_version,
        "signer_key_id": key_id,
        "public_key": base64.b64encode(public_key).decode("ascii"),
    }
    protected["anchor_sha256"] = hashlib.sha256(canonical_bytes(protected)).hexdigest()
    signature = provider.sign(canonical_bytes(protected))
    try:
        key.verify(signature, canonical_bytes(protected))
    except InvalidSignature as exc:
        raise ValueError(
            "security event anchor provider returned an invalid signature"
        ) from exc
    return {**protected, "signature": base64.b64encode(signature).decode("ascii")}


def verify_security_event_log_anchor(
    path: Path,
    anchor: dict[str, Any],
    *,
    trust_policy: dict[str, Any],
    expected_trusted_time_receipt_sha256: str,
    expected_previous_anchor_sha256: str = SECURITY_EVENT_ANCHOR_GENESIS_SHA256,
    expected_anchor_sequence: int = 1,
) -> str:
    """Verify an anchored log head against current bytes and relying-party trust."""
    if not _DIGEST.fullmatch(expected_trusted_time_receipt_sha256):
        raise ValueError("security event anchor trusted-time expectation is invalid")
    required = {
        "schema_version",
        "analysis",
        "records",
        "head_event_sha256",
        "log_sha256",
        "anchored_at",
        "trusted_time_observed_at",
        "trusted_time_receipt_sha256",
        "anchor_sequence",
        "previous_anchor_sha256",
        "organization_id",
        "key_provider",
        "key_version",
        "signer_key_id",
        "public_key",
        "anchor_sha256",
        "signature",
    }
    if not isinstance(anchor, dict) or set(anchor) != required:
        raise ValueError("security event anchor contract is invalid")
    unsigned = dict(anchor)
    signature_value = unsigned.pop("signature")
    retained = unsigned.pop("anchor_sha256")
    if (
        anchor.get("schema_version") != "1.1"
        or anchor.get("analysis") != "benchmark-security-event-log-verification"
        or anchor.get("previous_anchor_sha256") != expected_previous_anchor_sha256
        or anchor.get("anchor_sequence") != expected_anchor_sequence
        or anchor.get("trusted_time_receipt_sha256")
        != expected_trusted_time_receipt_sha256
        or not isinstance(retained, str)
        or hashlib.sha256(canonical_bytes(unsigned)).hexdigest() != retained
    ):
        raise ValueError("security event anchor self-binding is invalid")
    unsigned["anchor_sha256"] = retained
    try:
        public_key = base64.b64decode(anchor["public_key"], validate=True)
        signature = base64.b64decode(signature_value, validate=True)
        key = Ed25519PublicKey.from_public_bytes(public_key)
        key.verify(signature, canonical_bytes(unsigned))
    except (InvalidSignature, TypeError, ValueError) as exc:
        raise ValueError("security event anchor signature is invalid") from exc
    key_id = hashlib.sha256(public_key).hexdigest()
    authority = trust_policy.get("authority_index", {}).get(
        ("security-event-anchor", key_id)
    )
    if (
        anchor["signer_key_id"] != key_id
        or not isinstance(authority, dict)
        or authority.get("status") != "active"
        or authority.get("organization_id") != anchor.get("organization_id")
        or authority.get("key_version") != anchor.get("key_version")
    ):
        raise ValueError("security event anchor signer is not trusted")
    trusted_time = _utc_timestamp(
        anchor.get("trusted_time_observed_at"), "security event anchor trusted time"
    )
    anchored_at = _utc_timestamp(
        anchor.get("anchored_at"), "security event anchor time"
    )
    valid_from = _utc_timestamp(authority.get("valid_from"), "anchor key activation")
    valid_until = _utc_timestamp(authority.get("valid_until"), "anchor key retirement")
    revoked_at = authority.get("revoked_at")
    if (
        not valid_from <= trusted_time < valid_until
        or abs((anchored_at - trusted_time).total_seconds()) > 60
        or (
            isinstance(revoked_at, str)
            and trusted_time >= _utc_timestamp(revoked_at, "anchor key revocation")
        )
    ):
        raise ValueError("security event anchor signer lifecycle is invalid")
    try:
        _, payload = read_regular_file(
            path, "security event log", maximum_bytes=_MAX_EVENT_LOG_BYTES
        )
    except (OSError, ValueError) as exc:
        raise ValueError("security event log is not a safe regular file") from exc
    _verify_security_event_log_payload(payload)
    records = anchor.get("records")
    if not isinstance(records, int) or isinstance(records, bool):
        raise ValueError("security event anchor record count is invalid")
    anchored_prefix = _verify_security_event_log_payload(payload, record_limit=records)
    if any(
        anchored_prefix[field] != anchor[field]
        for field in ("analysis", "records", "head_event_sha256", "log_sha256")
    ):
        raise ValueError("security event anchor does not match the retained log")
    return retained


def _utc_timestamp(value: object, label: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError(f"{label} is invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{label} is invalid") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != UTC.utcoffset(parsed):
        raise ValueError(f"{label} is invalid")
    return parsed


def _last_event_state(descriptor: int, size: int) -> tuple[str, int]:
    if size == 0:
        return _GENESIS_EVENT_SHA256, 1
    read_size = min(size, 64 * 1024)
    os.lseek(descriptor, size - read_size, os.SEEK_SET)
    lines = os.read(descriptor, read_size).splitlines()
    if not lines:
        raise ValueError("security event log has no complete records")
    try:
        record = strict_loads(lines[-1])
    except (TypeError, ValueError) as exc:
        raise ValueError("security event log tail is invalid") from exc
    retained = _validated_event_record_hash(record)
    log_sequence = record.get("log_sequence")
    if not isinstance(log_sequence, int) or isinstance(log_sequence, bool):
        raise ValueError(
            "legacy security event log must be anchored and rotated before append"
        )
    return retained, log_sequence + 1


def _validated_event_record_hash(
    value: object,
    *,
    expected_previous: str | None = None,
    expected_log_sequence: int | None = None,
) -> str:
    schema_version = value.get("schema_version") if isinstance(value, dict) else None
    required = {"schema_version", "previous_event_sha256", "event", "event_sha256"}
    if schema_version == "1.1":
        required.add("log_sequence")
    if (
        not isinstance(value, dict)
        or set(value) != required
        or schema_version not in {"1.0", "1.1"}
        or (
            expected_previous is not None
            and value.get("previous_event_sha256") != expected_previous
        )
        or (
            schema_version == "1.1"
            and (
                not isinstance(value.get("log_sequence"), int)
                or isinstance(value.get("log_sequence"), bool)
                or value["log_sequence"] < 1
                or (
                    expected_log_sequence is not None
                    and value["log_sequence"] != expected_log_sequence
                )
            )
        )
        or not isinstance(value.get("event"), dict)
    ):
        raise ValueError("security event log record contract is invalid")
    _validate_security_event(value["event"])
    unsigned = dict(value)
    retained = unsigned.pop("event_sha256")
    if (
        not isinstance(retained, str)
        or hashlib.sha256(canonical_bytes(unsigned)).hexdigest() != retained
    ):
        raise ValueError("security event log chain is invalid")
    return retained


def _validate_security_event(event: object) -> None:
    required = {"sequence", "occurred_at", "control", "outcome", "details_sha256"}
    if not isinstance(event, dict) or set(event) != required:
        raise ValueError("security event contract is invalid")
    sequence = event.get("sequence")
    occurred_at = event.get("occurred_at")
    if (
        not isinstance(sequence, int)
        or isinstance(sequence, bool)
        or sequence < 1
        or not isinstance(occurred_at, str)
        or not _IDENTIFIER.fullmatch(str(event.get("control", "")))
        or event.get("outcome") not in {"passed", "failed", "observed"}
        or not _DIGEST.fullmatch(str(event.get("details_sha256", "")))
    ):
        raise ValueError("security event contract is invalid")
    try:
        timestamp = datetime.fromisoformat(occurred_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("security event timestamp is invalid") from exc
    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        raise ValueError("security event timestamp is invalid")


def _lock_event_log(descriptor: int) -> None:
    os.lseek(descriptor, 0, os.SEEK_SET)
    if os.name == "nt":
        import msvcrt

        msvcrt_api: Any = msvcrt
        msvcrt_api.locking(descriptor, msvcrt_api.LK_LOCK, 1)
        return
    import fcntl

    fcntl_api: Any = fcntl
    fcntl_api.flock(descriptor, fcntl_api.LOCK_EX)


def _unlock_event_log(descriptor: int) -> None:
    os.lseek(descriptor, 0, os.SEEK_SET)
    if os.name == "nt":
        import msvcrt

        msvcrt_api: Any = msvcrt
        msvcrt_api.locking(descriptor, msvcrt_api.LK_UNLCK, 1)
        return
    import fcntl

    fcntl_api: Any = fcntl
    fcntl_api.flock(descriptor, fcntl_api.LOCK_UN)
