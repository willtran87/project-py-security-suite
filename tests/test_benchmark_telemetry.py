from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from py_security_suite.benchmark_signing import LocalEd25519SigningProvider
from py_security_suite.benchmark_telemetry import (
    BenchmarkSecurityEventRecorder,
    DurableJsonlSecurityEventSink,
    SECURITY_EVENT_ANCHOR_GENESIS_SHA256,
    sign_security_event_log_head,
    verify_durable_security_event_log,
    verify_security_event_log_anchor,
)


def _event(sequence: int, control: str, outcome: str = "passed") -> dict[str, object]:
    return {
        "sequence": sequence,
        "occurred_at": datetime.now(UTC).isoformat(),
        "control": control,
        "outcome": outcome,
        "details_sha256": hashlib.sha256(b"{}").hexdigest(),
    }


def test_durable_security_events_are_fsynced_and_hash_chained(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    log = tmp_path / "audit" / "benchmark-events.jsonl"
    log.parent.mkdir()
    recorder = BenchmarkSecurityEventRecorder(
        DurableJsonlSecurityEventSink(log, workspace=workspace)
    )

    recorder.record("manifest-admission", "passed")
    recorder.record("replay-continuity", "failed", details={"sequence": 7})

    records = [json.loads(line) for line in log.read_text().splitlines()]
    assert len(records) == 2
    assert [record["log_sequence"] for record in records] == [1, 2]
    assert records[1]["previous_event_sha256"] == records[0]["event_sha256"]
    assert records[1]["event"]["details_sha256"] != "0" * 64
    verification = verify_durable_security_event_log(log)
    assert verification["records"] == 2
    assert verification["head_event_sha256"] == records[1]["event_sha256"]

    records[1]["previous_event_sha256"] = "0" * 64
    log.write_text("\n".join(json.dumps(record) for record in records) + "\n")
    with pytest.raises(ValueError, match="contract"):
        verify_durable_security_event_log(log)


def test_durable_security_event_log_must_be_outside_workspace(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    with pytest.raises(ValueError, match="outside"):
        DurableJsonlSecurityEventSink(workspace / "events.jsonl", workspace=workspace)


def test_security_event_log_head_is_signed_and_relying_party_anchored(
    tmp_path: Path,
) -> None:
    log = tmp_path / "events.jsonl"
    sink = DurableJsonlSecurityEventSink(log)
    sink(_event(1, "admission"))
    key = Ed25519PrivateKey.generate()
    provider = LocalEd25519SigningProvider(key)
    key_id = hashlib.sha256(
        key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    ).hexdigest()
    observed_at = datetime.now(UTC).isoformat()
    trusted_time_receipt_sha256 = "a" * 64
    trust_policy = {
        "authority_index": {
            ("security-event-anchor", key_id): {
                "organization_id": "audit.example",
                "key_version": provider.key_version,
                "status": "active",
                "valid_from": "2026-01-01T00:00:00+00:00",
                "valid_until": "2027-01-01T00:00:00+00:00",
                "revoked_at": None,
            }
        }
    }

    anchor = sign_security_event_log_head(
        log,
        provider=provider,
        organization_id="audit.example",
        trusted_time_observed_at=observed_at,
        trusted_time_receipt_sha256=trusted_time_receipt_sha256,
    )

    assert (
        verify_security_event_log_anchor(
            log,
            anchor,
            trust_policy=trust_policy,
            expected_trusted_time_receipt_sha256=trusted_time_receipt_sha256,
        )
        == anchor["anchor_sha256"]
    )
    assert anchor["previous_anchor_sha256"] == SECURITY_EVENT_ANCHOR_GENESIS_SHA256
    sink(_event(2, "execution"))
    assert (
        verify_security_event_log_anchor(
            log,
            anchor,
            trust_policy=trust_policy,
            expected_trusted_time_receipt_sha256=trusted_time_receipt_sha256,
        )
        == anchor["anchor_sha256"]
    )

    rotated = sign_security_event_log_head(
        log,
        provider=provider,
        organization_id="audit.example",
        trusted_time_observed_at=datetime.now(UTC).isoformat(),
        trusted_time_receipt_sha256="b" * 64,
        previous_anchor_sha256=anchor["anchor_sha256"],
        anchor_sequence=2,
    )
    assert (
        verify_security_event_log_anchor(
            log,
            rotated,
            trust_policy=trust_policy,
            expected_trusted_time_receipt_sha256="b" * 64,
            expected_previous_anchor_sha256=anchor["anchor_sha256"],
            expected_anchor_sequence=2,
        )
        == rotated["anchor_sha256"]
    )

    records = [json.loads(line) for line in log.read_text().splitlines()]
    records[0]["event"]["control"] = "tampered"
    log.write_text("\n".join(json.dumps(record) for record in records) + "\n")
    with pytest.raises(ValueError):
        verify_security_event_log_anchor(
            log,
            anchor,
            trust_policy=trust_policy,
            expected_trusted_time_receipt_sha256=trusted_time_receipt_sha256,
        )


def test_security_event_log_serializes_concurrent_writers(tmp_path: Path) -> None:
    log = tmp_path / "events.jsonl"
    sink = DurableJsonlSecurityEventSink(log)

    with ThreadPoolExecutor(max_workers=8) as executor:
        futures = [
            executor.submit(
                sink,
                _event(1, f"writer-{index}"),
            )
            for index in range(32)
        ]
        for future in futures:
            future.result()

    verification = verify_durable_security_event_log(log)
    assert verification["records"] == 32
    assert [
        json.loads(line)["log_sequence"] for line in log.read_text().splitlines()
    ] == list(range(1, 33))
