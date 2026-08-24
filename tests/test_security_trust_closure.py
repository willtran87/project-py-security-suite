from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
import sqlite3
from contextlib import closing

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from py_security_suite.artifact_validation import (
    _OPERATION_STATE_GENESIS_SHA256,
    _contains_operation_receipt,
    _consume_operation_receipts,
    _validate_operation_receipt_graph,
)
from py_security_suite.requirements_coverage import _procedure_manifests_valid
from py_security_suite.requirements_coverage import _runtime_sbom_covers_closure
from py_security_suite.checkpoint_authority import publish_checkpoint
from py_security_suite.strict_json import canonical_bytes
from py_security_suite.runtime_trace import _verify_raw_spans
from py_security_suite.trusted_time import (
    _TRUSTED_TIME_STATE_GENESIS_SHA256,
    _advance_time_state,
)
from tests.deployment_authority import operation_receipt


def test_operation_receipt_graph_rejects_forked_roots() -> None:
    key = Ed25519PrivateKey.generate()
    receipts = [
        operation_receipt(
            {"run": index},
            purpose="test-operation",
            operation_id=f"run-{index}",
            private_key=key,
        )[0]
        for index in range(2)
    ]
    with pytest.raises(ValueError, match="exactly one root"):
        _validate_operation_receipt_graph({"receipts": receipts})


def test_operation_receipt_validator_discovery_is_structural() -> None:
    receipt, _ = operation_receipt(
        {"run": 1}, purpose="test-operation", operation_id="discover-1"
    )
    assert _contains_operation_receipt({"nested": [{"receipt": receipt}]}) is True
    assert _contains_operation_receipt({"nested": [{"receipt": {}}]}) is False
    receipt["revision_metadata"] = {"format": "v2"}
    assert _contains_operation_receipt({"nested": [{"receipt": receipt}]}) is True


def test_external_checkpoint_fails_closed_when_required(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("PYSEC_TEST_CHECKPOINT_COMMAND_JSON", raising=False)
    with pytest.raises(ValueError, match="unavailable"):
        publish_checkpoint(
            "PYSEC_TEST_CHECKPOINT",
            {"schema_version": "1.0", "checkpoint_sha256": "a" * 64},
            required=True,
        )


def test_requirements_sbom_must_cover_exact_runtime_closure() -> None:
    closure = [
        {
            "path": "runtime/library.bin",
            "sha256": "a" * 64,
            "content_base64": "",
        }
    ]
    empty_sbom = canonical_bytes(
        {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []}
    )
    assert _runtime_sbom_covers_closure(empty_sbom, closure) is False


def test_operation_receipt_state_rejects_cross_report_replay(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    receipt, _ = operation_receipt(
        {"run": 1}, purpose="test-operation", operation_id="global-run-1"
    )
    monkeypatch.setenv(
        "PYSEC_OPERATION_RECEIPT_STATE_PATH", str(tmp_path / "operations.sqlite")
    )
    monkeypatch.setenv("PYSEC_OPERATION_RECEIPT_MIN_SEQUENCE", "0")
    monkeypatch.setenv(
        "PYSEC_OPERATION_RECEIPT_CHECKPOINT_SHA256",
        _OPERATION_STATE_GENESIS_SHA256,
    )
    _consume_operation_receipts([receipt], {"report": 1})
    _consume_operation_receipts([receipt], {"report": 1})
    with pytest.raises(ValueError, match="replay across reports"):
        _consume_operation_receipts([receipt], {"report": 2})


def test_operation_receipt_anchor_detects_deleted_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "operations.sqlite"
    monkeypatch.setenv("PYSEC_OPERATION_RECEIPT_STATE_PATH", str(path))
    monkeypatch.setenv("PYSEC_OPERATION_RECEIPT_MIN_SEQUENCE", "0")
    monkeypatch.setenv(
        "PYSEC_OPERATION_RECEIPT_CHECKPOINT_SHA256",
        _OPERATION_STATE_GENESIS_SHA256,
    )
    first, _ = operation_receipt(
        {"run": 1}, purpose="test-operation", operation_id="anchor-1"
    )
    _consume_operation_receipts([first], {"report": 1})
    with closing(sqlite3.connect(path)) as connection:
        sequence, checkpoint = connection.execute(
            "SELECT sequence, checkpoint_sha256 FROM operation_receipt_checkpoint"
        ).fetchone()
    path.unlink()
    monkeypatch.setenv("PYSEC_OPERATION_RECEIPT_MIN_SEQUENCE", str(sequence))
    monkeypatch.setenv("PYSEC_OPERATION_RECEIPT_CHECKPOINT_SHA256", checkpoint)
    second, _ = operation_receipt(
        {"run": 2}, purpose="test-operation", operation_id="anchor-2"
    )
    with pytest.raises(ValueError, match="deletion or rollback"):
        _consume_operation_receipts([second], {"report": 2})


def test_requirements_executor_rejects_raw_environment_values() -> None:
    execution = {
        "environment": {"TOKEN": "secret"},
        "runtime_manifest": {},
        "assets_manifest": [],
        "sandbox_policy": {},
    }
    assert _procedure_manifests_valid(execution) is False


def test_raw_runtime_spans_reject_missing_parent() -> None:
    trace = {"trace_id": "trace-1234567890", "operation": "read", "span_count": 1}
    span = {
        "trace_id": trace["trace_id"],
        "span_id": "span-1",
        "parent_span_id": "missing",
        "process_identity_sha256": "a" * 64,
        "operation": "read",
    }
    with pytest.raises(ValueError, match="parent is missing"):
        _verify_raw_spans([span], [trace])


def test_trusted_time_state_rejects_rollback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(
        "PYSEC_TRUSTED_TIME_STATE_PATH", str(tmp_path / "trusted-time.sqlite")
    )
    monkeypatch.setenv("PYSEC_TRUSTED_TIME_MIN_SEQUENCE", "0")
    monkeypatch.setenv(
        "PYSEC_TRUSTED_TIME_CHECKPOINT_SHA256", _TRUSTED_TIME_STATE_GENESIS_SHA256
    )
    now = datetime.now(UTC)
    current = {
        "trusted_time_observed_at": now.isoformat(),
        "trusted_time_sha256": "a" * 64,
    }
    older = {
        "trusted_time_observed_at": (now - timedelta(seconds=1)).isoformat(),
        "trusted_time_sha256": "b" * 64,
    }
    _advance_time_state("c" * 64, current)
    with pytest.raises(ValueError, match="rollback or fork"):
        _advance_time_state("d" * 64, older)


def test_trusted_time_anchor_detects_deleted_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "trusted-time.sqlite"
    monkeypatch.setenv("PYSEC_TRUSTED_TIME_STATE_PATH", str(path))
    monkeypatch.setenv("PYSEC_TRUSTED_TIME_MIN_SEQUENCE", "0")
    monkeypatch.setenv(
        "PYSEC_TRUSTED_TIME_CHECKPOINT_SHA256", _TRUSTED_TIME_STATE_GENESIS_SHA256
    )
    now = datetime.now(UTC)
    _advance_time_state(
        "c" * 64,
        {"trusted_time_observed_at": now.isoformat(), "trusted_time_sha256": "a" * 64},
    )
    with closing(sqlite3.connect(path)) as connection:
        sequence, checkpoint = connection.execute(
            "SELECT sequence, checkpoint_sha256 FROM trusted_time_state"
        ).fetchone()
    path.unlink()
    monkeypatch.setenv("PYSEC_TRUSTED_TIME_MIN_SEQUENCE", str(sequence))
    monkeypatch.setenv("PYSEC_TRUSTED_TIME_CHECKPOINT_SHA256", checkpoint)
    with pytest.raises(ValueError, match="deletion or rollback"):
        _advance_time_state(
            "d" * 64,
            {
                "trusted_time_observed_at": (now + timedelta(seconds=1)).isoformat(),
                "trusted_time_sha256": "b" * 64,
            },
        )
