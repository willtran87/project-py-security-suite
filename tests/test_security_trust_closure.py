from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from py_security_suite.artifact_validation import (
    _consume_operation_receipts,
    _validate_operation_receipt_graph,
)
from py_security_suite.requirements_coverage import _procedure_manifests_valid
from py_security_suite.runtime_trace import _verify_raw_spans
from py_security_suite.trusted_time import _advance_time_state
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


def test_operation_receipt_state_rejects_cross_report_replay(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    receipt, _ = operation_receipt(
        {"run": 1}, purpose="test-operation", operation_id="global-run-1"
    )
    monkeypatch.setenv(
        "PYSEC_OPERATION_RECEIPT_STATE_PATH", str(tmp_path / "operations.sqlite")
    )
    _consume_operation_receipts([receipt], {"report": 1})
    _consume_operation_receipts([receipt], {"report": 1})
    with pytest.raises(ValueError, match="replay across reports"):
        _consume_operation_receipts([receipt], {"report": 2})


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
