from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from companion.assurance_context import load_context, target_set_sha256
from unittest.mock import patch
from py_security_suite.evidence_ingest import _expected_assurance_context


def _write_context(path: Path, targets: list[str], *, observed_at: datetime) -> None:
    path.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "run_id": "run-42",
                "target_manifest_sha256": "1" * 64,
                "exercised_targets_sha256": target_set_sha256(targets),
                "deployment_sha256": "2" * 64,
                "surface_sha256": "3" * 64,
                "challenge_sha256": "4" * 64,
                "trusted_time": {
                    "authority": "organization-tsa",
                    "observed_at": observed_at.isoformat(),
                    "receipt_sha256": "5" * 64,
                },
            }
        ),
        encoding="utf-8",
    )


def test_context_binds_exact_targets_and_trusted_time(tmp_path: Path) -> None:
    path = tmp_path / "context.json"
    _write_context(
        path, ["api-primary", "worker-orders"], observed_at=datetime.now(UTC)
    )

    with (
        patch(
            "companion.assurance_context.verify_rfc3161",
            side_effect=_verified_time,
        ),
        patch(
            "py_security_suite.evidence_ingest.verify_rfc3161",
            side_effect=_verified_time,
        ),
    ):
        result = load_context(path, ["worker-orders", "api-primary"])
        expected_run, expected = _expected_assurance_context(path)

    assert result["run_id"] == "run-42"
    assert len(result["trusted_time_sha256"]) == 64
    assert expected_run == "run-42"
    assert expected == {key: value for key, value in result.items() if key != "run_id"}


def test_context_rejects_wrong_targets_and_stale_time(tmp_path: Path) -> None:
    path = tmp_path / "context.json"
    _write_context(path, ["api-primary"], observed_at=datetime.now(UTC))
    with patch(
        "companion.assurance_context.verify_rfc3161", side_effect=_verified_time
    ):
        with pytest.raises(ValueError, match="target set"):
            load_context(path, ["different-api"])

    _write_context(
        path,
        ["api-primary"],
        observed_at=datetime.now(UTC) - timedelta(hours=25),
    )
    with patch(
        "companion.assurance_context.verify_rfc3161", side_effect=_verified_time
    ):
        with pytest.raises(ValueError, match="accepted window"):
            load_context(path, ["api-primary"])


def _verified_time(_path: Path, value: object, _challenge: str) -> dict[str, str]:
    assert isinstance(value, dict)
    return {
        "trusted_time_sha256": "5" * 64,
        "trusted_time_observed_at": str(value["observed_at"]),
        "trusted_time_receipt_sha256": "6" * 64,
        "trusted_time_signer_sha256": "7" * 64,
    }


def test_target_identity_rejects_duplicates() -> None:
    with pytest.raises(ValueError, match="unique"):
        target_set_sha256(["same", "same"])
