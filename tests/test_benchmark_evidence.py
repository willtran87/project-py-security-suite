from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

import pytest

from py_security_suite.benchmark_evidence import (
    BenchmarkEvidenceError,
    _verify_sbom,
    verify_benchmark_trusted_time,
)


def test_cyclonedx_document_must_match_claimed_specification_version() -> None:
    image_sha256 = "a" * 64
    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "metadata": {
            "component": {"hashes": [{"alg": "SHA-256", "content": image_sha256}]}
        },
    }

    with pytest.raises(BenchmarkEvidenceError, match="subject is invalid"):
        _verify_sbom(document, "CycloneDX-1.6", image_sha256)


def test_spdx_document_must_match_claimed_specification_version() -> None:
    image_sha256 = "b" * 64
    document = {
        "spdxVersion": "SPDX-2.2",
        "packages": [
            {"checksums": [{"algorithm": "SHA256", "checksumValue": image_sha256}]}
        ],
    }

    with pytest.raises(BenchmarkEvidenceError, match="subject is invalid"):
        _verify_sbom(document, "SPDX-2.3", image_sha256)


def test_trusted_time_replays_raw_rfc3161_context(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    context = tmp_path / "trusted-time.json"
    context_payload = json.dumps(
        {"schema_version": "1.0", "trusted_time": {"receipt": "timestamp.tsr"}},
        sort_keys=True,
    ).encode()
    context.write_bytes(context_payload)
    observed_at = datetime.now(UTC).isoformat()
    replay = {
        "trusted_time_receipt_sha256": "a" * 64,
        "trusted_time_sha256": "b" * 64,
        "trusted_time_observed_at": observed_at,
    }
    claims = {
        "trusted_time_receipt_sha256": "a" * 64,
        "trusted_time_sha256": "b" * 64,
        "observed_at": observed_at,
    }

    with (
        patch.dict(
            "os.environ",
            {"PYSEC_TRUSTED_TIME_STATE_PATH": str(tmp_path / "monotonic.json")},
        ),
        patch(
            "py_security_suite.benchmark_evidence.verify_rfc3161",
            return_value=replay,
        ) as verifier,
    ):
        result = verify_benchmark_trusted_time(
            context,
            hashlib.sha256(context_payload).hexdigest(),
            workspace=workspace,
            subject_sha256="c" * 64,
            claims=claims,
        )

    assert result == replay
    verifier.assert_called_once_with(
        context.resolve(),
        {"receipt": "timestamp.tsr"},
        "c" * 64,
        require_advanced=True,
    )


def test_trusted_time_rejects_claims_not_reproduced_by_proof(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    context = tmp_path / "trusted-time.json"
    payload = b'{"schema_version":"1.0","trusted_time":{}}'
    context.write_bytes(payload)
    observed_at = datetime.now(UTC).isoformat()
    with (
        patch.dict("os.environ", {"PYSEC_TRUSTED_TIME_STATE_PATH": "state"}),
        patch(
            "py_security_suite.benchmark_evidence.verify_rfc3161",
            return_value={
                "trusted_time_receipt_sha256": "d" * 64,
                "trusted_time_sha256": "b" * 64,
                "trusted_time_observed_at": observed_at,
            },
        ),
        pytest.raises(BenchmarkEvidenceError, match="does not reproduce"),
    ):
        verify_benchmark_trusted_time(
            context,
            hashlib.sha256(payload).hexdigest(),
            workspace=workspace,
            subject_sha256="c" * 64,
            claims={
                "trusted_time_receipt_sha256": "a" * 64,
                "trusted_time_sha256": "b" * 64,
                "observed_at": observed_at,
            },
        )
