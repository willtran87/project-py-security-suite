from __future__ import annotations

import copy
import os
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

import pytest

from py_security_suite.deployment_receipt import (
    verify_deployment_receipt,
    verify_portable_receipt,
)
from tests.deployment_authority import authority_environment


def test_portable_receipt_revalidates_without_original_authority_files(
    tmp_path: Path,
) -> None:
    subject = {"policy": "strict"}
    environment = authority_environment(
        tmp_path,
        subject,
        purpose="portable-test",
        prefix="PYSEC_PORTABLE_TEST_AUTHORITY",
    )
    with patch.dict(os.environ, environment):
        receipt = verify_deployment_receipt(
            subject,
            purpose="portable-test",
            environment_prefix="PYSEC_PORTABLE_TEST_AUTHORITY",
            observed_at=datetime.now(UTC),
        )

    statement = receipt["statement"]
    verify_portable_receipt(
        subject,
        receipt,
        purpose="portable-test",
        observed_at=datetime.now(UTC),
        challenge_sha256=statement["challenge_sha256"],
    )

    tampered = copy.deepcopy(receipt)
    tampered["receipt_payload_base64"] = receipt["receipt_payload_base64"][:-4] + "AAAA"
    with pytest.raises(ValueError, match="trust binding|key is invalid"):
        verify_portable_receipt(
            subject,
            tampered,
            purpose="portable-test",
            observed_at=datetime.now(UTC),
            challenge_sha256=statement["challenge_sha256"],
        )


def test_same_generation_and_receipt_is_idempotent(tmp_path: Path) -> None:
    subject = {"policy": "strict"}
    environment = authority_environment(
        tmp_path,
        subject,
        purpose="monotonic-test",
        prefix="PYSEC_MONOTONIC_TEST_AUTHORITY",
    )
    with patch.dict(os.environ, environment):
        for _ in range(2):
            verify_deployment_receipt(
                subject,
                purpose="monotonic-test",
                environment_prefix="PYSEC_MONOTONIC_TEST_AUTHORITY",
                observed_at=datetime.now(UTC),
            )
