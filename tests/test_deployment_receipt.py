from __future__ import annotations

import copy
import hashlib
import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from py_security_suite.deployment_receipt import (
    verify_deployment_receipt,
    verify_portable_receipt,
)
from py_security_suite.strict_json import canonical_bytes
from tests.deployment_authority import authority_environment, operation_receipt


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


def test_external_monotonic_state_is_pinned_and_retained(tmp_path: Path) -> None:
    subject = {"policy": "strict"}
    prefix = "PYSEC_EXTERNAL_STATE_AUTHORITY"
    environment = authority_environment(
        tmp_path,
        subject,
        purpose="external-state-test",
        prefix=prefix,
    )
    private = Ed25519PrivateKey.generate()
    public_bytes = private.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    backend_identity = hashlib.sha256(public_bytes).hexdigest()
    command_context = {
        "schema_version": "1.0",
        "executable_sha256": hashlib.sha256(
            Path(sys.executable).read_bytes()
        ).hexdigest(),
        "allowed_endpoints": [],
        "mtls_identity_sha256": "d" * 64,
        "sandbox_identity_sha256": "e" * 64,
    }
    backend_request = {
        "schema_version": "1.0",
        "operation": "compare-and-advance",
        "purpose": "external-state-test",
        "generation": 1,
        "receipt_sha256": environment[f"{prefix}_RECEIPT_SHA256"],
        "challenge_sha256": "c" * 64,
        "command_context": command_context,
    }
    request_sha256 = hashlib.sha256(canonical_bytes(backend_request)).hexdigest()
    backend_subject = {
        "schema_version": "1.0",
        "operation": "compare-and-advance",
        "purpose": "external-state-test",
        "generation": 1,
        "receipt_sha256": environment[f"{prefix}_RECEIPT_SHA256"],
        "previous_generation": 0,
        "previous_receipt_sha256": "",
        "backend_identity_sha256": backend_identity,
        "operation_id": "cas-42",
        "request_sha256": request_sha256,
    }
    backend_receipt, _ = operation_receipt(
        backend_subject,
        purpose="monotonic-state-compare-and-advance",
        operation_id="cas-42",
        private_key=private,
    )
    backend = tmp_path / "monotonic.py"
    backend.write_text(
        "import base64,json,sys\n"
        "r=json.loads(base64.b64decode(sys.argv[-1]))\n"
        "print(json.dumps({'schema_version':'1.0','accepted':True,"
        "'generation':r['generation'],'receipt_sha256':r['receipt_sha256'],"
        f"'backend_identity_sha256':'{backend_identity}','operation_id':'cas-42',"
        f"'previous_generation':0,'previous_receipt_sha256':'','backend_receipt':{backend_receipt!r},"
        "'request_sha256':__import__('hashlib').sha256(__import__('json').dumps(r,separators=(',',':'),sort_keys=True).encode()).hexdigest()}))\n",
        encoding="utf-8",
    )
    environment.update(
        {
            f"{prefix}_STATE_COMMAND_JSON": json.dumps(
                [sys.executable, "-I", str(backend)]
            ),
            f"{prefix}_STATE_EXECUTABLE_SHA256": hashlib.sha256(
                Path(sys.executable).read_bytes()
            ).hexdigest(),
            f"{prefix}_STATE_ASSETS_JSON": json.dumps(
                [
                    {
                        "path": str(backend),
                        "sha256": hashlib.sha256(backend.read_bytes()).hexdigest(),
                    }
                ]
            ),
            f"{prefix}_STATE_ALLOWED_ENDPOINTS_JSON": "[]",
            f"{prefix}_STATE_MTLS_IDENTITY_SHA256": "d" * 64,
            f"{prefix}_STATE_SANDBOX_IDENTITY_SHA256": "e" * 64,
        }
    )
    with patch.dict(os.environ, environment):
        receipt = verify_deployment_receipt(
            subject,
            purpose="external-state-test",
            environment_prefix=prefix,
            observed_at=datetime.now(UTC),
        )
    assert receipt["monotonic_state"] == {
        "mode": "external-command",
        "backend_identity_sha256": backend_identity,
        "operation_id": "cas-42",
        "generation": receipt["statement"]["generation"],
        "previous_generation": 0,
        "previous_receipt_sha256": "",
        "backend_receipt": backend_receipt,
        "request_sha256": request_sha256,
    }
