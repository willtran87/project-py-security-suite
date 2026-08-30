from __future__ import annotations

import base64
import hashlib
import json
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

import cryptography
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from py_security_suite.benchmark_signing import (
    ExternalEd25519SigningProvider,
    verify_signing_provider_conformance,
)
from py_security_suite.release_readiness import _provider_conformance_control


def _receipt(observed_at: datetime) -> dict[str, object]:
    key = Ed25519PrivateKey.generate()
    private_key = key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    executable = Path(sys.executable).resolve()
    script = (
        "import base64,sys;"
        f"sys.path.insert(0,{str(Path(cryptography.__file__).resolve().parent.parent)!r});"
        "from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey;"
        "key=Ed25519PrivateKey.from_private_bytes(base64.b64decode(sys.argv[1]));"
        "sys.stdout.write(base64.b64encode(key.sign(sys.stdin.buffer.read())).decode())"
    )
    provider = ExternalEd25519SigningProvider(
        executable=executable,
        executable_sha256=hashlib.sha256(executable.read_bytes()).hexdigest(),
        arguments=("-I", "-c", script, base64.b64encode(private_key).decode()),
        public_key=key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        ),
        provider_id="release-provider",
        key_version="release-key-2026-08",
        backend="pkcs11",
        credential_mode="hardware-session",
    )
    receipt = verify_signing_provider_conformance(
        provider,
        challenge=b"r" * 32,
        portable=True,
        observed_at=observed_at,
        profile_sha256="a" * 64,
        time_context_sha256="b" * 64,
    )
    return receipt


def _write(path: Path, receipt: dict[str, object]) -> str:
    payload = json.dumps(receipt, sort_keys=True).encode()
    path.write_bytes(payload)
    return hashlib.sha256(payload).hexdigest()


def test_release_control_requires_fresh_exact_provider_receipt(tmp_path: Path) -> None:
    now = datetime(2026, 8, 30, 12, tzinfo=UTC)
    path = tmp_path / "provider.json"
    digest = _write(path, _receipt(now - timedelta(hours=2)))
    with patch("py_security_suite.release_readiness.governed_now", return_value=now):
        control = _provider_conformance_control(
            (path,), (digest,), ("release-provider",), 24, True
        )
    assert control is not None
    assert control["status"] == "pass"
    assert "1 fresh" in control["detail"]


def test_release_control_reports_missing_and_stale_providers(tmp_path: Path) -> None:
    now = datetime(2026, 8, 30, 12, tzinfo=UTC)
    path = tmp_path / "provider.json"
    digest = _write(path, _receipt(now - timedelta(hours=25)))
    with patch("py_security_suite.release_readiness.governed_now", return_value=now):
        control = _provider_conformance_control(
            (path,), (digest,), ("release-provider", "second-provider"), 24, True
        )
    assert control is not None
    assert control["status"] == "fail"
    assert "second-provider" in control["detail"]
    assert "release-provider" in control["detail"]


def test_release_control_rejects_receipt_digest_mismatch(tmp_path: Path) -> None:
    now = datetime(2026, 8, 30, 12, tzinfo=UTC)
    path = tmp_path / "provider.json"
    _write(path, _receipt(now))
    with (
        patch("py_security_suite.release_readiness.governed_now", return_value=now),
        pytest.raises(ValueError, match="does not match"),
    ):
        _provider_conformance_control(
            (path,), ("f" * 64,), ("release-provider",), 24, True
        )
