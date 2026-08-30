from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jsonschema import Draft202012Validator

from py_security_suite.benchmark_signing import (
    ExternalEd25519SigningProvider,
    _portable_conformance_statement,
    load_external_signing_provider_profile,
    verify_signing_provider_conformance,
    verify_portable_signing_provider_conformance,
)
from py_security_suite.cli import (
    _external_benchmark_signing_provider,
    build_parser,
    main,
)
from py_security_suite.report_inspection import read_bundled_schema


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _profile(executable: Path, backend: str, credential_mode: str) -> dict[str, object]:
    public_key = (
        Ed25519PrivateKey.generate()
        .public_key()
        .public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
    )
    return {
        "schema_version": "1.0",
        "backend": backend,
        "credential_mode": credential_mode,
        "provider_id": f"provider-{backend}",
        "key_version": "version-2026-08",
        "executable": str(executable),
        "executable_sha256": _sha256(executable),
        "arguments": ["sign", "benchmark-receipt"],
        "public_key_base64": base64.b64encode(public_key).decode(),
        "timeout_seconds": 15.0,
    }


def _live_profile(executable: Path, backend: str = "generic-hsm") -> dict[str, object]:
    key = Ed25519PrivateKey.generate()
    private_key = key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    script = (
        "import base64,sys;"
        "from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey;"
        "key=Ed25519PrivateKey.from_private_bytes(base64.b64decode(sys.argv[1]));"
        "sys.stdout.write(base64.b64encode(key.sign(sys.stdin.buffer.read())).decode())"
    )
    return {
        "schema_version": "1.0",
        "backend": backend,
        "credential_mode": "secure-agent",
        "provider_id": f"provider-{backend}",
        "key_version": "version-2026-08",
        "executable": str(executable),
        "executable_sha256": _sha256(executable),
        "arguments": ["-I", "-c", script, base64.b64encode(private_key).decode()],
        "public_key_base64": base64.b64encode(
            key.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            )
        ).decode(),
        "timeout_seconds": 15.0,
    }


@pytest.mark.parametrize(
    ("backend", "credential_mode"),
    [
        ("pkcs11", "hardware-session"),
        ("generic-hsm", "secure-agent"),
        ("hashicorp-vault-transit", "workload-identity"),
        ("aws-kms", "workload-identity"),
        ("azure-key-vault", "workload-identity"),
        ("gcp-cloud-kms", "workload-identity"),
    ],
)
def test_provider_profiles_cover_supported_deployment_backends(
    tmp_path: Path, backend: str, credential_mode: str
) -> None:
    executable = Path(sys.executable).resolve()
    value = _profile(executable, backend, credential_mode)
    Draft202012Validator(
        json.loads(read_bundled_schema("benchmark-signing-provider-profile-1.0"))
    ).validate(value)
    profile = tmp_path / "provider.json"
    profile.write_text(json.dumps(value), encoding="utf-8")

    provider = load_external_signing_provider_profile(profile, _sha256(profile))

    assert provider.provider_id == f"provider-{backend}"
    assert provider.executable == executable
    assert provider.arguments == ("sign", "benchmark-receipt")


def test_provider_profile_requires_out_of_band_digest(tmp_path: Path) -> None:
    profile = tmp_path / "provider.json"
    profile.write_text(
        json.dumps(_profile(Path(sys.executable).resolve(), "pkcs11", "secure-agent")),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="digest does not match"):
        load_external_signing_provider_profile(profile, "0" * 64)


@pytest.mark.parametrize(
    ("backend", "credential_mode"),
    [
        ("unknown-kms", "workload-identity"),
        ("aws-kms", "hardware-session"),
        ("pkcs11", "workload-identity"),
    ],
)
def test_provider_profile_rejects_unknown_or_incompatible_authentication(
    tmp_path: Path, backend: str, credential_mode: str
) -> None:
    profile = tmp_path / "provider.json"
    profile.write_text(
        json.dumps(_profile(Path(sys.executable).resolve(), backend, credential_mode)),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="profile is invalid"):
        load_external_signing_provider_profile(profile, _sha256(profile))


def test_provider_profile_rejects_relative_or_missing_executable(
    tmp_path: Path,
) -> None:
    value = _profile(Path(sys.executable).resolve(), "pkcs11", "secure-agent")
    value["executable"] = "relative-bridge"
    profile = tmp_path / "provider.json"
    profile.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(ValueError, match="profile is invalid"):
        load_external_signing_provider_profile(profile, _sha256(profile))

    value["executable"] = str((tmp_path / "missing-bridge").resolve())
    profile.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(ValueError, match="not a regular file"):
        load_external_signing_provider_profile(profile, _sha256(profile))


def test_benchmark_cli_loads_one_profile_and_rejects_mixed_provider_options(
    tmp_path: Path,
) -> None:
    profile = tmp_path / "provider.json"
    profile.write_text(
        json.dumps(_profile(Path(sys.executable).resolve(), "pkcs11", "secure-agent")),
        encoding="utf-8",
    )
    parser = build_parser()
    base = [
        "benchmark-run",
        "manifest.json",
        "--workspace",
        str(tmp_path),
        "--output",
        str(tmp_path / "receipt.json"),
        "--receipt-signing-provider-profile",
        str(profile),
        "--receipt-signing-provider-profile-sha256",
        _sha256(profile),
    ]
    provider = _external_benchmark_signing_provider(parser.parse_args(base))
    assert provider is not None
    assert provider.provider_id == "provider-pkcs11"

    mixed = parser.parse_args(
        [*base, "--receipt-signing-provider-executable", sys.executable]
    )
    with pytest.raises(ValueError, match="mutually exclusive"):
        _external_benchmark_signing_provider(mixed)


def test_external_provider_conformance_actively_signs_twice_and_validates_schema(
    tmp_path: Path,
) -> None:
    executable = Path(sys.executable).resolve()
    value = _live_profile(executable)
    profile = tmp_path / "provider.json"
    profile.write_text(json.dumps(value), encoding="utf-8")
    provider = load_external_signing_provider_profile(profile, _sha256(profile))

    result = verify_signing_provider_conformance(provider, challenge=b"c" * 32)

    assert result["verified"] is True
    assert result["deterministic_signature"] is True
    assert result["backend"] == "generic-hsm"
    Draft202012Validator(
        json.loads(read_bundled_schema("benchmark-signing-provider-conformance-1.0"))
    ).validate(result)


def test_provider_conformance_cli_publishes_verified_receipt(tmp_path: Path) -> None:
    executable = Path(sys.executable).resolve()
    profile = tmp_path / "provider.json"
    profile.write_text(json.dumps(_live_profile(executable)), encoding="utf-8")
    output = tmp_path / "conformance.json"

    assert (
        main(
            [
                "benchmark-provider-check",
                "--profile",
                str(profile),
                "--profile-sha256",
                _sha256(profile),
                "--output",
                str(output),
            ]
        )
        == 0
    )
    receipt = json.loads(output.read_text(encoding="utf-8"))
    assert receipt["verified"] is True
    assert receipt["schema_version"] == "1.1"
    assert receipt["profile_sha256"] == _sha256(profile)
    Draft202012Validator(
        json.loads(read_bundled_schema("benchmark-signing-provider-conformance-1.1"))
    ).validate(receipt)
    verified = verify_portable_signing_provider_conformance(receipt)
    assert verified["provider_id"] == "provider-generic-hsm"


def test_portable_provider_conformance_rejects_detached_signature(
    tmp_path: Path,
) -> None:
    executable = Path(sys.executable).resolve()
    profile = tmp_path / "provider.json"
    profile.write_text(json.dumps(_live_profile(executable)), encoding="utf-8")
    provider = load_external_signing_provider_profile(profile, _sha256(profile))
    receipt = verify_signing_provider_conformance(
        provider,
        challenge=b"p" * 32,
        portable=True,
        profile_sha256=_sha256(profile),
    )
    receipt["signature_base64"] = "A" * 88
    with pytest.raises(ValueError, match="digest is detached"):
        verify_portable_signing_provider_conformance(receipt)

    receipt = verify_signing_provider_conformance(
        provider,
        challenge=b"p" * 32,
        portable=True,
        profile_sha256=_sha256(profile),
    )
    receipt["backend"] = "pkcs11"
    receipt["statement_sha256"] = hashlib.sha256(
        _portable_conformance_statement(receipt, b"p" * 32)
    ).hexdigest()
    with pytest.raises(ValueError, match="signature is invalid"):
        verify_portable_signing_provider_conformance(receipt)


def test_provider_conformance_rejects_invalid_challenge() -> None:
    key = Ed25519PrivateKey.generate()
    provider = ExternalEd25519SigningProvider(
        executable=Path(sys.executable).resolve(),
        executable_sha256=_sha256(Path(sys.executable).resolve()),
        arguments=(),
        public_key=key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        ),
        provider_id="test-provider",
        key_version="test-version",
    )
    with pytest.raises(ValueError, match="challenge is invalid"):
        verify_signing_provider_conformance(provider, challenge=b"too-short")
