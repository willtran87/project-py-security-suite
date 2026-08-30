from __future__ import annotations

import base64
import hashlib
import os
import re
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol, runtime_checkable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .bounded_subprocess import BoundedSubprocessError, run_bounded_subprocess
from .path_safety import read_regular_file, resolve_regular_file
from .strict_json import canonical_bytes, loads as strict_loads


_IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_MAX_PROVIDER_OUTPUT = 4096
_PROVIDER_BACKENDS = frozenset(
    {
        "pkcs11",
        "generic-hsm",
        "hashicorp-vault-transit",
        "aws-kms",
        "azure-key-vault",
        "gcp-cloud-kms",
    }
)
_CREDENTIAL_MODES = frozenset({"workload-identity", "secure-agent", "hardware-session"})
_BACKEND_CREDENTIAL_MODES = {
    "pkcs11": {"hardware-session", "secure-agent"},
    "generic-hsm": {"hardware-session", "secure-agent"},
    "hashicorp-vault-transit": {"workload-identity", "secure-agent"},
    "aws-kms": {"workload-identity"},
    "azure-key-vault": {"workload-identity"},
    "gcp-cloud-kms": {"workload-identity"},
}


@runtime_checkable
class ReceiptSigningProvider(Protocol):
    """Minimal provider boundary for local, PKCS#11, HSM, and KMS signers."""

    @property
    def provider_id(self) -> str: ...

    @property
    def key_version(self) -> str: ...

    def public_key_bytes(self) -> bytes: ...

    def sign(self, payload: bytes) -> bytes: ...


@dataclass(frozen=True)
class LocalEd25519SigningProvider:
    """In-process Ed25519 provider used by the PEM compatibility entry point."""

    private_key: Ed25519PrivateKey
    provider_id: str = "local-pem"

    @property
    def key_version(self) -> str:
        import hashlib

        return hashlib.sha256(self.public_key_bytes()).hexdigest()

    def public_key_bytes(self) -> bytes:
        return self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def sign(self, payload: bytes) -> bytes:
        return self.private_key.sign(payload)


@dataclass(frozen=True)
class ExternalEd25519SigningProvider:
    """Digest-pinned command adapter for PKCS#11, HSM, and KMS signers.

    The command receives the exact bytes to sign on standard input and must emit
    one strict base64-encoded Ed25519 signature on standard output.  It is invoked
    without a shell or inherited secrets, and its binary and result are verified
    on every call. Vendor-specific authentication remains in the command's secure
    agent or workload identity rather than process arguments.
    """

    executable: Path
    executable_sha256: str
    arguments: tuple[str, ...]
    public_key: bytes
    provider_id: str
    key_version: str
    timeout_seconds: float = 30.0
    backend: str = "generic-hsm"
    credential_mode: str = "secure-agent"

    def __post_init__(self) -> None:
        if (
            not _DIGEST.fullmatch(self.executable_sha256)
            or not _IDENTIFIER.fullmatch(self.provider_id)
            or not _IDENTIFIER.fullmatch(self.key_version)
            or not 0.1 <= self.timeout_seconds <= 60.0
            or len(self.arguments) > 32
            or self.backend not in _PROVIDER_BACKENDS
            or self.credential_mode
            not in _BACKEND_CREDENTIAL_MODES.get(self.backend, set())
            or any(
                not isinstance(item, str) or len(item) > 1024 for item in self.arguments
            )
        ):
            raise ValueError("external signing provider configuration is invalid")
        Ed25519PublicKey.from_public_bytes(self.public_key)

    def public_key_bytes(self) -> bytes:
        return self.public_key

    def sign(self, payload: bytes) -> bytes:
        executable = self.executable.expanduser().absolute()
        if executable.is_symlink() or not executable.is_file():
            raise ValueError("external signing provider executable is unsafe")
        before = executable.stat()
        if _sha256_file(executable) != self.executable_sha256:
            raise ValueError("external signing provider executable digest changed")
        environment = {
            name: os.environ[name]
            for name in ("SYSTEMROOT", "WINDIR", "TMP", "TEMP")
            if name in os.environ
        }
        try:
            completed = run_bounded_subprocess(
                (str(executable), *self.arguments),
                input_bytes=payload,
                timeout_seconds=self.timeout_seconds,
                environment=environment,
                maximum_stdout_bytes=_MAX_PROVIDER_OUTPUT,
                maximum_stderr_bytes=_MAX_PROVIDER_OUTPUT,
            )
        except BoundedSubprocessError as exc:
            message = str(exc).replace(
                "bounded subprocess", "external signing provider"
            )
            raise ValueError(message) from exc
        after = executable.stat()
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ) or _sha256_file(executable) != self.executable_sha256:
            raise ValueError("external signing provider executable changed during use")
        if completed.returncode != 0:
            raise ValueError("external signing provider command failed")
        try:
            signature = base64.b64decode(completed.stdout.strip(), validate=True)
        except ValueError as exc:
            raise ValueError(
                "external signing provider returned invalid base64"
            ) from exc
        try:
            Ed25519PublicKey.from_public_bytes(self.public_key).verify(
                signature, payload
            )
        except InvalidSignature as exc:
            raise ValueError(
                "external signing provider returned an invalid signature"
            ) from exc
        return signature


def load_external_signing_provider_profile(
    path: Path,
    expected_sha256: str,
) -> ExternalEd25519SigningProvider:
    """Load a digest-pinned, secret-free deployment signing-provider profile."""
    _, payload = read_regular_file(
        path,
        "external signing provider profile",
        maximum_bytes=256 * 1024,
    )
    if (
        not _DIGEST.fullmatch(expected_sha256)
        or hashlib.sha256(payload).hexdigest() != expected_sha256
    ):
        raise ValueError("external signing provider profile digest does not match")
    value = strict_loads(payload)
    required = {
        "schema_version",
        "backend",
        "credential_mode",
        "provider_id",
        "key_version",
        "executable",
        "executable_sha256",
        "arguments",
        "public_key_base64",
        "timeout_seconds",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise ValueError("external signing provider profile fields do not match")
    executable = Path(str(value["executable"]))
    arguments = value["arguments"]
    if (
        value["schema_version"] != "1.0"
        or value["backend"] not in _PROVIDER_BACKENDS
        or value["credential_mode"] not in _CREDENTIAL_MODES
        or value["credential_mode"]
        not in _BACKEND_CREDENTIAL_MODES.get(str(value["backend"]), set())
        or not executable.is_absolute()
        or not isinstance(arguments, list)
        or any(not isinstance(item, str) for item in arguments)
        or isinstance(value["timeout_seconds"], bool)
        or not isinstance(value["timeout_seconds"], (int, float))
    ):
        raise ValueError("external signing provider profile is invalid")
    try:
        public_key = base64.b64decode(value["public_key_base64"], validate=True)
    except (TypeError, ValueError) as exc:
        raise ValueError("external signing provider public key is invalid") from exc
    return ExternalEd25519SigningProvider(
        executable=resolve_regular_file(
            executable, "external signing provider executable"
        ),
        executable_sha256=str(value["executable_sha256"]),
        arguments=tuple(arguments),
        public_key=public_key,
        provider_id=str(value["provider_id"]),
        key_version=str(value["key_version"]),
        timeout_seconds=float(value["timeout_seconds"]),
        backend=str(value["backend"]),
        credential_mode=str(value["credential_mode"]),
    )


def verify_signing_provider_conformance(
    provider: ReceiptSigningProvider,
    *,
    challenge: bytes | None = None,
    portable: bool = False,
    observed_at: datetime | None = None,
    profile_sha256: str = "",
    time_context_sha256: str = "",
) -> dict[str, object]:
    """Actively prove provider identity, key stability, and Ed25519 signing behavior."""
    nonce = secrets.token_bytes(32) if challenge is None else challenge
    if not 32 <= len(nonce) <= 4096:
        raise ValueError("signing provider conformance challenge is invalid")
    if not _IDENTIFIER.fullmatch(provider.provider_id) or not _IDENTIFIER.fullmatch(
        provider.key_version
    ):
        raise ValueError("signing provider identity is invalid")
    public_key = provider.public_key_bytes()
    if len(public_key) != 32 or provider.public_key_bytes() != public_key:
        raise ValueError("signing provider public key is invalid or unstable")
    result: dict[str, object] = {
        "schema_version": "1.0",
        "provider_id": provider.provider_id,
        "key_version": provider.key_version,
        "algorithm": "Ed25519",
        "public_key_sha256": hashlib.sha256(public_key).hexdigest(),
        "challenge_sha256": hashlib.sha256(nonce).hexdigest(),
        "deterministic_signature": True,
        "verified": True,
    }
    if isinstance(provider, ExternalEd25519SigningProvider):
        result.update(
            {
                "backend": provider.backend,
                "credential_mode": provider.credential_mode,
                "executable_sha256": provider.executable_sha256,
            }
        )
    else:
        result.update(
            {
                "backend": "local-ed25519",
                "credential_mode": "local-key",
                "executable_sha256": "",
            }
        )
    if portable:
        observed = datetime.now(UTC) if observed_at is None else observed_at
        if observed.tzinfo is None:
            raise ValueError("signing provider conformance time must be timezone-aware")
        if not _DIGEST.fullmatch(profile_sha256):
            raise ValueError("signing provider profile digest is invalid")
        if time_context_sha256 and not _DIGEST.fullmatch(time_context_sha256):
            raise ValueError("signing provider trusted-time identity is invalid")
        result.update(
            {
                "schema_version": "1.1",
                "observed_at": observed.astimezone(UTC).isoformat(),
                "profile_sha256": profile_sha256,
                "time_context_sha256": time_context_sha256,
                "public_key_base64": base64.b64encode(public_key).decode("ascii"),
                "challenge_base64": base64.b64encode(nonce).decode("ascii"),
            }
        )
        statement = _portable_conformance_statement(result, nonce)
    else:
        statement = b"pysec-benchmark-signing-provider-conformance-v1\x00" + nonce
    first = provider.sign(statement)
    second = provider.sign(statement)
    try:
        verifier = Ed25519PublicKey.from_public_bytes(public_key)
        verifier.verify(first, statement)
        verifier.verify(second, statement)
    except (InvalidSignature, ValueError) as exc:
        raise ValueError("signing provider conformance signature is invalid") from exc
    if first != second:
        raise ValueError(
            "Ed25519 signing provider returned nondeterministic signatures"
        )
    result.update(
        {
            "statement_sha256": hashlib.sha256(statement).hexdigest(),
            "signature_sha256": hashlib.sha256(first).hexdigest(),
        }
    )
    if portable:
        result["signature_base64"] = base64.b64encode(first).decode("ascii")
    return result


def verify_portable_signing_provider_conformance(
    receipt: dict[str, object],
) -> dict[str, object]:
    """Independently replay a portable signing-provider conformance receipt."""

    required = {
        "schema_version",
        "provider_id",
        "key_version",
        "algorithm",
        "backend",
        "credential_mode",
        "public_key_sha256",
        "challenge_sha256",
        "statement_sha256",
        "signature_sha256",
        "executable_sha256",
        "deterministic_signature",
        "verified",
        "observed_at",
        "profile_sha256",
        "time_context_sha256",
        "public_key_base64",
        "challenge_base64",
        "signature_base64",
    }
    if set(receipt) != required or receipt.get("schema_version") != "1.1":
        raise ValueError("portable signing provider conformance fields are invalid")
    if (
        receipt.get("algorithm") != "Ed25519"
        or receipt.get("deterministic_signature") is not True
        or receipt.get("verified") is not True
        or receipt.get("backend") not in _PROVIDER_BACKENDS
        or receipt.get("credential_mode") not in _CREDENTIAL_MODES
        or not _IDENTIFIER.fullmatch(str(receipt.get("provider_id") or ""))
        or not _IDENTIFIER.fullmatch(str(receipt.get("key_version") or ""))
    ):
        raise ValueError("portable signing provider conformance identity is invalid")
    for field in (
        "public_key_sha256",
        "challenge_sha256",
        "statement_sha256",
        "signature_sha256",
        "executable_sha256",
        "profile_sha256",
    ):
        if not _DIGEST.fullmatch(str(receipt.get(field) or "")):
            raise ValueError(f"portable signing provider {field} is invalid")
    time_identity = str(receipt.get("time_context_sha256") or "")
    if time_identity and not _DIGEST.fullmatch(time_identity):
        raise ValueError("portable signing provider trusted-time identity is invalid")
    try:
        observed = datetime.fromisoformat(
            str(receipt["observed_at"]).replace("Z", "+00:00")
        )
        public_key = base64.b64decode(str(receipt["public_key_base64"]), validate=True)
        challenge = base64.b64decode(str(receipt["challenge_base64"]), validate=True)
        signature = base64.b64decode(str(receipt["signature_base64"]), validate=True)
    except (TypeError, ValueError) as exc:
        raise ValueError(
            "portable signing provider evidence encoding is invalid"
        ) from exc
    if observed.tzinfo is None or not 32 <= len(challenge) <= 4096:
        raise ValueError("portable signing provider observation is invalid")
    statement = _portable_conformance_statement(receipt, challenge)
    expected_hashes = {
        "public_key_sha256": hashlib.sha256(public_key).hexdigest(),
        "challenge_sha256": hashlib.sha256(challenge).hexdigest(),
        "statement_sha256": hashlib.sha256(statement).hexdigest(),
        "signature_sha256": hashlib.sha256(signature).hexdigest(),
    }
    if any(receipt[name] != digest for name, digest in expected_hashes.items()):
        raise ValueError("portable signing provider evidence digest is detached")
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, statement)
    except (InvalidSignature, ValueError) as exc:
        raise ValueError("portable signing provider signature is invalid") from exc
    return {
        "provider_id": receipt["provider_id"],
        "key_version": receipt["key_version"],
        "backend": receipt["backend"],
        "credential_mode": receipt["credential_mode"],
        "public_key_sha256": receipt["public_key_sha256"],
        "executable_sha256": receipt["executable_sha256"],
        "profile_sha256": receipt["profile_sha256"],
        "time_context_sha256": time_identity,
        "observed_at": observed.astimezone(UTC),
    }


def _portable_conformance_statement(
    receipt: dict[str, object], challenge: bytes
) -> bytes:
    """Bind portable evidence and provider metadata into one domain statement."""

    subject = {
        "schema_version": receipt.get("schema_version"),
        "provider_id": receipt.get("provider_id"),
        "key_version": receipt.get("key_version"),
        "algorithm": receipt.get("algorithm"),
        "backend": receipt.get("backend"),
        "credential_mode": receipt.get("credential_mode"),
        "public_key_sha256": receipt.get("public_key_sha256"),
        "challenge_sha256": receipt.get("challenge_sha256"),
        "executable_sha256": receipt.get("executable_sha256"),
        "deterministic_signature": receipt.get("deterministic_signature"),
        "verified": receipt.get("verified"),
        "observed_at": receipt.get("observed_at"),
        "profile_sha256": receipt.get("profile_sha256"),
        "time_context_sha256": receipt.get("time_context_sha256"),
    }
    return (
        b"pysec-benchmark-signing-provider-conformance-portable-v1\x00"
        + canonical_bytes(subject)
        + b"\x00"
        + challenge
    )


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
