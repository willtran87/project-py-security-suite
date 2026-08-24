from __future__ import annotations

import base64
import hashlib
import json
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from py_security_suite.strict_json import canonical_bytes


def pinned_command_sandbox_environment(
    root: Path, *, prefix: str, allowed_endpoints: list[str]
) -> tuple[dict[str, str], dict[str, object], dict[str, str]]:
    """Return a pinned pass-through launcher contract for protocol tests."""

    launcher = root / f"{prefix.casefold()}-sandbox.py"
    launcher.write_text(
        "import subprocess,sys\n"
        "raise SystemExit(subprocess.run(sys.argv[1:]).returncode)\n",
        encoding="utf-8",
    )
    executable_sha256 = hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest()
    mtls_identity = "d" * 64
    launcher_argv = ["-I", str(launcher)]
    sandbox_identity = hashlib.sha256(
        canonical_bytes(
            {
                "launcher_sha256": executable_sha256,
                "launcher_argv": launcher_argv,
                "allowed_endpoints": allowed_endpoints,
                "mtls_identity_sha256": mtls_identity,
            }
        )
    ).hexdigest()
    environment = {
        f"{prefix}_ALLOWED_ENDPOINTS_JSON": json.dumps(allowed_endpoints),
        f"{prefix}_MTLS_IDENTITY_SHA256": mtls_identity,
        f"{prefix}_SANDBOX_IDENTITY_SHA256": sandbox_identity,
        f"{prefix}_SANDBOX_COMMAND_JSON": json.dumps([sys.executable, *launcher_argv]),
        f"{prefix}_SANDBOX_EXECUTABLE_SHA256": executable_sha256,
    }
    context: dict[str, object] = {
        "schema_version": "1.0",
        "executable_sha256": executable_sha256,
        "allowed_endpoints": allowed_endpoints,
        "mtls_identity_sha256": mtls_identity,
        "sandbox_identity_sha256": sandbox_identity,
        "sandbox_executable_sha256": executable_sha256,
        "sandbox_launcher_argv": launcher_argv,
    }
    asset = {
        "path": str(launcher),
        "sha256": hashlib.sha256(launcher.read_bytes()).hexdigest(),
    }
    return environment, context, asset


def operation_receipt(
    subject: object,
    *,
    purpose: str,
    challenge: str = "c" * 64,
    operation_id: str = "operation-1",
    previous_operation_sha256: str = "",
    private_key: Ed25519PrivateKey | None = None,
) -> tuple[dict[str, object], str]:
    """Create a short-lived external-operation receipt for integration tests."""

    private = private_key or Ed25519PrivateKey.generate()
    public_bytes = private.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    key_sha256 = hashlib.sha256(public_bytes).hexdigest()
    now = datetime.now(UTC)
    statement = {
        "schema_version": "1.0",
        "purpose": purpose,
        "subject_sha256": hashlib.sha256(canonical_bytes(subject)).hexdigest(),
        "operation_id": operation_id,
        "previous_operation_sha256": previous_operation_sha256,
        "challenge_sha256": challenge,
        "issued_at": now.isoformat(),
        "expires_at": (now + timedelta(hours=1)).isoformat(),
        "signer_key_sha256": key_sha256,
    }
    return (
        {
            "schema_version": "1.0",
            "statement": statement,
            "signature_base64": base64.b64encode(
                private.sign(canonical_bytes(statement))
            ).decode("ascii"),
            "public_key_pem_base64": base64.b64encode(public_bytes).decode("ascii"),
        },
        key_sha256,
    )


def authority_environment(
    root: Path,
    subject: object,
    *,
    purpose: str,
    prefix: str,
    challenge: str = "c" * 64,
) -> dict[str, str]:
    private = Ed25519PrivateKey.generate()
    public = root / f"{purpose}.authority.pem"
    public.write_bytes(
        private.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    key_sha256 = hashlib.sha256(public.read_bytes()).hexdigest()
    now = datetime.now(UTC)
    statement = {
        "schema_version": "1.0",
        "purpose": purpose,
        "subject_sha256": hashlib.sha256(canonical_bytes(subject)).hexdigest(),
        "challenge_sha256": challenge,
        "generation": 1,
        "issued_at": now.isoformat(),
        "expires_at": (now + timedelta(hours=1)).isoformat(),
        "signer_key_sha256": key_sha256,
    }
    receipt = root / f"{purpose}.authority-receipt.json"
    receipt.write_bytes(
        canonical_bytes(
            {
                "schema_version": "1.0",
                "statement": statement,
                "signature_base64": base64.b64encode(
                    private.sign(canonical_bytes(statement))
                ).decode("ascii"),
            }
        )
    )
    return {
        "PYSEC_SCAN_TIME_CHALLENGE_SHA256": challenge,
        f"{prefix}_RECEIPT_PATH": str(receipt),
        f"{prefix}_RECEIPT_SHA256": hashlib.sha256(receipt.read_bytes()).hexdigest(),
        f"{prefix}_KEY_PATH": str(public),
        f"{prefix}_KEY_SHA256": key_sha256,
        f"{prefix}_MIN_GENERATION": "1",
        f"{prefix}_STATE_PATH": str(root / f"{purpose}.authority-state.sqlite3"),
    }
