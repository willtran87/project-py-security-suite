from __future__ import annotations

from collections.abc import Sequence

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec as _ec
from cryptography.hazmat.primitives.asymmetric import ed448 as _ed448
from cryptography.hazmat.primitives.asymmetric import padding as _padding
from cryptography.hazmat.primitives.asymmetric import rsa as _rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import NameOID


def preload_fork_sensitive_crypto_runtime() -> None:
    """Initialize native crypto types before Mutmut creates fork workers.

    Mutmut 3 uses ``fork`` and invokes pytest in its long-lived parent process.
    Loading only part of cryptography after that fork can leave its Rust-backed
    key and X.509 objects paired with re-imported Python wrapper classes.  The
    result is a false baseline failure even though pytest passes independently.
    Import and exercise the complete native surface used by the assurance tests
    before Mutmut creates its pool, and fail closed if class identity is broken.
    """

    # These imports deliberately initialize the remaining asymmetric backends.
    # Referencing the modules keeps static analysis honest about that contract.
    native_backends = {_ec.__name__, _ed448.__name__, _padding.__name__, _rsa.__name__}
    if len(native_backends) != 4:  # pragma: no cover
        raise RuntimeError("cryptography asymmetric backends are unavailable")

    private_key = Ed25519PrivateKey.generate()
    private_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    loaded_key = serialization.load_pem_private_key(private_pem, password=None)
    if not isinstance(loaded_key, Ed25519PrivateKey):
        raise RuntimeError("cryptography Ed25519 runtime identity is inconsistent")
    expected_public = private_key.public_key().public_bytes_raw()
    if loaded_key.public_key().public_bytes_raw() != expected_public:
        raise RuntimeError("cryptography Ed25519 preload self-check failed")

    subject = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "pysec-mutation-parent")]
    )
    if subject.rfc4514_string() != "CN=pysec-mutation-parent":
        raise RuntimeError("cryptography X.509 preload self-check failed")


def main(argv: Sequence[str] | None = None) -> None:
    """Run Mutmut after initializing fork-sensitive native dependencies."""

    preload_fork_sensitive_crypto_runtime()

    # Importing Mutmut is intentionally delayed: its module selects the fork
    # multiprocessing context at import time and exits on unsupported hosts.
    from mutmut.__main__ import cli

    arguments = list(argv) if argv is not None else None
    cli(
        args=["run", *(arguments or [])],
        prog_name="pysec-mutation-assurance",
        standalone_mode=True,
    )


if __name__ == "__main__":
    import sys

    main(sys.argv[1:])
