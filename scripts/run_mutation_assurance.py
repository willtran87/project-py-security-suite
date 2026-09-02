from __future__ import annotations

import argparse
from collections.abc import Mapping, Sequence
from pathlib import Path

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


def select_mutation_shard(
    candidates: Sequence[str],
    *,
    shard_index: int,
    shard_count: int,
    weights: Mapping[str, int] | None = None,
) -> list[str]:
    """Return one deterministic, workload-balanced mutation partition."""

    if shard_count < 1:
        raise ValueError("mutation shard count must be positive")
    if not 0 <= shard_index < shard_count:
        raise ValueError("mutation shard index must be within the shard count")
    ordered = sorted(dict.fromkeys(candidates))
    if not ordered:
        raise ValueError("mutation assurance has no configured source modules")
    normalized_weights: dict[str, int] = {}
    for candidate in ordered:
        weight = 1 if weights is None else weights.get(candidate, 1)
        if isinstance(weight, bool) or not isinstance(weight, int) or weight < 1:
            raise ValueError("mutation shard weights must be positive integers")
        normalized_weights[candidate] = weight

    # Largest-processing-time-first scheduling gives deterministic, disjoint
    # shards while avoiding the severe skew caused by round-robin module count.
    # Source bytes are a stable proxy for Mutmut's generated mutant workload.
    shards: list[list[str]] = [[] for _ in range(shard_count)]
    shard_weights = [0] * shard_count
    for candidate in sorted(
        ordered, key=lambda item: (-normalized_weights[item], item)
    ):
        destination = min(
            range(shard_count), key=lambda index: (shard_weights[index], index)
        )
        shards[destination].append(candidate)
        shard_weights[destination] += normalized_weights[candidate]
    selected = sorted(shards[shard_index])
    if not selected:
        raise ValueError("mutation shard is empty; reduce the shard count")
    return selected


def mutation_workload_weights(candidates: Sequence[str]) -> dict[str, int]:
    """Estimate Mutmut work from stable source sizes, including empty files."""

    return {
        candidate: max(1, Path(candidate).stat().st_size) for candidate in candidates
    }


def main(argv: Sequence[str] | None = None) -> None:
    """Run Mutmut after initializing fork-sensitive native dependencies."""

    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--shard-index", type=int)
    parser.add_argument("--shard-count", type=int)
    options, mutmut_arguments = parser.parse_known_args(argv)
    if (options.shard_index is None) != (options.shard_count is None):
        parser.error("--shard-index and --shard-count must be supplied together")

    preload_fork_sensitive_crypto_runtime()

    # Importing Mutmut is intentionally delayed: its module selects the fork
    # multiprocessing context at import time and exits on unsupported hosts.
    from mutmut.__main__ import cli
    from mutmut.configuration import Config

    if options.shard_index is not None and options.shard_count is not None:
        config = Config.get()
        weights = mutation_workload_weights(config.only_mutate)
        config.only_mutate = select_mutation_shard(
            config.only_mutate,
            shard_index=options.shard_index,
            shard_count=options.shard_count,
            weights=weights,
        )
        print(
            f"Mutation shard {options.shard_index + 1}/{options.shard_count}: "
            f"{len(config.only_mutate)} modules"
        )

    cli(
        args=["run", *mutmut_arguments],
        prog_name="pysec-mutation-assurance",
        standalone_mode=True,
    )


if __name__ == "__main__":
    import sys

    main(sys.argv[1:])
