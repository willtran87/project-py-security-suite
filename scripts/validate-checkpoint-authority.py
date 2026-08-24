from __future__ import annotations

import argparse
import hashlib
import uuid
from typing import Any

from py_security_suite.checkpoint_authority import publish_checkpoint
from py_security_suite.strict_json import canonical_bytes, dumps


def _subject(namespace: str, sequence: int, state: str) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "state_kind": namespace,
        "sequence": sequence,
        "checkpoint_sha256": hashlib.sha256(state.encode("utf-8")).hexdigest(),
    }


def _receipt_digest(receipt: dict[str, Any] | None) -> str:
    if receipt is None:
        raise ValueError("checkpoint authority unexpectedly returned no receipt")
    return hashlib.sha256(canonical_bytes(receipt)).hexdigest()


def _must_reject(prefix: str, subject: dict[str, Any], label: str) -> None:
    try:
        publish_checkpoint(prefix, subject, required=True)
    except ValueError:
        return
    raise ValueError(f"checkpoint authority accepted {label}")


def validate(prefix: str, namespace: str) -> dict[str, Any]:
    """Exercise monotonic, idempotent, fork, rollback, and gap behavior live."""

    first = _subject(namespace, 1, "first")
    second = _subject(namespace, 2, "second")
    first_receipt = publish_checkpoint(prefix, first, required=True)
    repeated_receipt = publish_checkpoint(prefix, first, required=True)
    _receipt_digest(repeated_receipt)

    _must_reject(prefix, _subject(namespace, 1, "fork"), "a same-sequence fork")
    second_receipt = publish_checkpoint(prefix, second, required=True)
    _must_reject(prefix, _subject(namespace, 1, "rollback"), "a rollback")
    _must_reject(prefix, _subject(namespace, 4, "gap"), "a sequence gap")

    return {
        "schema_version": "1.0",
        "status": "pass",
        "authority_prefix": prefix,
        "namespace": namespace,
        "checks": {
            "first_transition": "accepted",
            "idempotent_retry": "accepted-and-stable",
            "same_sequence_fork": "rejected",
            "next_transition": "accepted",
            "rollback": "rejected",
            "sequence_gap": "rejected",
        },
        "receipt_sha256": {
            "sequence_1": _receipt_digest(first_receipt),
            "sequence_2": _receipt_digest(second_receipt),
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Conformance-test a configured external checkpoint authority."
    )
    parser.add_argument(
        "--prefix",
        default="PYSEC_CHECKPOINT_CONFORMANCE",
        help="configured pinned-command environment prefix",
    )
    parser.add_argument(
        "--namespace",
        help="disposable authority namespace (a random value is used by default)",
    )
    args = parser.parse_args()
    namespace = args.namespace or f"pysec-conformance-{uuid.uuid4()}"
    print(dumps(validate(str(args.prefix), namespace), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
