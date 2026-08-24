from __future__ import annotations

import base64
import hashlib
import os
from datetime import UTC, datetime
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .path_safety import read_regular_file
from .strict_json import canonical_bytes, loads as strict_loads

_FIELDS = {
    "organization",
    "host_identity_sha256",
    "control_plane_sha256",
    "implementation_sha256",
}


def verify_failure_domain(value: object, label: str) -> dict[str, str]:
    """Validate one deployment-owned authority failure-domain identity."""

    if not isinstance(value, dict) or set(value) != _FIELDS:
        raise ValueError(f"{label} failure-domain fields do not match")
    normalized = {name: str(value[name]).strip().casefold() for name in _FIELDS}
    if not normalized["organization"] or any(
        not _digest(normalized[name])
        for name in (
            "host_identity_sha256",
            "control_plane_sha256",
            "implementation_sha256",
        )
    ):
        raise ValueError(f"{label} failure-domain identity is invalid")
    return normalized


def require_independent_failure_domains(
    first: object, second: object, *, labels: tuple[str, str]
) -> tuple[dict[str, str], dict[str, str]]:
    """Require organizational, host, control-plane, and implementation diversity."""

    left = verify_failure_domain(first, labels[0])
    right = verify_failure_domain(second, labels[1])
    if any(left[name] == right[name] for name in _FIELDS):
        raise ValueError(
            f"{labels[0]} and {labels[1]} do not span independent failure domains"
        )
    return left, right


def verify_registered_failure_domain(
    value: object, authority_key_sha256: str, label: str
) -> dict[str, str]:
    """Verify an authority domain against a deployment-pinned identity registry."""

    domain = verify_failure_domain(value, label)
    path_value = os.environ.get("PYSEC_FAILURE_DOMAIN_REGISTRY_PATH", "").strip()
    digest = (
        os.environ.get("PYSEC_FAILURE_DOMAIN_REGISTRY_SHA256", "").strip().casefold()
    )
    required = (
        os.environ.get("PYSEC_REQUIRE_REGISTERED_FAILURE_DOMAINS", "").strip() == "1"
    )
    if not path_value and not digest:
        if required:
            raise ValueError("failure-domain registry is required")
        return domain
    if not path_value or not _digest(digest) or not _digest(authority_key_sha256):
        raise ValueError("failure-domain registry configuration is incomplete")
    _, payload = read_regular_file(
        Path(path_value), "failure-domain registry", maximum_bytes=4 * 1024 * 1024
    )
    if hashlib.sha256(payload).hexdigest() != digest:
        raise ValueError("failure-domain registry does not match its pin")
    document = strict_loads(payload)
    fresh_required = (
        os.environ.get("PYSEC_REQUIRE_FRESH_FAILURE_DOMAIN_REGISTRY", "").strip() == "1"
    )
    if isinstance(document, dict) and document.get("schema_version") == "2.0":
        document = _verify_fresh_registry(document)
    elif fresh_required:
        raise ValueError("a fresh threshold-signed failure-domain registry is required")
    if (
        not isinstance(document, dict)
        or set(document) != {"schema_version", "generation", "authorities"}
        or document.get("schema_version") != "1.0"
        or not isinstance(document.get("generation"), int)
        or document["generation"] < 1
        or not isinstance(document.get("authorities"), list)
    ):
        raise ValueError("failure-domain registry is invalid")
    matches = []
    seen: set[str] = set()
    for item in document["authorities"]:
        if (
            not isinstance(item, dict)
            or set(item)
            != {
                "authority_key_sha256",
                "failure_domain",
                "implementation_artifact_sha256",
                "status",
            }
            or not _digest(str(item.get("authority_key_sha256") or ""))
            or item["authority_key_sha256"] in seen
            or item.get("status") not in {"active", "revoked"}
        ):
            raise ValueError("failure-domain registry authority is invalid")
        seen.add(item["authority_key_sha256"])
        registered = verify_failure_domain(
            item["failure_domain"], "registered authority"
        )
        if (
            item.get("implementation_artifact_sha256")
            != registered["implementation_sha256"]
        ):
            raise ValueError("registered implementation artifact is detached")
        if item["authority_key_sha256"] == authority_key_sha256:
            matches.append((item, registered))
    if (
        len(matches) != 1
        or matches[0][0]["status"] != "active"
        or matches[0][1] != domain
    ):
        raise ValueError(f"{label} failure domain is not actively registered")
    return domain


def _verify_fresh_registry(document: dict[str, object]) -> dict[str, object]:
    if set(document) != {"schema_version", "signed", "signatures", "transparency"}:
        raise ValueError("fresh failure-domain registry fields are invalid")
    signed = document["signed"]
    signatures = document["signatures"]
    if (
        not isinstance(signed, dict)
        or set(signed) != {"generation", "issued_at", "expires_at", "authorities"}
        or not isinstance(signed.get("generation"), int)
        or signed["generation"] < 1
        or not isinstance(signed.get("authorities"), list)
        or not isinstance(signatures, list)
    ):
        raise ValueError("fresh failure-domain registry subject is invalid")
    minimum = _positive_environment("PYSEC_FAILURE_DOMAIN_REGISTRY_MIN_GENERATION", 1)
    if signed["generation"] < minimum:
        raise ValueError(
            "failure-domain registry generation is below the deployment floor"
        )
    issued = _timestamp(signed["issued_at"], "failure-domain registry issued_at")
    expires = _timestamp(signed["expires_at"], "failure-domain registry expires_at")
    now = datetime.now(UTC)
    if issued > now or expires <= now or expires <= issued:
        raise ValueError("failure-domain registry is expired or not yet valid")
    _verify_registry_signatures(signed, signatures)
    _verify_transparency(signed, document["transparency"])
    return {
        "schema_version": "1.0",
        "generation": signed["generation"],
        "authorities": signed["authorities"],
    }


def _verify_registry_signatures(
    signed: dict[str, object], signatures: list[object]
) -> None:
    raw_keys = os.environ.get(
        "PYSEC_FAILURE_DOMAIN_REGISTRY_ROOT_KEYS_JSON", ""
    ).strip()
    try:
        keys = strict_loads(raw_keys)
    except (TypeError, ValueError) as exc:
        raise ValueError("failure-domain registry root keys are invalid") from exc
    if not isinstance(keys, list) or not 2 <= len(keys) <= 16:
        raise ValueError("failure-domain registry root key quorum is unavailable")
    approved: dict[str, Ed25519PublicKey] = {}
    for item in keys:
        if (
            not isinstance(item, dict)
            or set(item) != {"key_sha256", "public_key_pem_base64"}
            or not _digest(str(item.get("key_sha256") or ""))
        ):
            raise ValueError("failure-domain registry root key is invalid")
        try:
            payload = base64.b64decode(
                str(item["public_key_pem_base64"]), validate=True
            )
            public = serialization.load_pem_public_key(payload)
        except (TypeError, ValueError) as exc:
            raise ValueError(
                "failure-domain registry root key encoding is invalid"
            ) from exc
        digest = hashlib.sha256(payload).hexdigest()
        if digest != item["key_sha256"] or not isinstance(public, Ed25519PublicKey):
            raise ValueError("failure-domain registry root key does not match its pin")
        if digest in approved:
            raise ValueError("failure-domain registry root keys are not unique")
        approved[digest] = public
    threshold = _positive_environment(
        "PYSEC_FAILURE_DOMAIN_REGISTRY_SIGNATURE_THRESHOLD", 2
    )
    if threshold > len(approved):
        raise ValueError("failure-domain registry signature threshold is unavailable")
    verified: set[str] = set()
    payload = canonical_bytes(signed)
    for item in signatures:
        if (
            not isinstance(item, dict)
            or set(item) != {"key_sha256", "signature_base64"}
            or item.get("key_sha256") not in approved
            or item["key_sha256"] in verified
        ):
            raise ValueError("failure-domain registry signature is invalid")
        try:
            signature = base64.b64decode(str(item["signature_base64"]), validate=True)
            approved[str(item["key_sha256"])].verify(signature, payload)
        except Exception as exc:
            raise ValueError("failure-domain registry signature is invalid") from exc
        verified.add(str(item["key_sha256"]))
    if len(verified) < threshold:
        raise ValueError("failure-domain registry signature threshold is not met")


def _verify_transparency(signed: dict[str, object], value: object) -> None:
    if (
        not isinstance(value, dict)
        or set(value)
        != {"log_id", "log_index", "tree_size", "audit_path", "root_sha256"}
        or not str(value.get("log_id") or "").strip()
        or isinstance(value.get("log_index"), bool)
        or not isinstance(value.get("log_index"), int)
        or isinstance(value.get("tree_size"), bool)
        or not isinstance(value.get("tree_size"), int)
        or value["log_index"] < 0
        or value["tree_size"] < 1
        or value["log_index"] >= value["tree_size"]
        or not isinstance(value.get("audit_path"), list)
        or any(not _digest(str(item)) for item in value["audit_path"])
        or len(value["audit_path"]) > 64
        or not _digest(str(value.get("root_sha256") or ""))
    ):
        raise ValueError("failure-domain registry transparency proof is invalid")
    expected = (
        os.environ.get("PYSEC_FAILURE_DOMAIN_LOG_ROOT_SHA256", "").strip().casefold()
    )
    if not _digest(expected) or value["root_sha256"] != expected:
        raise ValueError("failure-domain registry transparency root is not pinned")
    node = hashlib.sha256(b"\x00" + canonical_bytes(signed)).digest()
    index = int(value["log_index"])
    last = int(value["tree_size"]) - 1
    for raw in value["audit_path"]:
        if last == 0:
            raise ValueError("failure-domain registry transparency proof is too long")
        sibling = bytes.fromhex(str(raw))
        if index % 2 == 1 or index == last:
            node = hashlib.sha256(b"\x01" + sibling + node).digest()
            while index != 0 and index % 2 == 0:
                index //= 2
                last //= 2
        else:
            node = hashlib.sha256(b"\x01" + node + sibling).digest()
        index //= 2
        last //= 2
    if last != 0 or index != 0 or node.hex() != expected:
        raise ValueError("failure-domain registry transparency inclusion proof failed")


def _timestamp(value: object, label: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{label} is invalid") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{label} must include a timezone")
    return parsed.astimezone(UTC)


def _positive_environment(name: str, default: int) -> int:
    try:
        value = int(os.environ.get(name, str(default)).strip())
    except ValueError as exc:
        raise ValueError(f"{name} is invalid") from exc
    if value < 1:
        raise ValueError(f"{name} is invalid")
    return value


def _digest(value: str) -> bool:
    return len(value) == 64 and all(
        character in "0123456789abcdef" for character in value
    )
