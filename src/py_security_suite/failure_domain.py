from __future__ import annotations

import base64
import hashlib
import os
import sqlite3
import threading
from datetime import UTC, datetime
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .path_safety import read_regular_file
from .strict_json import canonical_bytes, loads as strict_loads
from .trusted_observation import governed_now

_REGISTRY_ANCHOR = threading.local()

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
    for item, registered in _registry_authorities(document["authorities"]):
        if item["authority_key_sha256"] == authority_key_sha256:
            matches.append((item, registered))
    if (
        len(matches) != 1
        or matches[0][0]["status"] != "active"
        or matches[0][1] != domain
    ):
        raise ValueError(f"{label} failure domain is not actively registered")
    return domain


def _registry_authorities(
    authorities: object,
) -> list[tuple[dict[str, object], dict[str, str]]]:
    if not isinstance(authorities, list):
        raise ValueError("failure-domain registry authorities are invalid")
    records: list[tuple[dict[str, object], dict[str, str]]] = []
    seen: set[str] = set()
    for item in authorities:
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
        records.append((item, registered))
    return records


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
    now = governed_now()
    if issued > now or expires <= now or expires <= issued:
        raise ValueError("failure-domain registry is expired or not yet valid")
    registry_signers = _verify_registry_signatures(signed, signatures)
    _registry_authorities(signed["authorities"])
    _verify_transparency(signed, document["transparency"], registry_signers)
    return {
        "schema_version": "1.0",
        "generation": signed["generation"],
        "authorities": signed["authorities"],
    }


def _verify_registry_signatures(
    signed: dict[str, object], signatures: list[object]
) -> set[str]:
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
    return verified


def _verify_transparency(
    signed: dict[str, object], value: object, registry_signers: set[str]
) -> None:
    if (
        not isinstance(value, dict)
        or set(value)
        != {
            "log_id",
            "log_index",
            "tree_size",
            "audit_path",
            "root_sha256",
            "checkpoint",
            "consistency_path",
        }
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
        or not _proof(value.get("consistency_path"))
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
    checkpoint = value["checkpoint"]
    if not isinstance(checkpoint, dict) or set(checkpoint) != {
        "signed",
        "signatures",
    }:
        raise ValueError("failure-domain registry log checkpoint is invalid")
    checkpoint_subject = checkpoint["signed"]
    if (
        not isinstance(checkpoint_subject, dict)
        or set(checkpoint_subject)
        != {
            "schema_version",
            "log_id",
            "tree_size",
            "root_sha256",
            "generation",
            "previous_tree_size",
            "previous_root_sha256",
        }
        or checkpoint_subject.get("schema_version") != "1.0"
        or checkpoint_subject.get("log_id") != value["log_id"]
        or checkpoint_subject.get("tree_size") != value["tree_size"]
        or checkpoint_subject.get("root_sha256") != expected
        or checkpoint_subject.get("generation") != signed["generation"]
    ):
        raise ValueError("failure-domain registry log checkpoint is detached")
    _verify_log_witnesses(
        checkpoint_subject, checkpoint["signatures"], registry_signers
    )
    state_path = os.environ.get("PYSEC_FAILURE_DOMAIN_REGISTRY_STATE_PATH", "").strip()
    if not state_path:
        raise ValueError("failure-domain registry durable checkpoint state is required")
    state = _checkpoint_state(Path(state_path), str(value["log_id"]))
    current = (
        int(value["tree_size"]),
        expected,
        int(str(signed["generation"])),
    )
    if state == current:
        return
    previous_size, previous_root, previous_generation = state
    if (
        checkpoint_subject["previous_tree_size"] != previous_size
        or checkpoint_subject["previous_root_sha256"] != previous_root
        or current[2] <= previous_generation
        or not _verify_consistency(
            previous_size,
            current[0],
            previous_root,
            current[1],
            [str(item) for item in value["consistency_path"]],
        )
    ):
        raise ValueError("failure-domain registry checkpoint consistency failed")
    if getattr(_REGISTRY_ANCHOR, "active", False):
        # A checkpoint authority's own hardware identity is verified against this
        # registry.  Reentrant verification must validate the same transition but
        # leave publication and mutation to the outer transaction.
        return
    required_anchor = (
        os.environ.get(
            "PYSEC_REQUIRE_EXTERNAL_FAILURE_DOMAIN_STATE_CHECKPOINT", ""
        ).strip()
        == "1"
        or os.environ.get("PYSEC_REQUIRE_HARDENED_RELEASE_EVIDENCE", "").strip() == "1"
    )
    from .checkpoint_authority import publish_checkpoint

    _REGISTRY_ANCHOR.active = True
    try:
        publish_checkpoint(
            "PYSEC_FAILURE_DOMAIN_STATE_CHECKPOINT",
            {
                "schema_version": "1.0",
                "namespace": "failure-domain-registry",
                "log_id": str(value["log_id"]),
                "previous": {
                    "tree_size": previous_size,
                    "root_sha256": previous_root,
                    "generation": previous_generation,
                },
                "proposed": {
                    "tree_size": current[0],
                    "root_sha256": current[1],
                    "generation": current[2],
                },
            },
            required=required_anchor,
        )
    finally:
        _REGISTRY_ANCHOR.active = False
    _advance_checkpoint_state(
        Path(state_path),
        str(value["log_id"]),
        expected=state,
        current=current,
    )


def _verify_log_witnesses(
    subject: dict[str, object], signatures: object, registry_signers: set[str]
) -> None:
    raw_keys = os.environ.get("PYSEC_FAILURE_DOMAIN_LOG_WITNESS_KEYS_JSON", "").strip()
    try:
        records = strict_loads(raw_keys)
    except (TypeError, ValueError) as exc:
        raise ValueError("failure-domain log witness keys are invalid") from exc
    if not isinstance(records, list) or not 2 <= len(records) <= 16:
        raise ValueError("failure-domain log witness quorum is unavailable")
    keys: dict[str, Ed25519PublicKey] = {}
    for item in records:
        if not isinstance(item, dict) or set(item) != {
            "key_sha256",
            "public_key_pem_base64",
        }:
            raise ValueError("failure-domain log witness key is invalid")
        try:
            public_bytes = base64.b64decode(
                str(item["public_key_pem_base64"]), validate=True
            )
            public = serialization.load_pem_public_key(public_bytes)
        except (TypeError, ValueError) as exc:
            raise ValueError("failure-domain log witness key is invalid") from exc
        digest = hashlib.sha256(public_bytes).hexdigest()
        if (
            digest != item.get("key_sha256")
            or digest in keys
            or digest in registry_signers
            or not isinstance(public, Ed25519PublicKey)
        ):
            raise ValueError("failure-domain log witness independence is invalid")
        keys[digest] = public
    threshold = _positive_environment("PYSEC_FAILURE_DOMAIN_LOG_WITNESS_THRESHOLD", 2)
    if threshold > len(keys) or not isinstance(signatures, list):
        raise ValueError("failure-domain log witness threshold is unavailable")
    verified: set[str] = set()
    payload = canonical_bytes(subject)
    for item in signatures:
        if (
            not isinstance(item, dict)
            or set(item) != {"key_sha256", "signature_base64"}
            or item.get("key_sha256") not in keys
            or item["key_sha256"] in verified
        ):
            raise ValueError("failure-domain log witness signature is invalid")
        try:
            signature = base64.b64decode(str(item["signature_base64"]), validate=True)
            keys[str(item["key_sha256"])].verify(signature, payload)
        except Exception as exc:
            raise ValueError("failure-domain log witness signature is invalid") from exc
        verified.add(str(item["key_sha256"]))
    if len(verified) < threshold:
        raise ValueError("failure-domain log witness threshold is not met")


def _checkpoint_state(path: Path, log_id: str) -> tuple[int, str, int]:
    if path.is_symlink():
        raise ValueError("failure-domain registry state must not be a symbolic link")
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path, timeout=30, isolation_level=None)
    try:
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute(
            "CREATE TABLE IF NOT EXISTS checkpoint "
            "(log_id TEXT PRIMARY KEY, size INTEGER NOT NULL, root TEXT NOT NULL, "
            "generation INTEGER NOT NULL)"
        )
        row = connection.execute(
            "SELECT size, root, generation FROM checkpoint WHERE log_id=?", (log_id,)
        ).fetchone()
        return (0, "", 0) if row is None else (int(row[0]), str(row[1]), int(row[2]))
    finally:
        connection.close()


def _advance_checkpoint_state(
    path: Path,
    log_id: str,
    *,
    expected: tuple[int, str, int],
    current: tuple[int, str, int],
) -> None:
    connection = sqlite3.connect(path, timeout=30, isolation_level=None)
    try:
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("BEGIN IMMEDIATE")
        row = connection.execute(
            "SELECT size, root, generation FROM checkpoint WHERE log_id=?", (log_id,)
        ).fetchone()
        observed = (
            (0, "", 0) if row is None else (int(row[0]), str(row[1]), int(row[2]))
        )
        if observed != expected:
            connection.execute("ROLLBACK")
            raise ValueError("failure-domain registry state advanced concurrently")
        connection.execute(
            "INSERT INTO checkpoint(log_id, size, root, generation) VALUES (?, ?, ?, ?) "
            "ON CONFLICT(log_id) DO UPDATE SET size=excluded.size, "
            "root=excluded.root, generation=excluded.generation",
            (log_id, *current),
        )
        connection.execute("COMMIT")
    finally:
        connection.close()
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def _verify_consistency(
    old_size: int, new_size: int, old_root: str, new_root: str, proof: list[str]
) -> bool:
    if old_size == 0:
        return not proof
    if old_size == new_size:
        return old_root == new_root and not proof
    if not 0 < old_size < new_size or not proof:
        return False
    first, *remaining = [bytes.fromhex(item) for item in proof]
    old_index, new_index = old_size - 1, new_size - 1
    while old_index & 1:
        old_index >>= 1
        new_index >>= 1
    if old_index == 0:
        old_hash = new_hash = bytes.fromhex(old_root)
        remaining = [first, *remaining]
    else:
        old_hash = new_hash = first
    for sibling in remaining:
        if new_index == 0:
            return False
        if old_index & 1 or old_index == new_index:
            old_hash = hashlib.sha256(b"\x01" + sibling + old_hash).digest()
            new_hash = hashlib.sha256(b"\x01" + sibling + new_hash).digest()
            while old_index and not old_index & 1:
                old_index >>= 1
                new_index >>= 1
        elif old_index < new_index:
            new_hash = hashlib.sha256(b"\x01" + new_hash + sibling).digest()
        old_index >>= 1
        new_index >>= 1
    return new_index == 0 and old_hash.hex() == old_root and new_hash.hex() == new_root


def _proof(value: object) -> bool:
    return (
        isinstance(value, list)
        and len(value) <= 256
        and all(isinstance(item, str) and _digest(item) for item in value)
    )


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
