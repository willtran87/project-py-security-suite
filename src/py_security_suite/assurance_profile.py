from __future__ import annotations

import hashlib
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from .governance_quorum import (
    verify_authority_quorum,
    verify_governance_quorum as verify_governance_quorum,
)
from .strict_json import canonical_bytes, loads as strict_loads
from .trusted_observation import governed_now
from .trusted_time import verify_rfc3161


def load_assurance_profile(
    path: Path,
    *,
    at: datetime | None = None,
    require_checkpoint: bool = False,
) -> dict[str, Any]:
    """Verify a threshold-signed admission profile outside the evidence bundle."""
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 1024 * 1024:
        raise ValueError("assurance profile must be a bounded regular file")
    raw = path.read_bytes()
    value = strict_loads(raw)
    core = {
        "schema_version",
        "profile_id",
        "generation",
        "issued_at",
        "expires_at",
        "minimum_contract_versions",
        "required_features",
        "minimum_slsa_level",
        "required_provenance_verifiers",
        "minimum_authority_signatures",
        "checkpoint_backend",
    }
    if not isinstance(value, dict):
        raise ValueError("assurance profile fields do not match the v1 contract")
    version = value.get("schema_version")
    required = core | {"authorities"}
    if version == "2.0":
        required |= {"checkpoint", "trusted_time"}
    if version not in {"1.0", "2.0"} or set(value) != required:
        raise ValueError("assurance profile fields do not match a supported contract")
    if require_checkpoint and version != "2.0":
        raise ValueError("trusted admission requires a checkpointed profile v2")
    generation = _integer(value.get("generation"), "generation")
    if generation < _environment_integer("PYSEC_ASSURANCE_PROFILE_MIN_GENERATION", 1):
        raise ValueError("assurance profile generation is below deployment policy")
    issued_at = _timestamp(value.get("issued_at"), "issued_at")
    expires_at = _timestamp(value.get("expires_at"), "expires_at")
    policy_subject = {name: value[name] for name in core}
    policy_sha256 = hashlib.sha256(canonical_bytes(policy_subject)).hexdigest()
    trusted_time: dict[str, str] | None = None
    if version == "2.0":
        trusted_time = verify_rfc3161(path, value.get("trusted_time"), policy_sha256)
        observed_at = _timestamp(
            trusted_time["trusted_time_observed_at"], "trusted_time observed_at"
        )
    else:
        observed_at = (at or governed_now()).astimezone(UTC)
    if (
        issued_at > observed_at + timedelta(minutes=5)
        or expires_at <= observed_at
        or expires_at <= issued_at
        or expires_at - issued_at > timedelta(days=366)
    ):
        raise ValueError("assurance profile validity window is invalid")
    versions = _versions(value.get("minimum_contract_versions"))
    features = _features(value.get("required_features"), versions)
    slsa_level = _integer(value.get("minimum_slsa_level"), "minimum_slsa_level")
    if slsa_level not in {1, 2, 3}:
        raise ValueError("assurance profile SLSA level is invalid")
    verifiers = value.get("required_provenance_verifiers")
    allowed_verifiers = {"slsa", "sigstore", "vsa", "dependency-closure"}
    if (
        not isinstance(verifiers, list)
        or len(verifiers) != len(set(verifiers))
        or not set(verifiers).issubset(allowed_verifiers)
        or not (
            ({"slsa", "sigstore", "vsa", "dependency-closure"}.issubset(verifiers))
            if version == "2.0"
            else {"slsa", "sigstore"}.issubset(verifiers)
        )
    ):
        raise ValueError("assurance profile provenance verifiers are invalid")
    threshold = _integer(
        value.get("minimum_authority_signatures"), "minimum_authority_signatures"
    )
    deployment_threshold = _environment_integer(
        "PYSEC_ASSURANCE_PROFILE_SIGNATURE_THRESHOLD", 2
    )
    if not 2 <= threshold <= 16 or threshold < deployment_threshold:
        raise ValueError(
            "assurance profile authority threshold is below deployment policy"
        )
    if value.get("checkpoint_backend") not in {
        "https-cas-transparency",
        "rfc6962-transparency-log",
    }:
        raise ValueError("assurance profile requires a remote append-only checkpoint")
    checkpoint: dict[str, Any] | None = None
    checkpoint_verified: list[tuple[str, str, str, str]] = []
    if version == "2.0":
        checkpoint, checkpoint_verified = _verify_checkpoint(
            path,
            value.get("checkpoint"),
            policy_sha256=policy_sha256,
            generation=generation,
            backend=str(value["checkpoint_backend"]),
            threshold=threshold,
            observed_at=observed_at,
        )
    subject = policy_subject
    verified = verify_authority_quorum(
        path,
        value.get("authorities"),
        subject,
        threshold,
        observed_at,
        purpose="assurance-profile",
        require_organizations=version == "2.0",
    )
    return {
        **subject,
        "profile_id": _label(value.get("profile_id"), "profile_id"),
        "generation": generation,
        "issued_at": issued_at.isoformat(),
        "expires_at": expires_at.isoformat(),
        "minimum_contract_versions": versions,
        "required_features": features,
        "required_provenance_verifiers": sorted(verifiers),
        "profile_sha256": hashlib.sha256(raw).hexdigest(),
        "profile_subject_sha256": policy_sha256,
        "authority_signers": sorted(item[0] for item in verified),
        "authority_signer_refs": sorted(f"{item[3]}:{item[0]}" for item in verified),
        "authority_collectors": sorted(item[1] for item in verified),
        "authority_organizations": sorted({item[2] for item in verified}),
        "checkpoint": checkpoint,
        "checkpoint_signers": sorted(item[0] for item in checkpoint_verified),
        "trusted_time": trusted_time,
    }


def enforce_assurance_profile(
    profile: dict[str, Any], document: dict[str, Any], *, kind: str
) -> dict[str, Any]:
    minimum = profile["minimum_contract_versions"].get(kind)
    if minimum is None:
        raise ValueError(f"assurance profile does not authorize evidence kind {kind!r}")
    observed = str(document.get("schema_version") or "")
    if _version(observed) < _version(minimum):
        raise ValueError(
            f"{kind} contract {observed!r} is below profile minimum {minimum!r}"
        )
    execution = document.get("execution")
    observed_features = (
        set(execution.get("features", [])) if isinstance(execution, dict) else set()
    )
    missing = sorted(
        set(profile["required_features"].get(kind, [])) - observed_features
    )
    if missing:
        raise ValueError(
            f"{kind} evidence is missing required features: {', '.join(missing)}"
        )
    provenance = document.get("provenance")
    if not isinstance(provenance, dict):
        raise ValueError("profile-governed evidence requires provenance")
    if _integer(provenance.get("slsa_level"), "slsa_level") < int(
        profile["minimum_slsa_level"]
    ):
        raise ValueError("evidence SLSA level is below the assurance profile")
    verified_by = provenance.get("verified_by")
    if not isinstance(verified_by, list) or len(verified_by) != len(set(verified_by)):
        raise ValueError("evidence provenance verifier receipt is invalid")
    missing_verifiers = sorted(
        set(profile["required_provenance_verifiers"]) - set(verified_by)
    )
    if missing_verifiers:
        raise ValueError(
            "evidence provenance is missing required verification: "
            + ", ".join(missing_verifiers)
        )
    return {
        "profile_id": str(profile["profile_id"]),
        "profile_generation": int(profile["generation"]),
        "profile_authority_signers": list(profile["authority_signers"]),
        "profile_authority_signer_refs": list(profile["authority_signer_refs"]),
        "profile_authority_organizations": list(profile["authority_organizations"]),
        "profile_checkpoint_backend": str(profile["checkpoint_backend"]),
        "profile_sha256": str(profile["profile_sha256"]),
        "profile_subject_sha256": str(profile["profile_subject_sha256"]),
        "profile_checkpoint_sequence": (
            int(profile["checkpoint"]["sequence"]) if profile["checkpoint"] else 0
        ),
        "profile_trusted_time_sha256": (
            str(profile["trusted_time"]["trusted_time_sha256"])
            if profile["trusted_time"]
            else ""
        ),
    }


def _verify_checkpoint(
    context: Path,
    value: object,
    *,
    policy_sha256: str,
    generation: int,
    backend: str,
    threshold: int,
    observed_at: datetime,
) -> tuple[dict[str, Any], list[tuple[str, str, str, str]]]:
    required = {
        "schema_version",
        "backend",
        "sequence",
        "generation",
        "profile_subject_sha256",
        "previous_checkpoint_sha256",
        "authorities",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise ValueError("assurance profile checkpoint fields do not match")
    sequence = _integer(value.get("sequence"), "checkpoint sequence")
    minimum_sequence = _environment_integer(
        "PYSEC_ASSURANCE_PROFILE_MIN_CHECKPOINT_SEQUENCE", 1
    )
    previous = str(value.get("previous_checkpoint_sha256") or "")
    if (
        value.get("schema_version") != "1.0"
        or value.get("backend") != backend
        or _integer(value.get("generation"), "checkpoint generation") != generation
        or value.get("profile_subject_sha256") != policy_sha256
        or sequence < minimum_sequence
        or (previous != "0" * 64 and not _digest(previous))
    ):
        raise ValueError("assurance profile checkpoint is stale or detached")
    subject = {name: value[name] for name in required - {"authorities"}}
    verified = verify_authority_quorum(
        context,
        value.get("authorities"),
        subject,
        threshold,
        observed_at,
        purpose="assurance-profile-checkpoint",
        require_organizations=True,
    )
    return {
        **subject,
        "checkpoint_sha256": hashlib.sha256(canonical_bytes(subject)).hexdigest(),
    }, verified


def _versions(value: object) -> dict[str, str]:
    if not isinstance(value, dict) or not 1 <= len(value) <= 128:
        raise ValueError("assurance profile minimum versions are invalid")
    result = {
        _label(key, "evidence kind"): str(version) for key, version in value.items()
    }
    for version in result.values():
        _version(version)
    return result


def _features(value: object, versions: dict[str, str]) -> dict[str, list[str]]:
    if not isinstance(value, dict) or set(value) != set(versions):
        raise ValueError(
            "assurance profile feature policy must cover every evidence kind"
        )
    result: dict[str, list[str]] = {}
    for kind, features in value.items():
        if (
            not isinstance(features, list)
            or len(features) > 128
            or len(features) != len(set(features))
        ):
            raise ValueError("assurance profile required features are invalid")
        result[str(kind)] = [_label(item, "required feature") for item in features]
    return result


def _version(value: str) -> tuple[int, int]:
    parts = value.split(".")
    if len(parts) != 2 or any(not part.isdigit() for part in parts):
        raise ValueError("assurance contract version must use MAJOR.MINOR")
    return int(parts[0]), int(parts[1])


def _integer(value: object, label: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, str))
        or not str(value).isdigit()
        or int(value) < 1
    ):
        raise ValueError(f"{label} must be a positive integer")
    return int(value)


def _environment_integer(name: str, default: int) -> int:
    return _integer(os.environ.get(name, str(default)), name)


def _timestamp(value: object, label: str) -> datetime:
    try:
        result = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"assurance profile {label} is invalid") from exc
    if result.tzinfo is None:
        raise ValueError(f"assurance profile {label} requires a timezone")
    return result.astimezone(UTC)


def _label(value: object, label: str) -> str:
    result = str(value or "").strip()
    if (
        not result
        or len(result) > 200
        or any(ord(character) < 32 for character in result)
        or not all(character.isalnum() or character in "._:/@-" for character in result)
    ):
        raise ValueError(f"assurance profile {label} is invalid")
    return result


def _digest(value: str) -> bool:
    return len(value) == 64 and all(
        character in "0123456789abcdef" for character in value
    )
