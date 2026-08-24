from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from pathlib import Path

try:
    from companion.file_safety import read_bounded_regular
    from companion.strict_json import canonical_bytes
    from companion.strict_json import loads as strict_loads
    from companion.trusted_time import verify_rfc3161
except ModuleNotFoundError:  # Direct script execution.
    from file_safety import read_bounded_regular  # type: ignore[import-not-found,no-redef]
    from strict_json import canonical_bytes  # type: ignore[import-not-found,no-redef]
    from strict_json import loads as strict_loads  # type: ignore[import-not-found,no-redef]
    from trusted_time import verify_rfc3161  # type: ignore[import-not-found,no-redef]

try:
    from py_security_suite.trusted_observation import governed_now
except ModuleNotFoundError:  # Direct script execution with the suite on PYTHONPATH.
    from trusted_observation import governed_now  # type: ignore[import-not-found,no-redef]


_DIGEST_FIELDS = (
    "target_manifest_sha256",
    "exercised_targets_sha256",
    "deployment_sha256",
    "surface_sha256",
    "challenge_sha256",
)


def load_context(path: Path, exercised_target_ids: list[str]) -> dict[str, str]:
    """Load an organization-issued run context and bind it to exercised targets."""

    value = strict_loads(read_bounded_regular(path, 1024 * 1024, "assurance context"))
    required = {"schema_version", "run_id", *_DIGEST_FIELDS, "trusted_time"}
    if not isinstance(value, dict) or set(value) != required:
        raise ValueError("assurance context fields do not match the v1 contract")
    if value.get("schema_version") != "1.0":
        raise ValueError("assurance context schema_version must be '1.0'")
    run_id = _identifier(value.get("run_id"), "run_id", 100)
    context = {name: _digest(value.get(name), name) for name in _DIGEST_FIELDS}
    actual_targets = target_set_sha256(exercised_target_ids)
    if actual_targets != context["exercised_targets_sha256"]:
        raise ValueError("assurance context does not match the exercised target set")
    trusted = verify_rfc3161(
        path, value.get("trusted_time"), context["challenge_sha256"]
    )
    observed_at = datetime.fromisoformat(
        trusted["trusted_time_observed_at"].replace("Z", "+00:00")
    ).astimezone(UTC)
    if abs(governed_now() - observed_at) > timedelta(hours=24):
        raise ValueError("trusted time is outside the accepted window")
    return {
        "run_id": run_id,
        **context,
        **trusted,
    }


def target_set_sha256(target_ids: list[str]) -> str:
    if not target_ids or len(target_ids) > 10_000:
        raise ValueError("exercised target IDs must contain 1 to 10000 entries")
    normalized = sorted({_identifier(value, "target ID", 200) for value in target_ids})
    if len(normalized) != len(target_ids):
        raise ValueError("exercised target IDs must be unique")
    return hashlib.sha256(canonical_bytes(normalized)).hexdigest()


def load_target_ids(path: Path) -> list[str]:
    value = strict_loads(read_bounded_regular(path, 1024 * 1024, "exercised targets"))
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError("exercised targets must be a JSON array of opaque IDs")
    target_set_sha256(value)
    return value


def _digest(value: object, label: str) -> str:
    result = str(value or "")
    if len(result) != 64 or any(
        character not in "0123456789abcdef" for character in result
    ):
        raise ValueError(f"{label} must be a lowercase SHA-256 digest")
    return result


def _identifier(value: object, label: str, maximum: int) -> str:
    result = str(value or "").strip()
    if (
        not result
        or len(result) > maximum
        or not all(character.isalnum() or character in "._:-/@" for character in result)
    ):
        raise ValueError(f"{label} is invalid")
    return result
