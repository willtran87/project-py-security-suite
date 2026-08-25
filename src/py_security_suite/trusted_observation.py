from __future__ import annotations

import hashlib
import os
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path

from .path_safety import read_regular_file
from .strict_json import loads as strict_loads
from .trusted_time import verify_rfc3161


def scan_observed_at(environment: Mapping[str, str] | None = None) -> datetime:
    """Return the deployment-pinned RFC 3161 time for governed decisions."""

    values = os.environ if environment is None else environment
    raw_path = values.get("PYSEC_SCAN_TIME_CONTEXT_PATH", "").strip()
    expected = values.get("PYSEC_SCAN_TIME_CONTEXT_SHA256", "").strip().casefold()
    challenge = values.get("PYSEC_SCAN_TIME_CHALLENGE_SHA256", "").strip().casefold()
    if not raw_path or not _digest(expected) or not _digest(challenge):
        raise ValueError("governed scan trusted-time configuration is incomplete")
    path = Path(raw_path).expanduser().resolve()
    _, payload = read_regular_file(
        path, "governed scan trusted-time context", maximum_bytes=8 * 1024 * 1024
    )
    if hashlib.sha256(payload).hexdigest() != expected:
        raise ValueError("governed scan trusted-time context SHA-256 does not match")
    value = strict_loads(payload)
    if (
        not isinstance(value, dict)
        or set(value) != {"schema_version", "challenge_sha256", "trusted_time"}
        or value.get("schema_version") != "1.0"
        or value.get("challenge_sha256") != challenge
    ):
        raise ValueError("governed scan trusted-time context fields do not match")
    receipt = verify_rfc3161(
        path, value["trusted_time"], challenge, require_advanced=True
    )
    observed = datetime.fromisoformat(
        receipt["trusted_time_observed_at"].replace("Z", "+00:00")
    )
    if observed.tzinfo is None:
        raise ValueError("governed scan trusted time must include a timezone")
    return observed.astimezone(UTC)


def scan_time_identity(environment: Mapping[str, str] | None = None) -> str:
    """Commit the configured time context without exposing its path."""

    values = os.environ if environment is None else environment
    expected = values.get("PYSEC_SCAN_TIME_CONTEXT_SHA256", "").strip().casefold()
    challenge = values.get("PYSEC_SCAN_TIME_CHALLENGE_SHA256", "").strip().casefold()
    if not _digest(expected) or not _digest(challenge):
        raise ValueError("governed scan trusted-time identity is incomplete")
    return hashlib.sha256(f"{expected}:{challenge}".encode()).hexdigest()


def governed_now(environment: Mapping[str, str] | None = None) -> datetime:
    """Use trusted scan time whenever a governed or configured decision is made."""

    values = os.environ if environment is None else environment
    configured = any(
        values.get(name, "").strip()
        for name in (
            "PYSEC_SCAN_TIME_CONTEXT_PATH",
            "PYSEC_SCAN_TIME_CONTEXT_SHA256",
            "PYSEC_SCAN_TIME_CHALLENGE_SHA256",
        )
    )
    hardened = values.get("PYSEC_REQUIRE_HARDENED_RELEASE_EVIDENCE", "").strip() == "1"
    if configured or hardened:
        return scan_observed_at(values)
    return datetime.now(UTC)


def _digest(value: str) -> bool:
    return len(value) == 64 and all(
        character in "0123456789abcdef" for character in value
    )
