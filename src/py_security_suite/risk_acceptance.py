from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Any

from .models import Finding, FindingStatus
from .path_safety import resolve_regular_file


_MAX_FILE_BYTES = 1024 * 1024
_MAX_ACCEPTANCES = 1000
_FINGERPRINT = re.compile(r"sha256:[0-9a-f]{64}")
_DISPOSITIONS = {"accepted_risk", "false_positive", "approved_suppression"}


def apply_risk_acceptances(
    findings: list[Finding],
    path: Path | None,
    expected_sha256: str = "",
    *,
    today: date | None = None,
) -> list[str]:
    """Apply bounded, expiring acceptances and return fail-closed policy errors."""
    if path is None:
        return []
    current = today or datetime.now(UTC).date()
    try:
        document, digest = _load_document(path)
        if expected_sha256 and digest != expected_sha256:
            raise ValueError("risk-acceptance file SHA-256 does not match policy")
        entries = _entries(document)
    except (OSError, TypeError, ValueError, UnicodeError, json.JSONDecodeError) as exc:
        return [f"risk-acceptance policy is invalid: {exc}"]

    errors: list[str] = []
    active: dict[str, dict[str, str]] = {}
    for index, value in enumerate(entries, start=1):
        try:
            normalized = _normalize(value, current)
        except (TypeError, ValueError) as exc:
            errors.append(f"risk acceptance {index} is invalid: {exc}")
            continue
        fingerprint = normalized["fingerprint"]
        if fingerprint in active:
            errors.append(f"duplicate risk acceptance for {fingerprint}")
            continue
        active[fingerprint] = normalized

    matched: set[str] = set()
    for finding in findings:
        acceptance = active.get(finding.fingerprint)
        if acceptance is None:
            continue
        expected_id = acceptance["finding_id"]
        if expected_id and expected_id != finding.finding_id:
            errors.append(
                f"risk acceptance fingerprint matched {finding.finding_id} but "
                f"declared finding_id {expected_id}"
            )
            continue
        finding.status = FindingStatus.SUPPRESSED
        finding.blocking = False
        finding.evidence = {
            **finding.evidence,
            "risk_acceptance": {
                "disposition": acceptance["disposition"],
                "owner": acceptance["owner"],
                "rationale": acceptance["rationale"],
                "expires": acceptance["expires"],
            },
        }
        matched.add(finding.fingerprint)

    errors.extend(
        (
            f"risk acceptance {fingerprint} does not match a current finding; "
            "remove or update the stale acceptance"
        )
        for fingerprint in sorted(set(active) - matched)
    )
    return errors


def validate_risk_acceptances(
    path: Path | None,
    expected_sha256: str = "",
    *,
    today: date | None = None,
) -> list[str]:
    """Validate acceptance governance without requiring current findings."""
    if path is None:
        return []
    current = today or datetime.now(UTC).date()
    try:
        document, digest = _load_document(path)
        if expected_sha256 and digest != expected_sha256:
            raise ValueError("risk-acceptance file SHA-256 does not match policy")
        entries = _entries(document)
    except (OSError, TypeError, ValueError, UnicodeError, json.JSONDecodeError) as exc:
        return [f"risk-acceptance policy is invalid: {exc}"]
    errors: list[str] = []
    fingerprints: set[str] = set()
    for index, value in enumerate(entries, start=1):
        try:
            normalized = _normalize(value, current)
        except (TypeError, ValueError) as exc:
            errors.append(f"risk acceptance {index} is invalid: {exc}")
            continue
        fingerprint = normalized["fingerprint"]
        if fingerprint in fingerprints:
            errors.append(f"duplicate risk acceptance for {fingerprint}")
        fingerprints.add(fingerprint)
    return errors


def _load_document(path: Path) -> tuple[dict[str, Any], str]:
    resolved = resolve_regular_file(path, "risk-acceptance file")
    data = resolved.read_bytes()
    if len(data) > _MAX_FILE_BYTES:
        raise ValueError("risk-acceptance file exceeds 1 MiB")
    value = json.loads(data.decode("utf-8"))
    if not isinstance(value, dict):
        raise TypeError("risk-acceptance root must be an object")
    return value, hashlib.sha256(data).hexdigest()


def _entries(document: dict[str, Any]) -> list[object]:
    if document.get("schema_version") != "1.0":
        raise ValueError("risk-acceptance schema_version must be '1.0'")
    values = document.get("acceptances")
    if not isinstance(values, list):
        raise TypeError("risk-acceptance acceptances must be a list")
    if len(values) > _MAX_ACCEPTANCES:
        raise ValueError(f"risk-acceptance file exceeds {_MAX_ACCEPTANCES} entries")
    return values


def _normalize(value: object, current: date) -> dict[str, str]:
    if not isinstance(value, dict):
        raise TypeError("entry must be an object")
    allowed = {
        "fingerprint",
        "finding_id",
        "disposition",
        "owner",
        "rationale",
        "expires",
    }
    unknown = set(value) - allowed
    if unknown:
        raise ValueError(f"unknown fields: {sorted(unknown)}")
    fingerprint = _text(value.get("fingerprint"), "fingerprint", 80)
    if _FINGERPRINT.fullmatch(fingerprint) is None:
        raise ValueError("fingerprint must be a lowercase sha256 value")
    finding_id = _text(value.get("finding_id"), "finding_id", 80, required=False)
    disposition = _text(value.get("disposition"), "disposition", 40)
    if disposition not in _DISPOSITIONS:
        raise ValueError(f"unsupported disposition: {disposition!r}")
    owner = _text(value.get("owner"), "owner", 200)
    rationale = _text(value.get("rationale"), "rationale", 2000)
    expires_text = _text(value.get("expires"), "expires", 10)
    try:
        expires = date.fromisoformat(expires_text)
    except ValueError as exc:
        raise ValueError("expires must be an ISO date") from exc
    if expires < current:
        raise ValueError(f"acceptance expired on {expires_text}")
    if expires > current + timedelta(days=366):
        raise ValueError("acceptance expiry cannot be more than 366 days away")
    return {
        "fingerprint": fingerprint,
        "finding_id": finding_id,
        "disposition": disposition,
        "owner": owner,
        "rationale": rationale,
        "expires": expires_text,
    }


def _text(value: object, name: str, maximum: int, *, required: bool = True) -> str:
    text = " ".join(str(value or "").split())
    if required and not text:
        raise ValueError(f"{name} is required")
    if len(text) > maximum:
        raise ValueError(f"{name} exceeds {maximum} characters")
    return text
