from __future__ import annotations

import hashlib
import json
import re
from datetime import date, timedelta
from pathlib import Path
from typing import Any

from .models import Finding, FindingStatus, Severity
from .path_safety import read_regular_file
from .strict_json import loads as strict_loads
from .trusted_observation import governed_now


_MAX_FILE_BYTES = 1024 * 1024
_MAX_ACCEPTANCES = 1000
_FINGERPRINT = re.compile(r"sha256:[0-9a-f]{64}")
_DISPOSITIONS = {"accepted_risk", "false_positive", "approved_suppression"}
_PRODUCTION_PROFILES = frozenset({"production", "release"})
# UNKNOWN ranks with CRITICAL: an unrated finding cannot prove it stays in bounds.
_SEVERITY_RANK = {
    Severity.INFORMATIONAL: 1,
    Severity.LOW: 2,
    Severity.MEDIUM: 3,
    Severity.HIGH: 4,
    Severity.CRITICAL: 5,
    Severity.UNKNOWN: 5,
}
_MAX_SEVERITIES = {
    severity.value for severity in Severity if severity is not Severity.UNKNOWN
}


def apply_risk_acceptances(
    findings: list[Finding],
    path: Path | None,
    expected_sha256: str = "",
    *,
    today: date | None = None,
    profile: str = "standard",
) -> list[str]:
    """Apply bounded, expiring acceptances and return fail-closed policy errors."""
    if path is None:
        return []
    production = profile in _PRODUCTION_PROFILES
    current = today or governed_now().date()
    try:
        entries = _verified_entries(path, expected_sha256, production)
    except (OSError, TypeError, ValueError, UnicodeError, json.JSONDecodeError) as exc:
        return [f"risk-acceptance policy is invalid: {exc}"]

    errors: list[str] = []
    active: dict[str, dict[str, Any]] = {}
    for index, value in enumerate(entries, start=1):
        try:
            normalized = _normalize(value, current, production=production)
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
        matched.add(finding.fingerprint)
        rejection = _bound_rejection(finding, acceptance, production)
        if rejection:
            finding.evidence = {
                **finding.evidence,
                "risk_acceptance_rejected": rejection,
            }
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
    profile: str = "standard",
) -> list[str]:
    """Validate acceptance governance without requiring current findings."""
    if path is None:
        return []
    production = profile in _PRODUCTION_PROFILES
    current = today or governed_now().date()
    try:
        entries = _verified_entries(path, expected_sha256, production)
    except (OSError, TypeError, ValueError, UnicodeError, json.JSONDecodeError) as exc:
        return [f"risk-acceptance policy is invalid: {exc}"]
    errors: list[str] = []
    fingerprints: set[str] = set()
    for index, value in enumerate(entries, start=1):
        try:
            normalized = _normalize(value, current, production=production)
        except (TypeError, ValueError) as exc:
            errors.append(f"risk acceptance {index} is invalid: {exc}")
            continue
        fingerprint = normalized["fingerprint"]
        if fingerprint in fingerprints:
            errors.append(f"duplicate risk acceptance for {fingerprint}")
        fingerprints.add(fingerprint)
    return errors


def _verified_entries(
    path: Path, expected_sha256: str, production: bool
) -> list[object]:
    if production and not expected_sha256:
        raise ValueError(
            "production and release scans require an organization-approved "
            "risk_acceptance_sha256 for the risk-acceptance file"
        )
    document, digest = _load_document(path)
    if expected_sha256 and digest != expected_sha256:
        raise ValueError("risk-acceptance file SHA-256 does not match policy")
    return _entries(document)


def _bound_rejection(
    finding: Finding, acceptance: dict[str, Any], production: bool
) -> str:
    """Return why an exact-fingerprint acceptance cannot cover this finding."""
    intelligence = finding.evidence.get("risk_intelligence")
    if isinstance(intelligence, dict) and intelligence.get("known_exploited"):
        if production:
            return (
                "known-exploited findings cannot be suppressed in production or release"
            )
        if acceptance["known_exploited"] is not True:
            return (
                "finding is known-exploited and the acceptance does not "
                "acknowledge known_exploited status"
            )
    maximum = acceptance["max_severity"]
    if maximum and _SEVERITY_RANK[finding.severity] > _SEVERITY_RANK[Severity(maximum)]:
        return (
            f"finding severity {finding.severity.value} exceeds the accepted "
            f"max_severity {maximum}"
        )
    return ""


def _load_document(path: Path) -> tuple[dict[str, Any], str]:
    _, data = read_regular_file(
        path, "risk-acceptance file", maximum_bytes=_MAX_FILE_BYTES
    )
    value = strict_loads(data)
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


def _normalize(
    value: object, current: date, *, production: bool = False
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise TypeError("entry must be an object")
    allowed = {
        "fingerprint",
        "finding_id",
        "disposition",
        "owner",
        "rationale",
        "expires",
        "max_severity",
        "known_exploited",
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
    max_severity = _text(
        value.get("max_severity"), "max_severity", 20, required=production
    )
    if max_severity and max_severity not in _MAX_SEVERITIES:
        raise ValueError(f"unsupported max_severity: {max_severity!r}")
    known_exploited = value.get("known_exploited", False)
    if not isinstance(known_exploited, bool):
        raise TypeError("known_exploited must be a boolean")
    return {
        "fingerprint": fingerprint,
        "finding_id": finding_id,
        "disposition": disposition,
        "owner": owner,
        "rationale": rationale,
        "expires": expires_text,
        "max_severity": max_severity,
        "known_exploited": known_exploited,
    }


def _text(value: object, name: str, maximum: int, *, required: bool = True) -> str:
    text = " ".join(str(value or "").split())
    if required and not text:
        raise ValueError(f"{name} is required")
    if len(text) > maximum:
        raise ValueError(f"{name} exceeds {maximum} characters")
    return text
