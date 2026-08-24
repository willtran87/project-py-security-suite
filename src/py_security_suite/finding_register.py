from __future__ import annotations


from .strict_json import loads as strict_json_loads
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .execution import sha256_file
from .passport import verify_report
from .path_safety import resolve_regular_file

_MAX_JSON_BYTES = 128 * 1024 * 1024
_SLA_DAYS = {
    "critical": 1,
    "high": 7,
    "medium": 30,
    "low": 90,
    "informational": 180,
    "info": 180,
    "unknown": 30,
}


def build_finding_register(
    report: Path,
    *,
    previous: Path | None = None,
    previous_sha256: str = "",
) -> dict[str, Any]:
    """Build durable finding lifecycle state from sealed reports."""
    if bool(previous) != bool(previous_sha256):
        raise ValueError("previous register path and SHA-256 must be supplied together")
    verification = verify_report(report)
    root = report.expanduser().resolve()
    manifest = _read(root / "scan-manifest.json", "finding register input")
    findings_document = _read(root / "findings.json", "finding register input")
    observed = _timestamp(
        str(manifest.get("finished_at") or manifest.get("started_at") or "")
    )
    findings = _objects(findings_document.get("findings"), "findings")
    current = {
        _identity(value): value
        for value in findings
        if value.get("status") != "suppressed"
    }
    prior = _previous_records(previous, previous_sha256)
    records = [
        _current_record(identity, value, prior.get(identity), observed)
        for identity, value in sorted(current.items())
    ]
    records.extend(
        _resolved_record(identity, value, observed)
        for identity, value in sorted(prior.items())
        if identity not in current
    )
    records.sort(
        key=lambda value: (
            str(value["lifecycle"]),
            str(value["severity"]),
            str(value["identity"]),
        )
    )
    return {
        "schema_version": "1.0",
        "authoritative": False,
        "scope": "Lifecycle and SLA decision support derived from sealed reports; issue ownership and risk acceptance remain governed externally.",
        "report": {
            "scan_id": verification["scan_id"],
            "checksums_sha256": verification["checksums_sha256"],
            "observed_at": _iso(observed),
        },
        "previous_register_sha256": previous_sha256 or None,
        "summary": {
            "records": len(records),
            "open": sum(
                value["lifecycle"] in {"open", "reopened"} for value in records
            ),
            "resolved": sum(value["lifecycle"] == "resolved" for value in records),
            "reopened": sum(value["lifecycle"] == "reopened" for value in records),
            "overdue": sum(value["sla"]["status"] == "overdue" for value in records),
        },
        "records": records,
    }


def _current_record(
    identity: str,
    finding: dict[str, Any],
    prior: dict[str, Any] | None,
    observed: datetime,
) -> dict[str, Any]:
    first_seen = str(prior.get("first_seen")) if prior else _iso(observed)
    previous_lifecycle = str(prior.get("lifecycle")) if prior else ""
    lifecycle = "reopened" if previous_lifecycle == "resolved" else "open"
    severity = str(finding.get("severity") or "unknown").casefold()
    due = _timestamp(first_seen) + timedelta(days=_SLA_DAYS.get(severity, 30))
    return {
        "identity": identity,
        "finding_id": str(finding.get("finding_id") or "unknown"),
        "title": str(finding.get("title") or "Untitled finding"),
        "severity": severity,
        "blocking": finding.get("blocking") is True,
        "lifecycle": lifecycle,
        "first_seen": first_seen,
        "last_seen": _iso(observed),
        "resolved_at": None,
        "occurrences": int(prior.get("occurrences") or 0) + 1 if prior else 1,
        "owners": _owners(finding),
        "sla": {
            "target_days": _SLA_DAYS.get(severity, 30),
            "due_at": _iso(due),
            "status": "overdue" if observed > due else "open",
        },
    }


def _resolved_record(
    identity: str, prior: dict[str, Any], observed: datetime
) -> dict[str, Any]:
    value = dict(prior)
    value["identity"] = identity
    if value.get("lifecycle") != "resolved":
        value["lifecycle"] = "resolved"
        value["resolved_at"] = _iso(observed)
    value["sla"] = dict(value.get("sla") or {})
    value["sla"]["status"] = "met"
    return value


def _previous_records(path: Path | None, expected: str) -> dict[str, dict[str, Any]]:
    if path is None:
        return {}
    source = resolve_regular_file(path, "previous finding register")
    if sha256_file(source) != _digest(expected):
        raise ValueError("previous finding register does not match its SHA-256")
    document = _read(source, "previous finding register")
    if document.get("schema_version") != "1.0":
        raise ValueError("previous finding register schema_version must be '1.0'")
    records = _objects(document.get("records"), "previous finding records")
    result: dict[str, dict[str, Any]] = {}
    for record in records:
        identity = str(record.get("identity") or "")
        if not identity or identity in result:
            raise ValueError(
                "previous finding register identities must be non-empty and unique"
            )
        result[identity] = record
    return result


def _identity(finding: dict[str, Any]) -> str:
    return str(finding.get("fingerprint") or finding.get("finding_id") or "unknown")


def _owners(finding: dict[str, Any]) -> list[str]:
    evidence = finding.get("evidence")
    owners = evidence.get("owners") if isinstance(evidence, dict) else None
    return (
        sorted(str(value) for value in owners if isinstance(value, str) and value)
        if isinstance(owners, list)
        else []
    )


def _digest(value: str) -> str:
    normalized = value.strip().casefold()
    if len(normalized) != 64 or any(
        character not in "0123456789abcdef" for character in normalized
    ):
        raise ValueError("previous register SHA-256 must be a lowercase digest")
    return normalized


def _timestamp(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("report timestamp is invalid") from exc
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _read(path: Path, label: str) -> dict[str, Any]:
    source = resolve_regular_file(path, label)
    if source.stat().st_size > _MAX_JSON_BYTES:
        raise ValueError(f"{label} exceeds 128 MiB")
    value = strict_json_loads(source.read_bytes())
    if not isinstance(value, dict):
        raise TypeError(f"{label} root must be an object")
    return value


def _objects(value: object, label: str) -> list[dict[str, Any]]:
    if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
        raise TypeError(f"{label} must be an array of objects")
    return value
