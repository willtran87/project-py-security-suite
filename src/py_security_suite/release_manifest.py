from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Any

from .execution import sha256_file
from .passport import verify_report
from .path_safety import resolve_regular_file
from .strict_json import canonical_bytes, loads as strict_loads

_MAX_JSON_BYTES = 128 * 1024 * 1024
_DIGEST_LENGTH = 64
_HARDENED_RELEASE_EVIDENCE = {
    "clusterfuzzlite",
    "github-attestation",
    "in-toto",
    "reproducible-build",
    "surface-inventory",
}


def build_release_evidence_manifest(
    report: Path,
    *,
    evidence: tuple[tuple[str, Path, str], ...],
    path_base: Path | None = None,
) -> dict[str, Any]:
    """Create a closed, digest-bound index of external release evidence."""
    verification = verify_report(report)
    records: list[dict[str, Any]] = []
    names: set[str] = set()
    for name, path, expected_digest in evidence:
        if name in names:
            raise ValueError(f"duplicate release evidence name: {name}")
        names.add(name)
        source = resolve_regular_file(path, f"release evidence {name}")
        if source.stat().st_size > _MAX_JSON_BYTES:
            raise ValueError(f"release evidence {name} exceeds 128 MiB")
        digest = sha256_file(source)
        if not expected_digest or digest != expected_digest:
            raise ValueError(
                f"release evidence {name} does not match its approved SHA-256"
            )
        document = strict_loads(source.read_bytes())
        if not isinstance(document, dict):
            raise TypeError(f"release evidence {name} root must be an object")
        bound_digest = bound_report_digest(document)
        if bound_digest != verification["checksums_sha256"]:
            raise ValueError(f"release evidence {name} is not bound to this report")
        _validate_hardened_evidence(name, document)
        records.append(
            {
                "name": name,
                "path": _portable_path(source, path_base),
                "sha256": digest,
                "schema_version": str(document.get("schema_version") or "unknown"),
            }
        )
    records.sort(key=lambda item: str(item["name"]))
    manifest_id = _manifest_id(
        verification["checksums_sha256"],
        [{"name": item["name"], "sha256": item["sha256"]} for item in records],
    )
    return {
        "schema_version": "1.0",
        "status": "candidate",
        "authoritative": False,
        "closed_set": True,
        "scope": "Exact evidence index for independent approval; this manifest does not sign or approve its contents.",
        "manifest_id": manifest_id,
        "report": {
            "scan_id": verification["scan_id"],
            "checksums_sha256": verification["checksums_sha256"],
        },
        "evidence": records,
        "required_authorities": [
            "controlled-signing",
            "organization-security",
            "release-approver",
        ],
    }


def verify_release_evidence_manifest(
    manifest: Path,
    *,
    manifest_sha256: str,
    report: Path,
    required_evidence: tuple[str, ...] = (),
    evidence_locations: tuple[tuple[str, Path], ...] = (),
) -> dict[str, Any]:
    """Verify a closed evidence manifest without granting release approval."""
    expected = _validated_digest(manifest_sha256, "manifest SHA-256")
    source = resolve_regular_file(manifest, "release evidence manifest")
    if source.stat().st_size > _MAX_JSON_BYTES:
        raise ValueError("release evidence manifest exceeds 128 MiB")
    actual = sha256_file(source)
    if actual != expected:
        raise ValueError("release evidence manifest does not match its SHA-256")
    document = strict_loads(source.read_bytes())
    if not isinstance(document, dict):
        raise TypeError("release evidence manifest root must be an object")
    _validate_manifest_shape(document)

    verification = verify_report(report)
    report_record = document["report"]
    if report_record.get("scan_id") != verification["scan_id"]:
        raise ValueError("release evidence manifest scan ID does not match report")
    if report_record.get("checksums_sha256") != verification["checksums_sha256"]:
        raise ValueError("release evidence manifest is not bound to this report")

    location_overrides: dict[str, Path] = {}
    for name, path in evidence_locations:
        if not name or name in location_overrides:
            raise ValueError("evidence location names must be non-empty and unique")
        location_overrides[name] = path
    names: set[str] = set()
    paths: set[Path] = set()
    verified_names: list[str] = []
    identity: list[dict[str, str]] = []
    for raw in document["evidence"]:
        name = str(raw["name"])
        if name in names:
            raise ValueError(f"duplicate release evidence name: {name}")
        names.add(name)
        recorded_path = Path(str(raw["path"]))
        default_path = (
            recorded_path
            if recorded_path.is_absolute()
            else source.parent / recorded_path
        )
        evidence_path = resolve_regular_file(
            location_overrides.get(name, default_path),
            f"release evidence {name}",
        )
        if evidence_path in paths:
            raise ValueError(f"duplicate release evidence path: {evidence_path}")
        paths.add(evidence_path)
        if evidence_path.stat().st_size > _MAX_JSON_BYTES:
            raise ValueError(f"release evidence {name} exceeds 128 MiB")
        digest = _validated_digest(
            str(raw["sha256"]), f"release evidence {name} SHA-256"
        )
        if sha256_file(evidence_path) != digest:
            raise ValueError(f"release evidence {name} does not match its SHA-256")
        evidence_document = strict_loads(evidence_path.read_bytes())
        if not isinstance(evidence_document, dict):
            raise TypeError(f"release evidence {name} root must be an object")
        if bound_report_digest(evidence_document) != verification["checksums_sha256"]:
            raise ValueError(f"release evidence {name} is not bound to this report")
        _validate_hardened_evidence(name, evidence_document)
        verified_names.append(name)
        identity.append({"name": name, "sha256": digest})

    calculated_id = _manifest_id(verification["checksums_sha256"], identity)
    if calculated_id != document["manifest_id"]:
        raise ValueError("release evidence manifest ID is invalid")
    requested = set(required_evidence)
    if os.environ.get("PYSEC_REQUIRE_HARDENED_RELEASE_EVIDENCE", "").strip() == "1":
        requested.update(_HARDENED_RELEASE_EVIDENCE)
    if "" in required_evidence or len(set(required_evidence)) != len(required_evidence):
        raise ValueError("required evidence names must be non-empty and unique")
    missing = sorted(requested - names)
    if missing:
        raise ValueError(
            "release evidence manifest is missing required evidence: "
            + ", ".join(missing)
        )
    unused_locations = sorted(set(location_overrides) - names)
    if unused_locations:
        raise ValueError(
            "evidence locations name records absent from manifest: "
            + ", ".join(unused_locations)
        )
    return {
        "schema_version": "1.0",
        "verified": True,
        "authoritative": False,
        "admission": "requires_external_approval",
        "scope": "Integrity receipt for a closed release evidence set; it is not a signature or release approval.",
        "manifest": {
            "path": str(source),
            "sha256": actual,
            "manifest_id": calculated_id,
        },
        "report": {
            "scan_id": verification["scan_id"],
            "checksums_sha256": verification["checksums_sha256"],
            "outcome": verification["outcome"],
        },
        "evidence": {
            "verified_count": len(verified_names),
            "verified_names": sorted(verified_names),
            "required_names": sorted(requested),
            "missing_required": [],
        },
        "required_authorities": list(document["required_authorities"]),
    }


def _validate_hardened_evidence(name: str, document: dict[str, Any]) -> None:
    if name == "reproducible-build" and (
        document.get("reproducible") is not True or document.get("status") != "match"
    ):
        raise ValueError(
            "release reproducibility evidence does not demonstrate a match"
        )
    if name not in _HARDENED_RELEASE_EVIDENCE - {"reproducible-build"}:
        return
    binding = document.get("evidence_binding")
    execution = document.get("execution")
    if (
        document.get("kind") != name
        or not isinstance(binding, dict)
        or binding.get("verified") is not True
        or binding.get("authenticated") is not True
        or not isinstance(execution, dict)
        or execution.get("status") != "completed"
        or execution.get("coverage_percent") != 100.0
        or execution.get("skipped_checks")
    ):
        raise ValueError(
            f"release evidence {name} lacks authenticated complete execution"
        )
    if name == "surface-inventory":
        features = set(execution.get("features") or [])
        required = {
            "independent-collectors",
            "independent-signers",
            "pagination-completeness",
            "server-signed-page-chain",
            "signed-total-count",
            "liveness-probes",
        }
        if not required.issubset(features):
            raise ValueError(
                "release surface inventory lacks an independent denominator"
            )


def _validate_manifest_shape(document: dict[str, Any]) -> None:
    expected = {
        "schema_version",
        "status",
        "authoritative",
        "closed_set",
        "scope",
        "manifest_id",
        "report",
        "evidence",
        "required_authorities",
    }
    if set(document) != expected:
        raise ValueError("release evidence manifest has an unsupported shape")
    if document.get("schema_version") != "1.0":
        raise ValueError("release evidence manifest schema_version must be '1.0'")
    if (
        document.get("status") != "candidate"
        or document.get("authoritative") is not False
    ):
        raise ValueError(
            "release evidence manifest must be a non-authoritative candidate"
        )
    if document.get("closed_set") is not True:
        raise ValueError("release evidence manifest must declare a closed evidence set")
    if not isinstance(document.get("scope"), str) or not document["scope"]:
        raise ValueError("release evidence manifest scope must be non-empty")
    _validated_digest(str(document.get("manifest_id") or ""), "manifest ID")
    report_record = document.get("report")
    if not isinstance(report_record, dict) or set(report_record) != {
        "scan_id",
        "checksums_sha256",
    }:
        raise ValueError("release evidence manifest report identity is invalid")
    if not isinstance(report_record["scan_id"], str) or not report_record["scan_id"]:
        raise ValueError("release evidence manifest report scan ID is invalid")
    _validated_digest(str(report_record["checksums_sha256"]), "report checksum seal")
    evidence = document.get("evidence")
    if not isinstance(evidence, list) or not evidence or len(evidence) > 100:
        raise ValueError(
            "release evidence manifest must contain 1-100 evidence records"
        )
    for record in evidence:
        if not isinstance(record, dict) or set(record) != {
            "name",
            "path",
            "sha256",
            "schema_version",
        }:
            raise ValueError(
                "release evidence manifest contains an invalid evidence record"
            )
        if any(
            not isinstance(record[key], str) or not record[key]
            for key in ("name", "path", "schema_version")
        ):
            raise ValueError("release evidence manifest evidence identity is invalid")
    authorities = document.get("required_authorities")
    allowed = {"controlled-signing", "organization-security", "release-approver"}
    if (
        not isinstance(authorities, list)
        or not authorities
        or len(set(authorities)) != len(authorities)
        or any(value not in allowed for value in authorities)
    ):
        raise ValueError("release evidence manifest authorities are invalid")


def _validated_digest(value: str, label: str) -> str:
    normalized = value.strip().casefold()
    if len(normalized) != _DIGEST_LENGTH or any(
        character not in "0123456789abcdef" for character in normalized
    ):
        raise ValueError(f"{label} must be a lowercase SHA-256 digest")
    return normalized


def _manifest_id(report_digest: str, evidence: list[dict[str, str]]) -> str:
    payload = {
        "report_checksums_sha256": report_digest,
        "evidence": sorted(evidence, key=lambda item: item["name"]),
    }
    return hashlib.sha256(canonical_bytes(payload)).hexdigest()


def _portable_path(source: Path, base: Path | None) -> str:
    if base is None:
        return str(source)
    root = base.expanduser().resolve()
    return (
        source.relative_to(root).as_posix()
        if source.is_relative_to(root)
        else str(source)
    )


def bound_report_digest(document: dict[str, Any]) -> str:
    report = document.get("report")
    if isinstance(report, dict):
        value = report.get("checksums_sha256") or report.get("report_checksums_sha256")
        if isinstance(value, str):
            return value
    value = document.get("report_checksums_sha256")
    return str(value or "")
