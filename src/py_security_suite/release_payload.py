from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from .execution import sha256_file
from .passport import verify_report
from .path_safety import resolve_regular_directory, resolve_regular_file

_MAX_ARTIFACTS = 1000
_MAX_ARTIFACT_BYTES = 2 * 1024 * 1024 * 1024
_MAX_REQUEST_BYTES = 16 * 1024 * 1024
_DISTRIBUTION_SUFFIXES = (".whl", ".tar.gz", ".zip")


def prepare_signing_request(report: Path, artifacts: Path) -> dict[str, Any]:
    """Bind a verified report to the exact release distributions sent for signing."""
    verification = verify_report(report)
    report_root = report.expanduser().resolve()
    manifest = _read_object(report_root / "scan-manifest.json", _MAX_REQUEST_BYTES)
    root = resolve_regular_directory(artifacts, "release artifact directory")
    subjects = _artifact_subjects(root)
    payload_id = _payload_id(subjects)
    inventory = manifest.get("inventory")
    source_sha256 = (
        str(inventory.get("source_sha256") or "") if isinstance(inventory, dict) else ""
    )
    return {
        "schema_version": "1.0",
        "status": "candidate",
        "authoritative": False,
        "scope": (
            "Exact release payload prepared for an independently authorized signing "
            "lane; this request is not a signature or release approval."
        ),
        "report": {
            "scan_id": verification["scan_id"],
            "checksums_sha256": verification["checksums_sha256"],
            "source_sha256": source_sha256,
            "outcome": verification["outcome"],
        },
        "payload": {
            "id": payload_id,
            "algorithm": "sha256-canonical-json",
            "artifact_count": len(subjects),
            "subjects": subjects,
        },
        "policy": {
            "exact_artifact_set_required": True,
            "signature_format": "sigstore-bundle-v0.3",
            "organization_authorization_required": True,
            "private_key_material_permitted": False,
        },
        "handoff": [
            "verify this request digest through an independent trusted channel",
            "verify every artifact digest before signing",
            "sign each exact subject in the controlled signing lane",
            "return Sigstore bundles and signer identity policy evidence",
            "verify the returned payload before release approval",
        ],
    }


def verify_signing_request(
    request: Path,
    artifacts: Path,
    *,
    request_sha256: str,
) -> dict[str, Any]:
    """Verify that a digest-approved signing request still matches an exact payload."""
    expected = request_sha256.strip().casefold()
    if not _is_digest(expected):
        raise ValueError("signing request SHA-256 must be 64 hexadecimal characters")
    request_path = resolve_regular_file(request, "signing request")
    if request_path.stat().st_size > _MAX_REQUEST_BYTES:
        raise ValueError("signing request exceeds the size limit")
    observed = sha256_file(request_path)
    if observed != expected:
        raise ValueError("signing request does not match the approved SHA-256")
    document = _read_object(request_path, _MAX_REQUEST_BYTES)
    _validate_request(document)
    root = resolve_regular_directory(artifacts, "release artifact directory")
    observed_subjects = _artifact_subjects(root)
    payload = document["payload"]
    expected_subjects = payload["subjects"]
    if observed_subjects != expected_subjects:
        raise ValueError("release artifact set does not match the signing request")
    payload_id = _payload_id(observed_subjects)
    if payload_id != payload["id"]:
        raise ValueError("signing request payload identity is invalid")
    return {
        "schema_version": "1.0",
        "verified": True,
        "authoritative": False,
        "request_sha256": observed,
        "payload_id": payload_id,
        "artifact_count": len(observed_subjects),
        "exact_artifact_set_verified": True,
        "next_required_authority": "controlled-signing",
    }


def _artifact_subjects(root: Path) -> list[dict[str, Any]]:
    subjects: list[dict[str, Any]] = []
    for count, path in enumerate(root.iterdir(), start=1):
        if count > _MAX_ARTIFACTS:
            raise ValueError("release artifact directory exceeds the entry limit")
        if not _is_distribution(path.name):
            continue
        if not path.is_file() or path.is_symlink():
            raise ValueError(f"release artifact is not a regular file: {path.name}")
        size = path.stat().st_size
        if size > _MAX_ARTIFACT_BYTES:
            raise ValueError(f"release artifact exceeds the size limit: {path.name}")
        subjects.append(
            {
                "name": path.name,
                "sha256": sha256_file(path),
                "size_bytes": size,
            }
        )
    if not subjects:
        raise ValueError("release artifact directory contains no wheel, sdist, or zip")
    return sorted(subjects, key=lambda item: item["name"])


def _payload_id(subjects: list[dict[str, Any]]) -> str:
    payload = json.dumps(
        subjects,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    return hashlib.sha256(payload).hexdigest()


def _validate_request(document: dict[str, Any]) -> None:
    if (
        document.get("schema_version") != "1.0"
        or document.get("status") != "candidate"
        or document.get("authoritative") is not False
    ):
        raise ValueError("signing request identity is invalid")
    payload = document.get("payload")
    if not isinstance(payload, dict):
        raise TypeError("signing request payload must be an object")
    subjects = payload.get("subjects")
    if not isinstance(subjects, list) or not subjects:
        raise TypeError("signing request subjects must be a non-empty array")
    if len(subjects) > _MAX_ARTIFACTS:
        raise ValueError("signing request contains too many subjects")
    names: set[str] = set()
    for subject in subjects:
        if not isinstance(subject, dict):
            raise TypeError("signing request subjects must be objects")
        name = subject.get("name")
        digest = subject.get("sha256")
        size = subject.get("size_bytes")
        if (
            not isinstance(name, str)
            or not _is_distribution(name)
            or Path(name).name != name
            or name in names
            or not isinstance(digest, str)
            or not _is_digest(digest)
            or type(size) is not int
            or size < 0
            or size > _MAX_ARTIFACT_BYTES
        ):
            raise ValueError("signing request subject identity is invalid")
        names.add(name)
    if payload.get("artifact_count") != len(subjects):
        raise ValueError("signing request artifact count is invalid")
    if not _is_digest(str(payload.get("id") or "")):
        raise ValueError("signing request payload digest is invalid")


def _read_object(path: Path, maximum: int) -> dict[str, Any]:
    source = resolve_regular_file(path, "JSON evidence")
    if source.stat().st_size > maximum:
        raise ValueError(f"JSON evidence exceeds {maximum} bytes")
    value = json.loads(source.read_bytes())
    if not isinstance(value, dict):
        raise TypeError("JSON evidence root must be an object")
    return value


def _is_distribution(name: str) -> bool:
    lowered = name.casefold()
    return lowered.endswith(_DISTRIBUTION_SUFFIXES)


def _is_digest(value: str) -> bool:
    return len(value) == 64 and all(
        character in "0123456789abcdef" for character in value
    )
