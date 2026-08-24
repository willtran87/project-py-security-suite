from __future__ import annotations

import hashlib
import os
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from .failure_domain import (
    require_independent_failure_domains,
    verify_failure_domain,
    verify_registered_failure_domain,
)
from .operation_receipt import verify_operation_receipt
from .pinned_command import remote_attested_failure_domain, run_pinned_json_command
from .strict_json import canonical_bytes
from .trusted_observation import governed_now


def externalize_and_reverify_bundle(
    bundle: Path,
    *,
    reachable_objects_sha256: str,
    signature_ledger: dict[str, Any],
    allowed_signers_sha256: str,
    verified_commits: int,
    verified_tags: int,
) -> dict[str, Any]:
    """Publish a Git bundle and require an independent second implementation."""

    bundle_sha256 = _sha256_file(bundle)
    bundle_size = bundle.stat().st_size
    request = {
        "schema_version": "1.0",
        "bundle_path": str(bundle.resolve()),
        "bundle_sha256": bundle_sha256,
        "bundle_size_bytes": bundle_size,
        "reachable_objects_sha256": reachable_objects_sha256,
        "signature_ledger_sha256": hashlib.sha256(
            canonical_bytes(signature_ledger)
        ).hexdigest(),
        "allowed_signers_sha256": allowed_signers_sha256,
        "verified_commits": verified_commits,
        "verified_tags": verified_tags,
    }
    primary = _primary_failure_domain()
    storage = _invoke(
        "PYSEC_GIT_BUNDLE_CAS",
        request,
        response_fields={
            "schema_version",
            "object_id",
            "object_version",
            "immutable_uri",
            "retention_until",
            "bundle_sha256",
            "bundle_size_bytes",
            "authority_key_sha256",
            "execution_nonce",
            "failure_domain",
            "operation_receipt",
        },
        purpose="git-bundle-cas-publish",
        subject_extra=(
            "object_id",
            "object_version",
            "immutable_uri",
            "retention_until",
            "execution_nonce",
        ),
    )
    try:
        retention_until = datetime.fromisoformat(
            str(storage["retention_until"]).replace("Z", "+00:00")
        )
    except ValueError as exc:
        raise ValueError("Git CAS retention is invalid") from exc
    if (
        storage["object_id"] != f"sha256:{bundle_sha256}"
        or not str(storage["object_version"]).strip()
        or not str(storage["immutable_uri"]).startswith("cas://")
        or retention_until < governed_now() + timedelta(days=30)
    ):
        raise ValueError("Git CAS object is not immutable and durably retained")
    secondary_request = {
        name: value for name, value in request.items() if name != "bundle_path"
    }
    secondary_request.update(
        {
            "cas_object_id": storage["object_id"],
            "cas_object_version": storage["object_version"],
            "cas_immutable_uri": storage["immutable_uri"],
            "cas_authority_key_sha256": storage["authority_key_sha256"],
            "cas_operation_receipt_sha256": hashlib.sha256(
                canonical_bytes(storage["operation_receipt"])
            ).hexdigest(),
            "cas_effective_policy_attestation_sha256": hashlib.sha256(
                canonical_bytes(storage["effective_policy_attestation"])
            ).hexdigest(),
        }
    )
    secondary = _invoke(
        "PYSEC_GIT_SECONDARY_VERIFIER",
        secondary_request,
        response_fields={
            "schema_version",
            "bundle_sha256",
            "bundle_size_bytes",
            "reachable_objects_sha256",
            "signature_ledger_sha256",
            "allowed_signers_sha256",
            "verified_commits",
            "verified_tags",
            "cas_object_id",
            "cas_object_version",
            "cas_bundle_read_sha256",
            "authority_key_sha256",
            "execution_nonce",
            "failure_domain",
            "operation_receipt",
        },
        purpose="git-bundle-secondary-verification",
        subject_extra=("cas_bundle_read_sha256", "execution_nonce"),
    )
    if secondary.get("cas_bundle_read_sha256") != bundle_sha256:
        raise ValueError("secondary Git verifier did not read the retained CAS bytes")
    for response, expected_request in (
        (storage, request),
        (secondary, secondary_request),
    ):
        for name, expected in expected_request.items():
            if (
                name != "bundle_path"
                and name in response
                and response[name] != expected
            ):
                raise ValueError("external Git replay response is detached")
    require_independent_failure_domains(
        primary,
        storage["failure_domain"],
        labels=("primary Git verifier", "Git CAS authority"),
    )
    require_independent_failure_domains(
        primary,
        secondary["failure_domain"],
        labels=("primary Git verifier", "secondary Git verifier"),
    )
    require_independent_failure_domains(
        storage["failure_domain"],
        secondary["failure_domain"],
        labels=("Git CAS authority", "secondary Git verifier"),
    )
    return {
        "primary_failure_domain": primary,
        "bundle_storage": storage,
        "secondary_verification": secondary,
    }


def _invoke(
    prefix: str,
    request: dict[str, Any],
    *,
    response_fields: set[str],
    purpose: str,
    subject_extra: tuple[str, ...] = (),
) -> dict[str, Any]:
    attested_request = dict(request)
    response = run_pinned_json_command(prefix, attested_request)
    attestation = response.pop("_effective_policy_attestation", None)
    expected_key = os.environ.get(f"{prefix}_AUTHORITY_KEY_SHA256", "").strip()
    if (
        set(response) != response_fields
        or response.get("schema_version") != "1.0"
        or response.get("authority_key_sha256") != expected_key
        or not _digest(expected_key)
    ):
        raise ValueError("external Git replay authority response is invalid")
    failure_domain = verify_failure_domain(response["failure_domain"], prefix)
    verify_registered_failure_domain(response["failure_domain"], expected_key, prefix)
    attestation_subject = (
        attestation.get("subject") if isinstance(attestation, dict) else None
    )
    if (
        failure_domain != remote_attested_failure_domain(attestation)
        or not isinstance(attestation_subject, dict)
        or response.get("execution_nonce") != attestation_subject.get("execution_nonce")
    ):
        raise ValueError("external Git authority failure domain is not attested")
    subject = {name: value for name, value in request.items() if name != "bundle_path"}
    subject.update({name: response[name] for name in subject_extra})
    subject["failure_domain"] = failure_domain
    receipt = response["operation_receipt"]
    statement = receipt.get("statement") if isinstance(receipt, dict) else None
    try:
        observed_at = datetime.fromisoformat(
            str((statement or {})["issued_at"]).replace("Z", "+00:00")
        )
    except (KeyError, ValueError) as exc:
        raise ValueError("external Git replay authority time is invalid") from exc
    verify_operation_receipt(
        subject,
        receipt,
        purpose=purpose,
        observed_at=observed_at,
        challenge_sha256=os.environ.get("PYSEC_SCAN_TIME_CHALLENGE_SHA256", "").strip(),
        expected_key_sha256=expected_key,
    )
    response["effective_policy_attestation"] = attestation
    response["attested_request"] = attested_request
    return response


def _primary_failure_domain() -> dict[str, str]:
    value = {
        "organization": os.environ.get("PYSEC_GIT_PRIMARY_ORGANIZATION", ""),
        "host_identity_sha256": os.environ.get(
            "PYSEC_GIT_PRIMARY_HOST_IDENTITY_SHA256", ""
        ),
        "control_plane_sha256": os.environ.get(
            "PYSEC_GIT_PRIMARY_CONTROL_PLANE_SHA256", ""
        ),
        "implementation_sha256": os.environ.get(
            "PYSEC_GIT_PRIMARY_IMPLEMENTATION_SHA256", ""
        ),
    }
    return verify_failure_domain(value, "primary Git verifier")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _digest(value: str) -> bool:
    return len(value) == 64 and all(
        character in "0123456789abcdef" for character in value
    )
