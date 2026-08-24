from __future__ import annotations

import os
from datetime import datetime
from typing import Any

from .failure_domain import verify_failure_domain
from .operation_receipt import verify_operation_receipt
from .pinned_command import (
    command_configured,
    run_pinned_json_command,
    remote_attested_failure_domain,
    verify_effective_policy_subject,
)
from .strict_json import loads as strict_loads


def publish_checkpoint(
    prefix: str, subject: dict[str, Any], *, required: bool
) -> dict[str, Any] | None:
    """Publish a state checkpoint through an attested external monotonic service."""

    if not command_configured(prefix):
        if required:
            raise ValueError(f"{prefix} external checkpoint authority is unavailable")
        return None
    request = dict(subject)
    response = run_pinned_json_command(prefix, request)
    policy_attestation = response.pop("_effective_policy_attestation", None)
    fields = {
        "schema_version",
        "accepted",
        "checkpoint_authority_key_sha256",
        "checkpoint_operation_receipt",
        "failure_domain",
    }
    expected_key = (
        os.environ.get(f"{prefix}_AUTHORITY_KEY_SHA256", "").strip().casefold()
    )
    if (
        set(response) != fields
        or response.get("schema_version") != "1.0"
        or response.get("accepted") is not True
        or response.get("checkpoint_authority_key_sha256") != expected_key
        or not _digest(expected_key)
        or not isinstance(policy_attestation, dict)
    ):
        raise ValueError("external checkpoint authority response is invalid")
    failure_domain = verify_failure_domain(
        response["failure_domain"], "checkpoint authority"
    )
    try:
        configured_domain = verify_failure_domain(
            strict_loads(os.environ.get(f"{prefix}_FAILURE_DOMAIN_JSON", "")),
            "configured checkpoint authority",
        )
    except (TypeError, ValueError) as exc:
        raise ValueError("checkpoint authority failure-domain pin is invalid") from exc
    if failure_domain != configured_domain:
        raise ValueError("checkpoint authority failure domain does not match its pin")
    receipt = response["checkpoint_operation_receipt"]
    statement = receipt.get("statement") if isinstance(receipt, dict) else None
    try:
        observed = datetime.fromisoformat(
            str((statement or {})["issued_at"]).replace("Z", "+00:00")
        )
    except (KeyError, ValueError) as exc:
        raise ValueError("external checkpoint authority time is invalid") from exc
    verified = verify_operation_receipt(
        {**request, "failure_domain": response["failure_domain"]},
        receipt,
        purpose="state-checkpoint-publish",
        observed_at=observed,
        challenge_sha256=os.environ.get("PYSEC_SCAN_TIME_CHALLENGE_SHA256", "").strip(),
        expected_key_sha256=expected_key,
    )
    attestation_subject = policy_attestation.get("subject")
    if not isinstance(attestation_subject, dict):
        raise ValueError("external checkpoint execution attestation is invalid")
    verify_effective_policy_subject(attestation_subject)
    if failure_domain != remote_attested_failure_domain(policy_attestation):
        raise ValueError("checkpoint authority failure domain is not hardware-attested")
    return {
        **response,
        "checkpoint_operation_receipt": verified,
        "effective_policy_attestation": policy_attestation,
    }


def _digest(value: str) -> bool:
    return len(value) == 64 and all(
        character in "0123456789abcdef" for character in value
    )
