from __future__ import annotations

import os
import hashlib
from datetime import datetime
from typing import Any

from .failure_domain import (
    require_independent_failure_domains,
    verify_failure_domain,
    verify_registered_failure_domain,
)
from .operation_receipt import verify_operation_receipt
from .pinned_command import (
    command_configured,
    run_pinned_json_command,
    remote_attested_failure_domain,
    verify_effective_policy_subject,
)
from .strict_json import loads as strict_loads
from .strict_json import canonical_bytes


def publish_checkpoint(
    prefix: str, subject: dict[str, Any], *, required: bool
) -> dict[str, Any] | None:
    """Publish a state checkpoint through an attested external monotonic service."""

    quorum_raw = os.environ.get(f"{prefix}_QUORUM_PREFIXES_JSON", "").strip()
    if quorum_raw:
        try:
            prefixes = strict_loads(quorum_raw)
            threshold = int(os.environ.get(f"{prefix}_QUORUM_THRESHOLD", ""))
        except (TypeError, ValueError) as exc:
            raise ValueError(
                "checkpoint authority quorum configuration is invalid"
            ) from exc
        if (
            not isinstance(prefixes, list)
            or len(prefixes) < 2
            or prefixes != sorted(set(prefixes))
            or any(not isinstance(item, str) or not item for item in prefixes)
            or threshold < 2
            or threshold > len(prefixes)
        ):
            raise ValueError("checkpoint authority quorum configuration is invalid")
        authorities = []
        for authority_prefix in prefixes:
            try:
                receipt = _publish_single(authority_prefix, subject, required=True)
            except ValueError:
                continue
            if receipt is not None:
                authorities.append({"prefix": authority_prefix, "receipt": receipt})
        if len(authorities) < threshold:
            raise ValueError("checkpoint authority quorum threshold is not met")
        _verify_quorum_domains(authorities)
        return {
            "schema_version": "1.0",
            "quorum_threshold": threshold,
            "authorities": authorities,
        }
    return _publish_single(prefix, subject, required=required)


def _publish_single(
    prefix: str, subject: dict[str, Any], *, required: bool
) -> dict[str, Any] | None:

    if not command_configured(prefix):
        if required:
            raise ValueError(f"{prefix} external checkpoint authority is unavailable")
        return None
    request = {
        **subject,
        "idempotency_key_sha256": hashlib.sha256(canonical_bytes(subject)).hexdigest(),
    }
    response = run_pinned_json_command(prefix, request)
    policy_attestation = response.pop("_effective_policy_attestation", None)
    fields = {
        "schema_version",
        "accepted",
        "checkpoint_authority_key_sha256",
        "execution_nonce",
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
    verify_registered_failure_domain(
        failure_domain, expected_key, "checkpoint authority"
    )
    attestation_subject = policy_attestation.get("subject")
    if not isinstance(attestation_subject, dict) or response.get(
        "execution_nonce"
    ) != attestation_subject.get("execution_nonce"):
        raise ValueError("checkpoint result is detached from its attested execution")
    receipt = response["checkpoint_operation_receipt"]
    statement = receipt.get("statement") if isinstance(receipt, dict) else None
    try:
        observed = datetime.fromisoformat(
            str((statement or {})["issued_at"]).replace("Z", "+00:00")
        )
    except (KeyError, ValueError) as exc:
        raise ValueError("external checkpoint authority time is invalid") from exc
    verified = verify_operation_receipt(
        {
            **request,
            "execution_nonce": response["execution_nonce"],
            "failure_domain": response["failure_domain"],
        },
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
        "checkpoint_subject": request,
    }


def verify_retained_checkpoint(
    prefix: str, value: object, subject: dict[str, Any]
) -> dict[str, Any]:
    """Fully reverify a persisted checkpoint acknowledgement."""

    if isinstance(value, dict) and set(value) == {
        "schema_version",
        "quorum_threshold",
        "authorities",
    }:
        authorities = value.get("authorities")
        threshold = value.get("quorum_threshold")
        if (
            value.get("schema_version") != "1.0"
            or not isinstance(authorities, list)
            or not isinstance(threshold, int)
            or threshold < 2
            or threshold > len(authorities)
        ):
            raise ValueError("retained checkpoint quorum is invalid")
        verified = []
        for item in authorities:
            if not isinstance(item, dict) or set(item) != {"prefix", "receipt"}:
                raise ValueError("retained checkpoint quorum member is invalid")
            verified.append(
                {
                    "prefix": item["prefix"],
                    "receipt": verify_retained_checkpoint(
                        str(item["prefix"]), item["receipt"], subject
                    ),
                }
            )
        _verify_quorum_domains(verified)
        if len(verified) < threshold:
            raise ValueError("retained checkpoint quorum threshold is not met")
        return dict(value)

    if not isinstance(value, dict) or set(value) != {
        "schema_version",
        "accepted",
        "checkpoint_authority_key_sha256",
        "execution_nonce",
        "checkpoint_operation_receipt",
        "failure_domain",
        "effective_policy_attestation",
        "checkpoint_subject",
    }:
        raise ValueError("retained external checkpoint fields do not match")
    expected_request = {
        **subject,
        "idempotency_key_sha256": hashlib.sha256(canonical_bytes(subject)).hexdigest(),
    }
    retained_request = value.get("checkpoint_subject")
    if (
        not isinstance(retained_request, dict)
        or any(
            retained_request.get(name) != expected
            for name, expected in expected_request.items()
        )
        or set(retained_request) != {*expected_request, "command_context"}
        or not isinstance(retained_request.get("command_context"), dict)
    ):
        raise ValueError("retained external checkpoint subject is detached")
    expected_key = (
        os.environ.get(f"{prefix}_AUTHORITY_KEY_SHA256", "").strip().casefold()
    )
    failure_domain = verify_failure_domain(
        value["failure_domain"], "checkpoint authority"
    )
    configured_domain = verify_failure_domain(
        strict_loads(os.environ.get(f"{prefix}_FAILURE_DOMAIN_JSON", "")),
        "configured checkpoint authority",
    )
    if (
        value.get("schema_version") != "1.0"
        or value.get("accepted") is not True
        or value.get("checkpoint_authority_key_sha256") != expected_key
        or failure_domain != configured_domain
    ):
        raise ValueError("retained external checkpoint is invalid")
    verify_registered_failure_domain(
        failure_domain, expected_key, "checkpoint authority"
    )
    attestation = value["effective_policy_attestation"]
    attestation_subject = (
        attestation.get("subject") if isinstance(attestation, dict) else None
    )
    if not isinstance(attestation_subject, dict) or value.get(
        "execution_nonce"
    ) != attestation_subject.get("execution_nonce"):
        raise ValueError("retained checkpoint execution binding is invalid")
    receipt = value["checkpoint_operation_receipt"]
    statement = receipt.get("statement") if isinstance(receipt, dict) else None
    try:
        observed = datetime.fromisoformat(
            str((statement or {})["issued_at"]).replace("Z", "+00:00")
        )
    except (KeyError, ValueError) as exc:
        raise ValueError("retained external checkpoint time is invalid") from exc
    verify_operation_receipt(
        {
            **retained_request,
            "execution_nonce": value["execution_nonce"],
            "failure_domain": value["failure_domain"],
        },
        receipt,
        purpose="state-checkpoint-publish",
        observed_at=observed,
        challenge_sha256=os.environ.get("PYSEC_SCAN_TIME_CHALLENGE_SHA256", "").strip(),
        expected_key_sha256=expected_key,
    )
    from .pinned_command import verify_retained_effective_policy_attestation

    if failure_domain != verify_retained_effective_policy_attestation(
        value["effective_policy_attestation"]
    ):
        raise ValueError("retained checkpoint failure domain is not attested")
    return dict(value)


def _verify_quorum_domains(authorities: list[dict[str, Any]]) -> None:
    for index, left in enumerate(authorities):
        for right in authorities[index + 1 :]:
            require_independent_failure_domains(
                left["receipt"]["failure_domain"],
                right["receipt"]["failure_domain"],
                labels=(str(left["prefix"]), str(right["prefix"])),
            )


def _digest(value: str) -> bool:
    return len(value) == 64 and all(
        character in "0123456789abcdef" for character in value
    )
