from __future__ import annotations

import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .passport import verify_report
from .path_safety import (
    hold_parent_directory,
    read_regular_file,
    resolve_regular_directory,
)
from .strict_json import loads as strict_loads
from .strict_json import canonical_bytes
from .trusted_time import verify_rfc3161

import hashlib


def retention_status(
    report: Path,
    *,
    observed_at: datetime | None = None,
    trusted_time_context: Path | None = None,
) -> dict[str, Any]:
    """Verify a report and evaluate its sealed retention deadline."""
    verification = verify_report(report)
    root = resolve_regular_directory(report, "report")
    _, payload = read_regular_file(
        root / "report-security.json",
        "report security policy",
        maximum_bytes=64 * 1024,
        boundary=root,
    )
    policy = strict_loads(payload)
    if not isinstance(policy, dict) or policy.get("schema_version") != "1.0":
        raise ValueError("report security policy is invalid")
    raw_deadline = policy.get("delete_after")
    if not isinstance(raw_deadline, str):
        raise ValueError("report retention deadline is invalid")
    deadline = datetime.fromisoformat(raw_deadline.replace("Z", "+00:00"))
    if deadline.tzinfo is None:
        raise ValueError("report retention deadline must include a timezone")
    trusted_time: dict[str, str] | None = None
    if trusted_time_context is not None:
        _, context_payload = read_regular_file(
            trusted_time_context,
            "retention trusted-time context",
            maximum_bytes=64 * 1024,
        )
        context = strict_loads(context_payload)
        if (
            not isinstance(context, dict)
            or set(context)
            != {
                "schema_version",
                "trusted_time",
            }
            or context.get("schema_version") != "1.0"
        ):
            raise ValueError("retention trusted-time context is invalid")
        challenge = hashlib.sha256(
            canonical_bytes(
                {
                    "action": "purge-report",
                    "report_checksums_sha256": verification["checksums_sha256"],
                    "delete_after": deadline.astimezone(UTC).isoformat(),
                }
            )
        ).hexdigest()
        trusted_time = verify_rfc3161(
            trusted_time_context,
            context["trusted_time"],
            challenge,
            require_advanced=True,
        )
        now = datetime.fromisoformat(
            trusted_time["trusted_time_observed_at"].replace("Z", "+00:00")
        ).astimezone(UTC)
    else:
        now = (observed_at or datetime.now(UTC)).astimezone(UTC)
    deadline = deadline.astimezone(UTC)
    return {
        "schema_version": "1.0",
        "report_checksums_sha256": verification["checksums_sha256"],
        "delete_after": deadline.isoformat(),
        "observed_at": now.isoformat(),
        "trusted_time_verified": trusted_time is not None,
        "trusted_time_receipt_sha256": (
            trusted_time["trusted_time_receipt_sha256"] if trusted_time else None
        ),
        "expired": now >= deadline,
    }


def purge_verified_report(
    report: Path,
    *,
    require_expired: bool = True,
    observed_at: datetime | None = None,
    trusted_time_context: Path | None = None,
) -> dict[str, Any]:
    """Atomically detach and delete a verified report after policy evaluation."""
    if require_expired and trusted_time_context is None:
        raise ValueError(
            "expired report purge requires an RFC 3161 trusted-time receipt"
        )
    status = retention_status(
        report,
        observed_at=observed_at,
        trusted_time_context=trusted_time_context,
    )
    if require_expired and not status["expired"]:
        raise ValueError("report retention deadline has not been reached")
    root = resolve_regular_directory(report, "report")
    temporary = Path(tempfile.mkdtemp(prefix=f".{root.name}.purge-", dir=root.parent))
    temporary.rmdir()
    with hold_parent_directory(root, "report purge") as parent:
        parent.rename(root, temporary)
        # If deletion fails, leave the report detached at the private tombstone
        # instead of restoring a potentially partial report under its trusted name.
        parent.remove_tree(temporary)
    return {**status, "purged": True, "report": str(root)}
