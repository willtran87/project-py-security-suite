"""Route ownership attribution and coordination signals."""

from __future__ import annotations

from typing import Any

from .risk_path_values import _strings
from .ownership import owners_for_path


__all__ = [
    "_ownership_coordination_action",
    "_ownership_coordination_status",
    "_ownership_path_records",
    "_target_owner_alignment",
]


def _ownership_path_records(
    files: list[str],
    rules: list[tuple[str, list[str]]],
    *,
    entry_path: str | None,
    target_path: str | None,
) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for path in files:
        roles = []
        if path == entry_path:
            roles.append("entry")
        if path == target_path:
            roles.append("target")
        if not roles:
            roles.append("transit")
        result.append(
            {
                "path": path,
                "owners": owners_for_path(path, rules) if rules else [],
                "roles": roles,
            }
        )
    return result


def _target_owner_alignment(
    records: list[dict[str, Any]],
    target_path: str | None,
    target_owners: list[str],
    evidence_available: bool,
) -> str:
    if not evidence_available or not target_path:
        return "not-established"
    path_owners = next(
        (
            _strings(record.get("owners"), 20)
            for record in records
            if record.get("path") == target_path
        ),
        [],
    )
    if not path_owners:
        return "target-unowned"
    if not target_owners:
        return "target-owner-not-attributed"
    return "aligned" if set(path_owners) == set(target_owners) else "mismatch"


def _ownership_coordination_status(
    evidence_available: bool,
    boundaries: list[dict[str, Any]],
    unowned: list[str],
    owners: list[str],
) -> str:
    if not evidence_available:
        return "not-established"
    if unowned:
        return "unowned-segment"
    if boundaries or len(owners) > 1:
        return "cross-owner"
    return "single-owner"


def _ownership_coordination_action(
    evidence_available: bool,
    boundaries: list[dict[str, Any]],
    unowned: list[str],
    owners: list[str],
) -> str:
    if not evidence_available:
        return (
            "Retain bounded CODEOWNERS evidence and rerun route synthesis before "
            "assigning cross-file remediation responsibility."
        )
    if unowned:
        return (
            "Assign CODEOWNERS responsibility for every unowned route file, then "
            "coordinate remediation and validation across the retained handoffs."
        )
    if boundaries or len(owners) > 1:
        return (
            "Coordinate remediation, review, and regression evidence across every "
            "retained ownership handoff before route disposition."
        )
    return "Keep remediation and regression evidence with the retained route owner."
