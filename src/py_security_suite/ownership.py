from __future__ import annotations

import fnmatch
from typing import Any


OwnershipRule = tuple[str, list[str]]


def owners_for_path(path: str, rules: list[OwnershipRule]) -> list[str]:
    """Apply bounded CODEOWNERS-style last-match semantics to a repository path."""
    normalized_path = path.replace("\\", "/").lstrip("/")
    if not normalized_path or normalized_path.startswith("<"):
        return []
    owners: list[str] = []
    for pattern, candidates in rules:
        normalized = pattern.rstrip("/")
        matched = fnmatch.fnmatchcase(normalized_path, normalized)
        if not matched and "/" not in normalized:
            matched = any(
                fnmatch.fnmatchcase(part, normalized)
                for part in normalized_path.split("/")
            )
        if not matched and pattern.endswith("/"):
            matched = normalized_path.startswith(normalized + "/")
        if matched:
            owners = candidates
    return owners[:20]


def ownership_rule_records(rules: list[OwnershipRule]) -> list[dict[str, Any]]:
    return [
        {"pattern": pattern[:4096], "owners": owners[:20]}
        for pattern, owners in rules[:10_000]
    ]


def ownership_rules_from_artifact(value: Any) -> list[OwnershipRule]:
    if not isinstance(value, dict):
        return []
    records = value.get("ownership_rule_details")
    if not isinstance(records, list):
        return []
    rules: list[OwnershipRule] = []
    for item in records[:10_000]:
        if not isinstance(item, dict):
            continue
        pattern = str(item.get("pattern") or "")[:4096]
        raw_owners = item.get("owners")
        owners = (
            [str(owner)[:256] for owner in raw_owners[:20] if isinstance(owner, str)]
            if isinstance(raw_owners, list)
            else []
        )
        if pattern and owners:
            rules.append((pattern, owners))
    return rules
