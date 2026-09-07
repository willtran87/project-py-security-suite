"""Strict numeric values at the TOML configuration boundary."""

from __future__ import annotations

import math
from collections.abc import Mapping
from typing import Any


def integer_setting(value: object, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"{field} must be an integer")
    return value


def real_setting(value: object, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{field} must be a finite number")
    result = float(value)
    if not math.isfinite(result):
        raise ValueError(f"{field} must be a finite number")
    return result


def execution_limits(data: Mapping[str, Any]) -> dict[str, int]:
    limits = {
        name: integer_setting(data.get(name, default), f"execution.{name}")
        for name, default in (
            ("max_workers", 4),
            ("max_output_bytes", 16 * 1024 * 1024),
            ("max_scan_seconds", 0),
            ("max_scan_memory_bytes", 0),
        )
    }
    if not 1 <= limits["max_workers"] <= 16:
        raise ValueError("execution.max_workers must be between 1 and 16")
    if limits["max_output_bytes"] < 1024:
        raise ValueError("execution.max_output_bytes must be at least 1024")
    if not 0 <= limits["max_scan_seconds"] <= 86400:
        raise ValueError("execution.max_scan_seconds must be between 0 and 86400")
    if (
        limits["max_scan_memory_bytes"]
        and limits["max_scan_memory_bytes"] < 64 * 1024**2
    ):
        raise ValueError("execution.max_scan_memory_bytes must be 0 or at least 64 MiB")
    return limits


def protect_scan_deadline(
    organization: Mapping[str, Any], repository: Mapping[str, Any]
) -> None:
    approved = integer_setting(
        organization.get("max_scan_seconds", 0), "execution.max_scan_seconds"
    )
    requested = integer_setting(
        repository.get("max_scan_seconds", approved), "execution.max_scan_seconds"
    )
    if approved and (not requested or requested > approved):
        raise ValueError(
            "repository configuration cannot weaken the organization scan deadline"
        )
    approved_memory = integer_setting(
        organization.get("max_scan_memory_bytes", 0), "execution.max_scan_memory_bytes"
    )
    requested_memory = integer_setting(
        repository.get("max_scan_memory_bytes", approved_memory),
        "execution.max_scan_memory_bytes",
    )
    if approved_memory and (not requested_memory or requested_memory > approved_memory):
        raise ValueError(
            "repository configuration cannot weaken the organization scan memory budget"
        )
