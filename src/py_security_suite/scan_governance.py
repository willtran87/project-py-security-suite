"""Replay and timestamp authority prerequisites for scan admission."""

from __future__ import annotations

import os
from typing import Any


def production_state_errors(
    profile: str, derived_artifacts: dict[str, Any]
) -> list[str]:
    context_errors: list[str] = []
    if profile in {"production", "release"} and has_local_monotonic_receipt(
        derived_artifacts
    ):
        context_errors.append(
            "deployment authority generations require an external monotonic CAS backend"
        )
    if profile in {"production", "release"}:
        anchored_state = (
            "PYSEC_OPERATION_RECEIPT_STATE_PATH",
            "PYSEC_OPERATION_RECEIPT_MIN_SEQUENCE",
            "PYSEC_OPERATION_RECEIPT_CHECKPOINT_SHA256",
            "PYSEC_TRUSTED_TIME_STATE_PATH",
            "PYSEC_TRUSTED_TIME_MIN_SEQUENCE",
            "PYSEC_TRUSTED_TIME_CHECKPOINT_SHA256",
        )
        missing_state = [name for name in anchored_state if not os.environ.get(name)]
        if missing_state:
            context_errors.append(
                "production replay and trusted-time state lacks deployment anchors: "
                + ", ".join(missing_state)
            )
        external_checkpoints = (
            (
                "PYSEC_OPERATION_RECEIPT_CHECKPOINT",
                "PYSEC_OPERATION_RECEIPT_REQUIRE_EXTERNAL_CHECKPOINT",
            ),
            (
                "PYSEC_TRUSTED_TIME_CHECKPOINT",
                "PYSEC_TRUSTED_TIME_REQUIRE_EXTERNAL_CHECKPOINT",
            ),
        )
        missing_external = [
            prefix
            for prefix, required_name in external_checkpoints
            if os.environ.get(required_name) != "1"
            or not os.environ.get(f"{prefix}_COMMAND_JSON")
            or not os.environ.get(f"{prefix}_AUTHORITY_KEY_SHA256")
            or not os.environ.get(f"{prefix}_FAILURE_DOMAIN_JSON")
        ]
        if missing_external:
            context_errors.append(
                "production monotonic state lacks independently attested external "
                "checkpoint authorities: " + ", ".join(missing_external)
            )
        else:
            try:
                from .failure_domain import require_independent_failure_domains
                from .strict_json import loads as strict_loads

                operation_domain = strict_loads(
                    os.environ["PYSEC_OPERATION_RECEIPT_CHECKPOINT_FAILURE_DOMAIN_JSON"]
                )
                time_domain = strict_loads(
                    os.environ["PYSEC_TRUSTED_TIME_CHECKPOINT_FAILURE_DOMAIN_JSON"]
                )
                require_independent_failure_domains(
                    operation_domain,
                    time_domain,
                    labels=(
                        "operation checkpoint authority",
                        "trusted-time checkpoint authority",
                    ),
                )
            except (KeyError, TypeError, ValueError):
                context_errors.append(
                    "production checkpoint authorities do not span independent "
                    "organization, host, control-plane, and implementation domains"
                )

    return context_errors


def has_local_monotonic_receipt(value: object) -> bool:
    if isinstance(value, dict):
        state = value.get("monotonic_state")
        if isinstance(state, dict) and state.get("mode") == "local-sqlite":
            return True
        return any(has_local_monotonic_receipt(item) for item in value.values())
    if isinstance(value, list):
        return any(has_local_monotonic_receipt(item) for item in value)
    return False
