from __future__ import annotations

import hashlib
import re
from typing import Any

from .strict_json import canonical_bytes

_DIGEST = re.compile(r"[0-9a-f]{64}")


def verify_control_proof(value: object, required_features: set[str]) -> dict[str, Any]:
    """Bind semantic feature claims to concrete case and observation commitments."""

    if (
        not isinstance(value, dict)
        or set(value) != {"schema_version", "controls", "proof_sha256"}
        or value.get("schema_version") != "1.0"
        or not isinstance(value.get("controls"), dict)
    ):
        raise ValueError("structured control proof fields do not match")
    subject = {"schema_version": "1.0", "controls": value["controls"]}
    if (
        value.get("proof_sha256")
        != hashlib.sha256(canonical_bytes(subject)).hexdigest()
    ):
        raise ValueError("structured control proof commitment does not match")
    controls = value["controls"]
    if set(controls) != required_features:
        raise ValueError(
            "structured control proof does not cover the required features"
        )
    for name, record in controls.items():
        if (
            not isinstance(name, str)
            or not name
            or not isinstance(record, dict)
            or set(record)
            != {"cases", "failed_cases", "case_ids_sha256", "observations_sha256"}
            or isinstance(record.get("cases"), bool)
            or not isinstance(record.get("cases"), int)
            or record["cases"] < 1
            or isinstance(record.get("failed_cases"), bool)
            or not isinstance(record.get("failed_cases"), int)
            or not 0 <= record["failed_cases"] <= record["cases"]
            or _DIGEST.fullmatch(str(record.get("case_ids_sha256") or "")) is None
            or _DIGEST.fullmatch(str(record.get("observations_sha256") or "")) is None
        ):
            raise ValueError("structured control proof record is invalid")
    return value
