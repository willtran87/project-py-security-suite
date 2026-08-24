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
        or set(value) != {"schema_version", "controls", "case_ledger", "proof_sha256"}
        or value.get("schema_version") != "1.0"
        or not isinstance(value.get("controls"), dict)
        or not isinstance(value.get("case_ledger"), list)
    ):
        raise ValueError("structured control proof fields do not match")
    subject = {
        "schema_version": "1.0",
        "controls": value["controls"],
        "case_ledger": value["case_ledger"],
    }
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
    ledger = value["case_ledger"]
    if not 1 <= len(ledger) <= 10_000:
        raise ValueError("structured control proof case ledger is invalid")
    normalized_cases: list[dict[str, str]] = []
    case_ids: set[str] = set()
    base_fields = {
        "id",
        "target_id",
        "role",
        "control",
        "expected",
        "observed",
        "severity",
        "classification",
    }
    advanced_fields = base_fields | {"rule_id", "stratum", "mutation_operator"}
    for case in ledger:
        if (
            not isinstance(case, dict)
            or frozenset(case)
            not in {frozenset(base_fields), frozenset(advanced_fields)}
            or any(not isinstance(item, str) for item in case.values())
            or any(
                not value or len(value) > 500
                for name, value in case.items()
                if name != "mutation_operator"
            )
            or len(str(case.get("mutation_operator") or "")) > 160
        ):
            raise ValueError("structured control proof case is invalid")
        identifier = str(case["id"])
        if identifier in case_ids:
            raise ValueError("structured control proof case IDs are not unique")
        case_ids.add(identifier)
        normalized_cases.append({str(name): str(item) for name, item in case.items()})
    if {case["control"] for case in normalized_cases} != required_features:
        raise ValueError("structured control proof ledger does not cover the features")
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
        selected = [case for case in normalized_cases if case["control"] == name]
        expected_record = {
            "cases": len(selected),
            "failed_cases": sum(
                case["expected"] != case["observed"] for case in selected
            ),
            "case_ids_sha256": hashlib.sha256(
                canonical_bytes(sorted(case["id"] for case in selected))
            ).hexdigest(),
            "observations_sha256": hashlib.sha256(
                canonical_bytes(selected)
            ).hexdigest(),
        }
        if record != expected_record:
            raise ValueError(
                "structured control proof record does not match its case ledger"
            )
    return value
