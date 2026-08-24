from __future__ import annotations

import math

import pytest

from companion.strict_json import canonical_bytes as companion_canonical_bytes
from companion.strict_json import loads as companion_loads
from py_security_suite.evidence_ingest import _assurance_execution
from py_security_suite.strict_json import canonical_bytes, dumps, loads


@pytest.mark.parametrize(
    "payload",
    [
        '{"value":1,"value":2}',
        '{"value":NaN}',
        '{"value":Infinity}',
        '{"value":-Infinity}',
        '{"value":9007199254740992}',
    ],
)
def test_strict_json_rejects_ambiguous_or_non_interoperable_input(
    payload: str,
) -> None:
    with pytest.raises(ValueError):
        loads(payload)
    with pytest.raises(ValueError):
        companion_loads(payload)


def test_strict_json_rejects_excessive_nesting() -> None:
    payload = "[" * 65 + "0" + "]" * 65

    with pytest.raises(ValueError, match="nesting|safety"):
        loads(payload)
    with pytest.raises(ValueError, match="safety"):
        companion_loads(payload)


def test_canonical_json_is_stable_across_implementations() -> None:
    value = {"z": 1.0, "é": "line\nvalue", "a": [3, True, None]}
    expected = b'{"a":[3,true,null],"z":1,"\xc3\xa9":"line\\nvalue"}'

    assert canonical_bytes(value) == expected
    assert companion_canonical_bytes(value) == expected


def test_serialization_and_execution_metadata_reject_nonfinite_numbers() -> None:
    for value in (math.nan, math.inf, -math.inf):
        with pytest.raises(ValueError, match="finite"):
            dumps({"coverage": value})
        execution = {
            "status": "completed",
            "targets_discovered": 1,
            "targets_exercised": 1,
            "requests": 1,
            "coverage_percent": value,
            "coverage_metric": "cases",
            "roles": ["anonymous"],
            "features": ["canary"],
            "skipped_checks": [],
            "canaries_expected": 1,
            "canaries_observed": 1,
        }
        with pytest.raises(TypeError, match="finite"):
            _assurance_execution(execution, 80.0)
