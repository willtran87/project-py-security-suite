from __future__ import annotations

import json

from jsonschema import Draft202012Validator

from scripts.generate_architecture_assurance import build_architecture_assurance
from py_security_suite.report_inspection import read_bundled_schema


def test_architecture_assurance_matches_enforced_ratchets() -> None:
    result = build_architecture_assurance()
    assert result["module_boundaries"] >= 143
    assert len(result["cyclic_components"]) <= 1
    assert result["concentration"]["files"]
    assert result["concentration"]["functions"]
    assert all(
        item["observed_lines"] == item["maximum_lines"]
        for item in result["concentration"]["files"]
    )
    assert all(
        item["maximum_lines"] is None
        or item["observed_lines"] == item["maximum_lines"]
        for item in result["concentration"]["functions"]
    )
    assert all(
        item["maximum_decisions"] is None
        or item["observed_decisions"] == item["maximum_decisions"]
        for item in result["concentration"]["functions"]
    )
    Draft202012Validator(
        json.loads(read_bundled_schema("architecture-assurance-1.0"))
    ).validate(result)
