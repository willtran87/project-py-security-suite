from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from py_security_suite.assurance_catalog import (
    AssuranceCatalogError,
    build_standards_source_manifest,
    export_assurance_catalog,
)
from py_security_suite.industry_assurance import _validate_policy
from py_security_suite.report_inspection import read_bundled_schema


def test_catalog_export_is_complete_deterministic_and_schema_valid() -> None:
    first = export_assurance_catalog()
    second = export_assurance_catalog()

    assert first == second
    assert first["counts"]["standards"] == 481
    assert first["counts"]["benchmarks"] == 182
    assert first["counts"]["adapter_specs"] == 100
    assert first["counts"]["execution_contracts"] == 100
    assert len(first["catalog_sha256"]) == 64
    schema = json.loads(read_bundled_schema("assurance-catalog-export-1.0"))
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(first)


def test_standards_manifest_builder_verifies_baselines_and_impact(
    tmp_path: Path,
) -> None:
    baseline = tmp_path / "owasp-asvs.html"
    baseline.write_text("publisher snapshot", encoding="utf-8")
    inventory = {
        "schema_version": "1.0",
        "baselines": [
            {
                "id": "OWASP-ASVS",
                "publisher": "OWASP Foundation",
                "baseline_path": baseline.name,
                "baseline_sha256": hashlib.sha256(baseline.read_bytes()).hexdigest(),
                "media_type": "text/html",
                "maximum_bytes": 4096,
            }
        ],
    }
    path = tmp_path / "inventory.json"
    path.write_text(json.dumps(inventory), encoding="utf-8")

    manifest = build_standards_source_manifest(path, selected_ids={"OWASP-ASVS"})

    assert manifest["allowed_hosts"] == ["owasp.org"]
    assert (
        manifest["sources"][0]["baseline_sha256"]
        == inventory["baselines"][0]["baseline_sha256"]
    )
    assert manifest["sources"][0]["impact"]["profiles"]
    schema = json.loads(read_bundled_schema("standards-source-manifest-1.0"))
    Draft202012Validator(schema).validate(manifest)

    inventory["baselines"][0]["baseline_sha256"] = "0" * 64
    path.write_text(json.dumps(inventory), encoding="utf-8")
    with pytest.raises(AssuranceCatalogError, match="digest does not match"):
        build_standards_source_manifest(path, selected_ids={"OWASP-ASVS"})


def test_new_policy_and_preparation_examples_match_their_contracts() -> None:
    examples = Path("examples")
    policy = json.loads(
        (examples / "industry-assurance-policy-1.3.example.json").read_text(
            encoding="utf-8"
        )
    )
    request = json.loads(
        (examples / "benchmark-preparation-request.example.json").read_text(
            encoding="utf-8"
        )
    )

    _validate_policy(policy)
    Draft202012Validator(
        json.loads(read_bundled_schema("industry-assurance-policy-1.3"))
    ).validate(policy)
    Draft202012Validator(
        json.loads(read_bundled_schema("benchmark-preparation-request-1.0"))
    ).validate(request)
