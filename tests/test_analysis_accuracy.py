from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

from py_security_suite.application_contracts import analyze_application_contracts
from py_security_suite.artifact_validation import validate_governed_artifacts
from py_security_suite.architecture_history import architecture_history
from py_security_suite.capability_manifest import capability_manifest
from py_security_suite.code_health import analyze_code_health, _retain_ranked_issues
from py_security_suite.finding_validation import apply_finding_validation
from py_security_suite.framework_coverage import framework_model_coverage
from py_security_suite.models import (
    Confidence,
    Finding,
    Location,
    Severity,
    Source,
    ToolRun,
    ToolStatus,
    ValidationStatus,
)
from py_security_suite.strict_json import canonical_bytes
from py_security_suite.static_architecture import analyze_static_architecture


def test_framework_import_without_manifest_is_fail_visible(tmp_path: Path) -> None:
    source = tmp_path / "app.py"
    source.write_text("from fastapi import FastAPI\n", encoding="utf-8")

    findings, artifact = framework_model_coverage(
        tmp_path, [_run("semgrep", ToolStatus.COMPLETED)], []
    )

    assert artifact["frameworks_detected"] == 1
    assert artifact["complete"] is False
    assert findings[0].sources[0].tool == "framework-model-coverage"


def test_repository_framework_models_are_digest_bound_and_canary_qualified() -> None:
    # Mutation runners copy the test module under a synthetic source tree while
    # retaining the repository as the working directory. Resolve governed model
    # subjects from that stable execution boundary, not from ``__file__``.
    repository = Path.cwd().resolve()
    assert (repository / ".pysec-models.json").is_file()
    grpc = _finding("semgrep")
    grpc.finding_id = "grpc-canary"
    grpc.sources[0].rule_id = "python.grpc-insecure-channel"
    grpc.locations = [
        Location(path="security/framework-canaries/grpc-positive.py", start_line=8)
    ]
    psycopg = _finding("semgrep")
    psycopg.finding_id = "psycopg-canary"
    psycopg.sources[0].rule_id = "python.psycopg-sql-composition"
    psycopg.locations = [
        Location(path="security/framework-canaries/psycopg-positive.py", start_line=8)
    ]

    findings, artifact = framework_model_coverage(
        repository,
        [_run("semgrep", ToolStatus.COMPLETED)],
        [grpc, psycopg],
    )

    assert findings == []
    assert artifact["complete"] is True
    assert artifact["frameworks_detected"] == 2
    assert artifact["frameworks_modeled"] == 2
    assert artifact["qualified_canary_finding_ids"] == [
        "grpc-canary",
        "psycopg-canary",
    ]


def test_framework_manifest_requires_bound_canaries_and_completed_engine(
    tmp_path: Path,
) -> None:
    (tmp_path / "app.py").write_text("import fastapi\n", encoding="utf-8")
    subjects = {}
    for name, payload in (
        ("model.yml", "models: []\n"),
        ("positive.py", "unsafe = True\n"),
        ("negative.py", "unsafe = False\n"),
    ):
        (tmp_path / name).write_text(payload, encoding="utf-8")
        subjects[name] = hashlib.sha256((tmp_path / name).read_bytes()).hexdigest()
    (tmp_path / ".pysec-models.json").write_text(
        json.dumps(
            {
                "schema_version": "1.1",
                "models": [
                    {
                        "framework": "fastapi",
                        "engine": "semgrep",
                        "model_path": "model.yml",
                        "model_sha256": subjects["model.yml"],
                        "positive_canary_path": "positive.py",
                        "positive_canary_sha256": subjects["positive.py"],
                        "negative_canary_path": "negative.py",
                        "negative_canary_sha256": subjects["negative.py"],
                        "expected_rule_ids": ["framework-rule"],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    canary_finding = _finding("semgrep")
    canary_finding.sources[0].rule_id = "framework-rule"
    canary_finding.locations = [Location(path="positive.py", start_line=1)]
    locationless = _finding("semgrep")
    locationless.locations = []
    multiple_paths = _finding("semgrep")
    multiple_paths.locations = [
        Location(path="positive.py", start_line=1),
        Location(path="negative.py", start_line=1),
    ]
    findings, artifact = framework_model_coverage(
        tmp_path,
        [_run("semgrep", ToolStatus.COMPLETED)],
        [canary_finding, locationless, multiple_paths],
    )

    assert findings == []
    assert artifact["complete"] is True
    assert artifact["frameworks"][0]["completed_model_engines"] == ["semgrep"]
    assert artifact["qualified_canary_finding_ids"] == ["finding-1"]
    validate_governed_artifacts({"framework-model-coverage.json": artifact})


def test_framework_coverage_rejects_unverified_and_malformed_models(
    tmp_path: Path,
) -> None:
    (tmp_path / "app.py").write_text("from flask import Flask\n", encoding="utf-8")
    (tmp_path / "invalid.py").write_text("import (\n", encoding="utf-8")
    subjects: dict[str, str] = {}
    for name, payload in (
        ("model.yml", "models: []\n"),
        ("positive.py", "unsafe = True\n"),
        ("negative.py", "unsafe = False\n"),
    ):
        (tmp_path / name).write_text(payload, encoding="utf-8")
        subjects[name] = hashlib.sha256((tmp_path / name).read_bytes()).hexdigest()

    model = {
        "framework": "flask",
        "engine": "semgrep",
        "model_path": "model.yml",
        "model_sha256": "0" * 64,
        "positive_canary_path": "positive.py",
        "positive_canary_sha256": subjects["positive.py"],
        "negative_canary_path": "negative.py",
        "negative_canary_sha256": subjects["negative.py"],
        "expected_rule_ids": ["flask-rule"],
    }
    manifest = tmp_path / ".pysec-models.json"
    manifest.write_text(
        json.dumps({"schema_version": "1.1", "models": [model]}), encoding="utf-8"
    )
    findings, artifact = framework_model_coverage(
        tmp_path, [_run("semgrep", ToolStatus.COMPLETED)], []
    )
    assert "digest verification failed" in findings[0].description
    assert artifact["parse_errors"] == ["invalid.py: SyntaxError"]

    model["model_sha256"] = subjects["model.yml"]
    manifest.write_text(
        json.dumps({"schema_version": "1.1", "models": [model]}), encoding="utf-8"
    )
    findings, _ = framework_model_coverage(
        tmp_path, [_run("semgrep", ToolStatus.COMPLETED)], []
    )
    assert "canary outcomes were not observed" in findings[0].description

    manifest.write_text("{", encoding="utf-8")
    _, artifact = framework_model_coverage(tmp_path, [], [])
    assert "manifest could not be read" in artifact["manifest_errors"][0]

    manifest.write_text(json.dumps({"schema_version": "1.1"}), encoding="utf-8")
    _, artifact = framework_model_coverage(tmp_path, [], [])
    assert artifact["manifest_errors"] == ["manifest fields do not match schema 1.0"]

    invalid_model = dict(model)
    invalid_model["framework"] = "unknown"
    manifest.write_text(
        json.dumps({"schema_version": "1.1", "models": ["invalid", invalid_model]}),
        encoding="utf-8",
    )
    _, artifact = framework_model_coverage(tmp_path, [], [])
    assert len(artifact["manifest_errors"]) == 2


def test_validation_tier_does_not_treat_missing_runtime_as_false_positive() -> None:
    finding = _finding("codeql")
    finding.evidence["sarif_code_flows"] = [
        {
            "step_count": 2,
            "steps": [
                {"path": "src/source.py", "line": 1},
                {"path": "src/app.py", "line": 1},
            ],
        }
    ]

    artifact = apply_finding_validation([finding], {})

    assert finding.validation_status is ValidationStatus.STATIC_PATH_CONFIRMED
    assert (
        "runtime" in finding.validation_limitations[0].casefold()
        or "static" in finding.validation_limitations[0].casefold()
    )
    assert artifact["summary"]["reproduced"] == 0
    validate_governed_artifacts({"finding-validation.json": artifact})


def test_runtime_tier_requires_an_exact_graph_bound_location() -> None:
    finding = _finding("codeql")
    edge = {
        "source": "src/app.py",
        "line": 1,
        "kind": "network-endpoint",
        "target": "https://example.test",
        "language": "python",
    }
    edge_sha256 = hashlib.sha256(canonical_bytes(edge)).hexdigest()

    apply_finding_validation(
        [finding],
        {
            "boundary-graph.json": {"edges": [edge]},
            "runtime-trace-correlation.json": {
                "complete": True,
                "traces": [{"edge_sha256": edge_sha256}],
            },
        },
    )

    assert finding.validation_status is ValidationStatus.RUNTIME_OBSERVED
    assert finding.evidence["validation"]["runtime_trace_locations"] == ["src/app.py:1"]


def test_reproducing_companion_promotes_validation_tier() -> None:
    finding = _finding("iast")
    finding.evidence["reproduction_binding"] = {
        "schema_version": "1.0",
        "source_sha256": "a" * 64,
        "finding_fingerprint": "fingerprint-1",
        "path": "src/app.py",
        "line": 1,
        "payload_sha256": "b" * 64,
        "oracle": "sensitive row returned",
        "impact_observed": True,
        "negative_control_passed": True,
        "environment_sha256": "c" * 64,
        "deployment_sha256": "d" * 64,
    }

    apply_finding_validation(
        [finding], {"source-inventory.json": {"source_sha256": "a" * 64}}
    )

    assert finding.validation_status is ValidationStatus.REPRODUCED


def test_reproducing_tool_without_bound_proof_is_only_runtime_observed() -> None:
    finding = _finding("iast")

    artifact = apply_finding_validation([finding], {})

    assert finding.validation_status is ValidationStatus.RUNTIME_OBSERVED
    assert artifact["summary"]["reproduced"] == 0


def test_reproduction_bindings_reject_every_unsealed_proof_dimension() -> None:
    finding = _finding("iast")
    long_fingerprint = "x" * 201
    finding.evidence["cross_tool_corroboration"] = {
        "independent_perspectives": 2,
        "observations": [{"fingerprint": long_fingerprint}],
    }
    finding.evidence["sarif_code_flows"] = [
        {
            "step_count": 2,
            "steps": [
                {"path": "src/source.py", "line": 1, "kinds": ["source"]},
                {"path": "src/app.py", "line": 1},
            ],
        }
    ]
    valid: dict[str, Any] = {
        "schema_version": "1.0",
        "source_sha256": "a" * 64,
        "finding_fingerprint": finding.fingerprint,
        "path": "src/app.py",
        "line": 1,
        "payload_sha256": "b" * 64,
        "oracle": "sensitive row returned",
        "impact_observed": True,
        "negative_control_passed": True,
        "environment_sha256": "c" * 64,
        "deployment_sha256": "d" * 64,
    }

    def changed(**values: Any) -> dict[str, Any]:
        return {**valid, **values}

    bindings: list[Any] = [
        "not-an-object",
        changed(schema_version="2.0"),
        changed(source_sha256="f" * 64),
        changed(finding_fingerprint="not-retained"),
        changed(finding_fingerprint=long_fingerprint),
        changed(line=True),
        changed(payload_sha256="invalid"),
        changed(oracle=""),
        changed(impact_observed=False),
        changed(negative_control_passed=False),
        valid,
    ]
    bindings.extend(["overflow"] * 90)
    finding.evidence["reproduction_bindings"] = bindings

    artifact = apply_finding_validation(
        [finding],
        {
            "source-inventory.json": {"source_sha256": "a" * 64},
            "runtime-trace-correlation.json": {
                "complete": True,
                "deployment_sha256": "e" * 64,
                "traces": [None, {"edge_sha256": "missing"}],
            },
            "boundary-graph.json": {"edges": []},
        },
    )

    validation = finding.evidence["validation"]
    assert finding.validation_status is ValidationStatus.REPRODUCED
    assert validation["dimensions"]["attacker_control"] == "established"
    assert validation["dimensions"]["production_environment_parity"] == "conflicting"
    assert len(validation["reproduction_bindings_rejected"]) == 100
    assert artifact["summary"]["reproduced"] == 1


def test_code_health_detects_deep_control_flow(tmp_path: Path) -> None:
    conditions = "\n".join(
        f"    {'    ' * index}if value > {index}:" for index in range(7)
    )
    returns = "    " * 8 + "return value\n"
    (tmp_path / "complex.py").write_text(
        "def complex_path(value):\n" + conditions + "\n" + returns,
        encoding="utf-8",
    )

    findings, artifact = analyze_code_health(tmp_path)

    assert artifact["files_analyzed"] == 1
    assert any(item["kind"] == "cognitive-complexity" for item in artifact["issues"])
    assert any(
        finding.classifications == ["CODE-COGNITIVE-COMPLEXITY"] for finding in findings
    )
    validate_governed_artifacts({"code-health.json": artifact})


def test_code_health_consolidates_correlated_symptoms_into_root_causes(
    tmp_path: Path,
) -> None:
    nested = "\n".join(f"    {'    ' * index}if value > {index}:" for index in range(7))
    body = nested + "\n" + "    " * 8 + "return value\n"
    body += "\n".join("    value += 1" for _ in range(101)) + "\n"
    (tmp_path / "service.py").write_text(
        "def coordinate(value):\n" + body, encoding="utf-8"
    )

    _, artifact = analyze_code_health(tmp_path)

    cluster = next(
        item
        for item in artifact["root_cause_clusters"]
        if item["family"] == "function-complexity"
    )
    assert artifact["schema_version"] == "1.4"
    assert cluster["symbol"] == "coordinate"
    assert cluster["issue_count"] >= 3
    assert {"cognitive-complexity", "deep-nesting", "long-function"}.issubset(
        cluster["issue_kinds"]
    )
    assert cluster["priority"] in {"p0", "p1"}
    validate_governed_artifacts({"code-health.json": artifact})


def test_code_health_covers_size_coupling_and_clone_boundaries(
    tmp_path: Path,
) -> None:
    (tmp_path / "invalid.py").write_text("def broken(:\n", encoding="utf-8")
    oversized_body = "\n".join("    a += 1" for _ in range(101))
    (tmp_path / "oversized.py").write_text(
        "def oversized(a, b, c, d, e, f, g, h, i, *args, **kwargs):\n"
        + oversized_body
        + "\n    return a\n",
        encoding="utf-8",
    )
    (tmp_path / "giant.py").write_text(
        "class Giant:\n"
        + "\n".join(f"    field_{index} = {index}" for index in range(800))
        + "\n",
        encoding="utf-8",
    )
    copied = (
        "def copied(value):\n"
        + "\n".join(f"    value += {index}" for index in range(11))
        + "\n    return value\n"
    )
    (tmp_path / "copy_a.py").write_text(copied, encoding="utf-8")
    (tmp_path / "copy_b.py").write_text(copied, encoding="utf-8")

    def semantic_clone(name: str, parameter: str, local: str, offset: int) -> str:
        assignments = "\n".join(
            f"    {local}_{index} = {parameter} + {index + offset}"
            for index in range(19)
        )
        return f"def {name}({parameter}):\n{assignments}\n    return {local}_18\n"

    (tmp_path / "semantic_a.py").write_text(
        semantic_clone("calculate", "source", "value", 1), encoding="utf-8"
    )
    (tmp_path / "semantic_b.py").write_text(
        semantic_clone("derive", "input_value", "result", 101), encoding="utf-8"
    )

    findings, artifact = analyze_code_health(tmp_path)

    kinds = {item["kind"] for item in artifact["issues"]}
    assert {
        "duplicate-function",
        "large-class",
        "long-function",
        "parameter-coupling",
        "semantic-clone",
    }.issubset(kinds)
    assert artifact["complete"] is False
    assert artifact["parse_errors_detected"] == 1
    assert any(
        "Matching implementations" in finding.description for finding in findings
    )
    validate_governed_artifacts({"code-health.json": artifact})


def test_architecture_history_reports_strong_temporal_coupling(tmp_path: Path) -> None:
    (tmp_path / ".git").mkdir()
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "left.py").write_text("left = 1\n", encoding="utf-8")
    (tmp_path / "src" / "right.py").write_text("right = 1\n", encoding="utf-8")
    payload = "\n".join(
        f"commit:{index:040x}\nsrc/left.py\nsrc/right.py\n" for index in range(10)
    )
    execution = SimpleNamespace(
        exit_code=0,
        timed_out=False,
        output_limit_exceeded=False,
        stdout=payload,
    )
    with (
        patch(
            "py_security_suite.architecture_history.resolve_executable",
            return_value="git",
        ),
        patch(
            "py_security_suite.architecture_history.run_command", return_value=execution
        ),
    ):
        architecture_finding = _finding("tach")
        architecture_finding.locations = [Location(path="src/left.py", start_line=1)]
        findings, artifact = architecture_history(tmp_path, [architecture_finding])

    assert artifact["complete"] is True
    assert artifact["temporal_couplings"][0]["coupling_ratio"] == 1.0
    assert (
        artifact["temporal_couplings"][0]["overlaps_architecture_contract_violation"]
        is True
    )
    assert artifact["change_risk_hotspots"][0]["path"] == "src/left.py"
    assert findings[0].classifications == ["ARCH-TEMPORAL-COUPLING"]
    assert findings[-1].classifications == ["ARCH-CHANGE-RISK-HOTSPOT"]
    validate_governed_artifacts({"architecture-history.json": artifact})


def test_architecture_history_is_fail_visible_without_usable_git(
    tmp_path: Path,
) -> None:
    findings, artifact = architecture_history(tmp_path, [])
    assert findings == []
    assert artifact["complete"] is False

    (tmp_path / ".git").mkdir()
    execution = SimpleNamespace(
        exit_code=1,
        timed_out=False,
        output_limit_exceeded=False,
        stdout="",
    )
    with (
        patch(
            "py_security_suite.architecture_history.resolve_executable",
            return_value="git",
        ),
        patch(
            "py_security_suite.architecture_history.run_command", return_value=execution
        ),
    ):
        findings, artifact = architecture_history(tmp_path, [])
    assert findings == []
    assert artifact["complete"] is False


def test_capability_manifest_separates_selection_from_execution() -> None:
    artifact = capability_manifest(
        "standard",
        [
            _run("bandit", ToolStatus.COMPLETED),
            _run("semgrep", ToolStatus.UNAVAILABLE),
            _run("detect-secrets", ToolStatus.COMPLETED),
            _run("osv-scanner", ToolStatus.SKIPPED, applicable=False),
        ],
    )

    assert artifact["selected_tool_count"] == 4
    assert artifact["completed_tool_count"] == 2
    assert artifact["execution_gaps"] == ["semgrep"]
    assert artifact["layers"]["architecture"]["selected"] is False
    assert artifact["layers"]["supply_chain"]["selected"] is True
    validate_governed_artifacts({"capability-manifest.json": artifact})


def test_application_contracts_detect_auth_drift_and_exact_vulnerable_call(
    tmp_path: Path,
) -> None:
    (tmp_path / "app.py").write_text(
        "from vulnerable.lib import dangerous as invoke\n"
        "def run_update(tenant_id):\n"
        "    return invoke(tenant_id)\n"
        "@app.post('/tenants/{tenant_id}')\n"
        "def update_tenant(tenant_id):\n"
        "    return run_update(tenant_id)\n",
        encoding="utf-8",
    )
    security = tmp_path / "security"
    baseline = security / "baselines"
    baseline.mkdir(parents=True)
    operation: dict[str, Any] = {
        "paths": {
            "/tenants/{tenant_id}": {
                "post": {
                    "security": [],
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "name": {"type": "string", "minLength": 1},
                                        "selector": {
                                            "enum": [
                                                {"kind": "owner"},
                                                {"kind": "member"},
                                                {"kind": "guest"},
                                            ]
                                        },
                                    },
                                }
                            }
                        }
                    },
                }
            }
        }
    }
    (tmp_path / "openapi.json").write_text(json.dumps(operation), encoding="utf-8")
    operation["paths"]["/tenants/{tenant_id}"]["post"]["security"] = [{"bearer": []}]
    schema = operation["paths"]["/tenants/{tenant_id}"]["post"]["requestBody"][
        "content"
    ]["application/json"]["schema"]
    schema["required"] = ["name"]
    schema["properties"]["name"]["minLength"] = 3
    schema["properties"]["selector"]["enum"] = [
        {"kind": "owner"},
        {"kind": "member"},
    ]
    (baseline / "openapi.json").write_text(json.dumps(operation), encoding="utf-8")
    (security / "application-contracts.json").write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "endpoints": [
                    {
                        "method": "POST",
                        "path": "/tenants/{tenant_id}",
                        "tenant_scoped": True,
                        "allow_test_ids": ["allow-owner"],
                        "deny_test_ids": ["deny-anonymous"],
                        "cross_tenant_test_ids": ["deny-other-tenant"],
                    }
                ],
                "vulnerable_functions": [
                    {
                        "package": "vulnerable",
                        "advisory_id": "GHSA-fixture",
                        "symbols": ["vulnerable.lib.dangerous"],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    evidence = {
        "source-inventory.json": {"source_sha256": "a" * 64},
        "authorization-security.json": {
            "source_sha256": "a" * 64,
            "cases": [
                {"id": "allow-owner", "result": "passed"},
                {"id": "deny-anonymous", "result": "passed"},
                {"id": "deny-other-tenant", "result": "passed"},
            ],
        },
    }

    findings, artifact = analyze_application_contracts(tmp_path, evidence)

    classifications = {finding.classifications[0] for finding in findings}
    assert "API-AUTHORIZATION-REGRESSION" in classifications
    assert "API-REQUEST-CONTRACT-WEAKENED" in classifications
    assert "VULNERABLE-FUNCTION-CALL" in classifications
    assert "BUSINESS-LOGIC-EVIDENCE-GAP" not in classifications
    assert artifact["business_logic"][0]["complete"] is True
    assert artifact["vulnerable_call_matches"][0]["symbol"] == (
        "vulnerable.lib.dangerous"
    )
    assert artifact["vulnerable_call_matches"][0]["entrypoint_reachable"] is True
    assert artifact["vulnerable_call_matches"][0]["call_chain"] == [
        "app.update_tenant",
        "app.run_update",
        "vulnerable.lib.dangerous",
    ]
    scenario_kinds = {
        scenario["kind"] for scenario in artifact["generated_test_scenarios"]
    }
    assert {
        "constraint-boundary",
        "cross-tenant-deny",
        "replay-safety",
    } == scenario_kinds
    replay = next(
        item
        for item in artifact["generated_test_scenarios"]
        if item["kind"] == "replay-safety"
    )
    assert replay["subjects"] == [
        "request-body",
        "idempotency-key",
        "resource-state",
    ]
    assert replay["execution"] == {
        "actor": "authorized-principal",
        "oracle": "state-invariant",
        "consumers": ["authorization-security"],
        "repeat": 2,
        "source_bound_evidence_required": True,
    }
    assert any(
        regression["subject"].endswith(":enum-expanded-or-removed")
        for regression in artifact["openapi"]["contract_regressions"]
    )
    validate_governed_artifacts({"application-contract-analysis.json": artifact})


def test_application_contracts_require_deny_and_tenant_isolation_evidence(
    tmp_path: Path,
) -> None:
    security = tmp_path / "security"
    security.mkdir()
    (security / "application-contracts.json").write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "endpoints": [
                    {
                        "method": "GET",
                        "path": "/accounts/{account_id}",
                        "tenant_scoped": True,
                        "allow_test_ids": ["allow-owner"],
                        "deny_test_ids": ["deny-anonymous"],
                        "cross_tenant_test_ids": [],
                    }
                ],
                "vulnerable_functions": [],
            }
        ),
        encoding="utf-8",
    )

    findings, artifact = analyze_application_contracts(
        tmp_path,
        {
            "source-inventory.json": {"source_sha256": "a" * 64},
            "junit-summary.json": {
                "source_sha256": "a" * 64,
                "test_cases": [{"id": "allow-owner", "result": "passed"}],
            },
        },
    )

    assert findings[0].classifications[0] == "BUSINESS-LOGIC-EVIDENCE-GAP"
    assert "missing deny evidence" in findings[0].description
    assert "cross-tenant denial obligation" in findings[0].description
    validate_governed_artifacts({"application-contract-analysis.json": artifact})


def test_application_contracts_generate_secured_operation_scenarios(
    tmp_path: Path,
) -> None:
    (tmp_path / "openapi.json").write_text(
        json.dumps(
            {
                "paths": {
                    "/accounts/{tenant_id}": {
                        "get": {
                            "security": [{"bearer": []}],
                            "parameters": [
                                {
                                    "name": "tenant_id",
                                    "in": "path",
                                    "required": True,
                                    "schema": {"type": "string", "minLength": 1},
                                }
                            ],
                        }
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    _, artifact = analyze_application_contracts(tmp_path, {})

    assert {
        "anonymous-deny",
        "authenticated-allow",
        "constraint-boundary",
        "cross-tenant-deny",
        "required-input-negative",
    } == {item["kind"] for item in artifact["generated_test_scenarios"]}


def test_application_contracts_handle_route_variants_and_invalid_source(
    tmp_path: Path,
) -> None:
    (tmp_path / "invalid.py").write_text("def invalid(:\n", encoding="utf-8")
    (tmp_path / "api.py").write_text(
        "import helpers as support\n"
        "from services import execute as run\n"
        "@app.route('/multi', methods=('GET', 'DELETE', 'INVALID'))\n"
        "async def multi():\n"
        "    def nested():\n"
        "        return support.hidden()\n"
        "    return run()\n"
        "@app.api_route('/default')\n"
        "def default_route():\n"
        "    return support.visible()\n"
        "@decorator\n"
        "def ignored():\n"
        "    return None\n",
        encoding="utf-8",
    )

    _, artifact = analyze_application_contracts(tmp_path, {})

    operations = {f"{route['method']} {route['path']}" for route in artifact["routes"]}
    assert operations == {"DELETE /multi", "GET /default", "GET /multi"}
    assert artifact["errors"] == ["invalid.py: SyntaxError"]
    assert artifact["complete"] is False
    validate_governed_artifacts({"application-contract-analysis.json": artifact})


def test_static_architecture_detects_local_dependency_cycle(tmp_path: Path) -> None:
    package = tmp_path / "src" / "sample"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "left.py").write_text("from . import right\n", encoding="utf-8")
    (package / "right.py").write_text("from . import left\n", encoding="utf-8")

    findings, artifact = analyze_static_architecture(tmp_path)

    assert artifact["cycles_detected"] == 1
    assert artifact["cycles"][0]["modules"] == ["sample.left", "sample.right"]
    assert findings[0].classifications == ["ARCH-DEPENDENCY-CYCLE"]
    validate_governed_artifacts({"static-architecture.json": artifact})


def test_static_architecture_ranks_refactoring_targets_and_preserves_semantics(
    tmp_path: Path,
) -> None:
    package = tmp_path / "src" / "sample"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "left.py").write_text("from . import right\n", encoding="utf-8")
    (package / "right.py").write_text("from . import left\n", encoding="utf-8")
    reachability = {
        "schema_version": "1.2",
        "analysis": {"confidence": "high", "complete": True},
        "summary": {"entry_points": 1},
        "entry_points": [{}],
        "islands": [{}, {}],
        "nodes": [{}, {}, {}],
        "edges": [{}, {}],
        "dynamic_features": ["polymorphic-dispatch"],
        "precision_features": [
            "framework-registration-resolution",
            "typed-receiver-resolution",
        ],
        "warnings": [],
        "errors": [],
    }

    _, artifact = analyze_static_architecture(tmp_path, reachability)

    assert artifact["schema_version"] == "1.4"
    assert artifact["refactoring_targets"][0]["kind"] == "dependency-cycle"
    assert artifact["refactoring_targets"][0]["exact_contract_failure"] is False
    assert artifact["semantic_graph"] == {
        "available": True,
        "schema_version": "1.2",
        "confidence": "high",
        "complete": True,
        "nodes": 3,
        "edges": 2,
        "entry_points": 1,
        "islands": 2,
        "precision_features": [
            "framework-registration-resolution",
            "typed-receiver-resolution",
        ],
        "type_aware": True,
        "framework_aware": True,
        "dynamic_features_detected": 1,
        "errors_detected": 0,
    }
    validate_governed_artifacts({"static-architecture.json": artifact})


def test_code_health_policy_adds_nesting_call_and_class_responsibility_signals(
    tmp_path: Path,
) -> None:
    security = tmp_path / "security"
    security.mkdir()
    (security / "code-health-policy.json").write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "thresholds": {
                    "nesting_depth": 1,
                    "function_call_targets": 1,
                    "class_methods": 1,
                },
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "service.py").write_text(
        "def coordinate(value):\n"
        "    if value:\n"
        "        if value > 1:\n"
        "            first()\n"
        "            second()\n"
        "class Service:\n"
        "    def left(self):\n"
        "        return 1\n"
        "    def right(self):\n"
        "        return 2\n",
        encoding="utf-8",
    )

    findings, artifact = analyze_code_health(tmp_path)

    kinds = {item["kind"] for item in artifact["issues"]}
    assert {
        "deep-nesting",
        "excessive-call-coupling",
        "excessive-class-responsibilities",
    }.issubset(kinds)
    assert artifact["policy_present"] is True
    assert artifact["thresholds"]["nesting_depth"] == 1
    assert len(findings) >= 3
    validate_governed_artifacts({"code-health.json": artifact})


def test_static_architecture_enforces_declared_layers_and_forbidden_edges(
    tmp_path: Path,
) -> None:
    package = tmp_path / "src" / "sample"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "api.py").write_text("from . import infrastructure\n", encoding="utf-8")
    (package / "infrastructure.py").write_text("", encoding="utf-8")
    security = tmp_path / "security"
    security.mkdir()
    (security / "architecture-policy.json").write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "layers": [
                    {"name": "api", "modules": ["sample.api"], "may_depend_on": []},
                    {
                        "name": "infrastructure",
                        "modules": ["sample.infrastructure"],
                        "may_depend_on": [],
                    },
                ],
                "forbidden_edges": [
                    {
                        "source": "sample.api",
                        "destination": "sample.infrastructure",
                        "reason": "API layer cannot own persistence adapters",
                    }
                ],
                "thresholds": {"module_fan_out": 1},
            }
        ),
        encoding="utf-8",
    )

    findings, artifact = analyze_static_architecture(tmp_path)

    assert artifact["policy_present"] is True
    assert artifact["policy_violations_detected"] == 2
    assert {item["kind"] for item in artifact["policy_violations"]} == {
        "forbidden-edge",
        "layer-dependency",
    }
    assert any(
        finding.classifications == ["ARCH-POLICY-VIOLATION"] for finding in findings
    )
    validate_governed_artifacts({"static-architecture.json": artifact})


def test_static_architecture_reports_hubs_instability_fanout_and_new_edges(
    tmp_path: Path,
) -> None:
    package = tmp_path / "src" / "sample"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    for index in range(13):
        (package / f"leaf_{index}.py").write_text("", encoding="utf-8")
    (package / "volatile.py").write_text(
        "\n".join(f"from . import leaf_{index}" for index in range(13)) + "\n",
        encoding="utf-8",
    )
    (package / "stable.py").write_text("from . import volatile\n", encoding="utf-8")
    for index in range(21):
        (package / f"consumer_{index}.py").write_text(
            "from . import stable\n", encoding="utf-8"
        )
    (package / "invalid.py").write_text("from . import\n", encoding="utf-8")
    baseline = tmp_path / "security" / "baselines"
    baseline.mkdir(parents=True)
    baseline_path = baseline / "architecture-edges.json"
    baseline_path.write_text("{}", encoding="utf-8")
    _, malformed_artifact = analyze_static_architecture(tmp_path)
    assert (
        "security/baselines/architecture-edges.json: ValueError"
        in (malformed_artifact["parse_errors"])
    )

    baseline_path.write_text(
        json.dumps({"schema_version": "1.0", "edges": []}), encoding="utf-8"
    )

    findings, artifact = analyze_static_architecture(tmp_path)

    classifications = {finding.classifications[0] for finding in findings}
    assert {
        "ARCH-EXCESSIVE-MODULE-FANOUT",
        "ARCH-HIGH-DEGREE-HUB",
        "ARCH-NEW-DEPENDENCY-EDGE",
        "ARCH-STABLE-DEPENDS-ON-UNSTABLE",
    }.issubset(classifications)
    assert artifact["baseline_present"] is True
    assert artifact["new_dependency_edges"]
    assert artifact["parse_errors"] == ["src/sample/invalid.py: SyntaxError"]
    validate_governed_artifacts({"static-architecture.json": artifact})


def test_application_contracts_trace_relative_imports_and_class_wrappers(
    tmp_path: Path,
) -> None:
    package = tmp_path / "src" / "sample"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "api.py").write_text(
        "from .worker import run\n"
        "class Controller:\n"
        "    def delegate(self):\n"
        "        return run()\n"
        "    @router.post('/execute')\n"
        "    def endpoint(self):\n"
        "        return self.delegate()\n",
        encoding="utf-8",
    )
    (package / "worker.py").write_text(
        "from vulnerable import dangerous\ndef run():\n    return dangerous()\n",
        encoding="utf-8",
    )
    security = tmp_path / "security"
    security.mkdir()
    (security / "application-contracts.json").write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "endpoints": [],
                "vulnerable_functions": [
                    {
                        "package": "vulnerable",
                        "advisory_id": "GHSA-wrapper",
                        "symbols": ["vulnerable.dangerous"],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    _, artifact = analyze_application_contracts(tmp_path, {})

    match = artifact["vulnerable_call_matches"][0]
    assert match["entrypoint"] == "POST /execute"
    assert match["call_chain"] == [
        "sample.api.Controller.endpoint",
        "sample.api.Controller.delegate",
        "sample.worker.run",
        "vulnerable.dangerous",
    ]
    validate_governed_artifacts({"application-contract-analysis.json": artifact})


def test_code_health_detects_behavioral_maintainability_risks(tmp_path: Path) -> None:
    (tmp_path / "service.py").write_text(
        "import time\n"
        "cache = {}\n"
        "def clear_cache(): cache.clear()\n"
        "async def refresh():\n"
        "    try:\n"
        "        time.sleep(1)\n"
        "    except Exception:\n"
        "        pass\n"
        "class SplitResponsibilities:\n"
        "    def first(self): return self.alpha\n"
        "    def second(self): return self.beta\n"
        "    def third(self): return self.gamma\n"
        "    def fourth(self): return self.delta\n",
        encoding="utf-8",
    )

    findings, artifact = analyze_code_health(tmp_path)

    kinds = {item["kind"] for item in artifact["issues"]}
    assert {
        "async-blocking-call",
        "low-class-cohesion",
        "module-mutable-globals",
        "swallowed-broad-exception",
    }.issubset(kinds)
    assert {
        "CODE-ASYNC-BLOCKING-CALL",
        "CODE-LOW-CLASS-COHESION",
        "CODE-MUTABLE-GLOBAL-STATE",
        "CODE-SWALLOWED-BROAD-EXCEPTION",
    }.issubset({finding.classifications[0] for finding in findings})
    validate_governed_artifacts({"code-health.json": artifact})


def test_static_architecture_retains_symbol_entrypoint_and_dynamic_import_evidence(
    tmp_path: Path,
) -> None:
    package = tmp_path / "src" / "sample"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "service.py").write_text("def run(): return 1\n", encoding="utf-8")
    (package / "plugin.py").write_text("", encoding="utf-8")
    (package / "api.py").write_text(
        "import importlib\n"
        "from . import service\n"
        "@router.get('/items')\n"
        "def items():\n"
        "    importlib.import_module('.plugin', package=__package__)\n"
        "    return service.run()\n"
        "def load(name):\n"
        "    return importlib.import_module(name)\n",
        encoding="utf-8",
    )

    _, artifact = analyze_static_architecture(tmp_path)

    assert artifact["symbol_edges_detected"] == 1
    assert artifact["symbol_edges"][0]["source"] == "sample.api.items"
    assert artifact["symbol_edges"][0]["destination"] == "sample.service.run"
    assert artifact["dynamic_imports_detected"] == 2
    assert artifact["unresolved_dynamic_imports"] == 1
    assert any(
        item["resolved_module"] == "sample.plugin"
        for item in artifact["dynamic_imports"]
    )
    assert artifact["entrypoint_symbols"][0]["symbol"] == "sample.api.items"
    validate_governed_artifacts({"static-architecture.json": artifact})


def test_code_health_detects_async_lifecycle_and_exception_chain_defects(
    tmp_path: Path,
) -> None:
    (tmp_path / "worker.py").write_text(
        "import asyncio\n"
        "async def fetch(): return 1\n"
        "async def run():\n"
        "    fetch()\n"
        "    client.fetch()\n"
        "    async def nested():\n"
        "        fetch()\n"
        "    asyncio.create_task(fetch())\n"
        "    try:\n"
        "        await fetch()\n"
        "    except asyncio.CancelledError:\n"
        "        pass\n"
        "    try:\n"
        "        raise ValueError('bad')\n"
        "    except ValueError as exc:\n"
        "        raise RuntimeError('translated')\n",
        encoding="utf-8",
    )

    findings, artifact = analyze_code_health(tmp_path)

    kinds = set(artifact["issue_counts_by_kind"])
    assert {
        "discarded-async-task",
        "implicit-exception-chain",
        "swallowed-cancellation",
        "unawaited-async-call",
    }.issubset(kinds)
    assert artifact["issue_counts_by_kind"]["unawaited-async-call"] == 2
    assert artifact["issues_detected"] == artifact["issues_retained"]
    assert artifact["issues_omitted"] == 0
    assert artifact["retention_strategy"] == (
        "severity-kind-diversified-overage-ranking"
    )
    assert {
        "CODE-DISCARDED-ASYNC-TASK",
        "CODE-IMPLICIT-EXCEPTION-CHAIN",
        "CODE-SWALLOWED-CANCELLATION",
        "CODE-UNAWAITED-ASYNC-CALL",
    }.issubset({finding.classifications[0] for finding in findings})
    validate_governed_artifacts({"code-health.json": artifact})


def test_code_health_rejects_invalid_policy_and_retains_each_issue_kind(
    tmp_path: Path,
) -> None:
    security = tmp_path / "security"
    security.mkdir()
    policy = security / "code-health-policy.json"
    policy.write_text('{"unexpected":true}', encoding="utf-8")

    _, malformed = analyze_code_health(tmp_path)

    assert malformed["complete"] is False
    assert malformed["parse_errors"] == ["security/code-health-policy.json: ValueError"]

    policy.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "thresholds": {"function_lines": True},
            }
        ),
        encoding="utf-8",
    )
    _, invalid_threshold = analyze_code_health(tmp_path)
    assert invalid_threshold["parse_errors"] == [
        "security/code-health-policy.json: ValueError"
    ]

    issues = [
        {
            "kind": "long-function",
            "value": 120,
            "threshold": 100,
            "path": "a.py",
            "line": 1,
        },
        {
            "kind": "long-function",
            "value": 150,
            "threshold": 100,
            "path": "b.py",
            "line": 2,
        },
        {
            "kind": "large-class",
            "value": 900,
            "threshold": 800,
            "path": "c.py",
            "line": 3,
        },
        {
            "kind": "semantic-clone",
            "value": 30,
            "threshold": 20,
            "path": "d.py",
            "line": 4,
        },
    ]
    retained = _retain_ranked_issues(issues, 3)
    assert {item["kind"] for item in retained} == {
        "large-class",
        "long-function",
        "semantic-clone",
    }


def test_static_architecture_unifies_packaging_main_and_tach_policy(
    tmp_path: Path,
) -> None:
    package = tmp_path / "src" / "sample"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "core.py").write_text(
        "from .cli import main\ndef run(): return main\n", encoding="utf-8"
    )
    (package / "cli.py").write_text(
        "from .core import run\n"
        "def main(): return run()\n"
        "if __name__ == '__main__': main()\n",
        encoding="utf-8",
    )
    (package / "__main__.py").write_text(
        "from .cli import main\nmain()\n", encoding="utf-8"
    )
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "sample"\nversion = "1"\n'
        '[project.scripts]\nsample = "sample.cli:main"\n',
        encoding="utf-8",
    )
    (tmp_path / "tach.toml").write_text(
        'source_roots = ["src"]\nroot_module = "forbid"\n'
        "forbid_circular_dependencies = true\n"
        '[[modules]]\npath = "sample"\ndepends_on = []\n'
        '[[modules]]\npath = "sample.cli"\ndepends_on = []\n',
        encoding="utf-8",
    )

    findings, artifact = analyze_static_architecture(tmp_path)

    assert artifact["policy_path"] == "tach.toml"
    assert artifact["policy_format"] == "tach"
    assert artifact["policy_violations_detected"] == 4
    assert {item["kind"] for item in artifact["policy_violations"]} == {
        "circular-dependency",
        "undeclared-dependency",
    }
    assert any(
        finding.classifications == ["ARCH-POLICY-VIOLATION"] for finding in findings
    )
    entrypoint_kinds = {item["kind"] for item in artifact["entrypoint_symbols"]}
    assert {"main-guard", "module-main", "packaging-script"}.issubset(entrypoint_kinds)
    assert any(
        item["symbol"] == "sample.cli.main" for item in artifact["entrypoint_symbols"]
    )
    validate_governed_artifacts({"static-architecture.json": artifact})


def test_application_contracts_emit_argv_safe_execution_handoff(
    tmp_path: Path,
) -> None:
    (tmp_path / "openapi.json").write_text(
        json.dumps(
            {
                "openapi": "3.1.0",
                "paths": {
                    "/items": {
                        "post": {
                            "security": [{"bearer": []}],
                            "responses": {"200": {"description": "ok"}},
                        }
                    }
                },
            }
        ),
        encoding="utf-8",
    )

    _, artifact = analyze_application_contracts(tmp_path, {})

    plan = artifact["scenario_execution_plan"]
    assert plan["handoff_complete"] is True
    assert plan["authorized_companion_lane_required"] is True
    assert plan["tasks_detected"] == len(plan["tasks"])
    assert {task["consumer"] for task in plan["tasks"]} == {"authorization-security"}
    assert all(isinstance(task["command"], list) for task in plan["tasks"])
    assert all(task["source_bound_evidence_required"] is True for task in plan["tasks"])
    assert all(
        task["actor"] in {"anonymous", "authorized-principal"} for task in plan["tasks"]
    )
    assert all(
        task["oracle"] in {"allow", "deny", "state-invariant"} for task in plan["tasks"]
    )
    assert "PYSEC_SOURCE_REVISION" in plan["required_environment"]
    validate_governed_artifacts({"application-contract-analysis.json": artifact})


def _finding(tool: str) -> Finding:
    return Finding(
        finding_id="finding-1",
        fingerprint="fingerprint-1",
        title="candidate",
        description="candidate",
        impact="impact",
        remediation="remediation",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        area="security",
        locations=[Location(path="src/app.py", start_line=1)],
        sources=[Source(tool=tool, rule_id="rule", message="message")],
    )


def _run(tool: str, status: ToolStatus, *, applicable: bool = True) -> ToolRun:
    return ToolRun(
        tool=tool,
        status=status,
        command=[tool],
        duration_seconds=0.1,
        applicable=applicable,
    )
