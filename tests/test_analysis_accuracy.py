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
from py_security_suite.code_health import analyze_code_health
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
    findings, artifact = framework_model_coverage(
        tmp_path, [_run("semgrep", ToolStatus.COMPLETED)], [canary_finding]
    )

    assert findings == []
    assert artifact["complete"] is True
    assert artifact["frameworks"][0]["completed_model_engines"] == ["semgrep"]
    assert artifact["qualified_canary_finding_ids"] == ["finding-1"]
    validate_governed_artifacts({"framework-model-coverage.json": artifact})


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


def test_architecture_history_reports_strong_temporal_coupling(tmp_path: Path) -> None:
    (tmp_path / ".git").mkdir()
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "left.py").write_text("left = 1\n", encoding="utf-8")
    (tmp_path / "src" / "right.py").write_text("right = 1\n", encoding="utf-8")
    payload = "\n".join(
        f"commit:{index:040x}\nsrc/left.py\nsrc/right.py\n" for index in range(8)
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
        findings, artifact = architecture_history(tmp_path, [])

    assert artifact["complete"] is True
    assert artifact["temporal_couplings"][0]["coupling_ratio"] == 1.0
    assert findings[0].classifications == ["ARCH-TEMPORAL-COUPLING"]
    validate_governed_artifacts({"architecture-history.json": artifact})


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
