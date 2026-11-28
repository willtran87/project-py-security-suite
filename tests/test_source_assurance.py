from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import patch

from py_security_suite.source_assurance import apply_source_assurance


def test_standard_source_assurance_is_complete_and_idempotent(tmp_path: Path) -> None:
    artifacts: dict[str, Any] = {"reachability.json": {"complete": True}}
    framework = {
        "complete": True,
        "frameworks_detected": 0,
        "parse_errors": [],
        "qualified_canary_finding_ids": [],
    }
    contract = {
        "complete": True,
        "contract_present": False,
        "openapi": {"current_path": None},
    }
    with (
        patch(
            "py_security_suite.source_assurance.framework_model_coverage",
            return_value=([], framework),
        ) as framework_stage,
        patch(
            "py_security_suite.source_assurance.analyze_application_contracts",
            return_value=([], contract),
        ) as contract_stage,
        patch(
            "py_security_suite.source_assurance.analyze_code_health",
            return_value=([], {"complete": True}),
        ) as health_stage,
        patch(
            "py_security_suite.source_assurance.analyze_static_architecture",
            return_value=([], {"complete": True}),
        ) as architecture_stage,
        patch(
            "py_security_suite.source_assurance.architecture_history",
            return_value=([], {"complete": True}),
        ) as history_stage,
    ):
        first = apply_source_assurance(
            target=tmp_path,
            profile="standard",
            findings=[],
            tool_runs=[],
            artifacts=artifacts,
        )
        second = apply_source_assurance(
            target=tmp_path,
            profile="standard",
            findings=[],
            tool_runs=[],
            artifacts=artifacts,
        )

    assert first == second == []
    assert {
        "framework-model-coverage.json",
        "application-contract-analysis.json",
        "code-health.json",
        "static-architecture.json",
        "architecture-history.json",
    } <= set(artifacts)
    for stage in (
        framework_stage,
        contract_stage,
        health_stage,
        architecture_stage,
        history_stage,
    ):
        stage.assert_called_once()


def test_release_source_assurance_preserves_fail_closed_gates(tmp_path: Path) -> None:
    framework = {
        "complete": False,
        "frameworks_detected": 1,
        "parse_errors": [],
        "qualified_canary_finding_ids": [],
    }
    contract = {
        "complete": False,
        "contract_present": True,
        "openapi": {"current_path": "openapi.json"},
    }
    with (
        patch(
            "py_security_suite.source_assurance.framework_model_coverage",
            return_value=([], framework),
        ),
        patch(
            "py_security_suite.source_assurance.analyze_application_contracts",
            return_value=([], contract),
        ),
        patch(
            "py_security_suite.source_assurance.analyze_code_health",
            return_value=([], {}),
        ),
        patch(
            "py_security_suite.source_assurance.analyze_static_architecture",
            return_value=([], {}),
        ),
        patch(
            "py_security_suite.source_assurance.architecture_history",
            return_value=([], {}),
        ),
    ):
        errors = apply_source_assurance(
            target=tmp_path,
            profile="release",
            findings=[],
            tool_runs=[],
            artifacts={},
        )

    assert len(errors) == 2
    assert "digest-bound semantic models" in errors[0]
    assert "application contracts" in errors[1]
