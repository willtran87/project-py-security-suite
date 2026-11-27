import json
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from py_security_suite.adapters.coverage import native_coverage, reconcile_coverage
from py_security_suite.adapters.semgrep import SemgrepAdapter
from py_security_suite.config import ToolConfig
from py_security_suite.execution import RawExecution
from py_security_suite.models import ToolStatus
from scripts import benchmark_external


def payload():
    return json.dumps(
        {
            "results": [
                {
                    "check_id": "test.rule",
                    "path": "app.py",
                    "start": {"line": 1},
                    "extra": {"message": "test"},
                }
            ],
            "errors": [],
            "paths": {"scanned": ["app.py"]},
            "time": {
                "fixpoint_timeouts": [
                    {
                        "message": "PRIVATE_TIMEOUT_DETAIL",
                        "location": {"path": "PRIVATE_PATH"},
                    }
                ]
            },
        }
    )


def test_fixpoint_timeout_prevents_complete_coverage(tmp_path: Path):
    result = reconcile_coverage(payload(), tmp_path, ("app.py",), semgrep=True)
    assert result["state"] == "partial"
    assert result["native_errors"] == 1
    assert "PRIVATE" not in json.dumps(result)


@pytest.mark.parametrize("has_findings", [False, True])
def test_native_success_with_fixpoint_timeout_retains_findings(
    tmp_path: Path, has_findings: bool
):
    document = json.loads(payload())
    if not has_findings:
        document["results"] = []
    adapter = SemgrepAdapter(ToolConfig(rules_path=tmp_path), 65536)
    with (
        patch.object(adapter, "_detect_version", return_value="test"),
        patch.object(adapter, "_executable_changed_error", return_value=None),
        patch.object(adapter, "_asset_changed_error", return_value=None),
        patch(
            "py_security_suite.adapters.base.run_command",
            return_value=RawExecution(["semgrep"], 0, json.dumps(document), "", 1),
        ),
    ):
        result = adapter._run_ready(tmp_path, "semgrep")
    assert result.tool_run.status == ToolStatus.PARSE_ERROR
    assert len(result.findings) == result.tool_run.finding_count == int(has_findings)
    assert "PRIVATE" not in json.dumps(result.diagnostic)


@pytest.mark.parametrize(
    "timing", [None, [], {"fixpoint_timeouts": None}, {"fixpoint_timeouts": {}}]
)
def test_malformed_timeout_evidence_is_not_clean(timing):
    with pytest.raises(TypeError):
        native_coverage(json.dumps({"time": timing}), semgrep=True)


@pytest.mark.parametrize("timing", [{}, {"fixpoint_timeouts": []}])
def test_empty_optional_profiling_does_not_break_complete_scans(tmp_path, timing):
    document = json.loads(payload())
    document["time"] = timing
    assert (
        reconcile_coverage(json.dumps(document), tmp_path, ("app.py",), semgrep=True)[
            "state"
        ]
        == "complete"
    )
    del document["time"]
    assert native_coverage(json.dumps(document), semgrep=True)["native_errors"] == 0


def test_timeout_and_top_level_errors_both_contribute():
    document = json.loads(payload())
    document["errors"] = [{"message": "another analysis error"}]
    assert native_coverage(json.dumps(document), semgrep=True)["native_errors"] == 2
    # Profiling is a Semgrep-specific channel, not part of Bandit's contract.
    assert native_coverage(json.dumps(document))["native_errors"] == 1


def test_benchmark_cli_fails_on_timeout_even_without_accuracy_policy(
    tmp_path, monkeypatch
):
    coverage = reconcile_coverage(payload(), tmp_path, ("app.py",), semgrep=True)
    measurement = {"measurement_complete": coverage["state"] == "complete"}
    monkeypatch.setattr(benchmark_external, "evaluate", lambda _: measurement)
    output = tmp_path / "measurement.json"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "benchmark",
            "--source",
            str(tmp_path),
            "--lock",
            "unused",
            "--bandit",
            "bandit",
            "--semgrep",
            "semgrep",
            "--output",
            str(output),
        ],
    )
    assert benchmark_external.main() == 1
    assert json.loads(output.read_text())["measurement_complete"] is False
