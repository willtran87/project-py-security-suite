from __future__ import annotations

import json
import time
from pathlib import Path
from unittest.mock import patch

import pytest

from py_security_suite.adapters.codeql import CodeQlAdapter
from py_security_suite.adapters.coverage import reconcile_coverage
from py_security_suite.config import ToolConfig
from py_security_suite.execution import (
    RawExecution,
    governed_asset_sha256,
    sealed_governed_assets,
)
from py_security_suite.models import ToolStatus
from scripts.benchmark_external import labels, score, regressions


@pytest.mark.parametrize("engine", ["semgrep", "bandit"])
@pytest.mark.parametrize("state", ["complete", "partial", "unknown"])
def test_inventory_reconciliation_cannot_call_missing_files_clean(
    tmp_path: Path, engine: str, state: str
) -> None:
    document = {"errors": []}
    if state != "unknown":
        scanned = ["app.py", "safe.py"] if state == "complete" else ["app.py"]
        document.update(
            {"paths": {"scanned": scanned}}
            if engine == "semgrep"
            else {"metrics": {name: {} for name in scanned}}
        )
    result = reconcile_coverage(
        json.dumps(document),
        tmp_path,
        ("app.py", "safe.py"),
        semgrep=engine == "semgrep",
    )
    assert result["state"] == state
    assert "app.py" not in json.dumps(result)
    assert result["missing_files"] == (
        None if state == "unknown" else int(state == "partial")
    )


def test_engine_inventory_cannot_escape_scan_boundary(tmp_path: Path) -> None:
    result = reconcile_coverage(
        json.dumps({"errors": [], "paths": {"scanned": ["../other.py"]}}),
        tmp_path,
        ("app.py",),
        semgrep=True,
    )
    assert result["state"] == "partial"
    assert result["invalid_paths"] == 1


def test_codeql_deadline_includes_preparation(tmp_path: Path) -> None:
    adapter = CodeQlAdapter(ToolConfig(), 1024)

    def prepare():
        adapter._deadline = time.monotonic() - 1
        return None

    with (
        patch.object(adapter, "not_applicable_reason", return_value=None),
        patch.object(adapter, "prerequisite_error", return_value=None),
        patch.object(adapter, "_prepare_assets", side_effect=prepare),
        patch.object(adapter, "_prepare_executable", return_value=("runner", None)),
        patch.object(adapter, "_detect_version") as version,
    ):
        result = adapter.run(tmp_path)
    assert result.tool_run.status == ToolStatus.TIMED_OUT
    assert result.diagnostic["failure_category"] == "wall-clock"
    version.assert_not_called()


def test_asset_snapshot_honors_deadline_before_copy(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    (home / "query.qll").write_text("library", encoding="utf-8")

    def expired():
        raise TimeoutError("expired")

    with (
        pytest.raises(TimeoutError),
        sealed_governed_assets(
            {"database": home}, {"database": governed_asset_sha256(home)}, check=expired
        ),
    ):
        pytest.fail("expired snapshot must not be supplied to scanner")


def test_both_codeql_stages_use_same_sealed_dependencies(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "app.py").write_text("pass\n", encoding="utf-8")
    home, rules = tmp_path / "home", tmp_path / "rules"
    home.mkdir()
    rules.mkdir()
    (home / "library").write_text("approved", encoding="utf-8")
    (rules / "query.ql").write_text("query", encoding="utf-8")
    adapter = CodeQlAdapter(ToolConfig(database_path=home, rules_path=rules), 65536)
    observed = []
    sarif = json.dumps(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "invocations": [
                        {
                            "executionSuccessful": True,
                            "toolExecutionNotifications": [
                                {
                                    "descriptor": {
                                        "id": "py/diagnostics/successfully-extracted-files"
                                    },
                                    "locations": [
                                        {
                                            "physicalLocation": {
                                                "artifactLocation": {
                                                    "uri": "app.py",
                                                    "uriBaseId": "%SRCROOT%",
                                                }
                                            }
                                        }
                                    ],
                                }
                            ],
                        }
                    ]
                }
            ],
        }
    )

    def primary(command, **kwargs):
        observed.append(kwargs["home"])
        report = kwargs["target"] / ".codeql/reports/python-test.sarif"
        report.parent.mkdir(parents=True)
        report.write_text(sarif, encoding="utf-8")
        return RawExecution(command, 0, "", "", 0.1)

    def supplemental(**kwargs):
        assert kwargs["home"] == observed[0] != home
        assert kwargs["already_sealed"] is True
        assert kwargs["rules"] != rules
        assert (kwargs["home"] / "library").read_text() == "approved"
        return sarif

    with (
        patch.object(adapter, "prerequisite_error", return_value=None),
        patch.object(adapter, "_prepare_executable", return_value=("runner", None)),
        patch.object(adapter, "_detect_version", return_value="test"),
        patch("py_security_suite.adapters.codeql.run_with_cache", side_effect=primary),
        patch(
            "py_security_suite.adapters.codeql.supplemental_queries",
            side_effect=supplemental,
        ),
    ):
        result = adapter.run(source)
    assert result.tool_run.status == ToolStatus.COMPLETED
    assert result.diagnostic["asset_snapshot_verified"] == {
        "database": True,
        "rules": True,
    }


def test_external_scoring_requires_correct_cwe_and_counts_false_positives() -> None:
    rows = labels("BenchmarkTest00001,sql,true,89\nBenchmarkTest00002,sql,false,89\n")
    result = score(
        rows, {("BenchmarkTest00001", "CWE-22"), ("BenchmarkTest00002", "CWE-89")}
    )["CWE-89"]
    assert (result["tp"], result["fn"], result["fp"], result["tn"]) == (0, 1, 1, 0)
    assert result["recall_wilson_95"][1] > 0
    with pytest.raises(ValueError):
        labels("BenchmarkTest00001,sql,true,89\nBenchmarkTest00001,sql,false,89\n")
    measured = {
        "upstream": {"source_sha256": "source", "labels_sha256": "labels"},
        "engines": {"bandit": {"by_cwe": {"CWE-89": result}}},
    }
    baseline = {"source_sha256": "source", "labels_sha256": "labels", "engines": {}}
    with pytest.raises(ValueError, match="every measured engine"):
        regressions(measured, baseline)
    baseline["engines"] = {"bandit": {"CWE-89": {"fp": 0, "fn": 0}}}
    assert regressions(measured, baseline) == ["bandit:CWE-89"]


def test_supplemental_analysis_refreshes_cached_results(tmp_path: Path) -> None:
    from py_security_suite.adapters.codeql_queries import supplemental_queries
    from py_security_suite.execution import CommandEnvironment

    output = tmp_path / ".codeql" / "supplemental.sarif"
    output.parent.mkdir()
    stale = '{"generation": "old-query", "results": []}'
    fresh = '{"generation": "current-query", "results": ["new-detection"]}'
    output.write_text(stale, encoding="utf-8")

    def native(command, **kwargs):
        # CodeQL reuses a stored BQRS result unless evaluation is forced.
        if "--rerun" in command:
            output.write_text(fresh, encoding="utf-8")
        return RawExecution(command, 0, "", "", 0.1)

    with (
        patch(
            "py_security_suite.adapters.codeql_queries.locked_pack_paths",
            return_value=[],
        ),
        patch(
            "py_security_suite.adapters.codeql_queries.run_command", side_effect=native
        ),
    ):
        payload = supplemental_queries(
            cli="codeql",
            target=tmp_path,
            rules=tmp_path,
            rules_digest="test",
            home=tmp_path,
            environment=CommandEnvironment(),
            timeout_seconds=10,
            max_output_bytes=4096,
            already_sealed=True,
        )
    assert json.loads(payload) == json.loads(fresh)
