from __future__ import annotations

import json
import tracemalloc
from pathlib import Path
from unittest.mock import patch

import pytest

from py_security_suite.adapters.bandit import BanditAdapter
from py_security_suite.adapters.semgrep import SemgrepAdapter
from py_security_suite.adapters.codeql import CodeQlAdapter
from py_security_suite.config import ToolConfig
from py_security_suite.execution import RawExecution
from py_security_suite.models import ToolStatus
from scripts.validate_detection import evaluate, metrics
from py_security_suite.path_safety import read_regular_file


@pytest.mark.parametrize(
    "engine,exit_code", [("bandit", 0), ("bandit", 1), ("semgrep", 0), ("semgrep", 3)]
)
def test_native_analysis_errors_retain_valid_findings(
    tmp_path: Path, engine: str, exit_code: int
) -> None:
    item = (
        {
            "filename": "app.py",
            "line_number": 1,
            "test_id": "B602",
            "issue_text": "shell",
        }
        if engine == "bandit"
        else {
            "path": "app.py",
            "start": {"line": 1},
            "check_id": "test-rule",
            "extra": {"message": "shell"},
        }
    )
    payload = json.dumps(
        {"results": [item], "errors": [{"reason": "PRIVATE_DIAGNOSTIC_CANARY"}]}
    )
    cls = BanditAdapter if engine == "bandit" else SemgrepAdapter
    adapter = cls(ToolConfig(rules_path=tmp_path), 65536)
    with (
        patch.object(adapter, "_detect_version", return_value="test"),
        patch.object(adapter, "_executable_changed_error", return_value=None),
        patch.object(adapter, "_asset_changed_error", return_value=None),
        patch(
            "py_security_suite.adapters.base.run_command",
            return_value=RawExecution([engine], exit_code, payload, "", 1),
        ),
    ):
        result = adapter._run_ready(tmp_path, engine)
    assert result.tool_run.status is ToolStatus.PARSE_ERROR
    assert result.tool_run.finding_count == len(result.findings) == 1
    assert result.diagnostic["analysis_coverage"]["native_errors"] == 1
    assert "PRIVATE_DIAGNOSTIC_CANARY" not in json.dumps(result.diagnostic)


def test_semgrep_skipped_files_are_visible() -> None:
    adapter = SemgrepAdapter(ToolConfig(), 4096)
    assert (
        adapter.analysis_coverage(
            json.dumps(
                {
                    "results": [],
                    "paths": {"skipped": [{"path": "big.py", "reason": "too big"}]},
                }
            )
        )["skipped_files"]
        == 1
    )


@pytest.mark.parametrize("errors", [None, {}, "unreadable"])
def test_invalid_coverage_shape_is_not_silently_clean(errors) -> None:
    with pytest.raises(TypeError):
        BanditAdapter(ToolConfig(), 4096).analysis_coverage(
            json.dumps({"errors": errors})
        )


@pytest.mark.parametrize("supplemental_fails", [False, True])
def test_codeql_supplemental_query_results_and_failures_are_retained(
    tmp_path: Path, supplemental_fails: bool
) -> None:
    target = tmp_path / "project"
    target.mkdir()
    (target / "app.py").write_text("value = 1\n", encoding="utf-8")
    rules = tmp_path / "queries"
    rules.mkdir()
    (rules / "qlpack.yml").write_text("name: fixture\n", encoding="utf-8")
    adapter = CodeQlAdapter(
        ToolConfig(executable="run-codeql", rules_path=rules), 65536
    )

    def sarif(rule):
        return json.dumps(
            {
                "version": "2.1.0",
                "runs": [
                    {
                        "tool": {"driver": {"name": "CodeQL"}},
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
                        ],
                        "results": [
                            {
                                "ruleId": rule,
                                "level": "error",
                                "message": {"text": "test"},
                                "locations": [
                                    {
                                        "physicalLocation": {
                                            "artifactLocation": {"uri": "app.py"},
                                            "region": {"startLine": 1},
                                        }
                                    }
                                ],
                            }
                        ],
                    }
                ],
            }
        )

    def primary(command, **kwargs):
        report = kwargs["cwd"] / ".codeql" / "reports" / "python-test.sarif"
        report.parent.mkdir(parents=True)
        report.write_text(sarif("primary"), encoding="utf-8")
        return RawExecution(command, 0, "", "", 1)

    with (
        patch.object(adapter, "prerequisite_error", return_value=None),
        patch.object(adapter, "_prepare_executable", return_value=("run-codeql", None)),
        patch.object(adapter, "_detect_version", return_value="test"),
        patch.object(adapter, "_executable_changed_error", return_value=None),
        patch.object(adapter, "_auxiliary_changed_error", return_value=None),
        patch("py_security_suite.adapters.codeql.run_command", side_effect=primary),
        patch(
            "py_security_suite.adapters.codeql.supplemental_queries",
            side_effect=ValueError("missing libraries") if supplemental_fails else None,
            return_value=sarif("supplemental"),
        ),
    ):
        result = adapter.run(target)
    assert len(result.findings) == (1 if supplemental_fails else 2)
    assert result.tool_run.status == (
        ToolStatus.FAILED if supplemental_fails else ToolStatus.COMPLETED
    )


def test_detection_gate_rejects_misses_and_false_positives() -> None:
    cases = [
        {"id": "positive", "positive": True, "category": "CWE-89"},
        {"id": "negative", "positive": False, "category": "CWE-89"},
    ]
    results = [{"path": "negative/app.py", "check_id": "python.request-to-sql"}]
    outcomes = evaluate(cases, results, "semgrep")
    assert not any(item["passed"] for item in outcomes)
    assert metrics(outcomes)["CWE-89"] == {
        "tp": 0,
        "fn": 1,
        "fp": 1,
        "tn": 0,
        "recall": 0.0,
        "precision": 0.0,
    }


def test_cross_function_gate_requires_retained_trace() -> None:
    outcomes = evaluate(
        [{"id": "cross-file", "positive": True, "category": "CWE-532"}],
        [
            {
                "ruleId": "pysec/environment-secret-to-log",
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": "cross_file/helper.py"}
                        }
                    }
                ],
            }
        ],
        "codeql",
    )
    assert outcomes[0]["detected"]
    assert not outcomes[0]["passed"]


def test_small_query_asset_does_not_allocate_the_read_ceiling(tmp_path: Path) -> None:
    path = tmp_path / "small.qll"
    path.write_bytes(b"query library")
    tracemalloc.start()
    try:
        _, payload = read_regular_file(path, "query", maximum_bytes=64 * 1024**2)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert payload == b"query library"
    assert peak < 2 * 1024**2


@pytest.mark.parametrize("tampered", [False, True])
def test_codeql_helper_path_requires_matching_digest(
    tmp_path: Path, tampered: bool
) -> None:
    import hashlib
    from py_security_suite.execution import isolated_environment

    helper = tmp_path / "codeql.exe"
    helper.write_bytes(b"approved CLI")
    digest = hashlib.sha256(helper.read_bytes()).hexdigest()
    if tampered:
        helper.write_bytes(b"replacement CLI")
        with pytest.raises(ValueError, match="approved SHA-256"):
            isolated_environment(auxiliary_executables=((str(helper), digest),))
    else:
        env = isolated_environment(auxiliary_executables=((str(helper), digest),))
        assert env["PATH"].split(__import__("os").pathsep)[0] == str(tmp_path)
    with pytest.raises(ValueError, match="cannot override"):
        isolated_environment({"PATH": str(tmp_path)})


def test_codeql_cache_is_staged_into_private_home(tmp_path: Path) -> None:
    import sys
    from py_security_suite.adapters.codeql_queries import run_with_staged_cache
    from py_security_suite.execution import CommandEnvironment, governed_asset_sha256

    home = tmp_path / "approved-home"
    cache = home / ".codeql"
    cache.mkdir(parents=True)
    (cache / "marker").write_text("approved query cache", encoding="utf-8")
    result = run_with_staged_cache(
        [
            sys.executable,
            "-I",
            "-c",
            "import os,pathlib; print(pathlib.Path(os.environ['HOME']).joinpath('.codeql/marker').read_text()); print(os.environ['HOME'])",
        ],
        home=home,
        digest=governed_asset_sha256(home),
        target=tmp_path,
        environment=CommandEnvironment(),
        timeout_seconds=15,
        max_output_bytes=4096,
    )
    assert result.exit_code == 0
    assert result.stdout.splitlines()[0] == "approved query cache"
    assert Path(result.stdout.splitlines()[1]) != home
    assert list(cache.iterdir()) == [cache / "marker"]


def test_detection_gate_rejects_duplicate_supplemental_flow() -> None:
    case = {
        "id": "native-ldap",
        "category": "CWE-90",
        "positive": True,
        "rule_id": "py/ldap-injection",
        "forbidden_rule_ids": ["pysec/ldap-factory-filter-injection"],
    }
    result = {
        "ruleId": "py/ldap-injection",
        "locations": [
            {"physicalLocation": {"artifactLocation": {"uri": "native_ldap/app.py"}}}
        ],
        "codeFlows": [{"threadFlows": []}],
    }
    assert evaluate([case], [result], "codeql")[0]["passed"]
    duplicate = {**result, "ruleId": "pysec/ldap-factory-filter-injection"}
    outcome = evaluate([case], [result, duplicate], "codeql")[0]
    assert outcome["detected"] and not outcome["passed"]
    assert outcome["forbidden_rule_ids_observed"] == [duplicate["ruleId"]]


@pytest.mark.parametrize(
    "rule", [None, "pysec/value-proof-safety-probe", "py/path-injection"]
)
def test_known_gap_requires_no_unsafe_proof_and_explicit_promotion(
    rule: str | None,
) -> None:
    from scripts.validate_detection import evaluate_proof_rejections

    case = {"id": "mutation-gap", "category": "CWE-22", "positive": True}
    results = (
        []
        if rule is None
        else [
            {
                "ruleId": rule,
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": "mutation_gap/app.py"}
                        }
                    }
                ],
            }
        ]
    )
    outcome = evaluate_proof_rejections([case], results)[0]
    assert outcome["passed"] is (rule is None)
    assert outcome["detected"] is (rule == "py/path-injection")
    assert outcome["native_value_proof_rejected"] is (
        rule != "pysec/value-proof-safety-probe"
    )
