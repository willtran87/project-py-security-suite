from __future__ import annotations

import json
import sys
from copy import deepcopy
from pathlib import Path

import pytest

from scripts.benchmark_external import labels, score
from scripts import benchmark_external
from scripts.external_benchmark_scoring import accuracy_gate, case_outcomes
from py_security_suite.adapters.coverage import reconcile_codeql_coverage
from py_security_suite.adapters.sarif import load_sarif_document
from py_security_suite.adapters.codeql import CodeQlAdapter
from py_security_suite.config import ToolConfig


def test_source_digest_has_platform_independent_case_order(tmp_path):
    import hashlib

    for name in ("a.py", "Z.py"):
        (tmp_path / name).write_bytes(b"pass\r\n")
    digest, members = benchmark_external.source_digest(tmp_path)
    assert [name for name, _ in members] == ["Z.py", "a.py"]
    expected = [
        (name, hashlib.sha256(b"pass\n").hexdigest()) for name in ("Z.py", "a.py")
    ]
    assert (
        digest
        == hashlib.sha256(
            json.dumps(expected, separators=(",", ":")).encode()
        ).hexdigest()
    )


def measurement():
    expected = labels(
        "BenchmarkTest00001,sql,true,89\nBenchmarkTest00002,sql,false,89\n"
    )
    return {
        "measurement_complete": True,
        "engines": {"bandit": {}, "semgrep": {}, "codeql": {}},
        "combined_by_cwe": score(expected, {("BenchmarkTest00001", "CWE-89")}),
    }


def policy():
    return {
        "schema_version": "1.0",
        "required_engines": ["bandit", "semgrep", "codeql"],
        "by_cwe": {
            "CWE-89": {
                "minimum_precision": 0.8,
                "minimum_recall": 0.8,
                "maximum_false_positive_rate": 0.1,
                "minimum_positive_cases": 1,
                "minimum_negative_cases": 1,
            }
        },
    }


def test_accuracy_is_independent_of_a_passing_regression_gate():
    result = measurement()
    assert accuracy_gate(result, policy())["passed"]
    result["regression_passed"] = True
    result["combined_by_cwe"]["CWE-89"].update(tp=0, fn=1, recall=0, precision=None)
    gate = accuracy_gate(result, policy())
    assert not gate["passed"]
    assert "CWE-89:recall" in gate["failures"]
    assert "CWE-89:precision" in gate["failures"]


@pytest.mark.parametrize("missing", ["engine", "coverage", "samples"])
def test_accuracy_fails_closed_without_the_required_evidence(missing):
    result, target = measurement(), policy()
    if missing == "engine":
        del result["engines"]["codeql"]
    elif missing == "coverage":
        result["measurement_complete"] = False
    else:
        target["by_cwe"]["CWE-89"]["minimum_negative_cases"] = 5
    assert not accuracy_gate(result, target)["passed"]


@pytest.mark.parametrize(
    "value", [True, "0.8", -1, 1.1, float("nan"), float("inf"), None]
)
def test_invalid_accuracy_targets_cannot_silently_pass(value):
    target = policy()
    target["by_cwe"]["CWE-89"]["minimum_recall"] = value
    with pytest.raises(ValueError):
        accuracy_gate(measurement(), target)


def test_policy_cannot_omit_a_poorly_performing_category():
    target = policy()
    del target["by_cwe"]["CWE-89"]
    with pytest.raises(ValueError, match="every measured CWE"):
        accuracy_gate(measurement(), target)


@pytest.mark.parametrize("enforce", [False, True])
def test_cli_accuracy_failure_is_explicit_and_enforceable(
    tmp_path, monkeypatch, enforce
):
    target = policy()
    target["by_cwe"]["CWE-89"]["minimum_negative_cases"] = 5
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(json.dumps(target), encoding="utf-8")
    output = tmp_path / "output.json"
    arguments = [
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
        "--accuracy-policy",
        str(policy_path),
    ]
    if enforce:
        arguments.append("--require-accuracy")
    monkeypatch.setattr(sys, "argv", arguments)
    monkeypatch.setattr(benchmark_external, "evaluate", lambda _: measurement())
    assert benchmark_external.main() == int(enforce)
    retained = json.loads(output.read_text())
    assert retained["measurement_complete"]
    assert not retained["accuracy_gate"]["passed"]


def test_case_attribution_distinguishes_wrong_classification_from_no_alert():
    expected = labels(
        "BenchmarkTest00001,sql,true,89\nBenchmarkTest00002,sql,false,89\n"
    )
    evidence = {
        "engine": "bandit",
        "rule": "B000",
        "path": "BenchmarkTest00001.py",
        "line": 3,
        "cwes": ["CWE-22"],
        "path_trace_retained": False,
    }
    cases = case_outcomes(expected, {"BenchmarkTest00001": [evidence]})
    assert cases[0]["outcome"] == "fn"
    assert cases[0]["classification_review_needed"]
    assert cases[0]["reported_cwes"] == ["CWE-22"]
    assert cases[1]["outcome"] == "tn"
    assert not cases[1]["classification_review_needed"]
    assert cases == case_outcomes(
        list(reversed(expected)), {"BenchmarkTest00001": [deepcopy(evidence)]}
    )
    evidence["cwes"] = []
    assert not case_outcomes(expected, {"BenchmarkTest00001": [evidence]})[0][
        "classification_review_needed"
    ]


def codeql_document():
    return {
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
                                "level": "none",
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
        ]
    }


def test_large_native_sarif_preserves_strict_json_checks():
    # File diagnostics alone on a large repository can exceed the general JSON budget.
    assert (
        len(
            load_sarif_document(json.dumps({"runs": [], "large": [0] * 250_001}))[
                "large"
            ]
        )
        == 250_001
    )
    with pytest.raises(ValueError, match="duplicate"):
        load_sarif_document('{"runs": [], "runs": []}')
    with pytest.raises(ValueError, match="node limit"):
        load_sarif_document(json.dumps({"runs": [], "large": [0] * 2_000_001}))
    with pytest.raises(ValueError, match="non-finite"):
        load_sarif_document('{"runs": [], "value": NaN}')


@pytest.mark.parametrize("explicit_outside_base", [False, True])
def test_native_codeql_binds_only_an_omitted_source_root(
    tmp_path, explicit_outside_base
):
    run = {
        "tool": {
            "driver": {
                "name": "CodeQL",
                "rules": [
                    {
                        "id": "py/sql-injection",
                        "properties": {"tags": ["external/cwe/cwe-089"]},
                    }
                ],
            }
        },
        "results": [
            {
                "ruleId": "py/sql-injection",
                "message": {"text": "SQL injection"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": "BenchmarkTest00001.py",
                                "uriBaseId": "%SRCROOT%",
                            },
                            "region": {"startLine": 3},
                        }
                    }
                ],
            }
        ],
    }
    if explicit_outside_base:
        run["originalUriBaseIds"] = {
            "%SRCROOT%": {"uri": tmp_path.parent.as_uri() + "/"}
        }
    findings = CodeQlAdapter(ToolConfig(), 4096).parse(
        json.dumps({"runs": [run]}), tmp_path
    )
    assert findings[0].classifications == ["CWE-89"]
    assert findings[0].locations[0].path == (
        "<outside-target>" if explicit_outside_base else "BenchmarkTest00001.py"
    )


@pytest.mark.parametrize(
    "failure",
    [
        None,
        "syntax-error",
        "missing-file",
        "no-metadata",
        "invalid-uri",
        "failed-invocation",
    ],
)
def test_codeql_coverage_does_not_confuse_extraction_with_complete_analysis(
    tmp_path: Path, failure
):
    document = codeql_document()
    invocation = document["runs"][0]["invocations"][0]
    expected = ("app.py",)
    if failure == "syntax-error":
        # Native CodeQL can report BOTH extracted and a syntax error for the same file.
        invocation["toolExecutionNotifications"].append(
            {
                "descriptor": {"id": "py/diagnostics/syntax-error"},
                "message": {"text": "PRIVATE_CANARY"},
            }
        )
    elif failure == "missing-file":
        expected += ("missing.py",)
    elif failure == "no-metadata":
        del document["runs"][0]["invocations"]
    elif failure == "invalid-uri":
        invocation["toolExecutionNotifications"][0]["locations"][0]["physicalLocation"][
            "artifactLocation"
        ]["uri"] = "../outside.py"
    elif failure == "failed-invocation":
        invocation["executionSuccessful"] = False
    coverage = reconcile_codeql_coverage(json.dumps(document), tmp_path, expected)
    assert coverage["state"] == (
        "complete"
        if failure is None
        else "unknown"
        if failure == "no-metadata"
        else "partial"
    )
    assert "PRIVATE_CANARY" not in json.dumps(coverage)
    assert "app.py" not in json.dumps(coverage)
