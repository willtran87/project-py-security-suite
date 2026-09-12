import copy
import hashlib
import json
from pathlib import Path
import sys

import pytest

from scripts import aggregate_validation as aggregation
from scripts.benchmark_external import score
from scripts.external_benchmark_scoring import accuracy_gate, case_outcomes


@pytest.fixture
def measurement():
    expected = [
        {"id": "BenchmarkTest00001", "cwe": "CWE-79", "positive": True},
        {"id": "BenchmarkTest00002", "cwe": "CWE-79", "positive": False},
    ]
    detections = {(row["id"], "CWE-79") for row in expected}
    coverage = {
        "state": "complete",
        "expected_files": 2,
        "analyzed_files": 2,
        "inventory_sha256": "inventory",
        **dict.fromkeys(
            (
                "native_errors",
                "skipped_files",
                "missing_files",
                "unexpected_files",
                "invalid_paths",
            ),
            0,
        ),
    }
    engines = {
        name: {
            "status": "completed",
            "error": None,
            "coverage": copy.deepcopy(coverage),
            "by_cwe": score(expected, detections if name == "codeql" else set()),
        }
        for name in ("bandit", "semgrep", "codeql")
    }
    policy = {
        "schema_version": "1.0",
        "required_engines": list(engines),
        "by_cwe": {
            "CWE-79": {
                "minimum_precision": 0.8,
                "minimum_recall": 0.8,
                "maximum_false_positive_rate": 0.1,
                "minimum_positive_cases": 1,
                "minimum_negative_cases": 1,
            }
        },
    }
    report = {
        "measurement_complete": True,
        "regression_passed": True,
        "regressions": [],
        "engines": engines,
        "upstream": {"cases": 2, "source_sha256": "source", "labels_sha256": "labels"},
        "combined_by_cwe": score(expected, detections),
        "cases": case_outcomes(
            expected,
            {
                row["id"]: [
                    {
                        "engine": "codeql",
                        "rule": "xss",
                        "path": row["id"] + ".py",
                        "line": 1,
                        "cwes": ["CWE-79"],
                    }
                ]
                for row in expected
            },
        ),
    }
    report["accuracy_gate"] = accuracy_gate(report, policy)
    baseline = {
        "source_sha256": "source",
        "labels_sha256": "labels",
        "engines": {
            name: {
                "CWE-79": {key: engine["by_cwe"]["CWE-79"][key] for key in ("fp", "fn")}
            }
            for name, engine in engines.items()
        },
        "protected_detections": {"codeql": {"CWE-79": ["BenchmarkTest00001"]}},
    }
    return report, baseline, policy


def test_valid_evidence_keeps_accuracy_failure_visible(measurement):
    result = aggregation.verify_benchmark(*measurement)
    assert result["totals"] == {"tp": 1, "fp": 1, "fn": 0, "tn": 0}
    assert result["accuracy_passed"] is False
    assert result["protected_detections"] == 1


def test_consistent_regression_failure_is_published_as_failure(measurement):
    report, baseline, _ = measurement
    baseline["engines"]["codeql"]["CWE-79"]["fp"] = 0
    report["regression_passed"] = False
    report["regressions"] = ["codeql:CWE-79"]
    result = aggregation.verify_benchmark(*measurement)
    assert result["regression_passed"] is False
    assert result["regression_failures"] == ["codeql:CWE-79"]
    assert result["totals"]["fp"] == 1


@pytest.mark.parametrize("claims", [[], ["codeql:CWE-79"] * 2, ["bandit:CWE-79"]])
def test_missing_duplicate_and_invented_regression_failures_are_rejected(
    measurement, claims
):
    report, baseline, _ = measurement
    baseline["engines"]["codeql"]["CWE-79"]["fp"] = 0
    report["regression_passed"] = False
    report["regressions"] = claims
    with pytest.raises(ValueError, match="regression result disagrees"):
        aggregation.verify_benchmark(*measurement)


@pytest.mark.parametrize(
    "change",
    [
        "counts",
        "rate",
        "accuracy",
        "outcome",
        "partial",
        "duplicate",
        "engine",
        "label",
        "ceiling",
    ],
)
def test_inconsistent_or_incomplete_measurements_are_rejected(measurement, change):
    report, baseline, _ = measurement
    if change == "counts":
        report["combined_by_cwe"]["CWE-79"]["fp"] = 0
    elif change == "rate":
        report["combined_by_cwe"]["CWE-79"]["precision"] = 1.0
    elif change == "accuracy":
        report["accuracy_gate"]["passed"] = True
    elif change == "outcome":
        report["cases"][1]["outcome"] = "tn"
    elif change == "partial":
        report["engines"]["codeql"]["coverage"]["missing_files"] = 1
    elif change == "duplicate":
        report["cases"][1] = report["cases"][0]
    elif change == "engine":
        report["cases"][0]["evidence"][0]["engine"] = "unknown"
    elif change == "label":
        report["cases"][0]["expected_positive"] = 1
    elif change == "ceiling":
        baseline["engines"]["codeql"]["CWE-79"]["fp"] = 0
    with pytest.raises(ValueError):
        aggregation.verify_benchmark(*measurement)


@pytest.mark.parametrize(
    "payload", ['{"passed":true,"passed":false}', '{"rate":NaN}', "[]"]
)
def test_ambiguous_json_is_rejected(tmp_path, payload):
    path = tmp_path / "result.json"
    path.write_text(payload)
    with pytest.raises(ValueError):
        aggregation.read_json(path)


@pytest.fixture
def receipt(tmp_path):
    report = tmp_path / "report.json"
    report.write_text('{"accuracy_passed":false}')
    artifact = {
        "wheel_sha256": "wheel",
        "package_sha256": "package",
        "package_files": 1,
    }
    driver_hash = hashlib.sha256(
        json.dumps(
            {
                p.name: aggregation.digest(p)
                for p in sorted(Path(aggregation.__file__).parent.glob("*.py"))
            },
            sort_keys=True,
        ).encode()
    ).hexdigest()
    receipt = {
        "mode": "benchmark",
        "artifact_verified": True,
        "artifact_before": artifact,
        "artifact_after": artifact,
        "report_sha256": aggregation.digest(report),
        "bytecode_policy": aggregation.BYTECODE_POLICY,
        "passed": False,
        "state": "failed",
        "driver_exit_code": 1,
        "driver_assets_sha256": driver_hash,
    }
    return receipt, report, artifact, "benchmark", False


def test_failed_accuracy_can_have_a_verified_receipt(receipt):
    aggregation.verify_receipt(*receipt)


@pytest.mark.parametrize(
    "change", ["report", "wheel", "drivers", "bytecode", "running", "passed"]
)
def test_stale_or_mismatched_receipts_are_rejected(receipt, change):
    data, path, *_ = receipt
    if change == "report":
        path.write_text('{"accuracy_passed":true}')
    elif change == "wheel":
        data["artifact_after"] = {"wheel_sha256": "other"}
    elif change == "drivers":
        data["driver_assets_sha256"] = "old"
    elif change == "bytecode":
        del data["bytecode_policy"]
    elif change == "running":
        data["state"] = "running"
    else:
        data["passed"] = True
    with pytest.raises(ValueError):
        aggregation.verify_receipt(*receipt)


def test_modified_retained_evidence_is_rejected(tmp_path):
    artifact = tmp_path / "scan.json"
    artifact.write_text("{}")
    record = {"path": "scan.json", "bytes": 2, "sha256": aggregation.digest(artifact)}
    report = {
        "passed": True,
        "state": "passed",
        "cases": [{"scenario": name, "passed": True} for name in aggregation.SCENARIOS],
        "artifacts": {name: [record] for name in aggregation.SCENARIOS},
    }
    aggregation.verify_acceptance(report, tmp_path / "report.json")
    artifact.write_text('{"changed":true}')
    with pytest.raises(ValueError, match="retained evidence changed"):
        aggregation.verify_acceptance(report, tmp_path / "report.json")


def test_rejected_aggregation_replaces_a_stale_success_page(tmp_path, monkeypatch):
    output, page = tmp_path / "summary.json", tmp_path / "results.md"
    page.write_text("Previous passing results")
    arguments = ["aggregate"]
    for name in (
        "wheel",
        "native",
        "runtime",
        "benchmark",
        "benchmark-receipt",
        "acceptance",
        "acceptance-receipt",
        "baseline",
        "policy",
    ):
        arguments.extend(["--" + name, str(tmp_path / (name + ".json"))])
    arguments.extend(["--output", str(output), "--markdown", str(page)])
    monkeypatch.setattr(sys, "argv", arguments)
    assert aggregation.main() == 1
    assert json.loads(output.read_text())["evidence_verified"] is False
    assert "Previous passing" not in page.read_text()
    assert "verification failed" in page.read_text()


def test_summary_cannot_overwrite_its_evidence(tmp_path, monkeypatch):
    arguments = ["aggregate"]
    for name in (
        "wheel",
        "native",
        "runtime",
        "benchmark",
        "benchmark-receipt",
        "acceptance",
        "acceptance-receipt",
        "baseline",
        "policy",
        "output",
    ):
        arguments.extend(["--" + name, str(tmp_path / "input.json")])
    monkeypatch.setattr(sys, "argv", arguments)
    with pytest.raises(SystemExit) as caught:
        aggregation.main()
    assert caught.value.code == 2
