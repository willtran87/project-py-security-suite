import argparse
import json
import subprocess
import errno
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

import pytest

from scripts.validation_evidence import ValidationEvidence
from scripts import validation_evidence
from scripts import validate_product_acceptance as acceptance


def test_late_acceptance_failure_retains_prior_scenarios_and_bounded_diagnostics(
    tmp_path,
):
    output = tmp_path / "acceptance.json"

    def fail_late(args, evidence):
        evidence.complete_case({"scenario": "complete", "passed": True})
        evidence.invoke(
            "partial:scan",
            lambda: subprocess.CompletedProcess(
                [], 2, "PRIVATE_SOURCE", "PRIVATE_TOKEN"
            ),
        )
        evidence.stage("partial:assertions")
        raise ValueError("PRIVATE_NATIVE_DETAIL")

    with patch.object(acceptance, "_validate", side_effect=fail_late):
        result = acceptance.validate(argparse.Namespace(output=output))
    assert json.loads(output.read_text()) == result
    assert result["cases"] == [{"scenario": "complete", "passed": True}]
    assert result["failed_stage"] == "partial:assertions"
    assert result["commands"][0]["exit_code"] == 2
    assert result["failure_sites"][-1]["function"] == "fail_late"
    assert result["state"] == "failed" and not result["passed"]
    assert "PRIVATE" not in output.read_text()


def test_checkpoint_remains_incomplete_when_execution_is_interrupted(tmp_path):
    output = tmp_path / "acceptance.json"
    evidence = ValidationEvidence(output, "test")
    evidence.complete_case({"scenario": "complete", "passed": True})

    def interrupted():
        raise KeyboardInterrupt()

    with pytest.raises(KeyboardInterrupt):
        evidence.invoke("partial:scan", interrupted)
    recorded = json.loads(output.read_text())
    assert recorded["state"] == "running" and not recorded["passed"]
    assert recorded["stage"] == "partial:scan"
    assert len(recorded["cases"]) == 1


def test_timeout_keeps_output_identity_without_output(tmp_path):
    evidence = ValidationEvidence(tmp_path / "result.json", "test")

    def timeout():
        raise subprocess.TimeoutExpired([], 1, output=b"SECRET", stderr=b"PRIVATE")

    with pytest.raises(subprocess.TimeoutExpired) as caught:
        evidence.invoke("scan", timeout)
    result = evidence.fail(caught.value)
    assert result["commands"][0]["timed_out"]
    assert result["commands"][0]["stdout"]["bytes"] == 6
    assert "SECRET" not in json.dumps(result)


def test_only_normalized_reports_are_retained(tmp_path):
    report = tmp_path / "temporary"
    (report / "evidence").mkdir(parents=True)
    (report / "findings.json").write_text('{"findings": []}')
    (report / "raw-source.py").write_text("SECRET")
    (report / "evidence/semgrep.json").write_text('{"status": "completed"}')
    evidence = ValidationEvidence(tmp_path / "result.json", "test")
    evidence.retain_report(report, "complete", ["semgrep"])
    saved = evidence.run_directory / "complete"
    assert (saved / "findings.json").read_bytes() == (
        report / "findings.json"
    ).read_bytes()
    assert not (saved / "raw-source.py").exists()
    assert len(evidence.document["artifacts"]["complete"]) == 2


def test_a_later_run_does_not_erase_the_failed_run(tmp_path):
    first = ValidationEvidence(tmp_path / "result.json", "test")
    first.fail(ValueError("private"))
    second = ValidationEvidence(tmp_path / "result.json", "test")
    second.finish({"passed": True})
    assert first.run_directory != second.run_directory
    assert (
        json.loads((first.run_directory / "run.json").read_text())["state"] == "failed"
    )
    assert (
        json.loads((second.run_directory / "run.json").read_text())["state"] == "passed"
    )


def test_disk_full_preserves_the_previous_checkpoint(tmp_path, monkeypatch):
    output = tmp_path / "result.json"
    evidence = ValidationEvidence(output, "test")
    evidence.stage("before-scan")
    before = output.read_bytes()

    def disk_full(*args):
        raise OSError(errno.ENOSPC, "No space left on device")

    monkeypatch.setattr(validation_evidence.os, "replace", disk_full)
    with pytest.raises(OSError) as caught:
        evidence.finish({"passed": True})
    assert caught.value.errno == errno.ENOSPC
    assert output.read_bytes() == before
    assert json.loads(before)["passed"] is False
    assert not list(tmp_path.rglob(".validation-*"))


def test_concurrent_runs_retain_separate_complete_archives(tmp_path):
    def validate(index):
        evidence = ValidationEvidence(tmp_path / "result.json", "concurrent test")
        evidence.finish({"passed": True, "index": index})
        return evidence.run_directory

    with ThreadPoolExecutor(max_workers=4) as executor:
        directories = list(executor.map(validate, range(8)))
    records = [
        json.loads((directory / "run.json").read_text()) for directory in directories
    ]
    assert len({record["run_id"] for record in records}) == 8
    assert {record["index"] for record in records} == set(range(8))
    latest = json.loads((tmp_path / "result.json").read_text())
    assert latest in records and latest["state"] == "passed"


@pytest.mark.parametrize("permanent", [False, True])
def test_windows_sharing_retries_are_bounded(tmp_path, monkeypatch, permanent):
    output = tmp_path / "report.json"
    original_replace = validation_evidence.os.replace
    calls, pauses = [], []

    def replace(source, destination):
        calls.append(destination)
        if permanent or len(calls) < 3:
            error = PermissionError("sharing violation")
            error.winerror = 32
            raise error
        original_replace(source, destination)

    monkeypatch.setattr(validation_evidence.os, "replace", replace)
    monkeypatch.setattr(validation_evidence.time, "sleep", pauses.append)
    if permanent:
        with pytest.raises(PermissionError):
            validation_evidence.atomic_json(output, {"passed": True})
        assert len(calls) == 6 and len(pauses) == 5
        assert not output.exists()
    else:
        validation_evidence.atomic_json(output, {"passed": True})
        assert len(calls) == 3 and len(pauses) == 2
        assert json.loads(output.read_text())["passed"]
    assert not list(tmp_path.glob(".validation-*"))
