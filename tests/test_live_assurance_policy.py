from __future__ import annotations

from pathlib import Path

from scripts.validate_live_assurance_policy import main, policy_failures
from scripts.validate_live_test_results import validate_results


def test_repository_live_assurance_policy_is_enforced() -> None:
    assert main() == 0


def test_live_assurance_policy_rejects_missing_gate_and_matrix_coverage() -> None:
    policy = {
        "required_gate": "gate",
        "required_jobs": ["live"],
        "required_matrices": {"live": {"runtime": ["docker", "podman"]}},
    }
    workflow = {
        "jobs": {
            "gate": {"needs": []},
            "live": {"strategy": {"matrix": {"runtime": ["docker"]}}},
        }
    }
    failures = policy_failures(policy, workflow)
    assert len(failures) == 2
    assert "required gate omits" in failures[0]
    assert "podman" in failures[1]


def test_live_result_matrix_requires_every_successful_combination(
    tmp_path: Path,
) -> None:
    policy = {
        "required_test_matrices": {
            "browser": {
                "test": "test_matrix",
                "parameters": {
                    "engine": ["chromium", "firefox"],
                    "role": ["anonymous", "tenant-a"],
                },
            }
        }
    }
    junit = tmp_path / "junit.xml"
    junit.write_text(
        """<?xml version='1.0' encoding='utf-8'?>
<testsuites><testsuite>
  <testcase name="test_matrix[anonymous-chromium]" />
  <testcase name="test_matrix[anonymous-firefox]" />
  <testcase name="test_matrix[tenant-a-chromium]" />
  <testcase name="test_matrix[tenant-a-firefox]" />
</testsuite></testsuites>
""",
        encoding="utf-8",
    )
    result = validate_results(policy, job_name="browser", junit_path=junit)
    assert result["passed"] is True
    assert result["passed_cases"] == 4

    junit.write_text(
        """<testsuite>
  <testcase name="test_matrix[anonymous-chromium]" />
  <testcase name="test_matrix[anonymous-firefox]"><skipped /></testcase>
</testsuite>
""",
        encoding="utf-8",
    )
    result = validate_results(policy, job_name="browser", junit_path=junit)
    assert result["passed"] is False
    assert any("did not pass" in item for item in result["failures"])
    assert any("missing required" in item for item in result["failures"])
