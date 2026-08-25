from __future__ import annotations

from py_security_suite.execution import RawExecution
from py_security_suite.pinned_command import _execution_failure_detail


def test_execution_failure_detail_reports_every_governed_limit() -> None:
    result = RawExecution(
        command=["scanner"],
        exit_code=137,
        stdout="",
        stderr="token=visible\nscanner failed",
        duration_seconds=1.0,
        timed_out=True,
        output_limit_exceeded=True,
        scratch_limit_exceeded=True,
        resident_memory_limit_exceeded=True,
        resource_limit_errors=("open-files: unsupported",),
    )

    assert _execution_failure_detail(result) == (
        "exit code 137; timed out; output limit exceeded; scratch limit exceeded; "
        "resident-memory limit exceeded; resource limits were not enforced; "
        "token=<redacted>\nscanner failed"
    )


def test_execution_failure_detail_accepts_clean_execution() -> None:
    result = RawExecution(
        command=["scanner"],
        exit_code=0,
        stdout='{"accepted":true}',
        stderr="",
        duration_seconds=0.1,
    )

    assert _execution_failure_detail(result) == ""
