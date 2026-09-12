"""Exercise platform cleanup failures without requiring another operating system."""

import io
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from py_security_suite import bounded_subprocess as bounded


def process_fixture(monkeypatch, platform):
    process = MagicMock(pid=1234, returncode=0)
    process.poll.return_value = 0
    process.stdin = io.BytesIO()
    process.stdout = io.BytesIO(b"complete")
    process.stderr = io.BytesIO()
    launch = MagicMock(return_value=process)
    monkeypatch.setattr(bounded.subprocess, "Popen", launch)
    monkeypatch.setattr(bounded, "os", SimpleNamespace(name=platform))
    return process, launch


def run():
    return bounded.run_bounded_subprocess(
        ["approved-helper"],
        input_bytes=b"request",
        timeout_seconds=1,
        maximum_stdout_bytes=1024,
        maximum_stderr_bytes=1024,
        environment={},
    )


def test_windows_gate_and_job_cleanup_are_used_on_success(monkeypatch):
    process, launch = process_fixture(monkeypatch, "nt")
    assign = MagicMock(return_value=((), (), 42))
    close = MagicMock()
    monkeypatch.setattr(bounded, "apply_windows_job_limits", assign)
    monkeypatch.setattr(bounded, "close_windows_handle", close)
    assert run().stdout == b"complete"
    assert bounded._WINDOWS_GATE in launch.call_args.args[0]
    assign.assert_called_once()
    close.assert_called_once_with(42)
    assert all(
        stream.closed for stream in (process.stdin, process.stdout, process.stderr)
    )


def test_windows_job_assignment_failure_closes_all_pipes(monkeypatch):
    process, _ = process_fixture(monkeypatch, "nt")
    monkeypatch.setattr(
        bounded,
        "apply_windows_job_limits",
        MagicMock(side_effect=OSError("job failed")),
    )
    kill = MagicMock()
    monkeypatch.setattr(bounded, "_kill_process_tree", kill)
    with pytest.raises(OSError, match="job failed"):
        run()
    kill.assert_called_once_with(process)
    assert all(
        stream.closed for stream in (process.stdin, process.stdout, process.stderr)
    )


@pytest.mark.parametrize("error", [PermissionError, ProcessLookupError])
def test_posix_group_exit_race_preserves_output_and_closes_pipes(monkeypatch, error):
    process, _ = process_fixture(monkeypatch, "posix")
    monkeypatch.setattr(
        bounded.os, "killpg", MagicMock(side_effect=error), raising=False
    )
    monkeypatch.setattr(bounded, "signal", SimpleNamespace(SIGKILL=9))
    kill = MagicMock()
    monkeypatch.setattr(bounded, "_kill_process_tree", kill)
    assert run().stdout == b"complete"
    assert kill.call_count == int(error is PermissionError)
    assert all(
        stream.closed for stream in (process.stdin, process.stdout, process.stderr)
    )
