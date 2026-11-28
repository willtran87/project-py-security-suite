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


def test_exact_tree_cleanup_kills_descendants_before_parent(monkeypatch):
    order = []
    children = [MagicMock(), MagicMock()]
    for index, child in enumerate(children):
        child.kill.side_effect = lambda i=index: order.append(i)
    parent = MagicMock()
    parent.children.return_value = children
    parent.kill.side_effect = lambda: order.append("parent")
    monkeypatch.setattr(bounded.psutil, "Process", lambda _: parent)
    wait = MagicMock()
    monkeypatch.setattr(bounded.psutil, "wait_procs", wait)
    bounded._kill_process_tree(MagicMock(pid=1234))
    assert order == [1, 0, "parent"]
    parent.children.assert_called_once_with(recursive=True)
    wait.assert_called_once_with(children, timeout=2.0)


@pytest.mark.parametrize("running", [True, False])
def test_missing_tree_uses_owned_process_handle_only_when_running(monkeypatch, running):
    monkeypatch.setattr(
        bounded.psutil,
        "Process",
        MagicMock(side_effect=bounded.psutil.NoSuchProcess(1234)),
    )
    process = MagicMock(pid=1234)
    process.poll.return_value = None if running else 0
    bounded._kill_process_tree(process)
    assert process.kill.call_count == int(running)


def test_tree_cleanup_continues_when_descendants_exit_or_parent_denies_kill(
    monkeypatch,
):
    child = MagicMock()
    child.kill.side_effect = bounded.psutil.NoSuchProcess(1235)
    parent = MagicMock()
    parent.children.return_value = [child]
    parent.kill.side_effect = bounded.psutil.AccessDenied(1234)
    monkeypatch.setattr(bounded.psutil, "Process", lambda _: parent)
    wait = MagicMock()
    monkeypatch.setattr(bounded.psutil, "wait_procs", wait)
    bounded._kill_process_tree(MagicMock(pid=1234))
    parent.kill.assert_called_once()
    wait.assert_called_once_with([child], timeout=2.0)
