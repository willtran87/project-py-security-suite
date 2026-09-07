from __future__ import annotations

import os
import sys
import threading
import time
from pathlib import Path
from unittest.mock import patch

import psutil
import pytest

from py_security_suite.bounded_subprocess import run_bounded_subprocess


def test_parent_exit_cannot_leave_pipe_holding_children_or_reader_threads(
    tmp_path: Path,
) -> None:
    marker = tmp_path / "child.pid"
    child_code = "import time; time.sleep(15)"
    program = (
        "import subprocess,sys; from pathlib import Path; "
        f"p=subprocess.Popen([sys.executable,'-I','-c',{child_code!r}]); "
        f"Path({str(marker)!r}).write_text(str(p.pid))"
    )
    before = {thread.ident for thread in threading.enumerate()}
    started = time.monotonic()
    try:
        result = run_bounded_subprocess(
            [sys.executable, "-I", "-c", program],
            timeout_seconds=5,
            maximum_stdout_bytes=1024,
            maximum_stderr_bytes=1024,
            environment=os.environ,
        )
        assert result.returncode == 0
        assert time.monotonic() - started < 5
        child_pid = int(marker.read_text())
        if psutil.pid_exists(child_pid):
            assert psutil.Process(child_pid).status() == psutil.STATUS_ZOMBIE
        assert {thread.ident for thread in threading.enumerate()} == before
    finally:
        if marker.exists():
            try:
                child = psutil.Process(int(marker.read_text()))
                if (
                    child.status() != psutil.STATUS_ZOMBIE
                    and child.cmdline()[-1] == child_code
                ):
                    child.kill()
                    child.wait(timeout=3)
            except psutil.NoSuchProcess:
                pass


@pytest.mark.skipif(os.name != "nt", reason="Windows job assignment gate")
def test_job_assignment_failure_never_runs_caller_code(tmp_path: Path) -> None:
    marker = tmp_path / "must-not-exist"
    program = f"from pathlib import Path; Path({str(marker)!r}).touch()"
    with patch(
        "py_security_suite.bounded_subprocess.apply_windows_job_limits",
        side_effect=OSError("assignment failed"),
    ):
        with pytest.raises(OSError, match="assignment failed"):
            run_bounded_subprocess(
                [sys.executable, "-I", "-c", program],
                timeout_seconds=5,
                maximum_stdout_bytes=1024,
                maximum_stderr_bytes=1024,
                environment=os.environ,
            )
    assert not marker.exists()
