from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import pytest
import psutil
from unittest.mock import MagicMock, patch

from py_security_suite.benchmark_pipeline import run_benchmark_stages
from py_security_suite.bounded_subprocess import (
    BoundedSubprocessError,
    _kill_process_tree,
    run_bounded_subprocess,
)


pytestmark = pytest.mark.resilience


def _minimal_environment() -> dict[str, str]:
    return {
        name: os.environ[name]
        for name in ("SYSTEMROOT", "WINDIR", "TMP", "TEMP")
        if name in os.environ
    }


def test_signing_bridge_timeout_is_contained() -> None:
    with pytest.raises(BoundedSubprocessError, match="timed out"):
        run_bounded_subprocess(
            [sys.executable, "-I", "-c", "import time; time.sleep(2)"],
            timeout_seconds=0.1,
            maximum_stdout_bytes=1024,
            maximum_stderr_bytes=1024,
            environment=_minimal_environment(),
        )


@pytest.mark.parametrize(
    ("argv", "timeout_seconds", "maximum_stdout_bytes"),
    [([], 1.0, 1024), ([sys.executable], 0.0, 1024), ([sys.executable], 1.0, 0)],
)
def test_bounded_subprocess_rejects_unsafe_configuration(
    argv: list[str], timeout_seconds: float, maximum_stdout_bytes: int
) -> None:
    with pytest.raises(BoundedSubprocessError, match="configuration is invalid"):
        run_bounded_subprocess(
            argv,
            timeout_seconds=timeout_seconds,
            maximum_stdout_bytes=maximum_stdout_bytes,
            maximum_stderr_bytes=1024,
            environment=_minimal_environment(),
        )


def test_bounded_subprocess_wraps_spawn_failure() -> None:
    with (
        patch(
            "py_security_suite.bounded_subprocess.subprocess.Popen",
            side_effect=OSError("executable unavailable"),
        ),
        pytest.raises(BoundedSubprocessError, match="could not be started"),
    ):
        run_bounded_subprocess(
            ["missing-executable"],
            timeout_seconds=1.0,
            maximum_stdout_bytes=1024,
            maximum_stderr_bytes=1024,
            environment={},
        )


def test_signing_bridge_output_flood_is_contained() -> None:
    with pytest.raises(BoundedSubprocessError, match="output exceeded limit"):
        run_bounded_subprocess(
            [sys.executable, "-I", "-c", "import sys; sys.stdout.write('x'*65536)"],
            timeout_seconds=5.0,
            maximum_stdout_bytes=1024,
            maximum_stderr_bytes=1024,
            environment=_minimal_environment(),
        )


def test_process_tree_fallback_kills_unobservable_child() -> None:
    process = MagicMock(pid=4242)
    process.poll.return_value = None
    with patch(
        "py_security_suite.bounded_subprocess.psutil.Process",
        side_effect=psutil.NoSuchProcess(4242),
    ):
        _kill_process_tree(process)

    process.kill.assert_called_once_with()


def test_stage_failure_still_executes_cleanup_once() -> None:
    executed: list[str] = []

    def execute(stage: dict[str, object]) -> dict[str, object]:
        name = str(stage["name"])
        executed.append(name)
        return {"name": name, "status": "failed" if name == "attack" else "passed"}

    result = run_benchmark_stages(
        [{"name": "prepare"}, {"name": "attack"}, {"name": "cleanup"}], execute
    )
    assert result.decision == "fail"
    assert executed == ["prepare", "attack", "cleanup"]


def test_timeout_terminates_descendant_process_tree(tmp_path: Path) -> None:
    marker = tmp_path / "orphan-marker"
    child = (
        "import pathlib,time; time.sleep(0.8); "
        f"pathlib.Path({str(marker)!r}).write_text('orphaned')"
    )
    parent = (
        "import subprocess,sys,time; "
        f"subprocess.Popen([sys.executable, '-c', {child!r}]); time.sleep(10)"
    )
    with pytest.raises(BoundedSubprocessError, match="timed out"):
        run_bounded_subprocess(
            [sys.executable, "-I", "-c", parent],
            timeout_seconds=0.2,
            maximum_stdout_bytes=1024,
            maximum_stderr_bytes=1024,
            environment=_minimal_environment(),
        )
    time.sleep(1.0)
    assert not marker.exists()
