from __future__ import annotations

import os
import sys

import pytest

from py_security_suite.benchmark_pipeline import run_benchmark_stages
from py_security_suite.bounded_subprocess import (
    BoundedSubprocessError,
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


def test_signing_bridge_output_flood_is_contained() -> None:
    with pytest.raises(BoundedSubprocessError, match="output exceeded limit"):
        run_bounded_subprocess(
            [sys.executable, "-I", "-c", "import sys; sys.stdout.write('x'*65536)"],
            timeout_seconds=5.0,
            maximum_stdout_bytes=1024,
            maximum_stderr_bytes=1024,
            environment=_minimal_environment(),
        )


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
