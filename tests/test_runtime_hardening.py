from __future__ import annotations

import os
import sys
import threading
import time
from pathlib import Path
from unittest.mock import patch

import pytest

from py_security_suite.bounded_subprocess import (
    BoundedSubprocessError,
    run_bounded_subprocess,
)
from py_security_suite.scan_control import (
    ScanControl,
    controlled_scan,
    scan_session,
    stop_reason,
)
from py_security_suite.source_index import SourceIndex, SourceLimitError, parse_python


def _run(program: str, timeout: float = 0.3):
    return run_bounded_subprocess(
        [sys.executable, "-I", "-c", program],
        input_bytes=b"x" * (256 * 1024),
        timeout_seconds=timeout,
        maximum_stdout_bytes=512 * 1024,
        maximum_stderr_bytes=1024,
        environment=os.environ,
    )


def test_timeout_includes_blocked_stdin() -> None:
    started = time.monotonic()
    with pytest.raises(BoundedSubprocessError, match="timed out"):
        _run("import time; time.sleep(10)")
    assert time.monotonic() - started < 5


def test_cancellation_interrupts_blocked_stdin() -> None:
    control = ScanControl()
    timer = threading.Timer(0.3, control.cancel)
    started = time.monotonic()
    timer.start()
    try:
        with (
            controlled_scan(control),
            pytest.raises(BoundedSubprocessError, match="cancelled"),
        ):
            _run("import time; time.sleep(10)", timeout=8)
    finally:
        timer.cancel()
        timer.join()
    assert time.monotonic() - started < 5


def test_output_overflow_interrupts_blocked_stdin() -> None:
    with pytest.raises(BoundedSubprocessError, match="output exceeded"):
        _run(
            "import sys,time; sys.stderr.write('x'*65536); sys.stderr.flush(); time.sleep(10)",
            timeout=5,
        )


def test_large_input_and_output_are_delivered_completely() -> None:
    result = _run(
        "import sys; sys.stdout.buffer.write(sys.stdin.buffer.read())", timeout=5
    )
    assert result.returncode == 0
    assert result.stdout == b"x" * (256 * 1024)


def test_early_child_exit_closes_input_cleanly() -> None:
    assert _run("pass", timeout=5).returncode == 0


def test_nested_scan_enforces_local_deadline_and_restores_parent() -> None:
    started = time.monotonic()
    with patch(
        "py_security_suite.scan_control.time.monotonic", return_value=started
    ) as clock:
        parent = ScanControl(started=started)
        with controlled_scan(parent):
            with scan_session(1):
                clock.return_value = started + 2
                assert stop_reason() == "scan deadline exceeded"
            assert stop_reason() == ""


def test_nested_scan_preserves_parent_deadline_and_cancellation() -> None:
    parent = ScanControl(timeout_seconds=1, started=time.monotonic() - 2)
    with controlled_scan(parent), scan_session(60):
        assert stop_reason() == "scan deadline exceeded"
    parent = ScanControl()
    with controlled_scan(parent), scan_session(0):
        parent.cancel()
        assert stop_reason() == "scan cancelled by operator"


@pytest.mark.parametrize(
    "parent_limit,local_limit", [(0, 64), (64, 0), (64, 256), (256, 64)]
)
def test_nested_memory_limits_cannot_be_weakened(
    parent_limit: int, local_limit: int
) -> None:
    with patch(
        "py_security_suite.scan_control._process_tree_resident_bytes", return_value=128
    ):
        with (
            controlled_scan(ScanControl(max_memory_bytes=parent_limit)),
            scan_session(0, local_limit),
        ):
            assert stop_reason() == "scan process-tree memory budget exceeded"


@pytest.mark.parametrize("value", [True, -1, 1.5, "5"])
def test_direct_control_rejects_invalid_limits(value) -> None:
    with pytest.raises(ValueError, match="nonnegative integer"):
        ScanControl(timeout_seconds=value)


def test_ast_budget_counts_large_literal_payloads(tmp_path: Path) -> None:
    index = SourceIndex(tmp_path)
    for number in range(10):
        index.parse("value = " + repr("x" * 1024**2), f"{number}.py")
    assert 0 < len(index.trees) < 8
    assert 0 < index.retained_ast_bytes <= 8 * 1024**2


@pytest.mark.parametrize(
    "text",
    ["x" * (2 * 1024**2 + 1), "\u00e9" * (1024**2 + 1)],
    ids=["ascii", "multibyte"],
)
def test_source_size_is_checked_before_ast_parser(text: str) -> None:
    with patch("py_security_suite.source_index.ast.parse") as parser:
        with pytest.raises(SourceLimitError):
            parse_python(text, "large.py")
    parser.assert_not_called()


def test_data_inventory_reports_oversized_source_as_omitted(tmp_path: Path) -> None:
    from py_security_suite.data_exposure import _inventory

    (tmp_path / "large.py").write_bytes(b" " * (2 * 1024**2 + 1))
    (tmp_path / "small.py").write_text("pass", encoding="utf-8")
    inventory = _inventory(tmp_path)
    assert inventory["files_analyzed"] == 1
    assert inventory["files_omitted"] == 1
