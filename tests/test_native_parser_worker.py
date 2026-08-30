from __future__ import annotations

import json
import subprocess  # nosec B404 - isolated worker behavior is the test subject
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from py_security_suite.native_parser_worker import main
from py_security_suite import native_parser_worker


def test_native_parser_worker_reads_bounded_file_and_emits_compact_json(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    target = tmp_path / "native.bin"
    target.write_bytes(b"binary")
    with (
        patch.object(sys, "argv", ["native-parser-worker", str(target)]),
        patch(
            "py_security_suite.boundary_graph._native_imports_in_process",
            return_value=[{"library": "safe.dll"}],
        ),
    ):
        assert main() == 0

    assert json.loads(capsys.readouterr().out) == [{"library": "safe.dll"}]


def test_native_parser_worker_requires_exactly_one_path() -> None:
    with patch.object(sys, "argv", ["native-parser-worker"]):
        with pytest.raises(ValueError, match="requires one path"):
            main()


def test_native_parser_worker_rejects_oversized_input(tmp_path: Path) -> None:
    target = tmp_path / "native.bin"
    target.write_bytes(b"x" * (1024 * 1024 + 1))
    with patch.object(sys, "argv", ["native-parser-worker", str(target)]):
        with pytest.raises(ValueError, match="exceeds 1048576 bytes"):
            main()


def test_native_parser_worker_starts_under_isolated_python_mode(tmp_path: Path) -> None:
    target = tmp_path / "native.bin"
    target.write_bytes(b"x" * (1024 * 1024 + 1))
    completed = subprocess.run(  # noqa: S603  # nosec B603
        [
            sys.executable,
            "-I",
            str(Path(native_parser_worker.__file__).resolve()),
            str(target),
        ],
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    assert completed.returncode != 0
    assert "native parser input exceeds 1048576 bytes" in completed.stderr
    assert "ImportError" not in completed.stderr
