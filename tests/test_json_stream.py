from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from unittest.mock import patch

import pytest

from py_security_suite.json_stream import iter_model_json
from py_security_suite.models import Severity, json_ready
from py_security_suite.report_io import write_json


@dataclass
class Example:
    path: Path
    severity: Severity
    values: dict


def test_streamed_models_preserve_existing_json_and_digest_encoding(
    tmp_path: Path,
) -> None:
    value = Example(
        Path("app.py"), Severity.HIGH, {1: "line\n\u00e9", "two": [True, None, 3.5]}
    )
    expected = json_ready(value)
    assert (
        b"".join(iter_model_json(value))
        == json.dumps(
            expected, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode()
    )
    output = tmp_path / "report.json"
    write_json(output, value)
    assert (
        output.read_text(encoding="utf-8")
        == json.dumps(expected, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    )


@pytest.mark.parametrize("value", [float("nan"), float("inf"), 2**53])
def test_stream_rejects_values_the_recovery_reader_cannot_accept(value) -> None:
    with pytest.raises(ValueError):
        list(iter_model_json({"value": value}))


def test_stream_rejects_nesting_before_recursion_failure() -> None:
    value = []
    for _ in range(65):
        value = [value]
    with pytest.raises(ValueError, match="structure limits"):
        list(iter_model_json(value))


def test_checkpoint_budget_stops_serialization_and_cleanup_cannot_mask_error(
    tmp_path: Path, caplog
) -> None:
    from py_security_suite.report_checkpoint import ReportInputs, preserve_report_inputs

    consumed = []

    def chunks(_value):
        for number in range(100):
            consumed.append(number)
            yield b"x" * 32

    with (
        patch("py_security_suite.report_checkpoint._MAX_BYTES", 128),
        patch("py_security_suite.report_checkpoint.iter_model_json", chunks),
        patch(
            "py_security_suite.report_cleanup.shutil.rmtree",
            side_effect=PermissionError("cleanup failed"),
        ),
    ):
        with pytest.raises(ValueError, match="checkpoint limit"):
            with preserve_report_inputs(
                tmp_path / "report",
                ReportInputs([], None, {}, True, None),
                lambda _path: None,
            ):
                pytest.fail(
                    "rendering must not start after a checkpoint limit violation"
                )
    assert len(consumed) < 100
    retained = next(tmp_path.glob(".report.recovery-*/inputs.json"))
    assert retained.stat().st_size <= 128
    assert "Report cleanup incomplete" in caplog.text
