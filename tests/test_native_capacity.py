from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from scripts import qualify_native_capacity as capacity


@pytest.mark.parametrize(
    ("stdout", "exit_code", "expected"),
    [
        ('{"passed":false,"tool_statuses":{"semgrep":"error"}}', 1, "retained"),
        ('{"passed":true}', 1, "invalid-worker-result"),
        ('{"passed":false}', 0, "invalid-worker-result"),
        ('{"passed":1}', 0, "invalid-worker-result"),
        ("[]", 0, "invalid-worker-result"),
        ("not json", 1, "invalid-worker-result"),
    ],
)
def test_capacity_never_accepts_contradictory_worker_evidence(
    tmp_path, monkeypatch, stdout, exit_code, expected
):
    @contextmanager
    def invocation(*_):
        yield ["python"]

    monkeypatch.setattr(capacity, "isolated_python", invocation)
    monkeypatch.setattr(
        capacity,
        "run_command",
        lambda *a, **kw: SimpleNamespace(
            exit_code=exit_code,
            stop_reason=None,
            timed_out=False,
            output_limit_exceeded=False,
            stdout=stdout,
            stderr="",
        ),
    )
    args = SimpleNamespace(
        source=tmp_path, config=tmp_path / "config", timeout_seconds=30
    )
    result = capacity.collect(args, tmp_path / "report")
    assert result["passed"] is False
    if expected == "retained":
        assert result["tool_statuses"] == {"semgrep": "error"}
    else:
        assert result["error_category"] == expected


def test_capacity_inventory_detects_same_size_edits(tmp_path):
    source = tmp_path / "app.py"
    source.write_bytes(b"print(1)\n")
    before, inventory = capacity.source_digest(tmp_path)
    source.write_bytes(b"print(2)\n")
    after, modified = capacity.source_digest(tmp_path)
    assert before != after
    assert inventory == modified == {"files": 1, "bytes": 9}


def test_capacity_rejects_oversized_source_file(tmp_path):
    with (tmp_path / "app.py").open("wb") as stream:
        stream.truncate(16 * 1024**2 + 1)
    with pytest.raises(ValueError):
        capacity.source_digest(tmp_path)


def test_diagnostic_isolation_gap_cannot_hide_incomplete_analysis():
    isolation = "required external network-isolation attestation was not provided"
    assert capacity.operationally_complete(
        {"outcome": "incomplete", "policy_reasons": [isolation]}
    )
    assert not capacity.operationally_complete(
        {
            "outcome": "incomplete",
            "policy_reasons": [isolation, "partial scanner coverage"],
        }
    )
    assert not capacity.operationally_complete(
        {"outcome": "incomplete", "policy_reasons": []}
    )
