import json
from unittest.mock import patch

import pytest

from py_security_suite.execution import RawExecution
from scripts.qualify_semgrep import qualify


@pytest.mark.parametrize("failure", [None, "rules", "launcher", "native", "output"])
def test_qualification_binds_assets_and_retains_every_failure(tmp_path, failure):
    source = tmp_path / "source"
    source.mkdir()
    (source / "app.py").write_text("pass\n")
    rules = tmp_path / "rules.yml"
    rules.write_text("rules: []\n")
    launcher = tmp_path / "semgrep"
    launcher.write_text("launcher\n")
    calls = 0

    def execute(command, **kwargs):
        nonlocal calls
        calls += 1
        assert "--jobs=2" in command
        assert kwargs["timeout_seconds"] == 600
        if failure in {"rules", "launcher"} and calls == 1:
            (rules if failure == "rules" else launcher).write_text("changed\n")
        payload = json.dumps(
            {
                "version": "test",
                "results": [],
                "errors": [],
                "paths": {"scanned": ["app.py"]},
            }
        )
        return RawExecution(
            command,
            1 if failure == "native" and calls == 1 else 0,
            "PRIVATE_NATIVE_DETAIL" if failure == "output" and calls == 1 else payload,
            "",
            1,
        )

    with patch("scripts.qualify_semgrep.run_command", side_effect=execute):
        report = qualify(source, launcher, rules, 3)
    assert report["passed"] is (failure is None)
    assert len(report["attempts"]) == 3
    assert "PRIVATE" not in json.dumps(report)
    if failure is not None:
        assert not report["attempts"][0]["complete"]
    if failure in {"rules", "launcher"}:
        assert calls == 1
        assert not any(attempt["complete"] for attempt in report["attempts"])
