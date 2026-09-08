import json
from unittest.mock import patch

import pytest

from py_security_suite.execution import RawExecution
from scripts.qualify_semgrep import qualify
from scripts.validation_evidence import ValidationEvidence


@pytest.mark.parametrize(
    "failure", [None, "rules", "launcher", "runtime", "native", "output"]
)
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

    snapshots = 0

    def runtime(*args):
        nonlocal snapshots
        snapshots += 1
        return {
            "scanner_python": "python",
            "runtime_closure_sha256": "b" * 64
            if failure == "runtime" and snapshots > 2
            else "a" * 64,
        }

    with (
        patch("scripts.qualify_semgrep.run_command", side_effect=execute),
        patch("scripts.qualify_semgrep.runtime_identity", side_effect=runtime),
    ):
        report = qualify(source, launcher, rules, 3)
    assert report["passed"] is (failure is None)
    assert len(report["attempts"]) == 3
    assert "PRIVATE" not in json.dumps(report)
    if failure is not None:
        assert not report["attempts"][0]["complete"]
    if failure in {"rules", "launcher", "runtime"}:
        assert calls == 1
        assert not any(attempt["complete"] for attempt in report["attempts"])


def test_python_native_closure_uses_the_interpreter_base_install(tmp_path):
    from py_security_suite.execution import _native_dependency_closure

    extension = tmp_path / "venv/site-packages/module.pyd"
    base = tmp_path / "python-base"
    observed = []

    def dependencies(path, application_root):
        observed.append((path, application_root))
        return set()

    with patch(
        "py_security_suite.execution._native_dependencies", side_effect=dependencies
    ):
        assert _native_dependency_closure({extension}, application_root=base) == [
            extension.resolve()
        ]
    assert observed == [(extension.resolve(), base)]


def test_interrupted_qualification_preserves_completed_attempts(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "app.py").write_text("pass\n")
    rules, launcher = tmp_path / "rules.yml", tmp_path / "semgrep"
    rules.write_text("rules: []")
    launcher.write_text("launcher")
    payload = json.dumps(
        {
            "version": "fixture",
            "results": [],
            "errors": [],
            "paths": {"scanned": ["app.py"]},
        }
    )
    evidence = ValidationEvidence(tmp_path / "qualification.json", "fixture")
    with (
        patch(
            "scripts.qualify_semgrep.runtime_identity",
            return_value={
                "scanner_python": "python",
                "runtime_closure_sha256": "a" * 64,
            },
        ),
        patch(
            "scripts.qualify_semgrep.run_command",
            side_effect=[RawExecution([], 0, payload, "", 1), KeyboardInterrupt()],
        ),
        pytest.raises(KeyboardInterrupt),
    ):
        qualify(source, launcher, rules, 3, evidence=evidence)
    recorded = json.loads(evidence.output.read_text())
    assert not recorded["passed"] and recorded["state"] == "running"
    assert len(recorded["attempts"]) == 1 and recorded["attempts"][0]["complete"]
    assert recorded["current_attempt"]["attempt"] == 2
