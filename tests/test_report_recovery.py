from __future__ import annotations

import json
import hashlib
from pathlib import Path
from unittest.mock import patch

import pytest

from py_security_suite.cli import main
from py_security_suite.config import load_config
from py_security_suite.orchestrator import scan_project
from py_security_suite.passport import verify_report
from py_security_suite.report_checkpoint import load_report_inputs
from py_security_suite.reports import is_complete_report, _verify_report_permissions
from tests.test_orchestrator import FakeBandit, FakeSecrets


def test_renderer_failure_preserves_evidence_and_cli_recovers_without_scanning(
    tmp_path: Path,
) -> None:
    target = tmp_path / "project"
    target.mkdir()
    (target / "app.py").write_text("print('fixture')\n", encoding="utf-8")
    output = tmp_path / "report"
    with patch(
        "py_security_suite.reports.render_html", side_effect=ValueError("render failed")
    ):
        with pytest.raises(ValueError, match="render failed") as raised:
            scan_project(
                target=target,
                output=output,
                config=load_config(profile_override="quick"),
                network_isolation_attested=True,
                adapter_types={"bandit": FakeBandit, "detect-secrets": FakeSecrets},
            )
    checkpoints = list(tmp_path.glob(".report.recovery-*"))
    assert len(checkpoints) == 1
    checkpoint = checkpoints[0]
    _verify_report_permissions(checkpoint)
    assert str(checkpoint) in raised.value.__notes__[0]
    assert not output.exists()
    assert not list(tmp_path.glob(".report.staging-*"))
    assert not is_complete_report(checkpoint)
    inputs = load_report_inputs(checkpoint)
    assert inputs.findings
    assert inputs.manifest.tools
    recovered = tmp_path / "recovered"
    with patch(
        "py_security_suite.cli.scan_project",
        side_effect=AssertionError("must not rescan"),
    ):
        assert (
            main(["recover-report", str(checkpoint), "--output", str(recovered)]) == 0
        )
    verify_report(recovered)
    manifest = json.loads(
        (recovered / "scan-manifest.json").read_text(encoding="utf-8")
    )
    assert manifest["scan_id"] == inputs.manifest.scan_id
    assert manifest["outcome"] == inputs.manifest.outcome
    assert not list(tmp_path.glob(".recovered.recovery-*"))
    assert checkpoint.exists()  # Recovery never destroys its source checkpoint.
    assert main(["recover-report", str(checkpoint), "--output", str(recovered)]) == 3
    payload = json.loads((checkpoint / "inputs.json").read_text(encoding="utf-8"))
    payload["inputs"]["manifest"]["outcome"] = "pass"
    payload["inputs"]["manifest"]["scan_id"] = "tampered"
    (checkpoint / "inputs.json").write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="checksum mismatch"):
        load_report_inputs(checkpoint)

    # A recomputed checksum is not a substitute for validating field types.
    payload["inputs"]["manifest"]["duration_seconds"] = True
    payload["inputs_sha256"] = hashlib.sha256(
        json.dumps(payload["inputs"], sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    (checkpoint / "inputs.json").write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="field type"):
        load_report_inputs(checkpoint)


@pytest.mark.parametrize("name", ["../escape", "a/b", "C:stream", "a\\b", ""])
def test_recovery_rejects_diagnostic_path_injection(name: str) -> None:
    from py_security_suite.report_checkpoint import ReportInputs

    with pytest.raises(ValueError, match="unsafe diagnostic tool name"):
        ReportInputs([], None, {name: {}}, True, None)


def test_successful_report_removes_checkpoint(tmp_path: Path) -> None:
    target = tmp_path / "project"
    target.mkdir()
    scan_project(
        target=target,
        output=tmp_path / "report",
        config=load_config(profile_override="quick"),
        network_isolation_attested=False,
    )
    assert not list(tmp_path.glob(".report.recovery-*"))
