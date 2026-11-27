from __future__ import annotations

import json
import shutil
import time
from pathlib import Path
from unittest.mock import patch

from py_security_suite.config import load_config
from py_security_suite.models import Outcome, ToolStatus
from py_security_suite.orchestrator import scan_project
from py_security_suite.passport import verify_report
from py_security_suite.scan_control import ScanControl, controlled_scan
from py_security_suite.scan_scheduler import run_adapters
from tests.test_orchestrator import FakeBandit, FakeSecrets


def test_cleanup_error_does_not_turn_published_report_into_failure(
    tmp_path: Path, caplog
) -> None:
    target = tmp_path / "project"
    target.mkdir()
    remove = shutil.rmtree

    def deny_cleanup(path, *args, **kwargs):
        if Path(path).name.startswith(".report.recovery-"):
            raise PermissionError("cleanup denied")
        return remove(path, *args, **kwargs)

    with patch(
        "py_security_suite.report_cleanup.shutil.rmtree", side_effect=deny_cleanup
    ):
        result = scan_project(
            target=target,
            output=tmp_path / "report",
            config=load_config(profile_override="quick"),
            network_isolation_attested=False,
        )
    verify_report(tmp_path / "report")
    assert result.outcome == Outcome.INCOMPLETE
    assert list(tmp_path.glob(".report.recovery-*"))
    assert "Report cleanup incomplete" in caplog.text


def test_cancellation_during_enrichment_skips_new_analysis_and_keeps_finished_scanners(
    tmp_path: Path,
) -> None:
    target = tmp_path / "project"
    target.mkdir()
    events = []
    control = ScanControl(progress=events.append)

    def cancel(**kwargs):
        control.cancel()
        return []

    with (
        controlled_scan(control),
        patch(
            "py_security_suite.orchestrator.apply_source_assurance", side_effect=cancel
        ) as source,
        patch(
            "py_security_suite.orchestrator.analyze_domain_assurance",
            side_effect=AssertionError("analysis after stop"),
        ),
        patch(
            "py_security_suite.orchestrator.build_llm_adversarial_plan",
            side_effect=AssertionError("planning after stop"),
        ),
        patch(
            "py_security_suite.scan_enrichment.build_industry_assurance",
            side_effect=AssertionError("industry analysis after stop"),
        ),
    ):
        result = scan_project(
            target=target,
            output=tmp_path / "report",
            config=load_config(profile_override="quick"),
            network_isolation_attested=True,
            adapter_types={"bandit": FakeBandit, "detect-secrets": FakeSecrets},
        )
    source.assert_called_once()
    assert result.outcome == Outcome.INCOMPLETE
    assert all(run.status == ToolStatus.COMPLETED for run in result.tool_runs)
    assert result.findings
    assert any(
        event.stage == "evidence-analysis" and event.state == "stopped"
        for event in events
    )
    verify_report(tmp_path / "report")


def test_progress_reports_adapter_failure_after_result_and_retains_duration(
    tmp_path: Path,
) -> None:
    class BrokenAdapter(FakeBandit):
        def run(self, target):
            time.sleep(0.02)
            raise ValueError("private scanner detail")

    events = []
    with controlled_scan(ScanControl(progress=events.append)):
        result = run_adapters(
            target=tmp_path,
            config=load_config(profile_override="quick"),
            selected=["bandit"],
            adapter_types={"bandit": BrokenAdapter},
        )
    assert [event.state for event in events] == ["started", "failed"]
    assert result.tool_runs[0].duration_seconds >= 0.02
    assert "private scanner detail" not in json.dumps(result.diagnostics)
