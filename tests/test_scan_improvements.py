from __future__ import annotations

import ast
import hashlib
import json
import sys
import threading
import time
from pathlib import Path
from unittest.mock import patch

import pytest

from py_security_suite.adapters.base import AdapterResult, ScannerAdapter
from py_security_suite.artifact_validation import validate_governed_artifacts
from py_security_suite.config import (
    ConfigurationError,
    ExecutionConfig,
    SuiteConfig,
    ToolConfig,
    load_config,
)
from py_security_suite.dependency_surface import (
    dependency_surface_artifact,
    inventory_dependencies,
)
from py_security_suite.execution import run_command
from py_security_suite.models import ToolRun, ToolStatus
from py_security_suite.scan_artifacts import ArtifactRegistry
from py_security_suite.scan_control import ScanControl, controlled_scan, stop_reason
from py_security_suite.scan_scheduler import run_adapters
from py_security_suite.source_index import (
    parse_python,
    source_analysis_session,
    source_lines,
)
from py_security_suite.strict_json import canonical_bytes


@pytest.mark.parametrize(
    "field",
    ["max_workers", "max_output_bytes", "max_scan_seconds", "max_scan_memory_bytes"],
)
@pytest.mark.parametrize("value", ["true", "1.9", '"4"'])
def test_execution_rejects_coerced_toml_numbers(
    tmp_path: Path, field: str, value: str
) -> None:
    path = tmp_path / "config.toml"
    path.write_text(f"[execution]\n{field} = {value}\n", encoding="utf-8")
    with pytest.raises(
        ConfigurationError, match=rf"execution\.{field} must be an integer"
    ):
        load_config(repository_config=path)


@pytest.mark.parametrize(
    "field,value",
    [
        ("timeout_seconds", "true"),
        ("minimum_island_loc", "1.9"),
        ("minimum_coverage_percent", "nan"),
        ("maximum_database_age_days", "inf"),
        ("maximum_evidence_age_days", "true"),
    ],
)
def test_tool_numbers_are_typed_and_finite(
    tmp_path: Path, field: str, value: str
) -> None:
    path = tmp_path / "config.toml"
    path.write_text(f"[tools.bandit]\n{field} = {value}\n", encoding="utf-8")
    with pytest.raises(ConfigurationError, match=rf"tools\.bandit\.{field}"):
        load_config(repository_config=path)


def test_omitted_dependency_manifest_cannot_claim_complete_coverage(
    tmp_path: Path,
) -> None:
    payload = b"version = 1\n"
    rows = []
    for index in range(201):
        path = tmp_path / str(index) / "uv.lock"
        path.parent.mkdir()
        path.write_bytes(payload)
        rows.append(
            {
                "manifest": path.relative_to(tmp_path).as_posix(),
                "manifest_sha256": hashlib.sha256(payload).hexdigest(),
            }
        )
    receipt = {"manifests": rows}
    receipt["receipt_sha256"] = hashlib.sha256(canonical_bytes(receipt)).hexdigest()
    inventory = inventory_dependencies(tmp_path)
    with patch(
        "py_security_suite.dependency_surface.read_regular_file",
        side_effect=AssertionError("inventory must be reused"),
    ):
        artifact = dependency_surface_artifact(
            tmp_path,
            [ToolRun("osv-scanner", ToolStatus.COMPLETED, ["osv-scanner"], 0.1)],
            {"osv-manifest-receipts.json": receipt},
            inventory=inventory,
        )
    assert all(row["covered"] for row in artifact["coverage"])
    assert artifact["inventory_counts"]["python"] == {
        "discovered": 201,
        "analyzed": 200,
        "omitted": 1,
    }
    assert artifact["complete"] is False
    validate_governed_artifacts({"dependency-surface.json": artifact})
    artifact["omitted_manifests"] = 0
    with pytest.raises(ValueError, match="accounting"):
        validate_governed_artifacts({"dependency-surface.json": artifact})


def test_historical_dependency_schema_remains_readable(tmp_path: Path) -> None:
    artifact = dependency_surface_artifact(tmp_path, [])
    for name in [
        "inventory_counts",
        "omitted_manifests",
        "manifest_limit_per_ecosystem",
    ]:
        artifact.pop(name)
    artifact["schema_version"] = "1.1"
    assert (
        validate_governed_artifacts({"dependency-surface.json": artifact})[
            "dependency-surface.json"
        ]
        == "dependency-surface-1.1.schema.json"
    )


def test_registry_rejects_collision_without_partial_mutation() -> None:
    registry = ArtifactRegistry()
    registry.add("first", {"shared.json": {"value": 1}})
    with pytest.raises(ValueError, match="first and second"):
        registry.add("second", {"extra.json": {}, "shared.json": {"value": 2}})
    assert registry.values == {"shared.json": {"value": 1}}
    assert registry.producers == {"shared.json": "first"}


@pytest.mark.parametrize("requested", [0, 301])
def test_repository_cannot_disable_or_extend_approved_deadline(
    tmp_path: Path, requested: int
) -> None:
    policy = tmp_path / "policy.toml"
    repository = tmp_path / "repo.toml"
    policy.write_text("[execution]\nmax_scan_seconds = 300\n", encoding="utf-8")
    repository.write_text(
        f"[execution]\nmax_scan_seconds = {requested}\n", encoding="utf-8"
    )
    with pytest.raises(ConfigurationError, match="cannot weaken"):
        load_config(organization_policy=policy, repository_config=repository)


class ControlledAdapter(ScannerAdapter):
    name = "first"
    calls: list[str] = []
    control: ScanControl

    def build_command(self, executable: str, target: Path) -> list[str]:
        return []

    def parse(self, payload: str, target: Path) -> list:
        return []

    def run(self, target: Path) -> AdapterResult:
        self.calls.append(self.name)
        self.control.cancel()
        return AdapterResult(
            [], ToolRun(self.name, ToolStatus.COMPLETED, [self.name], 0.01), {}
        )


class PendingAdapter(ControlledAdapter):
    name = "second"


def test_cancellation_keeps_finished_results_and_skips_queued_tools(
    tmp_path: Path,
) -> None:
    control = ScanControl()
    ControlledAdapter.calls = []
    ControlledAdapter.control = control
    config = SuiteConfig(
        execution=ExecutionConfig(max_workers=1),
        tools={name: ToolConfig(executable=name) for name in ["first", "second"]},
    )
    with controlled_scan(control):
        _, runs, _, _ = run_adapters(
            target=tmp_path,
            config=config,
            selected=["first", "second"],
            adapter_types={"first": ControlledAdapter, "second": PendingAdapter},
        )
    assert ControlledAdapter.calls == ["first"]
    assert [run.status for run in runs] == [ToolStatus.COMPLETED, ToolStatus.SKIPPED]
    assert runs[1].error == "scan cancelled by operator"
    assert stop_reason() == ""


def test_running_scanner_is_terminated_on_cancellation(tmp_path: Path) -> None:
    control = ScanControl()
    timer = threading.Timer(0.5, control.cancel)
    timer.start()
    try:
        with controlled_scan(control):
            result = run_command(
                [sys.executable, "-c", "import time; time.sleep(30)"],
                cwd=tmp_path,
                timeout_seconds=40,
                max_output_bytes=1024,
            )
    finally:
        timer.cancel()
    assert not result.timed_out
    assert result.stop_reason == "scan cancelled by operator"
    assert result.process_tree_terminated
    assert result.duration_seconds < 15


def test_expired_scan_never_launches_another_process(tmp_path: Path) -> None:
    control = ScanControl(timeout_seconds=1, started=time.monotonic() - 2)
    with (
        controlled_scan(control),
        patch("py_security_suite.execution.subprocess.Popen") as launch,
    ):
        with pytest.raises(ValueError, match="deadline exceeded"):
            run_command(
                [sys.executable, "-c", "pass"],
                cwd=tmp_path,
                timeout_seconds=10,
                max_output_bytes=1024,
            )
    launch.assert_not_called()


def test_ast_reuse_is_content_bound_and_ends_with_snapshot(tmp_path: Path) -> None:
    with patch("py_security_suite.source_index.ast.parse", wraps=ast.parse) as parse:
        with source_analysis_session(tmp_path):
            first = parse_python("x = 1", "app.py")
            assert parse_python("x = 1", "app.py") is first
            assert parse_python("x = 2", "app.py") is not first
        with source_analysis_session(tmp_path):
            assert parse_python("x = 1", "app.py") is not first
    assert parse.call_count == 3


def test_excerpt_reads_are_reused_and_oversized_files_are_not_embedded(
    tmp_path: Path,
) -> None:
    path = tmp_path / "app.py"
    path.write_text("hello\n", encoding="utf-8")
    with source_analysis_session(tmp_path):
        first = source_lines(path)
        with patch.object(
            Path, "open", side_effect=AssertionError("duplicate file read")
        ):
            assert source_lines(path) is first
    path.write_bytes(b"x" * (2 * 1024 * 1024 + 1))
    with source_analysis_session(tmp_path):
        assert source_lines(path) is None


def test_json_progress_contains_only_stage_metadata(capsys) -> None:
    from py_security_suite.cli_scan import progress_sink

    control = ScanControl(progress=progress_sink("json"))
    with controlled_scan(control):
        control.emit("scanners", "completed", "bandit")
    output = capsys.readouterr()
    assert output.out == ""
    assert set(json.loads(output.err)) == {"stage", "state", "tool", "elapsed_seconds"}


def test_process_tree_memory_budget_is_latched_after_excess() -> None:
    control = ScanControl(max_memory_bytes=64 * 1024**2)
    with patch(
        "py_security_suite.scan_control._process_tree_resident_bytes",
        return_value=65 * 1024**2,
    ) as sample:
        assert control.reason == "scan process-tree memory budget exceeded"
        assert control.reason == "scan process-tree memory budget exceeded"
    sample.assert_called_once()


def test_memory_accounting_failure_cannot_silently_disable_budget() -> None:
    control = ScanControl(max_memory_bytes=64 * 1024**2)
    with patch(
        "py_security_suite.scan_control._process_tree_resident_bytes",
        side_effect=RuntimeError("unavailable"),
    ):
        assert control.reason == "scan process-tree memory accounting unavailable"


def test_excerpt_line_numbers_ignore_unicode_line_separators(tmp_path: Path) -> None:
    path = tmp_path / "app.py"
    path.write_bytes("first\u2028same-line\r\nsecond\n".encode("utf-8"))
    with source_analysis_session(tmp_path):
        assert source_lines(path) == ("first\u2028same-line", "second")


def test_source_file_enumeration_prunes_excluded_directories(tmp_path: Path) -> None:
    from py_security_suite.source_index import source_files

    (tmp_path / "app.py").write_text("pass", encoding="utf-8")
    excluded = tmp_path / "node_modules"
    excluded.mkdir()
    (excluded / "ignored.py").write_text("pass", encoding="utf-8")
    assert source_files(tmp_path, frozenset({"node_modules"})) == [tmp_path / "app.py"]


def test_memory_budget_cannot_be_disabled_by_repository(tmp_path: Path) -> None:
    policy = tmp_path / "policy.toml"
    repository = tmp_path / "repo.toml"
    policy.write_text(
        "[execution]\nmax_scan_memory_bytes = 67108864\n", encoding="utf-8"
    )
    repository.write_text("[execution]\nmax_scan_memory_bytes = 0\n", encoding="utf-8")
    with pytest.raises(ConfigurationError, match="cannot weaken"):
        load_config(organization_policy=policy, repository_config=repository)
