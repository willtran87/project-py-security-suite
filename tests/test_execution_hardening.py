"""Regression tests for scanner launch, containment and integrity hardening."""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from py_security_suite.adapters.base import ScannerAdapter
from py_security_suite.command_environment import (
    isolated_environment,
    reject_configured_code_variables,
)
from py_security_suite.config import ToolConfig
from py_security_suite.executable_pin import (
    pin_executable,
    require_windows_image,
    windows_image_error,
)
from py_security_suite.execution import (
    CommandEnvironment,
    RawExecution,
    _BoundedPipeCollector,
    _terminate_process_tree,
    run_command,
    sha256_file,
)
from py_security_suite.models import Finding, ToolStatus
from py_security_suite.report_cleanup import cleanup_directory
from py_security_suite.report_io import write_json, write_text
from py_security_suite.runtime_site_audit import site_directory_records
from py_security_suite.scanner_launch import (
    OutputBudget,
    kill_then_wait,
    launch_failure,
)


class LenientAdapter(ScannerAdapter):
    """Accepts exit 1 and parses empty output as clean, like many real adapters."""

    name = "lenient-test"
    accepted_exit_codes = frozenset({0, 1})

    def build_command(self, executable: str, target: Path) -> list[str]:
        return [executable, "-c", "pass"]

    def parse(self, payload: str, target: Path) -> list[Finding]:
        return []


def _adapter() -> LenientAdapter:
    return LenientAdapter(ToolConfig(executable=sys.executable), 4096)


def test_bootstrap_launch_failure_is_reported_and_never_completed(
    tmp_path: Path,
) -> None:
    missing = tmp_path / "missing-scanner"
    result = run_command(
        [str(missing), "--version"],
        cwd=tmp_path,
        timeout_seconds=20,
        max_output_bytes=4096,
    )
    assert result.exit_code is None
    assert "scanner launch failed during launch" in result.launch_error

    adapter = _adapter()
    with (
        patch.object(adapter, "_detect_version", return_value="test"),
        patch(
            "py_security_suite.adapters.base.run_command",
            return_value=result,
        ),
    ):
        outcome = adapter._run_ready(tmp_path, sys.executable)
    assert outcome.tool_run.status is ToolStatus.FAILED
    assert "launch failed" in (outcome.tool_run.error or "")


def test_launch_failure_marker_is_authoritative_and_bounded(tmp_path: Path) -> None:
    assert launch_failure(tmp_path) == ""
    (tmp_path / "launch-failure.json").write_text(
        '{"stage":"launch","error":"BlockingIOError: [Errno 11] fork"}',
        encoding="utf-8",
    )
    assert launch_failure(tmp_path) == (
        "scanner launch failed during launch: BlockingIOError: [Errno 11] fork"
    )
    (tmp_path / "launch-failure.json").write_text("not-json", encoding="utf-8")
    assert "unreadable" in launch_failure(tmp_path)


def test_containment_failure_is_not_a_normal_exit(tmp_path: Path) -> None:
    with patch(
        "py_security_suite.execution._apply_process_resource_limits",
        return_value=((), ("windows-job:AssignProcessToJobObject failed",), None),
    ):
        result = run_command(
            [sys.executable, "-c", "print('must not run')"],
            cwd=tmp_path,
            timeout_seconds=20,
            max_output_bytes=4096,
        )
    assert result.exit_code is None
    assert result.resource_limit_errors
    assert "must not run" not in result.stdout

    adapter = _adapter()
    with (
        patch.object(adapter, "_detect_version", return_value="test"),
        patch("py_security_suite.adapters.base.run_command", return_value=result),
    ):
        outcome = adapter._run_ready(tmp_path, sys.executable)
    assert outcome.tool_run.status is ToolStatus.FAILED
    assert "containment was not enforced" in (outcome.tool_run.error or "")


def test_resource_limit_errors_fail_the_adapter_even_with_accepted_exit(
    tmp_path: Path,
) -> None:
    adapter = _adapter()
    execution = RawExecution(
        [sys.executable],
        1,
        "",
        "",
        0.1,
        resource_limit_errors=("process-count:Operation not permitted",),
    )
    with (
        patch.object(adapter, "_detect_version", return_value="test"),
        patch("py_security_suite.adapters.base.run_command", return_value=execution),
    ):
        outcome = adapter._run_ready(tmp_path, sys.executable)
    assert outcome.tool_run.status is ToolStatus.FAILED
    assert outcome.findings == []


def test_batch_file_scanners_are_rejected(tmp_path: Path) -> None:
    batch = tmp_path / "shellcheck.cmd"
    batch.write_text("@echo off\r\n", encoding="utf-8")
    script = tmp_path / "scanner.exe"
    script.write_bytes(b"#!/bin/sh\n")
    native = tmp_path / "native.exe"
    native.write_bytes(b"MZ\x90\x00")
    with patch("py_security_suite.executable_pin.os.name", "nt"):
        assert "batch-file" in (windows_image_error(batch) or "")
        assert "not a native PE image" in (windows_image_error(script) or "")
        assert windows_image_error(native) is None
        with pytest.raises(ValueError, match="batch-file"):
            require_windows_image(str(batch))
    with patch("py_security_suite.executable_pin.os.name", "posix"):
        assert windows_image_error(batch) is None


@pytest.mark.skipif(os.name != "nt", reason="Windows batch launch semantics")
def test_batch_file_is_never_launched_on_windows(tmp_path: Path) -> None:
    marker = tmp_path / "ran"
    batch = tmp_path / "scanner.bat"
    batch.write_text(f"@echo off\r\necho ran> {marker}\r\n", encoding="utf-8")
    with pytest.raises(ValueError, match="batch-file"):
        run_command(
            [str(batch), "a&b"],
            cwd=tmp_path,
            timeout_seconds=10,
            max_output_bytes=1024,
        )
    assert not marker.exists()
    adapter = LenientAdapter(ToolConfig(executable=str(batch)), 4096)
    readiness = adapter.preflight(tmp_path)
    assert readiness.status == "unavailable"
    assert "batch-file" in (readiness.reason or "")


def test_isolated_environment_hardens_windows_lookup_and_loader_variables() -> None:
    environment = isolated_environment()
    if os.name == "nt":
        assert environment["PATHEXT"] == ".COM;.EXE"
        assert environment["NoDefaultCurrentDirectoryInExePath"] == "1"
    for name in (
        "LD_AUDIT",
        "DYLD_FRAMEWORK_PATH",
        "PYTHONSTARTUP",
        "BASH_ENV",
        "PathExt",
    ):
        with pytest.raises(ValueError, match="loader paths"):
            isolated_environment({name: "x"})
    # Adapter code may bound a JVM; configuration may not inject agents.
    assert isolated_environment({"JAVA_TOOL_OPTIONS": "-Xmx1g"})[
        "JAVA_TOOL_OPTIONS"
    ] == ("-Xmx1g")
    for name in (
        "NODE_OPTIONS",
        "JAVA_TOOL_OPTIONS",
        "PERL5OPT",
        "RUBYOPT",
        "GIT_SSH_COMMAND",
        "GIT_CONFIG_COUNT",
        "GIT_CONFIG_KEY_0",
        "LD_PRELOAD",
    ):
        with pytest.raises(ValueError, match="code-loading"):
            reject_configured_code_variables({name: "x"})
    reject_configured_code_variables({"PYSEC_TRUST_POLICY_SHA256": "a" * 64})


def test_configured_code_variables_make_scanner_unavailable(tmp_path: Path) -> None:
    adapter = LenientAdapter(
        ToolConfig(
            executable=sys.executable, trust_environment={"NODE_OPTIONS": "-r x"}
        ),
        4096,
    )
    readiness = adapter.preflight(tmp_path)
    assert readiness.status == "unavailable"
    assert "code-loading" in (readiness.reason or "")


def test_private_root_placeholder_is_not_substituted_in_scanner_arguments(
    tmp_path: Path,
) -> None:
    launcher = (
        sys.executable,
        "-c",
        (
            "import pathlib,subprocess,sys; "
            "assert pathlib.Path(sys.argv[1]).is_dir(); "
            "raise SystemExit(subprocess.run(sys.argv[2:]).returncode)"
        ),
        "{PYSEC_PRIVATE_ROOT}",
    )
    result = run_command(
        [
            sys.executable,
            "-c",
            "import sys; print(sys.argv[1])",
            "{PYSEC_PRIVATE_ROOT}",
        ],
        cwd=tmp_path,
        timeout_seconds=20,
        max_output_bytes=1024,
        environment=CommandEnvironment(
            sandbox_prefix=launcher,
            sandbox_executable_sha256=sha256_file(Path(sys.executable)),
        ),
    )
    assert result.exit_code == 0
    assert result.stdout.strip() == "{PYSEC_PRIVATE_ROOT}"


def _site(tmp_path: Path) -> Path:
    site = tmp_path / "site-packages"
    site.mkdir(parents=True)
    return site


def test_site_audit_rejects_unowned_startup_files_and_modules(tmp_path: Path) -> None:
    for name in ("evil.pth", "sitecustomize.py", "usercustomize.py", "planted.py"):
        site = _site(tmp_path / name)
        (site / name).write_text("import os\n", encoding="utf-8")
        with (
            patch(
                "py_security_suite.runtime_site_audit.importlib.metadata.distributions",
                return_value=[],
            ),
            pytest.raises(ValueError, match="no installed distribution owns"),
        ):
            site_directory_records(((site, True),))
    package_site = _site(tmp_path / "package")
    (package_site / "shadow").mkdir()
    with (
        patch(
            "py_security_suite.runtime_site_audit.importlib.metadata.distributions",
            return_value=[],
        ),
        pytest.raises(ValueError, match="shadow"),
    ):
        site_directory_records(((package_site, True),))


def test_site_audit_hashes_owned_and_virtualenv_startup_files(tmp_path: Path) -> None:
    site = _site(tmp_path)
    (site / "owned.pth").write_text("import owned\n", encoding="utf-8")
    (site / "owned").mkdir()
    (site / "_virtualenv.pth").write_text("import _virtualenv\n", encoding="utf-8")
    (site / "_virtualenv.py").write_text("pass\n", encoding="utf-8")
    (site / "README.txt").write_text("not importable\n", encoding="utf-8")
    distribution = MagicMock()
    distribution.locate_file.return_value = site
    distribution.read_text.return_value = "owned.pth,,\nowned/__init__.py,,\n"
    with (
        patch(
            "py_security_suite.runtime_site_audit.importlib.metadata.distributions",
            return_value=[distribution],
        ),
        patch("py_security_suite.runtime_site_audit.sys.base_prefix", "elsewhere"),
    ):
        records = site_directory_records(((site, True),))
        root_only = site_directory_records(((tmp_path, False),))
    assert [record["path"] for record in records] == [
        "_virtualenv.pth",
        "_virtualenv.py",
        "owned.pth",
    ]
    assert root_only == []
    (site / "owned.pth").write_text("import changed\n", encoding="utf-8")
    with (
        patch(
            "py_security_suite.runtime_site_audit.importlib.metadata.distributions",
            return_value=[distribution],
        ),
        patch("py_security_suite.runtime_site_audit.sys.base_prefix", "elsewhere"),
    ):
        assert site_directory_records(((site, True),)) != records


def test_current_environment_site_audit_succeeds() -> None:
    assert isinstance(site_directory_records(), list)


def test_executable_pin_hashes_and_detects_replacement(tmp_path: Path) -> None:
    executable = tmp_path / "scanner.exe"
    executable.write_bytes(b"MZ approved image")
    with pin_executable(executable) as pinned:
        assert pinned.sha256 == sha256_file(executable)
        assert pinned.unchanged()
        replacement = tmp_path / "replacement.exe"
        replacement.write_bytes(b"MZ attacker image")
        if os.name == "nt":
            with pytest.raises(PermissionError):
                os.replace(replacement, executable)
            with pytest.raises(PermissionError):
                executable.write_bytes(b"MZ modified")
            assert pinned.unchanged()
        else:
            os.replace(replacement, executable)
            assert not pinned.unchanged()


def test_adapter_rejects_executable_changed_after_preflight(tmp_path: Path) -> None:
    executable = tmp_path / "scanner.exe"
    executable.write_bytes(b"MZ approved image")
    adapter = LenientAdapter(ToolConfig(executable=str(executable)), 4096)
    adapter._executable_path = executable
    adapter._executable_sha256 = "0" * 64
    with patch("py_security_suite.adapters.base.run_command") as mocked:
        outcome = adapter._run_ready(tmp_path, str(executable))
    mocked.assert_not_called()
    assert outcome.tool_run.status is ToolStatus.FAILED
    assert "changed before execution" in (outcome.tool_run.error or "")


def test_process_cleanup_timeout_never_masks_the_original_error() -> None:
    process = MagicMock()
    process.poll.return_value = None
    process.pid = 4242
    process.wait.side_effect = subprocess.TimeoutExpired("scanner", 10)
    assert kill_then_wait(process, 0.01) is False
    process.kill.assert_called_once()
    with (
        patch("py_security_suite.execution._running_on_windows", return_value=True),
        patch("py_security_suite.execution.Path.is_file", return_value=False),
    ):
        assert _terminate_process_tree(process) is False


def test_bounded_subprocess_cleanup_timeout_is_a_violation() -> None:
    from py_security_suite import bounded_subprocess

    with (
        patch.object(bounded_subprocess, "wait_quietly", return_value=False),
        pytest.raises(bounded_subprocess.BoundedSubprocessError, match="did not exit"),
    ):
        bounded_subprocess.run_bounded_subprocess(
            [sys.executable, "-c", "pass"],
            timeout_seconds=10,
            maximum_stdout_bytes=1024,
            maximum_stderr_bytes=1024,
            environment={
                key: value
                for key, value in os.environ.items()
                if key.upper() in {"SYSTEMROOT", "PATH"}
            },
        )


def test_scratch_accounting_is_throttled(tmp_path: Path) -> None:
    calls: list[float] = []

    def count(_root: Path, _maximum: int) -> bool:
        calls.append(time.monotonic())
        return False

    with patch("py_security_suite.execution._directory_size_exceeds", count):
        run_command(
            [sys.executable, "-c", "import time; time.sleep(1.2)"],
            cwd=tmp_path,
            timeout_seconds=20,
            max_output_bytes=1024,
        )
    # Polling runs every 10 ms; accounting at most every 250 ms plus one final
    # inclusive pass (which may follow the last periodic walk immediately).
    assert len(calls) >= 2
    periodic = calls[:-1]
    gaps = [periodic[index + 1] - periodic[index] for index in range(len(periodic) - 1)]
    assert all(gap >= 0.24 for gap in gaps), gaps


def test_aggregate_output_budget_fails_closed() -> None:
    budget = OutputBudget(10)
    assert budget.reserve(6)
    assert not budget.reserve(5)
    budget.release(6)
    assert budget.reserve(10)

    reader, writer = os.pipe()
    os.write(writer, b"x" * 64)
    os.close(writer)
    with patch("py_security_suite.execution.OUTPUT_BUDGET", OutputBudget(16)):
        collector = _BoundedPipeCollector(os.fdopen(reader, "rb"), 1024)
        payload = collector.finish()
    assert collector.exceeded.is_set()
    assert payload == b""


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux subreaper")
def test_setsid_double_fork_descendant_is_reaped(tmp_path: Path) -> None:
    pid_file = tmp_path / "descendant.pid"
    script = (
        "import os,sys,time\n"
        "if os.fork() == 0:\n"
        "    os.setsid()\n"
        "    if os.fork() == 0:\n"
        f"        open({str(pid_file)!r}, 'w').write(str(os.getpid()))\n"
        "        time.sleep(60)\n"
        "    os._exit(0)\n"
        "time.sleep(0.5)\n"
    )
    result = run_command(
        [sys.executable, "-c", script],
        cwd=tmp_path,
        timeout_seconds=20,
        max_output_bytes=1024,
    )
    assert "descendant-subreaper" in result.resource_limits_enforced
    descendant = int(pid_file.read_text())
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        try:
            os.kill(descendant, 0)
        except ProcessLookupError:
            break
        time.sleep(0.05)
    else:
        pytest.fail("setsid double-fork descendant outlived the scanner")


def test_report_writes_are_durable_and_refuse_links(tmp_path: Path) -> None:
    with patch("py_security_suite.report_io.os.fsync") as fsync:
        write_json(tmp_path / "value.json", {"a": 1})
        write_text(tmp_path / "value.txt", "text\r\n")
    assert fsync.call_count == 2
    assert (tmp_path / "value.txt").read_bytes() == b"text\n"
    victim = tmp_path / "victim"
    victim.write_text("keep", encoding="utf-8")
    link = tmp_path / "link.json"
    try:
        link.symlink_to(victim)
    except OSError:
        pytest.skip("symbolic-link creation is unavailable")
    with pytest.raises(OSError):
        write_json(link, {"overwrite": True})
    assert victim.read_text(encoding="utf-8") == "keep"


def test_cleanup_failure_is_reported_with_retained_path(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    retained = tmp_path / ".report.backup-x"
    retained.mkdir()
    with (
        caplog.at_level(logging.ERROR),
        patch(
            "py_security_suite.report_cleanup.shutil.rmtree",
            side_effect=PermissionError("denied"),
        ),
    ):
        assert not cleanup_directory(retained, contents="previous report backup")
    assert "previous report backup" in caplog.text
    assert str(retained) in caplog.text
    assert cleanup_directory(retained)
    assert not retained.exists()


def test_cleanup_clears_read_only_entries(tmp_path: Path) -> None:
    tree = tmp_path / "tree"
    (tree / "nested").mkdir(parents=True)
    protected = tree / "nested" / "evidence.json"
    protected.write_text("{}", encoding="utf-8")
    os.chmod(protected, 0o400)
    assert cleanup_directory(tree)
    assert not tree.exists()
    shutil.rmtree(tmp_path, ignore_errors=True)


def test_retention_purge_verifies_the_detached_tree_and_restores_on_failure(
    tmp_path: Path,
) -> None:
    from py_security_suite import report_retention

    report = tmp_path / "report"
    report.mkdir()
    (report / "summary.md").write_text("evidence", encoding="utf-8")
    observed: list[Path] = []

    def reject(path: Path, **_kwargs: object) -> dict[str, object]:
        observed.append(path)
        assert not report.exists(), "verification must run after detaching"
        raise ValueError("report checksum mismatch")

    with (
        patch.object(report_retention, "retention_status", side_effect=reject),
        pytest.raises(ValueError, match="checksum mismatch"),
    ):
        report_retention.purge_verified_report(report, require_expired=False)
    assert observed and observed[0] != report
    assert (report / "summary.md").read_text(encoding="utf-8") == "evidence"

    def accept(path: Path, **_kwargs: object) -> dict[str, object]:
        return {"expired": True, "report_checksums_sha256": "0" * 64}

    with patch.object(report_retention, "retention_status", side_effect=accept):
        result = report_retention.purge_verified_report(report, require_expired=False)
    assert result["purged"] is True
    assert not report.exists()
    assert list(tmp_path.glob(".report.purge-*")) == []
