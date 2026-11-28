"""End-to-end CLI tests that exercise real commands without patching internals.

They drive the published entry point (``python -m py_security_suite``) or
``cli.main`` against a tiny fixture project. Scanner executables are made
unavailable by pointing ``PATH`` at an empty directory, so a scan must finish
INCOMPLETE without any network access (pytest-socket guards the in-process
commands).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from py_security_suite.cli import main
from py_security_suite.version import __version__


def _run_module(*arguments: str, cwd: Path) -> subprocess.CompletedProcess[str]:
    environment = {
        key: value
        for key, value in os.environ.items()
        if key.upper() in {"SYSTEMROOT", "TEMP", "TMP", "TMPDIR", "PYTHONPATH"}
    }
    environment["PATH"] = str(cwd)
    environment["PYTHONIOENCODING"] = "utf-8"
    return subprocess.run(  # noqa: S603 - fixed interpreter and arguments
        [sys.executable, "-m", "py_security_suite", *arguments],
        cwd=cwd,
        env=environment,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=60,
        check=False,
    )


@pytest.fixture
def project(tmp_path: Path) -> Path:
    root = tmp_path / "tiny-project"
    (root / "tiny").mkdir(parents=True)
    (root / "tiny" / "__init__.py").write_text(
        "def add(left: int, right: int) -> int:\n    return left + right\n",
        encoding="utf-8",
    )
    (root / "pyproject.toml").write_text(
        '[project]\nname = "tiny"\nversion = "0.0.1"\n', encoding="utf-8"
    )
    return root


@pytest.fixture
def no_scanners(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    empty = tmp_path / "empty-path"
    empty.mkdir()
    monkeypatch.setenv("PATH", str(empty))
    return empty


def test_entry_point_help_and_version(tmp_path: Path) -> None:
    helped = _run_module("--help", cwd=tmp_path)
    versioned = _run_module("--version", cwd=tmp_path)
    scan_help = _run_module("scan", "--help", cwd=tmp_path)

    assert helped.returncode == 0, helped.stderr
    assert helped.stdout.startswith("usage: pysec")
    for command in ("init", "scan", "verify-report", "config-check"):
        assert command in helped.stdout
    assert versioned.returncode == 0, versioned.stderr
    assert versioned.stdout.strip() == __version__
    assert scan_help.returncode == 0, scan_help.stderr
    assert "--network-isolated" in scan_help.stdout


def test_unknown_command_is_a_usage_error(tmp_path: Path) -> None:
    result = _run_module("no-such-command", cwd=tmp_path)

    assert result.returncode == 2
    assert "invalid choice" in result.stderr


def test_init_writes_a_configuration_that_config_check_accepts(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["init", str(project), "--format", "json"]) == 0
    receipt = json.loads(capsys.readouterr().out)
    config = project / "pysec.toml"

    assert receipt["configuration"] == "pysec.toml"
    assert config.is_file()
    assert main(["config-check", "--config", str(config), "--format", "json"]) == 0
    advice = json.loads(capsys.readouterr().out)
    assert advice["decision"] != "invalid"

    # Re-running init must refuse to clobber the existing configuration.
    assert main(["init", str(project)]) == 3
    assert "pysec: error" in capsys.readouterr().err


def test_config_check_rejects_an_invalid_configuration(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    config = project / "pysec.toml"
    config.write_text("[execution]\nmax_scan_seconds = -5\n", encoding="utf-8")

    status = main(["config-check", "--config", str(config), "--format", "json"])

    captured = capsys.readouterr()
    assert status in {2, 3}
    if status == 2:
        assert json.loads(captured.out)["decision"] == "invalid"
    else:
        assert json.loads(captured.err)["status"] == "error"


def test_scan_without_scanners_is_incomplete_and_report_verifies(
    project: Path,
    no_scanners: Path,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main(["init", str(project), "--profile", "quick"]) == 0
    report = tmp_path / "report"
    capsys.readouterr()

    status = main(
        [
            "scan",
            str(project),
            "--config",
            str(project / "pysec.toml"),
            "--profile",
            "quick",
            "--output",
            str(report),
        ]
    )

    assert status == 2, capsys.readouterr()
    assert capsys.readouterr().out.startswith("INCOMPLETE:")
    for name in ("summary.md", "findings.json", "checksums.sha256", "index.html"):
        assert (report / name).is_file(), name

    assert main(["verify-report", str(report), "--format", "json"]) == 0
    verification = json.loads(capsys.readouterr().out)
    assert verification["outcome"] == "incomplete"

    # Tampering with a sealed artifact must make verification fail closed.
    summary = report / "summary.md"
    summary.write_text(
        summary.read_text(encoding="utf-8") + "\ntampered\n", encoding="utf-8"
    )
    assert main(["verify-report", str(report)]) == 3
    assert "pysec: error" in capsys.readouterr().err
