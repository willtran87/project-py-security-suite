from __future__ import annotations

import subprocess
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

import py_security_suite.reports as reports


def _completed(
    stdout: str = "[]", *, returncode: int = 0
) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(
        args=["powershell.exe"],
        returncode=returncode,
        stdout=stdout,
        stderr="inspection failed" if returncode else "",
    )


def test_acl_inspection_translates_and_validates_rule_contract() -> None:
    payload = (
        '[{"sid":"S-1-5-21-1","type":"Allow","rights":2032127},'
        '{"sid":"S-1-5-18","type":"Deny","rights":1}]'
    )
    with patch.object(reports.subprocess, "run", return_value=_completed(payload)):
        assert reports._windows_acl_rules(Path("report"), Path("powershell.exe")) == [
            ("S-1-5-21-1", "Allow", 2032127),
            ("S-1-5-18", "Deny", 1),
        ]

    with (
        patch.object(
            reports.subprocess,
            "run",
            return_value=_completed(returncode=1),
        ),
        pytest.raises(OSError, match="ACL inspection failed"),
    ):
        reports._windows_acl_rules(Path("report"), Path("powershell.exe"))

    for invalid in ("{}", "[null]", '[{"sid":"Everyone"}]'):
        with (
            patch.object(reports.subprocess, "run", return_value=_completed(invalid)),
            pytest.raises(OSError, match="invalid"),
        ):
            reports._windows_acl_rules(Path("report"), Path("powershell.exe"))


def test_acl_hardening_removes_every_non_current_principal() -> None:
    current = "S-1-5-21-1"
    run = MagicMock(return_value=_completed())
    with (
        patch.object(Path, "is_file", return_value=True),
        patch.object(reports, "_current_windows_sid", return_value=current),
        patch.object(
            reports,
            "_windows_acl_rules",
            return_value=[
                (current, "Allow", 0x1F01FF),
                ("S-1-5-18", "Allow", 0x1F01FF),
                ("S-1-5-32-544", "Allow", 0x1F01FF),
            ],
        ),
        patch.object(reports.subprocess, "run", run),
    ):
        reports._harden_windows_acl(Path("report"))

    commands = [call.args[0] for call in run.call_args_list]
    assert commands[0][2:5] == ["/inheritance:r", "/grant:r", f"*{current}:F"]
    removed = {command[3] for command in commands[1:]}
    assert removed == {"*S-1-5-18", "*S-1-5-32-544"}


def test_acl_verification_requires_one_allowed_full_control_principal() -> None:
    current = "S-1-5-21-1"
    fake_os = SimpleNamespace(name="nt", environ={"SYSTEMROOT": "C:/Windows"})

    def verify(rules: list[tuple[str, str, int]]) -> None:
        with (
            patch.object(reports, "os", fake_os),
            patch.object(Path, "is_file", return_value=True),
            patch.object(reports.subprocess, "run", return_value=_completed()),
            patch.object(reports, "_current_windows_sid", return_value=current),
            patch.object(reports, "_windows_acl_rules", return_value=rules),
        ):
            reports._verify_report_permissions(Path("report"))

    verify([(current, "Allow", 0x1F01FF)])

    invalid_rules: tuple[list[tuple[str, str, int]], ...] = (
        [],
        [("S-1-5-18", "Allow", 0x1F01FF)],
        [(current, "Deny", 0x1F01FF)],
        [(current, "Allow", 1)],
    )
    for rules in invalid_rules:
        with pytest.raises(PermissionError, match="ACL postcondition"):
            verify(rules)
