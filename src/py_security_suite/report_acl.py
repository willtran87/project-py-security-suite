"""Private report permission hardening and verification.

Windows ACL utilities are fixed system binaries. The current principal's SID
is constant for the life of the process, so it is resolved once instead of
launching ``whoami.exe`` for every staging, checkpoint and publication pass.
"""

from __future__ import annotations

import csv
import functools
import json
import os
import re
import subprocess  # nosec B404 - fixed Windows ACL utilities only
from pathlib import Path


def _harden_report_tree(output: Path) -> None:
    for path in output.rglob("*"):
        os.chmod(
            path,
            0o700 if path.is_dir() else 0o600,
        )  # noqa: S103 - private security evidence tree
    os.chmod(output, 0o700)  # noqa: S103 - private security evidence tree
    if os.name == "nt":
        _harden_windows_acl(output)


def _harden_windows_acl(output: Path) -> None:
    system_root = Path(os.environ.get("SYSTEMROOT") or "C:/Windows").resolve()
    whoami = system_root / "System32" / "whoami.exe"
    icacls = system_root / "System32" / "icacls.exe"
    powershell = (
        system_root / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    )
    if not whoami.is_file() or not icacls.is_file() or not powershell.is_file():
        raise OSError("Windows ACL utilities are unavailable")
    sid = _current_windows_sid(whoami)

    subprocess.run(  # noqa: S603  # nosec B603
        [
            str(icacls),
            str(output),
            "/inheritance:r",
            "/grant:r",
            f"*{sid}:F",
            "/T",
            "/C",
            "/Q",
        ],
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        timeout=30,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    # Some managed Windows volumes materialize explicit service or
    # administrator ACEs instead of inherited ACEs. Removing inheritance does
    # not remove those entries, so close the DACL over the current principal
    # explicitly before publishing the report.
    retained_sids = {
        rule_sid for rule_sid, _, _ in _windows_acl_rules(output, powershell)
    }
    for unexpected_sid in sorted(retained_sids - {sid}):
        subprocess.run(  # noqa: S603  # nosec B603
            [
                str(icacls),
                str(output),
                "/remove",
                f"*{unexpected_sid}",
                "/T",
                "/C",
                "/Q",
            ],
            check=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            timeout=30,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )


def _current_windows_sid(whoami: Path) -> str:
    return _cached_windows_sid(str(whoami))


@functools.lru_cache(maxsize=4)
def _cached_windows_sid(whoami: str) -> str:
    identity = subprocess.run(  # noqa: S603  # nosec B603
        [whoami, "/user", "/fo", "csv", "/nh"],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    ).stdout.strip()
    rows = list(csv.reader([identity]))
    sid = rows[0][1] if len(rows) == 1 and len(rows[0]) == 2 else ""
    if re.fullmatch(r"S-1-(?:\d+-)+\d+", sid) is None:
        raise OSError("could not establish the current Windows security identifier")
    return sid


def _verify_report_permissions(output: Path) -> None:
    if os.name != "nt":
        exposed = [
            path for path in (output, *output.rglob("*")) if path.stat().st_mode & 0o077
        ]
        if exposed:
            raise PermissionError(
                f"report permission postcondition failed for {exposed[0]}"
            )
        return
    system_root = Path(os.environ.get("SYSTEMROOT") or "C:/Windows").resolve()
    icacls = system_root / "System32" / "icacls.exe"
    whoami = system_root / "System32" / "whoami.exe"
    powershell = (
        system_root / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    )
    if not icacls.is_file() or not whoami.is_file() or not powershell.is_file():
        raise OSError("Windows ACL verification utility is unavailable")
    subprocess.run(  # noqa: S603  # nosec B603
        [str(icacls), str(output), "/verify", "/T", "/C", "/Q"],
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        timeout=30,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    sid = _current_windows_sid(whoami)
    rules = _windows_acl_rules(output, powershell)
    full_control = 0x1F01FF
    if not rules or any(
        rule_sid != sid
        or access_type != "Allow"
        or rights & full_control != full_control
        for rule_sid, access_type, rights in rules
    ):
        raise PermissionError("report Windows ACL postcondition failed")


def _windows_acl_rules(output: Path, powershell: Path) -> list[tuple[str, str, int]]:
    """Read every report DACL rule as ``(sid, Allow|Deny, access mask)``.

    The native reader avoids starting PowerShell (about a second per call,
    several calls per report) and is used whenever the Win32 API is present;
    PowerShell remains the fallback contract.
    """
    if os.name == "nt":  # pragma: no cover - exercised on Windows
        return _native_windows_acl_rules(output)
    return _powershell_windows_acl_rules(output, powershell)


def _native_windows_acl_rules(
    output: Path,
) -> list[tuple[str, str, int]]:  # pragma: no cover - Windows only
    import ctypes
    from ctypes import wintypes

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)  # type: ignore[attr-defined]
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined]
    advapi32.GetNamedSecurityInfoW.argtypes = [
        wintypes.LPCWSTR,
        ctypes.c_int,
        wintypes.DWORD,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    advapi32.GetNamedSecurityInfoW.restype = wintypes.DWORD
    advapi32.GetAce.argtypes = [
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    advapi32.GetAce.restype = wintypes.BOOL
    advapi32.ConvertSidToStringSidW.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.LPWSTR),
    ]
    advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p

    class ACL(ctypes.Structure):
        _fields_ = [
            ("AclRevision", ctypes.c_ubyte),
            ("Sbz1", ctypes.c_ubyte),
            ("AclSize", ctypes.c_ushort),
            ("AceCount", ctypes.c_ushort),
            ("Sbz2", ctypes.c_ushort),
        ]

    class ACE(ctypes.Structure):
        _fields_ = [
            ("AceType", ctypes.c_ubyte),
            ("AceFlags", ctypes.c_ubyte),
            ("AceSize", ctypes.c_ushort),
            ("Mask", wintypes.DWORD),
            ("SidStart", wintypes.DWORD),
        ]

    rules: list[tuple[str, str, int]] = []
    for path in (output, *output.rglob("*")):
        dacl = ctypes.c_void_p()
        descriptor = ctypes.c_void_p()
        status = advapi32.GetNamedSecurityInfoW(
            str(path), 1, 0x4, None, None, ctypes.byref(dacl), None,
            ctypes.byref(descriptor),
        )  # fmt: skip
        if status != 0:
            raise OSError(status, "Windows ACL inspection failed", str(path))
        try:
            if not dacl.value:
                # A NULL DACL grants everyone full access.
                rules.append(("S-1-1-0", "Allow", 0x1F01FF))
                continue
            header = ACL.from_address(dacl.value)
            for index in range(header.AceCount):
                entry = ctypes.c_void_p()
                if not advapi32.GetAce(dacl, index, ctypes.byref(entry)):
                    raise OSError("Windows ACL inspection returned an invalid rule")
                ace = ACE.from_address(entry.value or 0)
                if ace.AceType not in {0, 1}:
                    raise OSError("Windows ACL contains an unsupported rule type")
                text = wintypes.LPWSTR()
                sid_address = (entry.value or 0) + ACE.SidStart.offset
                if not advapi32.ConvertSidToStringSidW(
                    ctypes.c_void_p(sid_address), ctypes.byref(text)
                ):
                    raise OSError("Windows ACL inspection returned an invalid rule")
                try:
                    sid = str(text.value or "")
                finally:
                    kernel32.LocalFree(ctypes.cast(text, ctypes.c_void_p))
                rules.append(
                    (sid, "Allow" if ace.AceType == 0 else "Deny", int(ace.Mask))
                )
        finally:
            kernel32.LocalFree(descriptor)
    return rules


def _powershell_windows_acl_rules(
    output: Path, powershell: Path
) -> list[tuple[str, str, int]]:
    """Read every effective report DACL rule with names translated to SIDs."""
    script = """
$ErrorActionPreference = 'Stop'
Import-Module (
  Join-Path $env:SystemRoot 'System32/WindowsPowerShell/v1.0/Modules/Microsoft.PowerShell.Security/Microsoft.PowerShell.Security.psd1'
)
$paths = @((Get-Item -LiteralPath $env:PYSEC_ACL_PATH -Force))
$paths += @(Get-ChildItem -LiteralPath $env:PYSEC_ACL_PATH -Force -Recurse)
$rules = @(
  foreach ($path in $paths) {
    foreach ($rule in (Get-Acl -LiteralPath $path.FullName).Access) {
      [PSCustomObject]@{
        sid = $rule.IdentityReference.Translate(
          [System.Security.Principal.SecurityIdentifier]
        ).Value
        type = $rule.AccessControlType.ToString()
        rights = [Int64]$rule.FileSystemRights
      }
    }
  }
)
ConvertTo-Json -InputObject $rules -Compress
"""
    environment = os.environ.copy()
    environment["PYSEC_ACL_PATH"] = str(output)
    completed = subprocess.run(  # noqa: S603  # nosec B603
        [
            str(powershell),
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        ],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
        timeout=30,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if completed.returncode != 0:
        diagnostic = completed.stderr.strip().replace("\r", " ").replace("\n", " ")
        raise OSError("Windows ACL inspection failed: " + diagnostic[:512])
    payload = json.loads(completed.stdout)
    if not isinstance(payload, list):
        raise OSError("Windows ACL inspection returned an invalid contract")
    rules: list[tuple[str, str, int]] = []
    for entry in payload:
        if not isinstance(entry, dict):
            raise OSError("Windows ACL inspection returned an invalid rule")
        rule_sid = entry.get("sid")
        access_type = entry.get("type")
        rights = entry.get("rights")
        if (
            not isinstance(rule_sid, str)
            or re.fullmatch(r"S-1-(?:\d+-)+\d+", rule_sid) is None
            or access_type not in {"Allow", "Deny"}
            or not isinstance(rights, int)
        ):
            raise OSError("Windows ACL inspection returned an invalid rule")
        rules.append((rule_sid, access_type, rights))
    return rules
