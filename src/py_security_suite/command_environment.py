"""Build isolated scanner environments with explicitly pinned helper executables."""

from __future__ import annotations

import hashlib
import os
import re
import sys
from pathlib import Path

from .path_safety import read_regular_file


def isolate_python_command(command: list[str], cache: Path) -> list[str]:
    """Bind direct Python launches even when -I/-E ignores environment settings."""
    if command and re.fullmatch(
        r"python(?:\d+(?:\.\d+)*)?(?:w)?(?:\.exe)?", Path(command[0]).name, re.I
    ):
        return [command[0], "-B", "-X", f"pycache_prefix={cache}", *command[1:]]
    return command


def private_runtime_environment(env: dict[str, str], root: Path) -> None:
    """Keep all writable scanner locations within the supervised workspace."""
    locations = {
        "HOME": root,
        "USERPROFILE": root,
        "APPDATA": root / "AppData" / "Roaming",
        "LOCALAPPDATA": root / "AppData" / "Local",
        "XDG_CACHE_HOME": root / "cache",
        "PYTHONPYCACHEPREFIX": root / "bytecode",
        "TEMP": root / "tmp",
        "TMP": root / "tmp",
        "TMPDIR": root / "tmp",
    }
    for name, path in locations.items():
        path.mkdir(parents=True, exist_ok=True)
        env[name] = str(path)


def isolated_environment(
    extra: dict[str, str] | None = None,
    *,
    executable: str | None = None,
    auxiliary_executables: tuple[tuple[str, str], ...] = (),
) -> dict[str, str]:
    """Construct a low-credential environment for scanner subprocesses."""
    retained = {
        "SYSTEMROOT",
        "WINDIR",
        "COMSPEC",
        "TEMP",
        "TMP",
        "LANG",
        "LC_ALL",
    }
    env = {key: value for key, value in os.environ.items() if key.upper() in retained}
    path_entries = []
    for auxiliary, expected in auxiliary_executables:
        if not Path(auxiliary).is_absolute() or not expected:
            raise ValueError(
                "auxiliary executable requires an absolute path and digest"
            )
        resolved, payload = read_regular_file(
            Path(auxiliary), "auxiliary executable", maximum_bytes=2 * 1024**3
        )
        if hashlib.sha256(payload).hexdigest() != expected:
            raise ValueError("auxiliary executable does not match the approved SHA-256")
        path_entries.append(str(resolved.parent))
    if executable:
        path_entries.append(str(Path(executable).expanduser().resolve().parent))
    path_entries.append(str(Path(sys.executable).resolve().parent))
    if os.name == "nt":
        windows = Path(
            os.environ.get("SYSTEMROOT") or os.environ.get("WINDIR") or "C:/Windows"
        )
        path_entries.extend((str(windows / "System32"), str(windows)))
        env["PATHEXT"] = ".COM;.EXE;.BAT;.CMD"
    else:
        path_entries.extend(("/usr/local/bin", "/usr/bin", "/bin"))
    env["PATH"] = os.pathsep.join(dict.fromkeys(path_entries))
    env.update(
        {
            "PYTHONNOUSERSITE": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
            "SEMGREP_SEND_METRICS": "off",
            "SEMGREP_ENABLE_VERSION_CHECK": "0",
        }
    )
    if extra:
        forbidden = {
            "DYLD_INSERT_LIBRARIES",
            "DYLD_LIBRARY_PATH",
            "LD_LIBRARY_PATH",
            "LD_PRELOAD",
            "PATH",
            "PYTHONHOME",
            "PYTHONPATH",
            "PYTHONPYCACHEPREFIX",
            "PYTHONDONTWRITEBYTECODE",
            "PYTHONNOUSERSITE",
        }
        rejected = sorted(key for key in extra if key.upper() in forbidden)
        if rejected:
            raise ValueError(
                "scanner environment cannot override executable or loader paths: "
                + ", ".join(rejected)
            )
        env.update(extra)
    return env
