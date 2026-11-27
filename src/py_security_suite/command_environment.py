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
    """Keep writable locations within the supervised workspace.

    Execution uses a short private-root prefix so nested native Unix sockets
    (including Windows Semgrep) retain room for their bounded socket basename.
    """
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
        # Batch files are interpreted by cmd.exe, whose argument parsing turns
        # repository-controlled filenames into commands. Only native images
        # are discoverable, and the working directory (the scanned target) is
        # never searched for helper executables (Go, Python and cmd.exe honour
        # NoDefaultCurrentDirectoryInExePath).
        env["PATHEXT"] = ".COM;.EXE"
        env["NoDefaultCurrentDirectoryInExePath"] = "1"
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
        rejected = sorted(key for key in extra if _loader_variable(key))
        if rejected:
            raise ValueError(
                "scanner environment cannot override executable or loader paths: "
                + ", ".join(rejected)
            )
        env.update(extra)
    return env


# Variables that change which code a dynamic loader, interpreter or helper
# runs. They are never accepted from any scanner environment source.
_LOADER_VARIABLES = frozenset(
    {
        "BASH_ENV",
        "COMSPEC",
        "ENV",
        "NODEFAULTCURRENTDIRECTORYINEXEPATH",
        "PATH",
        "PATHEXT",
        "PYTHONBREAKPOINT",
        "PYTHONDONTWRITEBYTECODE",
        "PYTHONEXECUTABLE",
        "PYTHONHOME",
        "PYTHONINSPECT",
        "PYTHONNOUSERSITE",
        "PYTHONPATH",
        "PYTHONPYCACHEPREFIX",
        "PYTHONSAFEPATH",
        "PYTHONSTARTUP",
        "PYTHONUSERBASE",
        "PYTHONWARNINGS",
    }
)
_LOADER_PREFIXES = ("LD_", "DYLD_")
# Interpreter option variables that load agents or modules. Scanner adapters
# may set them in code (for example a bounded JVM heap for CodeQL), but they
# are never accepted from organization or repository configuration.
_CONFIGURED_CODE_VARIABLES = frozenset(
    {
        "GIT_ASKPASS",
        "GIT_EXEC_PATH",
        "GIT_EXTERNAL_DIFF",
        "GIT_PROXY_COMMAND",
        "GIT_SSH",
        "GIT_SSH_COMMAND",
        "GIT_TEMPLATE_DIR",
        "JAVA_TOOL_OPTIONS",
        "JDK_JAVA_OPTIONS",
        "_JAVA_OPTIONS",
        "NODE_OPTIONS",
        "NODE_PATH",
        "PERL5DB",
        "PERL5LIB",
        "PERL5OPT",
        "PERLLIB",
        "PROMPT_COMMAND",
        "PS4",
        "RUBYLIB",
        "RUBYOPT",
        "SHELLOPTS",
    }
)
_CONFIGURED_CODE_PREFIXES = ("GIT_CONFIG",)


def _loader_variable(name: str) -> bool:
    upper = name.upper()
    return upper in _LOADER_VARIABLES or upper.startswith(_LOADER_PREFIXES)


def reject_configured_code_variables(environment: dict[str, str]) -> None:
    """Reject configuration-sourced variables that inject code into scanners."""
    rejected = sorted(
        key
        for key in environment
        if _loader_variable(key)
        or key.upper() in _CONFIGURED_CODE_VARIABLES
        or key.upper().startswith(_CONFIGURED_CODE_PREFIXES)
    )
    if rejected:
        raise ValueError(
            "configured scanner environment cannot set code-loading variables: "
            + ", ".join(rejected)
        )
