from __future__ import annotations

import os
import re
import shutil
import subprocess  # nosec B404 - scanner execution is this module's purpose
import tempfile
import time
import hashlib
from dataclasses import dataclass, field
from pathlib import Path


_CONTROL_CHARACTERS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b(password|passwd|secret|token|api[_-]?key|private[_-]?key)"
    r"(\s*[=:]\s*)([^\s,;]+)"
)


@dataclass(slots=True)
class RawExecution:
    command: list[str]
    exit_code: int | None
    stdout: str
    stderr: str
    duration_seconds: float
    timed_out: bool = False
    stdout_truncated: bool = False
    stderr_truncated: bool = False


@dataclass(slots=True)
class CommandEnvironment:
    extra: dict[str, str] = field(default_factory=dict)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def resolve_executable(executable: str) -> str | None:
    candidate = Path(executable)
    if candidate.parent != Path(".") or candidate.is_absolute():
        resolved = candidate.expanduser().resolve()
        return str(resolved) if resolved.is_file() else None
    return shutil.which(executable)


def isolated_environment(extra: dict[str, str] | None = None) -> dict[str, str]:
    """Construct a low-credential environment for scanner subprocesses."""
    retained = {
        "PATH",
        "PATHEXT",
        "SYSTEMROOT",
        "WINDIR",
        "COMSPEC",
        "TEMP",
        "TMP",
        "LANG",
        "LC_ALL",
        "LD_LIBRARY_PATH",
        "DYLD_LIBRARY_PATH",
    }
    env = {key: value for key, value in os.environ.items() if key.upper() in retained}
    env.update(
        {
            "PYTHONNOUSERSITE": "1",
            "SEMGREP_SEND_METRICS": "off",
            "SEMGREP_ENABLE_VERSION_CHECK": "0",
        }
    )
    if extra:
        env.update(extra)
    return env


def _decode_and_cap(value: bytes, maximum: int) -> tuple[str, bool]:
    truncated = len(value) > maximum
    capped = value[:maximum]
    return capped.decode("utf-8", errors="replace"), truncated


def run_command(
    command: list[str],
    *,
    cwd: Path,
    timeout_seconds: int,
    max_output_bytes: int,
    environment: CommandEnvironment | None = None,
) -> RawExecution:
    started = time.monotonic()
    creation_flags = 0
    if os.name == "nt":
        creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    try:
        with tempfile.TemporaryDirectory(
            prefix="pysec-process-home-", ignore_cleanup_errors=True
        ) as private_home:
            private_root = Path(private_home)
            process_environment = isolated_environment(
                environment.extra if environment else None
            )
            private_locations = {
                "HOME": private_root,
                "USERPROFILE": private_root,
                "APPDATA": private_root / "AppData" / "Roaming",
                "LOCALAPPDATA": private_root / "AppData" / "Local",
                "XDG_CACHE_HOME": private_root / "cache",
            }
            for name, path in private_locations.items():
                path.mkdir(parents=True, exist_ok=True)
                process_environment.setdefault(name, str(path))
            # Executables are resolved by adapters, arguments are passed as a
            # vector, shell execution is disabled, and the environment is reduced.
            completed = subprocess.run(  # noqa: S603  # nosec B603
                command,
                cwd=cwd,
                env=process_environment,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                timeout=timeout_seconds,
                check=False,
                creationflags=creation_flags,
            )
        stdout, stdout_truncated = _decode_and_cap(completed.stdout, max_output_bytes)
        stderr, stderr_truncated = _decode_and_cap(completed.stderr, max_output_bytes)
        return RawExecution(
            command=command,
            exit_code=completed.returncode,
            stdout=stdout,
            stderr=stderr,
            duration_seconds=time.monotonic() - started,
            stdout_truncated=stdout_truncated,
            stderr_truncated=stderr_truncated,
        )
    except subprocess.TimeoutExpired as exc:
        stdout_bytes = exc.stdout or b""
        stderr_bytes = exc.stderr or b""
        stdout, stdout_truncated = _decode_and_cap(stdout_bytes, max_output_bytes)
        stderr, stderr_truncated = _decode_and_cap(stderr_bytes, max_output_bytes)
        return RawExecution(
            command=command,
            exit_code=None,
            stdout=stdout,
            stderr=stderr,
            duration_seconds=time.monotonic() - started,
            timed_out=True,
            stdout_truncated=stdout_truncated,
            stderr_truncated=stderr_truncated,
        )


def sanitize_diagnostic(value: str, *, maximum: int = 4096) -> str:
    cleaned = _CONTROL_CHARACTERS.sub("", value)
    cleaned = _SECRET_ASSIGNMENT.sub(r"\1\2<redacted>", cleaned)
    if len(cleaned) > maximum:
        cleaned = cleaned[:maximum] + "\n<truncated>"
    return cleaned.strip()
