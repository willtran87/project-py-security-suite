from __future__ import annotations

import hashlib
import os
import re
import signal
import shutil
import subprocess  # nosec B404 - scanner execution is this module's purpose
import sys
import tempfile
import time
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
    process_tree_terminated: bool = False


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
        resolved_path = candidate.expanduser().resolve()
        return str(resolved_path) if resolved_path.is_file() else None
    resolved_executable = shutil.which(executable)
    if resolved_executable is not None:
        return resolved_executable

    # ``python -m py_security_suite`` is a supported, activation-free entry
    # point. Console scripts installed in the same environment live beside the
    # interpreter, but that directory is not necessarily present on PATH.
    # Keep ordinary PATH precedence, then use the interpreter environment as a
    # deterministic fallback so doctor and scan resolve tools consistently.
    interpreter_bin = Path(sys.executable).resolve().parent
    return shutil.which(executable, path=str(interpreter_bin))


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
        creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) | getattr(
            subprocess, "CREATE_NEW_PROCESS_GROUP", 0
        )
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
        # The lifecycle is explicitly managed below so timeout and interruption
        # can terminate the complete process tree before pipes are closed.
        process = subprocess.Popen(  # noqa: S603  # nosec B603  # pylint: disable=consider-using-with
            command,
            cwd=cwd,
            env=process_environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            creationflags=creation_flags,
            start_new_session=os.name != "nt",
        )
        try:
            stdout_bytes, stderr_bytes = process.communicate(timeout=timeout_seconds)
        except subprocess.TimeoutExpired:
            terminated = _terminate_process_tree(process)
            stdout_bytes, stderr_bytes = process.communicate()
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
                process_tree_terminated=terminated,
            )
        except BaseException:
            _terminate_process_tree(process)
            process.communicate()
            raise
        stdout, stdout_truncated = _decode_and_cap(stdout_bytes, max_output_bytes)
        stderr, stderr_truncated = _decode_and_cap(stderr_bytes, max_output_bytes)
        return RawExecution(
            command=command,
            exit_code=process.returncode,
            stdout=stdout,
            stderr=stderr,
            duration_seconds=time.monotonic() - started,
            stdout_truncated=stdout_truncated,
            stderr_truncated=stderr_truncated,
        )


def _terminate_process_tree(process: subprocess.Popen[bytes]) -> bool:
    """Terminate the exact scanner process group and wait for cleanup."""
    if process.poll() is not None:
        return True
    try:
        if os.name == "nt":
            taskkill = resolve_executable("taskkill")
            if taskkill is None:
                process.kill()
                process.wait(timeout=10)
                return process.poll() is not None
            completed = subprocess.run(  # noqa: S603  # nosec B603
                [taskkill, "/PID", str(process.pid), "/T", "/F"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
                timeout=10,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            if completed.returncode != 0 and process.poll() is None:
                process.kill()
        else:
            kill_process_group = os.__dict__.get("killpg")
            hard_kill = signal.__dict__.get("SIGKILL")
            if not callable(kill_process_group) or hard_kill is None:
                raise OSError("process-group termination is unavailable")
            kill_process_group(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                kill_process_group(process.pid, hard_kill)
    except (OSError, ProcessLookupError, subprocess.SubprocessError):
        if process.poll() is None:
            process.kill()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=10)
    return process.poll() is not None


def sanitize_diagnostic(value: str, *, maximum: int = 4096) -> str:
    cleaned = _CONTROL_CHARACTERS.sub("", value)
    cleaned = _SECRET_ASSIGNMENT.sub(r"\1\2<redacted>", cleaned)
    if len(cleaned) > maximum:
        cleaned = cleaned[:maximum] + "\n<truncated>"
    return cleaned.strip()


def sanitize_terminal_text(value: str, *, maximum: int = 4096) -> str:
    """Return one bounded, redacted line safe for an operator terminal."""
    redacted = _SECRET_ASSIGNMENT.sub(r"\1\2<redacted>", value)
    sanitized = "".join(
        character if character.isprintable() else "�" for character in redacted
    )
    if len(sanitized) <= maximum:
        return sanitized
    return sanitized[: maximum - 1] + "…"
