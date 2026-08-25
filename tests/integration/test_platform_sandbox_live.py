from __future__ import annotations

import hashlib
import os
import platform
import shutil
import socket
import sys
import tempfile
import threading
from pathlib import Path

import pytest

from py_security_suite.execution import (
    CommandEnvironment,
    native_runtime_closure_sha256,
    run_command,
)
from py_security_suite.strict_json import loads as strict_loads
from tests.integration.windows_appcontainer import (
    run_in_empty_appcontainer,
    run_in_empty_appcontainer_verified,
)


pytestmark = pytest.mark.integration


@pytest.mark.skipif(
    platform.system() != "Windows",
    reason="AppContainer qualification only applies to Windows",
)
@pytest.mark.enable_socket
def test_windows_appcontainer_denies_host_reads_and_network() -> None:
    system = Path(os.environ["SYSTEMROOT"]) / "System32"
    command = system / "cmd.exe"
    curl = system / "curl.exe"
    assert command.is_file()
    assert curl.is_file()
    with tempfile.TemporaryDirectory() as directory:
        secret = Path(directory) / "credential-canary"
        secret.write_bytes(os.urandom(32))
        assert run_in_empty_appcontainer([str(command), "/d", "/c", "exit", "0"]) == 0
        assert (
            run_in_empty_appcontainer([str(command), "/d", "/c", "type", str(secret)])
            != 0
        )
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(4)
    connected = threading.Event()

    def serve() -> None:
        try:
            connection, _ = listener.accept()
        except OSError:
            return
        connected.set()
        with connection:
            connection.sendall(
                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK"
            )

    server = threading.Thread(target=serve, daemon=True)
    server.start()
    try:
        execution = run_in_empty_appcontainer_verified(
            [
                str(curl),
                "--fail",
                "--max-time",
                "2",
                f"http://127.0.0.1:{listener.getsockname()[1]}/",
            ]
        )
        assert execution.exit_code != 0
        assert execution.token_is_appcontainer is True
        assert execution.capability_count == 0
        connected.wait(timeout=0.25)
        assert not connected.is_set()
    finally:
        listener.close()
        server.join(timeout=5)


def _exercise_sandbox(executable: str, arguments: tuple[str, ...]) -> None:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    marker = Path.cwd() / ".pysec-real-sandbox-write-canary"
    secret_parents = [
        Path(tempfile.mkdtemp(prefix=f"pysec-sandbox-secret-{index}-"))
        for index in range(3)
    ]
    secrets = [parent / "credential-canary" for parent in secret_parents]
    for secret in secrets:
        secret.write_bytes(os.urandom(32))
    source = (
        "import json,pathlib,socket,sys; result={}; "
        "\ntry:\n s=socket.create_connection(('127.0.0.1',int(sys.argv[1])),timeout=1); s.close(); result['network_denied']=False"
        "\nexcept OSError: result['network_denied']=True"
        "\ntry:\n pathlib.Path(sys.argv[2]).write_text('escape'); result['target_write_denied']=False"
        "\nexcept OSError: result['target_write_denied']=True"
        "\nresult['host_read_denied']=True"
        "\nfor item in sys.argv[3:]:"
        "\n try:\n  pathlib.Path(item).read_bytes(); result['host_read_denied']=False"
        "\n except OSError:\n  pass"
        "\nprint(json.dumps(result,sort_keys=True))"
    )
    path = Path(executable).resolve()
    try:
        result = run_command(
            [
                sys.executable,
                "-I",
                "-c",
                source,
                str(listener.getsockname()[1]),
                str(marker),
                *(str(secret) for secret in secrets),
            ],
            cwd=Path.cwd(),
            timeout_seconds=15,
            max_output_bytes=4096,
            environment=CommandEnvironment(
                sandbox_prefix=(
                    str(path),
                    *(
                        item.replace(
                            "{PYSEC_PROBE_SECRET_PARENT}", str(secret_parents[0])
                        )
                        for item in arguments
                    ),
                ),
                sandbox_executable_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                sandbox_runtime_closure_sha256=native_runtime_closure_sha256(path),
            ),
        )
    finally:
        listener.close()
        marker.unlink(missing_ok=True)
        for secret, parent in zip(secrets, secret_parents, strict=True):
            secret.unlink(missing_ok=True)
            parent.rmdir()
    assert result.exit_code == 0, result.stderr
    assert strict_loads(result.stdout) == {
        "network_denied": True,
        "target_write_denied": True,
        "host_read_denied": True,
    }


@pytest.mark.skipif(
    platform.system() != "Linux" or os.environ.get("PYSEC_RUN_PLATFORM_SANDBOX") != "1",
    reason="live Bubblewrap qualification is enabled in Linux CI",
)
@pytest.mark.enable_socket
def test_linux_bubblewrap_enforces_network_and_read_only_target() -> None:
    executable = shutil.which("bwrap")
    assert executable
    candidates = {
        path.resolve()
        for path in (
            Path("/usr"),
            Path("/bin"),
            Path("/lib"),
            Path("/lib64"),
            Path(sys.base_prefix),
            Path(getattr(sys, "_base_executable", sys.executable))
            .resolve()
            .parent.parent,
            Path(sys.executable).resolve().parent.parent,
            Path.cwd(),
        )
        if path.exists()
    }
    readable_roots = sorted(
        (
            path
            for path in candidates
            if not any(
                path != other and path.is_relative_to(other) for other in candidates
            )
        ),
        key=str,
    )
    bind_arguments: list[str] = []
    created: set[Path] = set()
    for root in readable_roots:
        for parent in reversed(root.resolve().parents):
            if parent != Path("/") and parent not in created:
                bind_arguments.extend(("--dir", str(parent)))
                created.add(parent)
        bind_arguments.extend(("--ro-bind", str(root.resolve()), str(root.resolve())))
        created.add(root.resolve())
    _exercise_sandbox(
        executable,
        (
            "--unshare-net",
            "--unshare-ipc",
            "--unshare-pid",
            "--unshare-uts",
            "--new-session",
            "--die-with-parent",
            "--tmpfs",
            "/tmp",  # noqa: S108 - private sandbox scratch mount
            *bind_arguments,
            "--dev",
            "/dev",
            "--proc",
            "/proc",
            "--",
        ),
    )


@pytest.mark.skipif(
    platform.system() != "Darwin"
    or os.environ.get("PYSEC_RUN_PLATFORM_SANDBOX") != "1",
    reason="live sandbox-exec qualification is enabled in macOS CI",
)
@pytest.mark.enable_socket
def test_macos_sandbox_enforces_network_and_read_only_target() -> None:
    executable = shutil.which("sandbox-exec")
    assert executable
    readable = sorted(
        {
            "/System",
            "/usr",
            "/Library",
            str(Path(sys.base_prefix).resolve()),
            str(Path.cwd().resolve()),
        }
    )
    read_rules = "".join(f'(allow file-read* (subpath "{path}"))' for path in readable)
    profile = (
        "(version 1)(deny default)(allow process-exec)(allow sysctl-read)"
        '(allow mach-lookup)(allow file-write* (subpath "/private/tmp"))' + read_rules
    )
    _exercise_sandbox(executable, ("-p", profile))
