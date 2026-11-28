"""Execute a sealed, offline supplemental query pack against the existing database."""

from __future__ import annotations

from pathlib import Path
import os
import re
import sys
from contextlib import nullcontext

from ..execution import (
    CommandEnvironment,
    RawExecution,
    run_command,
    sealed_governed_assets,
)
from ..path_safety import read_regular_file


def locked_pack_paths(rules: Path, home: Path) -> list[Path]:
    _, payload = read_regular_file(
        rules / "codeql-pack.lock.yml", "CodeQL dependency lock", maximum_bytes=65536
    )
    entries = re.findall(
        r"^  ([a-z0-9-]+/[a-z0-9-]+):\n    version: ([0-9]+\.[0-9]+\.[0-9]+)$",
        payload.decode("utf-8").replace("\r\n", "\n"),
        re.MULTILINE,
    )
    if not entries or len(entries) > 64:
        raise ValueError("CodeQL dependency lock is missing or unsupported")
    paths = [
        home / ".codeql" / "packages" / name / version for name, version in entries
    ]
    if any(not (path / "qlpack.yml").is_file() for path in paths):
        raise ValueError("locked CodeQL libraries are not staged in database_path")
    return paths


def run_with_staged_cache(
    command: list[str],
    *,
    home: Path,
    digest: str,
    target: Path,
    environment: CommandEnvironment,
    timeout_seconds: int,
    max_output_bytes: int,
) -> RawExecution:
    with sealed_governed_assets({"database": home}, {"database": digest}) as copies:
        return run_with_cache(
            command,
            home=copies["database"],
            target=target,
            environment=environment,
            timeout_seconds=timeout_seconds,
            max_output_bytes=max_output_bytes,
        )


def run_with_cache(
    command: list[str],
    *,
    home: Path,
    target: Path,
    environment: CommandEnvironment,
    timeout_seconds: int,
    max_output_bytes: int,
) -> RawExecution:
    # HOME stays private; this runtime copy may be modified by the scanner.
    bootstrap = (
        "import os,pathlib,shutil,subprocess,sys; "
        "shutil.copytree(pathlib.Path(sys.argv[1])/'.codeql', "
        "pathlib.Path(os.environ['HOME'])/'.codeql'); "
        "sys.exit(subprocess.call(sys.argv[2:]))"
    )
    return run_command(
        [sys.executable, "-I", "-c", bootstrap, str(home), *command],
        cwd=target,
        environment=environment,
        timeout_seconds=timeout_seconds,
        max_output_bytes=max_output_bytes,
    )


def supplemental_queries(
    *,
    cli: str,
    target: Path,
    rules: Path,
    rules_digest: str,
    home: Path,
    environment: CommandEnvironment,
    timeout_seconds: int,
    max_output_bytes: int,
    already_sealed: bool = False,
) -> str:
    if timeout_seconds <= 0:
        raise ValueError("CodeQL budget exhausted before supplemental queries")
    database = target / ".codeql" / "db-python"
    output = target / ".codeql" / "supplemental.sarif"
    context = (
        nullcontext({"rules": rules})
        if already_sealed
        else sealed_governed_assets({"rules": rules}, {"rules": rules_digest})
    )
    with context as copies:
        libraries = locked_pack_paths(copies["rules"], home)
        result = run_command(
            [
                cli,
                "database",
                "analyze",
                str(database),
                str(copies["rules"]),
                "--rerun",
                "--format=sarif-latest",
                f"--output={output}",
                "--threads=2",
                "--ram=2048",
                "--additional-packs=" + os.pathsep.join(map(str, libraries)),
            ],
            cwd=target,
            timeout_seconds=timeout_seconds,
            max_output_bytes=max_output_bytes,
            environment=environment,
        )
        if (
            result.exit_code
            or result.timed_out
            or result.stop_reason
            or result.output_limit_exceeded
        ):
            raise ValueError(
                "supplemental CodeQL queries did not complete; check staged query dependencies and CLI compatibility"
            )
        _, payload = read_regular_file(
            output,
            "supplemental CodeQL results",
            maximum_bytes=max_output_bytes,
            boundary=target,
        )
    return payload.decode("utf-8")
