from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Any

from .bounded_subprocess import BoundedSubprocessError, run_bounded_subprocess
from .path_safety import resolve_regular_file
from .strict_json import canonical_bytes


_OCI_REQUIRED_RUN_OPTIONS = (
    "--cap-drop",
    "--cpus",
    "--env",
    "--init",
    "--memory",
    "--network",
    "--pids-limit",
    "--pull",
    "--read-only",
    "--security-opt",
    "--tmpfs",
    "--ulimit",
    "--user",
    "--volume",
    "--workdir",
)


class BenchmarkRuntimeError(ValueError):
    """Raised when an isolated benchmark runtime contract cannot be enforced."""


def verify_oci_runtime_capabilities(oci: dict[str, Any]) -> dict[str, Any]:
    """Actively verify and digest-pin the selected OCI runtime's required surface."""
    proof = probe_oci_runtime_capabilities(
        runtime_path=Path(oci["runtime"]),
        runtime_sha256=str(oci["runtime_sha256"]),
        runtime_name=str(oci["runtime_name"]),
        runtime_version=str(oci["runtime_version"]),
    )
    if proof["runtime_capabilities_sha256"] != oci["runtime_capabilities_sha256"]:
        raise BenchmarkRuntimeError(
            "OCI runtime capability probe does not match the manifest"
        )
    return proof


def probe_oci_runtime_capabilities(
    *,
    runtime_path: Path,
    runtime_sha256: str,
    runtime_name: str,
    runtime_version: str,
) -> dict[str, Any]:
    """Produce the normalized capability proof used when preparing a manifest."""
    if runtime_name not in {"docker", "podman", "nerdctl"}:
        raise BenchmarkRuntimeError("OCI runtime name is unsupported")
    runtime = resolve_regular_file(runtime_path, "OCI runtime executable")
    computed_runtime_sha256 = _sha256_file(runtime)
    if computed_runtime_sha256 != runtime_sha256:
        raise BenchmarkRuntimeError("OCI runtime digest does not match manifest")
    environment = {
        "PATH": os.path.dirname(str(runtime)),
        "HOME": str(runtime.parent),
        "LANG": "C",
        "LC_ALL": "C",
    }
    version = _run_runtime_probe([str(runtime), "--version"], environment)
    if runtime_version.casefold() not in version.casefold():
        raise BenchmarkRuntimeError("OCI runtime version does not match manifest")
    run_help = _run_runtime_probe([str(runtime), "run", "--help"], environment)
    missing = [option for option in _OCI_REQUIRED_RUN_OPTIONS if option not in run_help]
    if missing:
        raise BenchmarkRuntimeError(
            "OCI runtime lacks required containment options: " + ", ".join(missing)
        )
    proof: dict[str, Any] = {
        "schema_version": "1.0",
        "runtime_name": runtime_name,
        "runtime_sha256": computed_runtime_sha256,
        "runtime_version": runtime_version,
        "required_run_options": list(_OCI_REQUIRED_RUN_OPTIONS),
        "version_output_sha256": hashlib.sha256(version.encode("utf-8")).hexdigest(),
        "run_help_sha256": hashlib.sha256(run_help.encode("utf-8")).hexdigest(),
    }
    proof_sha256 = hashlib.sha256(canonical_bytes(proof)).hexdigest()
    proof["runtime_capabilities_sha256"] = proof_sha256
    return proof


def _run_runtime_probe(argv: list[str], environment: dict[str, str]) -> str:
    try:
        completed = run_bounded_subprocess(
            argv,
            timeout_seconds=15,
            maximum_stdout_bytes=1024 * 1024,
            maximum_stderr_bytes=1024 * 1024,
            environment=environment,
        )
    except (OSError, BoundedSubprocessError) as exc:
        raise BenchmarkRuntimeError("OCI runtime capability probe failed") from exc
    output = (
        (completed.stdout + completed.stderr)
        .decode("utf-8", errors="replace")
        .replace("\r\n", "\n")
    )
    normalized = output.strip()
    if completed.returncode != 0 or not normalized:
        raise BenchmarkRuntimeError("OCI runtime capability probe was rejected")
    return normalized


def build_stage_argv(
    executable: Path,
    stage: dict[str, Any],
    isolation: dict[str, Any],
    workspace: Path,
    corpus: Path,
) -> tuple[list[str], str]:
    """Build a shell-free process or OCI invocation from a validated contract."""
    if isolation["mode"] != "oci":
        return [str(executable), *stage["arguments"]], _sha256_file(executable)
    oci = isolation["oci"]
    runtime = resolve_regular_file(Path(oci["runtime"]), "OCI runtime executable")
    runtime_sha256 = _sha256_file(runtime)
    if runtime_sha256 != oci["runtime_sha256"]:
        raise BenchmarkRuntimeError("OCI runtime digest does not match manifest")
    enhanced = "runtime_name" in oci
    workspace_mount = f"--volume={workspace}:/workspace:{'ro' if enhanced else 'rw'}"
    command = [
        str(runtime),
        "run",
        "--rm",
        "--pull=never",
        "--init",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--network=none",
        f"--pids-limit={oci['pids_limit']}",
        f"--memory={oci['memory_bytes']}",
        f"--cpus={oci['cpu_count']}",
        f"--user={_oci_user()}",
        "--ulimit=nofile=1024:1024",
        "--ulimit=core=0:0",
        "--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=64m",
        workspace_mount,
        f"--volume={corpus}:/corpus/input:ro",
        f"--volume={executable}:/pysec/stage-executable:ro",
        "--workdir=/workspace",
    ]
    if enhanced:
        command.append(
            f"--volume={workspace / '.pysec-output'}:/workspace/.pysec-output:rw"
        )
    command.extend(
        [
            "--env=PYSEC_BENCHMARK_WORKSPACE=/workspace",
            "--env=PYSEC_BENCHMARK_CORPUS=/corpus/input",
            *(f"--env={name}" for name in sorted(stage["environment"])),
        ]
    )
    if oci["seccomp_profile"] is not None:
        profile = resolve_regular_file(Path(oci["seccomp_profile"]), "seccomp profile")
        if enhanced and _sha256_file(profile) != oci["seccomp_profile_sha256"]:
            raise BenchmarkRuntimeError("OCI seccomp profile digest does not match")
        command.append(f"--security-opt=seccomp={profile}")
    if oci["apparmor_profile"] is not None:
        command.append(f"--security-opt=apparmor={oci['apparmor_profile']}")
    command.extend([oci["image"], "/pysec/stage-executable", *stage["arguments"]])
    return command, runtime_sha256


def prepare_oci_output_directory(workspace: Path) -> None:
    """Create the sole OCI writable mount with a safe, empty host boundary."""
    output = workspace / ".pysec-output"
    if output.exists():
        if output.is_symlink() or not output.is_dir():
            raise BenchmarkRuntimeError("OCI output directory is unsafe")
        if any(output.iterdir()):
            raise BenchmarkRuntimeError("OCI output directory must be empty")
    else:
        output.mkdir(mode=0o700)
    getuid = getattr(os, "geteuid", None)
    if os.name == "posix" and getuid is not None and getuid() == 0:
        # The remapped unprivileged container user needs write-only traversal.
        output.chmod(0o733)


def oci_output_gaps(output: Path, oci: dict[str, Any]) -> list[str]:
    """Verify that an OCI stage stayed within its bounded regular-file output."""
    gaps: list[str] = []
    files = 0
    total_bytes = 0
    boundary = output.resolve()
    try:
        for candidate in output.rglob("*"):
            if candidate.is_symlink():
                gaps.append("OCI output contains a symbolic link")
                continue
            resolved = candidate.resolve()
            try:
                resolved.relative_to(boundary)
            except ValueError:
                gaps.append("OCI output escapes its writable boundary")
                continue
            if candidate.is_file():
                files += 1
                total_bytes += candidate.stat().st_size
            elif not candidate.is_dir():
                gaps.append("OCI output contains a non-regular entry")
    except OSError:
        return ["OCI output could not be verified after execution"]
    if files > oci["maximum_output_files"]:
        gaps.append("OCI output file count exceeds the manifest limit")
    if total_bytes > oci["maximum_output_bytes"]:
        gaps.append("OCI output bytes exceed the manifest limit")
    return gaps


def _oci_user() -> str:
    getuid = getattr(os, "getuid", None)
    getgid = getattr(os, "getgid", None)
    if os.name == "posix" and getuid is not None and getgid is not None:
        uid = getuid()
        gid = getgid()
        if uid != 0:
            return f"{uid}:{gid}"
    return "65532:65532"


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()
