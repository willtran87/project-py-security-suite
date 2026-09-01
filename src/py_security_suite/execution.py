from __future__ import annotations

import hashlib
import importlib.metadata
import os
import re
import signal
import shutil
import subprocess  # nosec B404 - scanner execution is this module's purpose
import sys
import sysconfig
import tempfile
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO
from collections.abc import Iterator, Mapping

from .path_safety import read_regular_file
from .execution_policy import validate_governed_command_input
from .diagnostic_safety import (
    sanitize_diagnostic as sanitize_diagnostic,
    sanitize_terminal_text as sanitize_terminal_text,
)
from .governance_quorum import verify_governance_quorum
from .strict_json import canonical_bytes, loads as strict_loads


_RUNTIME_CLOSURE_LOCK = threading.Lock()
_ENVIRONMENT_RUNTIME_CLOSURE: str | None = None
_LIMIT_GATE_BOOTSTRAP = """
import json, os, subprocess, sys, time
gate, report = sys.argv[1:3]
enforced, errors = [], []
if os.name != "nt":
    import resource
    memory_limits = (
        ()
        if sys.platform == "darwin"
        else (("address-space", "RLIMIT_AS", 8 * 1024**3),)
    )
    requested_limits = (
        *memory_limits,
        (
            "process-count",
            "RLIMIT_NPROC",
            None if sys.platform == "darwin" else 256,
        ),
        ("open-files", "RLIMIT_NOFILE", 2048),
        ("file-size", "RLIMIT_FSIZE", int(sys.argv[5])),
        ("cpu-time", "RLIMIT_CPU", max(1, int(sys.argv[4]))),
    )
    for name, constant, requested in requested_limits:
        try:
            kind = getattr(resource, constant)
            current_soft, current_hard = resource.getrlimit(kind)
            value = requested
            if requested is None:
                value = (
                    current_soft
                    if current_soft != resource.RLIM_INFINITY
                    else 4096
                )
            if current_hard != resource.RLIM_INFINITY:
                value = min(value, current_hard)
            if current_soft != resource.RLIM_INFINITY:
                value = min(value, current_soft)
            # Drop the hard ceiling too: an untrusted scanner must not be able
            # to raise its soft quota back to the inherited parent maximum.
            resource.setrlimit(kind, (value, value))
            enforced.append(name)
        except (AttributeError, OSError, ValueError) as exc:
            errors.append(f"{name}:{exc}")
temporary_report = report + ".tmp"
with open(temporary_report, "x", encoding="utf-8") as handle:
    json.dump({"enforced": enforced, "errors": errors}, handle)
os.replace(temporary_report, report)
deadline = time.monotonic() + 10
while not os.path.exists(gate):
    if time.monotonic() >= deadline:
        raise SystemExit(125)
    time.sleep(0.005)
raise SystemExit(subprocess.run(sys.argv[6:]).returncode)
"""


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
    output_limit_exceeded: bool = False
    scratch_limit_exceeded: bool = False
    resident_memory_limit_exceeded: bool = False
    resource_limits_enforced: tuple[str, ...] = ()
    resource_limit_errors: tuple[str, ...] = ()


@dataclass(slots=True)
class CommandEnvironment:
    extra: dict[str, str] = field(default_factory=dict)
    sandbox_prefix: tuple[str, ...] = ()
    sandbox_executable_sha256: str = ""
    sandbox_runtime_closure_sha256: str = ""
    max_scratch_bytes: int = 512 * 1024**2
    max_resident_memory_bytes: int = 8 * 1024**3


class _BoundedPipeCollector:
    """Drain a child pipe while retaining at most ``maximum + 1`` bytes."""

    def __init__(self, stream: IO[bytes] | None, maximum: int) -> None:
        self._stream = stream
        self._maximum = maximum
        self._payload = bytearray()
        self.exceeded = threading.Event()
        self._thread = threading.Thread(target=self._drain, daemon=True)
        self._thread.start()

    def _drain(self) -> None:
        if self._stream is None:
            return
        try:
            while True:
                chunk = self._stream.read(64 * 1024)
                if not isinstance(chunk, bytes) or not chunk:
                    return
                remaining = self._maximum + 1 - len(self._payload)
                if remaining > 0:
                    self._payload.extend(chunk[:remaining])
                if len(self._payload) > self._maximum or len(chunk) > remaining:
                    self.exceeded.set()
        finally:
            try:
                self._stream.close()
            except OSError:
                pass

    def finish(self) -> bytes:
        self._thread.join(timeout=10)
        if self._thread.is_alive():
            raise RuntimeError(
                "scanner output pipe did not close after process teardown"
            )
        return bytes(self._payload)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def governed_asset_sha256(path: Path) -> str:
    """Digest one regular file or an exact, symlink-free asset directory tree."""
    expanded = path.expanduser()
    if expanded.is_symlink():
        raise ValueError("governed scanner asset is a symbolic link")
    resolved = expanded.resolve()
    if resolved.is_file():
        if resolved.stat().st_size > 16 * 1024**3:
            raise ValueError("governed scanner asset file exceeds 16 GiB")
        return sha256_file(resolved)
    if not resolved.is_dir():
        raise ValueError("governed scanner asset is not a regular file or directory")
    records: list[dict[str, object]] = []
    total_bytes = 0
    for root, directories, names in os.walk(resolved, followlinks=False):
        root_path = Path(root)
        directories.sort()
        for directory in directories:
            if (root_path / directory).is_symlink():
                raise ValueError("governed scanner asset contains a symbolic link")
        for name in sorted(names):
            candidate = root_path / name
            if candidate.is_symlink():
                raise ValueError("governed scanner asset contains a symbolic link")
            _, payload = read_regular_file(
                candidate,
                "governed scanner asset",
                maximum_bytes=2 * 1024**3,
                boundary=resolved,
            )
            total_bytes += len(payload)
            if len(records) >= 1_000_000 or total_bytes > 16 * 1024**3:
                raise ValueError("governed scanner asset tree exceeds its limits")
            records.append(
                {
                    "path": candidate.relative_to(resolved).as_posix(),
                    "size_bytes": len(payload),
                    "sha256": hashlib.sha256(payload).hexdigest(),
                }
            )
    records.sort(key=lambda item: str(item["path"]))
    return hashlib.sha256(canonical_bytes(records)).hexdigest()


@contextmanager
def sealed_governed_assets(
    assets: Mapping[str, Path], expected_digests: Mapping[str, str]
) -> Iterator[dict[str, Path]]:
    """Copy governed scanner assets into an immutable, per-run private root.

    The scanner receives only the returned paths. The copy is made from
    race-resistant regular-file reads, is verified against the digest observed
    during preflight, and is re-verified before and after scanner execution.
    """
    if not assets:
        yield {}
        return
    temporary_root = Path(tempfile.mkdtemp(prefix="pysec-governed-assets-"))
    copies: dict[str, Path] = {}
    try:
        for label, source in sorted(assets.items()):
            expected = expected_digests.get(label, "")
            if not expected:
                raise ValueError(f"governed {label} asset has no preflight digest")
            resolved = source.expanduser().resolve()
            destination = temporary_root / label
            if resolved.is_file():
                _, payload = read_regular_file(
                    resolved,
                    f"governed {label} asset snapshot",
                    maximum_bytes=2 * 1024**3,
                )
                destination.parent.mkdir(parents=True, exist_ok=True)
                with destination.open("xb") as handle:
                    handle.write(payload)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.chmod(destination, 0o400)
            elif resolved.is_dir():
                destination.mkdir(mode=0o700)
                files = 0
                total_bytes = 0
                for root, directories, names in os.walk(resolved, followlinks=False):
                    root_path = Path(root)
                    relative_root = root_path.relative_to(resolved)
                    for directory in sorted(directories):
                        candidate = root_path / directory
                        if candidate.is_symlink():
                            raise ValueError(
                                f"governed {label} asset contains a symbolic link"
                            )
                        (destination / relative_root / directory).mkdir(mode=0o700)
                    for name in sorted(names):
                        candidate = root_path / name
                        if candidate.is_symlink():
                            raise ValueError(
                                f"governed {label} asset contains a symbolic link"
                            )
                        _, payload = read_regular_file(
                            candidate,
                            f"governed {label} asset snapshot member",
                            maximum_bytes=2 * 1024**3,
                            boundary=resolved,
                        )
                        files += 1
                        total_bytes += len(payload)
                        if files > 1_000_000 or total_bytes > 16 * 1024**3:
                            raise ValueError(
                                f"governed {label} asset exceeds snapshot limits"
                            )
                        output = destination / relative_root / name
                        with output.open("xb") as handle:
                            handle.write(payload)
                            handle.flush()
                            os.fsync(handle.fileno())
                        os.chmod(output, 0o400)
                for snapshot_directory in sorted(
                    (item for item in destination.rglob("*") if item.is_dir()),
                    reverse=True,
                ):
                    os.chmod(snapshot_directory, 0o500)
                os.chmod(destination, 0o500)
            else:
                raise ValueError(
                    f"governed {label} asset is not a regular file or directory"
                )
            if governed_asset_sha256(destination) != expected:
                raise ValueError(f"governed {label} asset changed while it was sealed")
            copies[label] = destination
        os.chmod(temporary_root, 0o500)
        yield copies
        for label, snapshot in copies.items():
            if governed_asset_sha256(snapshot) != expected_digests[label]:
                raise ValueError(
                    f"governed {label} asset snapshot changed during scanner execution"
                )
    finally:
        if temporary_root.exists():
            for item in [temporary_root, *temporary_root.rglob("*")]:
                try:
                    os.chmod(item, 0o700 if item.is_dir() else 0o600)
                except OSError:
                    pass
            shutil.rmtree(temporary_root, ignore_errors=False)


def python_runtime_closure_sha256(
    executable: str,
    *,
    include_environment: bool = False,
    refresh: bool = False,
    require_native_plugin_manifest: bool = False,
) -> str | None:
    """Digest the installed distribution closure behind a Python console script."""
    command_name = Path(executable).name.casefold()
    for suffix in (".exe", "-script.py", ".py"):
        if command_name.endswith(suffix):
            command_name = command_name[: -len(suffix)]
            break
    entry_point = next(
        (
            value
            for value in importlib.metadata.entry_points().select(
                group="console_scripts"
            )
            if value.name.casefold() == command_name
        ),
        None,
    )
    distribution = entry_point.dist if entry_point is not None else None
    if distribution is None:
        return native_runtime_closure_sha256(
            Path(executable), require_plugin_manifest=require_native_plugin_manifest
        )

    global _ENVIRONMENT_RUNTIME_CLOSURE
    if include_environment and not refresh:
        with _RUNTIME_CLOSURE_LOCK:
            if _ENVIRONMENT_RUNTIME_CLOSURE is not None:
                return _ENVIRONMENT_RUNTIME_CLOSURE

    pending = (
        list(importlib.metadata.distributions())
        if include_environment
        else [distribution]
    )
    visited: set[str] = set()
    records: list[dict[str, object]] = []
    native_roots: set[Path] = set()
    total_bytes = 0
    while pending:
        current = pending.pop()
        name = str(current.metadata.get("Name") or "").casefold()
        if not name or name in visited:
            continue
        visited.add(name)
        if len(visited) > 2_000:
            raise ValueError(
                "Python scanner runtime closure exceeds 2000 distributions"
            )
        files = sorted(current.files or (), key=str)
        for relative in files:
            located = Path(str(current.locate_file(relative)))
            if not located.is_file():
                continue
            _, payload = read_regular_file(
                located,
                f"{name} runtime file",
                maximum_bytes=256 * 1024 * 1024,
            )
            total_bytes += len(payload)
            if total_bytes > 4 * 1024 * 1024 * 1024:
                raise ValueError("Python scanner runtime closure exceeds 4 GiB")
            records.append(
                {
                    "distribution": name,
                    "path": str(relative).replace("\\", "/"),
                    "sha256": hashlib.sha256(payload).hexdigest(),
                    "size": len(payload),
                }
            )
            if _is_native_binary(located):
                native_roots.add(located.resolve())
        for requirement in current.requires or ():
            match = re.match(r"\s*([A-Za-z0-9][A-Za-z0-9._-]*)", requirement)
            if match is None:
                continue
            try:
                dependency = importlib.metadata.distribution(match.group(1))
            except importlib.metadata.PackageNotFoundError:
                continue
            pending.append(dependency)
    interpreter = Path(sys.executable).resolve()
    _, interpreter_payload = read_regular_file(
        interpreter, "Python scanner interpreter", maximum_bytes=512 * 1024 * 1024
    )
    records.append(
        {
            "distribution": "<python-interpreter>",
            "path": interpreter.name,
            "sha256": hashlib.sha256(interpreter_payload).hexdigest(),
            "size": len(interpreter_payload),
        }
    )
    native_roots.add(interpreter)
    if include_environment:
        stdlib = Path(sysconfig.get_path("stdlib")).resolve()
        stdlib_files = sorted(
            path
            for path in stdlib.rglob("*")
            if path.is_file()
            and "site-packages" not in path.parts
            and "__pycache__" not in path.parts
        )
        if len(stdlib_files) > 100_000:
            raise ValueError("Python standard-library closure exceeds 100000 files")
        for located in stdlib_files:
            _, payload = read_regular_file(
                located,
                "Python standard-library file",
                maximum_bytes=256 * 1024 * 1024,
            )
            total_bytes += len(payload)
            if total_bytes > 4 * 1024 * 1024 * 1024:
                raise ValueError("Python scanner runtime closure exceeds 4 GiB")
            records.append(
                {
                    "distribution": "<python-stdlib>",
                    "path": located.relative_to(stdlib).as_posix(),
                    "sha256": hashlib.sha256(payload).hexdigest(),
                    "size": len(payload),
                }
            )
        native_roots.update(_native_runtime_components())
    for located in _native_dependency_closure(native_roots):
        _, payload = read_regular_file(
            located,
            "Python native runtime component",
            maximum_bytes=512 * 1024 * 1024,
        )
        total_bytes += len(payload)
        if total_bytes > 4 * 1024 * 1024 * 1024:
            raise ValueError("Python scanner runtime closure exceeds 4 GiB")
        records.append(
            {
                "distribution": "<native-runtime>",
                "path": str(located),
                "sha256": hashlib.sha256(payload).hexdigest(),
                "size": len(payload),
            }
        )
    darwin_runtime = _darwin_system_runtime_record()
    if darwin_runtime is not None:
        records.append(darwin_runtime)
    result = hashlib.sha256(canonical_bytes(records)).hexdigest()
    if include_environment:
        with _RUNTIME_CLOSURE_LOCK:
            _ENVIRONMENT_RUNTIME_CLOSURE = result
    return result


def native_runtime_closure_sha256(
    executable: Path, *, require_plugin_manifest: bool = False
) -> str:
    """Digest an executable, adjacent plugins, and its transitive native imports."""
    resolved = executable.expanduser().resolve()
    if not resolved.is_file():
        raise ValueError("native scanner executable is not a regular file")
    roots = {resolved}
    roots.update(_declared_native_plugins(resolved, required=require_plugin_manifest))
    records: list[dict[str, object]] = []
    total_bytes = 0
    for path in _native_dependency_closure(roots):
        _, payload = read_regular_file(
            path, "native scanner runtime component", maximum_bytes=1024 * 1024**2
        )
        total_bytes += len(payload)
        if total_bytes > 8 * 1024**3:
            raise ValueError("native scanner runtime closure exceeds 8 GiB")
        records.append(
            {
                "path": str(path),
                "sha256": hashlib.sha256(payload).hexdigest(),
                "size": len(payload),
            }
        )
    darwin_runtime = _darwin_system_runtime_record()
    if darwin_runtime is not None:
        records.append(darwin_runtime)
    return hashlib.sha256(canonical_bytes(records)).hexdigest()


def _declared_native_plugins(executable: Path, *, required: bool = False) -> set[Path]:
    """Load declared plugins and qualification-time observed native components."""
    manifest = executable.with_name(f"{executable.name}.runtime-closure.json")
    if not manifest.exists():
        if required:
            raise ValueError(
                "production native scanner requires an explicit runtime-plugin manifest"
            )
        return set()
    _, raw = read_regular_file(
        manifest, "native runtime plugin manifest", maximum_bytes=1024 * 1024
    )
    value = strict_loads(raw)
    if not isinstance(value, dict) or set(value) not in (
        {"schema_version", "plugins"},
        {"schema_version", "plugins", "observation"},
        {
            "schema_version",
            "plugins",
            "observation",
            "minimum_authority_signatures",
            "authorities",
        },
    ):
        raise ValueError("native runtime plugin manifest fields do not match")
    plugins = value.get("plugins")
    version = value.get("schema_version")
    if version not in {"1.0", "1.1", "1.2"} or not isinstance(plugins, list):
        raise ValueError("native runtime plugin manifest is invalid")
    if (version in {"1.1", "1.2"}) != ("observation" in value):
        raise ValueError("native runtime observation contract is inconsistent")
    if (version == "1.2") != ("authorities" in value):
        raise ValueError("native runtime authority contract is inconsistent")
    if required and version != "1.2":
        raise ValueError(
            "production native scanner requires an independently authenticated loader-observed runtime manifest"
        )
    if len(plugins) > 2_048:
        raise ValueError("native runtime plugin manifest exceeds 2048 files")
    result = {manifest.resolve()}
    root = executable.parent.resolve()
    observed: set[str] = set()
    declared: dict[str, str] = {}
    for item in plugins:
        if not isinstance(item, dict) or set(item) != {"path", "sha256"}:
            raise ValueError("native runtime plugin entry fields do not match")
        relative = Path(str(item.get("path") or ""))
        digest = str(item.get("sha256") or "")
        if (
            not relative.parts
            or ".." in relative.parts
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
        ):
            raise ValueError("native runtime plugin identity is invalid")
        plugin = (
            relative.resolve()
            if relative.is_absolute()
            else (root / relative).resolve()
        )
        if str(plugin) in observed:
            raise ValueError("native runtime plugin identity is duplicated")
        _, payload = read_regular_file(
            plugin, "declared native runtime plugin", maximum_bytes=1024 * 1024**2
        )
        if hashlib.sha256(payload).hexdigest() != digest:
            raise ValueError("declared native runtime plugin SHA-256 does not match")
        observed.add(str(plugin))
        declared[str(plugin)] = digest
        result.add(plugin)
    if version in {"1.1", "1.2"}:
        result.update(
            _observed_native_components(
                executable,
                value.get("observation"),
                declared,
            )
        )
    if version == "1.2":
        threshold = value.get("minimum_authority_signatures")
        if (
            isinstance(threshold, bool)
            or not isinstance(threshold, int)
            or not 2 <= threshold <= 16
        ):
            raise ValueError("native runtime authority threshold is invalid")
        from .trusted_observation import scan_observed_at

        verify_governance_quorum(
            manifest,
            value.get("authorities"),
            {
                "schema_version": "1.2",
                "executable_sha256": hashlib.sha256(
                    executable.read_bytes()
                ).hexdigest(),
                "plugins": value["plugins"],
                "observation": value["observation"],
            },
            threshold,
            scan_observed_at(),
            purpose="native-loader-observation",
        )
    return result


def _observed_native_components(
    executable: Path, observation: object, declared: dict[str, str]
) -> set[Path]:
    if not isinstance(observation, dict) or set(observation) != {
        "collector",
        "collector_sha256",
        "platform",
        "observed_components",
    }:
        raise ValueError("native runtime observation fields do not match")
    collector_value = observation.get("collector")
    collector_digest = str(observation.get("collector_sha256") or "")
    platform_name = str(observation.get("platform") or "")
    components = observation.get("observed_components")
    if (
        not isinstance(collector_value, str)
        or not collector_value
        or len(collector_digest) != 64
        or any(character not in "0123456789abcdef" for character in collector_digest)
        or platform_name != sys.platform
        or not isinstance(components, list)
        or len(components) > 4_096
    ):
        raise ValueError("native runtime observation is invalid")
    root = executable.parent.resolve()
    collector_path = Path(collector_value)
    collector = (
        collector_path.resolve()
        if collector_path.is_absolute()
        else (root / collector_path).resolve()
    )
    _, collector_payload = read_regular_file(
        collector,
        "native loader observation collector",
        maximum_bytes=1024 * 1024**2,
    )
    if hashlib.sha256(collector_payload).hexdigest() != collector_digest:
        raise ValueError("native loader observation collector SHA-256 does not match")
    result = {collector}
    observed_plugins: dict[str, str] = {}
    observed_paths: set[str] = set()
    for item in components:
        if not isinstance(item, dict) or set(item) != {"path", "sha256", "scope"}:
            raise ValueError("observed native component fields do not match")
        relative = Path(str(item.get("path") or ""))
        digest = str(item.get("sha256") or "")
        scope = item.get("scope")
        if (
            not relative.parts
            or ".." in relative.parts
            or scope not in {"plugin", "os-tcb"}
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
        ):
            raise ValueError("observed native component identity is invalid")
        component = (
            relative.resolve()
            if relative.is_absolute()
            else (root / relative).resolve()
        )
        if str(component) in observed_paths:
            raise ValueError("observed native component identity is duplicated")
        _, payload = read_regular_file(
            component,
            "loader-observed native runtime component",
            maximum_bytes=1024 * 1024**2,
        )
        if hashlib.sha256(payload).hexdigest() != digest:
            raise ValueError("loader-observed native component SHA-256 does not match")
        observed_paths.add(str(component))
        result.add(component)
        if scope == "plugin":
            observed_plugins[str(component)] = digest
    if observed_plugins != declared:
        raise ValueError(
            "loader-observed plugin set does not match the declared runtime plugins"
        )
    return result


def _is_native_binary(path: Path) -> bool:
    if path.suffix.casefold() in {".dll", ".dylib", ".exe", ".pyd", ".so"}:
        return True
    try:
        with path.open("rb") as handle:
            magic = handle.read(4)
    except OSError:
        return False
    return magic.startswith(b"\x7fELF") or magic in {
        b"\xca\xfe\xba\xbe",
        b"\xce\xfa\xed\xfe",
        b"\xcf\xfa\xed\xfe",
        b"\xfe\xed\xfa\xce",
        b"\xfe\xed\xfa\xcf",
    }


def _native_dependency_closure(roots: set[Path]) -> list[Path]:
    pending = sorted(roots)
    observed: set[Path] = set()
    application_root = pending[0].parent if pending else Path.cwd()
    while pending:
        path = pending.pop()
        resolved = path.resolve()
        if resolved in observed:
            continue
        if len(observed) >= 4_096:
            raise ValueError("native runtime closure exceeds 4096 files")
        observed.add(resolved)
        for dependency in _native_dependencies(resolved, application_root):
            if dependency not in observed:
                pending.append(dependency)
    return sorted(observed)


def _native_dependencies(path: Path, application_root: Path) -> set[Path]:
    try:
        with path.open("rb") as handle:
            magic = handle.read(4)
    except OSError as exc:
        raise ValueError(f"native runtime component became unreadable: {path}") from exc
    if magic[:2] == b"MZ":
        return _pe_dependencies(path, application_root)
    if magic == b"\x7fELF":
        return _elf_dependencies(path, application_root)
    if magic in {
        b"\xca\xfe\xba\xbe",
        b"\xce\xfa\xed\xfe",
        b"\xcf\xfa\xed\xfe",
        b"\xfe\xed\xfa\xce",
        b"\xfe\xed\xfa\xcf",
    }:
        return _macho_dependencies(path, application_root)
    return set()


def _pe_dependencies(path: Path, application_root: Path) -> set[Path]:  # pragma: no cover  # fmt: skip
    import pefile  # type: ignore[import-untyped]

    try:
        pe = pefile.PE(str(path), fast_load=True)
        pe.parse_data_directories(
            directories=[
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT"],
            ]
        )
    except pefile.PEFormatError:
        return set()
    names: set[str] = set()
    optional_names: set[str] = set()
    try:
        for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", ()):
            raw = getattr(entry, "dll", b"")
            if isinstance(raw, bytes):
                names.add(raw.decode("utf-8", errors="strict"))
        for entry in getattr(pe, "DIRECTORY_ENTRY_DELAY_IMPORT", ()):
            raw = getattr(entry, "dll", b"")
            if isinstance(raw, bytes):
                optional_names.add(raw.decode("utf-8", errors="strict"))
    finally:
        pe.close()
    windows = Path(
        os.environ.get("SYSTEMROOT") or os.environ.get("WINDIR") or "C:/Windows"
    ).resolve()
    roots = (path.parent, application_root, windows / "System32", windows)
    api_sets = ("api-ms-", "ext-ms-")
    return _resolve_native_names(names, roots, api_set_prefixes=api_sets) | (
        _resolve_native_names(
            optional_names, roots, api_set_prefixes=api_sets, allow_missing=True
        )
    )


def _elf_dependencies(path: Path, application_root: Path) -> set[Path]:
    from elftools.elf.elffile import ELFFile  # type: ignore[import-untyped]

    names: set[str] = set()
    run_paths: list[Path] = []
    with path.open("rb") as handle:
        elf = ELFFile(handle)
        for segment in elf.iter_segments():
            if segment.header.p_type != "PT_DYNAMIC":
                continue
            for tag in segment.iter_tags():  # type: ignore[attr-defined]
                if tag.entry.d_tag == "DT_NEEDED":
                    names.add(str(tag.needed))
                elif tag.entry.d_tag in {"DT_RPATH", "DT_RUNPATH"}:
                    raw = str(getattr(tag, "rpath", getattr(tag, "runpath", "")))
                    run_paths.extend(
                        Path(value.replace("$ORIGIN", str(path.parent)))
                        for value in raw.split(":")
                        if value
                    )
    system_roots = [
        Path("/lib"),
        Path("/lib64"),
        Path("/usr/lib"),
        Path("/usr/lib64"),
        Path("/usr/local/lib"),
    ]
    for parent in (Path("/lib"), Path("/usr/lib")):
        if parent.is_dir():
            system_roots.extend(parent.glob("*-linux-gnu"))
    return _resolve_native_names(
        names, (path.parent, application_root, *run_paths, *system_roots)
    )


def _macho_dependencies(path: Path, application_root: Path) -> set[Path]:  # pragma: no cover  # fmt: skip
    from macholib.MachO import MachO  # type: ignore[import-untyped]

    names = {
        filename
        for header in MachO(str(path)).headers
        for _index, _command, filename in header.walkRelocatables()
    }
    resolved: set[Path] = set()
    unresolved: set[str] = set()
    for name in names:
        candidate = name.replace("@loader_path", str(path.parent)).replace(
            "@executable_path", str(application_root)
        )
        candidates = [Path(candidate)]
        if candidate.startswith("@rpath/"):
            suffix = candidate.removeprefix("@rpath/")
            candidates = [
                path.parent / suffix,
                application_root / suffix,
                application_root / "lib" / suffix,
                application_root / "Frameworks" / suffix,
            ]
        located = next((item for item in candidates if item.is_file()), None)
        if located is not None:
            resolved.add(located.resolve())
        elif not _darwin_shared_cache_dependency(name):
            unresolved.add(name)
    if unresolved:
        raise ValueError(
            "unresolved Mach-O dependencies: " + ", ".join(sorted(unresolved))
        )
    return resolved


def _darwin_shared_cache_dependency(name: str) -> bool:
    """Identify Apple system libraries supplied by the sealed dyld cache."""
    return sys.platform == "darwin" and name.startswith(
        ("/System/Library/", "/usr/lib/")
    )


def _darwin_system_runtime_record() -> dict[str, object] | None:  # pragma: no cover
    """Bind cache-resident Mach-O dependencies to the sealed OS build identity."""
    if sys.platform != "darwin":
        return None
    version_files = (
        Path("/System/Library/CoreServices/SystemVersion.plist"),
        Path("/System/Library/CoreServices/SystemVersionCompat.plist"),
    )
    identities: list[dict[str, object]] = []
    total_bytes = 0
    for path in version_files:
        if not path.is_file():
            continue
        _, payload = read_regular_file(
            path,
            "Darwin sealed system version identity",
            maximum_bytes=1024 * 1024,
        )
        total_bytes += len(payload)
        identities.append(
            {
                "path": str(path),
                "sha256": hashlib.sha256(payload).hexdigest(),
                "size": len(payload),
            }
        )
    if not identities:
        raise ValueError("Darwin sealed system version identity is unavailable")
    kernel = os.uname()
    identity = {
        "kernel": {
            "machine": kernel.machine,
            "release": kernel.release,
            "sysname": kernel.sysname,
            "version": kernel.version,
        },
        "sealed_system_versions": identities,
    }
    return {
        "path": "<darwin-sealed-system-runtime>",
        "sha256": hashlib.sha256(canonical_bytes(identity)).hexdigest(),
        "size": total_bytes,
    }


def _resolve_native_names(
    names: set[str],
    roots: tuple[Path, ...] | list[Path],
    *,
    api_set_prefixes: tuple[str, ...] = (),
    allow_missing: bool = False,
) -> set[Path]:
    result: set[Path] = set()
    unresolved: list[str] = []
    for name in sorted(names):
        if name.casefold().startswith(api_set_prefixes):
            continue
        direct = Path(name)
        candidates = (
            [direct] if direct.is_absolute() else [root / name for root in roots]
        )
        located = next(
            (candidate.resolve() for candidate in candidates if candidate.is_file()),
            None,
        )
        if located is None:
            unresolved.append(name)
        else:
            result.add(located)
    if unresolved and not allow_missing:
        raise ValueError(
            "unresolved native dependencies: " + ", ".join(unresolved[:50])
        )
    return result


def _native_runtime_components() -> list[Path]:
    """Return native libraries that form the interpreter's platform closure."""
    candidates: set[Path] = set()
    prefixes = {Path(sys.prefix).resolve(), Path(sys.base_prefix).resolve()}
    executable_parent = Path(sys.executable).resolve().parent
    for root in prefixes | {executable_parent}:
        for pattern in ("*.dll", "*.pyd", "libpython*.so*", "libpython*.dylib"):
            candidates.update(path.resolve() for path in root.glob(pattern))
        native_directory = root / "DLLs"
        if native_directory.is_dir():
            candidates.update(
                path.resolve()
                for pattern in ("*.dll", "*.pyd")
                for path in native_directory.glob(pattern)
            )
    library_directory = sysconfig.get_config_var("LIBDIR")
    library_name = sysconfig.get_config_var("LDLIBRARY")
    if library_directory and library_name:
        candidates.add((Path(str(library_directory)) / str(library_name)).resolve())
    if os.name == "nt":
        windows = Path(
            os.environ.get("SYSTEMROOT") or os.environ.get("WINDIR") or "C:/Windows"
        )
        system = windows / "System32"
        candidates.update(
            path.resolve()
            for name in ("ucrtbase.dll", "vcruntime140.dll", "vcruntime140_1.dll")
            if (path := system / name).is_file()
        )
    return sorted(path for path in candidates if path.is_file())


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


def isolated_environment(
    extra: dict[str, str] | None = None,
    *,
    executable: str | None = None,
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
        }
        rejected = sorted(key for key in extra if key.upper() in forbidden)
        if rejected:
            raise ValueError(
                "scanner environment cannot override executable or loader paths: "
                + ", ".join(rejected)
            )
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
    validate_governed_command_input(
        command,
        timeout_seconds=timeout_seconds,
        max_output_bytes=max_output_bytes,
        environment=environment.extra if environment is not None else None,
    )
    if environment is not None and environment.max_resident_memory_bytes < 64 * 1024**2:
        raise ValueError("scanner resident-memory limit must be at least 64 MiB")
    sandbox_path: Path | None = None
    sandbox_digest = ""
    sandbox_runtime_digest = ""
    if environment and environment.sandbox_prefix:
        resolved_sandbox = resolve_executable(environment.sandbox_prefix[0])
        if resolved_sandbox is None:
            raise ValueError("configured sandbox launcher was not found")
        sandbox_path = Path(resolved_sandbox).resolve()
        sandbox_digest = sha256_file(sandbox_path)
        if sandbox_digest != environment.sandbox_executable_sha256:
            raise ValueError("sandbox launcher does not match the approved SHA-256")
        if environment.sandbox_runtime_closure_sha256:
            sandbox_runtime_digest = native_runtime_closure_sha256(sandbox_path)
            if sandbox_runtime_digest != environment.sandbox_runtime_closure_sha256:
                raise ValueError(
                    "sandbox launcher runtime closure does not match the approved SHA-256"
                )
        command = [
            str(sandbox_path),
            *environment.sandbox_prefix[1:],
            *command,
        ]
    reported_command = list(command)
    started = time.monotonic()
    creation_flags = 0
    if os.name == "nt":
        creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) | getattr(
            subprocess, "CREATE_NEW_PROCESS_GROUP", 0
        )
    with tempfile.TemporaryDirectory(
        prefix="pysec-process-home-", ignore_cleanup_errors=True
    ) as private_home:
        # macOS exposes its temporary root through ``/var`` -> ``/private/var``.
        # Resolve that operating-system alias before establishing the private
        # boundary so the link-rejecting report reader sees only real path
        # components without weakening its symlink checks.
        private_root = Path(private_home).resolve()
        process_environment = isolated_environment(
            environment.extra if environment else None,
            executable=command[0] if command else None,
        )
        private_locations = {
            "HOME": private_root,
            "USERPROFILE": private_root,
            "APPDATA": private_root / "AppData" / "Roaming",
            "LOCALAPPDATA": private_root / "AppData" / "Local",
            "XDG_CACHE_HOME": private_root / "cache",
            "TEMP": private_root / "tmp",
            "TMP": private_root / "tmp",
            "TMPDIR": private_root / "tmp",
        }
        for name, path in private_locations.items():
            path.mkdir(parents=True, exist_ok=True)
            process_environment[name] = str(path)
        private_command = [
            item.replace("{PYSEC_PRIVATE_ROOT}", str(private_root)) for item in command
        ]
        gate: Path | None = None
        limit_report = private_root / "limits-applied.json"
        process_command = command
        gate = private_root / "limits-applied.gate"
        process_command = [
            sys.executable,
            "-I",
            "-c",
            _LIMIT_GATE_BOOTSTRAP,
            str(gate),
            str(limit_report),
            str(max_output_bytes),
            str(timeout_seconds),
            str(environment.max_scratch_bytes if environment else 512 * 1024**2),
            *private_command,
        ]
        # Executables are resolved by adapters, arguments are passed as a
        # vector, shell execution is disabled, and the environment is reduced.
        # The lifecycle is explicitly managed below so timeout and interruption
        # can terminate the complete process tree before pipes are closed.
        process = subprocess.Popen(  # noqa: S603  # nosec B603  # pylint: disable=consider-using-with
            process_command,
            cwd=cwd,
            env=process_environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            creationflags=creation_flags,
            start_new_session=os.name != "nt",
        )
        stdout_collector = _BoundedPipeCollector(process.stdout, max_output_bytes)
        stderr_collector = _BoundedPipeCollector(process.stderr, max_output_bytes)
        limits, limit_errors, limit_handle = _apply_process_resource_limits(
            process,
            max_output_bytes=max_output_bytes,
            timeout_seconds=timeout_seconds,
            max_scratch_bytes=(
                environment.max_scratch_bytes if environment else 512 * 1024**2
            ),
            limit_report=limit_report,
        )
        containment_failed = bool(limit_errors)
        if sys.platform == "darwin" and not containment_failed:
            limits = (*limits, "resident-memory-watchdog")
        if not containment_failed and "pre-execution-assignment" not in limits:
            limits = (*limits, "pre-execution-assignment")
        limits = (*limits, "bounded-output-pipes", "bounded-private-scratch")

        def terminate_tree() -> bool:
            nonlocal limit_handle
            if limit_handle is not None:
                _close_windows_handle(limit_handle)
                limit_handle = None
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=10)
                return process.poll() is not None
            return _terminate_process_tree(process)

        if not containment_failed:
            try:
                gate.touch(mode=0o600)
            except BaseException:
                terminate_tree()
                raise
        timed_out = False
        output_limit_exceeded = False
        scratch_limit_exceeded = False
        resident_memory_limit_exceeded = False
        terminated = terminate_tree() if containment_failed else False
        deadline = started + timeout_seconds
        scratch_limit = environment.max_scratch_bytes if environment else 512 * 1024**2
        resident_memory_limit = (
            environment.max_resident_memory_bytes if environment else 8 * 1024**3
        )
        next_memory_check = time.monotonic() if sys.platform == "darwin" else 0.0
        if scratch_limit < 1024 * 1024:
            terminate_tree()
            raise ValueError("scanner scratch limit must be at least 1 MiB")
        try:
            while process.poll() is None:
                if time.monotonic() >= deadline:
                    timed_out = True
                    terminated = terminate_tree()
                    break
                if (
                    stdout_collector.exceeded.is_set()
                    or stderr_collector.exceeded.is_set()
                ):
                    output_limit_exceeded = True
                    terminated = terminate_tree()
                    break
                if _directory_size_exceeds(private_root, scratch_limit):
                    scratch_limit_exceeded = True
                    terminated = terminate_tree()
                    break
                if sys.platform == "darwin" and time.monotonic() >= next_memory_check:
                    try:
                        resident_memory_limit_exceeded = (
                            _process_tree_resident_bytes(process.pid)
                            > resident_memory_limit
                        )
                    except RuntimeError as exc:
                        limit_errors = (*limit_errors, str(exc))
                        terminated = terminate_tree()
                        break
                    if resident_memory_limit_exceeded:
                        terminated = terminate_tree()
                        break
                    next_memory_check = time.monotonic() + 0.05
                time.sleep(0.01)
            if process.poll() is None:
                process.wait(timeout=10)
            if not scratch_limit_exceeded and _directory_size_exceeds(
                private_root, scratch_limit
            ):
                # A POSIX RLIMIT_FSIZE can stop a writer exactly at the byte
                # ceiling before the polling loop observes a larger file.  A
                # final inclusive accounting pass makes that enforcement
                # visible in the retained execution result on every platform.
                scratch_limit_exceeded = True
                terminated = terminate_tree() or process.poll() is not None
        except BaseException:
            terminate_tree()
            raise

        # Close the containment boundary before waiting for pipe EOF. A scanner
        # that exits after spawning a pipe-holding descendant cannot stall us.
        if limit_handle is not None:
            _close_windows_handle(limit_handle)
            limit_handle = None
        elif os.name != "nt":
            _kill_process_group_after_leader_exit(process)
        stdout_bytes = stdout_collector.finish()
        stderr_bytes = stderr_collector.finish()
        stdout, stdout_truncated = _decode_and_cap(stdout_bytes, max_output_bytes)
        stderr, stderr_truncated = _decode_and_cap(stderr_bytes, max_output_bytes)
        output_limit_exceeded = (
            output_limit_exceeded or stdout_truncated or stderr_truncated
        )
        if output_limit_exceeded and not terminated:
            terminated = True
        if sandbox_path is not None and sha256_file(sandbox_path) != sandbox_digest:
            raise ValueError("sandbox launcher changed during execution")
        if sandbox_path is not None and sandbox_runtime_digest:
            if native_runtime_closure_sha256(sandbox_path) != sandbox_runtime_digest:
                raise ValueError(
                    "sandbox launcher runtime closure changed during execution"
                )
        return RawExecution(
            command=reported_command,
            exit_code=None if timed_out else process.returncode,
            stdout=stdout,
            stderr=stderr,
            duration_seconds=time.monotonic() - started,
            timed_out=timed_out,
            stdout_truncated=stdout_truncated,
            stderr_truncated=stderr_truncated,
            process_tree_terminated=terminated,
            output_limit_exceeded=output_limit_exceeded,
            scratch_limit_exceeded=scratch_limit_exceeded,
            resident_memory_limit_exceeded=resident_memory_limit_exceeded,
            resource_limits_enforced=limits,
            resource_limit_errors=limit_errors,
        )


def _process_tree_resident_bytes(pid: int) -> int:
    """Return current aggregate RSS for one live process tree."""
    import psutil

    try:
        root = psutil.Process(pid)
        processes = [root, *root.children(recursive=True)]
        total = 0
        for candidate in processes:
            try:
                total += candidate.memory_info().rss
            except psutil.NoSuchProcess:
                continue
        return total
    except psutil.NoSuchProcess:
        return 0
    except (psutil.AccessDenied, OSError) as exc:
        raise RuntimeError("resident-memory-watchdog:unavailable") from exc


def _apply_process_resource_limits(
    process: subprocess.Popen[bytes],
    *,
    max_output_bytes: int,
    timeout_seconds: int,
    max_scratch_bytes: int,
    limit_report: Path,
) -> tuple[tuple[str, ...], tuple[str, ...], int | None]:
    """Apply OS-enforced scanner quotas immediately after process creation."""
    pid = getattr(process, "pid", None)
    if not isinstance(pid, int) or pid <= 0:
        return (), (), None
    if os.name == "nt":
        try:
            return _apply_windows_job_limits(process, timeout_seconds=timeout_seconds)
        except (OSError, ValueError) as exc:
            return (), (f"windows-job:{exc}",), None
    deadline = time.monotonic() + 10
    while not limit_report.is_file() and process.poll() is None:
        if time.monotonic() >= deadline:
            break
        time.sleep(0.005)
    try:
        _, payload = read_regular_file(
            limit_report,
            "POSIX child resource-limit report",
            maximum_bytes=4096,
            boundary=limit_report.parent,
        )
        report = strict_loads(payload)
    except (OSError, TypeError, ValueError):
        return (), ("posix-child-limits:unavailable",), None
    if (
        not isinstance(report, dict)
        or set(report) != {"enforced", "errors"}
        or not isinstance(report["enforced"], list)
        or not isinstance(report["errors"], list)
        or any(not isinstance(item, str) or not item for item in report["enforced"])
        or any(not isinstance(item, str) or not item for item in report["errors"])
    ):
        return (), ("posix-child-limits:invalid-report",), None
    return tuple(report["enforced"]), tuple(report["errors"]), None


def _apply_windows_job_limits(  # pragma: no cover - exercised on Windows CI
    process: subprocess.Popen[bytes],
    *,
    timeout_seconds: int,
) -> tuple[tuple[str, ...], tuple[str, ...], int]:
    """Contain a Windows scanner in a kill-on-close, quota-limited Job Object."""
    import ctypes
    from ctypes import wintypes

    class IO_COUNTERS(ctypes.Structure):
        _fields_ = [
            (name, ctypes.c_ulonglong)
            for name in (
                "ReadOperationCount",
                "WriteOperationCount",
                "OtherOperationCount",
                "ReadTransferCount",
                "WriteTransferCount",
                "OtherTransferCount",
            )
        ]

    class BASIC_LIMITS(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_longlong),
            ("PerJobUserTimeLimit", ctypes.c_longlong),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        ]

    class EXTENDED_LIMITS(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", BASIC_LIMITS),
            ("IoInfo", IO_COUNTERS),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    class CPU_RATE_CONTROL(ctypes.Structure):
        _fields_ = [("ControlFlags", wintypes.DWORD), ("CpuRate", wintypes.DWORD)]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined]
    kernel32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
    kernel32.CreateJobObjectW.restype = wintypes.HANDLE
    kernel32.SetInformationJobObject.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
    ]
    kernel32.SetInformationJobObject.restype = wintypes.BOOL
    kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    job = kernel32.CreateJobObjectW(None, None)
    if not job:
        error_code = ctypes.get_last_error()  # type: ignore[attr-defined]
        raise OSError(error_code, "CreateJobObjectW failed")
    limits = EXTENDED_LIMITS()
    limits.BasicLimitInformation.LimitFlags = 0x2000 | 0x200 | 0x100 | 0x8 | 0x4
    limits.BasicLimitInformation.PerJobUserTimeLimit = (
        max(1, timeout_seconds) * 10_000_000
    )
    limits.BasicLimitInformation.ActiveProcessLimit = 256
    limits.ProcessMemoryLimit = 8 * 1024**3
    limits.JobMemoryLimit = 16 * 1024**3
    if not kernel32.SetInformationJobObject(
        job, 9, ctypes.byref(limits), ctypes.sizeof(limits)
    ):
        error = ctypes.get_last_error()  # type: ignore[attr-defined]
        kernel32.CloseHandle(job)
        raise OSError(error, "SetInformationJobObject failed")
    cpu = CPU_RATE_CONTROL(ControlFlags=0x1 | 0x4, CpuRate=8000)
    if not kernel32.SetInformationJobObject(
        job, 15, ctypes.byref(cpu), ctypes.sizeof(cpu)
    ):
        error = ctypes.get_last_error()  # type: ignore[attr-defined]
        kernel32.CloseHandle(job)
        raise OSError(error, "CPU rate control could not be applied")
    process_handle = getattr(process, "_handle", None)
    if not process_handle or not kernel32.AssignProcessToJobObject(job, process_handle):
        error = ctypes.get_last_error()  # type: ignore[attr-defined]
        kernel32.CloseHandle(job)
        raise OSError(error, "AssignProcessToJobObject failed")
    return (
        (
            "kill-on-close",
            "process-count",
            "process-memory",
            "job-memory",
            "cpu-time",
            "cpu-rate",
            "pre-execution-assignment",
        ),
        (),
        int(ctypes.cast(job, ctypes.c_void_p).value or 0),
    )


def _close_windows_handle(handle: int) -> None:  # pragma: no cover
    import ctypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined]
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel32.CloseHandle.restype = ctypes.c_int
    kernel32.CloseHandle(handle)


def _directory_size_exceeds(root: Path, maximum: int) -> bool:
    total = 0
    entries = 0
    pending = [root]
    while pending:
        directory = pending.pop()
        try:
            children = list(os.scandir(directory))
        except OSError:
            continue
        for child in children:
            entries += 1
            if entries > 100_000:
                return True
            try:
                if child.is_symlink():
                    continue
                if child.is_dir(follow_symlinks=False):
                    pending.append(Path(child.path))
                elif child.is_file(follow_symlinks=False):
                    total += child.stat(follow_symlinks=False).st_size
                    if total >= maximum:
                        return True
            except OSError:
                continue
    return False


def _kill_process_group_after_leader_exit(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is None:
        return
    kill_process_group = os.__dict__.get("killpg")
    get_process_group = os.__dict__.get("getpgrp")
    hard_kill = signal.__dict__.get("SIGKILL")
    process_group = process.pid
    if (
        not callable(kill_process_group)
        or hard_kill is None
        or type(process_group) is not int
        or process_group <= 1
        or process_group == os.getpid()
        or (callable(get_process_group) and process_group == get_process_group())
    ):
        return
    try:
        kill_process_group(process_group, hard_kill)
    except (OSError, ProcessLookupError):
        pass


def _running_on_windows() -> bool:
    return os.name == "nt"


def _terminate_process_tree(process: subprocess.Popen[bytes]) -> bool:
    """Terminate the exact scanner process group and wait for cleanup."""
    if process.poll() is not None:
        return True
    try:
        if _running_on_windows():
            windows = Path(
                os.environ.get("SYSTEMROOT") or os.environ.get("WINDIR") or "C:/Windows"
            ).resolve()
            taskkill_path = windows / "System32" / "taskkill.exe"
            if not taskkill_path.is_file():
                process.kill()
                process.wait(timeout=10)
                return process.poll() is not None
            completed = subprocess.run(  # noqa: S603  # nosec B603
                [str(taskkill_path), "/PID", str(process.pid), "/T", "/F"],
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
