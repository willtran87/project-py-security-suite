from __future__ import annotations

import hashlib
import os
import shutil
import tempfile
import tomllib
from contextlib import contextmanager
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from .execution import CommandEnvironment, resolve_executable, run_command
from .models import Inventory
from .path_safety import read_regular_file


_SKIP_DIRECTORIES = frozenset(
    {
        ".artifacts",
        ".git",
        ".hg",
        ".mypy_cache",
        ".nox",
        ".pysec-tools",
        ".pytest_cache",
        ".ruff_cache",
        ".svn",
        ".tox",
        ".venv",
        "env",
        "venv",
        "__pycache__",
        "build",
        "dist",
        "node_modules",
    }
)
_INTEGRITY_SKIP_DIRECTORIES = _SKIP_DIRECTORIES - {"build", "dist"}
_DEPENDENCY_FILES = {
    "requirements.txt",
    "requirements-dev.txt",
    "poetry.lock",
    "pdm.lock",
    "pipfile.lock",
    "uv.lock",
    "pylock.toml",
    "pyproject.toml",
}
_LOCK_FILES = {
    "pipfile.lock",
    "poetry.lock",
    "pdm.lock",
    "uv.lock",
    "pylock.toml",
    "requirements.lock",
}


def inventory_target(
    target: Path, *, excluded_paths: tuple[Path, ...] = ()
) -> Inventory:
    inventory, _ = inventory_target_with_evidence(target, excluded_paths=excluded_paths)
    return inventory


def inventory_target_with_evidence(
    target: Path, *, excluded_paths: tuple[Path, ...] = ()
) -> tuple[Inventory, dict[str, Any]]:
    """Inventory a target and retain the exact file identities behind its digest."""
    python_files = 0
    dependency_files: list[str] = []
    lock_files: list[str] = []
    distribution_files = _distribution_files(target)
    maintained_files, skipped_symlinks = _maintained_files(target, excluded_paths)
    integrity_files, _ = _maintained_files(
        target,
        excluded_paths,
        skip_directories=_INTEGRITY_SKIP_DIRECTORIES,
    )
    source_evidence = _source_inventory(target, integrity_files)
    source_sha256 = str(source_evidence["source_sha256"])
    hashed_bytes = int(source_evidence["total_bytes"])
    for path in maintained_files:
        relative = path.relative_to(target).as_posix()
        if path.suffix == ".py":
            python_files += 1
        if path.name.casefold() in _DEPENDENCY_FILES:
            dependency_files.append(relative)
        if path.name.casefold() in _LOCK_FILES or path.name.casefold().startswith(
            "pylock."
        ):
            lock_files.append(relative)
    vcs_revision, vcs_revision_verified = _vcs_revision(target)
    inventory = Inventory(
        python_files=python_files,
        dependency_files=sorted(dependency_files),
        total_files=len(maintained_files),
        skipped_symlinks=skipped_symlinks,
        declared_dependencies=_declares_dependencies(target),
        lock_files=sorted(lock_files),
        vcs_history_available=(target / ".git").exists(),
        vcs_revision=vcs_revision,
        vcs_revision_verified=vcs_revision_verified,
        distribution_files=sorted(distribution_files),
        source_sha256=source_sha256,
        hashed_files=len(integrity_files),
        hashed_bytes=hashed_bytes,
    )
    return inventory, source_evidence


def _vcs_revision(target: Path) -> tuple[str, bool]:
    if not (target / ".git").exists():
        return "", False
    executable = resolve_executable("git")
    if executable is None:
        return "", False
    result = run_command(
        [
            executable,
            "-c",
            f"safe.directory={target.resolve()}",
            "rev-parse",
            "--verify",
            "HEAD",
        ],
        cwd=target,
        timeout_seconds=10,
        max_output_bytes=4096,
    )
    revision = result.stdout.strip().casefold()
    verified = (
        not result.timed_out
        and result.exit_code == 0
        and len(revision) == 40
        and all(character in "0123456789abcdef" for character in revision)
    )
    return (revision if verified else ""), verified


def source_snapshot(
    target: Path, *, excluded_paths: tuple[Path, ...] = ()
) -> tuple[str, int, int]:
    files, _ = _maintained_files(
        target,
        excluded_paths,
        skip_directories=_INTEGRITY_SKIP_DIRECTORIES,
    )
    digest, total_bytes = _source_digest(target, files)
    return digest, len(files), total_bytes


@contextmanager
def sealed_source_snapshot(
    target: Path,
    source_inventory: dict[str, Any],
    *,
    vcs_revision: str = "",
) -> Iterator[Path]:
    """Copy the exact inventoried source set into a private read-only scan root."""
    expected_digest = str(source_inventory.get("source_sha256") or "")
    records = source_inventory.get("files")
    if not isinstance(records, list) or not expected_digest:
        raise ValueError("source inventory cannot create a sealed scan snapshot")
    temporary_parent = Path(tempfile.mkdtemp(prefix="pysec-source-snapshot-"))
    snapshot = temporary_parent / target.name
    snapshot.mkdir(mode=0o700)
    try:
        _reject_lfs_pointer_records(target, records)
        for record in records:
            if not isinstance(record, dict):
                raise ValueError("source inventory contains an invalid file record")
            relative = Path(str(record.get("path") or ""))
            if (
                not relative.parts
                or relative.is_absolute()
                or ".." in relative.parts
                or relative.as_posix() != str(record.get("path"))
            ):
                raise ValueError("source inventory contains an unsafe snapshot path")
            size = record.get("size_bytes")
            digest = str(record.get("sha256") or "")
            if isinstance(size, bool) or not isinstance(size, int) or size < 0:
                raise ValueError("source inventory contains an invalid snapshot size")
            _, payload = read_regular_file(
                target / relative,
                "source snapshot member",
                maximum_bytes=max(1, size),
                boundary=target,
            )
            if len(payload) != size or hashlib.sha256(payload).hexdigest() != digest:
                raise ValueError("source changed while the sealed snapshot was created")
            destination = snapshot / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            with destination.open("xb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(destination, 0o400)
        if vcs_revision:
            _seal_git_history(target, snapshot, vcs_revision, temporary_parent)
        observed, count, total = source_snapshot(snapshot)
        if (
            observed != expected_digest
            or count != source_inventory.get("total_files")
            or total != source_inventory.get("total_bytes")
        ):
            raise ValueError("sealed scan snapshot does not match the source inventory")
        for directory in sorted(
            (path for path in snapshot.rglob("*") if path.is_dir()), reverse=True
        ):
            os.chmod(directory, 0o500)
        os.chmod(snapshot, 0o500)
        yield snapshot
    finally:
        for path in (
            [temporary_parent, *temporary_parent.rglob("*")]
            if temporary_parent.exists()
            else []
        ):
            try:
                os.chmod(path, 0o700 if path.is_dir() else 0o600)
            except OSError:
                pass
        shutil.rmtree(temporary_parent, ignore_errors=False)


def _seal_git_history(
    target: Path, snapshot: Path, revision: str, temporary_parent: Path
) -> None:
    """Materialize a hook-free, read-only Git history beside the source snapshot."""
    if not (target / ".git").exists():
        raise ValueError("verified Git revision has no repository metadata")
    git = resolve_executable("git")
    if git is None:
        raise ValueError("Git is unavailable while sealing repository history")
    _materialize_git_history(
        target,
        snapshot,
        revision,
        temporary_parent / "superproject",
    )
    _seal_submodule_histories(target, snapshot, temporary_parent)


def _materialize_git_history(
    target: Path, snapshot: Path, revision: str, work_root: Path
) -> None:
    """Bundle and materialize one exact repository without hooks or worktree files."""
    git = resolve_executable("git")
    if git is None:
        raise ValueError("Git is unavailable while sealing repository history")
    _validate_git_repository_mode(git, target)
    work_root.mkdir(mode=0o700, parents=True)
    bundle = work_root / "repository.bundle"
    clone = work_root / "history"
    environment = CommandEnvironment(max_scratch_bytes=4 * 1024**3)
    created = run_command(
        [
            git,
            "-c",
            f"safe.directory={target.resolve()}",
            "-C",
            str(target),
            "bundle",
            "create",
            str(bundle),
            "--all",
        ],
        cwd=target,
        timeout_seconds=300,
        max_output_bytes=64 * 1024,
        environment=environment,
    )
    if created.exit_code != 0 or created.timed_out or not bundle.is_file():
        raise ValueError("Git history could not be sealed into a repository bundle")
    if bundle.stat().st_size > 4 * 1024**3:
        raise ValueError("sealed Git history exceeds 4 GiB")
    verified = run_command(
        [git, "bundle", "verify", str(bundle)],
        cwd=target,
        timeout_seconds=300,
        max_output_bytes=64 * 1024,
        environment=environment,
    )
    if verified.exit_code != 0 or verified.timed_out:
        raise ValueError("sealed Git history bundle failed prerequisite validation")
    cloned = run_command(
        [git, "clone", "--no-checkout", "--no-local", str(bundle), str(clone)],
        cwd=work_root,
        timeout_seconds=300,
        max_output_bytes=64 * 1024,
        environment=environment,
    )
    if cloned.exit_code != 0 or cloned.timed_out or not (clone / ".git").is_dir():
        raise ValueError("sealed Git history could not be materialized")
    indexed = run_command(
        [git, "-C", str(clone), "read-tree", "HEAD"],
        cwd=clone,
        timeout_seconds=30,
        max_output_bytes=4096,
        environment=environment,
    )
    if indexed.exit_code != 0 or indexed.timed_out:
        raise ValueError("sealed Git history index could not be materialized")
    observed = run_command(
        [git, "-C", str(clone), "rev-parse", "--verify", "HEAD"],
        cwd=clone,
        timeout_seconds=10,
        max_output_bytes=4096,
    )
    if observed.exit_code != 0 or observed.stdout.strip().casefold() != revision:
        raise ValueError("sealed Git history does not match the inventoried revision")
    _copy_regular_tree(clone / ".git", snapshot / ".git")


def _validate_git_repository_mode(git: str, target: Path) -> None:
    """Reject repository modes that can hide or rewrite reachable history."""

    def query(arguments: list[str], *, exits: frozenset[int] = frozenset({0})) -> str:
        result = run_command(
            [
                git,
                "-c",
                f"safe.directory={target.resolve()}",
                "-C",
                str(target),
                *arguments,
            ],
            cwd=target,
            timeout_seconds=120,
            max_output_bytes=64 * 1024,
        )
        if result.timed_out or result.exit_code not in exits:
            raise ValueError("Git repository qualification command failed")
        return result.stdout.strip()

    if query(["rev-parse", "--is-shallow-repository"]).casefold() != "false":
        raise ValueError(
            "shallow Git history cannot provide complete repository evidence"
        )
    if query(["config", "--get", "extensions.partialClone"], exits=frozenset({0, 1})):
        raise ValueError("partial-clone Git repositories are not supported")
    promisor = query(
        ["config", "--get-regexp", r"^remote\..*\.promisor$"],
        exits=frozenset({0, 1}),
    )
    if any(
        line.rsplit(maxsplit=1)[-1].casefold() == "true"
        for line in promisor.splitlines()
    ):
        raise ValueError(
            "promisor-remotes can omit Git objects from repository evidence"
        )
    for setting in ("core.sparseCheckout", "core.sparseCheckoutCone"):
        if (
            query(
                ["config", "--bool", "--get", setting],
                exits=frozenset({0, 1}),
            ).casefold()
            == "true"
        ):
            raise ValueError("sparse-checkout Git repositories are not supported")
    if query(["replace", "-l"]):
        raise ValueError("Git replace refs can rewrite repository evidence")
    common_dir_text = query(["rev-parse", "--git-common-dir"])
    common_dir = Path(common_dir_text)
    if not common_dir.is_absolute():
        common_dir = target / common_dir
    alternates = common_dir.resolve() / "objects" / "info" / "alternates"
    if alternates.is_file() and alternates.stat().st_size:
        raise ValueError(
            "Git object alternates make repository evidence non-self-contained"
        )
    integrity = run_command(
        [
            git,
            "-c",
            f"safe.directory={target.resolve()}",
            "-C",
            str(target),
            "fsck",
            "--full",
            "--strict",
            "--no-dangling",
        ],
        cwd=target,
        timeout_seconds=300,
        max_output_bytes=64 * 1024,
    )
    if integrity.exit_code != 0 or integrity.timed_out:
        raise ValueError("Git object database failed full integrity validation")


def _seal_submodule_histories(
    target: Path, snapshot: Path, temporary_parent: Path
) -> None:
    """Recursively seal every initialized gitlink at its indexed revision."""
    gitmodules = target / ".gitmodules"
    if not gitmodules.is_file():
        return
    git = resolve_executable("git")
    if git is None:
        raise ValueError("Git is unavailable while sealing submodule history")
    listing = run_command(
        [
            git,
            "-c",
            f"safe.directory={target.resolve()}",
            "-C",
            str(target),
            "config",
            "--file",
            ".gitmodules",
            "--get-regexp",
            r"^submodule\..*\.path$",
        ],
        cwd=target,
        timeout_seconds=30,
        max_output_bytes=64 * 1024,
    )
    if listing.timed_out or listing.exit_code not in {0, 1}:
        raise ValueError("Git submodule declarations could not be enumerated")
    declarations = [
        line.split(maxsplit=1) for line in listing.stdout.splitlines() if line
    ]
    if len(declarations) > 128:
        raise ValueError("source repository exceeds 128 submodules")
    for index, declaration in enumerate(declarations):
        if len(declaration) != 2:
            raise ValueError("Git submodule declaration is malformed")
        relative = Path(declaration[1])
        if relative.is_absolute() or not relative.parts or ".." in relative.parts:
            raise ValueError("Git submodule path escapes the source root")
        source = (target / relative).resolve()
        try:
            source.relative_to(target.resolve())
        except ValueError as exc:
            raise ValueError("Git submodule path escapes the source root") from exc
        indexed = run_command(
            [git, "-C", str(target), "ls-files", "--stage", "--", relative.as_posix()],
            cwd=target,
            timeout_seconds=10,
            max_output_bytes=4096,
        )
        fields = indexed.stdout.strip().split(maxsplit=3)
        if indexed.exit_code != 0 or len(fields) < 3 or fields[0] != "160000":
            raise ValueError("declared Git submodule is not an indexed gitlink")
        expected_revision = fields[1].casefold()
        observed_revision, verified = _vcs_revision(source)
        if not verified or observed_revision != expected_revision:
            raise ValueError("Git submodule is absent or at the wrong indexed revision")
        destination = snapshot / relative
        destination.mkdir(parents=True, exist_ok=True)
        _materialize_git_history(
            source,
            destination,
            observed_revision,
            temporary_parent / f"submodule-{index}",
        )
        _seal_submodule_histories(
            source,
            destination,
            temporary_parent / f"submodule-{index}-nested",
        )


def _reject_lfs_pointer_records(target: Path, records: list[object]) -> None:
    """Reject Git LFS pointer placeholders in place of analyzable object bytes."""
    marker = b"version https://git-lfs.github.com/spec/v1\n"
    for record in records:
        if not isinstance(record, dict):
            continue
        size = record.get("size_bytes")
        if isinstance(size, bool) or not isinstance(size, int) or size > 4096:
            continue
        relative = Path(str(record.get("path") or ""))
        _, payload = read_regular_file(
            target / relative,
            "source snapshot LFS materialization check",
            maximum_bytes=4096,
            boundary=target,
        )
        normalized = payload.replace(b"\r\n", b"\n")
        if normalized.startswith(marker) and b"\noid sha256:" in normalized:
            raise ValueError(
                f"Git LFS object is not materialized in the source snapshot: {relative.as_posix()}"
            )


def _copy_regular_tree(source: Path, destination: Path) -> None:
    files = 0
    total_bytes = 0
    destination.mkdir(mode=0o700)
    for root, directories, names in os.walk(source, followlinks=False):
        root_path = Path(root)
        relative_root = root_path.relative_to(source)
        for directory in sorted(directories):
            candidate = root_path / directory
            if candidate.is_symlink():
                raise ValueError("sealed Git history contains a symbolic link")
            (destination / relative_root / directory).mkdir(mode=0o700)
        for name in sorted(names):
            candidate = root_path / name
            if candidate.is_symlink():
                raise ValueError("sealed Git history contains a symbolic link")
            _, payload = read_regular_file(
                candidate,
                "sealed Git history member",
                maximum_bytes=1024 * 1024**2,
                boundary=source,
            )
            files += 1
            total_bytes += len(payload)
            if files > 1_000_000 or total_bytes > 8 * 1024**3:
                raise ValueError("sealed Git history exceeds its copy limits")
            output = destination / relative_root / name
            with output.open("xb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(output, 0o400)


def _maintained_files(
    target: Path,
    excluded_paths: tuple[Path, ...],
    *,
    skip_directories: frozenset[str] = _SKIP_DIRECTORIES,
) -> tuple[list[Path], int]:
    resolved_target = target.resolve()
    excluded = tuple(path.resolve() for path in excluded_paths)
    files: list[Path] = []
    skipped_symlinks = 0
    for root, directories, filenames in os.walk(resolved_target, followlinks=False):
        root_path = Path(root)
        kept_directories: list[str] = []
        for directory in sorted(directories):
            path = root_path / directory
            if path.is_symlink():
                skipped_symlinks += 1
            elif directory not in skip_directories and not _is_excluded(path, excluded):
                kept_directories.append(directory)
        directories[:] = kept_directories
        for filename in sorted(filenames):
            path = root_path / filename
            if filename == ".git":
                # A submodule's .git pointer may reference the original host
                # checkout. Exact nested history is materialized separately.
                continue
            if path.is_symlink():
                skipped_symlinks += 1
                continue
            if not _is_excluded(path, excluded):
                files.append(path)
    return sorted(
        files,
        key=lambda path: path.relative_to(resolved_target).as_posix(),
    ), skipped_symlinks


def _is_excluded(path: Path, excluded: tuple[Path, ...]) -> bool:
    resolved = path.resolve()
    for root in excluded:
        if resolved == root:
            return True
        try:
            resolved.relative_to(root)
            return True
        except ValueError:
            continue
    return False


def _source_digest(target: Path, paths: list[Path]) -> tuple[str, int]:
    evidence = _source_inventory(target, paths)
    return str(evidence["source_sha256"]), int(evidence["total_bytes"])


def _source_inventory(target: Path, paths: list[Path]) -> dict[str, Any]:
    aggregate = hashlib.sha256()
    total_bytes = 0
    resolved_target = target.resolve()
    records: list[dict[str, Any]] = []
    for path in paths:
        content = hashlib.sha256()
        size = 0
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                content.update(chunk)
                size += len(chunk)
        relative = path.relative_to(resolved_target).as_posix().encode("utf-8")
        aggregate.update(len(relative).to_bytes(8, "big"))
        aggregate.update(relative)
        aggregate.update(size.to_bytes(8, "big"))
        aggregate.update(content.digest())
        total_bytes += size
        records.append(
            {
                "path": relative.decode("utf-8"),
                "size_bytes": size,
                "sha256": content.hexdigest(),
            }
        )
    return {
        "schema_version": "1.0",
        "scope": (
            "Exact regular-file identities included in the target source digest; "
            "generated scanner and report directories are excluded."
        ),
        "source_sha256": aggregate.hexdigest(),
        "total_files": len(records),
        "total_bytes": total_bytes,
        "files": records,
    }


def _declares_dependencies(target: Path) -> bool:
    pyproject = target / "pyproject.toml"
    if pyproject.is_file():
        try:
            with pyproject.open("rb") as handle:
                document: dict[str, Any] = tomllib.load(handle)
        except (OSError, tomllib.TOMLDecodeError):
            return True
        project = document.get("project")
        if isinstance(project, dict):
            dependencies = project.get("dependencies")
            if isinstance(dependencies, list) and dependencies:
                return True
            optional = project.get("optional-dependencies")
            if isinstance(optional, dict) and any(optional.values()):
                return True
        poetry = document.get("tool", {}).get("poetry", {})
        if isinstance(poetry, dict):
            dependencies = poetry.get("dependencies")
            if isinstance(dependencies, dict) and any(
                str(name).casefold() != "python" for name in dependencies
            ):
                return True
        groups = document.get("dependency-groups")
        if isinstance(groups, dict) and any(groups.values()):
            return True

    for name in ("requirements.txt", "requirements-dev.txt"):
        path = target / name
        if not path.is_file():
            continue
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except OSError:
            return True
        if any(
            line.strip() and not line.lstrip().startswith(("#", "--")) for line in lines
        ):
            return True
    return False


def _distribution_files(target: Path) -> list[str]:
    root = target / "dist"
    if not root.is_dir():
        return []
    return sorted(
        path.relative_to(target).as_posix()
        for path in root.iterdir()
        if path.is_file()
        and (
            path.suffix.casefold() == ".whl"
            or path.name.casefold().endswith((".tar.gz", ".zip"))
        )
    )
