from __future__ import annotations

import hashlib
import base64
import os
import shutil
import tempfile
import tomllib
from datetime import datetime
from contextlib import contextmanager
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from .deployment_receipt import verify_deployment_receipt
from .execution import (
    CommandEnvironment,
    native_runtime_closure_sha256,
    resolve_executable,
    run_command,
    sha256_file,
)
from .models import Inventory
from .path_safety import read_regular_file
from .strict_json import canonical_bytes, loads as strict_loads
from .git_replay import externalize_and_reverify_bundle


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
        and len(revision) in {40, 64}
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
    require_signed_git_provenance: bool = False,
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
            _seal_git_history(
                target,
                snapshot,
                vcs_revision,
                temporary_parent,
                require_signed_git_provenance=require_signed_git_provenance,
            )
            if require_signed_git_provenance:
                source_inventory["git_provenance"] = _retained_git_provenance(snapshot)
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
    target: Path,
    snapshot: Path,
    revision: str,
    temporary_parent: Path,
    *,
    require_signed_git_provenance: bool,
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
        require_signed_git_provenance=require_signed_git_provenance,
    )
    _seal_submodule_histories(
        target,
        snapshot,
        temporary_parent,
        require_signed_git_provenance=require_signed_git_provenance,
    )


def _materialize_git_history(
    target: Path,
    snapshot: Path,
    revision: str,
    work_root: Path,
    *,
    require_signed_git_provenance: bool = False,
) -> None:
    """Bundle and materialize one exact repository without hooks or worktree files."""
    git = resolve_executable("git")
    if git is None:
        raise ValueError("Git is unavailable while sealing repository history")
    signature_ledger = _validate_git_repository_mode(
        git, target, require_signed_provenance=require_signed_git_provenance
    )
    repository_state = _git_repository_state(git, target)
    if require_signed_git_provenance:
        git_sha256 = sha256_file(Path(git).resolve())
        allowed_signers_sha256, allowed_signers_base64 = _git_allowed_signers(
            git, target
        )
        git_manifest = {
            "schema_version": "1.0",
            "git_executable_sha256": git_sha256,
            "allowed_signers_file_sha256": allowed_signers_sha256,
            "allowed_signers_file_base64": allowed_signers_base64,
            "signer_policy": _git_signer_policy(),
            "signature_ledger": signature_ledger,
            "repository_state": repository_state,
            "git_runtime_manifest": {
                "version": _git_version(git, target),
                "executable_sha256": git_sha256,
                "runtime_closure_sha256": native_runtime_closure_sha256(Path(git)),
            },
        }
        git_manifest_receipt = None
    else:
        git_manifest = None
        git_manifest_receipt = None
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
    if _git_repository_state(git, target) != repository_state:
        raise ValueError(
            "Git refs or repository security configuration changed while sealing history"
        )
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
    bundled_refs = _git_bundle_refs(git, bundle, target)
    bundled_head = bundled_refs.pop("HEAD", None)
    if bundled_refs != repository_state["refs"] or bundled_head not in {
        None,
        repository_state["head"],
    }:
        raise ValueError(
            "sealed Git history bundle ref set does not match the qualified repository"
        )
    cloned = run_command(
        [git, "clone", "--no-checkout", "--no-local", str(bundle), str(clone)],
        cwd=work_root,
        timeout_seconds=300,
        max_output_bytes=64 * 1024,
        environment=environment,
    )
    if cloned.exit_code != 0 or cloned.timed_out or not (clone / ".git").is_dir():
        raise ValueError("sealed Git history could not be materialized")
    cloned_format = run_command(
        [git, "-C", str(clone), "rev-parse", "--show-object-format"],
        cwd=clone,
        timeout_seconds=10,
        max_output_bytes=4096,
    )
    if (
        cloned_format.exit_code != 0
        or cloned_format.timed_out
        or cloned_format.stdout.strip().casefold() != repository_state["object_format"]
    ):
        raise ValueError("sealed Git history changed its object format")
    cloned_objects = run_command(
        [git, "-C", str(clone), "rev-list", "--objects", "--all"],
        cwd=clone,
        timeout_seconds=120,
        max_output_bytes=64 * 1024 * 1024,
        environment=environment,
    )
    cloned_ledger = "\n".join(sorted(set(cloned_objects.stdout.strip().splitlines())))
    if (
        cloned_objects.exit_code != 0
        or cloned_objects.timed_out
        or cloned_objects.output_limit_exceeded
        or hashlib.sha256(cloned_ledger.encode()).hexdigest()
        != repository_state["reachable_objects_sha256"]
    ):
        raise ValueError("sealed Git bundle object ledger does not match its snapshot")
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
    if git_manifest is not None:
        git_manifest["clean_replay"] = _clean_git_signature_replay(
            git,
            clone,
            bundle,
            base64.b64decode(
                str(git_manifest["allowed_signers_file_base64"]), validate=True
            ),
            git_manifest["signature_ledger"],
            work_root,
        )
        git_manifest_receipt = verify_deployment_receipt(
            git_manifest,
            purpose="git-ref-manifest",
            environment_prefix="PYSEC_GIT_REF_MANIFEST_AUTHORITY",
        )
    _copy_regular_tree(clone / ".git", snapshot / ".git")
    if git_manifest is not None and git_manifest_receipt is not None:
        (snapshot / ".git" / "pysec-provenance.json").write_bytes(
            canonical_bytes(
                {
                    "schema_version": "1.0",
                    "manifest": git_manifest,
                    "authority_receipt": git_manifest_receipt,
                }
            )
        )


def _clean_git_signature_replay(
    git: str,
    clone: Path,
    bundle: Path,
    allowed_signers: bytes,
    expected_ledger: object,
    work_root: Path,
) -> dict[str, Any]:
    """Reverify every signature and object from the sealed bundle on a clean clone."""
    if not isinstance(expected_ledger, dict):
        raise ValueError("clean Git replay ledger is unavailable")
    signers = work_root / "clean-replay-allowed-signers"
    signers.write_bytes(allowed_signers)

    def query(arguments: list[str]) -> str:
        result = run_command(
            [
                git,
                "-c",
                "gpg.format=ssh",
                "-c",
                f"gpg.ssh.allowedSignersFile={signers}",
                "-C",
                str(clone),
                *arguments,
            ],
            cwd=clone,
            timeout_seconds=300,
            max_output_bytes=64 * 1024 * 1024,
        )
        if result.exit_code != 0 or result.timed_out or result.output_limit_exceeded:
            raise ValueError("clean Git signature replay failed")
        return result.stdout.strip()

    integrity = query(["fsck", "--full", "--strict", "--no-dangling"])
    if integrity:
        raise ValueError("clean Git replay reported object-integrity diagnostics")
    commit_rows = query(["log", "--all", "--format=%H%x00%G?%x00%GF%x00%cI"])
    observed_commits: dict[str, tuple[str, str, str]] = {}
    for row in commit_rows.splitlines():
        fields = row.split("\x00")
        if len(fields) != 4 or fields[1] != "G":
            raise ValueError("clean Git commit signature replay failed")
        observed_commits[fields[0].casefold()] = (
            fields[1],
            fields[2].strip().casefold(),
            datetime.fromisoformat(fields[3].replace("Z", "+00:00")).isoformat(),
        )
    expected_commits = {
        str(item["commit"]): (
            "G",
            str(item["fingerprint"]),
            str(item["committed_at"]),
        )
        for item in expected_ledger.get("commits", [])
    }
    if observed_commits != expected_commits:
        raise ValueError("clean Git commit ledger differs from qualified history")
    observed_tags: dict[str, tuple[str, str]] = {}
    for item in expected_ledger.get("tags", []):
        tag = str(item["tag"])
        signature = (
            query(
                [
                    "tag",
                    "-v",
                    "--format=%(signature:grade)%00%(signature:fingerprint)",
                    tag,
                ]
            )
            .splitlines()[-1]
            .split("\x00")
        )
        if len(signature) != 2 or signature[0] != "G":
            raise ValueError("clean Git tag signature replay failed")
        observed_tags[tag] = (signature[0], signature[1].strip().casefold())
    expected_tags = {
        str(item["tag"]): ("G", str(item["fingerprint"]))
        for item in expected_ledger.get("tags", [])
    }
    if observed_tags != expected_tags:
        raise ValueError("clean Git tag ledger differs from qualified history")
    replay: dict[str, Any] = {
        "schema_version": "1.0",
        "bundle_sha256": sha256_file(bundle),
        "reachable_objects_sha256": hashlib.sha256(
            "\n".join(
                sorted(set(query(["rev-list", "--objects", "--all"]).splitlines()))
            ).encode()
        ).hexdigest(),
        "signature_ledger_sha256": hashlib.sha256(
            canonical_bytes(expected_ledger)
        ).hexdigest(),
        "git_executable_sha256": sha256_file(Path(git)),
        "git_runtime_closure_sha256": native_runtime_closure_sha256(Path(git)),
        "verified_commits": len(observed_commits),
        "verified_tags": len(observed_tags),
    }
    replay.update(
        externalize_and_reverify_bundle(
            bundle,
            reachable_objects_sha256=replay["reachable_objects_sha256"],
            signature_ledger=expected_ledger,
            allowed_signers_sha256=hashlib.sha256(allowed_signers).hexdigest(),
            verified_commits=len(observed_commits),
            verified_tags=len(observed_tags),
        )
    )
    return replay


def _git_repository_state(git: str, target: Path) -> dict[str, Any]:
    """Capture the complete ref namespace and security-sensitive Git state."""

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
            max_output_bytes=64 * 1024 * 1024,
        )
        if (
            result.timed_out
            or result.output_limit_exceeded
            or result.exit_code not in exits
        ):
            raise ValueError("Git repository state could not be captured atomically")
        return result.stdout.strip()

    refs = _parse_ref_lines(
        query(["for-each-ref", "--format=%(objectname) %(refname)"])
    )
    object_format = query(["rev-parse", "--show-object-format"]).casefold()
    digest_length = (
        40 if object_format == "sha1" else 64 if object_format == "sha256" else 0
    )
    if not digest_length or any(
        len(digest) != digest_length for digest in refs.values()
    ):
        raise ValueError("Git repository object format is inconsistent")
    unreachable = query(
        [
            "fsck",
            "--full",
            "--strict",
            "--unreachable",
            "--no-reflogs",
            "--no-progress",
        ],
        exits=frozenset({0}),
    )
    if unreachable:
        raise ValueError(
            "Git object store contains unreachable or reflog-only objects that cannot be sealed"
        )
    reachable_objects = "\n".join(
        sorted(set(query(["rev-list", "--objects", "--all"]).splitlines()))
    )
    head = query(["rev-parse", "--verify", "HEAD"]).casefold()
    symbolic_head = query(["symbolic-ref", "-q", "HEAD"], exits=frozenset({0, 1}))
    configuration = query(
        [
            "config",
            "--null",
            "--get-regexp",
            r"^(extensions\.partialClone|core\.sparseCheckout|core\.sparseCheckoutCone|remote\..*\.promisor|gpg\..*|user\.signingKey|commit\.gpgSign|tag\.gpgSign)$",
        ],
        exits=frozenset({0, 1}),
    )
    common = Path(query(["rev-parse", "--git-common-dir"]))
    if not common.is_absolute():
        common = target / common
    alternates = common.resolve() / "objects" / "info" / "alternates"
    alternates_sha256 = (
        hashlib.sha256(alternates.read_bytes()).hexdigest()
        if alternates.is_file()
        else ""
    )
    return {
        "refs": refs,
        "object_format": object_format,
        "head": head,
        "symbolic_head": symbolic_head,
        "replace_refs": query(["replace", "-l"]),
        "security_config_sha256": hashlib.sha256(configuration.encode()).hexdigest(),
        "security_config_base64": base64.b64encode(configuration.encode()).decode(),
        "alternates_sha256": alternates_sha256,
        "reachable_objects_sha256": hashlib.sha256(
            reachable_objects.encode()
        ).hexdigest(),
    }


def _git_bundle_refs(git: str, bundle: Path, target: Path) -> dict[str, str]:
    listed = run_command(
        [git, "bundle", "list-heads", str(bundle)],
        cwd=target,
        timeout_seconds=120,
        max_output_bytes=4 * 1024 * 1024,
    )
    if listed.exit_code != 0 or listed.timed_out:
        raise ValueError("sealed Git history bundle refs could not be inspected")
    return _parse_ref_lines(listed.stdout.strip())


def _git_version(git: str, target: Path) -> str:
    result = run_command(
        [git, "--version"], cwd=target, timeout_seconds=10, max_output_bytes=4096
    )
    version = result.stdout.strip()
    if (
        result.exit_code != 0
        or result.timed_out
        or not version.startswith("git version ")
    ):
        raise ValueError("Git runtime version could not be retained")
    return version


def _parse_ref_lines(value: str) -> dict[str, str]:
    refs: dict[str, str] = {}
    for line in value.splitlines():
        parts = line.split(maxsplit=1)
        if len(parts) != 2 or len(parts[0]) not in {40, 64}:
            raise ValueError("Git ref advertisement is invalid")
        digest, name = parts[0].casefold(), parts[1]
        if name in refs or any(
            character not in "0123456789abcdef" for character in digest
        ):
            raise ValueError("Git ref advertisement is duplicated or invalid")
        refs[name] = digest
    return dict(sorted(refs.items()))


def _git_raw_object(
    git: str, target: Path, kind: str, identity: str
) -> tuple[str, str]:
    result = run_command(
        [
            git,
            "-c",
            f"safe.directory={target.resolve()}",
            "-C",
            str(target),
            "cat-file",
            kind,
            identity,
        ],
        cwd=target,
        timeout_seconds=120,
        max_output_bytes=16 * 1024 * 1024,
    )
    if result.exit_code != 0 or result.timed_out or result.output_limit_exceeded:
        raise ValueError(f"Git {kind} replay object could not be retained")
    payload = result.stdout.encode("utf-8")
    object_id = hashlib.sha256(
        kind.encode() + b" " + str(len(payload)).encode() + b"\0" + payload
    ).hexdigest()
    if object_id != identity.casefold():
        raise ValueError(f"Git {kind} replay object does not match its object ID")
    return base64.b64encode(payload).decode(), hashlib.sha256(payload).hexdigest()


def _validate_git_repository_mode(
    git: str, target: Path, *, require_signed_provenance: bool = False
) -> dict[str, Any] | None:
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
            max_output_bytes=64 * 1024 * 1024,
        )
        if (
            result.timed_out
            or result.output_limit_exceeded
            or result.exit_code not in exits
        ):
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
    if require_signed_provenance:
        if query(["rev-parse", "--show-object-format"]).casefold() != "sha256":
            raise ValueError("production Git provenance requires SHA-256 objects")
        git_sha256 = sha256_file(Path(git).resolve())
        expected_git = (
            os.environ.get("PYSEC_GIT_EXECUTABLE_SHA256", "").strip().casefold()
        )
        if not _sha256_digest(expected_git) or git_sha256 != expected_git:
            raise ValueError(
                "production Git verifier executable is not deployment-pinned"
            )
        state = _git_repository_state(git, target)
        expected_config = (
            os.environ.get("PYSEC_GIT_SECURITY_CONFIG_SHA256", "").strip().casefold()
        )
        if (
            not _sha256_digest(expected_config)
            or state["security_config_sha256"] != expected_config
        ):
            raise ValueError("production Git security configuration is not pinned")
        raw_signers = os.environ.get(
            "PYSEC_GIT_ALLOWED_SIGNER_FINGERPRINTS_JSON", ""
        ).strip()
        try:
            signer_value = strict_loads(raw_signers.encode())
        except (TypeError, ValueError) as exc:
            raise ValueError("production Git signer policy is invalid") from exc
        if not isinstance(signer_value, list) or not signer_value:
            raise ValueError("production Git signer policy is unavailable")
        signers: dict[str, tuple[str, datetime, datetime]] = {}
        for item in signer_value:
            if not isinstance(item, dict) or set(item) != {
                "fingerprint",
                "organization",
                "not_before",
                "not_after",
            }:
                raise ValueError("production Git signer policy has invalid identities")
            fingerprint = str(item["fingerprint"]).strip().casefold()
            try:
                not_before = datetime.fromisoformat(
                    str(item["not_before"]).replace("Z", "+00:00")
                )
                not_after = datetime.fromisoformat(
                    str(item["not_after"]).replace("Z", "+00:00")
                )
            except ValueError as exc:
                raise ValueError("production Git signer lifecycle is invalid") from exc
            organization = str(item["organization"]).strip()
            if (
                not 16 <= len(fingerprint) <= 128
                or not organization
                or not_before.tzinfo is None
                or not_after.tzinfo is None
                or not_before >= not_after
                or fingerprint in signers
            ):
                raise ValueError("production Git signer policy has invalid identities")
            signers[fingerprint] = organization, not_before, not_after
        if len({item[0] for item in signers.values()}) < 2:
            raise ValueError("production Git signer policy has invalid identities")
        if query(["config", "--get", "gpg.format"]).casefold() != "ssh":
            raise ValueError(
                "production Git signature verification requires SSH format"
            )
        _, allowed_signers_base64 = _git_allowed_signers(git, target)
        allowed_fingerprints = allowed_signer_fingerprints(
            base64.b64decode(allowed_signers_base64, validate=True)
        )
        if set(signers) - allowed_fingerprints:
            raise ValueError(
                "production Git signer policy is detached from allowed-signers file"
            )
        ledger = query(["log", "--all", "--format=%H%x00%G?%x00%GF%x00%cI"])
        commits = 0
        observed_organizations: set[str] = set()
        commit_ledger: list[dict[str, str]] = []
        for line in ledger.splitlines():
            fields = line.split("\x00")
            if len(fields) != 4:
                raise ValueError("Git commit provenance ledger is malformed")
            _, grade, fingerprint, committed_at = fields
            signer = signers.get(fingerprint.strip().casefold())
            try:
                committed = datetime.fromisoformat(committed_at.replace("Z", "+00:00"))
            except ValueError as exc:
                raise ValueError("Git commit timestamp is invalid") from exc
            if (
                grade != "G"
                or signer is None
                or committed.tzinfo is None
                or not signer[1] <= committed <= signer[2]
            ):
                raise ValueError(
                    "every reachable Git commit must have a trusted allowed signature"
                )
            observed_organizations.add(signer[0])
            object_base64, object_sha256 = _git_raw_object(
                git, target, "commit", fields[0]
            )
            commit_ledger.append(
                {
                    "commit": fields[0].casefold(),
                    "fingerprint": fingerprint.strip().casefold(),
                    "committed_at": committed.isoformat(),
                    "organization": signer[0],
                    "object_base64": object_base64,
                    "object_sha256": object_sha256,
                }
            )
            commits += 1
        if not commits:
            raise ValueError("Git commit provenance ledger is empty")
        tags = query(
            [
                "for-each-ref",
                "--format=%(refname:short)%00%(objecttype)%00%(taggerdate:iso-strict)",
                "refs/tags",
            ]
        )
        tag_ledger: list[dict[str, str]] = []
        for line in tags.splitlines():
            fields = line.split("\x00")
            if len(fields) != 3 or fields[1] != "tag":
                raise ValueError("production Git tags must be signed annotated tags")
            tag, _, tagged_at = fields
            signature = query(
                [
                    "tag",
                    "-v",
                    "--format=%(signature:grade)%00%(signature:fingerprint)",
                    tag,
                ],
                exits=frozenset({0}),
            ).splitlines()[-1]
            signature_fields = signature.split("\x00")
            signer = (
                signers.get(signature_fields[1].strip().casefold())
                if len(signature_fields) == 2
                else None
            )
            try:
                tag_time = datetime.fromisoformat(tagged_at.replace("Z", "+00:00"))
            except ValueError as exc:
                raise ValueError("Git tag timestamp is invalid") from exc
            if (
                len(signature_fields) != 2
                or signature_fields[0] != "G"
                or signer is None
                or tag_time.tzinfo is None
                or not signer[1] <= tag_time <= signer[2]
            ):
                raise ValueError("Git tag signature is not policy-approved")
            observed_organizations.add(signer[0])
            tag_object_id = query(["rev-parse", f"refs/tags/{tag}"])
            object_base64, object_sha256 = _git_raw_object(
                git, target, "tag", tag_object_id
            )
            tag_ledger.append(
                {
                    "tag": tag,
                    "object_id": tag_object_id,
                    "fingerprint": signature_fields[1].strip().casefold(),
                    "tagged_at": tag_time.isoformat(),
                    "organization": signer[0],
                    "object_base64": object_base64,
                    "object_sha256": object_sha256,
                }
            )
        if len(observed_organizations) < 2:
            raise ValueError(
                "production Git history requires signatures from two organizations"
            )
        return {
            "commits": sorted(commit_ledger, key=lambda item: item["commit"]),
            "tags": sorted(tag_ledger, key=lambda item: item["tag"]),
        }
    return None


def _seal_submodule_histories(
    target: Path,
    snapshot: Path,
    temporary_parent: Path,
    *,
    require_signed_git_provenance: bool,
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
            require_signed_git_provenance=require_signed_git_provenance,
        )
        _seal_submodule_histories(
            source,
            destination,
            temporary_parent / f"submodule-{index}-nested",
            require_signed_git_provenance=require_signed_git_provenance,
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


def _sha256_digest(value: str) -> bool:
    return len(value) == 64 and all(
        character in "0123456789abcdef" for character in value
    )


def _git_signer_policy() -> list[dict[str, Any]]:
    raw = os.environ.get("PYSEC_GIT_ALLOWED_SIGNER_FINGERPRINTS_JSON", "").strip()
    value = strict_loads(raw.encode())
    if not isinstance(value, list) or not value:
        raise ValueError("production Git signer policy is unavailable")
    return value


def _git_allowed_signers(git: str, target: Path) -> tuple[str, str]:
    result = run_command(
        [
            git,
            "-c",
            f"safe.directory={target.resolve()}",
            "-C",
            str(target),
            "config",
            "--path",
            "--get",
            "gpg.ssh.allowedSignersFile",
        ],
        cwd=target,
        timeout_seconds=30,
        max_output_bytes=64 * 1024,
    )
    if result.exit_code != 0 or result.timed_out or not result.stdout.strip():
        raise ValueError("production Git allowed-signers file is unavailable")
    path = Path(result.stdout.strip()).expanduser()
    if not path.is_absolute():
        path = target / path
    _, payload = read_regular_file(
        path.resolve(), "Git allowed-signers file", maximum_bytes=4 * 1024 * 1024
    )
    digest = hashlib.sha256(payload).hexdigest()
    expected = (
        os.environ.get("PYSEC_GIT_ALLOWED_SIGNERS_FILE_SHA256", "").strip().casefold()
    )
    if not _sha256_digest(expected) or digest != expected:
        raise ValueError("production Git allowed-signers file does not match its pin")
    return digest, base64.b64encode(payload).decode("ascii")


def allowed_signer_fingerprints(payload: bytes) -> set[str]:
    """Derive OpenSSH SHA-256 fingerprints from an allowed-signers file."""
    fingerprints: set[str] = set()
    key_markers = ("ssh-", "ecdsa-", "sk-")
    for raw_line in payload.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(b"#"):
            continue
        fields = line.split()
        index = next(
            (
                offset
                for offset, field in enumerate(fields[:-1])
                if field.decode("ascii", errors="ignore").startswith(key_markers)
            ),
            -1,
        )
        if index < 0:
            raise ValueError("Git allowed-signers entry has no public key")
        try:
            wire_key = base64.b64decode(fields[index + 1], validate=True)
        except ValueError as exc:
            raise ValueError("Git allowed-signers public key is invalid") from exc
        fingerprint = (
            base64.b64encode(hashlib.sha256(wire_key).digest())
            .decode("ascii")
            .rstrip("=")
        )
        fingerprints.add(f"sha256:{fingerprint}".casefold())
    if not fingerprints:
        raise ValueError("Git allowed-signers file contains no identities")
    return fingerprints


def _retained_git_provenance(snapshot: Path) -> list[dict[str, Any]]:
    retained: list[dict[str, Any]] = []
    for path in sorted(snapshot.rglob("pysec-provenance.json")):
        if path.parent.name != ".git":
            continue
        relative = path.parent.parent.relative_to(snapshot).as_posix() or "."
        _, payload = read_regular_file(
            path,
            "retained Git provenance",
            maximum_bytes=16 * 1024 * 1024,
            boundary=snapshot,
        )
        value = strict_loads(payload)
        if not isinstance(value, dict):
            raise ValueError("retained Git provenance is invalid")
        retained.append({"path": relative, **value})
    if not retained or retained[0]["path"] != ".":
        raise ValueError("superproject Git provenance was not retained")
    return retained


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
