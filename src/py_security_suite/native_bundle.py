from __future__ import annotations

import hashlib
import json

from .strict_json import loads as strict_json_loads
import os
import re
import stat
import tempfile
import zipfile
from email.parser import BytesParser
from email.policy import default as email_policy
from pathlib import Path, PurePosixPath
from typing import Any

from .execution import CommandEnvironment, run_command, sha256_file
from .path_safety import is_link_like, resolve_regular_directory, resolve_regular_file


_MANIFEST_NAME = "bundle-manifest.json"
_SCHEMA_ID = "urn:project-py-security-suite:schema:native-bundle-verification:1.0"
_MAX_MANIFEST_BYTES = 32 * 1024 * 1024
_MAX_FILES = 200_000
_MAX_PATH_LENGTH = 4096
_MAX_WHEEL_MEMBERS = 100_000
_MAX_WHEEL_MEMBER_BYTES = 1024 * 1024 * 1024
_MAX_WHEEL_EXPANDED_BYTES = 2 * 1024 * 1024 * 1024
_MAX_COMPRESSION_RATIO = 1000
_MAX_METADATA_BYTES = 8 * 1024 * 1024
_MAX_PROCESS_OUTPUT = 2 * 1024 * 1024
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def verify_native_bundle(
    bundle: Path,
    *,
    manifest_sha256: str = "",
    python: Path | None = None,
    require_wheelhouse_closure: bool = False,
) -> dict[str, Any]:
    """Verify a closed native bundle and optionally resolve every wheel set offline."""
    root = resolve_regular_directory(bundle, "native bundle")
    manifest_path = resolve_regular_file(root / _MANIFEST_NAME, "bundle manifest")
    if manifest_path.stat().st_size > _MAX_MANIFEST_BYTES:
        raise ValueError("bundle manifest exceeds the bounded size limit")
    payload = manifest_path.read_bytes()
    observed_manifest_digest = hashlib.sha256(payload).hexdigest()
    expected_manifest_digest = _expected_digest(manifest_sha256)
    if (
        expected_manifest_digest
        and observed_manifest_digest != expected_manifest_digest
    ):
        raise ValueError("bundle manifest digest does not match the approved SHA-256")
    document = _read_manifest(payload)
    records = _file_records(document)
    actual = _enumerate_bundle(root)
    expected_paths = set(records) | {_MANIFEST_NAME}
    actual_paths = set(actual)
    missing = sorted(expected_paths - actual_paths)
    unexpected = sorted(actual_paths - expected_paths)
    changed: list[dict[str, Any]] = []
    verified_bytes = 0
    for relative, record in records.items():
        source = actual.get(relative)
        if source is None:
            continue
        size = source.stat().st_size
        digest = sha256_file(source)
        verified_bytes += size
        if size != record["size"] or digest != record["sha256"]:
            changed.append(
                {
                    "path": relative,
                    "expected_sha256": record["sha256"],
                    "observed_sha256": digest,
                    "expected_size": record["size"],
                    "observed_size": size,
                }
            )
    wheels, wheel_errors = _inspect_wheels(root, records)
    resolution = _wheelhouse_resolution(
        root,
        document,
        python=python,
        required=require_wheelhouse_closure,
    )
    errors = [
        *[f"missing file: {value}" for value in missing],
        *[f"unexpected file: {value}" for value in unexpected],
        *[f"changed file: {value['path']}" for value in changed],
        *wheel_errors,
    ]
    if resolution["status"] == "failed":
        errors.append("one or more declared Python environments do not resolve offline")
    verified = not errors and (
        not require_wheelhouse_closure or resolution["status"] == "passed"
    )
    canonical_records = json.dumps(
        [records[name] for name in sorted(records)],
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return {
        "schema_version": "1.0",
        "schema_id": _SCHEMA_ID,
        "authoritative": False,
        "verified": verified,
        "bundle": {
            "platform": _bounded_text(document.get("platform"), 200),
            "manifest_schema_version": _bounded_text(
                document.get("schema_version"), 20
            ),
            "manifest_sha256": observed_manifest_digest,
            "inventory_sha256": hashlib.sha256(canonical_records).hexdigest(),
        },
        "summary": {
            "declared_files": len(records),
            "verified_files": len(records) - len(missing) - len(changed),
            "verified_bytes": verified_bytes,
            "missing_files": len(missing),
            "unexpected_files": len(unexpected),
            "changed_files": len(changed),
            "wheels": len(wheels),
            "wheel_errors": len(wheel_errors),
            "python_environments": len(resolution["environments"]),
        },
        "missing": missing,
        "unexpected": unexpected,
        "changed": changed,
        "wheels": wheels,
        "wheelhouse_resolution": resolution,
        "errors": errors,
        "scope": (
            "Closed-set, checksum, size, link, wheel-structure, and optional no-index "
            "dependency-resolution verification. This receipt does not establish "
            "publisher identity, malware absence, external isolation, or organization "
            "approval."
        ),
    }


def render_native_bundle_verification(document: dict[str, Any]) -> str:
    summary = document["summary"]
    resolution = document["wheelhouse_resolution"]
    lines = [
        f"{'VERIFIED' if document['verified'] else 'FAILED'}: native bundle",
        (
            f"Files: {summary['verified_files']}/{summary['declared_files']} verified; "
            f"missing {summary['missing_files']}; unexpected "
            f"{summary['unexpected_files']}; changed {summary['changed_files']}"
        ),
        (
            f"Wheels: {summary['wheels']} inspected; "
            f"{summary['wheel_errors']} structural error(s)"
        ),
        (
            "Offline dependency resolution: "
            f"{str(resolution['status']).upper()} "
            f"({resolution['passed']}/{resolution['declared']} environment(s))"
        ),
        f"Manifest SHA-256: {document['bundle']['manifest_sha256']}",
    ]
    if document["errors"]:
        lines.append("Required actions:")
        lines.extend(f"- {error}" for error in document["errors"][:20])
        omitted = len(document["errors"]) - 20
        if omitted:
            lines.append(f"- ... {omitted} additional error(s) omitted")
    lines.append(f"Scope: {document['scope']}")
    return "\n".join(lines)


def render_native_bundle_verification_markdown(document: dict[str, Any]) -> str:
    summary = document["summary"]
    resolution = document["wheelhouse_resolution"]
    lines = [
        "# Native scanner bundle verification",
        "",
        f"**Decision:** {'VERIFIED' if document['verified'] else 'FAILED'}  ",
        f"**Platform:** `{document['bundle']['platform']}`  ",
        f"**Manifest SHA-256:** `{document['bundle']['manifest_sha256']}`",
        "",
        "## Closed-set integrity",
        "",
        "| Measure | Result |",
        "|---|---:|",
        f"| Declared files | {summary['declared_files']} |",
        f"| Verified files | {summary['verified_files']} |",
        f"| Missing files | {summary['missing_files']} |",
        f"| Unexpected files | {summary['unexpected_files']} |",
        f"| Changed files | {summary['changed_files']} |",
        f"| Wheels inspected | {summary['wheels']} |",
        f"| Wheel structural errors | {summary['wheel_errors']} |",
        "",
        "## Offline dependency closure",
        "",
        f"**Status:** {str(resolution['status']).upper()}  ",
        f"**Environments:** {resolution['passed']} / {resolution['declared']} passed",
        "",
        "| Environment | Requirements | Status | Action |",
        "|---|---:|---|---|",
    ]
    if resolution["environments"]:
        lines.extend(
            f"| `{item['name']}` | {item['requirements']} | {item['status']} | "
            f"{item['action']} |"
            for item in resolution["environments"]
        )
    else:
        lines.append(
            "| - | 0 | not declared | Generate a schema 2.0 bundle manifest. |"
        )
    lines.extend(["", "## Required actions", ""])
    if document["errors"]:
        lines.extend(f"- {error}" for error in document["errors"])
    else:
        lines.append("- None. Transfer the receipt to the independent approval lane.")
    lines.extend(["", f"> {document['scope']}"])
    return "\n".join(lines) + "\n"


def _expected_digest(value: str) -> str:
    normalized = value.strip().casefold()
    if normalized and _SHA256.fullmatch(normalized) is None:
        raise ValueError("manifest SHA-256 must be exactly 64 hexadecimal characters")
    return normalized


def _read_manifest(payload: bytes) -> dict[str, Any]:
    try:
        value = strict_json_loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("bundle manifest is not valid UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise ValueError("bundle manifest root must be an object")
    if str(value.get("schema_version")) not in {"1", "2.0"}:
        raise ValueError("bundle manifest schema_version must be '1' or '2.0'")
    return value


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("bundle manifest contains a duplicate object key")
        result[key] = value
    return result


def _file_records(document: dict[str, Any]) -> dict[str, dict[str, Any]]:
    values = document.get("files")
    if not isinstance(values, list) or not values or len(values) > _MAX_FILES:
        raise ValueError("bundle manifest files must be a bounded non-empty array")
    records: dict[str, dict[str, Any]] = {}
    folded: set[str] = set()
    for value in values:
        if not isinstance(value, dict):
            raise ValueError("bundle manifest file entries must be objects")
        relative = _safe_relative(value.get("path"))
        if relative == _MANIFEST_NAME:
            raise ValueError("bundle manifest cannot include itself in files")
        digest = str(value.get("sha256") or "").casefold()
        size = value.get("size")
        if _SHA256.fullmatch(digest) is None:
            raise ValueError(f"bundle file has an invalid SHA-256: {relative}")
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            raise ValueError(f"bundle file has an invalid size: {relative}")
        collision = relative.casefold()
        if relative in records or collision in folded:
            raise ValueError(f"bundle manifest has a duplicate path: {relative}")
        folded.add(collision)
        records[relative] = {"path": relative, "sha256": digest, "size": size}
    return records


def _safe_relative(value: object) -> str:
    text = str(value or "")
    path = PurePosixPath(text)
    if (
        not text
        or len(text) > _MAX_PATH_LENGTH
        or "\\" in text
        or "\x00" in text
        or path.is_absolute()
        or any(part in {"", ".", ".."} for part in path.parts)
        or ":" in path.parts[0]
    ):
        raise ValueError("bundle manifest contains an unsafe relative path")
    return path.as_posix()


def _enumerate_bundle(root: Path) -> dict[str, Path]:
    files: dict[str, Path] = {}
    stack = [root]
    while stack:
        directory = stack.pop()
        with os.scandir(directory) as entries:
            for entry in entries:
                path = Path(entry.path)
                if entry.is_symlink() or is_link_like(path):
                    raise ValueError("native bundle cannot contain links or junctions")
                if entry.is_dir(follow_symlinks=False):
                    stack.append(path)
                    continue
                if not entry.is_file(follow_symlinks=False):
                    raise ValueError(
                        "native bundle contains a non-regular filesystem entry"
                    )
                relative = path.relative_to(root).as_posix()
                if len(files) >= _MAX_FILES + 1:
                    raise ValueError(
                        "native bundle exceeds the bounded file-count limit"
                    )
                files[relative] = path
    return files


def _inspect_wheels(
    root: Path, records: dict[str, dict[str, Any]]
) -> tuple[list[dict[str, Any]], list[str]]:
    wheels: list[dict[str, Any]] = []
    errors: list[str] = []
    for relative in sorted(name for name in records if name.endswith(".whl")):
        wheel, error = _inspect_wheel_safely(root / PurePosixPath(relative), relative)
        if wheel is not None:
            wheels.append(wheel)
        if error is not None:
            errors.append(error)
    return wheels, errors


def _inspect_wheel_safely(
    path: Path, relative: str
) -> tuple[dict[str, Any] | None, str | None]:
    try:
        return _inspect_wheel(path, relative), None
    except (OSError, ValueError, zipfile.BadZipFile) as exc:
        return None, f"invalid wheel {relative}: {_bounded_text(exc, 500)}"


def _inspect_wheel(path: Path, relative: str) -> dict[str, Any]:
    with zipfile.ZipFile(path) as archive:
        members = archive.infolist()
        if not members or len(members) > _MAX_WHEEL_MEMBERS:
            raise ValueError("member count is empty or exceeds the limit")
        expanded = 0
        metadata_members: list[zipfile.ZipInfo] = []
        for member in members:
            _safe_relative(member.filename.rstrip("/"))
            if member.flag_bits & 0x1:
                raise ValueError("encrypted members are not allowed")
            mode = (member.external_attr >> 16) & 0o170000
            if mode == stat.S_IFLNK:
                raise ValueError("symbolic-link members are not allowed")
            if member.file_size > _MAX_WHEEL_MEMBER_BYTES:
                raise ValueError("member expanded size exceeds the limit")
            if member.file_size and (
                member.compress_size == 0
                or member.file_size / member.compress_size > _MAX_COMPRESSION_RATIO
            ):
                raise ValueError("member compression ratio exceeds the limit")
            expanded += member.file_size
            if expanded > _MAX_WHEEL_EXPANDED_BYTES:
                raise ValueError("expanded size exceeds the limit")
            # Vendored libraries may retain nested dist-info metadata. The wheel's
            # own metadata is the single top-level ``dist-info/METADATA`` member.
            if (
                member.filename.endswith(".dist-info/METADATA")
                and member.filename.count("/") == 1
            ):
                metadata_members.append(member)
        if len(metadata_members) != 1:
            raise ValueError("exactly one dist-info/METADATA file is required")
        metadata_info = metadata_members[0]
        if metadata_info.file_size > _MAX_METADATA_BYTES:
            raise ValueError("wheel metadata exceeds the bounded size limit")
        corrupt = archive.testzip()
        if corrupt is not None:
            raise ValueError(f"CRC verification failed for {corrupt}")
        message = BytesParser(policy=email_policy).parsebytes(
            archive.read(metadata_info)
        )
    name = str(message.get("Name") or "").strip()
    version = str(message.get("Version") or "").strip()
    if not name or not version:
        raise ValueError("wheel metadata requires Name and Version")
    requirements = [str(item) for item in (message.get_all("Requires-Dist") or [])]
    return {
        "path": relative,
        "name": _bounded_text(name, 500),
        "version": _bounded_text(version, 500),
        "members": len(members),
        "expanded_bytes": expanded,
        "declared_dependencies": len(requirements),
    }


def _wheelhouse_resolution(
    root: Path,
    document: dict[str, Any],
    *,
    python: Path | None,
    required: bool,
) -> dict[str, Any]:
    environments = _python_environments(document)
    if not environments:
        return {
            "status": "failed" if required else "not_declared",
            "declared": 0,
            "passed": 0,
            "python": None,
            "environments": [],
        }
    if python is None:
        return {
            "status": "failed" if required else "not_checked",
            "declared": len(environments),
            "passed": 0,
            "python": None,
            "environments": [
                {
                    "name": item["name"],
                    "requirements": len(item["requirements"]),
                    "status": "not_checked",
                    "action": "Pass --python to run bounded no-index resolution.",
                }
                for item in environments
            ],
        }
    interpreter = resolve_regular_file(python, "dependency-resolution Python")
    wheelhouse = resolve_regular_directory(root / "wheelhouse", "bundle wheelhouse")
    results = [
        _resolve_environment(interpreter, wheelhouse, root, item)
        for item in environments
    ]
    passed = sum(item["status"] == "passed" for item in results)
    return {
        "status": "passed" if passed == len(results) else "failed",
        "declared": len(results),
        "passed": passed,
        "python": interpreter.name,
        "environments": results,
    }


def _python_environments(document: dict[str, Any]) -> list[dict[str, Any]]:
    values = document.get("python_environments")
    if values is None:
        return []
    if not isinstance(values, list) or not values or len(values) > 32:
        raise ValueError("python_environments must be a bounded non-empty array")
    result: list[dict[str, Any]] = []
    names: set[str] = set()
    for value in values:
        if not isinstance(value, dict):
            raise ValueError("python environment declarations must be objects")
        name = _bounded_text(value.get("name"), 100).strip()
        requirements = value.get("requirements")
        if (
            not name
            or name in names
            or not isinstance(requirements, list)
            or not requirements
            or len(requirements) > 500
        ):
            raise ValueError("python environment declarations are invalid")
        normalized = [_requirement_text(item) for item in requirements]
        names.add(name)
        result.append({"name": name, "requirements": normalized})
    return result


def _requirement_text(value: object) -> str:
    text = str(value or "").strip()
    if (
        not text
        or len(text) > 1000
        or text.startswith("-")
        or any(character in text for character in "\r\n\x00")
        or "://" in text
        or " @ " in text
    ):
        raise ValueError("python requirements must be bounded registry requirements")
    return text


def _resolve_environment(
    interpreter: Path,
    wheelhouse: Path,
    root: Path,
    environment: dict[str, Any],
) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="pysec-wheel-resolution-") as temporary:
        report = Path(temporary) / "pip-report.json"
        command = [
            str(interpreter),
            "-m",
            "pip",
            "install",
            "--dry-run",
            "--ignore-installed",
            "--isolated",
            "--no-index",
            "--find-links",
            str(wheelhouse),
            "--report",
            str(report),
            *environment["requirements"],
        ]
        result = run_command(
            command,
            cwd=root,
            timeout_seconds=300,
            max_output_bytes=_MAX_PROCESS_OUTPUT,
            environment=CommandEnvironment(
                {
                    "PIP_NO_INDEX": "1",
                    "PIP_DISABLE_PIP_VERSION_CHECK": "1",
                    "PIP_CONFIG_FILE": os.devnull,
                }
            ),
        )
        passed = (
            result.exit_code == 0
            and not result.timed_out
            and not result.stdout_truncated
            and not result.stderr_truncated
            and report.is_file()
        )
        resolved = 0
        if passed:
            try:
                report_value = strict_json_loads(report.read_bytes())
                installs = report_value.get("install", [])
                if not isinstance(installs, list):
                    raise ValueError
                resolved = len(installs)
            except (AttributeError, json.JSONDecodeError, ValueError):
                passed = False
        return {
            "name": environment["name"],
            "requirements": len(environment["requirements"]),
            "status": "passed" if passed else "failed",
            "resolved_distributions": resolved,
            "action": (
                "No action."
                if passed
                else "Rebuild the wheelhouse with every transitive dependency for this platform."
            ),
        }


def _bounded_text(value: object, maximum: int) -> str:
    text = str(value or "").replace("\r", " ").replace("\n", " ").strip()
    return text[:maximum]
