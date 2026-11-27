"""Validate built wheel/sdist core metadata and governed archive contents.

This is the repository's ``twine check`` equivalent: it parses the core
metadata of both distributions with strict validation, requires the PEP 639
license expression and license file, requires a renderable Markdown long
description, and rejects repository-only material in the sdist.
"""

from __future__ import annotations

import argparse
import sys
import tarfile
import zipfile
from pathlib import Path, PurePosixPath

from packaging.metadata import InvalidMetadata, Metadata


EXPECTED_LICENSE_EXPRESSION = "Apache-2.0"
EXPECTED_LICENSE_FILE = "LICENSE"
EXPECTED_DESCRIPTION_TYPE = "text/markdown"
# Repository-only trees that must never be shipped in the sdist.
FORBIDDEN_SDIST_ROOTS = frozenset({".github", "fuzz", "overrides", "tests"})


def _metadata_failures(label: str, raw: bytes) -> list[str]:
    failures: list[str] = []
    try:
        metadata = Metadata.from_email(raw, validate=True)
    except InvalidMetadata as error:
        return [f"{label}: invalid core metadata: {error}"]
    except ExceptionGroup as group:  # packaging aggregates validation errors
        return [f"{label}: invalid core metadata: {item}" for item in group.exceptions]
    if metadata.license_expression != EXPECTED_LICENSE_EXPRESSION:
        failures.append(
            f"{label}: License-Expression is {metadata.license_expression!r}, "
            f"expected {EXPECTED_LICENSE_EXPRESSION!r}"
        )
    if EXPECTED_LICENSE_FILE not in (metadata.license_files or []):
        failures.append(f"{label}: License-File {EXPECTED_LICENSE_FILE} is missing")
    if metadata.license:
        failures.append(f"{label}: legacy License field must not be set with PEP 639")
    content_type = (metadata.description_content_type or "").split(";", 1)[0]
    if content_type.strip() != EXPECTED_DESCRIPTION_TYPE:
        failures.append(
            f"{label}: Description-Content-Type must be {EXPECTED_DESCRIPTION_TYPE}"
        )
    if not (metadata.description or "").strip():
        failures.append(f"{label}: long description is empty")
    return failures


def wheel_failures(path: Path) -> list[str]:
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        metadata_names = [
            name
            for name in names
            if PurePosixPath(name).name == "METADATA"
            and PurePosixPath(name).parent.name.endswith(".dist-info")
        ]
        if len(metadata_names) != 1:
            return [f"{path.name}: expected exactly one .dist-info/METADATA"]
        dist_info = PurePosixPath(metadata_names[0]).parent
        failures = _metadata_failures(path.name, archive.read(metadata_names[0]))
    if str(dist_info / "licenses" / EXPECTED_LICENSE_FILE) not in names:
        failures.append(f"{path.name}: {EXPECTED_LICENSE_FILE} is not packaged")
    return failures


def sdist_failures(path: Path) -> list[str]:
    with tarfile.open(path, "r:gz") as archive:
        members = archive.getmembers()
        tops = {PurePosixPath(member.name).parts[0] for member in members}
        if len(tops) != 1:
            return [f"{path.name}: expected exactly one top-level directory"]
        top = next(iter(tops))
        relative = {
            PurePosixPath(*PurePosixPath(member.name).parts[1:]).as_posix()
            for member in members
            if len(PurePosixPath(member.name).parts) > 1
        }
        pkg_info = archive.extractfile(f"{top}/PKG-INFO")
        if pkg_info is None:
            return [f"{path.name}: PKG-INFO is missing"]
        failures = _metadata_failures(path.name, pkg_info.read())
    if EXPECTED_LICENSE_FILE not in relative:
        failures.append(f"{path.name}: {EXPECTED_LICENSE_FILE} is not packaged")
    leaked = sorted(
        name
        for name in relative
        if PurePosixPath(name).parts[0] in FORBIDDEN_SDIST_ROOTS
        or "__pycache__" in PurePosixPath(name).parts
    )
    if leaked:
        failures.append(
            f"{path.name}: repository-only files are packaged: {', '.join(leaked[:10])}"
        )
    return failures


def distribution_failures(directory: Path) -> list[str]:
    wheels = sorted(directory.glob("*.whl"))
    sdists = sorted(directory.glob("*.tar.gz"))
    if len(wheels) != 1 or len(sdists) != 1:
        return [f"{directory}: expected exactly one wheel and one sdist"]
    return wheel_failures(wheels[0]) + sdist_failures(sdists[0])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    arguments = parser.parse_args(argv)
    try:
        failures = distribution_failures(arguments.directory)
    except (OSError, tarfile.TarError, zipfile.BadZipFile, KeyError) as error:
        print(f"distribution metadata check failed: {error}", file=sys.stderr)
        return 1
    if failures:
        print(
            "distribution metadata check failed:\n- " + "\n- ".join(failures),
            file=sys.stderr,
        )
        return 1
    print("distribution metadata and contents are valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
