from __future__ import annotations

import zipfile
import tarfile
from pathlib import Path
from unittest.mock import patch

import pytest

from py_security_suite.benchmark_input_validation import (
    BenchmarkInputError,
    validate_benchmark_input,
)
from py_security_suite import benchmark_input_validation


def test_validates_strict_json_and_safe_archive(tmp_path: Path) -> None:
    document = tmp_path / "labels.json"
    document.write_text('{"case": true}', encoding="utf-8")
    archive = tmp_path / "source.zip"
    with zipfile.ZipFile(archive, "w") as output:
        output.writestr("src/example.py", "print('safe')\n")

    assert validate_benchmark_input(document)["format"] == "json"
    validation = validate_benchmark_input(archive)
    assert validation["format"] == "zip"
    assert validation["entries"] == 1


def test_rejects_duplicate_or_traversing_archive_members(tmp_path: Path) -> None:
    archive = tmp_path / "unsafe.zip"
    with zipfile.ZipFile(archive, "w") as output:
        output.writestr("../escape.txt", "unsafe")

    with pytest.raises(BenchmarkInputError, match="unsafe path"):
        validate_benchmark_input(archive)


def test_rejects_nonportable_archive_paths(tmp_path: Path) -> None:
    collision = tmp_path / "collision.zip"
    with zipfile.ZipFile(collision, "w") as output:
        output.writestr("Data/case.json", "{}")
        output.writestr("data\\case.json", "{}")

    with pytest.raises(BenchmarkInputError, match="duplicate paths"):
        validate_benchmark_input(collision)

    drive_path = tmp_path / "drive.zip"
    with zipfile.ZipFile(drive_path, "w") as output:
        output.writestr("C:/outside.json", "{}")

    with pytest.raises(BenchmarkInputError, match="unsafe path"):
        validate_benchmark_input(drive_path)


def test_rejects_duplicate_json_keys(tmp_path: Path) -> None:
    document = tmp_path / "labels.json"
    document.write_text('{"case": true, "case": false}', encoding="utf-8")

    with pytest.raises(BenchmarkInputError, match="JSON input is invalid"):
        validate_benchmark_input(document)


def test_rejects_tar_special_entries(tmp_path: Path) -> None:
    archive = tmp_path / "special.tar"
    with tarfile.open(archive, "w") as output:
        fifo = tarfile.TarInfo("unsafe.fifo")
        fifo.type = tarfile.FIFOTYPE
        output.addfile(fifo)

    with pytest.raises(BenchmarkInputError, match="special entries"):
        validate_benchmark_input(archive)


def test_rejects_zip_special_entries(tmp_path: Path) -> None:
    archive = tmp_path / "special.zip"
    with zipfile.ZipFile(archive, "w") as output:
        link = zipfile.ZipInfo("unsafe-link")
        link.create_system = 3
        link.external_attr = 0o120777 << 16
        output.writestr(link, "target")

    with pytest.raises(BenchmarkInputError, match="special entries"):
        validate_benchmark_input(archive)


def test_detects_archive_mutation_while_held_handle_is_being_inspected(
    tmp_path: Path,
) -> None:
    archive = tmp_path / "changing.zip"
    with zipfile.ZipFile(archive, "w") as output:
        output.writestr("case.json", "{}")
    original = benchmark_input_validation._validate_zip

    def mutate_after_inspection(handle: object, size: int) -> dict[str, object]:
        result = original(handle, size)  # type: ignore[arg-type]
        archive.write_bytes(b"changed after inspection")
        return result

    with (
        patch.object(
            benchmark_input_validation,
            "_validate_zip",
            side_effect=mutate_after_inspection,
        ),
        pytest.raises(BenchmarkInputError, match="not a safe regular file") as captured,
    ):
        validate_benchmark_input(archive)
    assert captured.value.__cause__ is not None
    assert "changed while it was being read" in str(captured.value.__cause__)
