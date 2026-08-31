from __future__ import annotations

import importlib.util
import os
import stat
import zipfile
from pathlib import Path
from types import ModuleType

import pytest


_ROOT = Path(__file__).parent.parent


def _script() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "extract_github_artifact", _ROOT / "scripts/extract_github_artifact.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _archive(path: Path, name: str, payload: bytes = b"evidence") -> None:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(name, payload)


def test_extracts_regular_artifact_members_with_private_permissions(
    tmp_path: Path,
) -> None:
    module = _script()
    source = tmp_path / "artifact.zip"
    destination = tmp_path / "evidence"
    _archive(source, "report/report.json")

    module.extract_github_artifact(source, destination)

    output = destination / "report/report.json"
    assert output.read_bytes() == b"evidence"
    if os.name != "nt":
        assert stat.S_IMODE(output.stat().st_mode) & 0o077 == 0


@pytest.mark.parametrize(
    "name",
    ("../escape", "/absolute", "C:/drive", "a/../b", "name. "),
)
def test_rejects_nonportable_and_escaping_names(tmp_path: Path, name: str) -> None:
    module = _script()
    source = tmp_path / "artifact.zip"
    _archive(source, name)

    with pytest.raises(ValueError, match="unsafe"):
        module.extract_github_artifact(source, tmp_path / "evidence")


def test_rejects_backslash_member_name_before_extraction() -> None:
    with pytest.raises(ValueError, match="unsafe"):
        _script()._validated_name("a\\b", set())


def test_rejects_links_duplicate_portable_names_and_compression_bombs(
    tmp_path: Path,
) -> None:
    module = _script()
    destination = tmp_path / "evidence"

    link = tmp_path / "link.zip"
    with zipfile.ZipFile(link, "w") as archive:
        member = zipfile.ZipInfo("link")
        member.external_attr = (stat.S_IFLNK | 0o777) << 16
        archive.writestr(member, "target")
    with pytest.raises(ValueError, match="links"):
        module.extract_github_artifact(link, destination)

    duplicate = tmp_path / "duplicate.zip"
    with zipfile.ZipFile(duplicate, "w") as archive:
        archive.writestr("Report.json", "a")
        archive.writestr("report.json", "b")
    with pytest.raises(ValueError, match="duplicate"):
        module.extract_github_artifact(duplicate, destination)

    bomb = tmp_path / "bomb.zip"
    _archive(bomb, "zeros.bin", b"\0" * 2_000_000)
    with pytest.raises(ValueError, match="compression ratio"):
        module.extract_github_artifact(bomb, destination)


def test_rejects_preexisting_or_linked_destination(tmp_path: Path) -> None:
    module = _script()
    source = tmp_path / "artifact.zip"
    _archive(source, "report.json")
    destination = tmp_path / "evidence"
    destination.mkdir()

    with pytest.raises(ValueError, match="must not already exist"):
        module.extract_github_artifact(source, destination)
