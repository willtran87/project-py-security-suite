from __future__ import annotations

import base64
import csv
import hashlib
import importlib.util
import io
import tarfile
import zipfile
from pathlib import Path
from types import ModuleType

import pytest


_ROOT = Path(__file__).parent.parent


def _script() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "verify_release_independent",
        _ROOT / "scripts/verify_release_independent.py",
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _digest(payload: bytes) -> str:
    value = base64.urlsafe_b64encode(hashlib.sha256(payload).digest()).rstrip(b"=")
    return f"sha256={value.decode('ascii')}"


def _release(root: Path, *, epoch: int, unsafe_wheel: bool = False) -> None:
    wheel = root / "example-1.0-py3-none-any.whl"
    files = {
        "example/__init__.py": b"__version__ = '1.0'\n",
        "example-1.0.dist-info/METADATA": b"Name: example\nVersion: 1.0\n\n",
        "example-1.0.dist-info/WHEEL": b"Wheel-Version: 1.0\nTag: py3-none-any\n",
    }
    if unsafe_wheel:
        files["../escape"] = b"bad"
    record_name = "example-1.0.dist-info/RECORD"
    rows = [
        [name, _digest(payload), str(len(payload))] for name, payload in files.items()
    ]
    rows.append([record_name, "", ""])
    buffer = io.StringIO()
    csv.writer(buffer, lineterminator="\n").writerows(rows)
    files[record_name] = buffer.getvalue().encode("utf-8")
    with zipfile.ZipFile(wheel, "w") as archive:
        for name, payload in files.items():
            archive.writestr(name, payload)

    with tarfile.open(root / "example-1.0.tar.gz", "w:gz") as archive:
        for name, payload in (
            ("example-1.0/PKG-INFO", b"Name: example\nVersion: 1.0\n"),
            ("example-1.0/example.py", b"pass\n"),
        ):
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            info.mtime = epoch
            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""
            archive.addfile(info, io.BytesIO(payload))


def test_independent_verifier_checks_exact_reproducible_artifact_set(
    tmp_path: Path,
) -> None:
    module = _script()
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    second.mkdir()
    _release(first, epoch=123)
    for source in first.iterdir():
        (second / source.name).write_bytes(source.read_bytes())

    result = module.compare(first, second, source_date_epoch=123)

    assert result["verified"] is True
    assert result["artifacts"]["wheel"]["project"] == "example"


def test_independent_verifier_rejects_archive_traversal(tmp_path: Path) -> None:
    module = _script()
    release = tmp_path / "release"
    release.mkdir()
    _release(release, epoch=123, unsafe_wheel=True)
    with pytest.raises(ValueError, match="unsafe"):
        module.verify_directory(release, source_date_epoch=123)
