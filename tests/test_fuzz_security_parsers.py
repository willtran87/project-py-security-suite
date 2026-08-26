from __future__ import annotations

import importlib.util
import io
import stat
import tarfile
import zipfile
from pathlib import Path
from types import ModuleType

import pytest


_ROOT = Path(__file__).parent.parent


def _script() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "fuzz_security_parsers", _ROOT / "scripts/fuzz_security_parsers.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_binary_archive_oracles_accept_regular_members() -> None:
    module = _script()
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w") as archive:
        archive.writestr("reports/finding.json", "{}")
    assert module._inspect_zip(zip_buffer.getvalue())[0][0] == "reports/finding.json"

    tar_buffer = io.BytesIO()
    with tarfile.open(fileobj=tar_buffer, mode="w") as archive:
        data = b"{}"
        info = tarfile.TarInfo("reports/finding.json")
        info.size = len(data)
        archive.addfile(info, io.BytesIO(data))
    assert module._inspect_tar(tar_buffer.getvalue())[0][0] == "reports/finding.json"


def test_archive_oracles_reject_traversal_and_links() -> None:
    module = _script()
    with pytest.raises(ValueError, match="escapes"):
        module._safe_archive_path("../outside")

    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w") as archive:
        info = zipfile.ZipInfo("link")
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        archive.writestr(info, "target")
    with pytest.raises(ValueError, match="links"):
        module._inspect_zip(zip_buffer.getvalue())

    tar_buffer = io.BytesIO()
    with tarfile.open(fileobj=tar_buffer, mode="w") as archive:
        tar_info = tarfile.TarInfo("link")
        tar_info.type = tarfile.SYMTYPE
        tar_info.linkname = "target"
        archive.addfile(tar_info)
    with pytest.raises(ValueError, match="links"):
        module._inspect_tar(tar_buffer.getvalue())


def test_xml_oracle_rejects_external_entities() -> None:
    module = _script()
    assert module._inspect_xml(b"<root><child /></root>") == (2, 0, 0)
    with pytest.raises(Exception, match="EntitiesForbidden"):
        module._inspect_xml(
            b'<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
            b"<root>&xxe;</root>"
        )
