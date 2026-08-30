from __future__ import annotations

import importlib.util
import io
import json
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


def test_zip_oracle_normalizes_unsupported_versions() -> None:
    module = _script()
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w") as archive:
        archive.writestr("report.json", "{}")
    payload = bytearray(zip_buffer.getvalue())
    central_directory = payload.index(b"PK\x01\x02")
    payload[central_directory + 6] = 102

    with pytest.raises(ValueError, match="unsupported feature or version"):
        module._inspect_zip(bytes(payload))


def test_xml_oracle_rejects_external_entities() -> None:
    module = _script()
    assert module._inspect_xml(b"<root><child /></root>") == (2, 0, 0)
    with pytest.raises(Exception, match="EntitiesForbidden"):
        module._inspect_xml(
            b'<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
            b"<root>&xxe;</root>"
        )


def test_xml_oracle_normalizes_unknown_encoding_rejection() -> None:
    module = _script()

    with pytest.raises(ValueError, match="unsupported encoding"):
        module._inspect_xml(b'<?xml version="1.0" encoding="UTF-5"?><report></report>')


def test_target_specific_corpus_seeds_reach_archive_validation(tmp_path: Path) -> None:
    module = _script()
    zip_corpus = tmp_path / "zip"
    tar_corpus = tmp_path / "tar"

    module._seed_target_corpus("zip-archive", zip_corpus)
    module._seed_target_corpus("tar-archive", tar_corpus)

    assert module._inspect_zip((zip_corpus / "zip-safe").read_bytes())
    with pytest.raises(ValueError, match="escapes"):
        module._inspect_zip((zip_corpus / "zip-traversal").read_bytes())
    with pytest.raises(ValueError, match="links"):
        module._inspect_zip((zip_corpus / "zip-link").read_bytes())
    with pytest.raises(ValueError, match="compression ratio"):
        module._inspect_zip((zip_corpus / "zip-ratio").read_bytes())

    assert module._inspect_tar((tar_corpus / "tar-safe").read_bytes())
    with pytest.raises(ValueError, match="escapes"):
        module._inspect_tar((tar_corpus / "tar-traversal").read_bytes())
    with pytest.raises(ValueError, match="links"):
        module._inspect_tar((tar_corpus / "tar-link").read_bytes())


def test_pull_request_matrix_shards_every_adapter(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    module = _script()
    monkeypatch.setattr(
        module.sys,
        "argv",
        ["fuzz_security_parsers.py", "--list-targets", "--shard-adapters"],
    )

    module.main()

    targets = json.loads(capsys.readouterr().out)
    adapter_targets = [
        target for target in targets if target["target"].startswith("adapter-")
    ]
    assert [target["target"] for target in adapter_targets] == [
        f"adapter-{index}" for index in range(module._ADAPTER_SHARDS)
    ]
    selected = {
        name
        for target in adapter_targets
        for name, _adapter in module._selected_adapters(target["target"])
    }
    assert selected == {name for name, _adapter in module._NAMED_ADAPTERS}
