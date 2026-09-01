from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path

import pytest

from scripts import prepare_scanner_database


class _Response(io.BytesIO):
    def __enter__(self) -> _Response:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def geturl(self) -> str:
        return prepare_scanner_database._DEFAULT_URL


def test_database_preparation_seals_exact_build_input(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    payload = b"PK\x03\x04bounded-osv-fixture"
    monkeypatch.setattr(
        prepare_scanner_database,
        "build_opener",
        lambda *_handlers: type(
            "Opener", (), {"open": lambda *_args, **_kwargs: _Response(payload)}
        )(),
    )

    metadata = prepare_scanner_database.prepare_database(tmp_path / "database")

    destination = tmp_path / "database" / "osv-pypi-all.zip"
    expected = hashlib.sha256(payload).hexdigest()
    assert destination.read_bytes() == payload
    assert metadata["sha256"] == expected
    assert json.loads((destination.parent / "metadata.json").read_text()) == metadata
    assert (destination.parent / "osv-pypi-all.zip.sha256").read_text() == (
        f"{expected}  osv-pypi-all.zip\n"
    )


def test_database_preparation_rejects_untrusted_or_unbounded_inputs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with pytest.raises(
        prepare_scanner_database.ScannerDatabasePreparationError,
        match="authorized HTTPS",
    ):
        prepare_scanner_database.prepare_database(
            tmp_path / "host", url="https://example.invalid/PyPI/all.zip"
        )

    monkeypatch.setattr(
        prepare_scanner_database,
        "build_opener",
        lambda *_handlers: type(
            "Opener", (), {"open": lambda *_args, **_kwargs: _Response(b"too-large")}
        )(),
    )
    output = tmp_path / "bounded"
    with pytest.raises(
        prepare_scanner_database.ScannerDatabasePreparationError,
        match="byte limit",
    ):
        prepare_scanner_database.prepare_database(output, maximum_bytes=4)
    assert not list(output.glob("*.part"))


def test_database_preparation_rejects_digest_mismatch_without_publishing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        prepare_scanner_database,
        "build_opener",
        lambda *_handlers: type(
            "Opener", (), {"open": lambda *_args, **_kwargs: _Response(b"snapshot")}
        )(),
    )
    output = tmp_path / "digest"

    with pytest.raises(
        prepare_scanner_database.ScannerDatabasePreparationError,
        match="operator-supplied digest",
    ):
        prepare_scanner_database.prepare_database(output, expected_sha256="0" * 64)

    assert not (output / "osv-pypi-all.zip").exists()
    assert not list(output.glob("*.part"))
