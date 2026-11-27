from __future__ import annotations

import io
import tarfile
import zipfile
from pathlib import Path

from scripts.validate_distribution_metadata import distribution_failures


_METADATA = (
    "Metadata-Version: 2.4\n"
    "Name: py-security-suite\n"
    "Version: 0.1.0\n"
    "License-Expression: Apache-2.0\n"
    "License-File: LICENSE\n"
    "Description-Content-Type: text/markdown\n"
    "\n"
    "# Python Security Suite\n"
)


def _write(directory: Path, *, metadata: str = _METADATA, extra: str = "") -> None:
    with zipfile.ZipFile(
        directory / "py_security_suite-0.1.0-py3-none-any.whl", "w"
    ) as wheel:
        wheel.writestr("py_security_suite-0.1.0.dist-info/METADATA", metadata)
        wheel.writestr("py_security_suite-0.1.0.dist-info/licenses/LICENSE", "Apache")
    with tarfile.open(directory / "py_security_suite-0.1.0.tar.gz", "w:gz") as sdist:
        for name, payload in (
            ("PKG-INFO", metadata),
            ("LICENSE", "Apache"),
            *([(extra, "x")] if extra else []),
        ):
            data = payload.encode()
            info = tarfile.TarInfo(f"py_security_suite-0.1.0/{name}")
            info.size = len(data)
            sdist.addfile(info, io.BytesIO(data))


def test_valid_distributions_pass(tmp_path: Path) -> None:
    _write(tmp_path)

    assert distribution_failures(tmp_path) == []


def test_missing_license_expression_and_test_leak_fail(tmp_path: Path) -> None:
    _write(
        tmp_path,
        metadata=_METADATA.replace("License-Expression: Apache-2.0\n", ""),
        extra="tests/test_example.py",
    )

    failures = distribution_failures(tmp_path)

    assert any("License-Expression" in failure for failure in failures)
    assert any("repository-only files" in failure for failure in failures)
