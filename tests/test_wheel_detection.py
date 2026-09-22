import zipfile

import pytest

from scripts.validate_wheel_detection import verify_wheel


@pytest.mark.parametrize("mutation", [None, "changed", "missing", "extra"])
def test_exact_wheel_checks_all_installed_members(tmp_path, mutation):
    package = tmp_path / "py_security_suite"
    package.mkdir()
    wheel = tmp_path / "product.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("py_security_suite/__init__.py", "VERSION = 'test'\n")
        archive.writestr("py_security_suite/rules.json", '{"rule": "original"}')
    (package / "__init__.py").write_bytes(b"VERSION = 'test'\n")
    (package / "rules.json").write_text('{"rule": "original"}')
    if mutation == "changed":
        (package / "rules.json").write_text('{"rule": "replacement"}')
    elif mutation == "missing":
        (package / "rules.json").unlink()
    elif mutation == "extra":
        (package / "unexpected.py").write_text("pass")
    if mutation:
        with pytest.raises(ValueError):
            verify_wheel(wheel, package)
    else:
        result = verify_wheel(wheel, package)
        assert result["package_files"] == 2
        assert len(result["wheel_sha256"]) == 64


def test_wheel_traversal_is_rejected(tmp_path):
    wheel = tmp_path / "product.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("py_security_suite/../outside", "bad")
    with pytest.raises(ValueError, match="unsafe wheel entry"):
        verify_wheel(wheel, tmp_path)
