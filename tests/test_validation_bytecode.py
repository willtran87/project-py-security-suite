import json
import marshal
from pathlib import Path
import py_compile
import shutil
import subprocess
import sys
import zipfile
import pytest

from scripts.validate_product_acceptance import invoke


def poison_cache(source, replacement):
    cache = Path(
        py_compile.compile(
            str(source),
            doraise=True,
            invalidation_mode=py_compile.PycInvalidationMode.TIMESTAMP,
        )
    )
    cache.write_bytes(
        cache.read_bytes()[:16]
        + marshal.dumps(compile(replacement, str(source), "exec"))
    )


@pytest.mark.parametrize("emit_report", [True, False])
def test_wheel_validator_ignores_poisoned_product_and_helper_caches(
    tmp_path, emit_report
):
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    repository = Path(__file__).resolve().parents[1]
    for name in ("validate_wheel_detection.py", "validation_evidence.py"):
        shutil.copyfile(repository / "scripts" / name, scripts / name)
    poison_cache(
        scripts / "validation_evidence.py",
        "raise RuntimeError('cached helper executed')",
    )
    package = tmp_path / "site-packages/py_security_suite"
    package.mkdir(parents=True)
    source = package / "__init__.py"
    source.write_text("MARKER = 'wheel'\n")
    wheel = tmp_path / "fixture.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.write(source, "py_security_suite/__init__.py")
    poison_cache(source, "MARKER = 'cache'\n")
    driver = (
        "import json,sys,py_security_suite\nfrom pathlib import Path\n"
        "def main():\n"
        "    Path(sys.argv[-1]).write_text(json.dumps({'measurement_complete':True,'regression_passed':True,'marker':py_security_suite.MARKER}))\n"
        "    return 0\n"
    )
    if not emit_report:
        driver = "def main():\n    return 0\n"
    (scripts / "benchmark_external.py").write_text(driver)
    report, receipt = tmp_path / "report.json", tmp_path / "receipt.json"
    report.write_text(
        json.dumps(
            {"measurement_complete": True, "regression_passed": True, "marker": "stale"}
        )
    )
    wrapper = scripts / "validate_wheel_detection.py"
    result = subprocess.run(  # noqa: S603 - current interpreter and generated fixture only.
        [
            sys.executable,
            "-I",
            "-c",
            "import sys,runpy; sys.path.insert(0,sys.argv.pop(1)); sys.argv=sys.argv[1:]; runpy.run_path(sys.argv[0],run_name='__main__')",
            str(package.parent),
            str(wrapper),
            "--wheel",
            str(wheel),
            "--mode",
            "benchmark",
            "--receipt",
            str(receipt),
            "--",
            "--output",
            str(report),
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )
    recorded = json.loads(receipt.read_text())
    assert result.returncode == (0 if emit_report else 1), result.stderr
    assert recorded["passed"] is emit_report
    archived = receipt.parent / recorded["archived_report"]
    assert archived.read_bytes() == report.read_bytes()
    if emit_report:
        assert json.loads(report.read_text())["marker"] == "wheel"
    else:
        assert json.loads(report.read_text())["state"] == "running"
        assert "stale" not in report.read_text()


def test_wheel_receipt_cannot_overwrite_wheel(tmp_path, monkeypatch):
    from scripts.validate_wheel_detection import main

    wheel = tmp_path / "product.whl"
    wheel.write_bytes(b"original artifact")
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "verify",
            "--wheel",
            str(wheel),
            "--receipt",
            str(wheel),
            "--mode",
            "benchmark",
        ],
    )
    with pytest.raises(SystemExit) as caught:
        main()
    assert caught.value.code == 2
    assert wheel.read_bytes() == b"original artifact"


def test_acceptance_subprocess_ignores_an_existing_cache(tmp_path):
    source = tmp_path / "fixture.py"
    source.write_text("MARKER = 'source'\n")
    poison_cache(source, "MARKER = 'cache'\n")
    arguments = [
        "-c",
        "import sys; sys.path.insert(0,sys.argv[1]); import fixture; print(fixture.MARKER)",
        str(tmp_path),
    ]
    assert invoke(sys.executable, arguments, tmp_path).stdout.strip() == "source"
