"""Run detection validation with isolated Python and an exact, verified installed wheel."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import runpy
import sys
import tempfile
import atexit
import zipfile
from pathlib import Path, PurePosixPath

if __name__ == "__main__":
    # Establish this before importing any repository validation helper.
    _cache = tempfile.TemporaryDirectory(prefix="")
    atexit.register(_cache.cleanup)
    sys.pycache_prefix = _cache.name
    sys.dont_write_bytecode = True
if __package__:
    from .validation_evidence import ValidationEvidence, atomic_bytes, atomic_json
else:
    # -I deliberately excludes the script directory until this explicit driver import.
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from validation_evidence import ValidationEvidence, atomic_bytes, atomic_json


def verify_wheel(wheel: Path, package: Path) -> dict:
    if wheel.stat().st_size > 64 * 1024**2:
        raise ValueError("wheel exceeds 64 MiB")
    expected = {}
    with zipfile.ZipFile(wheel) as archive:
        names = archive.namelist()
        if len(names) != len(set(names)) or len(names) > 10000:
            raise ValueError("duplicate or excessive wheel entries")
        total = 0
        for member in archive.infolist():
            name = PurePosixPath(member.filename)
            if name.is_absolute() or ".." in name.parts or "\\" in member.filename:
                raise ValueError("unsafe wheel entry")
            if not member.filename.startswith("py_security_suite/") or member.is_dir():
                continue
            total += member.file_size
            if total > 128 * 1024**2 or member.file_size > 16 * 1024**2:
                raise ValueError("unpacked wheel exceeds validation bounds")
            relative = name.relative_to("py_security_suite").as_posix()
            expected[relative] = hashlib.sha256(archive.read(member)).hexdigest()
    if "__init__.py" not in expected:
        raise ValueError("wheel does not contain the product")
    actual = {}
    for count, path in enumerate(package.rglob("*"), start=1):
        if count > 20000:
            raise ValueError("installed package exceeds entry limit")
        if path.is_symlink() or (hasattr(path, "is_junction") and path.is_junction()):
            raise ValueError("installed package contains a link")
        if path.is_dir() or "__pycache__" in path.relative_to(package).parts:
            continue
        relative = path.relative_to(package).as_posix()
        if relative not in expected or path.stat().st_size > 16 * 1024**2:
            raise ValueError("unexpected installed package member")
        actual[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
    if actual != expected:
        raise ValueError("installed package differs from the wheel")
    return {
        "wheel_sha256": hashlib.sha256(wheel.read_bytes()).hexdigest(),
        "package_sha256": hashlib.sha256(
            json.dumps(expected, sort_keys=True).encode()
        ).hexdigest(),
        "package_files": len(expected),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wheel", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--mode", choices=("benchmark", "acceptance"), required=True)
    parser.add_argument("arguments", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    arguments = args.arguments[1:] if args.arguments[:1] == ["--"] else args.arguments
    if args.receipt.resolve() == args.wheel.resolve():
        parser.error("receipt must not overwrite the wheel")
    evidence = ValidationEvidence(args.receipt, "exact installed-wheel validation")
    receipt = evidence.document
    evidence.stage("verify-installed-package", mode=args.mode)
    try:
        if not sys.flags.isolated:
            raise ValueError("exact wheel validation requires python -I")
        if not sys.pycache_prefix or not sys.dont_write_bytecode:
            raise ValueError(
                "exact wheel validation requires a fresh bytecode namespace"
            )
        if any(
            name == "py_security_suite" or name.startswith("py_security_suite.")
            for name in sys.modules
        ):
            raise ValueError("product must not be imported before wheel verification")
        receipt["bytecode_policy"] = "fresh private prefix; cache writes disabled"
        spec = importlib.util.find_spec("py_security_suite")
        if spec is None or spec.origin is None:
            raise ValueError("installed product is missing")
        package = Path(spec.origin).resolve().parent
        if "site-packages" not in package.parts:
            raise ValueError("exact wheel validation rejects editable installations")
        before = verify_wheel(args.wheel, package)
        receipt.update(artifact_before=before, interpreter=sys.executable)
        if "--output" not in arguments:
            raise ValueError("validation requires an output report")
        output = Path(arguments[arguments.index("--output") + 1])
        if output.resolve() == args.receipt.resolve():
            raise ValueError("receipt and validation report must be different")
        if output.resolve() == args.wheel.resolve():
            raise ValueError("validation report must not overwrite the wheel")
        driver = Path(__file__).with_name(
            "benchmark_external.py"
            if args.mode == "benchmark"
            else "validate_product_acceptance.py"
        )
        if args.mode == "acceptance":
            if any(
                arg == "--python" or arg.startswith("--python=") for arg in arguments
            ):
                raise ValueError(
                    "acceptance interpreter is bound to this wheel validation process"
                )
            arguments = ["--python", sys.executable, *arguments]
        # The scripts directory has validation drivers, never the product's src directory.
        sys.path.insert(0, str(driver.parent.resolve()))
        receipt["driver_assets_sha256"] = hashlib.sha256(
            json.dumps(
                {
                    p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                    for p in sorted(driver.parent.glob("*.py"))
                },
                sort_keys=True,
            ).encode()
        ).hexdigest()
        evidence.stage("validation-driver")
        # A driver that fails to emit a report must not reuse a prior successful run.
        atomic_json(
            output, {"state": "running", "passed": False, "run_id": receipt["run_id"]}
        )
        sys.argv = [str(driver), *arguments]
        module = runpy.run_path(str(driver), run_name="verified_detection_driver")
        code = module["main"]()
        evidence.stage("verify-final-package-and-report")
        after = verify_wheel(args.wheel, package)
        if before != after:
            raise ValueError("wheel or installation changed during validation")
        with output.open("rb") as stream:
            report_bytes = stream.read(64 * 1024**2 + 1)
        if len(report_bytes) > 64 * 1024**2:
            raise ValueError("validation report exceeds 64 MiB")
        document = json.loads(report_bytes)
        valid = (
            document.get("passed") is True
            if args.mode == "acceptance"
            else (
                document.get("measurement_complete") is True
                and document.get("regression_passed") is True
                and (
                    "--require-accuracy" not in arguments
                    or document.get("accuracy_gate", {}).get("passed") is True
                )
            )
        )
        receipt.update(
            artifact_after=after,
            artifact_verified=True,
            driver_exit_code=code,
            report_sha256=hashlib.sha256(report_bytes).hexdigest(),
            state="passed" if code == 0 and valid else "failed",
            passed=code == 0 and valid,
        )
        archive = evidence.run_directory / "report.json"
        atomic_bytes(archive, report_bytes)
        receipt["archived_report"] = archive.relative_to(args.receipt.parent).as_posix()
        receipt["stage"] = "finished"
    except (
        OSError,
        ValueError,
        KeyError,
        IndexError,
        RuntimeError,
        zipfile.BadZipFile,
    ) as exc:
        receipt.update(state="failed", passed=False, error_category=type(exc).__name__)
    finally:
        evidence.save()
    print(json.dumps({"passed": receipt["passed"], "receipt": str(args.receipt)}))
    return 0 if receipt["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
