"""Qualify a fixed native scan profile; preserve all attempts, including failures."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import tempfile
import atexit
import time
from pathlib import Path
from typing import Any

if __name__ == "__main__":
    _cache = tempfile.TemporaryDirectory(prefix="")
    atexit.register(_cache.cleanup)
    sys.pycache_prefix = _cache.name
    sys.dont_write_bytecode = True

from py_security_suite.adapters.semgrep import SEMGREP_JOBS
from py_security_suite.execution import run_command
from py_security_suite.path_safety import read_regular_file
from py_security_suite.strict_json import loads as strict_json_loads

if __package__:
    from .isolated_python import isolated_python
    from .validation_evidence import ValidationEvidence, output_identity
    from .native_resources import native_resources
    from .detection_stability import repeated_semgrep
else:
    from isolated_python import isolated_python
    from validation_evidence import ValidationEvidence, output_identity
    from native_resources import native_resources
    from detection_stability import repeated_semgrep


def _run_python(python: str, arguments: list[str], **kwargs):
    with isolated_python(python, arguments) as command:
        return run_command(command, **kwargs)


def runtime_identity(executable: Path, python: Path | None = None) -> dict[str, str]:
    """Inspect the scanner environment with its own interpreter, never the driver's."""
    python = python or executable.parent / (
        "python.exe" if executable.suffix == ".exe" else "python"
    )
    result = _run_python(
        str(python),
        [
            "-c",
            "import json,sys,sysconfig; from pathlib import Path; "
            "from importlib.metadata import distribution; "
            "from py_security_suite.execution import python_runtime_closure_sha256; "
            "p=Path(sys.argv[1]).resolve(); "
            "assert p.parent == Path(sysconfig.get_path('scripts')).resolve(); "
            "assert any(e.name == 'semgrep' for e in distribution('semgrep').entry_points); "
            "print(json.dumps({'python':sys.executable,'runtime_closure_sha256':"
            "python_runtime_closure_sha256(str(p),include_standard_library=True,refresh=True)}))",
            str(executable),
        ],
        cwd=executable.parent,
        timeout_seconds=180,
        max_output_bytes=4096,
    )
    if (
        result.exit_code
        or result.timed_out
        or result.output_limit_exceeded
        or result.stop_reason
    ):
        raise ValueError("scanner runtime identity could not be established")
    identity = strict_json_loads(result.stdout)
    if not isinstance(identity, dict) or not re.fullmatch(
        "[a-f0-9]{64}", str(identity.get("runtime_closure_sha256", ""))
    ):
        raise ValueError("invalid scanner runtime identity")
    if Path(identity.get("python", "")).resolve() != python.resolve():
        raise ValueError("scanner interpreter identity mismatch")
    return {
        "scanner_python": str(python),
        "runtime_closure_sha256": identity["runtime_closure_sha256"],
    }


def asset_identity(
    executable: Path, rules: Path, python: Path | None = None
) -> dict[str, str]:
    identities = {}
    for name, path in (("launcher", executable), ("rules", rules)):
        _, data = read_regular_file(path, name, maximum_bytes=32 * 1024**2)
        identities[name + "_sha256"] = hashlib.sha256(data).hexdigest()
    return {**identities, **runtime_identity(executable, python)}


def qualify(
    source: Path,
    executable: Path,
    rules: Path,
    repetitions: int,
    python: Path | None = None,
    evidence: ValidationEvidence | None = None,
) -> dict[str, Any]:
    if evidence:
        evidence.stage("initial-runtime-identity", attempts=[])
    identity_checks = []

    def identity(stage: str) -> dict[str, str]:
        started = time.monotonic()
        record = {"stage": stage, "complete": False}
        try:
            value = asset_identity(executable, rules, python)
            record["complete"] = True
            return value
        finally:
            record["duration_seconds"] = round(time.monotonic() - started, 3)
            identity_checks.append(record)
            if evidence:
                evidence.document["identity_checks"] = identity_checks
                evidence.save()

    assets = identity("initial")
    native_invocations = []
    profile = {
        "jobs": SEMGREP_JOBS,
        "bytecode_policy": "fresh private prefix; cache writes disabled",
        **assets,
    }
    if evidence:
        evidence.stage("runtime-identified", profile=profile)

    def checkpoint(state: str, attempt: dict) -> None:
        if evidence:
            if state == "finished":
                evidence.document["attempts"].append(attempt)
            evidence.stage(
                f"attempt-{attempt['attempt']}:{state}", current_attempt=attempt
            )

    def execute() -> dict[str, Any]:
        if evidence:
            evidence.stage("before-native:runtime-identity")
        if identity("before-native") != assets:
            raise ValueError("native qualification assets changed")
        if evidence:
            evidence.stage("native-scan")
        with native_resources() as resources:
            native_invocations.append(resources)
            result = _run_python(
                assets["scanner_python"],
                [
                    "-c",
                    "import sys; from importlib.metadata import distribution; "
                    "sys.argv=sys.argv[1:]; "
                    "next(e for e in distribution('semgrep').entry_points if e.name=='semgrep').load()()",
                    str(executable),
                    "scan",
                    "--config",
                    str(rules),
                    "--json",
                    "--metrics=off",
                    "--disable-version-check",
                    "--strict",
                    "--no-git-ignore",
                    f"--jobs={SEMGREP_JOBS}",
                    str(source),
                ],
                cwd=source,
                timeout_seconds=600,
                max_output_bytes=32 * 1024**2,
            )
        resources.update(
            exit_code=result.exit_code,
            timed_out=result.timed_out,
            stdout=output_identity(result.stdout),
            stderr=output_identity(result.stderr),
        )
        if evidence:
            evidence.stage(
                "after-native:runtime-identity", native_invocations=native_invocations
            )
        if not resources["measurement_complete"]:
            raise RuntimeError("native resource measurement was incomplete")
        if (
            result.exit_code
            or result.timed_out
            or result.stop_reason
            or result.output_limit_exceeded
        ):
            raise RuntimeError("native qualification did not finish")
        if identity("after-native") != assets:
            raise ValueError("native qualification assets changed")
        return strict_json_loads(result.stdout)

    _, report = repeated_semgrep(execute, source, repetitions, checkpoint=checkpoint)
    return {
        "schema_version": "1.0",
        "profile": profile,
        "native_invocations": native_invocations,
        "identity_checks": identity_checks,
        **report,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--semgrep", type=Path, required=True)
    parser.add_argument("--scanner-python", type=Path)
    parser.add_argument("--rules", type=Path, required=True)
    parser.add_argument("--repetitions", type=int, default=3, choices=range(1, 6))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    evidence = ValidationEvidence(
        args.output, "native runtime qualification; not production approval"
    )
    try:
        report = qualify(
            args.source.absolute(),
            args.semgrep.absolute(),
            args.rules.absolute(),
            args.repetitions,
            args.scanner_python.absolute() if args.scanner_python else None,
            evidence,
        )
        report = evidence.finish(report)
    except (OSError, ValueError) as exc:
        report = evidence.fail(exc)
    print(json.dumps(report, indent=2))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
