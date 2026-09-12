"""Measure real scanner throughput through scan, report publication and verification.

Run with the installed candidate's interpreter. Results qualify only the recorded
host, source inventory, profile and concurrency; first runs are not cold-cache claims.
"""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import platform
import sys
import threading
import time
from pathlib import Path
import tempfile
import atexit

if __name__ == "__main__":
    _cache = tempfile.TemporaryDirectory(prefix="")
    atexit.register(_cache.cleanup)
    sys.pycache_prefix = _cache.name
    sys.dont_write_bytecode = True

from py_security_suite.config import PROFILE_TOOLS, load_config
from py_security_suite.execution import run_command
from py_security_suite.orchestrator import scan_project
from py_security_suite.passport import verify_report
from py_security_suite.scan_control import ScanControl, controlled_scan
from py_security_suite.repository_file_policy import maintained_repository_files
from py_security_suite.path_safety import read_regular_file

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.isolated_python import isolated_python
from scripts.native_resources import native_resources
from scripts.validation_evidence import ValidationEvidence
from scripts.validate_wheel_detection import verify_wheel


def source_digest(root: Path):
    records: list[tuple[str, str]] = []
    total = 0
    for path in maintained_repository_files(root):
        _, data = read_regular_file(
            path, "capacity source", boundary=root, maximum_bytes=16 * 1024**2
        )
        total += len(data)
        if total > 1024**3 or len(records) >= 100000:
            raise ValueError("capacity source exceeds bounded inventory")
        records.append(
            (path.relative_to(root).as_posix(), hashlib.sha256(data).hexdigest())
        )
    return hashlib.sha256(json.dumps(sorted(records)).encode()).hexdigest(), {
        "files": len(records),
        "bytes": total,
    }


def worker(args) -> dict:
    source, output = args.source.absolute(), args.worker.absolute()
    config = load_config(repository_config=args.config)
    events, cancelled = [], []
    timers = []
    control = ScanControl(timeout_seconds=args.timeout_seconds)

    def progress(event):
        events.append(event)
        if args.cancel and event.stage == "scanners" and event.state == "started":

            def cancel():
                cancelled.append(time.monotonic())
                control.cancel()

            timer = threading.Timer(0.25, cancel)
            timers.append(timer)
            timer.start()

    control.progress = progress
    started = time.monotonic()
    try:
        with controlled_scan(control):
            result = scan_project(
                target=source,
                output=output,
                config=config,
                network_isolation_attested=False,
                diagnostic_without_isolation=True,
            )
        verify_report(output)
    finally:
        for timer in timers:
            timer.cancel()
            timer.join()
    elapsed = time.monotonic() - started
    findings = sorted((f.finding_id, f.fingerprint) for f in result.findings)
    statuses = {
        run.tool: str(run.status)
        for run in result.tool_runs
        if run.applicable and str(run.status) != "skipped"
    }
    selected = {
        name for name in PROFILE_TOOLS[config.profile] if config.tools[name].enabled
    }
    manifest = json.loads((output / "scan-manifest.json").read_bytes())
    passed = (
        bool(cancelled)
        and str(result.outcome) == "incomplete"
        and time.monotonic() - cancelled[0] <= 15
        if args.cancel
        else set(statuses) == selected
        and set(statuses.values()) == {"completed"}
        and manifest["inventory"]["source_integrity_verified"] is True
    )
    return {
        "passed": passed,
        "cancelled": args.cancel,
        "seconds": round(elapsed, 3),
        "cancellation_seconds": round(time.monotonic() - cancelled[0], 3)
        if cancelled
        else None,
        "tool_statuses": statuses,
        "outcome": str(result.outcome),
        "source_sha256": manifest["inventory"]["source_sha256"],
        "findings_sha256": hashlib.sha256(json.dumps(findings).encode()).hexdigest(),
        "manifest_sha256": hashlib.sha256(
            (output / "scan-manifest.json").read_bytes()
        ).hexdigest(),
        "report_verified": True,
        "progress": [
            {
                "stage": event.stage,
                "state": event.state,
                "seconds": event.elapsed_seconds,
            }
            for event in events
        ],
        "report_bytes": sum(p.stat().st_size for p in output.rglob("*") if p.is_file()),
    }


def collect(args, destination: Path, cancel=False):
    command = [
        str(Path(__file__).absolute()),
        "--source",
        str(args.source.absolute()),
        "--config",
        str(args.config.absolute()),
        "--worker",
        str(destination.absolute()),
        "--timeout-seconds",
        str(args.timeout_seconds),
    ]
    if cancel:
        command.append("--cancel")
    with isolated_python(sys.executable, command) as invocation:
        raw = run_command(
            invocation,
            cwd=destination.parent,
            timeout_seconds=args.timeout_seconds + 60,
            max_output_bytes=65536,
        )
    if (
        raw.exit_code not in {0, 1}
        or raw.stop_reason
        or raw.timed_out
        or raw.output_limit_exceeded
    ):
        return {
            "passed": False,
            "exit_code": raw.exit_code,
            "timed_out": raw.timed_out,
            "stdout_sha256": hashlib.sha256(raw.stdout.encode()).hexdigest(),
            "stderr_sha256": hashlib.sha256(raw.stderr.encode()).hexdigest(),
        }
    try:
        result = json.loads(raw.stdout)
        if not isinstance(result, dict) or type(result.get("passed")) is not bool:
            raise ValueError("invalid worker result")
        if raw.exit_code != int(not result["passed"]):
            raise ValueError("worker result contradicts exit status")
        return result
    except ValueError:
        return {
            "passed": False,
            "error_category": "invalid-worker-result",
            "stderr_sha256": hashlib.sha256(raw.stderr.encode()).hexdigest(),
        }


def qualify(args):
    evidence = ValidationEvidence(
        args.output,
        "native full-pipeline capacity qualification; measured host and profile only",
    )
    try:
        before, members = source_digest(args.source.resolve())
        config_sha = hashlib.sha256(args.config.read_bytes()).hexdigest()
        import py_security_suite

        package = Path(py_security_suite.__file__).parent
        if "site-packages" not in package.parts:
            raise ValueError("capacity qualification requires an installed candidate")
        artifact = verify_wheel(args.wheel, package)
        evidence.stage(
            "profile",
            host=platform.platform(),
            python=sys.version,
            source_sha256=before,
            source_files=members["files"],
            source_bytes=members["bytes"],
            configuration_sha256=config_sha,
            artifact_before=artifact,
            repetitions=args.repetitions,
            concurrency=args.concurrency,
            maximum_wave_memory_bytes=args.max_memory_mib * 1024**2,
            maximum_wave_scratch_bytes=args.max_scratch_mib * 1024**2,
        )
        samples, waves = [], []
        for concurrency in sorted({1, args.concurrency}):
            for repetition in range(args.repetitions):
                evidence.stage(
                    "native-wave", concurrency=concurrency, repetition=repetition
                )
                destinations = [
                    evidence.run_directory / f"c{concurrency}-r{repetition}-w{index}"
                    for index in range(concurrency)
                ]
                with native_resources() as resources:
                    with ThreadPoolExecutor(max_workers=concurrency) as pool:
                        results = list(
                            pool.map(lambda p: collect(args, p), destinations)
                        )
                waves.append(
                    {**resources, "concurrency": concurrency, "repetition": repetition}
                )
                for destination, result in zip(destinations, results, strict=True):
                    result["report_directory"] = str(destination)
                    samples.append(result)
                    evidence.complete_case(result)
        evidence.stage("native-cancellation")
        cancellation = collect(
            args, evidence.run_directory / "cancellation", cancel=True
        )
        evidence.complete_case(cancellation)
        stable = (
            len({sample.get("findings_sha256") for sample in samples}) == 1
            and len({sample.get("source_sha256") for sample in samples}) == 1
        )
        limits_passed = all(
            wave["measurement_complete"]
            and wave["peak_rss_bytes"] <= args.max_memory_mib * 1024**2
            and wave["peak_scratch_bytes"] <= args.max_scratch_mib * 1024**2
            for wave in waves
        )
        unchanged = (
            source_digest(args.source.resolve())[0] == before
            and hashlib.sha256(args.config.read_bytes()).hexdigest() == config_sha
            and verify_wheel(args.wheel, package) == artifact
        )
        return evidence.finish(
            {
                "passed": all(sample["passed"] for sample in samples)
                and cancellation["passed"]
                and stable
                and limits_passed
                and unchanged,
                "findings_stable": stable,
                "inputs_unchanged": unchanged,
                "resource_limits_passed": limits_passed,
                "waves": waves,
                "cancellation": cancellation,
            }
        )
    except (ValueError, OSError, KeyError, TypeError, RuntimeError) as exc:
        return evidence.fail(exc)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--wheel", type=Path)
    parser.add_argument("--worker", type=Path)
    parser.add_argument("--cancel", action="store_true")
    parser.add_argument("--concurrency", type=int, choices=range(1, 5), default=2)
    parser.add_argument("--repetitions", type=int, choices=range(3, 6), default=3)
    parser.add_argument(
        "--timeout-seconds", type=int, choices=range(30, 1801), default=300
    )
    parser.add_argument(
        "--max-memory-mib", type=int, choices=range(128, 16385), default=2048
    )
    parser.add_argument(
        "--max-scratch-mib", type=int, choices=range(1, 4097), default=1024
    )
    args = parser.parse_args()
    if not args.worker and (not args.output or not args.wheel):
        parser.error("--output and --wheel are required")
    result = worker(args) if args.worker else qualify(args)
    print(json.dumps(result))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
