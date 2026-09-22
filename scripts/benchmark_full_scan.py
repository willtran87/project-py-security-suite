"""Reproducible full-pipeline scaling probes with synthetic scanner results.

Every sample runs in a fresh process and includes snapshotting, orchestration,
report rendering, sealing, and verification. This measures engine performance,
not third-party scanner throughput or detection accuracy.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import statistics
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

from py_security_suite.adapters.base import AdapterResult, ScannerAdapter
from py_security_suite.bounded_subprocess import run_bounded_subprocess
from py_security_suite.config import load_config
from py_security_suite.execution import run_command
from py_security_suite.models import (
    Confidence,
    Finding,
    Location,
    Severity,
    Source,
    ToolRun,
    ToolStatus,
)
from py_security_suite.orchestrator import scan_project
from py_security_suite.passport import verify_report
from py_security_suite.process_memory import process_tree_resident_bytes
from py_security_suite.scan_control import ScanControl, ScanProgress, controlled_scan

CASES = ("many-files", "oversized-source", "many-findings", "cancellation")


def run_sample(case: str, scale: int) -> dict[str, Any]:
    events: list[ScanProgress] = []
    cancelled_at: list[float] = []
    control = ScanControl(timeout_seconds=50, progress=events.append)

    class FixtureAdapter(ScannerAdapter):
        name = "bandit"

        def build_command(self, executable: str, target: Path) -> list[str]:
            return []

        def parse(self, payload: str, target: Path) -> list[Finding]:
            return []

        def run(self, target: Path) -> AdapterResult:
            def cancel() -> None:
                cancelled_at.append(time.perf_counter())
                control.cancel()

            timer = threading.Timer(0.3, cancel) if case == "cancellation" else None
            if timer:
                timer.start()
            try:
                raw = run_command(
                    [
                        sys.executable,
                        "-I",
                        "-c",
                        "import time; time.sleep(10)" if timer else "pass",
                    ],
                    cwd=target,
                    timeout_seconds=15,
                    max_output_bytes=1024,
                )
            finally:
                if timer:
                    timer.cancel()
                    timer.join()
            count = (
                500 * scale if case == "many-findings" and self.name == "bandit" else 0
            )
            findings = [
                Finding(
                    finding_id=f"PYSEC-BENCH-{number}",
                    fingerprint=f"sha256:bench-{number}",
                    title=f"Synthetic benchmark finding {number}",
                    description="Engine scaling fixture",
                    impact="Synthetic",
                    remediation="Synthetic",
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    area="benchmark",
                    locations=[Location("app.py", 1)],
                    sources=[
                        Source(
                            self.name, f"BENCH-{number}", "Synthetic benchmark input"
                        )
                    ],
                )
                for number in range(count)
            ]
            status = (
                ToolStatus.TIMED_OUT
                if raw.timed_out
                else ToolStatus.FAILED
                if raw.stop_reason
                else ToolStatus.COMPLETED
            )
            return AdapterResult(
                findings,
                ToolRun(
                    self.name,
                    status,
                    ["synthetic-benchmark"],
                    raw.duration_seconds,
                    finding_count=count,
                    error=raw.stop_reason or None,
                ),
                {},
            )

    class FixtureSecrets(FixtureAdapter):
        name = "detect-secrets"

    done = threading.Event()
    memory: list[int] = []
    memory_errors: list[str] = []

    def sample_memory() -> None:
        while not done.is_set():
            try:
                memory.append(process_tree_resident_bytes(os.getpid()))
            except RuntimeError as exc:
                memory_errors.append(str(exc))
                return
            done.wait(0.02)

    with tempfile.TemporaryDirectory(prefix="pysec-full-scan-bench-") as temporary:
        root = Path(temporary)
        target, report = root / "project", root / "report"
        target.mkdir()
        (target / "app.py").write_text(
            "def example():\n    return 1\n", encoding="utf-8"
        )
        if case == "many-files":
            for number in range(250 * scale):
                (target / f"module_{number:06d}.py").write_text(
                    "VALUE = 1\n", encoding="utf-8"
                )
        elif case == "oversized-source":
            (target / "large.py").write_bytes(
                b"VALUE = '" + b"x" * (3 * 1024**2 * scale) + b"'\n"
            )
        watcher = threading.Thread(target=sample_memory, daemon=True)
        started = time.perf_counter()
        watcher.start()
        try:
            with controlled_scan(control):
                result = scan_project(
                    target=target,
                    output=report,
                    config=load_config(profile_override="quick"),
                    network_isolation_attested=False,
                    diagnostic_without_isolation=True,
                    adapter_types={
                        "bandit": FixtureAdapter,
                        "detect-secrets": FixtureSecrets,
                    },
                )
            scan_finished = time.perf_counter()
            verify_report(report)
            verified_at = time.perf_counter()
            artifact_bytes = sum(
                path.stat().st_size for path in report.rglob("*") if path.is_file()
            )
        finally:
            done.set()
            watcher.join()
        if memory_errors:
            raise RuntimeError(memory_errors[0])
        stages = {}
        for event in events:
            if not event.tool and event.state in {"completed", "stopped"}:
                start = next(
                    (
                        e.elapsed_seconds
                        for e in events
                        if e.stage == event.stage
                        and e.state == "started"
                        and not e.tool
                    ),
                    None,
                )
                if start is not None:
                    stages[event.stage] = round(event.elapsed_seconds - start, 6)
        if case == "cancellation" and not cancelled_at:
            raise RuntimeError("cancellation fixture never reached the scanner")
        return {
            "case": case,
            "scale": scale,
            "total_seconds": round(verified_at - started, 6),
            "verification_seconds": round(verified_at - scan_finished, 6),
            "peak_rss_bytes": max(memory, default=0),
            "artifact_bytes": artifact_bytes,
            "cancellation_seconds": round(scan_finished - min(cancelled_at), 6)
            if cancelled_at
            else None,
            "stage_seconds": stages,
            "finding_count": len(result.findings),
            "outcome": str(result.outcome),
            "report_verified": True,
            "tool_statuses": {run.tool: str(run.status) for run in result.tool_runs},
            "tool_stop_reasons": {run.tool: run.error for run in result.tool_runs},
        }


def summarize(samples: list[dict[str, Any]]) -> dict[str, Any]:
    times = sorted(float(sample["total_seconds"]) for sample in samples)
    failures = []
    if max(times) > 50:
        failures.append("scan and verification exceeded 50 seconds")
    if max(sample["peak_rss_bytes"] for sample in samples) > 1024**3:
        failures.append("process-tree peak RSS exceeded 1 GiB")
    if max(sample["artifact_bytes"] for sample in samples) > 128 * 1024**2:
        failures.append("report size exceeded 128 MiB")
    if any(
        sample["cancellation_seconds"] is not None
        and sample["cancellation_seconds"] > 10
        for sample in samples
    ):
        failures.append("cancellation through report publication exceeded 10 seconds")
    for sample in samples:
        expected = "failed" if sample["case"] == "cancellation" else "completed"
        if set(sample["tool_statuses"].values()) != {expected}:
            failures.append("synthetic scanners did not produce the expected result")
        if sample["case"] == "cancellation" and set(
            sample["tool_stop_reasons"].values()
        ) != {"scan cancelled by operator"}:
            failures.append("scanner cancellation reason was not retained")
        if (
            sample["case"] == "many-findings"
            and sample["finding_count"] < 500 * sample["scale"]
        ):
            failures.append("finding workload was not retained")
    return {
        "sample_count": len(samples),
        "median_seconds": statistics.median(times),
        "p95_seconds": times[math.ceil(0.95 * len(times)) - 1],
        "peak_rss_bytes": max(sample["peak_rss_bytes"] for sample in samples),
        "maximum_artifact_bytes": max(sample["artifact_bytes"] for sample in samples),
        "passed": not failures,
        "failures": failures,
        "samples": samples,
    }


def collect_case(case: str, sample_count: int, scale: int) -> dict[str, Any]:
    samples = []
    try:
        for _ in range(sample_count):
            result = run_bounded_subprocess(
                [
                    sys.executable,
                    str(Path(__file__).resolve()),
                    "--worker",
                    case,
                    "--scale",
                    str(scale),
                ],
                timeout_seconds=60,
                maximum_stdout_bytes=65536,
                maximum_stderr_bytes=65536,
                environment=os.environ,
            )
            if result.returncode:
                raise RuntimeError(result.stderr.decode("utf-8", errors="replace"))
            samples.append(json.loads(result.stdout))
    except (ValueError, RuntimeError) as exc:
        return {"passed": False, "failures": [str(exc)], "samples": samples}
    return summarize(samples)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--samples", type=int, choices=range(1, 11), default=3)
    parser.add_argument("--scale", type=int, choices=range(1, 9), default=1)
    parser.add_argument("--case", choices=CASES, action="append")
    parser.add_argument("--worker", choices=CASES, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.worker:
        print(json.dumps(run_sample(args.worker, args.scale)))
        return 0
    cases = {
        case: collect_case(case, args.samples, args.scale)
        for case in args.case or CASES
    }
    document = {
        "schema_version": "1.0",
        "synthetic_scanners": True,
        "memory_sample_interval_seconds": 0.02,
        "cases": cases,
        "passed": all(case["passed"] for case in cases.values()),
    }
    rendered = json.dumps(document, indent=2, sort_keys=True)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return 0 if document["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
