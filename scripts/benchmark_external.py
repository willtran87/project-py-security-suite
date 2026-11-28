"""Measure pinned, externally authored OWASP Python cases without executing them."""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import math
import re
import platform
import tempfile
import time
from importlib.resources import files
from pathlib import Path

from py_security_suite.adapters.bandit import BanditAdapter
from py_security_suite.adapters.codeql import CodeQlAdapter
from py_security_suite.adapters.semgrep import SemgrepAdapter
from py_security_suite.config import ToolConfig
from py_security_suite.execution import governed_asset_sha256
from py_security_suite.path_safety import read_regular_file

if __package__:
    from .validation_evidence import ValidationEvidence
    from .external_benchmark_scoring import (
        accuracy_gate,
        case_outcomes,
        protected_detection_regressions,
    )
else:
    from validation_evidence import ValidationEvidence
    from external_benchmark_scoring import (
        accuracy_gate,
        case_outcomes,
        protected_detection_regressions,
    )


def source_digest(root: Path) -> tuple[str, list[tuple[str, bytes]]]:
    members = []
    for path in sorted(
        root.rglob("*.py"), key=lambda p: p.relative_to(root).as_posix()
    ):
        _, data = read_regular_file(
            path, "external benchmark source", maximum_bytes=1024**2, boundary=root
        )
        # Git checkout line endings differ between supported operating systems.
        members.append(
            (path.relative_to(root).as_posix(), data.replace(b"\r\n", b"\n"))
        )
    records = [(name, hashlib.sha256(data).hexdigest()) for name, data in members]
    return hashlib.sha256(
        json.dumps(records, separators=(",", ":")).encode()
    ).hexdigest(), members


def labels(payload: str) -> list[dict]:
    rows = []
    seen = set()
    for row in csv.reader(io.StringIO(payload)):
        if not row or row[0].startswith("#"):
            continue
        if (
            len(row) != 4
            or not re.fullmatch(r"BenchmarkTest\d{5}", row[0])
            or row[2] not in {"true", "false"}
            or not row[3].isdigit()
            or row[0] in seen
        ):
            raise ValueError("invalid or duplicate external benchmark label")
        seen.add(row[0])
        rows.append(
            {"id": row[0], "cwe": "CWE-" + row[3], "positive": row[2] == "true"}
        )
    if not rows:
        raise ValueError("external benchmark has no labels")
    return rows


def interval(successes: int, total: int) -> list[float] | None:
    if not total:
        return None
    z, p = 1.959963984540054, successes / total
    denominator = 1 + z * z / total
    center = (p + z * z / (2 * total)) / denominator
    radius = (
        z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total)) / denominator
    )
    return [max(0.0, center - radius), min(1.0, center + radius)]


def score(expected: list[dict], detections: set[tuple[str, str]]) -> dict:
    results = {}
    for cwe in sorted({row["cwe"] for row in expected}):
        rows = [row for row in expected if row["cwe"] == cwe]
        tp = sum(row["positive"] and (row["id"], cwe) in detections for row in rows)
        fp = sum(not row["positive"] and (row["id"], cwe) in detections for row in rows)
        positive = sum(row["positive"] for row in rows)
        negative = len(rows) - positive
        results[cwe] = {
            "tp": tp,
            "fp": fp,
            "fn": positive - tp,
            "tn": negative - fp,
            "precision": tp / (tp + fp) if tp + fp else None,
            "recall": tp / positive if positive else None,
            "false_positive_rate": fp / negative if negative else None,
            "precision_wilson_95": interval(tp, tp + fp),
            "recall_wilson_95": interval(tp, positive),
        }
    return results


def evaluate(args: argparse.Namespace) -> dict:
    evidence = getattr(args, "evidence", None)
    lock = json.loads(args.lock.read_text(encoding="utf-8"))
    root = args.source.resolve()
    digest, members = source_digest(root)
    _, csv_bytes = read_regular_file(
        root / lock["labels_file"],
        "benchmark labels",
        maximum_bytes=1024**2,
        boundary=root,
    )
    csv_bytes = csv_bytes.replace(b"\r\n", b"\n")
    if (
        digest != lock["source_sha256"]
        or hashlib.sha256(csv_bytes).hexdigest() != lock["labels_sha256"]
    ):
        raise ValueError("external benchmark differs from its reviewed revision lock")
    expected = labels(csv_bytes.decode("utf-8"))
    case_ids = {row["id"] for row in expected}
    if len(expected) != lock["cases"]:
        raise ValueError("external benchmark label count changed")
    rules = Path(str(files("py_security_suite").joinpath("rules/python-security.yml")))
    adapters = [
        BanditAdapter(
            ToolConfig(executable=args.bandit, timeout_seconds=600), 32 * 1024**2
        ),
        SemgrepAdapter(
            ToolConfig(executable=args.semgrep, rules_path=rules, timeout_seconds=600),
            32 * 1024**2,
        ),
    ]
    if args.codeql:
        adapters.append(
            CodeQlAdapter(
                ToolConfig(
                    executable=args.codeql_runner,
                    auxiliary_executable=args.codeql,
                    database_path=args.codeql_home,
                    rules_path=rules.parent / "codeql",
                    timeout_seconds=args.codeql_timeout,
                ),
                64 * 1024**2,
            )
        )
    engines, union, observations = {}, set(), {}
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="pysec-external-benchmark-") as temporary:
        source = Path(temporary)
        # Expected labels, prior scanner results and repository configuration stay outside the scan.
        for name, data in members:
            destination = source / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(data)
        for adapter in adapters:
            if evidence:
                evidence.stage(f"{adapter.name}:scan", measurement_complete=False)
            print(
                f"Measuring {adapter.name} on {len(expected)} labeled cases", flush=True
            )
            result = adapter.run(source)
            detections = set()
            unattributed = []
            unresolved_locations = 0
            for finding in result.findings:
                cwes = {
                    "CWE-" + str(int(match.group(1)))
                    for value in finding.classifications
                    for match in re.finditer(r"\bCWE-(\d+)\b", value, re.IGNORECASE)
                }
                for location in finding.locations:
                    unresolved_locations += int(location.path.startswith("<"))
                    case = Path(location.path).stem
                    if case not in case_ids and len(unattributed) < 25:
                        unattributed.append(
                            {
                                "path": location.path,
                                "rules": [origin.rule_id for origin in finding.sources],
                                "cwes": sorted(cwes),
                            }
                        )
                    if case in case_ids:
                        for origin in finding.sources:
                            observations.setdefault(case, []).append(
                                {
                                    "engine": adapter.name,
                                    "rule": origin.rule_id,
                                    "path": location.path,
                                    "line": location.start_line,
                                    "cwes": sorted(cwes),
                                    "path_trace_retained": bool(
                                        finding.evidence.get("sarif_code_flows")
                                    ),
                                }
                            )
                    detections.update(
                        (case, cwe)
                        for cwe in cwes
                        if re.fullmatch(r"BenchmarkTest\d{5}", case)
                    )
            union.update(detections)
            engines[adapter.name] = {
                "version": result.tool_run.version,
                "finding_count": len(result.findings),
                "constant_sink_reviews": result.diagnostic.get(
                    "constant_sink_reviews", []
                ),
                "native_flow_refinement": result.diagnostic.get(
                    "native_flow_refinement", {}
                ),
                "unattributed_location_samples": unattributed,
                "unresolved_finding_locations": unresolved_locations,
                "status": result.tool_run.status.value,
                "coverage": result.diagnostic.get("analysis_coverage"),
                "duration_seconds": result.tool_run.duration_seconds,
                "error": result.tool_run.error,
                "executable_sha256": result.tool_run.executable_sha256,
                "auxiliary_executable_sha256": result.tool_run.auxiliary_executable_sha256,
                "by_cwe": score(expected, detections),
            }
            if evidence:
                evidence.stage(
                    f"{adapter.name}:completed",
                    engines=engines,
                    cases=case_outcomes(expected, observations),
                    measurement_complete=False,
                )
    return {
        "schema_version": "1.1",
        "profile": "python-source-security" if args.codeql else "bandit-semgrep",
        "environment": {
            "python": platform.python_version(),
            "platform": platform.system(),
        },
        "duration_seconds": round(time.monotonic() - started, 3),
        "scope": "public external benchmark; not a private holdout or production accuracy estimate",
        "method": "case and matching CWE; distinct findings within a case count once",
        "upstream": lock,
        "rules_sha256": governed_asset_sha256(rules),
        "codeql_rules_sha256": governed_asset_sha256(rules.parent / "codeql")
        if args.codeql
        else None,
        "engines": engines,
        "combined_by_cwe": score(expected, union),
        "cases": case_outcomes(expected, observations),
        "measurement_complete": all(
            item["status"] == "completed"
            and item["unresolved_finding_locations"] == 0
            and isinstance(item["coverage"], dict)
            and item["coverage"].get("state") == "complete"
            for item in engines.values()
        ),
        "production_accuracy_validated": False,
    }


def regressions(result: dict, baseline: dict) -> list[str]:
    if (
        result["upstream"]["source_sha256"] != baseline["source_sha256"]
        or result["upstream"]["labels_sha256"] != baseline["labels_sha256"]
    ):
        raise ValueError("baseline belongs to a different external corpus")
    if not baseline.get("engines") or set(baseline["engines"]) != set(
        result["engines"]
    ):
        raise ValueError("baseline must cover every measured engine")
    failures = []
    for engine, categories in baseline["engines"].items():
        if set(categories) != set(result["engines"][engine]["by_cwe"]):
            raise ValueError("baseline must cover every measured CWE")
        for cwe, ceilings in categories.items():
            if any(
                type(ceilings.get(name)) is not int or ceilings[name] < 0
                for name in ("fp", "fn")
            ):
                raise ValueError("baseline ceilings must be nonnegative integers")
            observed = result["engines"].get(engine, {}).get("by_cwe", {}).get(cwe)
            if observed is None or any(
                observed[name] > ceilings[name] for name in ("fp", "fn")
            ):
                failures.append(f"{engine}:{cwe}")
    return failures + protected_detection_regressions(result, baseline)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--lock", type=Path, required=True)
    parser.add_argument("--bandit", required=True)
    parser.add_argument("--semgrep", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--baseline", type=Path)
    parser.add_argument("--codeql")
    parser.add_argument("--codeql-runner")
    parser.add_argument("--codeql-home", type=Path)
    parser.add_argument("--codeql-timeout", type=int, default=1800)
    parser.add_argument("--accuracy-policy", type=Path)
    parser.add_argument(
        "--require-accuracy",
        action="store_true",
        help="Fail unless the supplied accuracy policy passes",
    )
    args = parser.parse_args()
    if any((args.codeql, args.codeql_runner, args.codeql_home)) and not all(
        (args.codeql, args.codeql_runner, args.codeql_home)
    ):
        parser.error(
            "CodeQL requires --codeql, --codeql-runner and --codeql-home together"
        )
    if args.codeql_timeout < 1:
        parser.error("--codeql-timeout must be positive")
    if args.require_accuracy and not args.accuracy_policy:
        parser.error("--require-accuracy requires --accuracy-policy")
    args.bandit, args.semgrep = (
        str(Path(args.bandit).resolve()),
        str(Path(args.semgrep).resolve()),
    )
    args.evidence = ValidationEvidence(
        args.output, "public benchmark; not production approval"
    )
    args.evidence.stage("verify-corpus", measurement_complete=False)
    result = {}
    try:
        result = evaluate(args)
        if args.accuracy_policy:
            result["accuracy_gate"] = accuracy_gate(
                result, json.loads(args.accuracy_policy.read_text(encoding="utf-8"))
            )
            result["accuracy_policy_sha256"] = hashlib.sha256(
                args.accuracy_policy.read_bytes()
            ).hexdigest()
        if args.baseline:
            baseline = json.loads(args.baseline.read_text(encoding="utf-8"))
            result["regressions"] = regressions(result, baseline)
            result["regression_passed"] = not result["regressions"]
            result["baseline_sha256"] = hashlib.sha256(
                args.baseline.read_bytes()
            ).hexdigest()
    except (OSError, ValueError, TypeError, KeyError) as exc:
        result = {
            **result,
            "measurement_complete": False,
            "error_category": type(exc).__name__,
        }
        args.evidence.fail(exc)
    result["passed"] = (
        result["measurement_complete"]
        and result.get("regression_passed", True)
        and (
            not args.require_accuracy
            or result.get("accuracy_gate", {}).get("passed") is True
        )
    )
    result = args.evidence.finish(result)
    print(
        json.dumps(
            {
                "measurement_complete": result["measurement_complete"],
                "error": result.get("error"),
                "regression_passed": result.get("regression_passed"),
                "accuracy_passed": result.get("accuracy_gate", {}).get("passed"),
                "accuracy_required": args.require_accuracy,
                "output": str(args.output),
            }
        )
    )
    return (
        0
        if result["measurement_complete"]
        and result.get("regression_passed", True)
        and (
            not args.require_accuracy
            or result.get("accuracy_gate", {}).get("passed") is True
        )
        else 1
    )


if __name__ == "__main__":
    raise SystemExit(main())
