"""Verify local validation receipts and generate measured acceptance documentation.

This command verifies consistency and file integrity, not independent review or
the authenticity of an untrusted producer. Failed accuracy remains a failed gate.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

if __package__:
    from .external_benchmark_scoring import (
        accuracy_gate,
        protected_detection_regressions,
    )
    from .validate_wheel_detection import verify_wheel
    from .validation_evidence import atomic_bytes, atomic_json
else:
    from external_benchmark_scoring import (
        accuracy_gate,
        protected_detection_regressions,
    )
    from validate_wheel_detection import verify_wheel
    from validation_evidence import atomic_bytes, atomic_json

ROOT = Path(__file__).resolve().parents[1]
BYTECODE_POLICY = "fresh private prefix; cache writes disabled"
SCENARIOS = {
    "positive-and-negative",
    "identity-original",
    "relocated",
    "partial",
    "unavailable",
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def read_bytes(path: Path) -> bytes:
    require(path.is_file() and not path.is_symlink(), "evidence must be a regular file")
    with path.open("rb") as stream:
        data = stream.read(64 * 1024**2 + 1)
    require(len(data) <= 64 * 1024**2, "evidence exceeds 64 MiB")
    return data


def digest(path: Path) -> str:
    return hashlib.sha256(read_bytes(path)).hexdigest()


def read_json(path: Path) -> dict:
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate evidence key")
            result[key] = value
        return result

    def constant(_):
        raise ValueError("nonfinite evidence number")

    document = json.loads(
        read_bytes(path), object_pairs_hook=pairs, parse_constant=constant
    )
    require(isinstance(document, dict), "evidence must be an object")
    return document


def verify_receipt(
    receipt: dict, report: Path, artifact: dict, mode: str, passed: bool
) -> None:
    require(receipt.get("mode") == mode, "receipt mode mismatch")
    require(receipt.get("artifact_verified") is True, "artifact was not verified")
    require(
        receipt.get("artifact_before") == artifact == receipt.get("artifact_after"),
        "wheel identity mismatch",
    )
    require(receipt.get("report_sha256") == digest(report), "report digest mismatch")
    require(
        receipt.get("bytecode_policy") == BYTECODE_POLICY,
        "receipt predates bytecode isolation",
    )
    require(
        receipt.get("passed") is passed
        and receipt.get("state") == ("passed" if passed else "failed"),
        "receipt result mismatch",
    )
    require(
        type(receipt.get("driver_exit_code")) is int
        and receipt["driver_exit_code"] == (0 if passed else 1),
        "driver exit mismatch",
    )
    driver_hash = hashlib.sha256(
        json.dumps(
            {p.name: digest(p) for p in sorted(Path(__file__).parent.glob("*.py"))},
            sort_keys=True,
        ).encode()
    ).hexdigest()
    require(
        receipt.get("driver_assets_sha256") == driver_hash,
        "validation drivers changed since receipt",
    )


def complete_coverage(coverage: dict) -> None:
    require(coverage.get("state") == "complete", "incomplete analysis coverage")
    count = coverage.get("expected_files")
    require(
        type(count) is int and count > 0 and coverage.get("analyzed_files") == count,
        "coverage inventory mismatch",
    )
    require(
        all(
            type(coverage.get(key)) is int and coverage[key] == 0
            for key in (
                "native_errors",
                "skipped_files",
                "missing_files",
                "unexpected_files",
                "invalid_paths",
            )
        ),
        "analysis coverage errors",
    )


def verify_benchmark(report: dict, baseline: dict, policy: dict) -> dict:
    require(report.get("measurement_complete") is True, "benchmark is incomplete")
    engines, rows = report["engines"], report["cases"]
    require(
        set(engines) == set(policy["required_engines"]) == set(baseline["engines"]),
        "benchmark engine mismatch",
    )
    require(
        len(rows) == report["upstream"]["cases"]
        and len({r["case"] for r in rows}) == len(rows),
        "benchmark case inventory mismatch",
    )
    for name in ("source_sha256", "labels_sha256"):
        require(report["upstream"][name] == baseline[name], "baseline corpus mismatch")
    totals = {}
    for engine in [*engines, "combined"]:
        observed = (
            report["combined_by_cwe"]
            if engine == "combined"
            else engines[engine]["by_cwe"]
        )
        counts = {
            cwe: dict.fromkeys(("tp", "fp", "fn", "tn"), 0) for cwe in policy["by_cwe"]
        }
        require(set(observed) == set(counts), "benchmark category mismatch")
        for row in rows:
            require(type(row["expected_positive"]) is bool, "invalid benchmark label")
            require(
                all(item["engine"] in engines for item in row["evidence"]),
                "unknown evidence engine",
            )
            detected = any(
                row["expected_cwe"] in item["cwes"]
                and (engine == "combined" or item["engine"] == engine)
                for item in row["evidence"]
            )
            outcome = (
                ("tp" if detected else "fn")
                if row["expected_positive"]
                else ("fp" if detected else "tn")
            )
            counts[row["expected_cwe"]][outcome] += 1
            if engine == "combined":
                require(
                    row["detected"] is detected and row["outcome"] == outcome,
                    "case outcome disagrees with native evidence",
                )
        for cwe, values in counts.items():
            require(
                all(
                    type(observed[cwe][key]) is int and observed[cwe][key] == value
                    for key, value in values.items()
                ),
                "aggregate counts disagree with case evidence",
            )
            for metric, numerator, denominator in (
                ("precision", values["tp"], values["tp"] + values["fp"]),
                ("recall", values["tp"], values["tp"] + values["fn"]),
                ("false_positive_rate", values["fp"], values["fp"] + values["tn"]),
            ):
                rate = numerator / denominator if denominator else None
                require(
                    observed[cwe][metric] == rate,
                    "aggregate rate disagrees with case evidence",
                )
            if engine != "combined":
                ceilings = baseline["engines"][engine][cwe]
                require(
                    all(
                        type(ceilings.get(key)) is int
                        and 0 <= values[key] <= ceilings[key]
                        for key in ("fp", "fn")
                    ),
                    "regression ceiling exceeded",
                )
        if engine == "combined":
            totals = {
                key: sum(v[key] for v in counts.values())
                for key in ("tp", "fp", "fn", "tn")
            }
        else:
            require(
                engines[engine]["status"] == "completed"
                and engines[engine].get("error") is None,
                "engine did not complete",
            )
            complete_coverage(engines[engine]["coverage"])
    require(
        not protected_detection_regressions(report, baseline),
        "protected detection lost",
    )
    require(
        report.get("regression_passed") is True and report.get("regressions") == [],
        "regression gate failed",
    )
    gate = accuracy_gate(report, policy)
    require(report["accuracy_gate"] == gate, "accuracy result disagrees with policy")
    return {
        "totals": totals,
        "by_cwe": report["combined_by_cwe"],
        "accuracy_passed": gate["passed"],
        "accuracy_failures": gate["failures"],
        "protected_detections": sum(
            len(names)
            for categories in baseline["protected_detections"].values()
            for names in categories.values()
        ),
    }


def verify_runtime(runtime: dict, benchmark: dict) -> None:
    require(
        runtime.get("passed") is True and runtime.get("state") == "passed",
        "runtime qualification did not pass",
    )
    profile, attempts, native = (
        runtime["profile"],
        runtime["attempts"],
        runtime["native_invocations"],
    )
    require(
        profile.get("bytecode_policy") == BYTECODE_POLICY,
        "runtime predates bytecode isolation",
    )
    require(
        type(runtime["repetitions"]) is int and 3 <= runtime["repetitions"] <= 5,
        "at least three runtime repetitions required",
    )
    require(
        len(attempts) == len(native) == runtime["repetitions"],
        "missing runtime repetitions",
    )
    require(runtime["stable_findings"] is True, "unstable runtime findings")
    checks = runtime["identity_checks"]
    require(
        len(checks) == 1 + 2 * runtime["repetitions"]
        and [check["stage"] for check in checks]
        == ["initial", *(["before-native", "after-native"] * runtime["repetitions"])]
        and all(check["complete"] is True for check in checks),
        "incomplete runtime identity checks",
    )
    expected = benchmark["engines"]["semgrep"]
    require(
        profile["rules_sha256"] == benchmark["rules_sha256"]
        and profile["launcher_sha256"] == expected["executable_sha256"],
        "runtime asset mismatch",
    )
    for index, (attempt, invocation) in enumerate(
        zip(attempts, native, strict=True), 1
    ):
        require(
            attempt["attempt"] == index
            and attempt["complete"] is True
            and attempt["unchanged_source"] is True,
            "incomplete runtime attempt",
        )
        require(
            attempt["source_sha256_before"]
            == attempt["source_sha256_after"]
            == attempts[0]["source_sha256_before"],
            "runtime source changed",
        )
        require(
            attempt["findings_sha256"] == attempts[0]["findings_sha256"]
            and attempt["version"] == attempts[0]["version"]
            and attempt["finding_count"] == expected["finding_count"],
            "runtime findings differ",
        )
        complete_coverage(attempt["coverage"])
        require(
            attempt["coverage"]["inventory_sha256"]
            == expected["coverage"]["inventory_sha256"],
            "runtime inventory differs from benchmark",
        )
        require(
            invocation["measurement_complete"] is True
            and invocation["exit_code"] == 0
            and invocation["timed_out"] is False,
            "incomplete native profiling",
        )


def verify_acceptance(report: dict, path: Path) -> None:
    require(
        report.get("passed") is True and report.get("state") == "passed",
        "acceptance did not pass",
    )
    require(
        len(report["cases"]) == len(SCENARIOS)
        and {row["scenario"] for row in report["cases"]} == SCENARIOS,
        "missing acceptance scenarios",
    )
    require(
        all(row["passed"] is True for row in report["cases"]),
        "acceptance scenario failed",
    )
    require(
        set(report["artifacts"]) == SCENARIOS, "missing retained acceptance evidence"
    )
    for records in report["artifacts"].values():
        require(bool(records), "empty retained evidence")
        for record in records:
            retained = path.parent / record["path"]
            require(
                not Path(record["path"]).is_absolute()
                and retained.resolve().is_relative_to(path.parent.resolve()),
                "retained evidence escapes report directory",
            )
            require(
                digest(retained) == record["sha256"]
                and retained.stat().st_size == record["bytes"],
                "retained evidence changed",
            )


def aggregate(args: argparse.Namespace) -> dict:
    names = (
        "native",
        "runtime",
        "benchmark",
        "benchmark_receipt",
        "acceptance",
        "acceptance_receipt",
        "baseline",
        "policy",
    )
    reports = {name: read_json(getattr(args, name)) for name in names}
    evidence_hashes = {name: digest(getattr(args, name)) for name in names}
    artifact = verify_wheel(args.wheel, ROOT / "src/py_security_suite")
    native, benchmark = reports["native"], reports["benchmark"]
    corpus = ROOT / "tests/fixtures/detection-regressions.json"
    require(
        native.get("passed") is True and native["corpus_sha256"] == digest(corpus),
        "native regression corpus changed or failed",
    )
    expected_cases = {
        case["id"]: case["positive"]
        for case in read_json(corpus)["cases"]
        if case["engine"] == "codeql"
    }
    cases = [row for row in native["cases"] if row["engine"] == "codeql"]
    require(
        len(cases) == len(expected_cases)
        and {row["case"] for row in cases} == set(expected_cases)
        and all(
            row["passed"] is True
            and row["path_trace_retained"] is True
            and row["expected_positive"] is expected_cases[row["case"]]
            and row["detected"] is row["expected_positive"]
            for row in cases
        ),
        "incomplete native regressions",
    )
    assets = ROOT / "src/py_security_suite/rules/codeql"
    require(
        native["codeql_assets"]
        == {
            path.name: digest(path)
            for path in sorted(assets.iterdir())
            if path.is_file() and path.suffix in {".ql", ".qll", ".yml"}
        },
        "native query assets changed",
    )
    gaps = ROOT / "tests/fixtures/detection-known-gaps.json"
    require(
        native["known_gap_corpus_sha256"] == digest(gaps), "known gap corpus changed"
    )
    require(
        native["proof_safety_query_sha256"]
        == digest(ROOT / "tests/fixtures/codeql-value-proof-safety.ql"),
        "proof safety query changed",
    )
    expected_gaps = {row["id"] for row in read_json(gaps)["cases"]}
    require(
        len(native["known_gap_proof_safety"]) == len(expected_gaps)
        and {row["case"] for row in native["known_gap_proof_safety"]} == expected_gaps
        and all(
            row["passed"] is True
            and row["detected"] is False
            and row["native_value_proof_rejected"] is True
            for row in native["known_gap_proof_safety"]
        ),
        "known gap proof check failed",
    )
    require(
        benchmark["accuracy_policy_sha256"] == evidence_hashes["policy"]
        and benchmark["baseline_sha256"] == evidence_hashes["baseline"],
        "benchmark policy or baseline changed",
    )
    measured = verify_benchmark(benchmark, reports["baseline"], reports["policy"])
    verify_receipt(
        reports["benchmark_receipt"],
        args.benchmark,
        artifact,
        "benchmark",
        measured["accuracy_passed"],
    )
    verify_acceptance(reports["acceptance"], args.acceptance)
    verify_receipt(
        reports["acceptance_receipt"], args.acceptance, artifact, "acceptance", True
    )
    verify_runtime(reports["runtime"], benchmark)
    for name in ("benchmark_receipt", "acceptance_receipt"):
        receipt = reports[name]
        directory = getattr(args, name).parent
        archive = directory / receipt["archived_report"]
        require(
            not Path(receipt["archived_report"]).is_absolute()
            and archive.resolve().is_relative_to(directory.resolve()),
            "receipt archive escapes evidence directory",
        )
        require(digest(archive) == receipt["report_sha256"], "archived report changed")
        require(
            read_json(archive.parent / "run.json") == receipt,
            "archived receipt differs from latest receipt",
        )
    require(
        evidence_hashes == {name: digest(getattr(args, name)) for name in names},
        "evidence changed during aggregation",
    )
    return {
        "schema_version": "1.0",
        "scope": "verified local evidence; not independent production approval",
        "evidence_verified": True,
        "passed": measured["accuracy_passed"],
        "artifact": artifact,
        "native_cases": len(cases),
        "known_gap_proof_checks": len(native["known_gap_proof_safety"]),
        "runtime_repetitions": reports["runtime"]["repetitions"],
        "acceptance_scenarios": len(SCENARIOS),
        "evidence_sha256": evidence_hashes,
        **measured,
    }


def markdown(report: dict) -> str:
    lines = [
        "# Verified local validation results",
        "",
        "Generated by `scripts/aggregate_validation.py`; do not edit the measurements by hand.",
        "",
        "These results do not establish independent production approval.",
        "",
        f"Wheel SHA-256: `{report['artifact']['wheel_sha256']}`.",
        "",
        f"Native regression cases: **{report['native_cases']} passing**. Installed acceptance: **{report['acceptance_scenarios']} passing**. Runtime qualification: **{report['runtime_repetitions']} complete repetitions**. Protected detections: **{report['protected_detections']} retained**.",
        "",
        f"Strict accuracy gate: **{'PASS' if report['accuracy_passed'] else 'FAIL'}**. Known gaps with proof rejection checks: **{report['known_gap_proof_checks']}**; these are not successful detections.",
        "",
        "| CWE | TP | FP | FN | TN | Precision | Recall |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for cwe, values in sorted(report["by_cwe"].items()):
        rates = [
            "—" if values[key] is None else f"{values[key]:.1%}"
            for key in ("precision", "recall")
        ]
        lines.append(
            f"| {cwe} | {values['tp']} | {values['fp']} | {values['fn']} | {values['tn']} | {' | '.join(rates)} |"
        )
    lines.extend(
        [
            "",
            "## Evidence identities",
            "",
            "These digests bind the supplied local records. They are not signatures.",
            "",
            "| Record | SHA-256 |",
            "| --- | --- |",
        ]
    )
    lines.extend(
        f"| {name} | `{value}` |"
        for name, value in sorted(report["evidence_sha256"].items())
    )
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in (
        "wheel",
        "native",
        "runtime",
        "benchmark",
        "benchmark-receipt",
        "acceptance",
        "acceptance-receipt",
        "baseline",
        "policy",
        "output",
    ):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--markdown", type=Path)
    args = parser.parse_args()
    inputs = {
        path.resolve()
        for name, path in vars(args).items()
        if name not in {"output", "markdown"} and isinstance(path, Path)
    }
    if args.output.resolve() in inputs or (
        args.markdown
        and (
            args.markdown.resolve() in inputs
            or args.markdown.resolve() == args.output.resolve()
        )
    ):
        parser.error("summary outputs must not overwrite evidence inputs or each other")
    try:
        report = aggregate(args)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        report = {
            "schema_version": "1.0",
            "evidence_verified": False,
            "passed": False,
            "error_category": type(exc).__name__,
        }
    atomic_json(args.output, report)
    if args.markdown:
        content = (
            markdown(report)
            if report["evidence_verified"]
            else "# Validation evidence rejected\n\nEvidence verification failed. No current measurements are approved for publication.\n"
        )
        atomic_bytes(args.markdown, content.encode("utf-8"))
    print(
        json.dumps(
            {
                "evidence_verified": report["evidence_verified"],
                "passed": report["passed"],
            }
        )
    )
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
