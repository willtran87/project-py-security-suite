"""Run real detectors against positive and negative security regression cases."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
from functools import partial as bind_call
from pathlib import Path
from typing import Any

from py_security_suite.adapters.bandit import BanditAdapter
from py_security_suite.adapters.codeql_queries import locked_pack_paths
from py_security_suite.adapters.codeql_refinement import refine_native_results
from py_security_suite.adapters.semgrep import SEMGREP_JOBS
from py_security_suite.execution import run_command
from py_security_suite.config import ToolConfig
from py_security_suite.models import ToolStatus

if __package__:
    from .validation_evidence import ValidationEvidence, output_identity
    from .detection_identity import validate_semgrep_identity
    from .detection_stability import repeated_semgrep
else:
    from validation_evidence import ValidationEvidence, output_identity
    from detection_identity import validate_semgrep_identity
    from detection_stability import repeated_semgrep


ROOT = Path(__file__).resolve().parents[1]
RULES = ROOT / "src/py_security_suite/rules/python-security.yml"
CORPUS = ROOT / "tests/fixtures/detection-regressions.json"
KNOWN_GAPS = ROOT / "tests/fixtures/detection-known-gaps.json"
SAFETY_QUERY = ROOT / "tests/fixtures/codeql-value-proof-safety.ql"
CATEGORIES = {
    "CWE-532": "sensitive-data-to-log",
    "CWE-89": "request-to-sql",
    "CWE-918": "request-to-ssrf",
    "CWE-22": "request-to-path",
    "CWE-328": "weak-cryptographic-hash",
    "CWE-614": "response-cookie-insecure",
    "CWE-79": "request-to-unsafe-html",
    "CWE-90": "request-to-ldap",
}


def run(
    command: list[str],
    cwd: Path,
    *,
    timeout: int = 180,
    json_output: bool = False,
    evidence: ValidationEvidence | None = None,
) -> dict[str, Any]:
    if evidence:
        evidence.stage("native-command")
    result = run_command(
        command,
        cwd=cwd,
        timeout_seconds=timeout,
        max_output_bytes=8 * 1024**2,
    )
    if evidence:
        evidence.document["commands"].append(
            {
                "exit_code": result.exit_code,
                "timed_out": result.timed_out,
                "stop_reason": result.stop_reason,
                "stdout": output_identity(result.stdout),
                "stderr": output_identity(result.stderr),
            }
        )
        evidence.save()
    if (
        result.exit_code
        or result.timed_out
        or result.stop_reason
        or result.output_limit_exceeded
    ):
        raise ValueError(
            f"detector exited with code {result.exit_code}: {result.stderr[-2000:]}"
        )
    return json.loads(result.stdout) if json_output else {}


def evaluate(
    cases: list[dict[str, Any]], results: list[dict[str, Any]], engine: str
) -> list[dict[str, Any]]:
    outcomes = []
    for case in cases:
        selected = []
        forbidden = []
        for result in results:
            if engine == "semgrep":
                path, rule = str(result["path"]), str(result["check_id"])
            else:
                path = str(
                    result["locations"][0]["physicalLocation"]["artifactLocation"][
                        "uri"
                    ]
                )
                rule = str(result["ruleId"])
            if case["id"].replace("-", "_") not in Path(path.replace("\\", "/")).parts:
                continue
            if rule in case.get("forbidden_rule_ids", []):
                forbidden.append(rule)
            if (
                engine == "semgrep" and rule.endswith(CATEGORIES[case["category"]])
            ) or (
                engine == "codeql"
                and rule
                in case.get(
                    "rule_ids", [case.get("rule_id", "pysec/environment-secret-to-log")]
                )
            ):
                selected.append(result)
        observed = bool(selected)
        trace = (
            engine != "codeql"
            or not observed
            or all(item.get("codeFlows") for item in selected)
        )
        outcomes.append(
            {
                "case": case["id"],
                "engine": engine,
                "category": case["category"],
                "expected_positive": case["positive"],
                "detected": observed,
                "passed": observed == case["positive"] and trace and not forbidden,
                "path_trace_retained": trace,
                "forbidden_rule_ids_observed": sorted(set(forbidden)),
            }
        )
    return outcomes


def evaluate_proof_rejections(cases: list[dict], results: list[dict]) -> list[dict]:
    """Check that value refinement leaves known upstream misses untouched."""
    checks = []
    rules = {
        "CWE-22": {"py/path-injection"},
        "CWE-643": {"py/xpath-injection"},
        "CWE-90": {"py/ldap-injection", "pysec/ldap-factory-filter-injection"},
    }
    for case in cases:
        observed = {
            item["ruleId"]
            for item in results
            if case["id"].replace("-", "_")
            in Path(
                item["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            ).parts
        }
        proof = "pysec/value-proof-safety-probe" in observed
        detected = bool(observed & rules[case["category"]])
        checks.append(
            {
                "case": case["id"],
                "category": case["category"],
                "expected_positive": case["positive"],
                "detected": detected,
                "native_value_proof_rejected": not proof,
                "scope": "precision safety only; known upstream detection gap",
                # A newly detected case must be promoted to the detection regression gate.
                "passed": not proof and not detected,
            }
        )
    return checks


def metrics(outcomes: list[dict[str, Any]]) -> dict[str, Any]:
    categories = {}
    for category in sorted({row["category"] for row in outcomes}):
        rows = [row for row in outcomes if row["category"] == category]
        tp = sum(row["detected"] and row["expected_positive"] for row in rows)
        fn = sum(not row["detected"] and row["expected_positive"] for row in rows)
        fp = sum(row["detected"] and not row["expected_positive"] for row in rows)
        tn = sum(not row["detected"] and not row["expected_positive"] for row in rows)
        categories[category] = {
            "tp": tp,
            "fn": fn,
            "fp": fp,
            "tn": tn,
            "recall": tp / (tp + fn) if tp + fn else None,
            "precision": tp / (tp + fp) if tp + fp else None,
        }
    return categories


def validate(args: argparse.Namespace) -> dict[str, Any]:
    evidence = getattr(args, "evidence", None)
    execute = bind_call(run, evidence=evidence)
    corpus = json.loads(CORPUS.read_text(encoding="utf-8"))
    engines = {"codeql"} if args.codeql_only else {"semgrep"}
    if args.codeql:
        engines.add("codeql")
    cases = [case for case in corpus["cases"] if case["engine"] in engines]
    gap_cases = (
        json.loads(KNOWN_GAPS.read_text(encoding="utf-8"))["cases"]
        if "codeql" in engines
        else []
    )
    proof_rejections = []
    outcomes = []
    versions = {}
    coverage_probe = None
    identity_acceptance = None
    stability = None
    with tempfile.TemporaryDirectory(
        prefix="pysec-detection-gate-", ignore_cleanup_errors=True
    ) as temporary:
        work = Path(temporary)
        source = work / "source"
        source.mkdir()
        for case in [*cases, *gap_cases]:
            name = case["id"].replace("-", "_")
            directory = source / name
            directory.mkdir()
            if not case.get("namespace_package"):
                (directory / "__init__.py").write_text("", encoding="utf-8")
            for filename, text in case["files"].items():
                path = directory / filename
                if not path.resolve().is_relative_to(directory):
                    raise ValueError("unsafe fixture filename")
                path.write_text(
                    text.replace("from helper import", f"from {name}.helper import"),
                    encoding="utf-8",
                )
        if "semgrep" in engines:
            identity_acceptance = validate_semgrep_identity(args.semgrep, RULES)
            command = [
                args.semgrep,
                "scan",
                "--config",
                str(RULES),
                "--json",
                "--metrics=off",
                "--disable-version-check",
                "--strict",
                f"--jobs={SEMGREP_JOBS}",
                "--no-git-ignore",
                str(source),
            ]
            document, stability = repeated_semgrep(
                lambda: execute(command, source, json_output=True),
                source,
                getattr(args, "semgrep_repetitions", 3),
            )
            versions["semgrep"] = document.get("version", "unknown")
            outcomes.extend(
                evaluate(
                    [case for case in cases if case["engine"] == "semgrep"],
                    document.get("results", []),
                    "semgrep",
                )
            )
            if evidence:
                evidence.stage(
                    "semgrep:completed", cases=outcomes, semgrep_stability=stability
                )
            broken = work / "broken"
            broken.mkdir()
            (broken / "bad.py").write_text(
                "def invalid(:\n    pass\n", encoding="utf-8"
            )
            document = execute(
                [args.bandit, "-r", str(broken), "-q", "-f", "json"],
                broken,
                json_output=True,
            )
            adapter = BanditAdapter(ToolConfig(), 1024**2)
            coverage_probe = adapter.analysis_coverage(json.dumps(document))
            if coverage_probe["native_errors"] != 1:
                raise ValueError("Bandit parsing failure was not retained")
            (broken / "good.py").write_text(
                'import logging, os\ndef example():\n    eval(input())\n    logging.info("value=%s", os.getenv("AUTH_TOKEN"))\n',
                encoding="utf-8",
            )
            for name, detector in (
                ("bandit", BanditAdapter(ToolConfig(executable=args.bandit), 1024**2)),
            ):
                partial = detector.run(broken)
                if (
                    partial.tool_run.status != ToolStatus.PARSE_ERROR
                    or not partial.findings
                ):
                    raise ValueError(
                        f"{name} did not retain findings with incomplete analysis"
                    )
        if "codeql" in engines:
            database, report = work / "database", work / "codeql.sarif"
            versions["codeql"] = execute(
                [args.codeql, "version", "--format=json"], work, json_output=True
            )
            execute(
                [
                    args.codeql,
                    "database",
                    "create",
                    str(database),
                    "--language=python",
                    f"--source-root={source}",
                    "--no-run-unnecessary-builds",
                    "--threads=2",
                    "--quiet",
                ],
                work,
                timeout=300,
            )
            supplemental = work / "supplemental.sarif"
            query_copy = work / "queries"
            query_copy.mkdir()
            for path in (RULES.parent / "codeql").iterdir():
                if path.is_file() and path.suffix in {".ql", ".qll", ".yml"}:
                    (query_copy / path.name).write_bytes(path.read_bytes())
            (query_copy / "ValueProofSafety.ql").write_bytes(SAFETY_QUERY.read_bytes())
            query_root = Path.home() / ".codeql/packages/codeql/python-queries/1.8.7"
            for queries, output in (
                (
                    [
                        str(query_root / "Security/CWE-022/PathInjection.ql"),
                        str(query_root / "Security/CWE-643/XpathInjection.ql"),
                        str(query_root / "Security/CWE-090/LdapInjection.ql"),
                        str(query_root / "Security/CWE-079/ReflectedXss.ql"),
                    ],
                    report,
                ),
                ([str(query_copy)], supplemental),
            ):
                execute(
                    [
                        args.codeql,
                        "database",
                        "analyze",
                        str(database),
                        *queries,
                        "--rerun",
                        "--format=sarif-latest",
                        f"--output={output}",
                        "--additional-packs="
                        + os.pathsep.join(
                            map(
                                str,
                                locked_pack_paths(RULES.parent / "codeql", Path.home()),
                            )
                        ),
                        "--threads=2",
                        "--ram=4096",
                        "--quiet",
                    ],
                    work,
                    timeout=1200,
                )
            refined, extra, native_refinement = refine_native_results(
                report.read_text(encoding="utf-8"),
                supplemental.read_text(encoding="utf-8"),
                eligible=True,
            )
            results = [
                item
                for payload in (refined, extra)
                for run_result in json.loads(payload)["runs"]
                for item in run_result.get("results", [])
            ]
            outcomes.extend(
                evaluate(
                    [case for case in cases if case["engine"] == "codeql"],
                    results,
                    "codeql",
                )
            )
            proof_rejections = evaluate_proof_rejections(gap_cases, results)
            if any(case.get("require_native_proof") for case in cases):
                proof_paths = {
                    proof["native_proof"]["locations"][0]["physicalLocation"][
                        "artifactLocation"
                    ]["uri"]
                    for proof in native_refinement["exclusions"]
                }
                for outcome in outcomes:
                    case = next(case for case in cases if case["id"] == outcome["case"])
                    if case.get("require_native_proof"):
                        present = any(
                            case["id"].replace("-", "_") in Path(path).parts
                            for path in proof_paths
                        )
                        outcome["native_proof_retained"] = present
                        outcome["passed"] = outcome["passed"] and present
    return {
        "schema_version": "1.0",
        "scope": corpus["scope"],
        "corpus_sha256": hashlib.sha256(CORPUS.read_bytes()).hexdigest(),
        "rules_sha256": hashlib.sha256(RULES.read_bytes()).hexdigest(),
        "codeql_query_sha256": hashlib.sha256(
            (RULES.parent / "codeql/EnvironmentSecretToLog.ql").read_bytes()
        ).hexdigest(),
        "codeql_lock_sha256": hashlib.sha256(
            (RULES.parent / "codeql/codeql-pack.lock.yml").read_bytes()
        ).hexdigest(),
        "codeql_precision_assets": {
            path.name: hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted((RULES.parent / "codeql").glob("Constant*"))
        },
        "codeql_assets": {
            path.name: hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted((RULES.parent / "codeql").iterdir())
            if path.is_file() and path.suffix in {".ql", ".qll", ".yml"}
        },
        "versions": versions,
        "cases": outcomes,
        "known_gap_proof_safety": proof_rejections,
        "known_gap_corpus_sha256": hashlib.sha256(KNOWN_GAPS.read_bytes()).hexdigest(),
        "proof_safety_query_sha256": hashlib.sha256(
            SAFETY_QUERY.read_bytes()
        ).hexdigest(),
        "by_cwe": metrics(outcomes),
        "bandit_coverage_probe": coverage_probe,
        "identity_acceptance": identity_acceptance,
        "semgrep_stability": stability,
        "passed": bool(outcomes)
        and all(row["passed"] for row in outcomes)
        and all(row["passed"] for row in proof_rejections)
        and (stability is None or stability["passed"]),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--semgrep", default="semgrep")
    parser.add_argument("--bandit", default="bandit")
    parser.add_argument("--codeql")
    parser.add_argument("--codeql-only", action="store_true")
    parser.add_argument(
        "--semgrep-repetitions",
        type=int,
        choices=range(1, 6),
        default=3,
        help="Fixed number of Semgrep attempts; every attempt must complete",
    )
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.codeql_only and not args.codeql:
        parser.error("--codeql-only requires --codeql")
    args.evidence = ValidationEvidence(
        args.output, "native developer regression validation"
    )
    try:
        report = args.evidence.finish(validate(args))
    except (ValueError, RuntimeError, OSError) as exc:
        report = args.evidence.fail(exc)
    print(json.dumps(report, indent=2))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
