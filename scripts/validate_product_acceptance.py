"""Exercise an installed wheel through the public scan command, outside the checkout."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import tempfile
import sys
import atexit
import time
from pathlib import Path

if __name__ == "__main__":
    _cache = tempfile.TemporaryDirectory(prefix="")
    atexit.register(_cache.cleanup)
    sys.pycache_prefix = _cache.name
    sys.dont_write_bytecode = True

if __package__:
    from .isolated_python import isolated_python
    from .validation_evidence import ValidationEvidence
    from .acceptance_codeql import check_codeql_controls, write_codeql_controls
else:
    from isolated_python import isolated_python
    from validation_evidence import ValidationEvidence
    from acceptance_codeql import check_codeql_controls, write_codeql_controls


def invoke(
    python: str, arguments: list[str], cwd: Path, timeout: int = 2400
) -> subprocess.CompletedProcess[str]:
    with isolated_python(python, arguments) as command:
        return subprocess.run(  # noqa: S603 - pinned interpreter and fixed CLI vectors
            command,
            cwd=cwd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
        )


def _validate(args: argparse.Namespace, evidence: ValidationEvidence) -> dict:
    with tempfile.TemporaryDirectory(prefix="pysec-installed-acceptance-") as temporary:
        work = Path(temporary)
        info = evidence.invoke(
            "package-import",
            lambda: invoke(
                args.python,
                [
                    "-c",
                    "import json,py_security_suite; from importlib.resources import files; from py_security_suite.config import PROFILE_TOOLS; print(json.dumps({'module':py_security_suite.__file__,'rules':str(files('py_security_suite').joinpath('rules')),'tools':PROFILE_TOOLS['deep']}))",
                ],
                work,
            ),
        )
        if info.returncode:
            raise ValueError("installed package import failed")
        package = json.loads(info.stdout)
        if "site-packages" not in Path(package["module"]).parts:
            raise ValueError(
                "acceptance requires a wheel installation, not an editable source tree"
            )
        evidence.stage("fixture-preparation", package=package)
        rules = Path(package["rules"])
        for name in (
            "EnvironmentSecretToLog.ql",
            "ConstantChoice.qll",
            "ConstantPathProof.ql",
            "ConstantXpathProof.ql",
            "LdapFactoryFilter.ql",
            "FlaskRegistrationHtml.ql",
            "HtmlValueFacts.qll",
            "NativeValueFacts.qll",
            "qlpack.yml",
            "codeql-pack.lock.yml",
        ):
            if not (rules / "codeql" / name).is_file():
                raise ValueError("installed wheel is missing CodeQL query assets")
        source = work / "source"
        source.mkdir()
        (source / "app.py").write_text(
            'import logging, os\nfrom flask import request\nfrom helper import publish\ndef unsafe(cursor):\n    eval(input())\n    cursor.execute("SELECT * FROM users WHERE name=" + request.args.get("name"))\n    publish(os.getenv("AUTH_TOKEN"))\n',
            encoding="utf-8",
        )
        (source / "helper.py").write_text(
            "import logging\ndef publish(value):\n    logging.warning(value)\n",
            encoding="utf-8",
        )
        (source / "safe.py").write_text(
            'from flask import request\ndef safe(cursor):\n    cursor.execute("SELECT * FROM users WHERE name=%s", (request.args.get("name"),))\n',
            encoding="utf-8",
        )
        (source / "injection_unsafe.py").write_text(
            "import ldap3\nfrom flask import request\nfrom markupsafe import Markup\n"
            'def unsafe():\n    value = request.args.get("name")\n'
            '    conn = ldap3.Connection("host")\n    conn.search("base", value)\n'
            '    return Markup(request.args.get("html"))\n',
            encoding="utf-8",
        )
        (source / "injection_safe.py").write_text(
            "import ldap3\nfrom ldap3.utils.conv import escape_filter_chars\n"
            "from flask import request\nfrom markupsafe import Markup, escape\n"
            'def safe():\n    value = escape_filter_chars(request.args.get("name"))\n'
            '    conn = ldap3.Connection("host")\n    conn.search("base", value)\n'
            '    safe = escape(request.args.get("html"))\n'
            '    return Markup(safe + request.args.get("other"))\n',
            encoding="utf-8",
        )
        enabled = {"bandit": args.bandit, "semgrep": args.semgrep}
        (source / "path_safe.py").write_text(
            "from flask import request\nfrom werkzeug.utils import secure_filename\n"
            'def safe():\n    value = request.args.get("path")\n    limit = 11\n'
            '    chosen = "fixed" if 3 * 7 + limit > 30 else value\n'
            "    open(chosen)\n    cleaned = secure_filename(value)\n"
            '    paths = [str(item) for item in [cleaned]]\n    open("".join(paths))\n',
            encoding="utf-8",
        )
        (source / "path_unsafe.py").write_text(
            "from flask import request\ndef unsafe():\n"
            '    value = request.args.get("path")\n    limit = 8\n'
            '    chosen = "fixed" if 3 * 7 + limit > 30 else value\n'
            '    paths = [str(item) for item in [chosen]]\n    open("".join(paths))\n',
            encoding="utf-8",
        )
        for safe in (False, True):
            (
                source
                / ("crypto_cookie_safe.py" if safe else "crypto_cookie_unsafe.py")
            ).write_text(
                "import hashlib\nfrom flask import make_response\ndef handler():\n"
                f"    digest = hashlib.{'sha256' if safe else 'md5'}(b'payload').hexdigest()\n"
                "    response = make_response(digest)\n"
                f"    response.set_cookie('session', digest, secure={safe})\n"
                "    return response\n",
                encoding="utf-8",
            )
        if args.codeql:
            if not args.codeql_home or not args.codeql_runner:
                raise ValueError("CodeQL requires --codeql-home and --codeql-runner")
            enabled["codeql"] = args.codeql_runner
            write_codeql_controls(source)
            (source / "service.py").write_text(
                'import requests\ndef search(cursor, name):\n    cursor.execute("SELECT * FROM users WHERE name=" + name)\ndef fetch(url):\n    return requests.get(url)\ndef load(name):\n    return open(name).read()\n',
                encoding="utf-8",
            )
            (source / "routes.py").write_text(
                'import sqlite3\nfrom flask import Flask, request\nfrom service import search, fetch, load\napp = Flask(__name__)\n@app.get("/example")\ndef example():\n    cursor = sqlite3.connect(":memory:").cursor()\n    search(cursor, request.args.get("name"))\n    fetch(request.args.get("url"))\n    return load(request.args.get("path"))\n',
                encoding="utf-8",
            )
            (source / "xpath_routes.py").write_text(
                'from flask import Flask, request\nfrom lxml import etree\napp = Flask(__name__)\n@app.get("/xpath-unsafe")\ndef unsafe_xpath():\n    query = "/item/" + request.args.get("query")\n    return str(etree.XPath(query))\n@app.get("/xpath-constant")\ndef constant_xpath():\n    param = request.args.get("query")\n    num = 106\n    bar = "fixed" if 7 * 18 + num > 200 else param\n    query = f"/item/{bar}"\n    return str(etree.XPath(query))\n',
                encoding="utf-8",
            )
            for kind in ("path", "xpath"):
                for safe in (False, True):
                    # Both forms have native flow; only the unreachable RHS may
                    # be excluded, and incomplete extraction must retain it.
                    fixed, tainted = '"fixed"', "param"
                    body, otherwise = (fixed, tainted) if safe else (tainted, fixed)
                    sink = (
                        "open(bar).read()"
                        if kind == "path"
                        else "str(etree.XPath(bar))"
                    )
                    (
                        source / f"branch_{kind}_{'safe' if safe else 'unsafe'}.py"
                    ).write_text(
                        "from flask import Flask, request\nfrom lxml import etree\n"
                        'app = Flask(__name__)\n@app.get("/branch")\ndef route():\n'
                        '    param = request.args.get("input")\n    num = 86\n'
                        f"    if 7 * 42 - num > 200:\n        bar = {body}\n"
                        f"    else:\n        bar = {otherwise}\n    return {sink}\n",
                        encoding="utf-8",
                    )
        outcomes = []
        semgrep_identities = None
        for scenario in (
            "positive-and-negative",
            "identity-original",
            "relocated",
            "partial",
            "unavailable",
        ):
            evidence.stage(scenario + ":prepare", scenario=scenario)
            started = time.monotonic()
            selected = enabled if scenario != "partial" else {"bandit": args.bandit}
            scan_source = source
            if scenario == "identity-original":
                selected = {"semgrep": args.semgrep}
            if scenario == "relocated":
                selected = {"semgrep": args.semgrep}
                scan_source = work / "relocated-source"
                shutil.copytree(source, scan_source)
            if scenario == "partial" and args.codeql:
                selected["codeql"] = args.codeql_runner
            if scenario == "unavailable":
                selected = {"bandit": str(work / "missing-bandit")}
            if scenario == "partial":
                (source / "broken.py").write_text(
                    "def invalid(:\n    pass\n", encoding="utf-8"
                )
            config = work / f"{scenario}.toml"
            content = [
                'schema_version = "1"',
                'profile = "deep"',
                "[policy]",
                "required_scanners = " + json.dumps(list(selected)),
            ]
            for tool in package["tools"]:
                content += [
                    f"[tools.{json.dumps(tool)}]",
                    f"enabled = {str(tool in selected).lower()}",
                ]
                if tool in selected:
                    content += [
                        "executable = "
                        + json.dumps(str(Path(selected[tool]).resolve()))
                    ]
                if tool == "codeql" and tool in selected:
                    content += [
                        "auxiliary_executable = "
                        + json.dumps(str(Path(args.codeql).resolve())),
                        "database_path = "
                        + json.dumps(str(Path(args.codeql_home).resolve())),
                    ]
            config.write_text("\n".join(content) + "\n", encoding="utf-8")
            report = work / scenario
            scan = evidence.invoke(
                scenario + ":scan",
                lambda scan_source=scan_source, config=config, report=report: invoke(
                    args.python,
                    [
                        "-m",
                        "py_security_suite",
                        "scan",
                        str(scan_source),
                        "--config",
                        str(config),
                        "--output",
                        str(report),
                        "--diagnostic-without-isolation",
                        "--progress",
                        "none",
                    ],
                    work,
                ),
            )
            evidence.stage(scenario + ":retain-report")
            evidence.retain_report(report, scenario, list(selected))
            evidence.stage(scenario + ":assertions")
            if not (report / "scan-manifest.json").is_file():
                raise ValueError("scan did not publish a report")
            manifest = json.loads(
                (report / "scan-manifest.json").read_text(encoding="utf-8")
            )
            findings = json.loads(
                (report / "findings.json").read_text(encoding="utf-8")
            )["findings"]
            observed = {
                item["rule_id"] for finding in findings for item in finding["sources"]
            }
            required = ({"B307"} if "bandit" in selected else set()) | (
                {"python.request-to-sql"} if "semgrep" in selected else set()
            )
            if scenario in {"identity-original", "relocated"}:
                identities = sorted(
                    (item["rule_id"], finding["finding_id"], finding["fingerprint"])
                    for finding in findings
                    for item in finding["sources"]
                    if item["tool"] == "semgrep"
                )
                if scenario == "relocated" and identities != semgrep_identities:
                    raise ValueError(
                        "installed finding identities changed after source relocation"
                    )
                semgrep_identities = identities
            if scenario == "unavailable":
                required = set()
            if "semgrep" in selected:
                injection_rules = {
                    "python.request-to-ldap": "CWE-90",
                    "python.request-to-unsafe-html": "CWE-79",
                }
                required.update(injection_rules)
                for finding in findings:
                    matched = {
                        item["rule_id"]
                        for item in finding["sources"]
                        if item["tool"] == "semgrep"
                    } & injection_rules.keys()
                    if matched and any(
                        loc["path"] == "injection_safe.py"
                        for loc in finding["locations"]
                    ):
                        raise ValueError(
                            "safe injection control produced a false positive: "
                            + ", ".join(sorted(matched))
                        )
                    if any(
                        injection_rules[rule] not in finding["classifications"]
                        for rule in matched
                    ):
                        raise ValueError(
                            "injection finding lost its CWE classification"
                        )
                required.update(
                    {
                        "python.weak-cryptographic-hash",
                        "python.response-cookie-insecure",
                    }
                )
                for finding in findings:
                    new_rules = {item["rule_id"] for item in finding["sources"]} & {
                        "python.weak-cryptographic-hash",
                        "python.response-cookie-insecure",
                    }
                    if new_rules and any(
                        loc["path"] == "crypto_cookie_safe.py"
                        for loc in finding["locations"]
                    ):
                        raise ValueError(
                            "secure hash/cookie negative control produced a false positive"
                        )
                    for rule in new_rules:
                        expected_cwe = (
                            "CWE-328"
                            if rule == "python.weak-cryptographic-hash"
                            else "CWE-614"
                        )
                        if expected_cwe not in {
                            value.partition(":")[0].strip()
                            for value in finding["classifications"]
                        }:
                            raise ValueError(
                                "new detector lost its precise CWE classification"
                            )
            if "codeql" in selected:
                required.update(
                    {
                        "pysec/environment-secret-to-log",
                        "pysec/ldap-factory-filter-injection",
                        "py/sql-injection",
                        "py/full-ssrf",
                        "py/path-injection",
                        "py/xpath-injection",
                    }
                )
                for rule in {
                    name for name in required if name.startswith(("py/", "pysec/"))
                }:
                    matches = [
                        finding
                        for finding in findings
                        if any(item["rule_id"] == rule for item in finding["sources"])
                    ]
                    if not matches or not all(
                        finding.get("evidence", {}).get("sarif_code_flows")
                        for finding in matches
                    ):
                        raise ValueError("CodeQL finding lost its path trace: " + rule)
                    if any(
                        location["path"].startswith("<")
                        for finding in matches
                        for location in finding["locations"]
                    ):
                        raise ValueError(
                            "CodeQL finding lost its source location: " + rule
                        )
                    if rule in {
                        "py/sql-injection",
                        "py/full-ssrf",
                        "py/path-injection",
                    } and not any(
                        all(
                            name in json.dumps(finding["evidence"]["sarif_code_flows"])
                            for name in ("routes.py", "service.py")
                        )
                        for finding in matches
                    ):
                        raise ValueError(
                            "CodeQL path did not cross the service boundary: " + rule
                        )
            if not required <= observed:
                raise ValueError(
                    "installed scan missed required findings: "
                    + str(sorted(required - observed))
                )
            if "semgrep" in selected:
                path_locations = {
                    location["path"]
                    for finding in findings
                    if any(
                        item["rule_id"] == "python.request-to-path"
                        for item in finding["sources"]
                    )
                    for location in finding["locations"]
                }
                if (
                    "path_unsafe.py" not in path_locations
                    or "path_safe.py" in path_locations
                ):
                    raise ValueError(
                        "installed path precision/propagation controls failed"
                    )
            if "codeql" in selected:
                for kind, rule in (
                    ("path", "py/path-injection"),
                    ("xpath", "py/xpath-injection"),
                ):
                    locations = {
                        loc["path"]
                        for finding in findings
                        if any(item["rule_id"] == rule for item in finding["sources"])
                        for loc in finding["locations"]
                    }
                    if f"branch_{kind}_unsafe.py" not in locations:
                        raise ValueError(
                            f"live branch {kind} positive control was lost"
                        )
                    if (f"branch_{kind}_safe.py" in locations) != (
                        scenario == "partial"
                    ):
                        raise ValueError(
                            f"branch {kind} refinement did not respect extraction coverage"
                        )
                xpath = [
                    finding
                    for finding in findings
                    if any(
                        item["rule_id"] == "py/xpath-injection"
                        for item in finding["sources"]
                    )
                ]
                if not any(
                    any(
                        loc["path"] == "xpath_routes.py" and loc["start_line"] == 7
                        for loc in finding["locations"]
                    )
                    for finding in xpath
                ):
                    raise ValueError("tainted XPath positive control was lost")
                for finding in xpath:
                    if any(
                        loc["path"] == "xpath_routes.py" and loc["start_line"] == 14
                        for loc in finding["locations"]
                    ):
                        if scenario != "partial":
                            raise ValueError(
                                "constant XPath false positive was not refined"
                            )
                        if (
                            not finding.get("evidence", {})
                            .get("constant_sink_review", {})
                            .get("native_finding_retained")
                        ):
                            raise ValueError(
                                "constant XPath alert lost its review evidence"
                            )
            if any(
                item["rule_id"] == "python.request-to-sql"
                and any(loc["path"] == "safe.py" for loc in finding["locations"])
                for finding in findings
                for item in finding["sources"]
            ):
                raise ValueError(
                    "parameterized SQL negative control produced a false positive"
                )
            diagnostics = {
                tool: json.loads(
                    (report / "evidence" / f"{tool}.json").read_text(encoding="utf-8")
                )
                for tool in selected
            }
            if "codeql" in selected:
                check_codeql_controls(
                    findings, diagnostics["codeql"], partial=scenario == "partial"
                )
                refinement = diagnostics["codeql"].get("native_flow_refinement", {})
                exclusions = refinement.get("exclusions", [])
                if scenario != "partial":
                    for kind in ("path", "xpath"):
                        if not any(
                            item["native_proof"]["ruleId"]
                            == f"pysec/constant-{kind}-proof"
                            and item["original_finding"]["evidence"].get(
                                "sarif_code_flows"
                            )
                            and any(
                                loc["path"] == f"branch_{kind}_safe.py"
                                for loc in item["original_finding"]["locations"]
                            )
                            for item in exclusions
                        ):
                            raise ValueError(
                                f"branch {kind} exclusion lost original alert or native proof"
                            )
                if scenario == "partial":
                    if exclusions or refinement.get("excluded_count"):
                        raise ValueError(
                            "incomplete extraction excluded a native alert"
                        )
                elif not any(
                    any(
                        source["rule_id"] == "py/xpath-injection"
                        for source in item["original_finding"]["sources"]
                    )
                    and item["original_finding"]["evidence"].get("sarif_code_flows")
                    and item["native_proof"]["ruleId"] == "pysec/constant-xpath-proof"
                    for item in exclusions
                ):
                    raise ValueError(
                        "installed report lost original XPath alert and native proof"
                    )
            for tool, diagnostic in diagnostics.items():
                wanted = {"partial": "parse_error", "unavailable": "unavailable"}.get(
                    scenario, "completed"
                )
                if diagnostic["status"] != wanted:
                    raise ValueError(
                        f"{scenario}: {tool} status {diagnostic['status']}: {diagnostic.get('error')}"
                    )
                if scenario != "unavailable" and tool in {
                    "bandit",
                    "semgrep",
                    "codeql",
                }:
                    state = "partial" if scenario == "partial" else "complete"
                    if diagnostic["analysis_coverage"]["state"] != state:
                        raise ValueError(
                            f"{tool} inventory reconciliation did not report {state}"
                        )
            # Functional acceptance must never turn a diagnostic scan into release approval.
            if (
                not manifest["diagnostic_without_isolation"]
                or manifest["outcome"] != "incomplete"
            ):
                raise ValueError(
                    "diagnostic scan incorrectly represented release eligibility"
                )
            verification = evidence.invoke(
                scenario + ":integrity",
                lambda report=report: invoke(
                    args.python,
                    [
                        "-c",
                        "import sys; from pathlib import Path; from py_security_suite.passport import verify_report; verify_report(Path(sys.argv[1]))",
                        str(report),
                    ],
                    work,
                ),
            )
            if verification.returncode:
                raise ValueError("installed report integrity verification failed")
            outcomes.append(
                {
                    "scenario": scenario,
                    "duration_seconds": round(time.monotonic() - started, 3),
                    "passed": True,
                    "scan_exit_code": scan.returncode,
                    "rules": sorted(required),
                    "diagnostics": diagnostics,
                    "manifest_sha256": hashlib.sha256(
                        (report / "scan-manifest.json").read_bytes()
                    ).hexdigest(),
                }
            )
            evidence.complete_case(outcomes[-1])
        return {
            "schema_version": "1.1",
            "scope": "installed product functional acceptance; not production approval",
            "package": package,
            "cases": outcomes,
            "passed": True,
        }


def validate(args: argparse.Namespace) -> dict:
    evidence = ValidationEvidence(
        args.output, "installed product functional acceptance; not production approval"
    )
    try:
        return evidence.finish(_validate(args, evidence))
    except (ValueError, OSError, KeyError, TypeError, subprocess.TimeoutExpired) as exc:
        return evidence.fail(exc)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("python", "bandit", "semgrep"):
        parser.add_argument("--" + name, required=True)
    for name in ("codeql", "codeql-home", "codeql-runner"):
        parser.add_argument("--" + name)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    # A POSIX venv interpreter is a symlink; resolving it selects the base
    # interpreter and loses the installed candidate's site-packages.
    args.python = str(Path(args.python).absolute())
    result = validate(args)
    print(
        json.dumps(
            {
                "passed": result["passed"],
                "error_category": result.get("error_category"),
                "failed_stage": result.get("failed_stage"),
                "output": str(args.output),
            }
        )
    )
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
