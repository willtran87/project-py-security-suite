from __future__ import annotations

import argparse
import hashlib
import math
import re
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator  # type: ignore[import-untyped]

try:
    from companion.strict_json import canonical_bytes
    from companion.strict_json import dumps as strict_dumps
    from companion.strict_json import loads as strict_loads
    from companion.deep_qualification import verify_area_receipt
    from companion.evidence_authority import verify_authority_quorum
except ModuleNotFoundError:  # Direct script execution.
    from strict_json import canonical_bytes  # type: ignore[import-not-found,no-redef]
    from strict_json import dumps as strict_dumps  # type: ignore[import-not-found,no-redef]
    from strict_json import loads as strict_loads  # type: ignore[import-not-found,no-redef]
    from deep_qualification import verify_area_receipt  # type: ignore[import-not-found,no-redef]
    from evidence_authority import verify_authority_quorum  # type: ignore[import-not-found,no-redef]


_MAX_INPUT_BYTES = 64 * 1024 * 1024


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Normalize bounded native-tool output for assurance_manifest.py."
    )
    parser.add_argument(
        "--tool",
        choices=(
            "clusterfuzzlite",
            "cargo-audit",
            "datadog-iast",
            "brakeman-sarif",
            "detekt-sarif",
            "eslint-sarif",
            "falco",
            "fuzz-introspector",
            "gosec",
            "govulncheck-sarif",
            "kubescape",
            "mobsf",
            "native-sanitizers",
            "npm-audit",
            "nuclei",
            "oast",
            "polyglot",
            "prowler",
            "rasp",
            "restler",
            "secret-verification",
            "spotbugs-sarif",
            "testssl",
            "zap",
        ),
        required=True,
    )
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--sarif-schema", type=Path)
    parser.add_argument("--sarif-schema-sha256", default="")
    parser.add_argument("--process-exit-code", type=int)
    parser.add_argument("--qualification-manifest", type=Path)
    parser.add_argument("--qualification-manifest-sha256", default="")
    args = parser.parse_args(argv)
    payload = _read(args.input)
    if args.tool.endswith("-sarif"):
        if (
            args.sarif_schema is None
            or not args.sarif_schema_sha256
            or args.process_exit_code != 0
            or args.qualification_manifest is None
            or not args.qualification_manifest_sha256
        ):
            raise ValueError(
                "SARIF normalization requires a pinned schema, successful process exit, and qualification manifest"
            )
        _validate_sarif_schema(
            payload, args.tool, args.sarif_schema, args.sarif_schema_sha256
        )
        verify_area_receipt(
            args.qualification_manifest,
            area="sarif",
            filename=args.qualification_manifest.name,
            sha256=args.qualification_manifest_sha256,
            target=payload,
        )
    normalizer = {
        "datadog-iast": _datadog_iast,
        "falco": _falco,
        "nuclei": _nuclei,
        "prowler": _prowler,
        "zap": _zap,
        "restler": _restler,
        "oast": _oast,
        "secret-verification": _secret_verification,
        "cargo-audit": lambda value: _polyglot_findings(value, "cargo-audit"),
        "gosec": lambda value: _polyglot_findings(value, "gosec"),
        "npm-audit": lambda value: _polyglot_findings(value, "npm-audit"),
        "brakeman-sarif": lambda value: _sarif_findings(value, "brakeman-sarif"),
        "detekt-sarif": lambda value: _sarif_findings(value, "detekt-sarif"),
        "eslint-sarif": lambda value: _sarif_findings(value, "eslint-sarif"),
        "govulncheck-sarif": lambda value: _sarif_findings(value, "govulncheck-sarif"),
        "spotbugs-sarif": lambda value: _sarif_findings(value, "spotbugs-sarif"),
    }.get(args.tool)
    findings = (
        normalizer(payload) if normalizer else _receipt_findings(payload, args.tool)
    )
    execution = _execution(payload, args.tool, findings, context=args.input)
    _write(args.output, {"execution": execution, "findings": findings})
    return 0


def _read(path: Path) -> object:
    if path.is_symlink() or not path.is_file():
        raise ValueError("native tool output is not a regular file")
    if path.stat().st_size > _MAX_INPUT_BYTES:
        raise ValueError("native tool output exceeds 64 MiB")
    text = path.read_text(encoding="utf-8", errors="strict")
    try:
        return strict_loads(text)
    except (TypeError, ValueError):
        records: list[object] = []
        for line_number, line in enumerate(text.splitlines(), start=1):
            if not line.strip():
                continue
            try:
                records.append(strict_loads(line))
            except (TypeError, ValueError) as exc:
                raise ValueError(
                    f"native tool JSONL is invalid at line {line_number}"
                ) from exc
        return records


def _nuclei(payload: object) -> list[dict[str, Any]]:
    records = payload if isinstance(payload, list) else [payload]
    findings: list[dict[str, Any]] = []
    for value in records:
        if not isinstance(value, dict):
            raise TypeError("Nuclei records must be objects")
        info = value.get("info")
        if not isinstance(info, dict):
            info = {}
        template_id = _text(value.get("template-id") or value.get("templateID"), 160)
        if not template_id:
            raise ValueError("Nuclei record is missing template-id")
        if template_id == "pysec-loopback-health-canary":
            continue
        findings.append(
            _finding(
                rule_id=template_id,
                title=_text(info.get("name"), 300) or template_id,
                message="A locally approved Nuclei template matched the authorized target.",
                severity=_severity(info.get("severity")),
                classification=_classification(info.get("classification"), template_id),
                citation=_https(info.get("reference")),
                area="independent-dynamic-application-security-testing",
                evidence={
                    "matcher": _text(value.get("matcher-name"), 160),
                    "protocol": _text(value.get("type"), 80),
                },
            )
        )
    return findings


def _datadog_iast(payload: object) -> list[dict[str, Any]]:
    if not isinstance(payload, dict):
        raise TypeError("Datadog IAST export root must be an object")
    records = payload.get("vulnerabilities") or payload.get("data")
    if not isinstance(records, list):
        raise TypeError("Datadog IAST export requires a vulnerabilities array")
    findings: list[dict[str, Any]] = []
    cwes = {
        "SQL_INJECTION": "CWE-89",
        "COMMAND_INJECTION": "CWE-78",
        "PATH_TRAVERSAL": "CWE-22",
        "SSRF": "CWE-918",
        "WEAK_HASH": "CWE-328",
        "WEAK_CIPHER": "CWE-327",
    }
    for value in records:
        if not isinstance(value, dict):
            raise TypeError("Datadog IAST vulnerabilities must be objects")
        rule_id = _text(value.get("type") or value.get("rule_id"), 160)
        if not rule_id:
            raise ValueError("Datadog IAST vulnerability is missing its type")
        location = value.get("location")
        path = location.get("path") if isinstance(location, dict) else ""
        safe_path = _relative_path(path)
        findings.append(
            {
                **_finding(
                    rule_id=rule_id,
                    title=_text(value.get("title"), 300)
                    or rule_id.replace("_", " ").title(),
                    message="Runtime instrumentation confirmed a source-to-sink weakness.",
                    severity=_severity(value.get("severity")),
                    classification=cwes.get(rule_id.upper(), rule_id),
                    citation="https://docs.datadoghq.com/security/code_security/iast/",
                    area="interactive-application-security-testing",
                    evidence={"vulnerability_hash": _text(value.get("hash"), 160)},
                ),
                "path": safe_path,
                "line": _line(
                    location.get("line") if isinstance(location, dict) else None
                ),
            }
        )
    return findings


def _falco(payload: object) -> list[dict[str, Any]]:
    records = payload if isinstance(payload, list) else [payload]
    findings: list[dict[str, Any]] = []
    for value in records:
        if not isinstance(value, dict):
            raise TypeError("Falco events must be objects")
        rule_id = _text(value.get("rule"), 160)
        if not rule_id:
            raise ValueError("Falco event is missing its rule")
        fields = value.get("output_fields")
        if not isinstance(fields, dict):
            fields = {}
        findings.append(
            _finding(
                rule_id=rule_id,
                title=rule_id,
                message="Falco observed behavior matching an approved runtime rule.",
                severity=_falco_severity(value.get("priority")),
                classification="RUNTIME-THREAT-DETECTION",
                citation="https://falco.org/docs/",
                area="runtime-threat-detection",
                evidence={
                    "container": _text(fields.get("container.name"), 100),
                    "process": _text(fields.get("proc.name"), 100),
                    "source": _text(value.get("source"), 80),
                },
            )
        )
    return findings


def _zap(payload: object) -> list[dict[str, Any]]:
    if not isinstance(payload, dict):
        raise TypeError("ZAP report root must be an object")
    sites = payload.get("site")
    if not isinstance(sites, list):
        raise TypeError("ZAP report requires a site array")
    findings: list[dict[str, Any]] = []
    for site in sites:
        if not isinstance(site, dict):
            raise TypeError("ZAP site entries must be objects")
        alerts = site.get("alerts")
        if not isinstance(alerts, list):
            raise TypeError("ZAP site alerts must be an array")
        for alert in alerts:
            if not isinstance(alert, dict):
                raise TypeError("ZAP alerts must be objects")
            rule_id = _text(alert.get("pluginid") or alert.get("alertRef"), 160)
            if not rule_id:
                raise ValueError("ZAP alert is missing its plugin ID")
            instances = alert.get("instances")
            count = len(instances) if isinstance(instances, list) else 0
            findings.append(
                _finding(
                    rule_id=rule_id,
                    title=_text(alert.get("name") or alert.get("alert"), 300)
                    or rule_id,
                    message=_text(alert.get("desc"), 1000)
                    or "OWASP ZAP reported a dynamic application weakness.",
                    severity=_zap_severity(alert),
                    classification=(
                        f"CWE-{int(alert['cweid'])}"
                        if str(alert.get("cweid") or "").isdigit()
                        else rule_id
                    ),
                    citation=_https(alert.get("reference")),
                    area="dynamic-application-security-testing",
                    evidence={"instances": count},
                )
            )
    return findings


def _prowler(payload: object) -> list[dict[str, Any]]:
    records = payload if isinstance(payload, list) else [payload]
    findings: list[dict[str, Any]] = []
    for value in records:
        if not isinstance(value, dict):
            raise TypeError("Prowler records must be objects")
        status = _text(value.get("Status") or value.get("status"), 40).casefold()
        if status and status not in {"fail", "failed"}:
            continue
        finding_info = value.get("finding_info")
        finding_uid = finding_info.get("uid") if isinstance(finding_info, dict) else ""
        rule_id = _text(
            value.get("CheckID") or value.get("check_id") or finding_uid, 160
        )
        if not rule_id:
            raise ValueError("Prowler failed check is missing CheckID")
        findings.append(
            _finding(
                rule_id=rule_id,
                title=_text(
                    value.get("CheckTitle") or value.get("status_extended"), 300
                )
                or rule_id,
                message=_text(
                    value.get("StatusExtended") or value.get("status_extended"), 1000
                )
                or "Prowler reported a deployed cloud posture failure.",
                severity=_severity(value.get("Severity") or value.get("severity")),
                classification=_text(
                    value.get("Compliance") or value.get("service_name"), 160
                )
                or rule_id,
                citation="https://docs.prowler.com/introduction",
                area="deployed-cloud-posture-and-drift",
                evidence={
                    "provider": _text(
                        value.get("Provider") or value.get("provider"), 80
                    ),
                    "region": _text(value.get("Region") or value.get("region"), 100),
                    "resource_type": _text(
                        value.get("ResourceType") or value.get("resource_type"), 100
                    ),
                },
            )
        )
    return findings


def _restler(payload: object) -> list[dict[str, Any]]:
    if not isinstance(payload, dict):
        raise TypeError("RESTler result root must be an object")
    records = payload.get("bugs") or payload.get("bug_buckets") or []
    if not isinstance(records, list):
        raise TypeError("RESTler results require a bugs array")
    findings: list[dict[str, Any]] = []
    for value in records:
        if not isinstance(value, dict):
            raise TypeError("RESTler bug buckets must be objects")
        rule_id = _text(
            value.get("checker") or value.get("type") or value.get("id"), 160
        )
        if not rule_id:
            raise ValueError("RESTler bug bucket is missing its checker identity")
        if value.get("replay_succeeded") is not True:
            raise ValueError("RESTler bug bucket lacks successful replay confirmation")
        findings.append(
            _finding(
                rule_id=rule_id,
                title=_text(value.get("title"), 300) or rule_id,
                message="RESTler confirmed a replayable stateful API property violation.",
                severity=_severity(value.get("severity") or "high"),
                classification=_text(value.get("classification"), 160) or "CWE-20",
                citation="https://github.com/microsoft/restler-fuzzer",
                area="stateful-rest-api-security-testing",
                evidence={
                    "sequence_length": _safe_integer(value.get("sequence_length")),
                    "replay_succeeded": value.get("replay_succeeded") is True,
                },
            )
        )
    return findings


def _oast(payload: object) -> list[dict[str, Any]]:
    if not isinstance(payload, dict) or set(payload) != {
        "service_mode",
        "egress_scope_approved",
        "interactions",
    }:
        raise ValueError("OAST export fields do not match the sanitized contract")
    if (
        payload.get("service_mode") != "self-hosted"
        or payload.get("egress_scope_approved") is not True
    ):
        raise ValueError("OAST requires self-hosted service and approved egress scope")
    _reject_sensitive_keys(payload)
    records = payload.get("interactions")
    if not isinstance(records, list) or not 1 <= len(records) <= 10_000:
        raise ValueError("OAST interactions must be a bounded non-empty list")
    findings: list[dict[str, Any]] = []
    for value in records:
        if not isinstance(value, dict):
            raise TypeError("OAST interactions must be objects")
        correlation = _text(value.get("correlation_id"), 160)
        protocol = _text(value.get("protocol"), 40).casefold()
        if not correlation or protocol not in {"dns", "http", "https", "smtp", "ldap"}:
            raise ValueError("OAST interaction identity or protocol is invalid")
        if value.get("health_canary") is True:
            continue
        findings.append(
            _finding(
                rule_id=_text(value.get("template_id"), 160) or "oast-callback",
                title="An out-of-band security callback was observed",
                message="The self-hosted OAST service correlated a callback to an approved test payload.",
                severity=_severity(value.get("severity") or "high"),
                classification=_text(value.get("classification"), 160) or "CWE-918",
                citation="https://docs.projectdiscovery.io/templates/reference/oob-testing",
                area="out-of-band-application-security-testing",
                evidence={"protocol": protocol, "correlation_id": correlation},
            )
        )
    return findings


def _secret_verification(payload: object) -> list[dict[str, Any]]:
    if not isinstance(payload, dict):
        raise TypeError("secret verification root must be an object")
    _reject_sensitive_keys(payload)
    receipts = payload.get("receipts")
    if not isinstance(receipts, list):
        raise TypeError("secret verification requires a receipts array")
    findings: list[dict[str, Any]] = []
    for value in receipts:
        if not isinstance(value, dict):
            raise TypeError("secret verification receipts must be objects")
        status = _text(value.get("status"), 40).casefold()
        provider = _text(value.get("provider"), 100)
        fingerprint = _text(value.get("fingerprint"), 160)
        if status not in {"active", "revoked", "invalid", "unknown"}:
            raise ValueError("secret verification status is unsupported")
        if not provider or not fingerprint:
            raise ValueError("secret verification receipt identity is incomplete")
        if status != "active":
            continue
        findings.append(
            _finding(
                rule_id="active-secret-confirmed",
                title="A detected credential remains active",
                message="An authorized provider verification lane confirmed an active credential without retaining its value.",
                severity="critical",
                classification="CWE-798",
                citation="https://github.com/trufflesecurity/trufflehog",
                area="connected-secret-status-verification",
                evidence={
                    "provider": provider,
                    "fingerprint": fingerprint,
                    "status": status,
                },
            )
        )
    return findings


def _receipt_findings(payload: object, tool: str) -> list[dict[str, Any]]:
    if not isinstance(payload, dict) or payload.get("tool") != tool:
        raise TypeError(f"{tool} receipt root must identify its tool")
    _reject_sensitive_keys(payload)
    checks = payload.get("checks")
    if not isinstance(checks, list) or len(checks) > 10_000:
        raise TypeError(f"{tool} receipt requires a bounded checks array")
    findings: list[dict[str, Any]] = []
    for value in checks:
        if not isinstance(value, dict):
            raise TypeError(f"{tool} checks must be objects")
        status = _text(value.get("status"), 40).casefold()
        if status not in {"pass", "fail"}:
            raise ValueError(f"{tool} check status must be pass or fail")
        if status == "pass":
            continue
        rule_id = _text(value.get("id"), 160)
        if not rule_id:
            raise ValueError(f"{tool} failed check is missing its ID")
        findings.append(
            _finding(
                rule_id=rule_id,
                title=_text(value.get("title"), 300) or rule_id,
                message=_text(value.get("message"), 1000)
                or f"{tool} reported a failed native security check.",
                severity=_severity(value.get("severity")),
                classification=_text(value.get("classification"), 160) or rule_id,
                citation=_https(value.get("citation")),
                area=_text(value.get("area"), 100) or f"{tool}-security-testing",
                evidence={
                    "native_check": rule_id,
                    "category": _text(value.get("category"), 100),
                },
            )
        )
    return findings


def _polyglot_findings(payload: object, tool: str) -> list[dict[str, Any]]:
    report, _canary = _native_report_pair(payload, tool)
    if tool == "gosec":
        if not isinstance(report, dict) or not isinstance(report.get("Issues"), list):
            raise ValueError("gosec report requires an Issues array")
        findings: list[dict[str, Any]] = []
        for issue in report["Issues"]:
            if not isinstance(issue, dict):
                raise ValueError("gosec issue must be an object")
            rule = _text(issue.get("rule_id"), 160)
            if not rule:
                raise ValueError("gosec issue is missing rule_id")
            cwe = issue.get("cwe")
            cwe_id = cwe.get("id") if isinstance(cwe, dict) else ""
            findings.append(
                {
                    **_finding(
                        rule_id=rule,
                        title=_text(issue.get("details"), 300) or rule,
                        message="gosec reported an ecosystem-native Go security weakness.",
                        severity=_severity(issue.get("severity")),
                        classification=f"CWE-{cwe_id}"
                        if str(cwe_id).isdigit()
                        else rule,
                        citation="https://github.com/securego/gosec",
                        area="polyglot-ecosystem-security-analysis",
                        evidence={"confidence": _text(issue.get("confidence"), 40)},
                    ),
                    "path": _relative_path(issue.get("file")),
                    "line": _line(str(issue.get("line") or "").split("-", 1)[0]),
                }
            )
        return findings
    if tool == "cargo-audit":
        vulnerabilities = (
            report.get("vulnerabilities") if isinstance(report, dict) else None
        )
        records = (
            vulnerabilities.get("list") if isinstance(vulnerabilities, dict) else None
        )
        if not isinstance(records, list):
            raise ValueError("cargo-audit report requires vulnerabilities.list")
        return [_cargo_finding(value) for value in records]
    vulnerabilities = (
        report.get("vulnerabilities") if isinstance(report, dict) else None
    )
    if not isinstance(vulnerabilities, dict):
        raise ValueError("npm audit report requires a vulnerabilities object")
    return [_npm_finding(name, value) for name, value in vulnerabilities.items()]


def _sarif_findings(payload: object, tool: str) -> list[dict[str, Any]]:
    report, _canary = _native_report_pair(payload, tool)
    runs = report.get("runs")
    if report.get("version") != "2.1.0" or not isinstance(runs, list):
        raise ValueError(f"{tool} report must be SARIF 2.1.0")
    findings: list[dict[str, Any]] = []
    for run in runs:
        if not isinstance(run, dict) or not isinstance(run.get("results", []), list):
            raise ValueError(f"{tool} SARIF run is invalid")
        tool_value = run.get("tool")
        driver = tool_value.get("driver") if isinstance(tool_value, dict) else None
        native_name = _text(driver.get("name"), 160) if isinstance(driver, dict) else ""
        native_version = (
            _text(driver.get("version"), 100) if isinstance(driver, dict) else ""
        )
        if not native_name or not native_version:
            raise ValueError(f"{tool} SARIF run must identify its driver and version")
        invocations = run.get("invocations", [])
        if not isinstance(invocations, list) or not invocations:
            raise ValueError(f"{tool} SARIF requires an invocation receipt")
        invocation_success = all(
            isinstance(item, dict) and item.get("executionSuccessful") is True
            for item in invocations
        )
        if not invocation_success:
            raise ValueError(f"{tool} SARIF invocation did not complete successfully")
        if any(
            isinstance(item, dict)
            and isinstance(item.get("exitCode"), int)
            and item.get("exitCode") != 0
            for item in invocations
        ):
            raise ValueError(f"{tool} SARIF invocation success conflicts with exitCode")
        for result in run.get("results", []):
            if not isinstance(result, dict):
                raise ValueError(f"{tool} SARIF result must be an object")
            rule = _safe_identifier(_text(result.get("ruleId"), 160), "sarif-rule")
            if not rule:
                raise ValueError(f"{tool} SARIF result is missing ruleId")
            message_value = result.get("message")
            raw_message = (
                _text(message_value.get("text"), 1000)
                if isinstance(message_value, dict)
                else ""
            )
            message, message_redacted = _safe_sarif_message(raw_message)
            location = _sarif_location(result.get("locations"))
            semantic_evidence = _sarif_semantics(result, run=run)
            semantic_evidence.update(
                {
                    "native_tool": tool,
                    "sarif_driver": _safe_identifier(
                        native_name or tool, "sarif-driver"
                    ),
                    "sarif_driver_version": _safe_identifier(
                        native_version, "sarif-version"
                    ),
                    "invocation_count": len(invocations),
                    "invocations_successful": invocation_success,
                    "message_redacted": message_redacted,
                }
            )
            findings.append(
                {
                    **_finding(
                        rule_id=rule,
                        title=rule,
                        message=message
                        or f"{tool} reported an ecosystem-native weakness.",
                        severity=_severity(result.get("level")),
                        classification=rule,
                        citation="https://docs.oasis-open.org/sarif/sarif/v2.1.0/",
                        area="polyglot-ecosystem-security-analysis",
                        evidence=semantic_evidence,
                    ),
                    "path": location[0],
                    "line": location[1],
                }
            )
    return findings


def _sarif_semantics(
    result: dict[str, Any], *, run: dict[str, Any] | None = None
) -> dict[str, Any]:
    flows = result.get("codeFlows", [])
    if not isinstance(flows, list):
        raise ValueError("SARIF codeFlows must be an array")
    structural_steps: list[dict[str, object]] = []
    truncated = len(flows) > 64
    logical_truncated = False
    for flow in flows[:64]:
        thread_flows = flow.get("threadFlows", []) if isinstance(flow, dict) else []
        if not isinstance(thread_flows, list):
            raise ValueError("SARIF threadFlows must be an array")
        truncated = truncated or len(thread_flows) > 64
        for thread_flow in thread_flows[:64]:
            locations = (
                thread_flow.get("locations", [])
                if isinstance(thread_flow, dict)
                else []
            )
            if not isinstance(locations, list):
                raise ValueError("SARIF thread-flow locations must be an array")
            truncated = truncated or len(locations) > 256
            for item in locations[:256]:
                location = item.get("location") if isinstance(item, dict) else None
                physical = (
                    location.get("physicalLocation")
                    if isinstance(location, dict)
                    else None
                )
                artifact = (
                    physical.get("artifactLocation")
                    if isinstance(physical, dict)
                    else None
                )
                region = physical.get("region") if isinstance(physical, dict) else None
                logical = (
                    location.get("logicalLocations", [])
                    if isinstance(location, dict)
                    else []
                )
                if not isinstance(logical, list):
                    raise ValueError("SARIF logicalLocations must be an array")
                logical_truncated = logical_truncated or len(logical) > 64
                structural_steps.append(
                    {
                        "path": _relative_path(artifact.get("uri"))
                        if isinstance(artifact, dict)
                        else "<unknown>",
                        "line": _line(region.get("startLine"))
                        if isinstance(region, dict)
                        else None,
                        "nesting_level": item.get("nestingLevel")
                        if isinstance(item, dict)
                        and isinstance(item.get("nestingLevel"), int)
                        else None,
                        "execution_order": item.get("executionOrder")
                        if isinstance(item, dict)
                        and isinstance(item.get("executionOrder"), int)
                        else None,
                        "importance": str(item.get("importance") or "")[:40]
                        if isinstance(item, dict)
                        else "",
                        "kinds": sorted(
                            str(kind)[:80]
                            for kind in item.get("kinds", [])[:32]
                            if isinstance(kind, str)
                        )
                        if isinstance(item, dict)
                        and isinstance(item.get("kinds", []), list)
                        else [],
                        "logical_locations_sha256": hashlib.sha256(
                            canonical_bytes(logical[:64])
                        ).hexdigest(),
                    }
                )
    fingerprints = result.get("fingerprints", {})
    if not isinstance(fingerprints, dict):
        raise ValueError("SARIF fingerprints must be an object")
    fingerprints_truncated = len(fingerprints) > 64
    fingerprint_digest = hashlib.sha256(
        canonical_bytes(
            {
                str(name)[:160]: hashlib.sha256(str(value).encode()).hexdigest()
                for name, value in sorted(
                    fingerprints.items(), key=lambda item: str(item[0])
                )[:64]
            }
        )
    ).hexdigest()
    taxa = result.get("taxa", [])
    if not isinstance(taxa, list):
        raise ValueError("SARIF taxa must be an array")
    taxa_truncated = len(taxa) > 64
    taxon_ids = sorted(
        {
            _text(item.get("id"), 160)
            for item in taxa[:64]
            if isinstance(item, dict) and _text(item.get("id"), 160)
        }
    )
    fixes = result.get("fixes", [])
    properties = result.get("properties", {})
    if not isinstance(fixes, list) or not isinstance(properties, dict):
        raise ValueError("SARIF fixes or properties have an invalid shape")
    truncations = [
        name
        for name, active in (
            ("code-flows", truncated),
            ("logical-locations", logical_truncated),
            ("fingerprints", fingerprints_truncated),
            ("taxa", taxa_truncated),
            ("properties", len(properties) > 64),
        )
        if active
    ]
    extra_arrays = {
        "related_locations": result.get("relatedLocations", []),
        "stacks": result.get("stacks", []),
        "graphs": result.get("graphs", []),
        "suppressions": result.get("suppressions", []),
    }
    extra_evidence: dict[str, Any] = {}
    for name, semantic in extra_arrays.items():
        if not isinstance(semantic, list):
            raise ValueError(f"SARIF {name.replace('_', ' ')} must be an array")
        extra_evidence[f"{name}_count"] = len(semantic)
        extra_evidence[f"{name}_sha256"] = hashlib.sha256(
            canonical_bytes(semantic[:256])
        ).hexdigest()
        if len(semantic) > 256:
            truncations.append(name.replace("_", "-"))
    baseline_state = str(result.get("baselineState") or "")[:40]
    automation = run.get("automationDetails", {}) if isinstance(run, dict) else {}
    if not isinstance(automation, dict):
        raise ValueError("SARIF automationDetails must be an object")
    return {
        "code_flow_count": len(flows),
        "thread_flow_step_count": len(structural_steps),
        "code_flows_truncated": truncated,
        "semantic_truncations": ",".join(truncations),
        "thread_flow_structure_sha256": hashlib.sha256(
            canonical_bytes(structural_steps)
        ).hexdigest(),
        "fingerprints_sha256": fingerprint_digest,
        "taxa": ",".join(_safe_identifier(item, "sarif-taxon") for item in taxon_ids)[
            :1000
        ],
        "fix_count": len(fixes),
        "property_names": ",".join(
            _safe_identifier(str(name)[:100], "sarif-property")
            for name in sorted(properties, key=str)[:64]
        ),
        "source_content_retained": False,
        "baseline_state": baseline_state,
        "automation_details_sha256": hashlib.sha256(
            canonical_bytes(automation)
        ).hexdigest(),
        **extra_evidence,
    }


def _safe_sarif_message(value: str) -> tuple[str, bool]:
    if not value:
        return "", False
    secret_pattern = re.compile(
        r"(?i)(?:authorization\s*:\s*bearer\s+\S+|"
        r"(?:api[_-]?key|client[_-]?secret|password|passwd|access[_-]?token|"
        r"private[_-]?key)\s*[=:]\s*\S+)"
    )
    if secret_pattern.search(value):
        return (
            "Sensitive native message redacted; sha256="
            + hashlib.sha256(value.encode()).hexdigest(),
            True,
        )
    token_pattern = re.compile(
        r"(?:AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|"
        r"eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}|"
        r"[A-Za-z0-9+/=_-]{24,})"
    )
    for match in token_pattern.finditer(value):
        candidate = match.group(0)
        counts = {character: candidate.count(character) for character in set(candidate)}
        entropy = -sum(
            (count / len(candidate)) * math.log2(count / len(candidate))
            for count in counts.values()
        )
        if candidate.startswith(("AKIA", "gh", "eyJ")) or entropy >= 4.0:
            return (
                "Sensitive native message redacted; sha256="
                + hashlib.sha256(value.encode()).hexdigest(),
                True,
            )
    return value, False


def _safe_identifier(value: str, namespace: str) -> str:
    safe, redacted = _safe_sarif_message(value)
    if not redacted:
        return safe
    return f"{namespace}-sha256:{hashlib.sha256(value.encode()).hexdigest()}"


def _sarif_location(value: object) -> tuple[str, int | None]:
    if not isinstance(value, list) or not value or not isinstance(value[0], dict):
        return "<runtime-assurance>", None
    physical = value[0].get("physicalLocation")
    if not isinstance(physical, dict):
        return "<runtime-assurance>", None
    artifact = physical.get("artifactLocation")
    region = physical.get("region")
    path = (
        _relative_path(artifact.get("uri"))
        if isinstance(artifact, dict)
        else "<runtime-assurance>"
    )
    line = _line(region.get("startLine")) if isinstance(region, dict) else None
    return _safe_identifier(path, "sarif-path"), line


def _validate_sarif_schema(
    payload: object, tool: str, schema_path: Path, expected_sha256: str
) -> None:
    if (
        schema_path.is_symlink()
        or not schema_path.is_file()
        or schema_path.stat().st_size > 8 * 1024 * 1024
    ):
        raise ValueError("SARIF schema must be a bounded regular file")
    raw = schema_path.read_bytes()
    if (
        not re.fullmatch(r"[0-9a-f]{64}", expected_sha256)
        or hashlib.sha256(raw).hexdigest() != expected_sha256
    ):
        raise ValueError("SARIF schema SHA-256 does not match")
    schema = strict_loads(raw)
    Draft202012Validator.check_schema(schema)
    report, canary = _native_report_pair(payload, tool)
    validator = Draft202012Validator(schema)
    validator.validate(report)
    validator.validate(canary)


def _native_report_pair(
    payload: object, tool: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    if not isinstance(payload, dict) or set(payload) != {
        "tool",
        "report",
        "canary_report",
    }:
        raise ValueError(f"{tool} native wrapper fields do not match the contract")
    if payload.get("tool") != tool:
        raise ValueError(f"{tool} native wrapper identifies the wrong tool")
    report = payload.get("report")
    canary = payload.get("canary_report")
    if not isinstance(report, dict) or not isinstance(canary, dict):
        raise ValueError(f"{tool} native reports must be objects")
    return report, canary


def _cargo_finding(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("cargo-audit vulnerability must be an object")
    advisory = value.get("advisory")
    package = value.get("package")
    if not isinstance(advisory, dict) or not isinstance(package, dict):
        raise ValueError("cargo-audit vulnerability identity is incomplete")
    rule = _text(advisory.get("id"), 160)
    if not rule:
        raise ValueError("cargo-audit advisory is missing its ID")
    return _finding(
        rule_id=rule,
        title=_text(advisory.get("title"), 300) or rule,
        message="cargo-audit identified a vulnerable Rust dependency.",
        severity=_severity(advisory.get("severity") or "high"),
        classification="CWE-1395",
        citation=_https(advisory.get("url")) or "https://rustsec.org/",
        area="polyglot-ecosystem-security-analysis",
        evidence={"package": _text(package.get("name"), 100)},
    )


def _npm_finding(name: object, value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("npm audit vulnerability must be an object")
    package = _text(name, 100)
    if not package:
        raise ValueError("npm audit vulnerability package is invalid")
    return _finding(
        rule_id=f"npm-audit:{package}",
        title=f"Vulnerable npm dependency: {package}",
        message="npm audit identified an ecosystem advisory affecting this dependency.",
        severity=_severity(value.get("severity")),
        classification="CWE-1395",
        citation="https://docs.npmjs.com/cli/commands/npm-audit",
        area="polyglot-ecosystem-security-analysis",
        evidence={"package": package, "direct": value.get("isDirect") is True},
    )


def _execution(
    payload: object, tool: str, findings: list[dict[str, Any]], *, context: Path
) -> dict[str, Any]:
    if tool in {
        "brakeman-sarif",
        "cargo-audit",
        "detekt-sarif",
        "eslint-sarif",
        "gosec",
        "govulncheck-sarif",
        "npm-audit",
        "spotbugs-sarif",
    }:
        _report, canary_report = _native_report_pair(payload, tool)
        parser = _sarif_findings if tool.endswith("-sarif") else _polyglot_findings
        canary_findings = parser(
            {"tool": tool, "report": canary_report, "canary_report": canary_report},
            tool,
        )
        return _execution_record(
            targets=1,
            requests=max(1, len(findings)) + max(1, len(canary_findings)),
            coverage=100.0 if canary_findings else 0.0,
            metric="native-ecosystem-report-and-canary",
            roles=["build-analysis"],
            features=["semantic-dataflow", "language-matrix", "ecosystem-native"],
            canaries=int(bool(canary_findings)),
        )
    if tool == "nuclei":
        nuclei_records = payload if isinstance(payload, list) else [payload]
        canaries = sum(
            isinstance(value, dict)
            and (
                value.get("template-id") == "pysec-loopback-health-canary"
                or value.get("templateID") == "pysec-loopback-health-canary"
            )
            for value in nuclei_records
        )
        return _execution_record(
            targets=1,
            requests=max(1, len(nuclei_records)),
            coverage=100.0 if canaries else 0.0,
            metric="approved-template-result-and-canary",
            roles=["anonymous"],
            features=["signed-templates", "approved-workflow"],
            canaries=canaries,
        )
    if tool == "restler" and isinstance(payload, dict):
        summary = payload.get("summary")
        if isinstance(summary, dict):
            return _validated_execution(summary, context=context)
    if tool == "oast":
        if not isinstance(payload, dict):
            raise ValueError("OAST execution metadata is absent")
        oast_records = payload.get("interactions")
        if not isinstance(oast_records, list):
            raise ValueError("OAST interactions are absent")
        canaries = sum(
            isinstance(value, dict) and value.get("health_canary") is True
            for value in oast_records
        )
        return _execution_record(
            targets=1,
            requests=max(1, len(oast_records)),
            coverage=100.0 if canaries else 0.0,
            metric="correlated-oast-callbacks",
            roles=["anonymous"],
            features=["self-hosted-oast", "callback-correlation", "egress-scope"],
            canaries=canaries,
        )
    if tool == "secret-verification" and isinstance(payload, dict):
        receipts = payload.get("receipts")
        count = len(receipts) if isinstance(receipts, list) else 0
        canary = int(payload.get("health_canary") is True)
        return _execution_record(
            targets=max(1, count),
            requests=count + canary,
            coverage=100.0 if canary else 0.0,
            metric="provider-verification-receipts",
            roles=["connected-verifier"],
            features=["provider-receipts", "value-redaction", "revocation-state"],
            canaries=canary,
        )
    if isinstance(payload, dict) and payload.get("tool") == tool:
        execution = payload.get("execution")
        if isinstance(execution, dict):
            return _validated_execution(execution, context=context)
    raise ValueError(f"{tool} output does not contain derivable execution metadata")


def _validated_execution(value: dict[str, Any], *, context: Path) -> dict[str, Any]:
    required = {
        "status",
        "targets_discovered",
        "targets_exercised",
        "requests",
        "coverage_percent",
        "coverage_metric",
        "roles",
        "features",
        "skipped_checks",
        "canaries_expected",
        "canaries_observed",
    }
    allowed = required | {"language_matrix", "cross_language_matrix"}
    if (
        set(value) - allowed
        or not required.issubset(value)
        or value.get("status") != "completed"
    ):
        raise ValueError("native execution metadata does not match the v2 contract")
    discovered = _safe_integer(value.get("targets_discovered"))
    exercised = _safe_integer(value.get("targets_exercised"))
    requests = _safe_integer(value.get("requests"))
    expected = _safe_integer(value.get("canaries_expected"))
    observed = _safe_integer(value.get("canaries_observed"))
    coverage = _safe_float(value.get("coverage_percent"))
    if (
        discovered < 1
        or exercised < 1
        or exercised > discovered
        or requests < 0
        or not 0 <= coverage <= 100
        or expected < 1
        or observed != expected
    ):
        raise ValueError("native execution metadata is incomplete")
    roles = _string_list(value.get("roles"), 64)
    features = _string_list(value.get("features"), 256)
    skipped = _string_list(value.get("skipped_checks"), 256)
    if skipped:
        raise ValueError("native execution metadata contains skipped checks")
    language_matrix = _validated_language_matrix(value.get("language_matrix", []))
    cross_language_matrix = _validated_cross_language_matrix(
        value.get("cross_language_matrix", []), context=context
    )
    return {
        "status": "completed",
        "targets_discovered": discovered,
        "targets_exercised": exercised,
        "requests": requests,
        "coverage_percent": coverage,
        "coverage_metric": _text(value.get("coverage_metric"), 100),
        "roles": roles,
        "features": features,
        "skipped_checks": [],
        "canaries_expected": expected,
        "canaries_observed": observed,
        **({"language_matrix": language_matrix} if language_matrix else {}),
        **(
            {"cross_language_matrix": cross_language_matrix}
            if cross_language_matrix
            else {}
        ),
    }


def _validated_language_matrix(value: object) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) > 64:
        raise ValueError("native language matrix must be a bounded list")
    result: list[dict[str, Any]] = []
    languages: set[str] = set()
    required = {
        "language",
        "engine",
        "engine_version",
        "query_pack_sha256",
        "source_files_sha256",
        "files_discovered",
        "files_analyzed",
        "exclusions",
        "analysis_modes",
        "files",
    }
    for item in value:
        if not isinstance(item, dict) or set(item) != required:
            raise ValueError("native language matrix entry fields do not match")
        language = _text(item["language"], 50).casefold()
        if not language or language in languages:
            raise ValueError("native language matrix languages must be unique")
        discovered = _safe_integer(item["files_discovered"])
        analyzed = _safe_integer(item["files_analyzed"])
        exclusions = item["exclusions"]
        if not isinstance(exclusions, list) or len(exclusions) > 10_000:
            raise ValueError("native language matrix exclusions are invalid")
        normalized_exclusions: list[dict[str, str]] = []
        for exclusion in exclusions:
            if not isinstance(exclusion, dict) or set(exclusion) != {"path", "reason"}:
                raise ValueError("native language matrix exclusion fields do not match")
            path = _text(exclusion["path"], 1000)
            reason = _text(exclusion["reason"], 200)
            if not path or not reason:
                raise ValueError("native language matrix exclusion is incomplete")
            normalized_exclusions.append({"path": path, "reason": reason})
        modes = _string_list(item["analysis_modes"], 32)
        if (
            discovered < 1
            or analyzed < 1
            or analyzed + len(exclusions) != discovered
            or "semantic-dataflow" not in modes
        ):
            raise ValueError("native language matrix file accounting is incomplete")
        for name in ("query_pack_sha256", "source_files_sha256"):
            digest = str(item[name])
            if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
                raise ValueError(f"native language matrix {name} is invalid")
        files = _validated_language_files(item["files"])
        if (
            len(files) != analyzed
            or hashlib.sha256(canonical_bytes(files)).hexdigest()
            != item["source_files_sha256"]
        ):
            raise ValueError("native language exact file ledger does not match")
        engine = _text(item["engine"], 100)
        engine_version = _text(item["engine_version"], 100)
        if not engine or not engine_version:
            raise ValueError("native language matrix engine identity is incomplete")
        languages.add(language)
        result.append(
            {
                "language": language,
                "engine": engine,
                "engine_version": engine_version,
                "query_pack_sha256": item["query_pack_sha256"],
                "source_files_sha256": item["source_files_sha256"],
                "files_discovered": discovered,
                "files_analyzed": analyzed,
                "exclusions": normalized_exclusions,
                "analysis_modes": modes,
                "files": files,
            }
        )
    return sorted(result, key=lambda item: str(item["language"]))


def _validated_language_files(value: object) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not 1 <= len(value) <= 50_000:
        raise ValueError("native language files must be a bounded non-empty list")
    result: list[dict[str, Any]] = []
    paths: set[str] = set()
    for item in value:
        if not isinstance(item, dict) or set(item) != {
            "path",
            "size_bytes",
            "sha256",
            "line_count",
        }:
            raise ValueError("native language file fields do not match")
        path = _text(item["path"], 1000)
        size = _safe_integer(item["size_bytes"])
        digest = str(item["sha256"])
        line_count = _safe_integer(item["line_count"])
        if (
            not path
            or size < 0
            or line_count < 0
            or path.startswith(("/", "\\"))
            or ".." in Path(path).parts
            or path in paths
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
        ):
            raise ValueError("native language file identity is invalid")
        paths.add(path)
        result.append(
            {
                "path": path,
                "size_bytes": size,
                "sha256": digest,
                "line_count": line_count,
            }
        )
    if result != sorted(result, key=lambda item: str(item["path"])):
        raise ValueError("native language files must use canonical path order")
    return result


def _validated_cross_language_matrix(
    value: object, *, context: Path
) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) > 2_016:
        raise ValueError("native cross-language matrix must be bounded")
    result: list[dict[str, Any]] = []
    pairs: set[tuple[str, str]] = set()
    required = {
        "languages",
        "engine",
        "engine_version",
        "query_pack_sha256",
        "source_file_sets_sha256",
        "boundaries_analyzed",
        "flows_found",
        "boundaries",
        "boundaries_sha256",
        "flows",
        "flows_sha256",
        "analysis_modes",
        "independent_validation",
    }
    for item in value:
        if not isinstance(item, dict) or set(item) != required:
            raise ValueError("native cross-language entry fields do not match")
        raw = item["languages"]
        if not isinstance(raw, list) or len(raw) != 2:
            raise ValueError("native cross-language entry requires two languages")
        names = sorted(_text(language, 50).casefold() for language in raw)
        pair = (names[0], names[1])
        modes = _string_list(item["analysis_modes"], 32)
        boundaries = _native_cross_records(item["boundaries"], pair, boundary=True)
        flows = _native_cross_records(item["flows"], pair, boundary=False)
        independent = _native_independent_validation(
            item["independent_validation"],
            context=context,
            subject_context={
                "languages": list(pair),
                "primary_engine": _text(item["engine"], 100),
                "primary_query_pack_sha256": item["query_pack_sha256"],
                "source_file_sets_sha256": item["source_file_sets_sha256"],
            },
        )
        digests = tuple(
            str(item[name])
            for name in (
                "query_pack_sha256",
                "source_file_sets_sha256",
                "boundaries_sha256",
                "flows_sha256",
            )
        )
        boundaries_analyzed = _safe_integer(item["boundaries_analyzed"])
        flows_found = _safe_integer(item["flows_found"])
        if (
            not pair[0]
            or pair[0] == pair[1]
            or pair in pairs
            or not {"semantic-dataflow", "cross-language-boundary"}.issubset(modes)
            or any(
                len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest)
                for digest in digests
            )
            or boundaries_analyzed < 0
            or flows_found < 0
            or boundaries_analyzed != len(boundaries)
            or flows_found != len(flows)
            or item["boundaries_sha256"]
            != hashlib.sha256(canonical_bytes(boundaries)).hexdigest()
            or item["flows_sha256"]
            != hashlib.sha256(canonical_bytes(flows)).hexdigest()
        ):
            raise ValueError("native cross-language entry is invalid")
        pairs.add(pair)
        result.append(
            {
                "languages": list(pair),
                "engine": _text(item["engine"], 100),
                "engine_version": _text(item["engine_version"], 100),
                "query_pack_sha256": item["query_pack_sha256"],
                "source_file_sets_sha256": item["source_file_sets_sha256"],
                "boundaries_analyzed": boundaries_analyzed,
                "flows_found": flows_found,
                "boundaries": boundaries,
                "boundaries_sha256": item["boundaries_sha256"],
                "flows": flows,
                "flows_sha256": item["flows_sha256"],
                "analysis_modes": modes,
                "independent_validation": independent,
            }
        )
    return sorted(result, key=lambda item: tuple(item["languages"]))


def _native_independent_validation(
    value: object, *, context: Path, subject_context: dict[str, Any]
) -> dict[str, Any]:
    required = {"engine", "query_pack_sha256", "boundaries_sha256", "flows_sha256"}
    governed = required | {"minimum_authority_signatures", "authorities"}
    if not isinstance(value, dict) or set(value) not in {
        frozenset(required),
        frozenset(governed),
    }:
        raise ValueError("native independent semantic validation fields do not match")
    result = {name: str(value[name]) for name in required}
    result["engine"] = _text(value["engine"], 100)
    if not result["engine"] or any(
        len(result[name]) != 64
        or any(character not in "0123456789abcdef" for character in result[name])
        for name in required - {"engine"}
    ):
        raise ValueError("native independent semantic validation is invalid")
    authority: dict[str, Any] = {
        "validated": False,
        "minimum_signatures": 0,
        "signers": [],
        "collectors": [],
        "organizations": [],
        "subject_sha256": "",
    }
    if set(value) == governed:
        threshold = _safe_integer(value["minimum_authority_signatures"])
        subject = {
            "schema_version": "1.0",
            "purpose": "independent-semantic-validation",
            **subject_context,
            "independent_result": result,
        }
        verified = verify_authority_quorum(
            context,
            value["authorities"],
            purpose="independent-semantic-validation",
            subject=subject,
            minimum_signatures=threshold,
            at=datetime.now(UTC),
        )
        if any(item["schema_version"] != "2.0" for item in verified):
            raise ValueError(
                "independent semantic authorities must use lifecycle-bound v2 receipts"
            )
        authority = {
            "validated": True,
            "minimum_signatures": threshold,
            "signers": sorted({item["signer_id"] for item in verified}),
            "collectors": sorted({item["collector_id"] for item in verified}),
            "organizations": sorted({item["organization"] for item in verified}),
            "subject_sha256": hashlib.sha256(canonical_bytes(subject)).hexdigest(),
        }
    return {**result, "authority": authority}


def _native_cross_records(
    value: object, pair: tuple[str, str], *, boundary: bool
) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) > 100_000:
        raise ValueError("native cross-language ledger must be bounded")
    fields = (
        {"path", "line", "language", "kind", "target"}
        if boundary
        else {
            "source_path",
            "source_line",
            "source_language",
            "sink_path",
            "sink_line",
            "sink_language",
            "source_kind",
            "sink_kind",
        }
    )
    result: list[dict[str, Any]] = []
    for item in value:
        if not isinstance(item, dict) or set(item) != fields:
            raise ValueError("native cross-language ledger fields do not match")
        record: dict[str, Any] = {}
        for name in sorted(fields):
            raw = item[name]
            if name.endswith("line") or name == "line":
                integer = _safe_integer(raw)
                if integer < 1:
                    raise ValueError("native cross-language ledger line is invalid")
                record[name] = integer
            else:
                text = _text(raw, 1000)
                if name.endswith("path") or name == "path":
                    if (
                        text.startswith(("/", "\\"))
                        or (len(text) >= 2 and text[1] == ":")
                        or ".." in Path(text).parts
                    ):
                        raise ValueError("native cross-language ledger path is unsafe")
                if name.endswith("language") or name == "language":
                    text = text.casefold()
                    if text not in pair:
                        raise ValueError(
                            "native cross-language ledger language is invalid"
                        )
                record[name] = text
        result.append(record)
    ordered = sorted(result, key=canonical_bytes)
    if result != ordered or len({canonical_bytes(item) for item in result}) != len(
        result
    ):
        raise ValueError("native cross-language ledger is not canonical and unique")
    return result


def _execution_record(
    *,
    targets: int,
    requests: int,
    coverage: float,
    metric: str,
    roles: list[str],
    features: list[str],
    canaries: int,
) -> dict[str, Any]:
    return {
        "status": "completed",
        "targets_discovered": targets,
        "targets_exercised": targets,
        "requests": requests,
        "coverage_percent": coverage,
        "coverage_metric": metric,
        "roles": roles,
        "features": features,
        "skipped_checks": [],
        "canaries_expected": 1,
        "canaries_observed": canaries,
    }


def _string_list(value: object, maximum: int) -> list[str]:
    if not isinstance(value, list) or len(value) > maximum:
        raise ValueError("native execution labels must be a bounded list")
    result = [_text(item, 160) for item in value]
    if any(not item for item in result) or len(set(result)) != len(result):
        raise ValueError("native execution labels are invalid")
    return result


def _safe_integer(value: object) -> int:
    if isinstance(value, bool):
        return -1
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return -1


def _safe_float(value: object) -> float:
    try:
        result = float(str(value))
    except (TypeError, ValueError):
        return -1.0
    return result if math.isfinite(result) else -1.0


def _reject_sensitive_keys(value: object) -> None:
    forbidden = {
        "authorization",
        "body",
        "command",
        "cookie",
        "credential",
        "password",
        "raw",
        "request",
        "response",
        "secret",
        "token",
        "value",
    }
    if isinstance(value, dict):
        for key, item in value.items():
            normalized = str(key).casefold().replace("-", "_")
            if any(part in forbidden for part in normalized.split("_")):
                raise ValueError("native receipt contains a forbidden sensitive field")
            _reject_sensitive_keys(item)
    elif isinstance(value, list):
        for item in value:
            _reject_sensitive_keys(item)


def _finding(
    *,
    rule_id: str,
    title: str,
    message: str,
    severity: str,
    classification: str,
    citation: str,
    area: str,
    evidence: dict[str, object],
) -> dict[str, Any]:
    return {
        "rule_id": rule_id,
        "title": title,
        "message": message,
        "path": "<runtime-assurance>",
        "severity": severity,
        "classification": classification,
        "citation": citation,
        "impact": "The independently executed companion control observed a security weakness.",
        "remediation": "Correct the control failure, add a regression canary, and regenerate signed evidence.",
        "area": area,
        "domain": "security",
        "fingerprint": "",
        "evidence": {
            key: value for key, value in evidence.items() if value not in {"", None}
        },
    }


def _zap_severity(value: dict[str, Any]) -> str:
    risk = _text(value.get("riskdesc"), 100).casefold()
    if risk:
        return _severity(risk.split()[0])
    code = str(value.get("riskcode") or "")
    return {"3": "high", "2": "medium", "1": "low", "0": "informational"}.get(
        code, "medium"
    )


def _falco_severity(value: object) -> str:
    return {
        "emergency": "critical",
        "alert": "critical",
        "critical": "critical",
        "error": "high",
        "warning": "medium",
        "notice": "low",
        "informational": "informational",
        "debug": "informational",
    }.get(_text(value, 40).casefold(), "medium")


def _severity(value: object) -> str:
    normalized = _text(value, 40).casefold()
    return {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "moderate": "medium",
        "low": "low",
        "info": "informational",
        "informational": "informational",
    }.get(normalized, "medium")


def _classification(value: object, fallback: str) -> str:
    if isinstance(value, dict):
        for key in ("cwe-id", "cwe", "cvss-metrics"):
            candidate = _text(value.get(key), 160)
            if candidate:
                return candidate
    return fallback


def _https(value: object) -> str:
    candidates = value if isinstance(value, list) else [value]
    for item in candidates:
        candidate = _text(item, 2048)
        if candidate.startswith("https://"):
            return candidate
    return ""


def _text(value: object, maximum: int) -> str:
    if isinstance(value, (dict, list)):
        return ""
    return str(value or "").strip()[:maximum]


def _relative_path(value: object) -> str:
    candidate = _text(value, 500).replace("\\", "/")
    parts = candidate.split("/")
    if (
        not candidate
        or candidate.startswith("/")
        or (len(candidate) > 1 and candidate[1] == ":")
        or ".." in parts
    ):
        return "<runtime-iast>"
    return candidate


def _line(value: object) -> int | None:
    try:
        line = int(str(value))
    except (TypeError, ValueError):
        return None
    return line if line > 0 else None


def _write(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and (path.is_symlink() or not path.is_file()):
        raise ValueError("normalizer output is not a replaceable regular file")
    payload = (strict_dumps(value, indent=2) + "\n").encode()
    with tempfile.NamedTemporaryFile(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
        delete=False,
    ) as handle:
        temporary = Path(handle.name)
        handle.write(payload)
        handle.flush()
    try:
        temporary.replace(path)
    finally:
        if temporary.exists():
            temporary.unlink()


if __name__ == "__main__":
    raise SystemExit(main())
