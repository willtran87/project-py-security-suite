from __future__ import annotations

import copy
import json

import pytest

from py_security_suite.adapters.codeql_refinement import refine_native_results


def documents():
    result = {
        "ruleId": "py/path-injection",
        "message": {"text": "native alert"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": "routes/app.py",
                        "uriBaseId": "%SRCROOT%",
                    },
                    "region": {"startLine": 12, "startColumn": 10, "endColumn": 24},
                }
            }
        ],
        "codeFlows": [
            {
                "threadFlows": [
                    {
                        "locations": [
                            {"location": {"message": {"text": "source to sink"}}}
                        ]
                    }
                ]
            }
        ],
    }
    primary = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "CodeQL"}},
                "invocations": [{"executionSuccessful": True}],
                "results": [result],
            }
        ],
    }
    extra = copy.deepcopy(primary)
    proof = extra["runs"][0]["results"][0]
    proof.pop("codeFlows")
    proof["ruleId"] = "pysec/constant-path-proof"
    proof["message"]["text"] = "pysec-constant-choice-v1:py/path-injection"
    return primary, extra


def apply(primary, extra, eligible=True):
    first, second, audit = refine_native_results(
        json.dumps(primary), json.dumps(extra), eligible=eligible
    )
    return (
        json.loads(first)["runs"][0]["results"],
        json.loads(second)["runs"][0]["results"],
        audit,
    )


def test_exact_native_match_retains_original_and_proof():
    primary, extra = documents()
    first, second, audit = apply(primary, extra)
    assert not first and not second
    assert audit["excluded_count"] == 1
    assert audit["exclusions"][0]["original_result"] == primary["runs"][0]["results"][0]
    assert audit["exclusions"][0]["native_proof"] == extra["runs"][0]["results"][0]


@pytest.mark.parametrize(
    "marker,excluded",
    [("pysec-xpath-context-v2:", 1), ("pysec-constant-choice-v1:", 0)],
)
def test_xpath_context_proof_requires_current_protocol(marker, excluded):
    primary, extra = documents()
    primary["runs"][0]["results"][0]["ruleId"] = "py/xpath-injection"
    proof = extra["runs"][0]["results"][0]
    proof["ruleId"] = "pysec/constant-xpath-proof"
    proof["message"]["text"] = marker + "py/xpath-injection"
    first, _, audit = apply(primary, extra)
    assert audit["excluded_count"] == excluded
    assert len(first) == 1 - excluded


@pytest.mark.parametrize(
    "mutation",
    [
        "ineligible",
        "no-proof",
        "duplicate",
        "failed",
        "no-invocation",
        "warning",
        "unknown-notice",
        "no-column",
        "other-column",
        "other-rule",
        "other-file",
        "other-base",
        "unsafe-uri",
        "wrong-message",
        "bad-message",
        "informational",
        "suppressed",
        "no-trace",
        "extra-location",
        "primary-failed",
        "boolean-line",
        "negative-line",
        "reverse-region",
    ],
)
def test_uncertain_or_mismatched_evidence_never_excludes(mutation):
    primary, extra = documents()
    run = extra["runs"][0]
    proof = run["results"][0]
    physical = proof["locations"][0]["physicalLocation"]
    match mutation:
        case "no-proof":
            run["results"] = []
        case "duplicate":
            run["results"].append(copy.deepcopy(proof))
        case "failed":
            run["invocations"][0]["executionSuccessful"] = False
        case "primary-failed":
            primary["runs"][0]["invocations"][0]["executionSuccessful"] = False
        case "no-invocation":
            run.pop("invocations")
        case "warning":
            run["invocations"][0]["toolExecutionNotifications"] = [{"level": "warning"}]
        case "unknown-notice":
            run["invocations"][0]["toolConfigurationNotifications"] = [{}]
        case "no-column":
            physical["region"].pop("startColumn")
        case "other-column":
            physical["region"]["startColumn"] = 11
        case "other-rule":
            primary["runs"][0]["results"][0]["ruleId"] = "py/xpath-injection"
        case "other-file":
            physical["artifactLocation"]["uri"] = "app.py"
        case "other-base":
            physical["artifactLocation"]["uriBaseId"] = "elsewhere"
        case "unsafe-uri":
            physical["artifactLocation"]["uri"] = "../routes/app.py"
        case "wrong-message":
            proof["message"]["text"] = "pysec-constant-choice-v2:py/path-injection"
        case "bad-message":
            proof["message"] = []
        case "informational":
            proof["kind"] = "informational"
        case "suppressed":
            proof["suppressions"] = [{"kind": "inSource"}]
        case "no-trace":
            primary["runs"][0]["results"][0].pop("codeFlows")
        case "extra-location":
            proof["locations"].append(copy.deepcopy(proof["locations"][0]))
        case "boolean-line":
            physical["region"]["startLine"] = True
        case "negative-line":
            physical["region"]["startLine"] = -1
        case "reverse-region":
            physical["region"]["endColumn"] = 1
    first, second, audit = apply(primary, extra, eligible=mutation != "ineligible")
    assert first == primary["runs"][0]["results"]
    assert not second
    assert audit["excluded_count"] == 0


def test_same_line_other_sink_and_other_supplemental_findings_survive():
    primary, extra = documents()
    unsafe = copy.deepcopy(primary["runs"][0]["results"][0])
    unsafe["locations"][0]["physicalLocation"]["region"].update(
        startColumn=30, endColumn=44
    )
    primary["runs"][0]["results"].append(unsafe)
    credential = copy.deepcopy(unsafe)
    credential["ruleId"] = "pysec/environment-secret-to-log"
    extra["runs"][0]["results"].append(credential)
    first, second, audit = apply(primary, extra)
    assert first == [unsafe]
    assert second == [credential]
    assert audit["excluded_count"] == 1


@pytest.mark.parametrize("limit", ["_MAX_PROOFS", "_MAX_AUDIT_BYTES"])
def test_resource_limit_keeps_all_primary_alerts(monkeypatch, limit):
    monkeypatch.setattr("py_security_suite.adapters.codeql_refinement." + limit, 0)
    primary, extra = documents()
    first, _, audit = apply(primary, extra)
    assert first == primary["runs"][0]["results"]
    assert audit["excluded_count"] == 0


def test_imported_sarif_does_not_apply_native_proofs(tmp_path):
    from py_security_suite.adapters.codeql import CodeQlAdapter
    from py_security_suite.config import ToolConfig

    primary, extra = documents()
    primary["runs"][0]["results"].extend(extra["runs"][0]["results"])
    findings = CodeQlAdapter(ToolConfig(), 65536).parse(json.dumps(primary), tmp_path)
    assert any(
        source.rule_id == "py/path-injection"
        for finding in findings
        for source in finding.sources
    )


def test_audit_normalization_receives_original_rule_and_trace_context():
    primary, extra = documents()
    primary["runs"][0]["threadFlowLocations"] = [
        {"location": {"message": {"text": "cached"}}}
    ]
    primary["runs"][0]["artifacts"] = [{"location": {"uri": "routes/app.py"}}]

    def normalize(payload):
        run = json.loads(payload)["runs"][0]
        assert run["threadFlowLocations"] == primary["runs"][0]["threadFlowLocations"]
        assert run["artifacts"] == primary["runs"][0]["artifacts"]
        assert run["results"] == primary["runs"][0]["results"]
        return [{"evidence": {"resolved_and_redacted": True}}]

    first, _, audit = refine_native_results(
        json.dumps(primary), json.dumps(extra), eligible=True, normalize=normalize
    )
    assert not json.loads(first)["runs"][0]["results"]
    assert audit["exclusions"][0]["original_finding"] == {
        "evidence": {"resolved_and_redacted": True}
    }
    assert "original_result" not in audit["exclusions"][0]


def test_incomplete_audit_normalization_rejects_refinement():
    primary, extra = documents()
    with pytest.raises(ValueError, match="normalized completely"):
        refine_native_results(
            json.dumps(primary),
            json.dumps(extra),
            eligible=True,
            normalize=lambda _: [],
        )
