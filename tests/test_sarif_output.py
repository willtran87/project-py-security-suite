from __future__ import annotations

import re
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from py_security_suite.models import (
    Confidence,
    Finding,
    FindingStatus,
    Location,
    Severity,
    Source,
)
from py_security_suite.report_markdown import _markdown_code, _markdown_text
from py_security_suite.report_sarif import SARIF_FINGERPRINT_KEY, _sarif_artifact_uri
from py_security_suite.reports import (
    _markdown_table,
    _write_primary_report_files,
    render_sarif,
)


def _finding(
    name: str,
    severity: Severity,
    *,
    path: str = "app.py",
    rule_id: str = "B602",
    impact: str = "Command injection.",
    remediation: str = "Avoid shell=True.",
    description: str = "Shell execution.",
) -> Finding:
    return Finding(
        finding_id=f"PYSEC-{name}",
        fingerprint=f"sha256:{name}",
        title="subprocess with shell",
        description=description,
        impact=impact,
        remediation=remediation,
        severity=severity,
        confidence=Confidence.HIGH,
        area="injection",
        locations=[Location(path=path, start_line=3)],
        sources=[Source(tool="bandit", rule_id=rule_id, message="shell")],
    )


def _run(sarif: dict[str, Any]) -> dict[str, Any]:
    run = sarif["runs"][0]
    assert isinstance(run, dict)
    return run


def test_sarif_rule_severity_follows_each_finding_not_the_first() -> None:
    run = _run(
        render_sarif(
            [
                _finding("low", Severity.LOW),
                _finding("critical", Severity.CRITICAL),
                _finding("low-again", Severity.LOW),
            ]
        )
    )
    rules = {rule["id"]: rule for rule in run["tool"]["driver"]["rules"]}
    assert set(rules) == {"bandit/B602/low", "bandit/B602/critical"}
    assert rules["bandit/B602/critical"]["properties"]["security-severity"] == "9.5"
    assert rules["bandit/B602/low"]["properties"]["security-severity"] == "3.0"
    assert {rule["properties"]["source_rule_id"] for rule in rules.values()} == {
        "bandit/B602"
    }
    assert len({rule["name"] for rule in rules.values()}) == 2
    for result in run["results"]:
        rule = rules[result["ruleId"]]
        assert result["level"] == rule["defaultConfiguration"]["level"]
        assert (
            result["properties"]["security-severity"]
            == rule["properties"]["security-severity"]
        )
    critical = next(
        result
        for result in run["results"]
        if result["properties"]["finding_id"] == "PYSEC-critical"
    )
    assert critical["ruleId"] == "bandit/B602/critical"
    assert critical["level"] == "error"


def test_sarif_help_markdown_and_message_neutralize_scanner_markup() -> None:
    hostile = "see [docs](javascript:alert(1)) ![x](https://evil.example/p.png) a|b"
    run = _run(
        render_sarif(
            [
                _finding(
                    "hostile",
                    Severity.HIGH,
                    impact=hostile,
                    remediation=hostile,
                    description=f"{hostile} \\[kept]",
                )
            ]
        )
    )
    markdown = run["tool"]["driver"]["rules"][0]["help"]["markdown"]
    assert "**Why it matters:**" in markdown
    # No unescaped bracket can open a Markdown link or image.
    assert re.search(r"(?<!\\)[\[\]]", markdown) is None
    assert "\\](javascript:" in markdown
    assert "a\\|b" in markdown
    message = run["results"][0]["message"]["text"]
    assert re.search(r"(?<!\\)(?:\\\\)*[\[\]]", message) is None
    assert "\\[docs\\](javascript:" in message
    # An existing backslash before a bracket is itself escaped.
    assert "\\\\\\[kept\\]" in message


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("src/my dir/a#b%c.py", "src/my%20dir/a%23b%25c.py"),
        ("src/ünï.py", "src/%C3%BCn%C3%AF.py"),
        ("./pkg/mod.py", "pkg/mod.py"),
        ("pkg\\win.py", "pkg/win.py"),
        ("a?b.py", "a%3Fb.py"),
        ("<outside-target>", None),
        ("<repository>", None),
        (".", None),
        ("", None),
        ("/etc/passwd", None),
        ("C:/Windows/system.ini", None),
        ("../escape.py", None),
        ("src/../../escape.py", None),
        ("bad\nname.py", None),
    ],
)
def test_sarif_artifact_uri_is_percent_encoded_and_in_target(
    path: str, expected: str | None
) -> None:
    assert _sarif_artifact_uri(path) == expected


def test_sarif_omits_placeholder_locations_and_uses_custom_fingerprint() -> None:
    inside = _finding("inside", Severity.MEDIUM, path="src/my dir/a#b.py")
    outside = _finding("outside", Severity.MEDIUM, path="<outside-target>")
    run = _run(render_sarif([inside, outside]))
    first, second = run["results"]
    assert first["locations"][0]["physicalLocation"]["artifactLocation"] == {
        "uri": "src/my%20dir/a%23b.py"
    }
    assert "locations" not in second
    for result, finding in zip(run["results"], (inside, outside), strict=True):
        assert result["partialFingerprints"] == {
            SARIF_FINGERPRINT_KEY: finding.fingerprint
        }
    assert SARIF_FINGERPRINT_KEY == "pysecFingerprint/v1"


def test_sarif_emits_accepted_suppressions_for_governed_risk_acceptance() -> None:
    accepted = _finding("accepted", Severity.HIGH)
    accepted.status = FindingStatus.SUPPRESSED
    accepted.evidence["risk_acceptance"] = {
        "disposition": "accepted-risk",
        "owner": "@security",
        "rationale": "Compensating control in place.",
        "expires": "2027-01-01",
    }
    bare = _finding("bare", Severity.LOW)
    bare.status = FindingStatus.SUPPRESSED
    active = _finding("active", Severity.LOW)
    results = _run(render_sarif([accepted, bare, active]))["results"]
    assert results[0]["suppressions"] == [
        {
            "kind": "external",
            "status": "accepted",
            "justification": (
                "disposition: accepted-risk; rationale: Compensating control in "
                "place.; owner: @security; expires: 2027-01-01"
            ),
        }
    ]
    assert results[1]["suppressions"][0]["status"] == "accepted"
    assert results[1]["suppressions"][0]["justification"]
    assert "suppressions" not in results[2]


def test_report_writer_keeps_suppressed_findings_in_sarif_only(
    tmp_path: Path,
) -> None:
    accepted = _finding("accepted", Severity.HIGH)
    accepted.status = FindingStatus.SUPPRESSED
    active = _finding("active", Severity.LOW)
    written: dict[str, Any] = {}

    def capture(path: Path, value: Any) -> None:
        written[path.name] = value

    with (
        patch("py_security_suite.reports._write_text"),
        patch("py_security_suite.reports._write_json", side_effect=capture),
        patch("py_security_suite.reports.render_summary"),
        patch("py_security_suite.reports.render_action_plan"),
        patch("py_security_suite.reports.render_assurance_case"),
        patch("py_security_suite.reports.render_html"),
    ):
        _write_primary_report_files(
            tmp_path, MagicMock(), [accepted, active], [active], None
        )
    sarif_results = written["results.sarif"]["runs"][0]["results"]
    assert [item["properties"]["finding_id"] for item in sarif_results] == [
        "PYSEC-accepted",
        "PYSEC-active",
    ]
    assert sarif_results[0]["suppressions"][0]["kind"] == "external"
    assert len(written["sonarqube-external-issues.json"]["issues"]) == 1


def test_markdown_helpers_escape_table_pipes_exactly_once() -> None:
    assert _markdown_text("a|b") == "a\\|b"
    assert _markdown_code("a|b`c") == "a\\|b'c"
    assert _markdown_table("a|b") == "a\\|b"
    row = f"| {_markdown_text('x | y')} | `{_markdown_code('p|q')}` |"
    # Exactly three unescaped cell delimiters remain: the row's own.
    assert len(re.findall(r"(?<!\\)\|", row)) == 3
