from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from py_security_suite.adapters.base import AdapterResult, ScannerAdapter
from py_security_suite.config import load_config
from py_security_suite.models import (
    Citation,
    Confidence,
    Finding,
    Location,
    Outcome,
    Severity,
    Source,
    ToolRun,
    ToolStatus,
)
from py_security_suite.orchestrator import scan_project
from py_security_suite.passport import verify_report
from py_security_suite.reports import render_action_plan, render_html, render_summary


class FakeBandit(ScannerAdapter):
    name = "bandit"

    def build_command(self, executable: str, target: Path) -> list[str]:
        return []

    def parse(self, payload: str, target: Path) -> list[Finding]:
        return []

    def run(self, target: Path) -> AdapterResult:
        finding = Finding(
            finding_id="PYSEC-FAKE",
            fingerprint="sha256:fake",
            title="Fake high finding <script>alert(1)</script>",
            description="Fixture",
            impact="Untrusted command input could execute with application privileges.",
            remediation="Pass a validated argument vector and avoid a shell.",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            area="injection",
            classifications=["CWE-78"],
            locations=[Location(path="app.py", start_line=7, end_line=7)],
            sources=[
                Source(
                    tool="bandit",
                    version="bandit 1.9.4",
                    rule_id="B602",
                    message="subprocess with shell=True",
                    native_severity="HIGH",
                )
            ],
            citations=[
                Citation(
                    kind="tool_rule",
                    identifier="B602",
                    title="subprocess_popen_with_shell_equals_true",
                    uri=(
                        "https://bandit.readthedocs.io/en/1.9.4/plugins/"
                        "b602_subprocess_popen_with_shell_equals_true.html"
                    ),
                )
            ],
        )
        run = ToolRun(
            tool=self.name,
            status=ToolStatus.COMPLETED,
            command=["bandit"],
            duration_seconds=0.01,
            version="bandit 1.9.4",
            finding_count=1,
        )
        return AdapterResult([finding], run, {"tool": self.name, "status": "completed"})


class FakeSecrets(FakeBandit):
    name = "detect-secrets"

    def run(self, target: Path) -> AdapterResult:
        run = ToolRun(
            tool=self.name,
            status=ToolStatus.COMPLETED,
            command=["detect-secrets"],
            duration_seconds=0.01,
        )
        return AdapterResult([], run, {"tool": self.name, "status": "completed"})


class MutatingSecrets(FakeSecrets):
    def run(self, target: Path) -> AdapterResult:
        (target / "scanner-created.py").write_text(
            "unexpected = True\n",
            encoding="utf-8",
        )
        return super().run(target)


class OrchestratorTests(unittest.TestCase):
    def test_end_to_end_report_is_coordinated(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "project"
            target.mkdir()
            (target / "app.py").write_text(
                "\n".join(
                    [
                        "import subprocess",
                        "",
                        "def run_command():",
                        "    command = 'echo safe'",
                        "    # context before",
                        "    # context before",
                        "    subprocess.run(command, shell=True)  # <source-tag>",
                        "    # context after",
                        "    # context after",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            output = root / "report"
            result = scan_project(
                target=target,
                output=output,
                config=load_config(profile_override="quick"),
                network_isolation_attested=True,
                adapter_types={
                    "bandit": FakeBandit,
                    "detect-secrets": FakeSecrets,
                },
            )
            self.assertEqual(result.outcome, Outcome.FAIL)
            for name in (
                "summary.md",
                "action-plan.md",
                "assurance-case.md",
                "index.html",
                "results.sarif",
                "sonarqube-external-issues.json",
                "findings.json",
                "scan-manifest.json",
                "checksums.sha256",
                "security-passport.json",
                "risk-intelligence.json",
                "finding-delta.json",
                "effectiveness.json",
                "assurance-claims.json",
            ):
                self.assertTrue((output / name).is_file(), name)
            findings = json.loads((output / "findings.json").read_text("utf-8"))
            manifest = json.loads((output / "scan-manifest.json").read_text("utf-8"))
            passport = json.loads(
                (output / "security-passport.json").read_text("utf-8")
            )
            self.assertEqual(findings["outcome"], "fail")
            self.assertEqual(manifest["outcome"], "fail")
            self.assertEqual(passport["predicate"]["verificationResult"], "FAILED")
            self.assertTrue(verify_report(output)["verified"])
            self.assertTrue(manifest["inventory"]["source_integrity_verified"])
            self.assertEqual(
                manifest["inventory"]["source_sha256"],
                manifest["inventory"]["source_sha256_after"],
            )
            markdown = (output / "summary.md").read_text("utf-8")
            action_plan = (output / "action-plan.md").read_text("utf-8")
            assurance_case = (output / "assurance-case.md").read_text("utf-8")
            report_html = (output / "index.html").read_text("utf-8")
            self.assertIn(r"Fake high finding \<script\>", markdown)
            self.assertIn("## Findings by domain", markdown)
            self.assertIn("`security` / `injection`", markdown)
            self.assertIn("## Findings by area", markdown)
            self.assertIn(
                "**Found by:** `bandit 1.9.4` rule `B602`",
                markdown,
            )
            self.assertIn(
                "[CWE-78](https://cwe.mitre.org/data/definitions/78.html)",
                markdown,
            )
            self.assertIn("**Why it matters:**", markdown)
            self.assertIn("**Recommended action:**", markdown)
            self.assertIn("**What was detected:**", markdown)
            self.assertIn("**Source evidence - `app.py:7`:**", markdown)
            self.assertIn(">     7 |     subprocess.run", markdown)
            self.assertIn("```python", markdown)
            self.assertIn("**Priority:** `P1`", markdown)
            self.assertIn("## Coverage gaps and actions", markdown)
            self.assertIn("**Target content integrity:** verified unchanged", markdown)
            self.assertIn("Entry-point integrity", markdown)
            self.assertIn("# Security action plan", action_plan)
            self.assertIn("bandit/B602", action_plan)
            self.assertIn("](index.html#PYSEC-", action_plan)
            self.assertIn("## Policy and release-evidence actions", action_plan)
            self.assertIn("**Scan-policy disposition:** `BLOCK`", action_plan)
            self.assertIn("# Production security assurance case", assurance_case)
            self.assertIn("Built artifact integrity and provenance", assurance_case)
            self.assertIn("Dynamic, API, and runtime behavior", assurance_case)
            self.assertIn("Target content integrity", assurance_case)
            self.assertIn("Scanner entry-point integrity", assurance_case)
            self.assertIn("Open the prioritized action plan", report_html)
            self.assertIn(
                'Decision: <span class="decision-badge block">BLOCK</span>',
                report_html,
            )
            self.assertIn("Open the production assurance case", report_html)
            self.assertIn("What was detected", report_html)
            self.assertIn("Prioritized findings", report_html)
            self.assertIn("Source evidence", report_html)
            self.assertIn("code-line highlight", report_html)
            self.assertIn("&lt;source-tag&gt;", report_html)
            self.assertNotIn("<script>alert(1)</script>", report_html)
            self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", report_html)
            self.assertIn("Found by", report_html)
            self.assertIn("Why it matters", report_html)
            self.assertIn("Recommended action", report_html)
            self.assertIn(
                "https://cwe.mitre.org/data/definitions/78.html",
                report_html,
            )
            for line in (output / "checksums.sha256").read_text("utf-8").splitlines():
                expected, relative = line.split("  ", 1)
                self.assertEqual(
                    hashlib.sha256((output / relative).read_bytes()).hexdigest(),
                    expected,
                )
            sarif = json.loads((output / "results.sarif").read_text("utf-8"))
            sonar = json.loads(
                (output / "sonarqube-external-issues.json").read_text("utf-8")
            )
            self.assertEqual(sonar["issues"][0]["engineId"], "py-security-suite")
            self.assertEqual(
                sonar["issues"][0]["primaryLocation"]["filePath"], "app.py"
            )
            self.assertEqual(sarif["version"], "2.1.0")
            rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
            sarif_result = sarif["runs"][0]["results"][0]
            self.assertEqual(
                rule["helpUri"],
                (
                    "https://bandit.readthedocs.io/en/1.9.4/plugins/"
                    "b602_subprocess_popen_with_shell_equals_true.html"
                ),
            )
            self.assertEqual(
                sarif_result["properties"]["classifications"],
                ["CWE-78"],
            )
            self.assertEqual(
                sarif_result["properties"]["source_rules"][0]["tool"],
                "bandit",
            )
            self.assertEqual(sarif_result["properties"]["priority"], "P1")
            self.assertEqual(sarif_result["properties"]["domain"], "security")
            physical = sarif_result["locations"][0]["physicalLocation"]
            self.assertIn("subprocess.run", physical["region"]["snippet"]["text"])
            self.assertEqual(physical["contextRegion"]["startLine"], 5)

            result.manifest.tools.extend(
                [
                    ToolRun(
                        tool="required-offline",
                        status=ToolStatus.UNAVAILABLE,
                        command=["required-offline"],
                        duration_seconds=0.0,
                        error="approved executable is missing",
                    ),
                    ToolRun(
                        tool="conditional-offline",
                        status=ToolStatus.SKIPPED,
                        command=["conditional-offline"],
                        duration_seconds=0.0,
                        error="no matching project content was found",
                        applicable=False,
                    ),
                ]
            )
            prioritized_summary = render_summary(result.manifest, result.findings)
            prioritized_plan = render_action_plan(result.manifest, result.findings)
            prioritized_html = render_html(result.manifest, result.findings)
            self.assertIn("Applicable scanner execution gaps:** 1", prioritized_summary)
            self.assertIn("Conditional controls not applicable: 1", prioritized_summary)
            self.assertIn("<summary>1 not-applicable controls", prioritized_summary)
            actionable, informational = prioritized_plan.split("<details>", 1)
            self.assertIn("required-offline", actionable)
            self.assertNotIn("conditional-offline", actionable)
            self.assertIn("conditional-offline", informational)
            self.assertIn("Applicable completed", prioritized_html)
            self.assertIn("Execution gaps", prioritized_html)
            self.assertIn("Not applicable", prioritized_html)
            self.assertIn("1 not-applicable controls", prioritized_html)
            coverage_section = prioritized_html.split(
                "<h2>Coverage gaps and actions</h2>", 1
            )[1]
            html_actionable, html_informational = coverage_section.split(
                "<details class='coverage-details'>", 1
            )
            self.assertIn("required-offline", html_actionable)
            self.assertNotIn("conditional-offline", html_actionable)
            self.assertIn("conditional-offline", html_informational)
            result.manifest.artifacts = {}
            self.assertNotIn(
                "## Derived assurance evidence",
                render_summary(result.manifest, result.findings),
            )

    def test_missing_isolation_attestation_still_writes_incomplete_report(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "project"
            target.mkdir()
            output = root / "report"
            result = scan_project(
                target=target,
                output=output,
                config=load_config(profile_override="quick"),
                network_isolation_attested=False,
            )
            self.assertEqual(result.outcome, Outcome.INCOMPLETE)
            self.assertTrue((output / "summary.md").is_file())
            self.assertIn(
                "do not interpret this result as clean",
                (output / "summary.md").read_text("utf-8"),
            )

    def test_unisolated_diagnostic_runs_tools_but_remains_incomplete(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "project"
            target.mkdir()
            (target / "app.py").write_text("print('hello')\n", encoding="utf-8")
            output = root / "report"
            result = scan_project(
                target=target,
                output=output,
                config=load_config(profile_override="quick"),
                network_isolation_attested=False,
                diagnostic_without_isolation=True,
                adapter_types={
                    "bandit": FakeBandit,
                    "detect-secrets": FakeSecrets,
                },
            )
            self.assertEqual(result.outcome, Outcome.INCOMPLETE)
            self.assertTrue(result.manifest.diagnostic_without_isolation)
            self.assertTrue(
                all(run.status is ToolStatus.COMPLETED for run in result.tool_runs)
            )

    def test_target_mutation_during_scan_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "project"
            target.mkdir()
            (target / "app.py").write_text("print('hello')\n", encoding="utf-8")
            result = scan_project(
                target=target,
                output=root / "report",
                config=load_config(profile_override="quick"),
                network_isolation_attested=True,
                adapter_types={
                    "bandit": FakeBandit,
                    "detect-secrets": MutatingSecrets,
                },
            )

            self.assertEqual(result.outcome, Outcome.INCOMPLETE)
            self.assertFalse(result.manifest.inventory.source_integrity_verified)
            self.assertNotEqual(
                result.manifest.inventory.source_sha256,
                result.manifest.inventory.source_sha256_after,
            )
            self.assertIn(
                "target content changed during scanner execution",
                " ".join(result.manifest.policy_reasons),
            )


if __name__ == "__main__":
    unittest.main()
