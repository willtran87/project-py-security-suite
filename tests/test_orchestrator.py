from __future__ import annotations

import hashlib
import json
import tempfile
import tomllib
import unittest
from pathlib import Path
from unittest.mock import patch

from py_security_suite.adapters.base import AdapterResult, ScannerAdapter
from py_security_suite.config import load_config
from py_security_suite.models import (
    Citation,
    Confidence,
    Finding,
    FindingStatus,
    Inventory,
    Location,
    Outcome,
    ScanManifest,
    Severity,
    Source,
    ToolRun,
    ToolStatus,
)
from py_security_suite.orchestrator import (
    _runtime_evidence_paths,
    resolve_asset_paths,
    scan_project,
)
from py_security_suite.path_safety import HeldParentDirectory
from py_security_suite.passport import verify_report
from py_security_suite.reports import (
    _finding_priority,
    _finding_sort_key,
    _render_entrypoint_trust_actions,
    _register_report_artifacts,
    _safe_http_reference,
    render_action_plan,
    render_assurance_case,
    render_html,
    render_summary,
    write_reports,
)


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
                ),
                Citation(
                    kind="external",
                    identifier="unsafe-reference",
                    title="Unsafe reference",
                    uri="javascript:alert(1)",
                ),
            ],
        )
        run = ToolRun(
            tool=self.name,
            status=ToolStatus.COMPLETED,
            command=["bandit"],
            duration_seconds=0.01,
            version="bandit 1.9.4",
            finding_count=1,
            executable_sha256="a" * 64,
            executable_integrity_verified=None,
            executable_unchanged=True,
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
            executable_sha256="b" * 64,
            executable_integrity_verified=True,
            executable_unchanged=None,
        )
        return AdapterResult([], run, {"tool": self.name, "status": "completed"})


class MutatingSecrets(FakeSecrets):
    def run(self, target: Path) -> AdapterResult:
        target.chmod(0o700)
        (target / "scanner-created.py").write_text(
            "unexpected = True\n",
            encoding="utf-8",
        )
        return super().run(target)


class OrchestratorTests(unittest.TestCase):
    def test_report_order_uses_derived_priority(self) -> None:
        def finding(
            finding_id: str,
            severity: Severity,
            *,
            classifications: list[str] | None = None,
            evidence: dict[str, object] | None = None,
        ) -> Finding:
            return Finding(
                finding_id=finding_id,
                fingerprint=f"sha256:{finding_id}",
                title=finding_id,
                description="Fixture",
                impact="Fixture impact",
                remediation="Fixture remediation",
                severity=severity,
                confidence=Confidence.HIGH,
                area="fixture",
                classifications=classifications or [],
                evidence=evidence or {},
                blocking=True,
            )

        findings = [
            finding("HIGH", Severity.HIGH),
            finding(
                "KEV-LOW",
                Severity.LOW,
                evidence={"risk_intelligence": {"known_exploited": ["CVE"]}},
            ),
            finding(
                "EPSS-MEDIUM",
                Severity.MEDIUM,
                classifications=["EPSS-HIGH"],
            ),
            finding("MEDIUM", Severity.MEDIUM),
        ]

        ordered = sorted(findings, key=_finding_sort_key)
        self.assertEqual(
            [(item.finding_id, _finding_priority(item)) for item in ordered],
            [
                ("KEV-LOW", "P0"),
                ("HIGH", "P1"),
                ("EPSS-MEDIUM", "P1"),
                ("MEDIUM", "P2"),
            ],
        )

    def test_assurance_case_actions_follow_attached_evidence_and_findings(
        self,
    ) -> None:
        def complete(tool: str) -> ToolRun:
            return ToolRun(
                tool=tool,
                status=ToolStatus.COMPLETED,
                command=[tool],
                duration_seconds=0.01,
            )

        manifest = ScanManifest(
            schema_version="1.0",
            suite_version="0.1.0",
            scan_id="scan-assurance",
            target="fixture",
            profile="comprehensive",
            outcome=Outcome.PASS,
            started_at="2026-08-04T00:00:00Z",
            finished_at="2026-08-04T00:00:01Z",
            duration_seconds=1.0,
            network_policy="deny",
            network_isolation_attested=True,
            execute_target_code=False,
            inventory=Inventory(
                python_files=1,
                dependency_files=[],
                total_files=1,
                skipped_symlinks=0,
                vcs_history_available=True,
                source_sha256="a" * 64,
                source_sha256_after="a" * 64,
                source_integrity_verified=True,
                hashed_files=1,
                hashed_bytes=10,
            ),
            tools=[
                complete("coverage"),
                complete("junit"),
                complete("codeql"),
                ToolRun(
                    tool="pysa",
                    status=ToolStatus.SKIPPED,
                    command=[],
                    duration_seconds=0.0,
                    applicable=False,
                ),
                complete("hypothesis"),
                complete("cosign"),
                complete("trivy"),
                complete("scancode"),
            ],
            finding_counts={},
            policy_reasons=[],
        )

        clean = render_assurance_case(manifest, [])
        self.assertIn(
            "Coverage, changed-line coverage, and JUnit evidence passed", clean
        )
        self.assertIn("At least one applicable deep data-flow engine completed", clean)
        self.assertIn("applicable external evidence attached", clean)
        self.assertIn("Preserve the immutable commit identity", clean)
        self.assertNotIn("Generate branch-enabled coverage JSON", clean)

        artifact_finding = Finding(
            finding_id="PYSEC-COSIGN",
            fingerprint="sha256:cosign",
            title="Signature missing",
            description="Fixture",
            impact="Publisher identity is unavailable.",
            remediation="Attach the approved signature bundle.",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            area="artifact-provenance",
            domain="supply-chain",
            sources=[
                Source(
                    tool="cosign",
                    rule_id="COSIGN-BUNDLE-MISSING",
                    message="bundle missing",
                )
            ],
            locations=[Location(path="dist/fixture.whl")],
            evidence={
                "artifact_path": "dist/fixture.whl",
                "artifact_sha256": "c" * 64,
                "artifact_size_bytes": 1234,
                "owners": ["@release", "@security"],
            },
        )
        artifact_summary = render_summary(
            manifest,
            [artifact_finding],
            application_contracts={
                "routes": [{"method": "POST", "path": "/tenant"}],
                "generated_test_scenarios": [{"kind": "anonymous-deny"}],
                "vulnerable_call_matches": [],
            },
            code_health={"issues_detected": 2},
            static_architecture={
                "cycles_detected": 1,
                "policy_violations": [{"kind": "forbidden-edge"}],
            },
        )
        artifact_html = render_html(manifest, [artifact_finding])
        artifact_action_plan = render_action_plan(manifest, [artifact_finding])
        self.assertIn(
            "**Artifact identity evidence - `dist/fixture.whl`:**",
            artifact_summary,
        )
        self.assertIn(f"sha256:{'c' * 64}", artifact_summary)
        self.assertIn("size: 1234 bytes", artifact_summary)
        self.assertIn(
            "## Contextual security and engineering analysis", artifact_summary
        )
        self.assertIn("| Generated security test scenarios | 1 |", artifact_summary)
        self.assertIn(
            "| Declared architecture-policy violations | 1 |", artifact_summary
        )
        self.assertIn("Artifact identity evidence", artifact_html)
        self.assertIn("aria-label='Artifact identity'", artifact_html)
        self.assertIn("### Release artifact bindings", artifact_action_plan)
        self.assertIn(
            "**Finding ownership:** 1/1 findings assigned across 2 named owner queues; "
            "0 unassigned",
            artifact_action_plan,
        )
        self.assertIn("### Ownership work queues", artifact_action_plan)
        self.assertIn("| `@release` | 0 | 1 | 0 | 0 | 0 |", artifact_action_plan)
        self.assertIn("| `@security` | 0 | 1 | 0 | 0 | 0 |", artifact_action_plan)
        self.assertIn("Use these immutable identities", artifact_action_plan)
        self.assertIn(f"`sha256:{'c' * 64}`", artifact_action_plan)
        self.assertIn("1234 bytes", artifact_action_plan)
        artifact_finding.evidence["artifact_path"] = "../outside.whl"
        rejected_identity = render_summary(manifest, [artifact_finding])
        rejected_action_plan = render_action_plan(manifest, [artifact_finding])
        self.assertNotIn("Artifact identity evidence", rejected_identity)
        self.assertNotIn("### Release artifact bindings", rejected_action_plan)
        self.assertIn("No source excerpt applies", rejected_identity)
        artifact_finding.evidence["artifact_path"] = "dist/fixture.whl"
        actionable = render_assurance_case(manifest, [artifact_finding])
        self.assertIn(
            "Built artifact integrity and provenance | findings require action",
            actionable,
        )
        self.assertIn("resolve 1 active finding attributed to cosign", actionable)

        next(
            run for run in manifest.tools if run.tool == "cosign"
        ).status = ToolStatus.FAILED
        combined = render_assurance_case(manifest, [artifact_finding])
        self.assertIn(
            "Built artifact integrity and provenance | coverage gap; findings require action",
            combined,
        )
        self.assertIn(
            "restore every incomplete artifact control, and rerun. Also, Open",
            combined,
        )

        artifact_finding.status = FindingStatus.SUPPRESSED
        governed = render_assurance_case(manifest, [artifact_finding])
        self.assertNotIn("resolve 1 active finding attributed to cosign", governed)

        license_finding = Finding(
            finding_id="PYSEC-LICENSE",
            fingerprint="sha256:license",
            title="Restricted license",
            description="Fixture",
            impact="Distribution terms require review.",
            remediation="Apply the approved license policy.",
            severity=Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
            area="license-governance",
            domain="governance",
            sources=[
                Source(
                    tool="trivy",
                    rule_id="license/example",
                    message="restricted license",
                )
            ],
        )
        scoped = render_assurance_case(manifest, [license_finding])
        self.assertIn(
            "Deployment, IaC, and CI configuration | verified for scan scope",
            scoped,
        )
        self.assertIn(
            "License and source inventory | findings require action",
            scoped,
        )
        self.assertEqual(
            scoped.count("resolve 1 active finding attributed to trivy"),
            1,
        )

        manifest.tools[0].status = ToolStatus.UNAVAILABLE
        incomplete = render_assurance_case(manifest, [])
        self.assertIn("Automated test evidence | partial coverage", incomplete)
        self.assertIn("Generate branch-enabled coverage JSON", incomplete)

        manifest.outcome = Outcome.INCOMPLETE
        manifest.policy_reasons = ["External isolation attestation is absent."]
        action_plan = render_action_plan(manifest, [])
        self.assertIn(
            "Immediate next step:** Resolve the first blocking evidence gap: "
            "External isolation attestation is absent.",
            action_plan,
        )

    def test_entrypoint_trust_actions_cover_clean_changed_and_helper_states(
        self,
    ) -> None:
        self.assertIn(
            "Configure scanner entry points",
            "\n".join(_render_entrypoint_trust_actions([])),
        )

        clean = ToolRun(
            tool="clean-tool",
            status=ToolStatus.COMPLETED,
            command=["clean-tool"],
            duration_seconds=0.01,
            executable_sha256="a" * 64,
            executable_integrity_verified=True,
            executable_organization_approved=True,
            executable_unchanged=True,
        )
        self.assertIn(
            "All observed entry points",
            "\n".join(_render_entrypoint_trust_actions([clean])),
        )

        changed_helper = ToolRun(
            tool="changed-tool",
            status=ToolStatus.COMPLETED,
            command=["changed-tool"],
            duration_seconds=0.01,
            auxiliary_executable_sha256="b" * 64,
            auxiliary_executable_integrity_verified=True,
            auxiliary_executable_unchanged=False,
        )
        candidate = ToolRun(
            tool="candidate-tool",
            status=ToolStatus.COMPLETED,
            command=["candidate-tool"],
            duration_seconds=0.01,
            version="candidate 1.2.3",
            executable_sha256="c" * 64,
            executable_integrity_verified=None,
            executable_unchanged=True,
            auxiliary_executable_sha256="d" * 64,
            auxiliary_executable_integrity_verified=None,
            auxiliary_executable_unchanged=True,
        )
        rendered = "\n".join(
            _render_entrypoint_trust_actions([candidate, changed_helper])
        )
        self.assertIn("| P0 | changed-tool (helper) |", rendered)
        self.assertIn(f"`sha256:{'b' * 12}...`", rendered)
        self.assertIn("Quarantine the changed toolchain", rendered)
        self.assertLess(
            rendered.index("changed-tool"), rendered.index("candidate-tool")
        )
        self.assertIn("2 copy-ready digest approval candidates", rendered)
        self.assertIn("### Provenance review batches", rendered)
        self.assertIn(
            "2 candidate policy bindings map to 2 unique executable digests",
            rendered,
        )
        self.assertIn(
            f"| `sha256:{'c' * 64}` | `candidate 1.2.3` | `candidate-tool (primary)` |",
            rendered,
        )
        self.assertIn("### Copy-ready policy bindings", rendered)
        self.assertEqual(rendered.count("[tools.candidate-tool]"), 1)
        self.assertIn(f'executable_sha256 = "{"c" * 64}"', rendered)
        self.assertIn(f'auxiliary_executable_sha256 = "{"d" * 64}"', rendered)
        candidate_toml = rendered.split("```toml\n", 1)[1].split("```", 1)[0]
        parsed = tomllib.loads(candidate_toml)
        self.assertEqual(
            parsed["tools"]["candidate-tool"]["executable_sha256"], "c" * 64
        )
        shared_candidate = ToolRun(
            tool="shared-candidate",
            status=ToolStatus.COMPLETED,
            command=["shared-candidate"],
            duration_seconds=0.01,
            version="candidate 1.2.3",
            executable_sha256="c" * 64,
            executable_integrity_verified=None,
            executable_unchanged=True,
        )
        grouped = "\n".join(
            _render_entrypoint_trust_actions([candidate, shared_candidate])
        )
        self.assertIn(
            "3 candidate policy bindings map to 2 unique executable digests",
            grouped,
        )
        self.assertIn(
            f"| `sha256:{'c' * 64}` | `candidate 1.2.3` | "
            "`candidate-tool (primary)`, "
            "`shared-candidate (primary)` |",
            grouped,
        )

    def test_governed_asset_paths_are_resolved_without_losing_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory).resolve()
            config = load_config(profile_override="quick")
            tool = config.tools["bandit"]
            tool.rules_path = Path("rules.yml")
            tool.database_path = Path("database")
            tool.public_key_path = Path("release.pub")
            tool.artifacts_path = Path("dist")
            tool.provenance_path = Path("provenance")
            config.policy.risk_acceptance_path = Path("acceptances.json")
            config.reports.baseline_path = Path("baseline.json")
            config.intelligence.kev_path = Path("kev.json")
            config.intelligence.epss_path = Path("epss.csv")
            config.intelligence.vex_path = Path("vex.json")

            resolve_asset_paths(config, target)

            self.assertEqual(tool.rules_path, (target / "rules.yml").resolve())
            self.assertEqual(tool.database_path, (target / "database").resolve())
            self.assertEqual(tool.public_key_path, (target / "release.pub").resolve())
            self.assertEqual(tool.artifacts_path, (target / "dist").resolve())
            self.assertEqual(tool.provenance_path, (target / "provenance").resolve())
            self.assertEqual(
                config.policy.risk_acceptance_path,
                (target / "acceptances.json").resolve(),
            )
            self.assertEqual(
                config.reports.baseline_path, (target / "baseline.json").resolve()
            )
            self.assertEqual(
                config.intelligence.kev_path, (target / "kev.json").resolve()
            )
            self.assertEqual(
                config.intelligence.epss_path, (target / "epss.csv").resolve()
            )
            self.assertEqual(
                config.intelligence.vex_path, (target / "vex.json").resolve()
            )

    def test_runtime_evidence_and_binding_sidecars_are_excluded_from_source_snapshot(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory).resolve()
            config = load_config(profile_override="quality")

            resolve_asset_paths(config, target)
            excluded = set(_runtime_evidence_paths(config, list(config.selected_tools)))

            coverage = (target / "coverage.json").resolve()
            junit = (target / "junit.xml").resolve()
            self.assertIn(coverage, excluded)
            self.assertIn(
                coverage.with_name("coverage.json.pysec-binding.json"), excluded
            )
            self.assertIn(junit, excluded)
            self.assertIn(junit.with_name("junit.xml.pysec-binding.json"), excluded)

    def test_governed_asset_paths_reject_linked_parent_components(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory).resolve()
            linked_parent = target / "linked-parent"
            config = load_config(profile_override="quick")
            config.tools["bandit"].rules_path = Path("linked-parent/rules.yml")

            with patch(
                "py_security_suite.path_safety.is_link_like",
                side_effect=lambda path: path == linked_parent,
            ):
                with self.assertRaisesRegex(
                    ValueError,
                    "cannot contain a symbolic link or junction",
                ):
                    resolve_asset_paths(config, target)

    def test_portable_bundle_references_resolve_below_governed_root(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory).resolve()
            config = load_config(profile_override="quick")
            config.paths.bundle_root = Path("vendor/security")
            tool = config.tools["bandit"]
            tool.executable = "@bundle/bin/bandit.exe"
            tool.auxiliary_executable = "@bundle/bin/helper.exe"
            tool.rules_path = Path("@bundle/rules/bandit.yml")
            config.intelligence.kev_path = Path("@bundle/intelligence/kev.json")

            resolve_asset_paths(config, target)

            bundle = (target / "vendor/security").resolve()
            self.assertEqual(config.paths.bundle_root, bundle)
            self.assertEqual(tool.executable, str(bundle / "bin/bandit.exe"))
            self.assertEqual(tool.auxiliary_executable, str(bundle / "bin/helper.exe"))
            self.assertEqual(tool.rules_path, bundle / "rules/bandit.yml")
            self.assertEqual(
                config.intelligence.kev_path,
                bundle / "intelligence/kev.json",
            )

    def test_portable_bundle_references_reject_escape(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory).resolve()
            config = load_config(profile_override="quick")
            config.tools["bandit"].executable = "@bundle/../outside/bandit"

            with self.assertRaisesRegex(ValueError, "cannot traverse"):
                resolve_asset_paths(config, target)

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
                "portfolio-health.json",
                "source-inventory.json",
                "admission-decisions.json",
                "scanner-trust.json",
                "isolation-attestation.json",
                "intelligence-approval.json",
            ):
                self.assertTrue((output / name).is_file(), name)
            findings = json.loads((output / "findings.json").read_text("utf-8"))
            manifest = json.loads((output / "scan-manifest.json").read_text("utf-8"))
            source_inventory = json.loads(
                (output / "source-inventory.json").read_text("utf-8")
            )
            passport = json.loads(
                (output / "security-passport.json").read_text("utf-8")
            )
            self.assertEqual(findings["outcome"], "fail")
            self.assertEqual(manifest["outcome"], "fail")
            self.assertEqual(
                source_inventory["source_sha256"],
                manifest["inventory"]["source_sha256"],
            )
            self.assertEqual(passport["predicate"]["verificationResult"], "FAILED")
            with self.assertRaisesRegex(FileExistsError, "already exists"):
                write_reports(
                    output=output,
                    findings=result.findings,
                    manifest=result.manifest,
                    diagnostics={},
                    include_evidence=False,
                )
            self.assertTrue(verify_report(output)["verified"])
            for reserved in ("summary", "findings", "manifest"):
                with (
                    self.subTest(reserved=reserved),
                    self.assertRaisesRegex(ValueError, "reserved derived artifact"),
                ):
                    _register_report_artifacts(
                        result.manifest,
                        {reserved: {"unexpected": True}},
                    )
            with self.assertRaisesRegex(ValueError, "source-inventory.json"):
                _register_report_artifacts(result.manifest, {})
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
            self.assertIn("## Admission decisions by evidence axis", markdown)
            self.assertIn(r"| Built artifacts | **NOT\_APPLICABLE** |", markdown)
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
            self.assertIn("**Scanner entry-point trust:**", markdown)
            self.assertIn("Entry-point integrity", markdown)
            self.assertIn("# Security action plan", action_plan)
            self.assertIn(
                "| Risk | Lifecycle | Finding | Domain / area | Location | "
                "Evidence | Owner | Action |",
                action_plan,
            )
            self.assertIn("| P1 / high | new |", action_plan)
            self.assertIn("security / injection", action_plan)
            self.assertIn("Source: bandit/B602; Class: [CWE-78]", action_plan)
            self.assertIn("Reference: [B602 -", action_plan)
            self.assertIn("| Unassigned |", action_plan)
            self.assertIn(
                "**Finding ownership:** 0/1 findings assigned across 0 named owner "
                "queues; 1 unassigned",
                action_plan,
            )
            self.assertIn("### Ownership work queues", action_plan)
            self.assertIn("| **Unassigned** | 0 | 1 | 0 | 0 | 0 | 1 | 1 |", action_plan)
            self.assertIn("bandit/B602", action_plan)
            self.assertIn("](index.html#PYSEC-", action_plan)
            self.assertIn("## Policy and release-evidence actions", action_plan)
            self.assertIn("## Scanner entry-point trust actions", action_plan)
            self.assertIn("### Provenance review batches", action_plan)
            self.assertIn("Independently verify provenance", action_plan)
            self.assertIn("2 approval gaps; 1 post-execution gap", action_plan)
            self.assertIn(
                "Approval review workload:** 1 candidate binding across 1 unique",
                action_plan,
            )
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
            self.assertIn("Admission decisions by evidence axis", report_html)
            self.assertIn("Source and architecture", report_html)
            self.assertIn("Entrypoints approved", report_html)
            self.assertIn("Entrypoints unchanged", report_html)
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
            self.assertNotIn("javascript:alert", markdown)
            self.assertNotIn("javascript:alert", report_html)
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
            actionable, informational = prioritized_plan.split(
                "<details><summary>1 not-applicable controls", 1
            )
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

    def test_report_reference_links_reject_ambiguous_destinations(self) -> None:
        valid = "https://example.test/reference?id=1#section"
        self.assertEqual(_safe_http_reference(valid), valid)
        for unsafe in (
            "javascript:alert(1)",
            "https://example.test/path_(ambiguous)",
            "https://example.test/line\nbreak",
            "https://user@example.test/reference",
            "https://example.test:not-a-port/reference",
            "https://[invalid/reference",
            "https:///missing-host",
            "https://example.test/" + "x" * 2048,
        ):
            with self.subTest(unsafe=unsafe[:80]):
                self.assertIsNone(_safe_http_reference(unsafe))

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

    def test_report_publication_is_atomic_and_cleans_failed_staging(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "project"
            target.mkdir()
            config = load_config(profile_override="quick")
            failed_output = root / "failed-report"
            with (
                patch(
                    "py_security_suite.reports.render_html",
                    side_effect=RuntimeError("fixture rendering failure"),
                ),
                self.assertRaisesRegex(RuntimeError, "fixture rendering failure"),
            ):
                scan_project(
                    target=target,
                    output=failed_output,
                    config=config,
                    network_isolation_attested=False,
                )
            self.assertFalse(failed_output.exists())
            self.assertEqual(list(root.glob(".failed-report.staging-*")), [])

            collided_output = root / "collided-report"

            def create_collision(*_args: object, **_kwargs: object) -> str:
                collided_output.mkdir()
                return "<!doctype html><title>Fixture</title>"

            with (
                patch(
                    "py_security_suite.reports.render_html",
                    side_effect=create_collision,
                ),
                self.assertRaisesRegex(FileExistsError, "appeared during generation"),
            ):
                scan_project(
                    target=target,
                    output=collided_output,
                    config=load_config(profile_override="quick"),
                    network_isolation_attested=False,
                )
            self.assertTrue(collided_output.is_dir())
            self.assertEqual(list(root.glob(".collided-report.staging-*")), [])

            invalid_output = root / "invalid-report"

            def write_invalid_checksums(staging: Path) -> None:
                (staging / "checksums.sha256").write_text(
                    f"{'0' * 64}  summary.md\n",
                    encoding="utf-8",
                    newline="\n",
                )

            with (
                patch(
                    "py_security_suite.reports._write_checksums",
                    side_effect=write_invalid_checksums,
                ),
                self.assertRaisesRegex(ValueError, "checksum mismatch"),
            ):
                scan_project(
                    target=target,
                    output=invalid_output,
                    config=load_config(profile_override="quick"),
                    network_isolation_attested=False,
                )
            self.assertFalse(invalid_output.exists())
            self.assertEqual(list(root.glob(".invalid-report.staging-*")), [])

            replacement_file = root / "replacement-file"
            replacement_file.write_text("preserve me", encoding="utf-8")
            with self.assertRaisesRegex(
                FileExistsError,
                "not a replaceable directory",
            ):
                scan_project(
                    target=target,
                    output=replacement_file,
                    config=load_config(profile_override="quick"),
                    network_isolation_attested=False,
                    replace_existing=True,
                )
            self.assertEqual(
                replacement_file.read_text(encoding="utf-8"),
                "preserve me",
            )

            unverified_output = root / "unverified-output"
            unverified_output.mkdir()
            user_file = unverified_output / "user-data.txt"
            user_file.write_text("preserve me", encoding="utf-8")
            with self.assertRaisesRegex(
                FileExistsError,
                "not a complete verified suite report",
            ):
                scan_project(
                    target=target,
                    output=unverified_output,
                    config=load_config(profile_override="quick"),
                    network_isolation_attested=False,
                    replace_existing=True,
                )
            self.assertEqual(user_file.read_text(encoding="utf-8"), "preserve me")

            replaced_output = root / "replaced-report"
            first = scan_project(
                target=target,
                output=replaced_output,
                config=load_config(profile_override="quick"),
                network_isolation_attested=False,
            )
            original_checksums = (replaced_output / "checksums.sha256").read_bytes()
            with (
                patch(
                    "py_security_suite.reports.render_html",
                    side_effect=RuntimeError("replacement rendering failure"),
                ),
                self.assertRaisesRegex(RuntimeError, "replacement rendering failure"),
            ):
                scan_project(
                    target=target,
                    output=replaced_output,
                    config=load_config(profile_override="quick"),
                    network_isolation_attested=False,
                    replace_existing=True,
                )
            self.assertEqual(
                (replaced_output / "checksums.sha256").read_bytes(),
                original_checksums,
            )
            self.assertEqual(
                verify_report(replaced_output)["scan_id"], first.manifest.scan_id
            )

            original_rename = HeldParentDirectory.rename

            def fail_staging_rename(
                held_parent: HeldParentDirectory,
                source: Path,
                target_path: Path,
            ) -> None:
                if source.name.startswith(".replaced-report.staging-"):
                    raise OSError("replacement publication failure")
                original_rename(held_parent, source, target_path)

            with (
                patch.object(HeldParentDirectory, "rename", fail_staging_rename),
                self.assertRaisesRegex(OSError, "publication failure"),
            ):
                scan_project(
                    target=target,
                    output=replaced_output,
                    config=load_config(profile_override="quick"),
                    network_isolation_attested=False,
                    replace_existing=True,
                )
            self.assertEqual(
                (replaced_output / "checksums.sha256").read_bytes(),
                original_checksums,
            )
            self.assertEqual(
                verify_report(replaced_output)["scan_id"], first.manifest.scan_id
            )

            publication_lock = root / ".replaced-report.publish-lock"
            publication_lock.mkdir()
            with self.assertRaisesRegex(
                FileExistsError,
                "already active or requires recovery",
            ):
                scan_project(
                    target=target,
                    output=replaced_output,
                    config=load_config(profile_override="quick"),
                    network_isolation_attested=False,
                    replace_existing=True,
                )
            self.assertEqual(
                (replaced_output / "checksums.sha256").read_bytes(),
                original_checksums,
            )
            self.assertEqual(
                verify_report(replaced_output)["scan_id"], first.manifest.scan_id
            )
            publication_lock.rmdir()

            second = scan_project(
                target=target,
                output=replaced_output,
                config=load_config(profile_override="quick"),
                network_isolation_attested=False,
                replace_existing=True,
            )
            self.assertNotEqual(second.manifest.scan_id, first.manifest.scan_id)
            self.assertEqual(
                verify_report(replaced_output)["scan_id"], second.manifest.scan_id
            )
            self.assertEqual(list(root.glob(".replaced-report.staging-*")), [])
            self.assertEqual(list(root.glob(".replaced-report.backup-*")), [])
            self.assertFalse(publication_lock.exists())

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
            self.assertEqual(
                result.manifest.inventory.source_sha256,
                result.manifest.inventory.source_sha256_after,
            )
            self.assertIn(
                "target content changed during scanner execution",
                " ".join(result.manifest.policy_reasons),
            )


if __name__ == "__main__":
    unittest.main()
