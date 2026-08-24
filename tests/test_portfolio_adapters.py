from __future__ import annotations

import json
import hashlib
import tempfile
import unittest
from pathlib import Path

from py_security_suite.strict_json import canonical_bytes

from py_security_suite.adapters.assurance_evidence import (
    BrowserSecurityAdapter,
    AuthorizationSecurityAdapter,
    ClusterFuzzLiteAdapter,
    CrossHairAdapter,
    FalcoAdapter,
    IastAdapter,
    InTotoAdapter,
    KubescapeAdapter,
    MobSfAdapter,
    NativeSanitizersAdapter,
    NucleiAdapter,
    PolyglotAdapter,
    ProwlerAdapter,
    RaspAdapter,
    TlsScanAdapter,
    OciImageAdapter,
    PyTmAdapter,
    ReproducibleBuildAdapter,
    SurfaceInventoryAdapter,
    YaraAdapter,
    ZapAdapter,
)
from py_security_suite.adapters.test_evidence import (
    HypothesisAdapter,
    SchemathesisAdapter,
)
from py_security_suite.adapters.portfolio import (
    ConftestAdapter,
    GitSizerAdapter,
    KicsAdapter,
    KubeLinterAdapter,
    PipdeptreeAdapter,
    ValeAdapter,
    ValidatePyprojectAdapter,
    _concern_metrics,
    _integer,
    _number,
)
from py_security_suite.config import ToolConfig
from py_security_suite.evidence_ingest import _assurance_document, _bind_evidence
from py_security_suite.reports import render_sonarqube_external_issues


class PortfolioAdapterTests(unittest.TestCase):
    def test_local_policy_adapters_are_explicit_about_applicability(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy = root / "policy"
            policy.mkdir()
            config_file = root / ".vale.ini"
            config_file.write_text("StylesPath = styles\n", encoding="utf-8")
            conftest = ConftestAdapter(ToolConfig(rules_path=policy), 4096)
            kics = KicsAdapter(ToolConfig(rules_path=policy), 4096)
            vale = ValeAdapter(ToolConfig(rules_path=config_file), 4096)

            self.assertIn(
                "structured configuration", conftest.not_applicable_reason(root) or ""
            )
            self.assertIn(
                "infrastructure-as-code", kics.not_applicable_reason(root) or ""
            )
            self.assertIn("documentation", vale.not_applicable_reason(root) or "")

            (root / "service.toml").write_text("enabled = true\n", encoding="utf-8")
            (root / "deploy.yaml").write_text(
                "apiVersion: v1\nkind: Pod\n", encoding="utf-8"
            )
            (root / "README.md").write_text("# Service\n", encoding="utf-8")
            self.assertIsNone(conftest.not_applicable_reason(root))
            self.assertIsNone(kics.not_applicable_reason(root))
            self.assertIsNone(vale.not_applicable_reason(root))
            self.assertIn("--policy", conftest.build_command("conftest", root))
            self.assertIn(
                "--queries-path",
                kics.build_file_command("kics", root, root / "out" / "results.json"),
            )
            self.assertIn("--config", vale.build_command("vale", root))
            self.assertEqual(conftest.environment().extra["NO_COLOR"], "1")

    def test_policy_adapters_reject_missing_local_rules(self) -> None:
        root = Path(".")
        conftest = ConftestAdapter(ToolConfig(), 4096)
        kics = KicsAdapter(ToolConfig(), 4096)
        vale = ValeAdapter(ToolConfig(), 4096)
        self.assertIn("policy directory", conftest.not_applicable_reason(root) or "")
        self.assertIn("query library", kics.not_applicable_reason(root) or "")
        self.assertIn("Vale configuration", vale.not_applicable_reason(root) or "")
        with self.assertRaisesRegex(ValueError, "local policy"):
            conftest.build_command("conftest", root)
        with self.assertRaisesRegex(ValueError, "query library"):
            kics.build_file_command("kics", root, root / "results.json")
        with self.assertRaisesRegex(ValueError, "configuration"):
            vale.build_command("vale", root)

    def test_kics_normalizes_location_classification_and_tool_citation(self) -> None:
        payload = json.dumps(
            {
                "queries": [
                    {
                        "query_name": "Privileged container",
                        "query_id": "abc-123",
                        "severity": "HIGH",
                        "platform": "Kubernetes",
                        "cwe": "250",
                        "description": "Container grants excessive privilege",
                        "files": [
                            {
                                "file_name": "deploy/pod.yaml",
                                "line": 14,
                                "issue_type": "IncorrectValue",
                                "expected_value": "privileged=false",
                                "actual_value": "privileged=true",
                            }
                        ],
                    }
                ]
            }
        )
        finding = KicsAdapter(ToolConfig(), 4096).parse(payload, Path("."))[0]
        self.assertEqual(finding.sources[0].tool, "kics")
        self.assertEqual(finding.locations[0].start_line, 14)
        self.assertIn("CWE-250", finding.classifications)
        self.assertEqual(finding.severity.value, "high")

    def test_pipdeptree_health_summary_creates_actionable_findings(self) -> None:
        payload = json.dumps(
            {
                "missing_dependencies": 1,
                "cyclic_dependencies": 2,
                "conflicting_dependencies": {"packages": 1, "edges": 3},
            }
        )
        findings = PipdeptreeAdapter(ToolConfig(), 4096).parse(payload, Path("."))
        self.assertEqual(len(findings), 3)
        self.assertTrue(all(item.domain == "supply-chain" for item in findings))

    def test_pipdeptree_preflight_command_artifact_and_validation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            adapter = PipdeptreeAdapter(ToolConfig(), 4096)
            self.assertIn("target Python", adapter.not_applicable_reason(root) or "")
            configured = PipdeptreeAdapter(
                ToolConfig(auxiliary_executable="python-approved"), 4096
            )
            self.assertIn("pyproject", configured.not_applicable_reason(root) or "")
            (root / "pyproject.toml").write_text(
                "[project]\nname='x'\n", encoding="utf-8"
            )
            self.assertIsNone(configured.not_applicable_reason(root))
            command = configured.build_command("pipdeptree", root)
            self.assertEqual(command[1:3], ["--python", "python-approved"])
            self.assertEqual(
                configured.derived_artifacts(
                    json.dumps(
                        {
                            "total_packages": 1,
                            "direct_dependencies": 1,
                            "transitive_dependencies": 0,
                            "max_depth": 1,
                            "missing_dependencies": 0,
                            "cyclic_dependencies": 0,
                            "conflicting_dependencies": {"packages": 0, "edges": 0},
                        }
                    ),
                    root,
                )["pipdeptree-summary.json"]["total_packages"],
                1,
            )
            with self.assertRaisesRegex(TypeError, "must be an object"):
                configured.parse("[]", root)

    def test_git_sizer_recurses_over_v2_concern_metrics(self) -> None:
        payload = json.dumps(
            {
                "maxBlobSize": {
                    "description": "largest blob",
                    "value": 50_000_000,
                    "levelOfConcern": 2,
                }
            }
        )
        finding = GitSizerAdapter(ToolConfig(), 4096).parse(payload, Path("."))[0]
        self.assertEqual(finding.area, "repository-health")
        self.assertEqual(finding.severity.value, "medium")

    def test_git_sizer_handles_nested_lists_low_concern_and_repository_state(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            adapter = GitSizerAdapter(ToolConfig(), 4096)
            self.assertIn(
                "not a full Git checkout", adapter.not_applicable_reason(root) or ""
            )
            (root / ".git").mkdir()
            self.assertIsNone(adapter.not_applicable_reason(root))
            self.assertEqual(
                adapter.build_command("git-sizer", root)[1:],
                ["--json", "--json-version", "2"],
            )
            payload = json.dumps(
                {
                    "history": [
                        {"description": "branches", "value": 9, "level_of_concern": 1},
                        {"description": "healthy", "value": 1, "levelOfConcern": 0},
                    ]
                }
            )
            findings = adapter.parse(payload, root)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].severity.value, "low")
            self.assertEqual(
                adapter.derived_artifacts(payload, root)["git-sizer.json"]["metrics"][
                    0
                ]["value"],
                "9",
            )
            with self.assertRaisesRegex(TypeError, "must be an object"):
                adapter.parse("[]", root)
            self.assertEqual(_concern_metrics("not-a-metric"), [])

    def test_validate_pyproject_distinguishes_valid_json_from_invalid_text(
        self,
    ) -> None:
        adapter = ValidatePyprojectAdapter(ToolConfig(), 4096)
        self.assertEqual(adapter.parse('{"project":{"name":"demo"}}', Path(".")), [])
        finding = adapter.parse("Invalid file: pyproject.toml", Path("."))[0]
        self.assertEqual(finding.locations[0].path, "pyproject.toml")

    def test_validate_pyproject_preflight_environment_and_type_guard(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            adapter = ValidatePyprojectAdapter(ToolConfig(), 4096)
            self.assertIn("no pyproject", adapter.not_applicable_reason(root) or "")
            (root / "pyproject.toml").write_text(
                "[project]\nname='x'\n", encoding="utf-8"
            )
            self.assertIsNone(adapter.not_applicable_reason(root))
            self.assertEqual(
                adapter.environment().extra["VALIDATE_PYPROJECT_NO_NETWORK"], "1"
            )
            self.assertEqual(
                adapter.build_command("validate-pyproject", root)[1], "--dump-json"
            )
            invalid = adapter.parse("[]", root)
            self.assertEqual(invalid[0].sources[0].tool, "validate-pyproject")

    def test_vale_preserves_file_line_and_rule(self) -> None:
        payload = json.dumps(
            {
                "README.md": [
                    {
                        "Check": "Docs.Weasel",
                        "Line": 9,
                        "Severity": "warning",
                        "Message": "Avoid vague language",
                    }
                ]
            }
        )
        finding = ValeAdapter(ToolConfig(), 4096).parse(payload, Path("."))[0]
        self.assertEqual(finding.sources[0].rule_id, "Docs.Weasel")
        self.assertEqual(finding.locations[0].start_line, 9)

    def test_vale_and_kics_validate_structures_and_preserve_artifacts(self) -> None:
        root = Path(".")
        vale = ValeAdapter(ToolConfig(), 4096)
        with self.assertRaisesRegex(TypeError, "must be an object"):
            vale.parse("[]", root)
        with self.assertRaisesRegex(TypeError, "alerts must be a list"):
            vale.parse('{"README.md": {}}', root)
        with self.assertRaisesRegex(TypeError, "alert must be an object"):
            vale.parse('{"README.md": [1]}', root)
        informational = vale.parse(
            '{"README.md":[{"Check":"Docs.Rule","Message":"note"}]}', root
        )[0]
        self.assertEqual(informational.severity.value, "informational")

        kics = KicsAdapter(ToolConfig(), 4096)
        with self.assertRaisesRegex(TypeError, "queries list"):
            kics.parse("[]", root)
        with self.assertRaisesRegex(TypeError, "files list"):
            kics.parse('{"queries":[{"files":{}}]}', root)
        with self.assertRaisesRegex(TypeError, "occurrence"):
            kics.parse('{"queries":[{"files":[1]}]}', root)
        self.assertEqual(
            kics.derived_artifacts('{"queries":[]}', root),
            {"kics-iac.json": {"queries": []}},
        )

    def test_kube_linter_detects_manifests_and_normalizes_reports(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            adapter = KubeLinterAdapter(ToolConfig(), 4096)
            self.assertIn("no Kubernetes", adapter.not_applicable_reason(root) or "")
            manifest = root / "pod.yaml"
            manifest.write_text("apiVersion: v1\nkind: Pod\n", encoding="utf-8")
            self.assertIsNone(adapter.not_applicable_reason(root))
            self.assertEqual(adapter.build_command("kube-linter", root)[1], "lint")
            finding = adapter.parse(
                json.dumps(
                    {
                        "Reports": [
                            {
                                "Check": "run-as-non-root",
                                "Diagnostic": {"Message": "container runs as root"},
                                "Object": {
                                    "Metadata": {"FilePath": str(manifest), "Line": 4}
                                },
                            }
                        ]
                    }
                ),
                root,
            )[0]
            self.assertEqual(finding.locations[0].path, "pod.yaml")
            self.assertEqual(finding.locations[0].start_line, 4)
            with self.assertRaisesRegex(TypeError, "reports list"):
                adapter.parse('{"Reports":{}}', root)
            with self.assertRaisesRegex(TypeError, "report must be an object"):
                adapter.parse('{"Reports":[1]}', root)

    def test_portfolio_numeric_helpers_fail_safely(self) -> None:
        self.assertEqual(_integer("7"), 7)
        self.assertEqual(_integer(object()), 0)
        self.assertEqual(_number("2.5"), 2.5)
        self.assertEqual(_number(object()), 0.0)

    def test_assurance_ingestion_is_bounded_and_sanitized(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "src").mkdir()
            (root / "src" / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
            path = root / "crosshair.json"
            path.write_text(
                json.dumps(
                    {
                        "kind": "crosshair",
                        "producer": "crosshair 0.0",
                        "findings": [
                            {
                                "rule_id": "postcondition",
                                "title": "Postcondition can fail",
                                "message": "Counterexample: value=-1",
                                "path": "src/app.py",
                                "line": 12,
                                "severity": "high",
                                "evidence": {"counterexample": "value=-1"},
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            _bind_evidence([path], source_root=root, overwrite=False)
            normalized = _assurance_document(path, "crosshair")
        finding = CrossHairAdapter(ToolConfig(), 4096).parse(
            json.dumps(normalized), root
        )[0]
        self.assertEqual(finding.sources[0].tool, "crosshair")
        self.assertEqual(finding.locations[0].start_line, 12)
        self.assertEqual(finding.evidence["counterexample"], "value=-1")
        self.assertTrue(finding.evidence["assurance_context"]["binding_verified"])

    def test_governed_surface_inventory_requires_external_denominator(self) -> None:
        document = {
            "kind": "surface-inventory",
            "findings": [],
            "source_sha256": "a" * 64,
            "evidence_binding": {"verified": True, "authenticated": True},
            "execution": {"features": ["independent-collectors"]},
        }
        adapter = SurfaceInventoryAdapter(
            ToolConfig(require_assurance_profile=True), 4096
        )
        with self.assertRaisesRegex(TypeError, "structured"):
            adapter.parse(json.dumps(document), Path.cwd())

        sources = []
        for index, kind in enumerate(("runtime", "gateway"), start=1):
            sources.append(
                {
                    "kind": kind,
                    "snapshot_sha256": str(index) * 64,
                    "collector_id": f"collector-{index}",
                    "collector_signer_id": f"collector-signer-{index}",
                    "collector_organization": f"collector-org-{index}",
                    "adapter_sha256": "a" * 64,
                    "endpoint_identity_sha256": "b" * 64,
                    "query_sha256": "c" * 64,
                    "pages_expected": 1,
                    "pages_observed": 1,
                    "page_receipts_sha256": "d" * 64,
                    "server_total_records": 1,
                    "records_observed": 1,
                    "liveness_probes": 1,
                    "server_collector_id": f"server-{index}",
                    "server_signer_id": f"server-signer-{index}",
                    "server_organization": f"server-org-{index}",
                    "collected_at": "2026-01-01T00:00:00+00:00",
                }
            )
        subject = {
            "schema_version": "1.0",
            "declared_sha256": "e" * 64,
            "history_sha256": "f" * 64,
            "trusted_time_sha256": "0" * 64,
            "sources": sources,
        }
        document["execution"]["surface_proof"] = {
            **subject,
            "proof_sha256": hashlib.sha256(canonical_bytes(subject)).hexdigest(),
        }
        self.assertEqual(adapter.parse(json.dumps(document), Path.cwd()), [])
        subject["sources"][0]["records_observed"] = 2
        document["execution"]["surface_proof"] = {
            **subject,
            "proof_sha256": hashlib.sha256(canonical_bytes(subject)).hexdigest(),
        }
        with self.assertRaisesRegex(TypeError, "source proof is invalid"):
            adapter.parse(json.dumps(document), Path.cwd())

    def test_runtime_evidence_applicability_fails_closed_for_matching_projects(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "uv.lock").write_text(
                '[[package]]\nname = "fastapi"\nversion = "1.0"\n',
                encoding="utf-8",
            )
            self.assertIn(
                "no web application surface",
                IastAdapter(ToolConfig(), 4096).not_applicable_reason(root) or "",
            )
            (root / "pyproject.toml").write_text(
                '[project]\ndependencies = ["fastapi>=0.100"]\n',
                encoding="utf-8",
            )
            web_adapters = (
                IastAdapter(ToolConfig(), 4096),
                BrowserSecurityAdapter(ToolConfig(), 4096),
                ZapAdapter(ToolConfig(), 4096),
                NucleiAdapter(ToolConfig(), 4096),
                RaspAdapter(ToolConfig(), 4096),
                TlsScanAdapter(ToolConfig(), 4096),
            )
            for adapter in web_adapters:
                with self.subTest(tool=adapter.name):
                    self.assertIsNone(adapter.not_applicable_reason(root))

            (root / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
            self.assertIsNone(
                FalcoAdapter(ToolConfig(), 4096).not_applicable_reason(root)
            )

            (root / "pod.yaml").write_text(
                "apiVersion: v1\nkind: Pod\n", encoding="utf-8"
            )
            self.assertIsNone(
                KubescapeAdapter(ToolConfig(), 4096).not_applicable_reason(root)
            )

            fuzz = ClusterFuzzLiteAdapter(ToolConfig(), 4096)
            self.assertIn("configuration", fuzz.not_applicable_reason(root) or "")
            (root / ".clusterfuzzlite").mkdir()
            self.assertIsNone(fuzz.not_applicable_reason(root))

            self.assertIn(
                "authorization contract",
                AuthorizationSecurityAdapter(ToolConfig(), 4096).not_applicable_reason(
                    root
                )
                or "",
            )
            (root / "security").mkdir()
            (root / "security" / "authorization-contract.json").write_text(
                "{}", encoding="utf-8"
            )
            self.assertIsNone(
                AuthorizationSecurityAdapter(ToolConfig(), 4096).not_applicable_reason(
                    root
                )
            )

            (root / "main.tf").write_text("terraform {}\n", encoding="utf-8")
            self.assertIsNone(
                ProwlerAdapter(ToolConfig(), 4096).not_applicable_reason(root)
            )
            (root / "extension.c").write_text("int value;\n", encoding="utf-8")
            self.assertIsNone(
                NativeSanitizersAdapter(ToolConfig(), 4096).not_applicable_reason(root)
            )
            (root / "AndroidManifest.xml").write_text(
                "<manifest />\n", encoding="utf-8"
            )
            self.assertIsNone(
                MobSfAdapter(ToolConfig(), 4096).not_applicable_reason(root)
            )
            (root / "app.ts").write_text("export const value = 1;\n", encoding="utf-8")
            self.assertIsNone(
                PolyglotAdapter(ToolConfig(), 4096).not_applicable_reason(root)
            )

    def test_property_and_api_junit_preserve_producer_attribution(self) -> None:
        payload = json.dumps(
            {
                "kind": "junit",
                "failures": [
                    {
                        "result": "failure",
                        "name": "test_invariant",
                        "classname": "tests.test_properties",
                        "file": "tests/test_properties.py",
                        "line": 12,
                        "message": "minimal counterexample found",
                    }
                ],
            }
        )
        hypothesis = HypothesisAdapter(ToolConfig(), 4096).parse(payload, Path("."))[0]
        schemathesis = SchemathesisAdapter(ToolConfig(), 4096).parse(
            payload, Path(".")
        )[0]
        self.assertEqual(hypothesis.sources[0].tool, "hypothesis")
        self.assertEqual(hypothesis.area, "property-based-testing")
        self.assertEqual(schemathesis.sources[0].tool, "schemathesis")
        self.assertEqual(schemathesis.area, "api-schema-testing")

    def test_new_companion_evidence_has_distinct_domains_and_areas(self) -> None:
        adapters = [
            (ZapAdapter, "security", "dynamic-application-security-testing"),
            (PyTmAdapter, "security", "threat-modeling"),
            (InTotoAdapter, "supply-chain", "build-provenance"),
            (
                ReproducibleBuildAdapter,
                "supply-chain",
                "build-reproducibility",
            ),
            (OciImageAdapter, "supply-chain", "container-image-security"),
            (YaraAdapter, "security", "malware-scanning"),
        ]
        for adapter_type, domain, area in adapters:
            adapter = adapter_type(ToolConfig(), 4096)
            payload = json.dumps(
                {
                    "kind": adapter.evidence_kind,
                    "source_sha256": "a" * 64,
                    "evidence_binding": {
                        "verified": True,
                        "evidence_sha256": "b" * 64,
                    },
                    "findings": [
                        {
                            "rule_id": "evidence-failure",
                            "title": "Evidence failed",
                            "message": "The companion control failed",
                        }
                    ],
                }
            )
            finding = adapter.parse(payload, Path("."))[0]
            self.assertEqual(finding.domain, domain)
            self.assertEqual(finding.area, area)
            self.assertEqual(finding.sources[0].tool, adapter.name)

    def test_assurance_parser_defends_v2_and_signature_requirements(self) -> None:
        adapter = NucleiAdapter(
            ToolConfig(
                require_evidence_contract_v2=True,
                require_signed_evidence=True,
            ),
            4096,
        )
        document = {
            "kind": "nuclei",
            "source_sha256": "a" * 64,
            "evidence_binding": {
                "verified": True,
                "authenticated": False,
                "evidence_sha256": "b" * 64,
            },
            "findings": [],
        }
        with self.assertRaisesRegex(TypeError, "contract version 2.0"):
            adapter.parse(json.dumps(document), Path("."))
        document["schema_version"] = "2.0"
        with self.assertRaisesRegex(TypeError, "authenticated binding"):
            adapter.parse(json.dumps(document), Path("."))

    def test_sonarqube_export_has_engine_rule_location_and_action(self) -> None:
        finding = ValeAdapter(ToolConfig(), 4096).parse(
            json.dumps(
                {
                    "README.md": [
                        {
                            "Check": "Docs.Rule",
                            "Line": 3,
                            "Severity": "error",
                            "Message": "Rewrite this sentence",
                        }
                    ]
                }
            ),
            Path("."),
        )[0]
        issue = render_sonarqube_external_issues([finding])["issues"][0]
        self.assertEqual(issue["engineId"], "py-security-suite")
        self.assertEqual(issue["primaryLocation"]["filePath"], "README.md")
        self.assertIn("Recommended", issue["primaryLocation"]["message"])


if __name__ == "__main__":
    unittest.main()
