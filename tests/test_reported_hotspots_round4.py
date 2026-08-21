from __future__ import annotations

import json
import tempfile
import unittest
from contextlib import nullcontext
from pathlib import Path
from typing import Any
from unittest.mock import patch

from py_security_suite.adapters.devskim import DevSkimAdapter
from py_security_suite.adapters.radon import (
    RadonAdapter,
    _flatten_blocks,
    _integer as radon_integer,
    _rank_severity,
)
from py_security_suite.adapters.reuse import ReuseAdapter, _issues, _rule_title
from py_security_suite.adapters.ruff import (
    RuffAdapter,
    _integer as ruff_integer,
    _rule_metadata,
    _safe_uri as ruff_safe_uri,
)
from py_security_suite.adapters.sarif import (
    _area,
    _artifact_path,
    _classifications,
    _derived_help_uri,
    _domain,
    _integer as sarif_integer,
    _invocation_configuration,
    _location,
    _locations,
    _message,
    _object,
    _object_list,
    _rule_classification,
    _rule_index,
    _resolve_rule,
    _result_semantics,
    _safe_uri as sarif_safe_uri,
    _sarif_severity,
    _sarif_severity_decision,
    _tags,
    _uri_path,
    parse_sarif_findings,
)
from py_security_suite.config import ToolConfig
from py_security_suite.inventory import (
    _declares_dependencies,
    _distribution_files,
    _is_excluded,
    inventory_target,
)
from py_security_suite.models import Severity
from py_security_suite.reports import render_sarif


class RemainingAdapterContractTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()  # pylint: disable=consider-using-with
        self.root = Path(self.enterContext(temporary)).resolve()

    def test_devskim_mirror_lifecycle_and_local_rules_command(self) -> None:
        rules = self.root / "devskim-rules"
        rules.mkdir()
        adapter = DevSkimAdapter(ToolConfig(rules_path=rules), 4096)
        mirror = self.root / "mirror"
        mirror.mkdir()
        sentinel = object()
        with (
            patch(
                "py_security_suite.adapters.devskim.mirrored_source_tree",
                return_value=nullcontext(mirror),
            ),
            patch(
                "py_security_suite.adapters.devskim.ScannerAdapter.run",
                return_value=sentinel,
            ),
        ):
            self.assertIs(adapter.run(self.root), sentinel)
        self.assertIsNone(adapter._scan_root)
        command = adapter.build_command("devskim", self.root)
        self.assertEqual(command[command.index("-r") + 1], str(rules))
        self.assertEqual(command[command.index("-I") + 1], str(self.root))

    def test_radon_applicability_nested_blocks_and_rejection_paths(self) -> None:
        adapter = RadonAdapter(ToolConfig(), 4096)
        self.assertIn("no Python", adapter.not_applicable_reason(self.root) or "")
        (self.root / "app.py").write_text("value = 1\n", encoding="utf-8")
        self.assertIsNone(adapter.not_applicable_reason(self.root))
        self.assertEqual(adapter.build_command("radon", self.root)[1], "cc")
        with self.assertRaisesRegex(TypeError, "must be an object"):
            adapter.parse("[]", self.root)
        with self.assertRaisesRegex(TypeError, "file entry must be a list"):
            adapter.parse('{"app.py":{}}', self.root)
        with self.assertRaisesRegex(TypeError, "block must be an object"):
            _flatten_blocks([1])
        with self.assertRaisesRegex(TypeError, "methods must be a list"):
            _flatten_blocks([{"methods": {}}])
        nested = _flatten_blocks(
            [
                {
                    "name": "container",
                    "methods": [{"name": "method"}],
                    "closures": [{"name": "closure"}],
                }
            ]
        )
        self.assertEqual(
            [item["name"] for item in nested], ["container", "method", "closure"]
        )
        with self.assertRaisesRegex(TypeError, "integer value is invalid"):
            radon_integer({"bad": 1})
        self.assertEqual(_rank_severity("E"), Severity.HIGH)
        self.assertEqual(_rank_severity("D"), Severity.MEDIUM)
        self.assertEqual(_rank_severity("C"), Severity.LOW)

    def test_reuse_applicability_issue_shapes_and_artifact(self) -> None:
        adapter = ReuseAdapter(ToolConfig(), 4096)
        self.assertIn("opt-in marker", adapter.not_applicable_reason(self.root) or "")
        (self.root / "REUSE.toml").write_text("version = 1\n", encoding="utf-8")
        self.assertIsNone(adapter.not_applicable_reason(self.root))
        self.assertEqual(
            adapter.build_command("reuse", self.root), ["reuse", "lint", "--json"]
        )
        with self.assertRaisesRegex(TypeError, "must be an object"):
            adapter.parse("[]", self.root)
        document = {
            "non_compliant": {
                "bad_licenses": {"LICENSE": "invalid identifier"},
                "deprecated_licenses": "ignored shape",
                "missing_licenses": [{"file": "LICENSES/MISSING.txt"}],
                "read_errors": [{"name": "unreadable.py", "message": "read failed"}],
                "invalid_spdx_expressions": ["src/legacy.py"],
            }
        }
        issues = _issues(document)
        self.assertEqual(len(issues), 4)
        findings = adapter.parse(json.dumps(document), self.root)
        self.assertEqual(len(findings), 4)
        self.assertEqual(_issues({"non_compliant": []}), [])
        self.assertEqual(_rule_title("missing-license"), "missing license")
        artifact = adapter.derived_artifacts(json.dumps(document), self.root)
        self.assertIn("reuse-compliance.json", artifact)

    def test_ruff_applicability_environment_guards_and_metadata_fallback(self) -> None:
        adapter = RuffAdapter(ToolConfig(), 4096)
        self.assertIn("no Python", adapter.not_applicable_reason(self.root) or "")
        (self.root / "app.py").write_text("value = 1\n", encoding="utf-8")
        self.assertIsNone(adapter.not_applicable_reason(self.root))
        self.assertEqual(adapter.environment().extra["RUFF_NO_CACHE"], "1")
        self.assertIn("--isolated", adapter.build_command("ruff", self.root))
        with self.assertRaisesRegex(TypeError, "must be a list"):
            adapter.parse("{}", self.root)
        with self.assertRaisesRegex(TypeError, "result must be an object"):
            adapter.parse("[1]", self.root)
        finding = adapter.parse(
            '[{"code":"S000","message":"fixture","filename":"app.py",'
            '"location":[],"end_location":[],"url":"relative"}]',
            self.root,
        )[0]
        self.assertIsNone(finding.locations[0].start_line)
        self.assertEqual(_rule_metadata("S000"), (Severity.MEDIUM, "python-code", []))
        self.assertIsNone(ruff_integer([]))
        self.assertIsNone(ruff_safe_uri("relative"))


class SarifNormalizationContractTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()  # pylint: disable=consider-using-with
        self.root = Path(self.enterContext(temporary)).resolve()

    def test_sarif_shape_helpers_reject_and_normalize_defensively(self) -> None:
        with self.assertRaisesRegex(TypeError, "list of objects"):
            _object_list({}, "runs")
        with self.assertRaisesRegex(TypeError, "list of objects"):
            _object_list([1], "runs")
        self.assertEqual(_object([]), {})
        self.assertEqual(_object({"value": 1}), {"value": 1})
        self.assertEqual(_rule_index([]), {})
        self.assertEqual(_rule_index({"rules": {"bad": 1}}), {})
        self.assertEqual(_rule_index({"rules": [1, {"name": "missing id"}]}), {})
        self.assertEqual(_message(" value "), "value")
        self.assertEqual(_message({"markdown": " formatted "}), "formatted")
        self.assertEqual(_message([]), "")

    def test_sarif_location_uri_and_integer_fallbacks(self) -> None:
        self.assertEqual(_location({}, self.root).path, "<repository>")
        location = _location(
            {
                "locations": [
                    {
                        "physicalLocation": [],
                    }
                ]
            },
            self.root,
        )
        self.assertEqual(location.path, "<repository>")
        location = _location(
            {
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": [],
                            "region": [],
                        }
                    }
                ]
            },
            self.root,
        )
        self.assertEqual(location.path, "<repository>")
        self.assertEqual(_uri_path("src/example%20file.py"), "src/example file.py")
        self.assertEqual(_uri_path("file:///C:/repo/app.py"), "C:/repo/app.py")
        self.assertEqual(_uri_path("C:/repo/app.py"), "C:/repo/app.py")
        self.assertEqual(
            _uri_path("https://user:secret@example.test/app.py"),
            "<external-artifact>",
        )
        self.assertIsNone(sarif_integer([]))
        self.assertIsNone(sarif_safe_uri("relative"))

    def test_sarif_locations_are_bounded_deduplicated_and_auditable(self) -> None:
        primary = {
            "physicalLocation": {
                "artifactLocation": {"uri": "src/primary.py"},
                "region": {"startLine": 7},
            }
        }
        raw_locations: list[object] = [
            primary,
            primary,
            "invalid",
            {"physicalLocation": {"region": {"startLine": True}}},
            {"physicalLocation": {"region": {"startLine": 1.5}}},
        ]
        raw_locations.extend(
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": f"src/secondary-{index}.py"},
                    "region": {"startLine": index + 1},
                }
            }
            for index in range(30)
        )

        locations, summary = _locations({"locations": raw_locations}, self.root)

        self.assertEqual(len(locations), 25)
        self.assertEqual(locations[0].path, "src/primary.py")
        self.assertEqual(locations[0].start_line, 7)
        self.assertEqual(summary["reported_count"], 35)
        self.assertEqual(summary["retained_count"], 25)
        self.assertEqual(summary["duplicate_count"], 1)
        self.assertEqual(summary["invalid_count"], 3)
        self.assertEqual(summary["limit_omitted_count"], 6)
        self.assertEqual(summary["omitted_count"], 10)
        self.assertTrue(summary["truncated"])
        self.assertEqual(summary["path_resolution_counts"], {"target-relative": 31})

    def test_sarif_uri_base_failures_do_not_create_repository_correlations(
        self,
    ) -> None:
        cases: tuple[tuple[str, dict[str, Any], dict[str, Any], str], ...] = (
            (
                "missing",
                {"uri": "sink.py", "uriBaseId": "MISSING"},
                {},
                "unresolved-uri-base",
            ),
            (
                "cycle",
                {"uri": "sink.py", "uriBaseId": "A"},
                {
                    "A": {"uri": "a/", "uriBaseId": "B"},
                    "B": {"uri": "b/", "uriBaseId": "A"},
                },
                "cyclic-uri-base",
            ),
            (
                "external",
                {"uri": "sink.py", "uriBaseId": "REMOTE"},
                {"REMOTE": {"uri": "https://user:secret@example.test/repository/"}},
                "external-uri-base",
            ),
            (
                "malformed-base",
                {"uri": "sink.py", "uriBaseId": "ROOT"},
                {"ROOT": {"uri": "file://[invalid"}},
                "invalid-uri-base",
            ),
            (
                "malformed-artifact",
                {"uri": "src/%not-encoded.py"},
                {},
                "invalid-artifact-uri",
            ),
            (
                "null-artifact",
                {"uri": None},
                {},
                "invalid-artifact-uri",
            ),
        )
        for name, artifact, uri_bases, expected_resolution in cases:
            with self.subTest(name=name):
                path, resolution = _artifact_path(
                    artifact, self.root, uri_bases=uri_bases
                )
                self.assertIn(
                    path,
                    {
                        "<unresolved-uri-base>",
                        "<external-artifact>",
                        "<invalid-artifact-uri>",
                    },
                )
                self.assertEqual(resolution, expected_resolution)
                self.assertNotIn("secret", path)

        deep_bases: dict[str, Any] = {
            f"BASE-{index}": {
                "uri": f"level-{index}/",
                "uriBaseId": f"BASE-{index + 1}",
            }
            for index in range(20)
        }
        deep_bases["BASE-20"] = {"uri": "root/"}
        path, resolution = _artifact_path(
            {"uri": "sink.py", "uriBaseId": "BASE-0"},
            self.root,
            uri_bases=deep_bases,
        )
        self.assertEqual(path, "<unresolved-uri-base>")
        self.assertEqual(resolution, "uri-base-depth-exceeded")

    def test_sarif_rejects_nonlocal_file_uri_authorities(self) -> None:
        path, resolution = _artifact_path(
            {"uri": "file://user:secret@server.example/src/sink.py"},
            self.root,
            uri_bases={},
        )

        self.assertEqual(path, "<external-artifact>")
        self.assertEqual(resolution, "external-uri")

    def test_sarif_artifact_indices_are_resolved_and_fail_closed(self) -> None:
        indexed_artifacts: list[dict[str, Any]] = [
            {"location": {"index": 1}},
            {"location": {"uri": "sink.py", "uriBaseId": "SRC"}},
        ]
        path, resolution = _artifact_path(
            {"index": 0},
            self.root,
            uri_bases={"SRC": {"uri": "src/"}},
            artifacts=indexed_artifacts,
        )
        self.assertEqual(path, "src/sink.py")
        self.assertEqual(resolution, "artifact-index-resolved")

        direct_path, direct_resolution = _artifact_path(
            {"uri": "src/direct.py", "index": True},
            self.root,
            uri_bases={},
            artifacts=indexed_artifacts,
        )
        self.assertEqual(direct_path, "src/direct.py")
        self.assertEqual(direct_resolution, "target-relative")

        outside_path, outside_resolution = _artifact_path(
            {"index": 0},
            self.root,
            uri_bases={},
            artifacts=[{"location": {"uri": "../outside.py"}}],
        )
        self.assertEqual(outside_path, "<outside-target>")
        self.assertEqual(outside_resolution, "artifact-index-outside-target")

        failures: tuple[
            tuple[str, dict[str, Any], list[dict[str, Any]], str, str], ...
        ] = (
            (
                "invalid",
                {"index": True},
                indexed_artifacts,
                "<invalid-artifact-index>",
                "invalid-artifact-index",
            ),
            (
                "missing",
                {"index": 50},
                indexed_artifacts,
                "<unresolved-artifact-index>",
                "unresolved-artifact-index",
            ),
            (
                "missing-location",
                {"index": 0},
                [{}],
                "<unresolved-artifact-index>",
                "unresolved-artifact-index",
            ),
            (
                "cycle",
                {"index": 0},
                [
                    {"location": {"index": 1}},
                    {"location": {"index": 0}},
                ],
                "<unresolved-artifact-index>",
                "cyclic-artifact-index",
            ),
        )
        for name, artifact, artifacts, expected_path, expected_resolution in failures:
            with self.subTest(name=name):
                path, resolution = _artifact_path(
                    artifact,
                    self.root,
                    uri_bases={},
                    artifacts=artifacts,
                )
                self.assertEqual(path, expected_path)
                self.assertEqual(resolution, expected_resolution)

    def test_sarif_indexed_external_uri_does_not_retain_credentials(self) -> None:
        path, resolution = _artifact_path(
            {"index": 0},
            self.root,
            uri_bases={},
            artifacts=[
                {"location": {"uri": "https://user:secret@example.test/src/sink.py"}}
            ],
        )

        self.assertEqual(path, "<external-artifact>")
        self.assertEqual(resolution, "artifact-index-external-uri")
        self.assertNotIn("secret", path)

    def test_sarif_artifact_index_depth_is_bounded(self) -> None:
        artifacts: list[dict[str, Any]] = [
            {"location": {"index": index + 1}} for index in range(21)
        ]
        artifacts.append({"location": {"uri": "src/sink.py"}})

        path, resolution = _artifact_path(
            {"index": 0},
            self.root,
            uri_bases={},
            artifacts=artifacts,
        )

        self.assertEqual(path, "<unresolved-artifact-index>")
        self.assertEqual(resolution, "artifact-index-depth-exceeded")

    def test_sarif_uri_paths_ignore_query_and_fragment_metadata(self) -> None:
        path, resolution = _artifact_path(
            {"uri": "src/sink.py?generated=true#result"},
            self.root,
            uri_bases={},
        )

        self.assertEqual(path, "src/sink.py")
        self.assertEqual(resolution, "target-relative")

    def test_sarif_excludes_only_semantically_inactive_results(self) -> None:
        results = [
            {
                "ruleId": f"rule-{name}",
                "kind": kind,
                "baselineState": baseline,
                "message": {"text": name},
            }
            for name, kind, baseline in (
                ("default-failure", None, None),
                ("explicit-failure", "fail", "new"),
                ("review", "review", "updated"),
                ("unknown", "future-kind", "future-state"),
                ("pass", "pass", None),
                ("not-applicable", "notApplicable", None),
                ("absent", "fail", "absent"),
            )
        ]
        payload = json.dumps(
            {
                "runs": [
                    {
                        "tool": {"driver": {"rules": []}},
                        "results": results,
                    }
                ]
            }
        )

        findings = parse_sarif_findings(
            payload,
            self.root,
            tool_name="codeql",
            default_area="security",
            default_impact="impact",
            default_remediation="fix",
        )

        self.assertEqual(
            [finding.description for finding in findings],
            ["default-failure", "explicit-failure", "review", "unknown"],
        )
        self.assertEqual(
            findings[-1].evidence["sarif_result_semantics"]["kind"], "unknown"
        )
        self.assertEqual(
            findings[-1].evidence["sarif_result_semantics"]["baseline_state"],
            "unknown",
        )

    def test_sarif_suppressions_are_evidence_not_policy_acceptance(self) -> None:
        justification_secret = "suppression-justification-must-not-be-retained"
        payload = json.dumps(
            {
                "runs": [
                    {
                        "tool": {"driver": {"rules": []}},
                        "results": [
                            {
                                "ruleId": "rule-suppressed",
                                "kind": "review",
                                "baselineState": "unchanged",
                                "message": {"text": "still requires policy review"},
                                "suppressions": [
                                    {
                                        "kind": "inSource",
                                        "status": "accepted",
                                        "justification": justification_secret,
                                    },
                                    {"kind": "external", "status": "underReview"},
                                    {"kind": "external", "status": "rejected"},
                                    {"kind": "external", "status": "future"},
                                    "malformed",
                                ],
                            }
                        ],
                    }
                ]
            }
        )

        finding = parse_sarif_findings(
            payload,
            self.root,
            tool_name="codeql",
            default_area="security",
            default_impact="impact",
            default_remediation="fix",
        )[0]
        semantics = finding.evidence["sarif_result_semantics"]

        self.assertEqual(finding.status.value, "new")
        self.assertTrue(semantics["normalized_as_finding"])
        self.assertEqual(semantics["native_suppression_count"], 5)
        self.assertEqual(semantics["accepted_native_suppression_count"], 1)
        self.assertEqual(semantics["invalid_native_suppression_count"], 1)
        self.assertEqual(
            semantics["native_suppression_status_counts"],
            {"accepted": 1, "rejected": 1, "under-review": 1, "unknown": 1},
        )
        self.assertNotIn(justification_secret, json.dumps(finding.evidence))
        self.assertIn(
            "suite policy acceptance", semantics["native_suppression_authority"]
        )
        self.assertTrue(
            _result_semantics({"suppressions": {}})[
                "malformed_native_suppression_container"
            ]
        )

    def test_sarif_rule_index_resolves_exact_descriptor_metadata(self) -> None:
        payload = json.dumps(
            {
                "runs": [
                    {
                        "tool": {
                            "driver": {
                                "rules": [
                                    {
                                        "id": "py/indexed-rule",
                                        "shortDescription": {
                                            "text": "Indexed rule title"
                                        },
                                        "messageStrings": {
                                            "flow": {
                                                "text": (
                                                    "Call {0} reaches {1}; "
                                                    "literal {{review}}"
                                                )
                                            }
                                        },
                                        "properties": {
                                            "security-severity": "8.2",
                                            "tags": ["security", "external/cwe/cwe-79"],
                                        },
                                    }
                                ]
                            }
                        },
                        "results": [
                            {
                                "ruleIndex": 0,
                                "message": {
                                    "id": "flow",
                                    "arguments": ["source_fn", "sink_fn"],
                                },
                            }
                        ],
                    }
                ]
            }
        )

        finding = parse_sarif_findings(
            payload,
            self.root,
            tool_name="codeql",
            default_area="security",
            default_impact="impact",
            default_remediation="fix",
        )[0]

        self.assertEqual(finding.sources[0].rule_id, "py/indexed-rule")
        self.assertEqual(
            finding.description,
            "Call source_fn reaches sink_fn; literal {review}",
        )
        self.assertEqual(finding.title, "Indexed rule title")
        self.assertEqual(finding.severity, Severity.HIGH)
        self.assertEqual(finding.classifications, ["CWE-79"])
        self.assertEqual(
            finding.evidence["sarif_rule_reference"],
            {
                "basis": "rule-index",
                "rule_index": 0,
                "metadata_resolved": True,
                "component": {
                    "kind": "driver",
                    "extension_index": None,
                    "basis": "default-driver",
                    "name_verified": False,
                    "guid_verified": False,
                },
            },
        )
        self.assertEqual(
            finding.evidence["sarif_message_reference"]["basis"],
            "rule-message-string",
        )
        self.assertEqual(
            finding.evidence["sarif_message_reference"]["used_argument_count"], 2
        )
        self.assertEqual(
            finding.evidence["sarif_message_reference"]["truncated_argument_count"],
            0,
        )
        self.assertEqual(
            finding.evidence["sarif_message_reference"]["unresolved_placeholder_count"],
            0,
        )
        portable = render_sarif([finding])["runs"][0]["results"][0]
        self.assertEqual(portable["message"]["text"], finding.description)
        self.assertNotEqual(portable["message"]["text"], finding.title)

    def test_sarif_global_message_template_is_bounded_and_sanitized(self) -> None:
        credential = "dynamic-credential-must-not-survive"
        payload = json.dumps(
            {
                "runs": [
                    {
                        "tool": {
                            "driver": {
                                "globalMessageStrings": {
                                    "global": {
                                        "text": (
                                            "Package {0} reported token={1}; "
                                            "invalid {2}; missing {3}"
                                        )
                                    }
                                }
                            }
                        },
                        "results": [
                            {
                                "ruleId": "global-rule",
                                "message": {
                                    "id": "global",
                                    "arguments": [
                                        "demo",
                                        credential,
                                        {"must_not": "be stringified"},
                                    ],
                                },
                            }
                        ],
                    }
                ]
            }
        )

        finding = parse_sarif_findings(
            payload,
            self.root,
            tool_name="codeql",
            default_area="security",
            default_impact="impact",
            default_remediation="fix",
        )[0]
        reference = finding.evidence["sarif_message_reference"]

        self.assertIn("Package demo", finding.description)
        self.assertNotIn(credential, finding.description)
        self.assertIn("token=<redacted>", finding.description)
        self.assertIn("invalid <invalid-argument>", finding.description)
        self.assertIn("missing {3}", finding.description)
        self.assertNotIn("must_not", json.dumps(finding.evidence))
        self.assertEqual(reference["basis"], "global-message-string")
        self.assertEqual(reference["invalid_argument_count"], 1)
        self.assertEqual(reference["unresolved_placeholder_count"], 1)

    def test_sarif_message_lookup_uses_the_selected_tool_component(self) -> None:
        payload = json.dumps(
            {
                "runs": [
                    {
                        "tool": {
                            "driver": {
                                "name": "driver",
                                "globalMessageStrings": {
                                    "component-global": {
                                        "text": "incorrect driver message"
                                    },
                                },
                            },
                            "extensions": [
                                {
                                    "name": "message-plugin",
                                    "globalMessageStrings": {
                                        "component-global": {
                                            "text": "Extension global {0}"
                                        },
                                        "rule-local": {
                                            "text": "incorrect component fallback"
                                        },
                                    },
                                    "rules": [
                                        {
                                            "id": "plugin-message-rule",
                                            "messageStrings": {
                                                "rule-local": {"text": "Rule-local {0}"}
                                            },
                                        }
                                    ],
                                }
                            ],
                        },
                        "results": [
                            {
                                "rule": {
                                    "index": 0,
                                    "toolComponent": {"index": 0},
                                },
                                "message": {
                                    "id": "component-global",
                                    "arguments": ["message"],
                                },
                            },
                            {
                                "rule": {
                                    "index": 0,
                                    "toolComponent": {"index": 0},
                                },
                                "message": {
                                    "id": "rule-local",
                                    "arguments": ["message"],
                                },
                            },
                        ],
                    }
                ]
            }
        )

        component_finding, rule_finding = parse_sarif_findings(
            payload,
            self.root,
            tool_name="codeql",
            default_area="security",
            default_impact="impact",
            default_remediation="fix",
        )

        self.assertEqual(component_finding.description, "Extension global message")
        self.assertEqual(rule_finding.description, "Rule-local message")
        self.assertNotIn("incorrect", component_finding.description)
        component_reference = component_finding.evidence["sarif_message_reference"]
        rule_reference = rule_finding.evidence["sarif_message_reference"]
        self.assertEqual(component_reference["basis"], "global-message-string")
        self.assertEqual(rule_reference["basis"], "rule-message-string")
        self.assertEqual(component_reference["component_kind"], "extension")
        self.assertEqual(component_reference["component_extension_index"], 0)
        portable = render_sarif([component_finding])["runs"][0]["results"][0]
        self.assertEqual(
            portable["properties"]["sarif_message_reference"],
            component_reference,
        )

    def test_sarif_rule_reference_rejects_mismatch_and_ambiguity(self) -> None:
        rules = [{"id": "rule-a"}, {"id": "rule-b"}]
        with self.assertRaisesRegex(ValueError, "different rules"):
            _resolve_rule({"ruleId": "rule-b", "ruleIndex": 0}, rules)
        with self.assertRaisesRegex(ValueError, "ambiguous"):
            _resolve_rule({"ruleId": "rule-a"}, [rules[0], rules[0]])

        invalid_references: tuple[
            tuple[dict[str, object], type[Exception], str], ...
        ] = (
            ({"ruleIndex": True}, TypeError, "integer"),
            ({"ruleIndex": -2}, ValueError, "-1 or non-negative"),
            ({"ruleIndex": 2}, ValueError, "outside"),
            ({"ruleIndex": 0}, ValueError, "without an id"),
            ({"ruleId": []}, TypeError, "string"),
            ({"ruleId": ""}, ValueError, "must not be empty"),
        )
        for reference, error_type, message in invalid_references:
            with self.subTest(reference=reference):
                candidate_rules = [{}] if reference.get("ruleIndex") == 0 else rules
                with self.assertRaisesRegex(error_type, message):
                    _resolve_rule(reference, candidate_rules)

    def test_sarif_resolves_extension_rule_metadata_and_component_identity(
        self,
    ) -> None:
        component_guid = "22222222-2222-4222-8222-222222222222"
        rule_guid = "33333333-3333-4333-8333-333333333333"
        payload = json.dumps(
            {
                "runs": [
                    {
                        "tool": {
                            "driver": {
                                "name": "driver",
                                "guid": "11111111-1111-4111-8111-111111111111",
                                "rules": [{"id": "driver-rule"}],
                            },
                            "extensions": [
                                {
                                    "name": "security-plugin",
                                    "guid": component_guid,
                                    "rules": [
                                        {
                                            "id": "plugin-rule",
                                            "guid": rule_guid,
                                            "shortDescription": {
                                                "text": "Extension rule title"
                                            },
                                            "defaultConfiguration": {"level": "error"},
                                            "properties": {
                                                "tags": [
                                                    "security",
                                                    "external/cwe/cwe-89",
                                                ]
                                            },
                                        }
                                    ],
                                }
                            ],
                        },
                        "invocations": [
                            {
                                "ruleConfigurationOverrides": [
                                    {
                                        "descriptor": {
                                            "guid": rule_guid,
                                            "toolComponent": {"guid": component_guid},
                                        },
                                        "configuration": {"level": "note"},
                                    }
                                ]
                            }
                        ],
                        "results": [
                            {
                                "ruleId": "plugin-rule/hierarchical",
                                "ruleIndex": 0,
                                "rule": {
                                    "id": "plugin-rule/hierarchical",
                                    "index": 0,
                                    "guid": rule_guid,
                                    "toolComponent": {
                                        "index": 0,
                                        "guid": component_guid,
                                        "name": "security-plugin",
                                    },
                                },
                                "message": {"text": "extension result"},
                            },
                            {
                                "rule": {
                                    "guid": rule_guid,
                                    "toolComponent": {"guid": component_guid},
                                },
                                "provenance": {"invocationIndex": 0},
                                "message": {"text": "extension result with override"},
                            },
                        ],
                    }
                ]
            }
        )

        findings = parse_sarif_findings(
            payload,
            self.root,
            tool_name="codeql",
            default_area="security",
            default_impact="impact",
            default_remediation="fix",
        )
        finding, overridden_finding = findings

        self.assertEqual(finding.sources[0].rule_id, "plugin-rule/hierarchical")
        self.assertEqual(finding.title, "Extension rule title")
        self.assertEqual(finding.severity, Severity.HIGH)
        self.assertEqual(finding.classifications, ["CWE-89"])
        self.assertEqual(
            finding.evidence["sarif_rule_reference"],
            {
                "basis": "rule-id-and-index",
                "rule_index": 0,
                "metadata_resolved": True,
                "component": {
                    "kind": "extension",
                    "extension_index": 0,
                    "basis": "extension-index",
                    "name_verified": True,
                    "guid_verified": True,
                },
            },
        )
        portable = render_sarif([finding])["runs"][0]["results"][0]
        self.assertEqual(
            portable["properties"]["sarif_rule_reference"],
            finding.evidence["sarif_rule_reference"],
        )
        override_decision = overridden_finding.evidence["sarif_severity_decision"]
        self.assertEqual(overridden_finding.severity, Severity.INFORMATIONAL)
        self.assertEqual(override_decision["basis"], "invocation-override-level")
        self.assertEqual(
            override_decision["configuration_override"]["basis"],
            "invocation-rule-override",
        )
        self.assertEqual(
            overridden_finding.evidence["sarif_rule_reference"]["component"]["basis"],
            "component-guid",
        )

    def test_sarif_component_guid_resolution_is_strict_and_unambiguous(self) -> None:
        component_guid = "22222222-2222-4222-8222-222222222222"
        rule_guid = "33333333-3333-4333-8333-333333333333"
        driver = {
            "name": "driver",
            "guid": "11111111-1111-4111-8111-111111111111",
            "rules": [{"id": "driver-rule"}],
        }
        extension = {
            "name": "security-plugin",
            "guid": component_guid,
            "rules": [{"id": "plugin-rule", "guid": rule_guid}],
        }
        rule_id, rule, reference = _resolve_rule(
            {
                "rule": {
                    "guid": rule_guid,
                    "toolComponent": {
                        "guid": component_guid,
                        "name": "security-plugin",
                    },
                }
            },
            driver["rules"],
            driver=driver,
            extensions=[extension],
        )
        self.assertEqual(rule_id, "plugin-rule")
        self.assertEqual(rule, extension["rules"][0])
        self.assertEqual(reference["basis"], "rule-guid")
        self.assertEqual(
            reference["component"],
            {
                "kind": "extension",
                "extension_index": 0,
                "basis": "component-guid",
                "name_verified": True,
                "guid_verified": True,
            },
        )
        invalid_references: tuple[
            tuple[dict[str, Any], list[dict[str, Any]], str], ...
        ] = (
            (
                {
                    "ruleId": "plugin-rule",
                    "rule": {
                        "toolComponent": {
                            "index": 0,
                            "guid": driver["guid"],
                        }
                    },
                },
                [extension],
                "different components",
            ),
            (
                {
                    "ruleId": "plugin-rule",
                    "rule": {
                        "toolComponent": {
                            "index": 0,
                            "name": "wrong-plugin",
                        }
                    },
                },
                [extension],
                "name does not match",
            ),
            (
                {
                    "ruleId": "plugin-rule",
                    "rule": {"toolComponent": {"guid": component_guid}},
                },
                [extension, extension],
                "ambiguous",
            ),
            (
                {
                    "ruleId": "plugin-rule",
                    "ruleIndex": 0,
                    "rule": {
                        "index": 1,
                        "toolComponent": {"index": 0},
                    },
                },
                [extension],
                "different rules",
            ),
            (
                {
                    "ruleId": "plugin-rule",
                    "rule": {"toolComponent": {"index": 1}},
                },
                [extension],
                "outside",
            ),
            (
                {
                    "ruleId": "plugin-rule/first/second",
                    "ruleIndex": 0,
                    "rule": {"toolComponent": {"index": 0}},
                },
                [extension],
                "different rules",
            ),
        )
        for result, extensions, message in invalid_references:
            with self.subTest(message=message):
                with self.assertRaisesRegex(ValueError, message):
                    _resolve_rule(
                        result,
                        driver["rules"],
                        driver=driver,
                        extensions=extensions,
                    )

    def test_sarif_severity_classification_domain_and_help_mapping(self) -> None:
        self.assertEqual(
            _sarif_severity(None, {"security-severity": 9.1}, {}), Severity.CRITICAL
        )
        self.assertEqual(
            _sarif_severity(None, {"security-severity": 7.2}, {}), Severity.HIGH
        )
        self.assertEqual(
            _sarif_severity(None, {"security-severity": 4.5}, {}), Severity.MEDIUM
        )
        self.assertEqual(
            _sarif_severity(None, {"security-severity": 0.1}, {}), Severity.LOW
        )
        self.assertEqual(_sarif_severity("note", {}, {}), Severity.INFORMATIONAL)
        classifications = _classifications(
            {"classifications": ["external/cwe/cwe-79", "OWASP-A03", "MITRE-T1059"]},
            {},
        )
        self.assertEqual(classifications, ["CWE-79", "OWASP-A03", "MITRE-T1059"])
        self.assertEqual(_tags({"tags": "Quality"}, {}), ["quality"])
        self.assertEqual(_domain(["quality"]), "quality")
        self.assertEqual(_domain(["quality", "security"]), "security")
        self.assertEqual(_area(["readability"], "fallback"), "code-quality")
        self.assertEqual(_area([], "fallback"), "fallback")
        self.assertEqual(_rule_classification("tool", "rule/value"), "TOOL-RULE-VALUE")
        self.assertIsNone(_derived_help_uri("devskim", "DS1001"))
        self.assertIn(
            "py-sql-injection", _derived_help_uri("codeql", "py/sql-injection") or ""
        )

    def test_sarif_severity_decision_is_bounded_and_rank_is_advisory(self) -> None:
        severity, decision = _sarif_severity_decision(
            "note",
            {"security-severity": 0},
            {"security-severity": 9.8},
            default_configuration={"level": "error", "rank": 95},
            rank=100,
            kind="fail",
            configuration_override={"level": "error", "rank": 50},
        )
        self.assertEqual(severity, Severity.LOW)
        self.assertEqual(decision["basis"], "result-security-score")
        self.assertEqual(decision["security_score"], 0.0)
        self.assertEqual(decision["effective_level"], "note")
        self.assertEqual(decision["effective_rank"], 100.0)
        self.assertEqual(decision["rank_basis"], "result-rank")
        self.assertFalse(decision["rank_used_for_severity"])

        severity, decision = _sarif_severity_decision(
            "warning",
            {"security-severity": float("inf")},
            {"security-severity": 7.5},
            default_configuration={},
            rank="100",
            kind="fail",
        )
        self.assertEqual(severity, Severity.HIGH)
        self.assertEqual(decision["basis"], "rule-security-score")
        self.assertEqual(decision["invalid_security_score_count"], 1)
        self.assertIsNone(decision["effective_rank"])
        self.assertEqual(decision["invalid_rank_count"], 1)

        severity, decision = _sarif_severity_decision(
            "error",
            {"security-severity": 10},
            {},
            default_configuration={"level": "error", "rank": 100},
            rank=100,
            kind="review",
        )
        self.assertEqual(severity, Severity.INFORMATIONAL)
        self.assertEqual(decision["basis"], "non-failure-kind")
        self.assertTrue(decision["security_score_ignored_for_kind"])
        self.assertIsNone(decision["effective_rank"])

        severity, decision = _sarif_severity_decision(
            None,
            {"security-severity": 10**10_000},
            {},
            default_configuration={},
            rank=10**10_000,
            kind="fail",
        )
        self.assertEqual(severity, Severity.MEDIUM)
        self.assertEqual(decision["basis"], "sarif-default-warning")
        self.assertEqual(decision["invalid_security_score_count"], 1)
        self.assertEqual(decision["invalid_rank_count"], 1)

    def test_sarif_rule_default_configuration_drives_effective_level(self) -> None:
        payload = json.dumps(
            {
                "runs": [
                    {
                        "tool": {
                            "driver": {
                                "rules": [
                                    {
                                        "id": "configured-rule",
                                        "defaultConfiguration": {
                                            "level": "error",
                                            "rank": 92,
                                        },
                                    }
                                ]
                            }
                        },
                        "results": [
                            {
                                "ruleId": "configured-rule",
                                "message": {"text": "configured severity"},
                            }
                        ],
                    }
                ]
            }
        )

        finding = parse_sarif_findings(
            payload,
            self.root,
            tool_name="codeql",
            default_area="security",
            default_impact="impact",
            default_remediation="fix",
        )[0]
        decision = finding.evidence["sarif_severity_decision"]
        portable = render_sarif([finding])["runs"][0]["results"][0]

        self.assertEqual(finding.severity, Severity.HIGH)
        self.assertEqual(finding.sources[0].native_severity, "error")
        self.assertEqual(decision["basis"], "rule-default-level")
        self.assertEqual(decision["effective_rank"], 92.0)
        self.assertEqual(decision["rank_basis"], "rule-default-rank")
        self.assertEqual(portable["properties"]["sarif_severity_decision"], decision)

    def test_sarif_invocation_configuration_overrides_rule_defaults(self) -> None:
        payload = json.dumps(
            {
                "runs": [
                    {
                        "tool": {
                            "driver": {
                                "rules": [
                                    {
                                        "id": "configured-rule",
                                        "defaultConfiguration": {
                                            "level": "error",
                                            "rank": 92,
                                        },
                                    },
                                    {"id": "other-rule"},
                                ]
                            }
                        },
                        "invocations": [
                            {
                                "ruleConfigurationOverrides": [
                                    {
                                        "descriptor": {"id": "other-rule"},
                                        "configuration": {"level": "error"},
                                    },
                                    {
                                        "descriptor": {
                                            "id": "configured-rule",
                                            "index": 0,
                                        },
                                        "configuration": {
                                            "level": "note",
                                            "rank": 12,
                                        },
                                    },
                                ]
                            }
                        ],
                        "results": [
                            {
                                "ruleId": "configured-rule",
                                "provenance": {},
                                "message": {"text": "overridden severity"},
                            }
                        ],
                    }
                ]
            }
        )

        finding = parse_sarif_findings(
            payload,
            self.root,
            tool_name="codeql",
            default_area="security",
            default_impact="impact",
            default_remediation="fix",
        )[0]
        decision = finding.evidence["sarif_severity_decision"]
        reference = decision["configuration_override"]

        self.assertEqual(finding.severity, Severity.INFORMATIONAL)
        self.assertEqual(finding.sources[0].native_severity, "note")
        self.assertEqual(decision["basis"], "invocation-override-level")
        self.assertEqual(decision["effective_rank"], 12.0)
        self.assertEqual(decision["rank_basis"], "invocation-override-rank")
        self.assertEqual(reference["basis"], "invocation-rule-override")
        self.assertEqual(reference["reported_override_count"], 2)
        self.assertEqual(reference["matching_override_count"], 1)
        self.assertEqual(
            reference["invocation_index_basis"], "single-invocation-default"
        )
        self.assertTrue(reference["applied"])

    def test_sarif_ambiguous_invocation_overrides_fail_closed(self) -> None:
        rules = [{"id": "configured-rule"}, {"id": "other-rule"}]
        override, reference = _invocation_configuration(
            {"provenance": {"invocationIndex": 0}},
            [
                {
                    "ruleConfigurationOverrides": [
                        {
                            "descriptor": {"id": "configured-rule"},
                            "configuration": {"level": "error"},
                        },
                        {
                            "descriptor": {"index": 0},
                            "configuration": {"level": "note"},
                        },
                        {
                            "descriptor": {"id": "configured-rule", "index": 1},
                            "configuration": {"level": "error"},
                        },
                    ]
                }
            ],
            rules,
            rule_id="configured-rule",
        )

        self.assertNotIsInstance(override, dict)
        self.assertEqual(reference["basis"], "ambiguous-matching-overrides")
        self.assertEqual(reference["matching_override_count"], 2)
        self.assertEqual(reference["invalid_override_count"], 1)
        self.assertFalse(reference["applied"])

        oversized_override, oversized_reference = _invocation_configuration(
            {"provenance": {"invocationIndex": 0}},
            [
                {
                    "ruleConfigurationOverrides": [
                        {
                            "descriptor": {"id": "other-rule"},
                            "configuration": {"level": "error"},
                        }
                        for _ in range(1_001)
                    ]
                }
            ],
            rules,
            rule_id="configured-rule",
        )
        self.assertNotIsInstance(oversized_override, dict)
        self.assertEqual(oversized_reference["basis"], "override-limit-exceeded")
        self.assertEqual(oversized_reference["evaluated_override_count"], 0)
        self.assertEqual(oversized_reference["overrides_omitted_count"], 1_001)

        _, null_reference = _invocation_configuration(
            {"provenance": None},
            [],
            rules,
            rule_id="configured-rule",
        )
        self.assertEqual(null_reference["basis"], "invalid-provenance")
        self.assertTrue(null_reference["invalid_provenance"])

        _, multiple_reference = _invocation_configuration(
            {"provenance": {}},
            [{}, {}],
            rules,
            rule_id="configured-rule",
        )
        self.assertEqual(multiple_reference["basis"], "no-invocation-reference")
        self.assertEqual(
            multiple_reference["invocation_index_basis"],
            "no-single-invocation-default",
        )

    def test_sarif_quality_finding_uses_safe_defaults_without_location(self) -> None:
        payload = json.dumps(
            {
                "runs": [
                    {
                        "tool": {
                            "driver": {
                                "rules": [
                                    {
                                        "id": "py/fixture-quality",
                                        "shortDescription": "Fixture quality rule",
                                        "properties": {"tags": ["quality"]},
                                    }
                                ]
                            }
                        },
                        "results": [
                            {
                                "ruleId": "py/fixture-quality",
                                "message": {"text": "Improve clarity"},
                            }
                        ],
                    }
                ]
            }
        )
        finding = parse_sarif_findings(
            payload,
            self.root,
            tool_name="codeql",
            default_area="fallback",
            default_impact="fallback impact",
            default_remediation="fallback action",
        )[0]
        self.assertEqual(finding.domain, "quality")
        self.assertEqual(finding.locations[0].path, "<repository>")
        self.assertEqual(finding.area, "fallback")
        self.assertEqual(finding.severity, Severity.MEDIUM)
        self.assertEqual(
            finding.evidence["sarif_severity_decision"]["basis"],
            "sarif-default-warning",
        )
        self.assertIn("implementation mistake", finding.impact)
        self.assertIn("focused test", finding.remediation)


class InventoryContractTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()  # pylint: disable=consider-using-with
        self.root = Path(self.enterContext(temporary)).resolve()

    def test_dependency_declaration_variants_are_detected(self) -> None:
        pyproject = self.root / "pyproject.toml"
        pyproject.write_text("not valid = [", encoding="utf-8")
        self.assertTrue(_declares_dependencies(self.root))
        pyproject.write_text(
            '[project.optional-dependencies]\nsecurity = ["fixture>=1"]\n',
            encoding="utf-8",
        )
        self.assertTrue(_declares_dependencies(self.root))
        pyproject.write_text(
            '[tool.poetry.dependencies]\npython = ">=3.11"\nfixture = ">=1"\n',
            encoding="utf-8",
        )
        self.assertTrue(_declares_dependencies(self.root))
        pyproject.write_text(
            '[dependency-groups]\ndev = ["fixture>=1"]\n', encoding="utf-8"
        )
        self.assertTrue(_declares_dependencies(self.root))

    def test_requirements_and_empty_metadata_decisions(self) -> None:
        pyproject = self.root / "pyproject.toml"
        pyproject.write_text('[project]\nname = "fixture"\n', encoding="utf-8")
        requirements = self.root / "requirements.txt"
        requirements.write_text("# comment\n--index-url local\n", encoding="utf-8")
        self.assertFalse(_declares_dependencies(self.root))
        requirements.write_text("fixture==1\n", encoding="utf-8")
        self.assertTrue(_declares_dependencies(self.root))
        with patch.object(Path, "read_text", side_effect=OSError("fixture")):
            self.assertTrue(_declares_dependencies(self.root))

    def test_inventory_exclusions_and_distribution_filtering(self) -> None:
        excluded = self.root / "excluded"
        nested = excluded / "nested"
        nested.mkdir(parents=True)
        included = self.root / "included.py"
        included.write_text("value = 1\n", encoding="utf-8")
        self.assertTrue(_is_excluded(excluded, (excluded,)))
        self.assertTrue(_is_excluded(nested, (excluded,)))
        self.assertFalse(_is_excluded(included, (excluded,)))
        self.assertEqual(_distribution_files(self.root), [])
        dist = self.root / "dist"
        dist.mkdir()
        for name in ("fixture.whl", "fixture.tar.gz", "fixture.zip", "ignored.txt"):
            (dist / name).write_bytes(b"fixture")
        self.assertEqual(
            _distribution_files(self.root),
            ["dist/fixture.tar.gz", "dist/fixture.whl", "dist/fixture.zip"],
        )
        inventory = inventory_target(self.root, excluded_paths=(excluded,))
        self.assertEqual(inventory.python_files, 1)


if __name__ == "__main__":
    unittest.main()
