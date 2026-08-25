from __future__ import annotations

import json
import tempfile
import unittest
from importlib.resources import files
from pathlib import Path
from unittest.mock import patch

from jsonschema import Draft202012Validator  # pylint: disable=import-error

from py_security_suite.adapters.base import ScannerReadiness
from py_security_suite.config import load_config
from py_security_suite.doctor import (
    _production_authority_error,
    assess_readiness,
    render_readiness,
    render_readiness_markdown,
)


class _ReadyAdapter:
    def __init__(self, _config: object, _max_output_bytes: int) -> None:
        pass

    def not_applicable_reason(self, target: Path) -> str | None:
        del target
        return None

    def preflight(self, target: Path) -> ScannerReadiness:
        del target
        return ScannerReadiness(
            tool="bandit",
            status="ready",
            executable="bandit",
            executable_sha256="a" * 64,
            executable_integrity_verified=True,
        )


class _UnavailableAdapter(_ReadyAdapter):
    def preflight(self, target: Path) -> ScannerReadiness:
        del target
        return ScannerReadiness(
            tool="semgrep",
            status="unavailable",
            reason="approved rules are missing",
        )


class _NotApplicableAdapter(_ReadyAdapter):
    def not_applicable_reason(self, target: Path) -> str:
        del target
        return "target has no applicable manifest"


class DoctorTests(unittest.TestCase):
    def test_production_preflight_requires_organization_digest_authority(self) -> None:
        config = load_config(profile_override="production")
        config.tools["bandit"].executable_sha256 = "a" * 64
        self.assertIn(
            "organization approval is missing",
            _production_authority_error(config, "bandit"),
        )
        config.tools["bandit"].executable_organization_approved = True
        self.assertEqual(_production_authority_error(config, "bandit"), "")

    def test_ready_profile_is_concise_and_machine_readable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            config = load_config(profile_override="standard")
            with (
                patch.dict(
                    "py_security_suite.doctor.ADAPTER_TYPES",
                    {name: _ReadyAdapter for name in config.selected_tools},
                    clear=True,
                ),
                patch("py_security_suite.doctor.enrich_findings") as intelligence,
                patch("py_security_suite.doctor.apply_finding_delta") as baseline,
            ):
                intelligence.return_value.errors = []
                baseline.return_value.errors = []
                document = assess_readiness(target=target, config=config)
        self.assertTrue(document["ready"])
        self.assertEqual(document["summary"]["ready"], 4)
        self.assertEqual(document["summary"]["applicable"], 4)
        self.assertEqual(document["summary"]["required_ready"], 4)
        self.assertEqual(document["decision"]["disposition"], "proceed")
        rendered = render_readiness(document)
        self.assertIn("READY: profile standard", rendered)
        self.assertIn("Decision: PROCEED TO ISOLATED SCAN (preflight only)", rendered)
        self.assertIn("release approval", rendered)
        self.assertEqual(document["schema_version"], "1.1")
        self.assertEqual(document["next_actions"], [])
        schema = json.loads(
            files("py_security_suite")
            .joinpath("schemas", "doctor-readiness-1.1.schema.json")
            .read_text("utf-8")
        )
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(document)

    def test_required_unavailable_tool_blocks_readiness(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            config = load_config(profile_override="standard")
            adapters = {name: _ReadyAdapter for name in config.selected_tools}
            adapters["semgrep"] = _UnavailableAdapter
            with (
                patch.dict(
                    "py_security_suite.doctor.ADAPTER_TYPES",
                    adapters,
                    clear=True,
                ),
                patch("py_security_suite.doctor.enrich_findings") as intelligence,
                patch("py_security_suite.doctor.apply_finding_delta") as baseline,
            ):
                intelligence.return_value.errors = ["EPSS digest mismatch"]
                baseline.return_value.errors = []
                document = assess_readiness(target=target, config=config)
        self.assertFalse(document["ready"])
        self.assertEqual(document["blocking_tools"], ["semgrep"])
        self.assertEqual(document["decision"]["disposition"], "block")
        self.assertEqual(len(document["decision"]["blocking_reasons"]), 2)
        rendered = render_readiness(document)
        self.assertIn("Decision: BLOCK PRE-FLIGHT (preflight only)", rendered)
        self.assertIn("[required] semgrep", rendered)
        self.assertIn("approved rules are missing", rendered)
        self.assertIn("[required context] EPSS digest mismatch", rendered)
        explained = render_readiness(document, explain=True)
        self.assertIn("Resolution batches:", explained)
        self.assertEqual(len(document["action_groups"]), 2)
        self.assertTrue(all(group["count"] == 1 for group in document["action_groups"]))
        self.assertIn("P0 BLOCK [missing evidence]: semgrep", explained)
        self.assertIn("semgrep: approved rules are missing", explained)
        self.assertIn("Selected controls:", explained)
        markdown = render_readiness_markdown(document)
        self.assertIn("# Scan preflight", markdown)
        self.assertIn("| P0 | BLOCK | missing evidence | 1 (semgrep)", markdown)
        self.assertIn("<summary>Per-control actions (2)</summary>", markdown)
        self.assertIn("<summary>All selected controls</summary>", markdown)

    def test_optional_unavailable_tool_is_visible_but_does_not_block(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            config = load_config(profile_override="standard")
            config.policy.required_scanners = ("bandit", "detect-secrets")
            adapters = {name: _ReadyAdapter for name in config.selected_tools}
            adapters["semgrep"] = _UnavailableAdapter
            with (
                patch.dict(
                    "py_security_suite.doctor.ADAPTER_TYPES",
                    adapters,
                    clear=True,
                ),
                patch("py_security_suite.doctor.enrich_findings") as intelligence,
                patch("py_security_suite.doctor.apply_finding_delta") as baseline,
            ):
                intelligence.return_value.errors = []
                baseline.return_value.errors = []
                document = assess_readiness(target=target, config=config)
        self.assertTrue(document["ready"])
        self.assertEqual(document["blocking_tools"], [])
        self.assertEqual(document["optional_attention_tools"], ["semgrep"])
        self.assertEqual(document["summary"]["attention"], 1)
        self.assertIn("[optional] semgrep", render_readiness(document))

    def test_missing_disabled_and_not_applicable_adapters_are_distinct(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            config = load_config(profile_override="standard")
            config.tools["semgrep"].enabled = False
            config.tools["detect-secrets"].enabled = False
            adapters = {
                "semgrep": _ReadyAdapter,
                "detect-secrets": _NotApplicableAdapter,
                "osv-scanner": _ReadyAdapter,
            }
            with (
                patch.dict(
                    "py_security_suite.doctor.ADAPTER_TYPES", adapters, clear=True
                ),
                patch("py_security_suite.doctor.enrich_findings") as intelligence,
                patch("py_security_suite.doctor.apply_finding_delta") as baseline,
            ):
                intelligence.return_value.errors = []
                baseline.return_value.errors = []
                document = assess_readiness(target=target, config=config)
        statuses = {item["tool"]: item["status"] for item in document["tools"]}
        self.assertEqual(statuses["bandit"], "unavailable")
        self.assertEqual(statuses["semgrep"], "disabled")
        self.assertEqual(statuses["detect-secrets"], "not_applicable")
        self.assertEqual(document["summary"]["not_applicable"], 1)
        not_applicable = next(
            item for item in document["tools"] if item["tool"] == "detect-secrets"
        )
        self.assertEqual(not_applicable["category"], "content_absent")
        self.assertIn("becomes applicable", not_applicable["required_action"])

    def test_conditional_evidence_is_grouped_by_actionable_reason(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            config = load_config(profile_override="comprehensive")

            class _EvidenceAdapter(_NotApplicableAdapter):
                def not_applicable_reason(self, target: Path) -> str:
                    del target
                    return "no pre-generated atheris evidence was found"

                def preflight(self, target: Path) -> ScannerReadiness:
                    return ScannerReadiness(
                        tool="evidence",
                        status="not_applicable",
                        reason=self.not_applicable_reason(target),
                    )

            with (
                patch.dict(
                    "py_security_suite.doctor.ADAPTER_TYPES",
                    {name: _EvidenceAdapter for name in config.selected_tools},
                    clear=True,
                ),
                patch("py_security_suite.doctor.enrich_findings") as intelligence,
                patch("py_security_suite.doctor.apply_finding_delta") as baseline,
            ):
                intelligence.return_value.errors = []
                baseline.return_value.errors = []
                document = assess_readiness(target=target, config=config)

        self.assertTrue(document["conditional_actions"])
        self.assertEqual(
            document["summary"]["missing_evidence"], len(document["tools"])
        )
        self.assertTrue(
            all(not action["blocking"] for action in document["next_actions"])
        )
        self.assertTrue(
            all(action["priority"] == "P2" for action in document["next_actions"])
        )
        self.assertEqual(len(document["action_groups"]), 1)
        self.assertEqual(document["action_groups"][0]["count"], len(document["tools"]))
        self.assertEqual(
            document["action_groups"][0]["subjects"],
            sorted(item["tool"] for item in document["tools"]),
        )
        self.assertIn(
            f"+{len(document['tools']) - 6} more",
            render_readiness_markdown(document),
        )
        self.assertIn("Conditional evidence", render_readiness(document))

    def test_guidance_distinguishes_configuration_evidence_and_approval(self) -> None:
        from py_security_suite.doctor import _readiness_guidance

        self.assertEqual(
            _readiness_guidance(
                "unavailable",
                "certificate_identity and certificate_oidc_issuer required",
            )[0],
            "missing_configuration",
        )
        self.assertEqual(
            _readiness_guidance("unavailable", "a pre-staged CodeQL CLI is required")[
                0
            ],
            "missing_evidence",
        )
        category, action = _readiness_guidance(
            "unavailable", "organization approval is missing for bandit primary"
        )
        self.assertEqual(category, "missing_approval")
        self.assertIn("provenance review", action)
        category, action = _readiness_guidance(
            "not_applicable", "no approved target Python environment was configured"
        )
        self.assertEqual(category, "missing_configuration")
        self.assertIn("target Python environment", action)
        category, action = _readiness_guidance(
            "not_applicable",
            "no OpenAPI schema or pre-generated Schemathesis evidence was found",
        )
        self.assertEqual(category, "missing_evidence")
        self.assertIn("OpenAPI schema", action)


if __name__ == "__main__":
    unittest.main()
