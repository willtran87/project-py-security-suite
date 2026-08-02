from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from py_security_suite.adapters.base import ScannerReadiness
from py_security_suite.config import load_config
from py_security_suite.doctor import assess_readiness, render_readiness


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


if __name__ == "__main__":
    unittest.main()
