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

    def not_applicable_reason(self, target: Path) -> None:
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
        self.assertIn("READY: profile standard", render_readiness(document))

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
                intelligence.return_value.errors = []
                baseline.return_value.errors = []
                document = assess_readiness(target=target, config=config)
        self.assertFalse(document["ready"])
        self.assertEqual(document["blocking_tools"], ["semgrep"])
        self.assertIn("approved rules are missing", render_readiness(document))


if __name__ == "__main__":
    unittest.main()
