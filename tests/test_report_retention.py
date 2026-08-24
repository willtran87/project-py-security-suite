from __future__ import annotations

import tempfile
import unittest
import json
from unittest.mock import patch
from datetime import UTC, datetime
from pathlib import Path

from jsonschema import Draft202012Validator

from py_security_suite.config import load_config
from py_security_suite.orchestrator import scan_project
from py_security_suite.report_retention import purge_verified_report, retention_status
from py_security_suite.report_inspection import read_bundled_schema
from tests.test_orchestrator import FakeBandit, FakeSecrets


class ReportRetentionTests(unittest.TestCase):
    def test_retention_is_enforced_and_expired_report_is_purged(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target"
            target.mkdir()
            (target / "app.py").write_text("print(1)\n", encoding="utf-8")
            report = root / "report"
            scan_project(
                target=target,
                output=report,
                config=load_config(profile_override="quick"),
                network_isolation_attested=True,
                adapter_types={"bandit": FakeBandit, "detect-secrets": FakeSecrets},
            )
            for artifact, schema in {
                "boundary-graph.json": "boundary-graph-1.0",
                "dependency-surface.json": "dependency-surface-1.1",
                "isolation-boundary.json": "isolation-boundary-1.0",
                "isolation-probe.json": "isolation-probe-1.0",
                "report-security.json": "report-security-1.0",
                "resource-limits.json": "resource-limits-1.0",
                "runtime-closure.json": "runtime-closure-1.0",
                "semantic-language-coverage.json": "semantic-language-coverage-1.0",
                "trust-policy.json": "trust-policy-1.0",
                "trust-policy-attestation.json": "trust-policy-attestation-1.0",
            }.items():
                Draft202012Validator(json.loads(read_bundled_schema(schema))).validate(
                    json.loads((report / artifact).read_text(encoding="utf-8"))
                )
            status = retention_status(
                report, observed_at=datetime(2026, 8, 23, tzinfo=UTC)
            )
            self.assertFalse(status["expired"])
            with self.assertRaisesRegex(ValueError, "has not been reached"):
                with patch(
                    "py_security_suite.report_retention.verify_rfc3161",
                    return_value={
                        "trusted_time_observed_at": "2026-08-23T00:00:00+00:00",
                        "trusted_time_receipt_sha256": "a" * 64,
                    },
                ):
                    context = root / "retention-time.json"
                    context.write_text(
                        json.dumps({"schema_version": "1.0", "trusted_time": {}}),
                        encoding="utf-8",
                    )
                    purge_verified_report(report, trusted_time_context=context)
            with patch(
                "py_security_suite.report_retention.verify_rfc3161",
                return_value={
                    "trusted_time_observed_at": "2100-01-01T00:00:00+00:00",
                    "trusted_time_receipt_sha256": "a" * 64,
                },
            ):
                receipt = purge_verified_report(report, trusted_time_context=context)
            self.assertTrue(receipt["purged"])
            self.assertFalse(report.exists())
