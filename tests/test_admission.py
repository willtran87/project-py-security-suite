from __future__ import annotations

import json
import unittest

# The isolated Pylint lane intentionally omits locked test-only dependencies.
from jsonschema import Draft202012Validator  # pylint: disable=import-error

from py_security_suite.admission import admission_decisions
from py_security_suite.models import (
    Confidence,
    Finding,
    Severity,
    Source,
    ToolRun,
    ToolStatus,
)
from py_security_suite.report_inspection import read_bundled_schema


class AdmissionDecisionTests(unittest.TestCase):
    def test_axes_separate_source_success_from_artifact_failure(self) -> None:
        runs = [
            ToolRun("bandit", ToolStatus.COMPLETED, [], 0.1),
            ToolRun("coverage", ToolStatus.COMPLETED, [], 0.1),
            ToolRun("osv-scanner", ToolStatus.COMPLETED, [], 0.1),
            ToolRun("cosign", ToolStatus.COMPLETED, [], 0.1),
            ToolRun("actionlint", ToolStatus.COMPLETED, [], 0.1),
        ]
        finding = Finding(
            finding_id="PYSEC-ARTIFACT",
            fingerprint="sha256:" + "a" * 64,
            title="Signature missing",
            description="Distribution has no signature.",
            impact="Consumers cannot verify provenance.",
            remediation="Sign the exact artifact.",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            area="provenance",
            sources=[Source("cosign", "unsigned", "missing")],
            blocking=True,
        )

        result = admission_decisions(
            [finding],
            runs,
            network_isolation_attested=True,
            source_integrity_verified=True,
        )
        rows = {row["axis"]: row for row in result["axes"]}
        self.assertEqual(rows["source"]["decision"], "allow")
        self.assertEqual(rows["tests"]["decision"], "allow")
        self.assertEqual(rows["artifacts"]["decision"], "block")
        schema = json.loads(read_bundled_schema("admission-decisions-1.0"))
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(result)

    def test_governance_axis_exposes_isolation_integrity_and_trust_gaps(self) -> None:
        run = ToolRun(
            "bandit",
            ToolStatus.COMPLETED,
            [],
            0.1,
            executable_sha256="a" * 64,
            executable_organization_approved=False,
        )
        result = admission_decisions(
            [],
            [run],
            network_isolation_attested=False,
            source_integrity_verified=False,
        )
        governance = next(row for row in result["axes"] if row["axis"] == "governance")
        self.assertEqual(governance["decision"], "incomplete")
        self.assertEqual(len(governance["integrity_gaps"]), 3)


if __name__ == "__main__":
    unittest.main()
