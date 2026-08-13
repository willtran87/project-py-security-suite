from __future__ import annotations

import json
import unittest
from typing import Any

from jsonschema import Draft202012Validator

from py_security_suite.effectiveness import (
    assurance_claims_artifact,
    effectiveness_artifact,
)
from py_security_suite.models import (
    Confidence,
    Finding,
    Severity,
    ToolRun,
    ToolStatus,
)
from py_security_suite.report_inspection import read_bundled_schema


def _completed(tool: str) -> ToolRun:
    return ToolRun(
        tool=tool,
        status=ToolStatus.COMPLETED,
        command=[tool],
        duration_seconds=0.1,
    )


def _claim(document: dict[str, Any], control: str) -> dict[str, Any]:
    claims = document["claims"]
    if not isinstance(claims, list):
        raise TypeError("claims must be a list")
    return next(
        claim
        for claim in claims
        if isinstance(claim, dict) and claim.get("control") == control
    )


class AssuranceClaimsTests(unittest.TestCase):
    def test_provenance_claim_fails_when_cosign_reports_missing_bundle(self) -> None:
        finding = Finding(
            finding_id="PYSEC-PROVENANCE",
            fingerprint="sha256:" + "a" * 64,
            title="bundle missing",
            description="bundle missing",
            impact="artifact cannot be verified",
            remediation="sign artifact",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            area="artifact-provenance",
            domain="supply-chain",
        )

        document = assurance_claims_artifact(
            [finding],
            [_completed("cosign")],
            source_integrity=True,
            network_isolation_attested=True,
        )
        claim = _claim(document, "PS.3")

        self.assertEqual(document["schema_version"], "1.1")
        self.assertEqual(claim["result"], "not_satisfied")
        self.assertIn("PYSEC-PROVENANCE", " ".join(claim["blocking_reasons"]))

    def test_continuous_vulnerability_claim_requires_fresh_context(self) -> None:
        runs = [
            _completed("semgrep"),
            _completed("osv-scanner"),
        ]
        document = assurance_claims_artifact(
            [],
            runs,
            source_integrity=True,
            context_errors=["offline KEV intelligence is stale"],
            network_isolation_attested=False,
        )

        self.assertEqual(_claim(document, "RV.1")["result"], "not_satisfied")
        self.assertIn(
            "offline KEV intelligence is stale",
            _claim(document, "RV.1")["blocking_reasons"],
        )
        self.assertEqual(_claim(document, "PO.5")["result"], "not_satisfied")

    def test_all_claims_expose_machine_readable_blockers(self) -> None:
        document = assurance_claims_artifact(
            [],
            [
                _completed("semgrep"),
                _completed("osv-scanner"),
                _completed("cosign"),
            ],
            source_integrity=True,
            network_isolation_attested=True,
        )

        self.assertTrue(
            all(
                isinstance(claim.get("blocking_reasons"), list)
                for claim in document["claims"]
            )
        )


class EffectivenessPostureTests(unittest.TestCase):
    def test_tool_posture_keeps_execution_integrity_and_approval_distinct(
        self,
    ) -> None:
        approved = _completed("semgrep")
        approved.executable_integrity_verified = True
        approved.executable_organization_approved = True
        approved.executable_unchanged = True
        approval_gap = _completed("bandit")
        approval_gap.executable_integrity_verified = True
        approval_gap.executable_organization_approved = False
        approval_gap.executable_unchanged = True
        integrity_gap = _completed("codeql")
        integrity_gap.executable_integrity_verified = False
        integrity_gap.executable_organization_approved = True
        integrity_gap.executable_unchanged = True
        unavailable = ToolRun(
            tool="pysa",
            status=ToolStatus.UNAVAILABLE,
            command=["pysa"],
            duration_seconds=0.0,
        )

        document = effectiveness_artifact(
            [], [approved, approval_gap, integrity_gap, unavailable]
        )
        by_tool = {item["tool"]: item for item in document["tool_posture"]}

        self.assertEqual(document["schema_version"], "1.1")
        self.assertEqual(by_tool["semgrep"]["assurance_status"], "approved")
        self.assertEqual(by_tool["bandit"]["assurance_status"], "approval-gap")
        self.assertEqual(by_tool["codeql"]["assurance_status"], "integrity-gap")
        self.assertEqual(by_tool["pysa"]["assurance_status"], "execution-gap")
        self.assertEqual(by_tool["semgrep"]["evidence_lane"], "source-security")
        Draft202012Validator(
            json.loads(read_bundled_schema("effectiveness-1.1"))
        ).validate(document)

    def test_auxiliary_entry_point_is_part_of_assurance(self) -> None:
        run = _completed("codeql")
        run.executable_integrity_verified = True
        run.executable_organization_approved = True
        run.executable_unchanged = True
        run.auxiliary_executable_sha256 = "a" * 64
        run.auxiliary_executable_integrity_verified = True
        run.auxiliary_executable_organization_approved = False
        run.auxiliary_executable_unchanged = True

        posture = effectiveness_artifact([], [run])["tool_posture"][0]

        self.assertTrue(posture["auxiliary_executable_present"])
        self.assertEqual(posture["assurance_status"], "approval-gap")


if __name__ == "__main__":
    unittest.main()
