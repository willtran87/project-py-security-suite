from __future__ import annotations

import unittest
from typing import Any

from py_security_suite.effectiveness import assurance_claims_artifact
from py_security_suite.models import (
    Confidence,
    Finding,
    Severity,
    ToolRun,
    ToolStatus,
)


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


if __name__ == "__main__":
    unittest.main()
