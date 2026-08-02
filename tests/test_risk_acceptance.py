from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from datetime import date, timedelta
from pathlib import Path

from py_security_suite.models import Confidence, Finding, FindingStatus, Severity
from py_security_suite.risk_acceptance import (
    _entries,
    _normalize,
    apply_risk_acceptances,
    validate_risk_acceptances,
)


_TODAY = date(2026, 8, 1)
_FINGERPRINT = "sha256:" + "a" * 64


def _finding() -> Finding:
    return Finding(
        finding_id="PYSEC-ACCEPTANCE-FIXTURE",
        fingerprint=_FINGERPRINT,
        title="Fixture",
        description="Fixture",
        impact="Fixture",
        remediation="Fixture",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        area="fixture",
    )


def _entry(**changes: object) -> dict[str, object]:
    value: dict[str, object] = {
        "fingerprint": _FINGERPRINT,
        "finding_id": "PYSEC-ACCEPTANCE-FIXTURE",
        "disposition": "accepted_risk",
        "owner": "security@example.invalid",
        "rationale": "A time-bounded fixture rationale.",
        "expires": "2026-08-31",
    }
    value.update(changes)
    return value


class RiskAcceptanceTests(unittest.TestCase):
    def test_absent_ledger_does_not_change_findings(self) -> None:
        item = _finding()
        self.assertEqual(apply_risk_acceptances([item], None), [])
        self.assertEqual(item.status, FindingStatus.NEW)

    def test_exact_acceptance_is_applied_with_governance_metadata(self) -> None:
        item = _finding()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "acceptances.json"
            data = json.dumps(
                {"schema_version": "1.0", "acceptances": [_entry()]}
            ).encode("utf-8")
            path.write_bytes(data)
            errors = apply_risk_acceptances(
                [item],
                path,
                hashlib.sha256(data).hexdigest(),
                today=_TODAY,
            )

        self.assertEqual(errors, [])
        self.assertEqual(item.status, FindingStatus.SUPPRESSED)
        governance = item.evidence["risk_acceptance"]
        self.assertEqual(governance["owner"], "security@example.invalid")
        self.assertEqual(governance["expires"], "2026-08-31")

    def test_preflight_validation_does_not_treat_unmatched_entries_as_stale(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "acceptances.json"
            path.write_text(
                json.dumps({"schema_version": "1.0", "acceptances": [_entry()]}),
                encoding="utf-8",
            )
            errors = validate_risk_acceptances(path, today=_TODAY)
        self.assertEqual(errors, [])

    def test_bad_digest_and_non_object_document_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "acceptances.json"
            path.write_text("[]", encoding="utf-8")
            root_errors = apply_risk_acceptances([], path, today=_TODAY)
            path.write_text(
                json.dumps({"schema_version": "1.0", "acceptances": []}),
                encoding="utf-8",
            )
            digest_errors = apply_risk_acceptances([], path, "b" * 64, today=_TODAY)

        self.assertIn("root must be an object", root_errors[0])
        self.assertIn("SHA-256 does not match", digest_errors[0])

    def test_stale_duplicate_and_id_mismatch_are_rejected(self) -> None:
        item = _finding()
        cases = (
            ([_entry(), _entry()], "duplicate risk acceptance"),
            ([_entry(finding_id="PYSEC-DIFFERENT")], "declared finding_id"),
            ([_entry(fingerprint="sha256:" + "b" * 64)], "does not match"),
        )
        for acceptances, message in cases:
            with (
                self.subTest(message=message),
                tempfile.TemporaryDirectory() as directory,
            ):
                path = Path(directory) / "acceptances.json"
                path.write_text(
                    json.dumps({"schema_version": "1.0", "acceptances": acceptances}),
                    encoding="utf-8",
                )
                errors = apply_risk_acceptances([item], path, today=_TODAY)
            self.assertIn(message, " ".join(errors))

    def test_document_shape_limits_are_enforced(self) -> None:
        with self.assertRaisesRegex(ValueError, "schema_version"):
            _entries({"schema_version": "2", "acceptances": []})
        with self.assertRaisesRegex(TypeError, "must be a list"):
            _entries({"schema_version": "1.0", "acceptances": {}})
        with self.assertRaisesRegex(ValueError, "exceeds 1000"):
            _entries({"schema_version": "1.0", "acceptances": [None] * 1001})

    def test_entry_shape_identity_and_disposition_are_enforced(self) -> None:
        cases = (
            (None, TypeError, "entry must be an object"),
            (_entry(extra=True), ValueError, "unknown fields"),
            (_entry(fingerprint="bad"), ValueError, "lowercase sha256"),
            (_entry(disposition="ignored"), ValueError, "unsupported disposition"),
            (_entry(owner=""), ValueError, "owner is required"),
            (_entry(rationale="x" * 2001), ValueError, "exceeds 2000"),
        )
        for value, exception, message in cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(exception, message):
                    _normalize(value, _TODAY)

    def test_expiry_is_valid_bounded_and_time_limited(self) -> None:
        cases = (
            (_entry(expires="not-a-date"), "must be an ISO date"),
            (_entry(expires="2026-07-31"), "expired"),
            (
                _entry(expires=(_TODAY + timedelta(days=367)).isoformat()),
                "more than 366 days",
            ),
        )
        for value, message in cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(ValueError, message):
                    _normalize(value, _TODAY)


if __name__ == "__main__":
    unittest.main()
