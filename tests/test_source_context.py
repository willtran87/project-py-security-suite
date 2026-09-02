from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from py_security_suite.models import (
    Confidence,
    Finding,
    Location,
    Severity,
    Source,
)
from py_security_suite.source_context import (
    attach_source_context,
    is_secret_bearing_scan,
    redact_sensitive_text,
    redact_sensitive_snippets,
    sanitize_secret_findings,
)


def finding(*, path: str, line: int, area: str = "injection") -> Finding:
    return Finding(
        finding_id="PYSEC-CONTEXT",
        fingerprint="sha256:context",
        title="Context fixture",
        description="Context fixture",
        impact="Context fixture",
        remediation="Context fixture",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        area=area,
        locations=[Location(path=path, start_line=line, end_line=line)],
        sources=[
            Source(
                tool="bandit" if area != "secrets" else "detect-secrets",
                rule_id="TEST",
                message="fixture",
            )
        ],
    )


class SourceContextTests(unittest.TestCase):
    def test_secret_lane_classification_is_shared_across_area_and_tool(self) -> None:
        self.assertTrue(is_secret_bearing_scan(area="secrets", tool_name="codeql"))
        self.assertTrue(is_secret_bearing_scan(area="other", tool_name="Gitleaks"))
        self.assertFalse(is_secret_bearing_scan(area="injection", tool_name="codeql"))

    def test_scanner_text_redacts_credentials_without_losing_context(self) -> None:
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIn0.signaturevalue"  # pragma: allowlist secret
        value = (
            "source Authorization: Bearer bearer_secret; "
            "url=postgresql://user:password@example.test/database; "  # pragma: allowlist secret
            f"token={jwt}; sink"
        )

        redacted = redact_sensitive_text(value)

        self.assertIn("source", redacted)
        self.assertIn("sink", redacted)
        self.assertNotIn("bearer_secret", redacted)
        self.assertNotIn("user:password", redacted)
        self.assertNotIn(jwt, redacted)
        self.assertGreaterEqual(redacted.count("<redacted>"), 3)

    def test_secret_scanner_text_is_fail_closed(self) -> None:
        secret = "unstructured-value-that-patterns-cannot-classify"  # pragma: allowlist secret

        redacted = redact_sensitive_text(secret, secret_bearing=True)

        self.assertNotIn(secret, redacted)
        self.assertIn("sensitive scanner text", redacted)

    def test_excerpt_is_bounded_numberable_and_sanitized(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            (target / "app.py").write_text(
                "before = 1\n"
                "password = exposed_fixture\n"
                "dangerous_call(user_input)\n"
                "after = 1\n",
                encoding="utf-8",
            )
            item = finding(path="app.py", line=3)
            attach_source_context(target, [item], context_lines=1)

        location = item.locations[0]
        self.assertEqual(location.snippet_start_line, 2)
        self.assertIn("password = <redacted>", location.snippet or "")
        self.assertIn("dangerous_call(user_input)", location.snippet or "")

    def test_excerpt_redacts_quoted_and_structured_secret_assignments(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            (target / "settings.py").write_text(
                'password = "a secret with spaces"  # owner note\n'  # pragma: allowlist secret
                "config['api_key'] = 'quoted-value'\n"  # pragma: allowlist secret
                'payload = {"private-key": "json-value", "safe": 1}\n'
                "token: unquoted yaml value # deployment note\n"
                "if token == expected_token:\n"
                "    dangerous_call(user_input)\n",
                encoding="utf-8",
            )
            item = finding(path="settings.py", line=6)
            attach_source_context(target, [item], context_lines=5)

        snippet = item.locations[0].snippet or ""
        for secret in (
            "a secret with spaces",
            "quoted-value",
            "json-value",
            "unquoted yaml value",
        ):
            self.assertNotIn(secret, snippet)
        self.assertIn("password = <redacted>  # owner note", snippet)
        self.assertIn("config['api_key'] = <redacted>", snippet)
        self.assertIn('"private-key": <redacted>, "safe": 1', snippet)
        self.assertIn("token: <redacted> # deployment note", snippet)
        self.assertIn("if token == expected_token:", snippet)

    def test_secret_source_is_never_embedded(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            (target / "settings.py").write_text(
                "api_token = real_value_must_not_leak\n",
                encoding="utf-8",
            )
            item = finding(path="settings.py", line=1, area="secrets")
            attach_source_context(target, [item])

        location = item.locations[0]
        self.assertTrue(location.snippet_redacted)
        self.assertNotIn("real_value_must_not_leak", location.snippet or "")

    def test_report_boundary_replaces_untrusted_redacted_snippets(self) -> None:
        item = finding(path="settings.py", line=1)
        item.locations[0].snippet = "raw_value_must_not_survive"
        item.locations[0].snippet_redacted = True

        redact_sensitive_snippets([item])

        location = item.locations[0]
        self.assertTrue(location.snippet_redacted)
        self.assertNotIn("raw_value_must_not_survive", location.snippet or "")
        self.assertEqual(location.snippet_start_line, 1)

    def test_report_boundary_redacts_secret_findings_from_future_adapters(
        self,
    ) -> None:
        item = finding(path="settings.py", line=1, area="secrets-history")
        item.sources[0].tool = "future-secret-scanner"
        item.locations[0].snippet = "future_adapter_secret"

        redact_sensitive_snippets([item])

        self.assertTrue(item.locations[0].snippet_redacted)
        self.assertNotIn("future_adapter_secret", item.locations[0].snippet or "")

    def test_secret_finding_boundary_discards_all_scanner_controlled_text(self) -> None:
        sentinel = "future-adapter-value-must-not-survive"
        item = finding(path="settings.py", line=1, area="secrets-history")
        item.sources[0].tool = "future-secret-scanner"
        item.title = sentinel
        item.description = sentinel
        item.impact = sentinel
        item.remediation = sentinel
        item.sources[0].rule_id = sentinel
        item.sources[0].message = sentinel
        item.citations = []
        item.evidence = {
            "redacted": False,
            "verified": True,
            "scan_mode": "git",
            "commit": "a" * 40,
            "raw": sentinel,
        }

        sanitize_secret_findings([item])

        self.assertNotIn(sentinel, repr(item))
        self.assertEqual(item.title, "Redacted credential candidate")
        self.assertEqual(
            item.evidence,
            {
                "redacted": True,
                "verified": True,
                "scan_mode": "git",
                "commit": "a" * 40,
            },
        )
        self.assertTrue(item.locations[0].snippet_redacted)

    def test_path_outside_target_is_not_read(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target"
            target.mkdir()
            (root / "outside.py").write_text("sensitive\n", encoding="utf-8")
            item = finding(path="../outside.py", line=1)
            attach_source_context(target, [item])

        self.assertIsNone(item.locations[0].snippet)


if __name__ == "__main__":
    unittest.main()
