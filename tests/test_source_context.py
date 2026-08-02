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
from py_security_suite.source_context import attach_source_context


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
