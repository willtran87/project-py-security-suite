from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from datetime import date, timedelta
from pathlib import Path

from py_security_suite.config import SuiteConfig, ToolConfig, load_config
from py_security_suite.trust_catalog import apply_trust_catalog


class TrustCatalogTests(unittest.TestCase):
    def test_unconfigured_catalog_is_explicit(self) -> None:
        result = apply_trust_catalog(load_config(profile_override="quick"))
        self.assertFalse(result.artifact["configured"])
        self.assertEqual(result.errors, [])

    def test_approved_digest_bound_catalog_applies_pin(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "trust.json"
            _write_catalog(path)
            config = load_config(profile_override="quick")
            config.trust.catalog_path = path
            config.trust.catalog_sha256 = _sha256(path)

            result = apply_trust_catalog(config)

        self.assertEqual(result.errors, [])
        self.assertEqual(config.tools["bandit"].executable_sha256, "a" * 64)
        self.assertEqual(result.artifact["applied"][0]["approved_by"], "security-team")

    def test_catalog_digest_mismatch_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "trust.json"
            _write_catalog(path)
            config = load_config(profile_override="quick")
            config.trust.catalog_path = path
            config.trust.catalog_sha256 = "b" * 64

            result = apply_trust_catalog(config)

        self.assertRegex(result.errors[0], "SHA-256 mismatch")
        self.assertEqual(config.tools["bandit"].executable_sha256, "")

    def test_expired_entry_fails_and_explicit_pin_has_precedence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "trust.json"
            _write_catalog(path, expires=date.today() - timedelta(days=1))
            config = load_config(profile_override="quick")
            config.trust.catalog_path = path
            config.trust.catalog_sha256 = _sha256(path)
            result = apply_trust_catalog(config)
            self.assertRegex(result.errors[0], "expired")

            _write_catalog(path, expires=date.today() + timedelta(days=30))
            config.trust.catalog_sha256 = _sha256(path)
            config.tools["bandit"].executable_sha256 = "c" * 64
            result = apply_trust_catalog(config)

        self.assertEqual(config.tools["bandit"].executable_sha256, "c" * 64)
        self.assertEqual(
            result.artifact["ignored"][0]["reason"], "explicit_pin_precedence"
        )

    def test_platform_auxiliary_and_unconfigured_tool_decisions_are_retained(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "trust.json"
            entries = [
                _entry("bandit", role="auxiliary", digest="b" * 64),
                _entry("semgrep", platforms=["definitely-not-this-platform"]),
                _entry("detect-secrets", digest="c" * 64),
            ]
            _write_catalog(path, entries=entries)
            config = SuiteConfig(tools={"bandit": ToolConfig()})
            config.trust.catalog_path = path
            config.trust.catalog_sha256 = _sha256(path)

            result = apply_trust_catalog(config)

        self.assertEqual(result.errors, [])
        self.assertEqual(config.tools["bandit"].auxiliary_executable_sha256, "b" * 64)
        self.assertEqual(
            {item["reason"] for item in result.artifact["ignored"]},
            {"platform_not_applicable", "tool_not_configured"},
        )

    def test_invalid_catalog_shapes_fail_closed(self) -> None:
        cases: tuple[tuple[object, str], ...] = (
            ([], "must be a JSON object"),
            ({"schema_version": "2.0"}, "schema_version"),
            (
                {
                    "schema_version": "1.0",
                    "status": "draft",
                    "catalog_id": "id",
                    "revision": "1",
                    "entries": [],
                },
                "status",
            ),
            (
                {
                    "schema_version": "1.0",
                    "status": "approved",
                    "catalog_id": "id",
                    "revision": "1",
                    "entries": [_entry("bandit"), _entry("bandit")],
                },
                "duplicate",
            ),
            (
                {
                    "schema_version": "1.0",
                    "status": "approved",
                    "catalog_id": "id",
                    "revision": "1",
                    "entries": [_entry("bandit", role="invalid")],
                },
                "role",
            ),
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "trust.json"
            for document, message in cases:
                with self.subTest(message=message):
                    path.write_text(json.dumps(document), encoding="utf-8")
                    config = load_config(profile_override="quick")
                    config.trust.catalog_path = path
                    config.trust.catalog_sha256 = _sha256(path)
                    result = apply_trust_catalog(config)
                    self.assertRegex(result.errors[0], message)


def _write_catalog(
    path: Path,
    *,
    expires: date | None = None,
    entries: list[dict[str, object]] | None = None,
) -> None:
    document = {
        "schema_version": "1.0",
        "status": "approved",
        "catalog_id": "enterprise-python-scanners",
        "revision": "2026.08.06",
        "entries": entries or [_entry("bandit", expires=expires)],
    }
    path.write_text(json.dumps(document), encoding="utf-8")


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _entry(
    tool: str,
    *,
    role: str = "primary",
    digest: str = "a" * 64,
    expires: date | None = None,
    platforms: list[str] | None = None,
) -> dict[str, object]:
    return {
        "tool": tool,
        "role": role,
        "sha256": digest,
        "version": "1.8.6",
        "source": "internal-artifact-repository",
        "approved_by": "security-team",
        "expires": str(expires or date.today() + timedelta(days=30)),
        "platforms": platforms or ["any"],
    }
