"""Regression tests for policy and configuration fail-open paths.

Each test reproduces a configuration or policy input that previously produced
PASS (or a silently weaker scan) and now fails closed.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
from datetime import date
from pathlib import Path
from unittest.mock import patch

from py_security_suite.config import ConfigurationError, load_config
from py_security_suite.config_policy_floor import profile_floor_error
from py_security_suite.models import (
    Confidence,
    Finding,
    FindingStatus,
    Outcome,
    Severity,
    ToolRun,
    ToolStatus,
)
from py_security_suite.policy import evaluate_policy
from py_security_suite.risk_acceptance import (
    apply_risk_acceptances,
    validate_risk_acceptances,
)


_TODAY = date(2026, 8, 1)
_FINGERPRINT = "sha256:" + "a" * 64


def _finding(severity: Severity, *, known_exploited: bool = False) -> Finding:
    item = Finding(
        finding_id="PYSEC-FAIL-CLOSED",
        fingerprint=_FINGERPRINT,
        title="Fixture",
        description="Fixture",
        impact="Fixture",
        remediation="Fixture",
        severity=severity,
        confidence=Confidence.HIGH,
        area="fixture",
    )
    if known_exploited:
        item.evidence = {"risk_intelligence": {"known_exploited": True}}
    return item


def _entry(**changes: object) -> dict[str, object]:
    value: dict[str, object] = {
        "fingerprint": _FINGERPRINT,
        "disposition": "accepted_risk",
        "owner": "security@example.invalid",
        "rationale": "A time-bounded fixture rationale.",
        "expires": "2026-08-31",
    }
    value.update(changes)
    return value


def _ledger(directory: str, *entries: dict[str, object]) -> tuple[Path, str]:
    path = Path(directory) / "acceptances.json"
    data = json.dumps({"schema_version": "1.0", "acceptances": list(entries)})
    path.write_text(data, encoding="utf-8")
    return path, hashlib.sha256(data.encode("utf-8")).hexdigest()


def _completed(names: tuple[str, ...]) -> list[ToolRun]:
    return [
        ToolRun(
            tool=name,
            status=ToolStatus.COMPLETED,
            command=[name],
            duration_seconds=0.1,
        )
        for name in names
    ]


class RequiredScannerUnionTests(unittest.TestCase):
    """Item 9: required_scanners must extend, never narrow, the profile."""

    def test_required_scanners_cannot_drop_profile_scanners(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config_path = Path(directory) / "pysec.toml"
            config_path.write_text(
                '[policy]\nrequired_scanners = ["bandit"]\n', encoding="utf-8"
            )
            config = load_config(repository_config=config_path)
        self.assertEqual(config.profile, "standard")
        self.assertEqual(set(config.required_tools), set(config.selected_tools))
        runs = _completed(("bandit",))
        runs.append(
            ToolRun(
                tool="semgrep",
                status=ToolStatus.FAILED,
                command=["semgrep"],
                duration_seconds=0.1,
                error="crashed",
            )
        )
        decision = evaluate_policy(
            config=config,
            findings=[],
            tool_runs=runs,
            network_isolation_attested=True,
        )
        self.assertEqual(decision.outcome, Outcome.INCOMPLETE)
        self.assertTrue(any("semgrep" in reason for reason in decision.reasons))

    def test_required_scanners_add_to_profile(self) -> None:
        config = load_config(profile_override="quick")
        config.policy.required_scanners = ("semgrep",)
        self.assertEqual(config.required_tools, ("bandit", "detect-secrets", "semgrep"))

    def test_disabling_a_profile_scanner_is_rejected_even_with_narrow_list(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config_path = Path(directory) / "pysec.toml"
            config_path.write_text(
                '[policy]\nrequired_scanners = ["bandit"]\n'
                "[tools.semgrep]\nenabled = false\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ConfigurationError, "cannot be disabled"):
                load_config(repository_config=config_path)


class ProfileFloorTests(unittest.TestCase):
    """Item 10: the organization profile is a floor."""

    def _load(
        self,
        organization: str,
        repository: str = "",
        override: str | None = None,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy = root / "policy.toml"
            policy.write_bytes(organization.encode("utf-8"))
            config_path = root / "pysec.toml"
            config_path.write_text(repository, encoding="utf-8")
            digest = hashlib.sha256(organization.encode("utf-8")).hexdigest()
            with patch.dict(os.environ, {"PYSEC_ORGANIZATION_POLICY_SHA256": digest}):
                load_config(
                    organization_policy=policy,
                    repository_config=config_path,
                    profile_override=override,
                )

    def test_repository_cannot_downgrade_organization_production_profile(
        self,
    ) -> None:
        with self.assertRaisesRegex(ConfigurationError, "weaker than"):
            self._load('profile = "production"\n', 'profile = "quick"\n')

    def test_cli_override_cannot_downgrade_organization_profile(self) -> None:
        with self.assertRaisesRegex(ConfigurationError, "weaker than"):
            self._load('profile = "production"\n', override="quick")
        with self.assertRaisesRegex(ConfigurationError, "weaker than"):
            self._load('profile = "standard"\n', override="quick")

    def test_production_floor_cannot_move_to_broader_non_production_profile(
        self,
    ) -> None:
        # repo/comprehensive run every production scanner but skip its gates.
        with self.assertRaisesRegex(ConfigurationError, "weaker than"):
            self._load('profile = "production"\n', override="comprehensive")
        with self.assertRaisesRegex(ConfigurationError, "weaker than"):
            self._load('profile = "release"\n', override="production")

    def test_raising_strictness_is_allowed(self) -> None:
        self._load('profile = "quick"\n', 'profile = "standard"\n')
        self._load('profile = "standard"\n', override="deep")
        self.assertEqual(
            profile_floor_error(
                "production", "release", {"production": (), "release": ()}
            ),
            "",
        )

    def test_without_organization_profile_any_profile_is_selectable(self) -> None:
        config = load_config(profile_override="quick")
        self.assertEqual(config.profile, "quick")


class RiskAcceptanceAuthorityTests(unittest.TestCase):
    """Item 11: production acceptances need an organization-pinned digest."""

    def test_production_rejects_repository_acceptance_without_org_pin(self) -> None:
        organization = 'profile = "production"\n'
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy = root / "policy.toml"
            policy.write_bytes(organization.encode("utf-8"))
            config_path = root / "pysec.toml"
            config_path.write_text(
                '[policy]\nrisk_acceptance_path = "accept.json"\n'
                f'risk_acceptance_sha256 = "{"a" * 64}"\n',
                encoding="utf-8",
            )
            digest = hashlib.sha256(organization.encode("utf-8")).hexdigest()
            with (
                patch.dict(os.environ, {"PYSEC_ORGANIZATION_POLICY_SHA256": digest}),
                self.assertRaisesRegex(
                    ConfigurationError, "pinned by the organization"
                ),
            ):
                load_config(organization_policy=policy, repository_config=config_path)

    def test_production_cli_profile_rejects_unpinned_acceptance(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config_path = Path(directory) / "pysec.toml"
            config_path.write_text(
                '[policy]\nrisk_acceptance_path = "accept.json"\n', encoding="utf-8"
            )
            with self.assertRaisesRegex(
                ConfigurationError, "pinned by the organization"
            ):
                load_config(repository_config=config_path, profile_override="release")

    def test_standard_profile_keeps_unpinned_acceptance_compatibility(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config_path = Path(directory) / "pysec.toml"
            config_path.write_text(
                '[policy]\nrisk_acceptance_path = "accept.json"\n', encoding="utf-8"
            )
            config = load_config(repository_config=config_path)
        self.assertEqual(config.policy.risk_acceptance_sha256, "")

    def test_policy_layer_rejects_unpinned_production_ledger(self) -> None:
        item = _finding(Severity.LOW)
        with tempfile.TemporaryDirectory() as directory:
            path, _ = _ledger(directory, _entry(max_severity="low"))
            errors = apply_risk_acceptances(
                [item], path, "", today=_TODAY, profile="production"
            )
        self.assertIn("organization-approved risk_acceptance_sha256", errors[0])
        self.assertIs(item.status, FindingStatus.NEW)


class AcceptanceBoundTests(unittest.TestCase):
    """Item 17: acceptances are bound to severity and KEV status."""

    def _apply(
        self, item: Finding, entry: dict[str, object], profile: str = "standard"
    ) -> list[str]:
        with tempfile.TemporaryDirectory() as directory:
            path, digest = _ledger(directory, entry)
            return apply_risk_acceptances(
                [item], path, digest, today=_TODAY, profile=profile
            )

    def test_severity_above_accepted_maximum_is_not_suppressed(self) -> None:
        item = _finding(Severity.CRITICAL)
        errors = self._apply(item, _entry(max_severity="low"))
        self.assertEqual(errors, [])
        self.assertIs(item.status, FindingStatus.NEW)
        self.assertIn("exceeds", item.evidence["risk_acceptance_rejected"])

    def test_severity_within_accepted_maximum_is_suppressed(self) -> None:
        item = _finding(Severity.LOW)
        self.assertEqual(self._apply(item, _entry(max_severity="medium")), [])
        self.assertIs(item.status, FindingStatus.SUPPRESSED)

    def test_unknown_severity_exceeds_any_bound_below_critical(self) -> None:
        item = _finding(Severity.UNKNOWN)
        self._apply(item, _entry(max_severity="high"))
        self.assertIs(item.status, FindingStatus.NEW)

    def test_newly_known_exploited_finding_is_not_suppressed(self) -> None:
        item = _finding(Severity.LOW, known_exploited=True)
        self._apply(item, _entry())
        self.assertIs(item.status, FindingStatus.NEW)
        self.assertIn("known-exploited", item.evidence["risk_acceptance_rejected"])
        acknowledged = _finding(Severity.LOW, known_exploited=True)
        self._apply(acknowledged, _entry(known_exploited=True))
        self.assertIs(acknowledged.status, FindingStatus.SUPPRESSED)

    def test_known_exploited_is_never_suppressed_in_production(self) -> None:
        item = _finding(Severity.LOW, known_exploited=True)
        self._apply(
            item,
            _entry(max_severity="critical", known_exploited=True),
            profile="release",
        )
        self.assertIs(item.status, FindingStatus.NEW)

    def test_production_requires_max_severity_and_strict_fields(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path, digest = _ledger(directory, _entry())
            errors = validate_risk_acceptances(
                path, digest, today=_TODAY, profile="production"
            )
            self.assertIn("max_severity is required", " ".join(errors))
            path, digest = _ledger(directory, _entry(max_severity="unknown"))
            errors = validate_risk_acceptances(path, digest, today=_TODAY)
            self.assertIn("unsupported max_severity", " ".join(errors))
            path, digest = _ledger(directory, _entry(known_exploited="true"))
            errors = validate_risk_acceptances(path, digest, today=_TODAY)
            self.assertIn("known_exploited must be a boolean", " ".join(errors))

    def test_policy_fails_when_bound_acceptance_is_exceeded(self) -> None:
        config = load_config(profile_override="quick")
        item = _finding(Severity.HIGH)
        with tempfile.TemporaryDirectory() as directory:
            path, digest = _ledger(directory, _entry(max_severity="low"))
            config.policy.risk_acceptance_path = path
            config.policy.risk_acceptance_sha256 = digest
            with patch(
                "py_security_suite.risk_acceptance.governed_now"
            ) as governed_now:
                governed_now.return_value.date.return_value = _TODAY
                decision = evaluate_policy(
                    config=config,
                    findings=[item],
                    tool_runs=_completed(config.required_tools),
                    network_isolation_attested=True,
                )
        self.assertEqual(decision.outcome, Outcome.FAIL)


class OutcomeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.config = load_config(profile_override="quick")
        self.runs = _completed(self.config.required_tools)

    def test_incomplete_reports_blocking_finding_count(self) -> None:
        """Item 18: INCOMPLETE must not hide blocking findings."""
        decision = evaluate_policy(
            config=self.config,
            findings=[_finding(Severity.CRITICAL)],
            tool_runs=self.runs,
            network_isolation_attested=False,
            context_errors=["fixture context error"],
        )
        self.assertEqual(decision.outcome, Outcome.INCOMPLETE)
        self.assertTrue(
            any("1 finding(s) already meet blocking" in r for r in decision.reasons)
        )

    def test_unknown_severity_blocks_in_production_and_release(self) -> None:
        """Item 19: unrated findings fail closed in production/release."""
        for profile in ("production", "release"):
            item = _finding(Severity.UNKNOWN)
            self.config.profile = profile
            evaluate_policy(
                config=self.config,
                findings=[item],
                tool_runs=self.runs,
                network_isolation_attested=True,
            )
            self.assertTrue(item.blocking, profile)
        self.config.profile = "quick"
        item = _finding(Severity.UNKNOWN)
        decision = evaluate_policy(
            config=self.config,
            findings=[item],
            tool_runs=self.runs,
            network_isolation_attested=True,
        )
        self.assertFalse(item.blocking)
        self.assertEqual(decision.outcome, Outcome.WARN)

    def test_diagnostic_without_isolation_never_passes(self) -> None:
        """Item 24: the diagnostic flag must reach policy."""
        self.config.isolation.require_attestation = False
        decision = evaluate_policy(
            config=self.config,
            findings=[],
            tool_runs=self.runs,
            network_isolation_attested=False,
            diagnostic_without_isolation=True,
        )
        self.assertEqual(decision.outcome, Outcome.INCOMPLETE)
        self.assertIn("diagnostic scan", " ".join(decision.reasons))


class StrictConfigurationTests(unittest.TestCase):
    def _load(self, text: str) -> None:
        # The organization layer bypasses repository weakening guards, so it
        # exercises the parser directly.
        with tempfile.TemporaryDirectory() as directory:
            policy = Path(directory) / "policy.toml"
            policy.write_bytes(text.encode("utf-8"))
            load_config(organization_policy=policy)

    def test_incomplete_is_blocking_false_is_rejected(self) -> None:
        """Item 25: the setting was parsed but silently ignored."""
        with self.assertRaisesRegex(ConfigurationError, "incomplete scans always"):
            self._load("[policy]\nincomplete_is_blocking = false\n")

    def test_string_booleans_are_rejected(self) -> None:
        """Item 26: bool("false") is True."""
        for text in (
            '[policy]\nincomplete_is_blocking = "false"\n',
            '[isolation]\nrequire_attestation = "false"\n',
            '[isolation]\nrequire_evidence = "false"\n',
            '[isolation]\nexecute_target_code = "false"\n',
            '[reports]\ninclude_sanitized_evidence = "false"\n',
            '[intelligence]\nrequire_approval = "false"\n',
            '[tools.bandit]\nenabled = "false"\n',
        ):
            with (
                self.subTest(text=text),
                self.assertRaisesRegex(ConfigurationError, "must be a boolean"),
            ):
                self._load(text)


if __name__ == "__main__":
    unittest.main()
