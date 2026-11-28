from __future__ import annotations

import os
from pathlib import Path
import re
from typing import Any

from ..models import (
    Citation,
    Confidence,
    Finding,
    Location,
    Severity,
    Source,
    finding_identity,
    normalize_repo_path,
)
from ..strict_json import loads as strict_json_loads
from ..path_safety import read_regular_file
from .base import ScannerAdapter


# The suite's own source checkout. Only that repository may use the
# suite-specific exclusions below; every other target is scanned in full.
_SUITE_REPOSITORY = Path(__file__).resolve().parents[3]

INLINE_ALLOWLIST_FILTER = "detect_secrets.filters.allowlist.is_line_allowlisted"

_GENERIC_SKIPPED_ROOTS = frozenset(
    {
        ".artifacts",
        ".git",
        ".hg",
        ".mypy_cache",
        ".nox",
        ".pysec-tools",
        ".pytest_cache",
        ".ruff_cache",
        ".svn",
        ".tox",
        ".venv",
        "__pycache__",
        "build",
        "dist",
        "env",
        "node_modules",
        "venv",
    }
)
# detect-secrets matches --exclude-files against paths relative to its working
# directory (the target), so ``^`` anchors each pattern to the target root.
_GENERIC_EXCLUDES = (
    r"^\.(artifacts|mypy_cache|pysec-tools|pytest_cache|ruff_cache)[\\/]"
)
_SUITE_EXCLUDES = (
    r"(^|[\\/])\.(artifacts|mypy_cache|pysec-tools|"
    r"pytest_cache|ruff_cache)([\\/]|$)|"
    # This governed API-security corpus deliberately contains
    # synthetic credential shapes. Its schema and negative-control
    # tests validate those fixtures independently.
    r"(^|[\\/])security[\\/]api-surface-1[.]1[.]json$"
    # This strict, governed manifest accepts only framework names,
    # paths, rule IDs, and SHA-256 subject bindings. Treating those
    # integrity digests as credentials creates false release blocks.
    r"|(^|[\\/])[.]pysec-models[.]json$"
    r"|(^|[\\/])(coverage[.](json|xml)|junit[.]xml)"
    r"([.]pysec-binding[.]json)?$|(^|[\\/])site([\\/]|$)"
)


# Set by the operator (scripts/run-self-scan.ps1) when the suite scans its own
# checkout from a container, where the installed suite and the mounted target
# live at different paths. Target code never runs, so a target cannot set it.
SELF_SCAN_ENVIRONMENT = "PYSEC_SUITE_SELF_SCAN"


def is_suite_repository(target: Path) -> bool:
    """Return whether ``target`` is this suite's own source checkout."""
    root = target.resolve()
    operator_declared = os.environ.get(SELF_SCAN_ENVIRONMENT) == "1"
    return (root == _SUITE_REPOSITORY or operator_declared) and (
        root / "src" / "py_security_suite" / "adapters" / "detect_secrets.py"
    ).resolve().is_file()


class DetectSecretsAdapter(ScannerAdapter):
    name = "detect-secrets"

    def build_command(self, executable: str, target: Path) -> list[str]:
        suite = is_suite_repository(target)
        scan_roots = [
            str(entry.resolve())
            for entry in sorted(target.iterdir(), key=lambda path: path.name.lower())
            if entry.name not in _GENERIC_SKIPPED_ROOTS
            and not (
                suite
                and (
                    entry.name in {"site", "coverage.json", "coverage.xml", "junit.xml"}
                    or entry.name.endswith(".pysec-binding.json")
                )
            )
        ]
        public_digest_filter = []
        if self.config.rules_path:
            public_digest_filter = [
                "--exclude-secrets",
                _public_digest_filter(self.config.rules_path),
            ]
        return [
            executable,
            "--cores",
            "1",
            "scan",
            *(scan_roots or [str(target.resolve())]),
            "--all-files",
            "--no-verify",
            *public_digest_filter,
            # Third-party targets must not self-suppress with inline
            # "pragma: allowlist secret" comments; only the suite's own
            # reviewed checkout keeps its governed allowlist pragmas.
            *(() if suite else ("--disable-filter", INLINE_ALLOWLIST_FILTER)),
            "--exclude-files",
            _SUITE_EXCLUDES if suite else _GENERIC_EXCLUDES,
        ]

    def parse(self, payload: str, target: Path) -> list[Finding]:
        document = strict_json_loads(payload)
        if not isinstance(document, dict):
            raise TypeError("detect-secrets output must be an object")
        results = document.get("results", {})
        if not isinstance(results, dict):
            raise TypeError("results must be an object")
        findings: list[Finding] = []
        for native_path, secrets in sorted(results.items()):
            if not isinstance(secrets, list):
                raise TypeError("secret results must be lists")
            path = normalize_repo_path(target, native_path)
            for secret in secrets:
                if not isinstance(secret, dict):
                    raise TypeError("secret result must be an object")
                detector = str(secret.get("type") or "Potential secret")
                line = _integer(secret.get("line_number"))
                rule_id = _rule_id(detector)
                finding_id, fingerprint = finding_identity(
                    tool=self.name,
                    rule_id=rule_id,
                    path=path,
                    start_line=line,
                )
                title = f"Potential secret detected: {detector}"
                findings.append(
                    Finding(
                        finding_id=finding_id,
                        fingerprint=fingerprint,
                        title=title,
                        description=(
                            "A local detect-secrets plugin identified a credential-like "
                            "value. The value is intentionally omitted from this report."
                        ),
                        impact=(
                            "Committed credentials can permit unauthorized access and "
                            "usually require rotation even after removal."
                        ),
                        remediation=(
                            "Validate the finding, revoke and rotate real credentials, "
                            "remove the value from source, and use an approved secret store."
                        ),
                        severity=Severity.HIGH,
                        confidence=Confidence.MEDIUM,
                        area="secrets",
                        classifications=["CWE-798"],
                        locations=[Location(path=path, start_line=line, end_line=line)],
                        sources=[
                            Source(
                                tool=self.name,
                                rule_id=rule_id,
                                message=title,
                                native_severity="potential-secret",
                            )
                        ],
                        citations=[
                            Citation(
                                kind="tool_rule",
                                identifier=rule_id,
                                title=detector,
                            ),
                            Citation(
                                kind="taxonomy",
                                identifier="CWE-798",
                                title="Use of Hard-coded Credentials",
                                uri=("https://cwe.mitre.org/data/definitions/798.html"),
                            ),
                        ],
                        evidence={"redacted": True},
                    )
                )
        return findings


def _integer(value: Any) -> int | None:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _rule_id(detector: str) -> str:
    normalized = "".join(
        character.lower() if character.isalnum() else "-" for character in detector
    ).strip("-")
    return f"detect-secrets.{normalized or 'unknown'}"


def _public_digest_filter(path: Path) -> str:
    """Permit only explicitly reviewed exact public integrity digests, never regexes."""
    _, data = read_regular_file(path, "public digest policy", maximum_bytes=65536)
    document = strict_json_loads(data)
    if (
        not isinstance(document, dict)
        or set(document) != {"schema_version", "public_digests"}
        or document["schema_version"] != "1.0"
        or not isinstance(document["public_digests"], list)
        or not 1 <= len(document["public_digests"]) <= 64
    ):
        raise ValueError("invalid public digest policy")
    values = []
    for entry in document["public_digests"]:
        if (
            not isinstance(entry, dict)
            or set(entry) != {"value", "purpose"}
            or not isinstance(entry["value"], str)
            or re.fullmatch(r"(?:[a-f0-9]{40}|[a-f0-9]{64})", entry["value"]) is None
            or not isinstance(entry["purpose"], str)
            or not 1 <= len(entry["purpose"].strip()) <= 500
            or entry["value"] in values
        ):
            raise ValueError(
                "public digest entries require unique exact digests and review purposes"
            )
        values.append(entry["value"])
    return "^(?:" + "|".join(values) + ")$"
