from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from unittest.mock import patch

import pytest

from py_security_suite.trusted_observation import scan_observed_at


def test_scan_observed_at_requires_digest_bound_advanced_rfc3161_context(
    tmp_path,
) -> None:
    context = tmp_path / "scan-time.json"
    challenge = "a" * 64
    context.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "challenge_sha256": challenge,
                "trusted_time": {"receipt": "opaque"},
            }
        ),
        encoding="utf-8",
    )
    observed = datetime.now(UTC)
    environment = {
        "PYSEC_SCAN_TIME_CONTEXT_PATH": str(context),
        "PYSEC_SCAN_TIME_CONTEXT_SHA256": hashlib.sha256(
            context.read_bytes()
        ).hexdigest(),
        "PYSEC_SCAN_TIME_CHALLENGE_SHA256": challenge,
    }
    with patch(
        "py_security_suite.trusted_observation.verify_rfc3161",
        return_value={"trusted_time_observed_at": observed.isoformat()},
    ) as verifier:
        assert scan_observed_at(environment) == observed
    verifier.assert_called_once_with(
        context.resolve(), {"receipt": "opaque"}, challenge, require_advanced=True
    )


def test_scan_observed_at_has_no_wall_clock_fallback() -> None:
    with pytest.raises(ValueError, match="configuration is incomplete"):
        scan_observed_at({})
