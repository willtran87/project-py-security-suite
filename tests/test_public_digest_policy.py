import json
import re

import pytest

from py_security_suite.adapters.detect_secrets import _public_digest_filter


def test_public_digest_filter_matches_only_reviewed_exact_values(tmp_path):
    policy = tmp_path / "policy.json"
    value = "a" * 64
    policy.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "public_digests": [
                    {"value": value, "purpose": "Public source checksum"}
                ],
            }
        ),
        encoding="utf-8",
    )
    pattern = _public_digest_filter(policy)
    assert re.fullmatch(pattern, value)
    assert not re.fullmatch(pattern, "b" * 64)
    assert not re.fullmatch(pattern, "prefix" + value)
    assert not re.fullmatch(pattern, value + "suffix")


@pytest.mark.parametrize(
    "entries",
    [
        [],
        [{"value": ".*", "purpose": "unsafe wildcard"}],
        [{"value": "a" * 64, "purpose": ""}],
        [{"value": "a" * 64, "purpose": "reviewed"}] * 2,
    ],
)
def test_invalid_public_digest_policies_fail_closed(tmp_path, entries):
    policy = tmp_path / "policy.json"
    policy.write_text(
        json.dumps({"schema_version": "1.0", "public_digests": entries}),
        encoding="utf-8",
    )
    with pytest.raises(ValueError):
        _public_digest_filter(policy)
