from __future__ import annotations

import importlib.util
import hashlib
import json
from pathlib import Path
from types import ModuleType
from typing import Any


_ROOT = Path(__file__).parent.parent


def _load_script(name: str, filename: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, _ROOT / "scripts" / filename)
    if spec is None or spec.loader is None:
        raise AssertionError(f"could not load {filename}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_checkpoint_authority_conformance_exercises_monotonic_contract(
    monkeypatch: Any,
) -> None:
    module = _load_script(
        "validate_checkpoint_authority", "validate-checkpoint-authority.py"
    )
    current: dict[str, object] = {}

    def publish(
        prefix: str, subject: dict[str, object], *, required: bool
    ) -> dict[str, object]:
        assert prefix == "PYSEC_TEST"
        assert required
        sequence = int(str(subject["sequence"]))
        checkpoint = str(subject["checkpoint_sha256"])
        if not current:
            assert sequence == 1
            current.update(sequence=sequence, checkpoint=checkpoint)
        elif sequence == current["sequence"]:
            if checkpoint != current["checkpoint"]:
                raise module.CheckpointTransitionRejected("same-sequence-fork")
        elif sequence == int(str(current["sequence"])) + 1:
            current.update(sequence=sequence, checkpoint=checkpoint)
        else:
            reason = (
                "rollback"
                if sequence < int(str(current["sequence"]))
                else "sequence-gap"
            )
            raise module.CheckpointTransitionRejected(reason)
        return {"accepted": True, "sequence": sequence, "checkpoint": checkpoint}

    monkeypatch.setattr(module, "publish_checkpoint", publish)
    result = module.validate("PYSEC_TEST", "conformance-test")

    assert result["status"] == "pass"
    assert result["checks"] == {
        "first_transition": "accepted",
        "idempotent_retry": "accepted-and-stable",
        "same_sequence_fork": "rejected",
        "next_transition": "accepted",
        "rollback": "rejected",
        "sequence_gap": "rejected",
        "post_rejection_liveness": "accepted-and-stable",
    }


def test_native_attestation_conformance_requires_accept_and_reject_per_format(
    tmp_path: Path, monkeypatch: Any
) -> None:
    module = _load_script(
        "validate_native_attestation_fixtures",
        "validate-native-attestation-fixtures.py",
    )
    fixtures = []
    formats = ("tpm2-quote", "nitro-attestation", "sev-snp")
    for index, format_name in enumerate(formats):
        for expected in ("accept", "reject"):
            identifier = f"{format_name}-{expected}"
            evidence_path = f"{identifier}.json"
            (tmp_path / evidence_path).write_text(expected, encoding="utf-8")
            fixtures.append(
                {
                    "id": identifier,
                    "format": format_name,
                    "evidence_path": evidence_path,
                    "evidence_sha256": hashlib.sha256(expected.encode()).hexdigest(),
                    "expected": expected,
                    "expected_error": "adversarial fixture rejected"
                    if expected == "reject"
                    else "",
                    "challenge_sha256": f"{index + 1:x}" * 64,
                    "host_identity_sha256": "a" * 64,
                    "pcrs_sha256": "b" * 64,
                    "implementation_sha256": "c" * 64,
                    "authority_key_sha256": "d" * 64,
                    "failure_domain": {"organization": "independent"},
                }
            )
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps({"schema_version": "1.0", "fixtures": fixtures}),
        encoding="utf-8",
    )

    def verify(payload: bytes, **_arguments: object) -> dict[str, object]:
        if payload == b"reject":
            raise ValueError("adversarial fixture rejected")
        return {"accepted": True}

    monkeypatch.setattr(module, "verify_format_evidence", verify)
    result = module.validate(
        manifest, hashlib.sha256(manifest.read_bytes()).hexdigest()
    )

    assert result["status"] == "pass"
    assert result["fixture_count"] == 6
    assert all(
        counts == {"accept": 1, "reject": 1} for counts in result["coverage"].values()
    )
