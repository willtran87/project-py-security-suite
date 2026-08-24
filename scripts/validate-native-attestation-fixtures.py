from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from py_security_suite.attestation_formats import verify_format_evidence
from py_security_suite.path_safety import read_regular_file
from py_security_suite.strict_json import dumps, loads as strict_loads


_FORMATS = {"tpm2-quote", "nitro-attestation", "sev-snp"}
_FIXTURE_FIELDS = {
    "id",
    "format",
    "evidence_path",
    "expected",
    "expected_error",
    "challenge_sha256",
    "host_identity_sha256",
    "pcrs_sha256",
    "implementation_sha256",
    "authority_key_sha256",
    "failure_domain",
}


def _digest(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def validate(manifest_path: Path) -> dict[str, Any]:
    manifest_file, raw = read_regular_file(
        manifest_path,
        "native attestation fixture manifest",
        maximum_bytes=1_048_576,
    )
    manifest = strict_loads(raw)
    if (
        not isinstance(manifest, dict)
        or set(manifest) != {"schema_version", "fixtures"}
        or manifest.get("schema_version") != "1.0"
        or not isinstance(manifest.get("fixtures"), list)
        or not 6 <= len(manifest["fixtures"]) <= 100
    ):
        raise ValueError("native attestation fixture manifest is invalid")

    identities: set[str] = set()
    coverage = {name: {"accept": 0, "reject": 0} for name in _FORMATS}
    results: list[dict[str, str]] = []
    for index, fixture in enumerate(manifest["fixtures"]):
        label = f"native attestation fixture {index + 1}"
        if (
            not isinstance(fixture, dict)
            or set(fixture) != _FIXTURE_FIELDS
            or not isinstance(fixture.get("id"), str)
            or not fixture["id"]
            or fixture["id"] in identities
            or fixture.get("format") not in _FORMATS
            or fixture.get("expected") not in {"accept", "reject"}
            or not isinstance(fixture.get("expected_error"), str)
            or (fixture["expected"] == "accept" and fixture["expected_error"])
            or (fixture["expected"] == "reject" and not fixture["expected_error"])
            or any(
                not _digest(fixture.get(field))
                for field in (
                    "challenge_sha256",
                    "host_identity_sha256",
                    "pcrs_sha256",
                    "implementation_sha256",
                    "authority_key_sha256",
                )
            )
            or not isinstance(fixture.get("failure_domain"), dict)
        ):
            raise ValueError(f"{label} contract is invalid")
        identities.add(fixture["id"])
        coverage[fixture["format"]][fixture["expected"]] += 1
        evidence_path = Path(str(fixture.get("evidence_path") or ""))
        if evidence_path.is_absolute() or ".." in evidence_path.parts:
            raise ValueError(f"{label} evidence path must remain beneath the manifest")
        _, evidence = read_regular_file(
            manifest_file.parent / evidence_path,
            f"{label} evidence",
            maximum_bytes=4 * 1024 * 1024,
            boundary=manifest_file.parent,
        )
        try:
            verify_format_evidence(
                evidence,
                format_name=fixture["format"],
                challenge_sha256=fixture["challenge_sha256"],
                host_identity_sha256=fixture["host_identity_sha256"],
                pcrs_sha256=fixture["pcrs_sha256"],
                implementation_sha256=fixture["implementation_sha256"],
                normalized_authority_key_sha256=fixture["authority_key_sha256"],
                normalized_failure_domain=fixture["failure_domain"],
            )
        except ValueError as exc:
            if fixture["expected"] != "reject" or fixture["expected_error"] not in str(
                exc
            ):
                raise ValueError(f"{label} failed unexpectedly: {exc}") from exc
        else:
            if fixture["expected"] != "accept":
                raise ValueError(f"{label} was accepted unexpectedly")
        results.append(
            {
                "id": fixture["id"],
                "format": fixture["format"],
                "expected": fixture["expected"],
                "status": "pass",
            }
        )

    missing = [
        f"{format_name}:{outcome}"
        for format_name in sorted(_FORMATS)
        for outcome in ("accept", "reject")
        if coverage[format_name][outcome] < 1
    ]
    if missing:
        raise ValueError(
            "native attestation fixture coverage is incomplete: " + ", ".join(missing)
        )
    return {
        "schema_version": "1.0",
        "status": "pass",
        "fixture_count": len(results),
        "coverage": coverage,
        "fixtures": results,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate positive and adversarial native attestation fixtures."
    )
    parser.add_argument("manifest", type=Path)
    args = parser.parse_args()
    print(dumps(validate(args.manifest), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
