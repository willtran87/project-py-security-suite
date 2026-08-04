from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


def write_embedded_statement(report: Path, manifest: dict[str, Any]) -> None:
    inputs = [
        {
            "uri": path.relative_to(report).as_posix(),
            "digest": {"sha256": hashlib.sha256(path.read_bytes()).hexdigest()},
        }
        for path in sorted(report.rglob("*"))
        if path.is_file()
        and path.relative_to(report).as_posix()
        not in {"checksums.sha256", "security-passport.json"}
    ]
    outcome = str(manifest["outcome"])
    profile = str(manifest["profile"])
    tools = manifest["tools"]
    inventory = manifest["inventory"]
    if not isinstance(tools, list) or not isinstance(inventory, dict):
        raise TypeError("fixture manifest tools and inventory must be structured")
    subjects = [
        {
            "name": f"source:{manifest['target']}",
            "digest": {"sha256": inventory["source_sha256"]},
        }
    ]
    artifact_manifest = report / "artifact-manifest.json"
    if artifact_manifest.is_file():
        document = json.loads(artifact_manifest.read_text(encoding="utf-8"))
        artifacts = document.get("artifacts")
        if not isinstance(artifacts, list):
            raise TypeError("fixture artifact manifest must contain a list")
        for value in artifacts:
            if not isinstance(value, dict):
                raise TypeError("fixture artifact record must be an object")
            subjects.append(
                {
                    "name": value["path"],
                    "digest": {"sha256": value["sha256"]},
                }
            )
    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": subjects,
        "predicateType": "https://slsa.dev/verification_summary/v1",
        "predicate": {
            "verifier": {
                "id": "https://github.com/william-zk/project-py-security-suite",
                "version": {"py-security-suite": manifest["suite_version"]},
            },
            "timeVerified": manifest["finished_at"],
            "resourceUri": f"urn:pysec:scan:{manifest['scan_id']}",
            "policy": {
                "uri": f"urn:pysec:profile:{profile}",
                "digest": {"sha256": manifest["configuration_sha256"]},
            },
            "inputAttestations": inputs,
            "verificationResult": "PASSED" if outcome == "pass" else "FAILED",
            "verifiedLevels": [f"PYSEC_PROFILE_{profile.upper().replace('-', '_')}"]
            if outcome == "pass"
            else ["FAILED"],
            "slsaVersion": "1.2",
            "pysec": {
                "schema_version": "1.0",
                "outcome": outcome,
                "profile": profile,
                "network_isolation_attested": manifest["network_isolation_attested"],
                "source_integrity_verified": inventory["source_integrity_verified"],
                "finding_counts": manifest["finding_counts"],
                "tool_statuses": {
                    status: sum(
                        isinstance(run, dict) and run.get("status") == status
                        for run in tools
                    )
                    for status in (
                        "completed",
                        "skipped",
                        "unavailable",
                        "failed",
                        "timed_out",
                        "parse_error",
                    )
                },
                "risk_acceptance_sha256": manifest.get("risk_acceptance_sha256", ""),
                "intelligence": manifest.get("intelligence", {}),
                "baseline": manifest.get("baseline", {}),
            },
        },
    }
    (report / "security-passport.json").write_text(
        json.dumps(statement), encoding="utf-8"
    )
