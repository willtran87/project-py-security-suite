from __future__ import annotations

import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from py_security_suite.standards_monitor import (
    monitor_standard_sources,
    verify_standards_monitor_report,
)


def _manifest(baseline: bytes) -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "allowed_hosts": ["standards.example.com"],
        "sources": [
            {
                "id": "TEST-STANDARD",
                "baseline_version": "1.0",
                "publisher": "Example Standards Body",
                "url": "https://standards.example.com/current",
                "baseline_sha256": hashlib.sha256(baseline).hexdigest(),
                "maximum_bytes": 4096,
                "baseline_path": "baseline.txt",
                "media_type": "text/plain",
                "impact": {
                    "profiles": ["enterprise-security"],
                    "controls": ["TEST-STANDARD:CONTROL-1"],
                    "benchmarks": ["artifact-interoperability-conformance"],
                },
            }
        ],
    }


def test_quarantines_changed_source_and_requires_review(tmp_path: Path) -> None:
    baseline = b"Implementations SHOULD retain edition 1"
    observed = b"publisher edition 2"
    (tmp_path / "baseline.txt").write_bytes(baseline)
    manifest = tmp_path / "sources.json"
    manifest.write_text(json.dumps(_manifest(baseline)), encoding="utf-8")

    report = monitor_standard_sources(
        manifest,
        tmp_path / "snapshots",
        network_authorized=False,
        fetcher=lambda url, maximum, hosts: (observed, url, "text/plain"),
    )

    assert report["decision"] == "review-required"
    assert report["sources_changed"] == 1
    snapshot = tmp_path / "snapshots" / report["sources"][0]["snapshot"]
    assert snapshot.read_bytes() == observed
    assert report["promotion_policy"]["automatic_promotion"] is False
    assert report["sources"][0]["semantic_diff"]["status"] == "review-required"
    assert report["sources"][0]["semantic_diff"]["normative_terms_changed"] == [
        "SHOULD"
    ]
    assert report["review_artifact"]["approval_status"] == "pending"


def test_records_current_snapshot_and_signs_report(tmp_path: Path) -> None:
    observed = b"publisher edition 1"
    (tmp_path / "baseline.txt").write_bytes(observed)
    manifest = tmp_path / "sources.json"
    manifest.write_text(json.dumps(_manifest(observed)), encoding="utf-8")
    private_key = Ed25519PrivateKey.generate()
    key_path = tmp_path / "monitor-key.pem"
    key_path.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    public_path = tmp_path / "monitor-key.pub.pem"
    public_path.write_bytes(
        private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )

    report = monitor_standard_sources(
        manifest,
        tmp_path / "snapshots",
        network_authorized=False,
        signing_key_path=key_path,
        fetcher=lambda url, maximum, hosts: (observed, url, "text/plain"),
    )

    assert report["decision"] == "current"
    assert report["signature"]["algorithm"] == "Ed25519"
    assert len(report["signature"]["key_id"]) == 64
    report_path = tmp_path / "snapshots" / "standards-monitor-report.json"
    verification = verify_standards_monitor_report(
        report_path,
        public_path,
        report_sha256=hashlib.sha256(report_path.read_bytes()).hexdigest(),
    )
    assert verification["decision"] == "verified"
