from __future__ import annotations

from pathlib import Path
from typing import Any


def add_benchmark_commands(
    subparsers: Any,
    *,
    replay_genesis_sha256: str,
) -> None:
    """Register benchmark and assurance-catalog commands as one cohesive CLI slice."""
    benchmark = subparsers.add_parser(
        "benchmark",
        help="measure a verified report against a digest-bound labeled corpus",
    )
    benchmark.add_argument("report", type=Path, metavar="REPORT_DIRECTORY")
    benchmark.add_argument("--corpus", type=Path, required=True)
    benchmark.add_argument("--corpus-sha256", required=True)
    benchmark.add_argument("--trusted-time", type=Path)
    benchmark.add_argument("--trusted-time-sha256", default="")
    benchmark.add_argument("--replay-ledger", type=Path)
    benchmark.add_argument("--replay-service-url", default="")
    benchmark.add_argument("--replay-service-token-env", default="")
    benchmark.add_argument("--replay-service-receipt-key", type=Path)
    benchmark.add_argument("--replay-service-receipt-key-sha256", default="")
    benchmark.add_argument("--replay-query-budget", type=int, default=1)
    benchmark.add_argument("--format", choices=("text", "json"), default="text")
    benchmark.add_argument(
        "--output",
        type=Path,
        metavar="FILE",
        help="atomically publish the effectiveness evaluation outside the sealed report",
    )
    benchmark.add_argument("--overwrite", action="store_true")

    benchmark_run = subparsers.add_parser(
        "benchmark-run",
        help="execute a digest-pinned benchmark adapter and score normalized cases",
    )
    benchmark_run.add_argument("manifest", type=Path, metavar="ADAPTER_MANIFEST")
    benchmark_run.add_argument("--workspace", type=Path, required=True)
    benchmark_run.add_argument(
        "--authorize-execution",
        action="store_true",
        help="confirm authorization to execute every manifest stage",
    )
    benchmark_run.add_argument(
        "--authority-trust-policy",
        type=Path,
        help="deployment-owned authority policy outside the benchmark workspace",
    )
    benchmark_run.add_argument(
        "--authority-trust-policy-sha256",
        default="",
        help="out-of-band approved SHA-256 of the authority trust policy",
    )
    benchmark_run.add_argument(
        "--authority-trust-policy-signature",
        type=Path,
        help="detached Ed25519 signature over the authority policy",
    )
    benchmark_run.add_argument(
        "--authority-trust-root",
        type=Path,
        help="deployment-pinned Ed25519 authority-policy root public key",
    )
    benchmark_run.add_argument(
        "--authority-trust-root-sha256",
        default="",
        help="out-of-band approved SHA-256 of the authority-policy root key",
    )
    benchmark_run.add_argument(
        "--trusted-time-context",
        type=Path,
        help="advanced RFC 3161 context outside the benchmark workspace",
    )
    benchmark_run.add_argument(
        "--trusted-time-context-sha256",
        default="",
        help="out-of-band approved SHA-256 of the RFC 3161 context",
    )
    benchmark_run.add_argument(
        "--replay-ledger",
        type=Path,
        help="deployment-owned SQLite replay ledger outside the benchmark workspace",
    )
    benchmark_run.add_argument(
        "--replay-minimum-sequence",
        type=int,
        default=0,
        help="minimum retained deployment replay checkpoint sequence",
    )
    benchmark_run.add_argument(
        "--replay-checkpoint-sha256",
        default=replay_genesis_sha256,
        help="initial replay checkpoint digest used only during explicit enrollment",
    )
    benchmark_run.add_argument(
        "--replay-checkpoint-state",
        type=Path,
        help="signed deployment-retained replay checkpoint state outside the workspace",
    )
    benchmark_run.add_argument(
        "--initialize-replay-checkpoint",
        action="store_true",
        help="explicitly enroll an absent replay checkpoint state",
    )
    benchmark_run.add_argument(
        "--receipt-signing-key",
        type=Path,
        help="deployment Ed25519 private key admitted for execution receipts",
    )
    benchmark_run.add_argument(
        "--receipt-signing-key-sha256",
        default="",
        help="out-of-band approved SHA-256 of the receipt signing key",
    )
    benchmark_run.add_argument(
        "--receipt-signing-provider-executable",
        type=Path,
        help="absolute digest-pinned PKCS#11, HSM, or KMS bridge executable",
    )
    benchmark_run.add_argument(
        "--receipt-signing-provider-executable-sha256",
        default="",
    )
    benchmark_run.add_argument(
        "--receipt-signing-provider-argument",
        action="append",
        default=[],
        help="repeatable fixed argument passed to the external signing bridge",
    )
    benchmark_run.add_argument(
        "--receipt-signing-provider-public-key",
        type=Path,
        help="raw or PEM Ed25519 public key for local result verification",
    )
    benchmark_run.add_argument(
        "--receipt-signing-provider-public-key-sha256",
        default="",
    )
    benchmark_run.add_argument("--receipt-signing-provider-id", default="")
    benchmark_run.add_argument("--receipt-signing-provider-key-version", default="")
    benchmark_run.add_argument(
        "--receipt-signing-provider-profile",
        type=Path,
        help=(
            "digest-pinned deployment profile for a PKCS#11, HSM, Vault, "
            "or cloud KMS bridge"
        ),
    )
    benchmark_run.add_argument(
        "--receipt-signing-provider-profile-sha256",
        default="",
        help="out-of-band approved SHA-256 of the signing-provider profile",
    )
    benchmark_run.add_argument(
        "--security-event-log",
        type=Path,
        help="fsync'd hash-chained JSONL audit log outside the benchmark workspace",
    )
    benchmark_run.add_argument("--output", type=Path, required=True, metavar="FILE")
    benchmark_run.add_argument("--overwrite", action="store_true")

    provider_check = subparsers.add_parser(
        "benchmark-provider-check",
        help="actively verify a digest-pinned HSM, Vault, or cloud KMS signing bridge",
    )
    provider_check.add_argument("--profile", type=Path, required=True)
    provider_check.add_argument("--profile-sha256", required=True)
    provider_check.add_argument("--output", type=Path, required=True, metavar="FILE")
    provider_check.add_argument("--overwrite", action="store_true")

    runtime_probe = subparsers.add_parser(
        "benchmark-runtime-probe",
        help="produce a digest-pinned OCI runtime capability proof",
    )
    runtime_probe.add_argument("runtime", type=Path, metavar="OCI_RUNTIME")
    runtime_probe.add_argument("--runtime-sha256", required=True)
    runtime_probe.add_argument(
        "--runtime-name", choices=("docker", "podman", "nerdctl"), required=True
    )
    runtime_probe.add_argument("--runtime-version", required=True)
    runtime_probe.add_argument("--authorize-execution", action="store_true")
    runtime_probe.add_argument("--output", type=Path, required=True, metavar="FILE")
    runtime_probe.add_argument("--overwrite", action="store_true")

    security_log_verify = subparsers.add_parser(
        "benchmark-security-log-verify",
        help="verify every record and hash-chain link in a benchmark audit log",
    )
    security_log_verify.add_argument("log", type=Path, metavar="JSONL_LOG")

    benchmark_prepare = subparsers.add_parser(
        "benchmark-prepare",
        help="compile a maintained adapter request into a registry-bound manifest",
    )
    benchmark_prepare.add_argument("request", type=Path, metavar="REQUEST")
    benchmark_prepare.add_argument("--workspace", type=Path, required=True)
    benchmark_prepare.add_argument("--output", type=Path, required=True, metavar="FILE")
    benchmark_prepare.add_argument("--overwrite", action="store_true")

    catalog_export = subparsers.add_parser(
        "assurance-catalog-export",
        help="export the compiled assurance registry with deterministic digests",
    )
    catalog_export.add_argument("--output", type=Path, required=True, metavar="FILE")
    catalog_export.add_argument("--overwrite", action="store_true")
