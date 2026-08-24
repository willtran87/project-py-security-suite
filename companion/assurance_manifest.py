from __future__ import annotations

import argparse
import hashlib
import math
import os
import tempfile
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

try:
    from companion.evidence_authority import verify_portable_authority
    from companion.assurance_context import load_context, load_target_ids
    from companion.provenance import file_provenance, slsa_provenance
    from companion.strict_json import dumps as strict_dumps
    from companion.strict_json import loads as strict_loads
    from companion.strict_json import canonical_bytes
except ModuleNotFoundError:  # Direct script execution.
    from evidence_authority import verify_portable_authority  # type: ignore[import-not-found,no-redef]
    from assurance_context import load_context, load_target_ids  # type: ignore[import-not-found,no-redef]
    from provenance import file_provenance, slsa_provenance  # type: ignore[import-not-found,no-redef]
    from strict_json import dumps as strict_dumps  # type: ignore[import-not-found,no-redef]
    from strict_json import loads as strict_loads  # type: ignore[import-not-found,no-redef]
    from strict_json import canonical_bytes  # type: ignore[import-not-found,no-redef]


KINDS = {
    "atheris",
    "authorization-security",
    "ai-security",
    "browser-security",
    "check-manifest",
    "clamav",
    "cloud-attack-path",
    "database-security",
    "event-security",
    "clusterfuzzlite",
    "crosshair",
    "falco",
    "fuzz-introspector",
    "github-attestation",
    "iast",
    "in-toto",
    "kubescape",
    "mobsf",
    "mutmut",
    "native-sanitizers",
    "nuclei",
    "oast",
    "oci-image",
    "polyglot",
    "prowler",
    "protocol-security",
    "pytm",
    "rasp",
    "reproducible-build",
    "ruleset-regression",
    "restler",
    "secret-verification",
    "tls-scan",
    "surface-inventory",
    "yara",
    "zap",
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Create a strict companion-assurance v2 producer manifest."
    )
    parser.add_argument("--kind", choices=sorted(KINDS), required=True)
    parser.add_argument("--producer", required=True)
    parser.add_argument("--producer-version", required=True)
    parser.add_argument("--producer-path", type=Path, required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--findings", type=Path, required=True)
    parser.add_argument("--native-report", type=Path, required=True)
    parser.add_argument("--normalizer-path", type=Path, required=True)
    parser.add_argument("--builder-id", required=True)
    parser.add_argument("--builder-path", type=Path, required=True)
    parser.add_argument("--invocation-path", type=Path, required=True)
    parser.add_argument("--materials-path", type=Path, required=True)
    parser.add_argument("--builder-environment", type=Path)
    parser.add_argument("--build-type")
    parser.add_argument("--source-repository")
    parser.add_argument("--source-revision")
    parser.add_argument("--external-parameters", type=Path)
    parser.add_argument("--byproducts", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--ruleset-path", type=Path, required=True)
    parser.add_argument("--config-path", type=Path, required=True)
    parser.add_argument("--environment-id", required=True)
    parser.add_argument("--artifact", type=Path)
    parser.add_argument("--execution-summary", type=Path, required=True)
    parser.add_argument("--context", type=Path, required=True)
    parser.add_argument("--exercised-targets", type=Path, required=True)
    parser.add_argument("--run-id", default="")
    parser.add_argument("--valid-for-hours", type=float, default=24.0)
    args = parser.parse_args(argv)

    if not 0.01 <= args.valid_for_hours <= 168.0:
        raise ValueError("valid-for-hours must be between 0.01 and 168")
    findings = _findings(args.findings)
    execution = _execution_summary(args.execution_summary, kind=args.kind)
    context = load_context(args.context, load_target_ids(args.exercised_targets))
    generated = datetime.now(UTC)
    document: dict[str, Any] = {
        "schema_version": "2.0",
        "kind": args.kind,
        "producer": _text(args.producer, "producer", 200),
        "producer_version": _text(args.producer_version, "producer-version", 100),
        "producer_sha256": _sha256(args.producer_path, "producer-path"),
        "revision": _text(args.revision, "revision", 200),
        "generated_at": generated.isoformat(),
        "expires_at": (generated + timedelta(hours=args.valid_for_hours)).isoformat(),
        "run_id": _context_run_id(args.run_id, context["run_id"]),
        "artifact_sha256": (
            _sha256(args.artifact, "artifact") if args.artifact is not None else ""
        ),
        "ruleset_sha256": _sha256(args.ruleset_path, "ruleset-path"),
        "config_sha256": _sha256(args.config_path, "config-path"),
        "environment": _text(args.environment_id, "environment-id", 200),
        "environment_sha256": hashlib.sha256(
            args.environment_id.encode("utf-8")
        ).hexdigest(),
        "context": {key: value for key, value in context.items() if key != "run_id"},
        "provenance": _provenance(args),
        "execution": execution,
        "findings": findings,
    }
    _write_json(args.output, document)
    return 0


def _provenance(args: argparse.Namespace) -> dict[str, str]:
    advanced = (
        args.builder_environment,
        args.build_type,
        args.source_repository,
        args.source_revision,
        args.external_parameters,
        args.byproducts,
    )
    if any(advanced) and not all(advanced):
        raise ValueError("SLSA provenance options must be provided together")
    if all(advanced):
        return slsa_provenance(
            native_report=args.native_report,
            normalizer=args.normalizer_path,
            builder_id=args.builder_id,
            builder=args.builder_path,
            builder_environment=args.builder_environment,
            build_type=args.build_type,
            source_repository=args.source_repository,
            source_revision=args.source_revision,
            invocation=args.invocation_path,
            external_parameters=args.external_parameters,
            materials=args.materials_path,
            byproducts=args.byproducts,
        )
    return file_provenance(
        native_report=args.native_report,
        normalizer=args.normalizer_path,
        builder_id=args.builder_id,
        builder=args.builder_path,
        invocation=args.invocation_path,
        materials=args.materials_path,
    )


def _findings(path: Path) -> list[dict[str, Any]]:
    payload = strict_loads(_regular_bytes(path, "findings"))
    if isinstance(payload, dict):
        payload = payload.get("findings")
    if not isinstance(payload, list) or len(payload) > 10_000:
        raise ValueError("findings must be a JSON list of at most 10000 objects")
    if not all(isinstance(value, dict) for value in payload):
        raise ValueError("every finding must be an object")
    return payload


def _execution_summary(path: Path, *, kind: str = "") -> dict[str, Any]:
    payload = strict_loads(_regular_bytes(path, "execution-summary"))
    if isinstance(payload, dict) and isinstance(payload.get("execution"), dict):
        payload = payload["execution"]
    required = {
        "status",
        "targets_discovered",
        "targets_exercised",
        "requests",
        "coverage_percent",
        "coverage_metric",
        "roles",
        "features",
        "skipped_checks",
        "canaries_expected",
        "canaries_observed",
    }
    allowed = required | {
        "language_matrix",
        "cross_language_matrix",
        "surface_proof",
    }
    if (
        not isinstance(payload, dict)
        or set(payload) - allowed
        or not required.issubset(payload)
    ):
        raise ValueError("execution-summary fields do not match the v2 contract")
    if payload.get("status") != "completed":
        raise ValueError("execution-summary status must be completed")
    integers = {
        name: _nonnegative_integer(payload.get(name), name)
        for name in (
            "targets_discovered",
            "targets_exercised",
            "requests",
            "canaries_expected",
            "canaries_observed",
        )
    }
    if (
        integers["targets_discovered"] < 1
        or integers["targets_exercised"] < 1
        or integers["targets_exercised"] > integers["targets_discovered"]
    ):
        raise ValueError("execution-summary target counts are invalid")
    if (
        integers["canaries_expected"] < 1
        or integers["canaries_expected"] != integers["canaries_observed"]
    ):
        raise ValueError("execution-summary canary coverage is incomplete")
    try:
        coverage = float(str(payload.get("coverage_percent")))
    except (TypeError, ValueError) as exc:
        raise ValueError("execution-summary coverage is invalid") from exc
    if not math.isfinite(coverage) or not 0.0 <= coverage <= 100.0:
        raise ValueError("execution-summary coverage is invalid")
    roles = _labels(payload.get("roles"), "roles", 64)
    features = _labels(payload.get("features"), "features", 256)
    skipped = _labels(payload.get("skipped_checks"), "skipped-checks", 256)
    if skipped:
        raise ValueError("execution-summary contains skipped checks")
    language_matrix = _language_matrix(payload.get("language_matrix", []))
    cross_language_matrix = _cross_language_matrix(
        payload.get("cross_language_matrix", [])
    )
    surface_proof = payload.get("surface_proof")
    if kind == "surface-inventory" and not isinstance(surface_proof, dict):
        raise ValueError("surface inventory requires a structured reconciliation proof")
    if kind != "surface-inventory" and surface_proof is not None:
        raise ValueError("surface proof is only valid for surface inventory evidence")
    if kind == "polyglot" and not language_matrix:
        raise ValueError("polyglot execution requires an explicit language matrix")
    if kind == "polyglot" and len(language_matrix) > 1 and not cross_language_matrix:
        raise ValueError("polyglot execution requires cross-language semantic coverage")
    return {
        "status": "completed",
        **integers,
        "coverage_percent": coverage,
        "coverage_metric": _text(
            payload.get("coverage_metric"), "coverage-metric", 100
        ),
        "roles": roles,
        "features": features,
        "skipped_checks": [],
        **({"language_matrix": language_matrix} if language_matrix else {}),
        **(
            {"cross_language_matrix": cross_language_matrix}
            if cross_language_matrix
            else {}
        ),
        **({"surface_proof": surface_proof} if surface_proof is not None else {}),
    }


def _language_matrix(value: object) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) > 64:
        raise ValueError("language matrix must be a bounded list")
    result: list[dict[str, Any]] = []
    observed: set[str] = set()
    for item in value:
        required = {
            "language",
            "engine",
            "engine_version",
            "query_pack_sha256",
            "source_files_sha256",
            "files_discovered",
            "files_analyzed",
            "exclusions",
            "analysis_modes",
            "files",
        }
        if not isinstance(item, dict) or set(item) != required:
            raise ValueError("language matrix entry fields do not match")
        language = _text(item["language"], "language", 50).casefold()
        if language in observed:
            raise ValueError("language matrix languages must be unique")
        discovered = _nonnegative_integer(item["files_discovered"], "files-discovered")
        analyzed = _nonnegative_integer(item["files_analyzed"], "files-analyzed")
        exclusions = item["exclusions"]
        if not isinstance(exclusions, list) or len(exclusions) > 10_000:
            raise ValueError("language matrix exclusions must be a bounded list")
        normalized_exclusions: list[dict[str, str]] = []
        for exclusion in exclusions:
            if not isinstance(exclusion, dict) or set(exclusion) != {"path", "reason"}:
                raise ValueError("language matrix exclusion is invalid")
            normalized_exclusions.append(
                {
                    "path": _text(exclusion["path"], "excluded-path", 1000),
                    "reason": _text(exclusion["reason"], "exclusion-reason", 200),
                }
            )
        if discovered < 1 or analyzed < 1 or analyzed + len(exclusions) != discovered:
            raise ValueError("language matrix file accounting is incomplete")
        modes = _labels(item["analysis_modes"], "analysis-modes", 32)
        if "semantic-dataflow" not in modes:
            raise ValueError("language matrix lacks semantic dataflow analysis")
        for name in ("query_pack_sha256", "source_files_sha256"):
            if (
                not isinstance(item[name], str)
                or len(item[name]) != 64
                or any(character not in "0123456789abcdef" for character in item[name])
            ):
                raise ValueError(f"language matrix {name} is invalid")
        files = _language_files(item["files"], "language matrix")
        if (
            len(files) != analyzed
            or hashlib.sha256(canonical_bytes(files)).hexdigest()
            != item["source_files_sha256"]
        ):
            raise ValueError("language matrix exact file ledger does not match")
        observed.add(language)
        result.append(
            {
                "language": language,
                "engine": _text(item["engine"], "engine", 100),
                "engine_version": _text(item["engine_version"], "engine-version", 100),
                "query_pack_sha256": item["query_pack_sha256"],
                "source_files_sha256": item["source_files_sha256"],
                "files_discovered": discovered,
                "files_analyzed": analyzed,
                "exclusions": normalized_exclusions,
                "analysis_modes": modes,
                "files": files,
            }
        )
    return sorted(result, key=lambda item: str(item["language"]))


def _language_files(value: object, label: str) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not 1 <= len(value) <= 50_000:
        raise ValueError(f"{label} files must be a bounded non-empty list")
    result: list[dict[str, Any]] = []
    paths: set[str] = set()
    for item in value:
        if not isinstance(item, dict) or set(item) != {
            "path",
            "size_bytes",
            "sha256",
            "line_count",
        }:
            raise ValueError(f"{label} file entry fields do not match")
        path = _text(item["path"], "source-file", 1000)
        size = _nonnegative_integer(item["size_bytes"], "source-file-size")
        digest = str(item["sha256"])
        line_count = _nonnegative_integer(item["line_count"], "source-line-count")
        if path.startswith(("/", "\\")) or ".." in Path(path).parts or path in paths:
            raise ValueError(f"{label} file paths are unsafe or duplicated")
        if len(digest) != 64 or any(
            character not in "0123456789abcdef" for character in digest
        ):
            raise ValueError(f"{label} file SHA-256 is invalid")
        paths.add(path)
        result.append(
            {
                "path": path,
                "size_bytes": size,
                "sha256": digest,
                "line_count": line_count,
            }
        )
    if result != sorted(result, key=lambda item: str(item["path"])):
        raise ValueError(f"{label} files must use canonical path order")
    return result


def _cross_language_matrix(value: object) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) > 2_016:
        raise ValueError("cross-language matrix must be a bounded list")
    result: list[dict[str, Any]] = []
    pairs: set[tuple[str, str]] = set()
    required = {
        "languages",
        "engine",
        "engine_version",
        "query_pack_sha256",
        "source_file_sets_sha256",
        "boundaries_analyzed",
        "flows_found",
        "boundaries",
        "boundaries_sha256",
        "flows",
        "flows_sha256",
        "analysis_modes",
        "independent_validation",
    }
    for item in value:
        if not isinstance(item, dict) or set(item) != required:
            raise ValueError("cross-language matrix entry fields do not match")
        raw_languages = item["languages"]
        if not isinstance(raw_languages, list) or len(raw_languages) != 2:
            raise ValueError("cross-language matrix must identify two languages")
        names = sorted(
            _text(value, "language", 50).casefold() for value in raw_languages
        )
        languages = (names[0], names[1])
        if languages[0] == languages[1] or languages in pairs:
            raise ValueError("cross-language matrix pairs must be distinct and unique")
        modes = _labels(item["analysis_modes"], "analysis-modes", 32)
        if not {"semantic-dataflow", "cross-language-boundary"}.issubset(modes):
            raise ValueError("cross-language matrix lacks semantic boundary analysis")
        boundaries = _cross_language_records(
            item["boundaries"], languages, kind="boundary"
        )
        flows = _cross_language_records(item["flows"], languages, kind="flow")
        independent = _independent_validation(
            item["independent_validation"],
            subject_context={
                "languages": list(languages),
                "primary_engine": str(item["engine"]),
                "primary_query_pack_sha256": str(item["query_pack_sha256"]),
                "source_file_sets_sha256": str(item["source_file_sets_sha256"]),
            },
        )
        for name in (
            "query_pack_sha256",
            "source_file_sets_sha256",
            "boundaries_sha256",
            "flows_sha256",
        ):
            digest = str(item[name])
            if len(digest) != 64 or any(
                character not in "0123456789abcdef" for character in digest
            ):
                raise ValueError(f"cross-language matrix {name} is invalid")
        if (
            item["boundaries_sha256"]
            != hashlib.sha256(canonical_bytes(boundaries)).hexdigest()
        ):
            raise ValueError("cross-language boundary ledger digest is invalid")
        if item["flows_sha256"] != hashlib.sha256(canonical_bytes(flows)).hexdigest():
            raise ValueError("cross-language flow ledger digest is invalid")
        if _nonnegative_integer(
            item["boundaries_analyzed"], "boundaries-analyzed"
        ) != len(boundaries):
            raise ValueError("cross-language boundary count does not match its ledger")
        if _nonnegative_integer(item["flows_found"], "flows-found") != len(flows):
            raise ValueError("cross-language flow count does not match its ledger")
        pairs.add(languages)
        result.append(
            {
                "languages": list(languages),
                "engine": _text(item["engine"], "engine", 100),
                "engine_version": _text(item["engine_version"], "engine-version", 100),
                "query_pack_sha256": item["query_pack_sha256"],
                "source_file_sets_sha256": item["source_file_sets_sha256"],
                "boundaries_analyzed": _nonnegative_integer(
                    item["boundaries_analyzed"], "boundaries-analyzed"
                ),
                "flows_found": _nonnegative_integer(item["flows_found"], "flows-found"),
                "boundaries": boundaries,
                "boundaries_sha256": item["boundaries_sha256"],
                "flows": flows,
                "flows_sha256": item["flows_sha256"],
                "analysis_modes": modes,
                "independent_validation": independent,
            }
        )
    return sorted(result, key=lambda item: tuple(item["languages"]))


def _independent_validation(
    value: object, *, subject_context: dict[str, Any]
) -> dict[str, Any]:
    required = {
        "engine",
        "query_pack_sha256",
        "boundaries_sha256",
        "flows_sha256",
        "authority",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise ValueError("independent semantic validation fields do not match")
    result: dict[str, Any] = {name: str(value[name]) for name in required}
    result["engine"] = _text(value["engine"], "independent-engine", 100)
    for name in required - {"engine"}:
        if name == "authority":
            continue
        if len(result[name]) != 64 or any(
            character not in "0123456789abcdef" for character in result[name]
        ):
            raise ValueError("independent semantic validation digest is invalid")
    authority = value["authority"]
    authority_fields = {
        "validated",
        "minimum_signatures",
        "signers",
        "collectors",
        "organizations",
        "subject_sha256",
        "observed_at",
        "trusted_time_sha256",
        "receipts",
    }
    if not isinstance(authority, dict) or set(authority) != authority_fields:
        raise ValueError("independent semantic authority summary is invalid")
    validated = authority.get("validated") is True
    threshold = _nonnegative_integer(
        authority.get("minimum_signatures"), "authority-threshold"
    )
    signers = _labels(authority.get("signers"), "authority-signers", 16)
    collectors = _labels(authority.get("collectors"), "authority-collectors", 16)
    organizations = _labels(
        authority.get("organizations"), "authority-organizations", 16
    )
    subject_sha256 = str(authority.get("subject_sha256") or "")
    observed_at_raw = str(authority.get("observed_at") or "")
    trusted_time_sha256 = str(authority.get("trusted_time_sha256") or "")
    receipts = authority.get("receipts")
    if not isinstance(receipts, list) or len(receipts) > 16:
        raise ValueError("independent semantic authority receipts are invalid")
    if validated and (
        threshold < 2
        or min(len(signers), len(collectors), len(organizations)) < threshold
        or len(subject_sha256) != 64
        or any(character not in "0123456789abcdef" for character in subject_sha256)
        or len(trusted_time_sha256) != 64
        or any(character not in "0123456789abcdef" for character in trusted_time_sha256)
        or len(receipts) < threshold
    ):
        raise ValueError("independent semantic authority quorum is incomplete")
    if not validated and any(
        (
            threshold,
            signers,
            collectors,
            organizations,
            subject_sha256,
            observed_at_raw,
            trusted_time_sha256,
            receipts,
        )
    ):
        raise ValueError("unvalidated independent semantic authority contains claims")
    normalized_receipts: list[dict[str, Any]] = []
    if validated:
        try:
            observed_at = datetime.fromisoformat(
                observed_at_raw.replace("Z", "+00:00")
            ).astimezone(UTC)
        except ValueError as exc:
            raise ValueError("independent semantic trusted time is invalid") from exc
        independent_result = {
            name: result[name]
            for name in (
                "engine",
                "query_pack_sha256",
                "boundaries_sha256",
                "flows_sha256",
            )
        }
        subject = {
            "schema_version": "1.0",
            "purpose": "independent-semantic-validation",
            **subject_context,
            "independent_result": independent_result,
        }
        if hashlib.sha256(canonical_bytes(subject)).hexdigest() != subject_sha256:
            raise ValueError("independent semantic authority subject was rewritten")
        verified = [
            verify_portable_authority(
                receipt,
                purpose="independent-semantic-validation",
                subject=subject,
                at=observed_at,
            )
            for receipt in receipts
        ]
        verified_signers = sorted({item["signer_id"] for item in verified})
        verified_collectors = sorted({item["collector_id"] for item in verified})
        verified_organizations = sorted({item["organization"] for item in verified})
        if (
            verified_signers != signers
            or verified_collectors != collectors
            or verified_organizations != organizations
            or min(
                len(verified_signers),
                len(verified_collectors),
                len(verified_organizations),
            )
            < threshold
        ):
            raise ValueError(
                "independent semantic portable receipt quorum does not match"
            )
        normalized_receipts = sorted(
            [dict(receipt) for receipt in receipts],
            key=lambda item: str(item["receipt_sha256"]),
        )
    result["authority"] = {
        "validated": validated,
        "minimum_signatures": threshold,
        "signers": signers,
        "collectors": collectors,
        "organizations": organizations,
        "subject_sha256": subject_sha256,
        "observed_at": observed_at_raw,
        "trusted_time_sha256": trusted_time_sha256,
        "receipts": normalized_receipts,
    }
    return result


def _cross_language_records(
    value: object, languages: tuple[str, str], *, kind: str
) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) > 100_000:
        raise ValueError(f"cross-language {kind} ledger must be bounded")
    fields = (
        {"path", "line", "language", "kind", "target"}
        if kind == "boundary"
        else {
            "source_path",
            "source_line",
            "source_language",
            "sink_path",
            "sink_line",
            "sink_language",
            "source_kind",
            "sink_kind",
        }
    )
    result: list[dict[str, Any]] = []
    for item in value:
        if not isinstance(item, dict) or set(item) != fields:
            raise ValueError(f"cross-language {kind} ledger fields do not match")
        normalized: dict[str, Any] = {}
        for name in sorted(fields):
            raw = item[name]
            if name.endswith("line") or name == "line":
                line = _nonnegative_integer(raw, f"{kind}-{name}")
                if line < 1:
                    raise ValueError(f"cross-language {kind} lines must be positive")
                normalized[name] = line
            else:
                text = _text(raw, f"{kind}-{name}", 1000)
                if name.endswith("path") or name == "path":
                    if (
                        text.startswith(("/", "\\"))
                        or (len(text) >= 2 and text[1] == ":")
                        or ".." in Path(text).parts
                    ):
                        raise ValueError(f"cross-language {kind} path is unsafe")
                if name.endswith("language") or name == "language":
                    text = text.casefold()
                    if text not in languages:
                        raise ValueError(
                            f"cross-language {kind} language is outside its pair"
                        )
                normalized[name] = text
        result.append(normalized)
    canonical = sorted(result, key=lambda record: canonical_bytes(record))
    if result != canonical or len({canonical_bytes(item) for item in result}) != len(
        result
    ):
        raise ValueError(f"cross-language {kind} ledger is not canonical and unique")
    return result


def _nonnegative_integer(value: object, label: str) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{label} must be a nonnegative integer")
    try:
        result = int(str(value))
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{label} must be a nonnegative integer") from exc
    if result < 0:
        raise ValueError(f"{label} must be a nonnegative integer")
    return result


def _labels(value: object, label: str, maximum: int) -> list[str]:
    if not isinstance(value, list) or len(value) > maximum:
        raise ValueError(f"{label} must be a bounded list")
    labels = [_text(item, label, 160) for item in value]
    if len(set(labels)) != len(labels):
        raise ValueError(f"{label} must not contain duplicates")
    return labels


def _regular_bytes(path: Path, label: str) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{label} is not a regular file")
    if path.stat().st_size > 64 * 1024 * 1024:
        raise ValueError(f"{label} exceeds 64 MiB")
    return path.read_bytes()


def _sha256(path: Path, label: str) -> str:
    if path.is_file() and not path.is_symlink():
        return hashlib.sha256(_regular_bytes(path, label)).hexdigest()
    if path.is_symlink() or not path.is_dir():
        raise ValueError(f"{label} is not a regular file or directory")
    digest = hashlib.sha256()
    files = sorted(candidate for candidate in path.rglob("*") if candidate.is_file())
    if not files or len(files) > 10_000:
        raise ValueError(f"{label} directory must contain 1 to 10000 files")
    total = 0
    for candidate in files:
        if candidate.is_symlink():
            raise ValueError(f"{label} directory contains a symbolic link")
        content = _regular_bytes(candidate, label)
        total += len(content)
        if total > 256 * 1024 * 1024:
            raise ValueError(f"{label} directory exceeds 256 MiB")
        relative = candidate.relative_to(path).as_posix().encode()
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        digest.update(hashlib.sha256(content).digest())
    return digest.hexdigest()


def _text(value: object, label: str, maximum: int) -> str:
    text = str(value or "").strip()
    if not text or len(text) > maximum:
        raise ValueError(f"{label} must be between 1 and {maximum} characters")
    return text


def _run_id(value: str) -> str:
    result = value.strip() or str(uuid.uuid4())
    if len(result) > 100 or not all(
        character.isalnum() or character in "._:-" for character in result
    ):
        raise ValueError("run-id contains unsupported characters")
    return result


def _context_run_id(requested: str, context_run_id: str) -> str:
    result = _run_id(requested or context_run_id)
    if result != context_run_id:
        raise ValueError("run-id does not match the organization-issued context")
    return result


def _write_json(path: Path, document: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and (path.is_symlink() or not path.is_file()):
        raise ValueError(f"output is not a replaceable regular file: {path}")
    payload = (strict_dumps(document, indent=2) + "\n").encode("utf-8")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


if __name__ == "__main__":
    raise SystemExit(main())
