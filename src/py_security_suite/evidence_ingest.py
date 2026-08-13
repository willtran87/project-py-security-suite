from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any

from defusedxml import ElementTree as DefusedET  # type: ignore[import-untyped]
from defusedxml.common import DefusedXmlException  # type: ignore[import-untyped]

from . import __version__
from .inventory import source_snapshot

_MAX_REPORT_BYTES = 64 * 1024 * 1024
_MAX_JUNIT_REPORTS = 128
_MAX_JUNIT_TEST_CASES = 100_000
_ASSURANCE_KINDS = frozenset(
    {
        "atheris",
        "check-manifest",
        "clamav",
        "crosshair",
        "github-attestation",
        "in-toto",
        "mutmut",
        "oci-image",
        "pytm",
        "reproducible-build",
        "yara",
        "zap",
    }
)
_MAX_ASSURANCE_FINDINGS = 10_000
_BINDING_SUFFIX = ".pysec-binding.json"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="pysec-evidence",
        description="Validate pre-generated test evidence without executing target code.",
    )
    parser.add_argument("--version", action="version", version=__version__)
    subparsers = parser.add_subparsers(dest="kind", required=True)
    coverage = subparsers.add_parser("coverage")
    coverage.add_argument("path", type=Path)
    junit = subparsers.add_parser("junit")
    junit.add_argument("path", type=Path)
    bind = subparsers.add_parser(
        "bind",
        help="bind pre-generated evidence to the current non-evidence source snapshot",
    )
    bind.add_argument("paths", type=Path, nargs="+")
    bind.add_argument("--source-root", type=Path, required=True)
    bind.add_argument("--overwrite", action="store_true")
    scorecard = subparsers.add_parser("scorecard")
    scorecard.add_argument("path", type=Path)
    assurance = subparsers.add_parser("assurance")
    assurance.add_argument("evidence_kind", choices=sorted(_ASSURANCE_KINDS))
    assurance.add_argument("path", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.kind == "bind":
            document = _bind_evidence(
                args.paths,
                source_root=args.source_root,
                overwrite=args.overwrite,
            )
        elif args.kind == "coverage":
            document = _coverage_document(args.path)
        elif args.kind == "junit":
            document = _junit_document(args.path)
        elif args.kind == "scorecard":
            document = _scorecard_document(args.path)
        else:
            document = _assurance_document(args.path, args.evidence_kind)
    except (OSError, TypeError, ValueError, DefusedXmlException) as exc:
        print(f"invalid {args.kind} evidence: {exc}", file=sys.stderr)
        return 2
    json.dump(document, sys.stdout, sort_keys=True, separators=(",", ":"))
    sys.stdout.write("\n")
    return 0


def _read_bounded(path: Path) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"report is not a regular file: {path}")
    size = path.stat().st_size
    if size > _MAX_REPORT_BYTES:
        raise ValueError(f"report exceeds {_MAX_REPORT_BYTES} bytes: {path}")
    return path.read_bytes()


def _bind_evidence(
    paths: list[Path], *, source_root: Path, overwrite: bool
) -> dict[str, Any]:
    if source_root.is_symlink() or not source_root.is_dir():
        raise ValueError(f"source root is not a regular directory: {source_root}")
    if len(paths) > 16:
        raise ValueError("at most 16 evidence paths may be bound together")
    resolved_paths: list[Path] = []
    for path in paths:
        if path.is_symlink() or not (path.is_file() or path.is_dir()):
            raise ValueError(f"evidence path does not exist or is linked: {path}")
        resolved_paths.append(path.resolve())
    sidecars = [_binding_path(path) for path in resolved_paths]
    digest, files, total_bytes = source_snapshot(
        source_root.resolve(), excluded_paths=tuple([*resolved_paths, *sidecars])
    )
    bindings: list[dict[str, Any]] = []
    for path, sidecar in zip(resolved_paths, sidecars, strict=True):
        evidence_sha256 = _evidence_sha256(path)
        binding = {
            "schema_version": "1.0",
            "source_sha256": digest,
            "evidence_sha256": evidence_sha256,
        }
        _write_binding(sidecar, binding, overwrite=overwrite)
        bindings.append(
            {
                "evidence_path": str(path),
                "binding_path": str(sidecar),
                "evidence_sha256": evidence_sha256,
            }
        )
    return {
        "schema_version": "1.0",
        "kind": "evidence-binding",
        "source_root": str(source_root.resolve()),
        "source_sha256": digest,
        "source_files": files,
        "source_bytes": total_bytes,
        "bindings": bindings,
    }


def _apply_source_binding(document: dict[str, Any], path: Path) -> dict[str, Any]:
    sidecar = _binding_path(path.resolve())
    if not sidecar.exists():
        return document
    binding = json.loads(_read_bounded(sidecar))
    if not isinstance(binding, dict) or set(binding) != {
        "schema_version",
        "source_sha256",
        "evidence_sha256",
    }:
        raise ValueError("evidence source binding fields do not match the contract")
    if binding.get("schema_version") != "1.0":
        raise ValueError("evidence source binding schema_version must be '1.0'")
    source_sha256 = binding.get("source_sha256")
    evidence_sha256 = binding.get("evidence_sha256")
    if not _digest(source_sha256) or not _digest(evidence_sha256):
        raise ValueError("evidence source binding contains an invalid digest")
    observed = _evidence_sha256(path.resolve())
    if observed != evidence_sha256:
        raise ValueError("evidence source binding does not match the evidence payload")
    document["source_sha256"] = source_sha256
    document["evidence_binding"] = {
        "schema_version": "1.0",
        "evidence_sha256": evidence_sha256,
        "binding_file": sidecar.name,
        "verified": True,
    }
    return document


def _binding_path(path: Path) -> Path:
    return path.with_name(path.name + _BINDING_SUFFIX)


def _evidence_sha256(path: Path) -> str:
    if path.is_file() and not path.is_symlink():
        return hashlib.sha256(_read_bounded(path)).hexdigest()
    reports = _junit_paths(path)
    aggregate = hashlib.sha256()
    resolved = path.resolve()
    for report in reports:
        payload = _read_bounded(report)
        relative = report.resolve().relative_to(resolved).as_posix().encode("utf-8")
        aggregate.update(len(relative).to_bytes(8, "big"))
        aggregate.update(relative)
        aggregate.update(len(payload).to_bytes(8, "big"))
        aggregate.update(hashlib.sha256(payload).digest())
    return aggregate.hexdigest()


def _write_binding(path: Path, document: dict[str, Any], *, overwrite: bool) -> None:
    if path.exists() and (path.is_symlink() or not overwrite):
        raise ValueError(f"binding output already exists: {path}")
    payload = (
        json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")
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


def _digest(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _coverage_document(path: Path) -> dict[str, Any]:
    payload = json.loads(_read_bounded(path))
    if not isinstance(payload, dict):
        raise TypeError("coverage JSON root must be an object")
    meta = payload.get("meta")
    totals = payload.get("totals")
    files = payload.get("files")
    if not isinstance(meta, dict) or not isinstance(totals, dict):
        raise TypeError("coverage JSON requires meta and totals objects")
    if not isinstance(files, dict):
        raise TypeError("coverage JSON requires a files object")
    normalized_files: list[dict[str, Any]] = []
    for name, value in sorted(files.items()):
        if not isinstance(value, dict) or not isinstance(value.get("summary"), dict):
            raise TypeError(f"coverage file entry is invalid: {name}")
        summary = value["summary"]
        normalized_files.append(
            {
                "path": str(name),
                "summary": _coverage_summary(summary),
                "missing_lines": _integer_list(value.get("missing_lines")),
                "missing_branches": _branch_list(value.get("missing_branches")),
            }
        )
    return _apply_source_binding(
        {
            "schema_version": "1.0",
            "kind": "coverage",
            "report": str(path.resolve()),
            "meta": {
                "format": _integer(meta.get("format")),
                "branch_coverage": bool(meta.get("branch_coverage", False)),
                "timestamp": str(meta.get("timestamp") or ""),
            },
            "totals": _coverage_summary(totals),
            "files": normalized_files,
        },
        path,
    )


def _coverage_summary(value: dict[str, Any]) -> dict[str, int | float]:
    return {
        "covered_lines": _integer(value.get("covered_lines")),
        "num_statements": _integer(value.get("num_statements")),
        "percent_covered": _number(value.get("percent_covered")),
        "missing_lines": _integer(value.get("missing_lines")),
        "num_branches": _integer(value.get("num_branches")),
        "covered_branches": _integer(value.get("covered_branches")),
        "missing_branches": _integer(value.get("missing_branches")),
        "num_partial_branches": _integer(value.get("num_partial_branches")),
    }


def _junit_document(path: Path) -> dict[str, Any]:
    reports = _junit_paths(path)
    totals = {"tests": 0, "failures": 0, "errors": 0, "skipped": 0, "time": 0.0}
    failures: list[dict[str, Any]] = []
    test_cases: list[dict[str, Any]] = []
    for report in reports:
        data = _read_bounded(report)
        lowered = data[:4096].lower()
        if b"<!doctype" in lowered or b"<!entity" in lowered:
            raise ValueError(f"DTD and entity declarations are not allowed: {report}")
        root = DefusedET.fromstring(
            data,
            forbid_dtd=True,
            forbid_entities=True,
            forbid_external=True,
        )
        for case in (
            node for node in root.iter() if _local_name(node.tag) == "testcase"
        ):
            totals["tests"] += 1
            totals["time"] += _number(case.attrib.get("time"))
            result = next(
                (
                    child
                    for child in case
                    if _local_name(child.tag) in {"failure", "error", "skipped"}
                ),
                None,
            )
            result_type = "passed" if result is None else _local_name(result.tag)
            if result_type != "passed":
                total_key = "skipped" if result_type == "skipped" else f"{result_type}s"
                totals[total_key] += 1
            case_record = {
                "name": _bounded_text(case.attrib.get("name") or "unnamed test", 500),
                "classname": _bounded_text(case.attrib.get("classname"), 500),
                "file": _bounded_text(case.attrib.get("file"), 4096),
                "line": _optional_integer(case.attrib.get("line")),
                "time": _number(case.attrib.get("time")),
                "result": result_type,
                "file_attribution": (
                    "producer" if case.attrib.get("file") else "unavailable"
                ),
            }
            if len(test_cases) < _MAX_JUNIT_TEST_CASES:
                test_cases.append(case_record)
            if result is not None and result_type != "skipped":
                failures.append(
                    {
                        "report": str(report.resolve()),
                        **case_record,
                        "message": _bounded_text(result.attrib.get("message")),
                        "type": _bounded_text(result.attrib.get("type")),
                    }
                )
    return _apply_source_binding(
        {
            "schema_version": "1.0",
            "kind": "junit",
            "report_count": len(reports),
            "totals": totals,
            "failures": failures,
            "test_cases": test_cases,
            "test_case_inventory_complete": totals["tests"] <= _MAX_JUNIT_TEST_CASES,
        },
        path,
    )


def _scorecard_document(path: Path) -> dict[str, Any]:
    payload = json.loads(_read_bounded(path))
    if not isinstance(payload, dict):
        raise TypeError("Scorecard JSON root must be an object")
    checks = payload.get("checks")
    if not isinstance(checks, list):
        raise TypeError("Scorecard JSON requires a checks list")
    normalized: list[dict[str, Any]] = []
    for check in checks:
        if not isinstance(check, dict):
            raise TypeError("Scorecard checks must be objects")
        details = check.get("details", [])
        if not isinstance(details, list):
            details = []
        documentation = check.get("documentation", {})
        if not isinstance(documentation, dict):
            documentation = {}
        normalized.append(
            {
                "name": _bounded_text(check.get("name"), 100),
                "score": _number(check.get("score")),
                "reason": _bounded_text(check.get("reason"), 500),
                "details": [_bounded_text(value, 300) for value in details[:50]],
                "documentation": {
                    "url": _https_url(documentation.get("url")),
                    "short": _bounded_text(documentation.get("short"), 300),
                },
            }
        )
    return {
        "schema_version": "1.0",
        "kind": "scorecard",
        "repository": _bounded_text(
            payload.get("repo") or payload.get("repository"), 300
        ),
        "score": _number(payload.get("score")),
        "date": _bounded_text(payload.get("date"), 100),
        "checks": normalized,
    }


def _assurance_document(path: Path, kind: str) -> dict[str, Any]:
    payload = json.loads(_read_bounded(path))
    if not isinstance(payload, dict):
        raise TypeError("assurance JSON root must be an object")
    if payload.get("kind") != kind:
        raise ValueError(f"assurance evidence kind must be {kind!r}")
    findings = payload.get("findings", [])
    if not isinstance(findings, list):
        raise TypeError("assurance evidence requires a findings list")
    if len(findings) > _MAX_ASSURANCE_FINDINGS:
        raise ValueError(
            f"assurance evidence exceeds {_MAX_ASSURANCE_FINDINGS} findings"
        )
    normalized: list[dict[str, Any]] = []
    for value in findings:
        if not isinstance(value, dict):
            raise TypeError("assurance findings must be objects")
        evidence = value.get("evidence", {})
        if not isinstance(evidence, dict):
            evidence = {}
        normalized.append(
            {
                "rule_id": _bounded_text(value.get("rule_id"), 160),
                "title": _bounded_text(value.get("title"), 300),
                "message": _bounded_text(
                    value.get("message") or value.get("description"), 1_000
                ),
                "path": _bounded_text(value.get("path"), 500),
                "line": _optional_integer(value.get("line")),
                "severity": _assurance_severity(value.get("severity")),
                "classification": _bounded_text(value.get("classification"), 160),
                "citation": _https_url(value.get("citation")),
                "impact": _bounded_text(value.get("impact"), 1_000),
                "remediation": _bounded_text(value.get("remediation"), 1_000),
                "area": _bounded_text(value.get("area"), 100),
                "domain": _bounded_text(value.get("domain"), 100),
                "fingerprint": _bounded_text(value.get("fingerprint"), 200),
                "evidence": {
                    _bounded_text(key, 100): _bounded_scalar(item)
                    for key, item in list(evidence.items())[:50]
                },
            }
        )
    return {
        "schema_version": "1.0",
        "kind": kind,
        "producer": _bounded_text(payload.get("producer"), 200),
        "revision": _bounded_text(payload.get("revision"), 200),
        "findings": normalized,
    }


def _junit_paths(path: Path) -> list[Path]:
    if path.is_file() and not path.is_symlink():
        return [path]
    if not path.is_dir() or path.is_symlink():
        raise ValueError(f"JUnit evidence path does not exist: {path}")
    reports = sorted(
        candidate
        for candidate in path.rglob("*.xml")
        if candidate.is_file() and not candidate.is_symlink()
    )
    if not reports:
        raise ValueError(f"no JUnit XML reports were found under: {path}")
    if len(reports) > _MAX_JUNIT_REPORTS:
        raise ValueError(f"more than {_MAX_JUNIT_REPORTS} JUnit reports were found")
    return reports


def _integer(value: object) -> int:
    try:
        return int(str(value or 0))
    except (TypeError, ValueError) as exc:
        raise TypeError(f"expected an integer, received {value!r}") from exc


def _optional_integer(value: object) -> int | None:
    return None if value in (None, "") else _integer(value)


def _number(value: object) -> float:
    try:
        return round(float(str(value or 0.0)), 6)
    except (TypeError, ValueError) as exc:
        raise TypeError(f"expected a number, received {value!r}") from exc


def _integer_list(value: object) -> list[int]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise TypeError("expected a list of line numbers")
    return [_integer(item) for item in value]


def _branch_list(value: object) -> list[list[int]]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise TypeError("expected a list of branch pairs")
    branches: list[list[int]] = []
    for item in value:
        if not isinstance(item, list) or len(item) != 2:
            raise TypeError("coverage branch entries must be two-item lists")
        branches.append([_integer(item[0]), _integer(item[1])])
    return branches


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _bounded_text(value: object, maximum: int = 300) -> str:
    text = " ".join(str(value or "").split())
    return text if len(text) <= maximum else text[: maximum - 3] + "..."


def _https_url(value: object) -> str:
    text = _bounded_text(value, 500)
    return text if text.startswith("https://") else ""


def _assurance_severity(value: object) -> str:
    normalized = _bounded_text(value, 30).casefold() or "medium"
    if normalized not in {"critical", "high", "medium", "low", "informational", "info"}:
        raise ValueError(f"unsupported assurance severity: {normalized!r}")
    return normalized


def _bounded_scalar(value: object) -> str | int | float | bool | None:
    if value is None or isinstance(value, (int, float, bool)):
        return value
    return _bounded_text(value, 500)


if __name__ == "__main__":
    raise SystemExit(main())
