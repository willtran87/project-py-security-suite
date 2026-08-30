from __future__ import annotations

import json
import io
import os
import re
import stat
import sys
import tarfile
import tempfile
import zipfile
from contextlib import nullcontext
from pathlib import Path
from typing import Any, cast

try:
    import atheris  # type: ignore[import-untyped]
except ModuleNotFoundError:  # Listing targets and unit-testing oracles is portable.
    atheris = None  # type: ignore[assignment]
from defusedxml import ElementTree as safe_element_tree  # type: ignore[import-untyped]
from defusedxml.common import DefusedXmlException  # type: ignore[import-untyped]

with atheris.instrument_imports() if atheris is not None else nullcontext():
    from py_security_suite.adapters import ADAPTER_TYPES
    from py_security_suite.adapters.sarif import parse_sarif_findings
    from py_security_suite.benchmark_execution import (
        BenchmarkExecutionError,
        _validate_attestation_document,
    )
    from py_security_suite.benchmark_adapter_conformance import (
        BenchmarkAdapterConformanceError,
        run_adapter_conformance_suite,
    )
    from py_security_suite.benchmark_assurance import (
        BenchmarkAssuranceError,
        _validate_authority_entry,
    )
    from py_security_suite.benchmark_input_validation import (
        BenchmarkInputError,
        validate_benchmark_input,
    )
    from py_security_suite.benchmark_semantic_evidence import (
        BenchmarkSemanticEvidenceError,
        semantic_fingerprint,
    )
    from py_security_suite.benchmark_telemetry import _validate_security_event
    from py_security_suite.config import ToolConfig
    from py_security_suite.models import Finding, json_ready
    from py_security_suite.strict_json import canonical_bytes
    from py_security_suite.strict_json import loads as strict_loads


def _instrument_fuzz_function(function: Any) -> Any:
    """Instrument harness-owned Python code while retaining portable unit imports."""

    return atheris.instrument_func(function) if atheris is not None else function


_TARGET = Path("/fuzz-target")
_GITLEAKS_REPORT = Path(tempfile.gettempdir()) / "pysec-gitleaks-fuzz.json"
_NAMED_ADAPTERS: tuple[tuple[str, Any], ...] = tuple(
    (name, cast(Any, adapter_type)(ToolConfig(), 1024 * 1024))
    for name, adapter_type in sorted(ADAPTER_TYPES.items())
)
_TARGET_NAME = os.environ.get("PYSEC_FUZZ_TARGET", "strict-json")
_ADAPTER_SHARDS = 8


@_instrument_fuzz_function
def test_one_input(data: bytes) -> None:
    if not data or len(data) > 1024 * 1024:
        return
    payload = data
    if _TARGET_NAME == "strict-json":
        try:
            parsed = strict_loads(
                payload,
                maximum_nodes=100_000,
                maximum_string_length=1024 * 1024,
            )
            if strict_loads(canonical_bytes(parsed)) != parsed:
                raise RuntimeError("strict JSON canonical round-trip changed the value")
        except (TypeError, ValueError):
            pass
        return
    if _TARGET_NAME == "benchmark-attestation":
        kinds = (
            "trusted-time",
            "replay-protection",
            "contamination-manifest",
            "runner-sbom",
            "runner-provenance",
            "environment",
            "acceptance-criteria",
            "adapter-conformance",
            "runtime-observation",
            "external-isolation",
            "cleanup-capability",
        )
        try:
            parsed = strict_loads(payload)
            if isinstance(parsed, dict):
                _validate_attestation_document(
                    parsed,
                    kinds[data[0] % len(kinds)],
                    "0" * 64,
                    require_authority=True,
                )
        except (BenchmarkExecutionError, TypeError, ValueError):
            pass
        return
    if _TARGET_NAME == "benchmark-semantic-python":
        try:
            first = semantic_fingerprint(payload, language="python")
            second = semantic_fingerprint(payload, language="python")
            if first != second:
                raise RuntimeError("semantic fingerprint is nondeterministic")
        except BenchmarkSemanticEvidenceError:
            pass
        return
    if _TARGET_NAME == "benchmark-authority-entry":
        try:
            parsed = strict_loads(payload)
            _validate_authority_entry(
                parsed,
                policy={
                    "schema_version": "1.1",
                    "issued_at": "2026-01-01T00:00:00+00:00",
                    "expires_at": "2026-12-31T00:00:00+00:00",
                },
            )
        except (BenchmarkAssuranceError, TypeError, ValueError):
            pass
        return
    if _TARGET_NAME == "benchmark-security-event":
        try:
            _validate_security_event(strict_loads(payload))
        except (TypeError, ValueError):
            pass
        return
    if _TARGET_NAME == "benchmark-adapter-conformance":

        def normalizer(candidate: bytes) -> dict[str, Any]:
            parsed = strict_loads(candidate)
            if not isinstance(parsed, dict):
                raise ValueError("fixture is not an object")
            return parsed

        try:
            expected = normalizer(payload)
            run_adapter_conformance_suite(
                normalizer=normalizer,
                golden_fixtures=[(payload, expected)] * 3,
                malformed_fixtures=[b"", b"[]", b"null"],
                inverted_fixtures=[payload] * 3,
                semantic_oracle=lambda value: value.get("passed") is True,
                adapter_spec_sha256="a" * 64,
                runner_executable_sha256="b" * 64,
                normalizer_identity="fuzz:strict-json-object",
                semantic_oracle_identity="fuzz:passed-boolean:v1",
                semantic_oracle_sha256="c" * 64,
            )
        except (BenchmarkAdapterConformanceError, TypeError, ValueError):
            pass
        return
    if _TARGET_NAME == "strict-xml":
        try:
            xml_first = _inspect_xml(payload)
            xml_second = _inspect_xml(payload)
            if xml_first != xml_second:
                raise RuntimeError("XML inspection is nondeterministic")
        except (DefusedXmlException, safe_element_tree.ParseError, ValueError):
            pass
        return
    if _TARGET_NAME == "zip-archive":
        _assert_production_archive_deterministic(payload, ".zip")
        try:
            zip_first = _inspect_zip(payload)
            zip_second = _inspect_zip(payload)
            if zip_first != zip_second:
                raise AssertionError("ZIP inspection is nondeterministic")
        except (
            OSError,
            ValueError,
            zipfile.BadZipFile,
        ):
            pass
        return
    if _TARGET_NAME == "tar-archive":
        _assert_production_archive_deterministic(payload, ".tar")
        try:
            tar_first = _inspect_tar(payload)
            tar_second = _inspect_tar(payload)
            if tar_first != tar_second:
                raise AssertionError("TAR inspection is nondeterministic")
        except (
            EOFError,
            OSError,
            ValueError,
            tarfile.TarError,
        ):
            pass
        return
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError:
        return
    if _TARGET_NAME == "sarif":
        try:
            sarif_first = parse_sarif_findings(
                text,
                _TARGET,
                tool_name="fuzz",
                default_area="parser-fuzzing",
                default_impact="fuzz",
                default_remediation="fuzz",
            )
            parse_sarif_findings(
                "{}",
                _TARGET,
                tool_name="fuzz",
                default_area="parser-fuzzing",
                default_impact="fuzz",
                default_remediation="fuzz",
            )
            sarif_second = parse_sarif_findings(
                text,
                _TARGET,
                tool_name="fuzz",
                default_area="parser-fuzzing",
                default_impact="fuzz",
                default_remediation="fuzz",
            )
            if sarif_first != sarif_second:
                raise RuntimeError("SARIF normalization is nondeterministic")
            _assert_normalized_findings(sarif_first)
        except (TypeError, ValueError):
            pass
        return
    selected = _selected_adapters(_TARGET_NAME)
    selector = data[0] % len(selected)
    try:
        name, adapter = selected[selector]
        adapter_first = _parse_adapter(name, adapter, text)
        _parse_adapter(name, adapter, "{}")
        adapter_second = _parse_adapter(name, adapter, text)
        if adapter_first != adapter_second:
            raise RuntimeError("adapter normalization leaks state between reports")
        _assert_normalized_findings(adapter_first)
    except (TypeError, ValueError):
        pass


@_instrument_fuzz_function
def _safe_archive_path(name: str) -> str:
    normalized = name.replace("\\", "/")
    parts = normalized.split("/")
    if (
        not normalized
        or "\x00" in normalized
        or normalized.startswith("/")
        or re.match(r"^[a-zA-Z]:", normalized)
        or any(part == ".." for part in parts)
    ):
        raise ValueError("archive member escapes its extraction root")
    return normalized


@_instrument_fuzz_function
def _inspect_xml(payload: bytes) -> tuple[int, int, int]:
    try:
        root = safe_element_tree.fromstring(payload)
    except LookupError as exc:
        raise ValueError("XML declares an unsupported encoding") from exc
    nodes = 0
    attributes = 0
    text_bytes = 0
    for element in root.iter():
        nodes += 1
        if nodes > 100_000:
            raise ValueError("XML node limit exceeded")
        attributes += len(element.attrib)
        if attributes > 200_000:
            raise ValueError("XML attribute limit exceeded")
        text_bytes += len((element.text or "").encode("utf-8", errors="replace"))
        text_bytes += len((element.tail or "").encode("utf-8", errors="replace"))
        if text_bytes > 16 * 1024 * 1024:
            raise ValueError("XML text limit exceeded")
    return nodes, attributes, text_bytes


@_instrument_fuzz_function
def _inspect_zip(payload: bytes) -> tuple[tuple[str, int, int], ...]:
    records: list[tuple[str, int, int]] = []
    total_size = 0
    try:
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            entries = archive.infolist()
            if len(entries) > 100_000:
                raise ValueError("ZIP member limit exceeded")
            for entry in entries:
                name = _safe_archive_path(entry.filename)
                mode = (entry.external_attr >> 16) & 0o170000
                if mode == stat.S_IFLNK or entry.flag_bits & 0x1:
                    raise ValueError("ZIP links and encrypted entries are not accepted")
                if entry.file_size > 64 * 1024 * 1024:
                    raise ValueError("ZIP member size limit exceeded")
                total_size += entry.file_size
                if total_size > 128 * 1024 * 1024:
                    raise ValueError("ZIP aggregate size limit exceeded")
                if entry.file_size > max(1, entry.compress_size) * 1_000:
                    raise ValueError("ZIP compression ratio limit exceeded")
                records.append((name, entry.file_size, entry.CRC))
    except NotImplementedError as exc:
        raise ValueError("ZIP uses an unsupported feature or version") from exc
    return tuple(records)


@_instrument_fuzz_function
def _inspect_tar(payload: bytes) -> tuple[tuple[str, int, str], ...]:
    records: list[tuple[str, int, str]] = []
    total_size = 0
    with tarfile.open(fileobj=io.BytesIO(payload), mode="r:*") as archive:
        for index, entry in enumerate(archive):
            if index >= 100_000:
                raise ValueError("TAR member limit exceeded")
            name = _safe_archive_path(entry.name)
            if entry.issym() or entry.islnk() or entry.isdev() or entry.isfifo():
                raise ValueError("TAR links and special files are not accepted")
            if entry.size > 64 * 1024 * 1024:
                raise ValueError("TAR member size limit exceeded")
            total_size += entry.size
            if total_size > 128 * 1024 * 1024:
                raise ValueError("TAR aggregate size limit exceeded")
            entry_type = (
                entry.type.decode("ascii", errors="replace")
                if isinstance(entry.type, bytes)
                else str(entry.type)
            )
            records.append((name, entry.size, entry_type))
    return tuple(records)


@_instrument_fuzz_function
def _inspect_production_archive(payload: bytes, suffix: str) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="pysec-benchmark-fuzz-") as directory:
        candidate = Path(directory) / f"input{suffix}"
        candidate.write_bytes(payload)
        return validate_benchmark_input(candidate)


def _assert_production_archive_deterministic(payload: bytes, suffix: str) -> None:
    try:
        first = _inspect_production_archive(payload, suffix)
        second = _inspect_production_archive(payload, suffix)
    except (BenchmarkInputError, OSError, ValueError):
        return
    if first != second:
        raise AssertionError("production archive validation is nondeterministic")


def _parse_adapter(name: str, adapter: Any, text: str) -> list[Finding]:
    if name == "gitleaks":
        # Gitleaks writes JSON to --report-path instead of stdout. Recreate that
        # production boundary for every pass because the adapter deliberately
        # removes the sensitive report immediately after parsing it.
        adapter._report_path = _GITLEAKS_REPORT
        _GITLEAKS_REPORT.write_text(text, encoding="utf-8")
    return cast(list[Finding], adapter.parse(text, _TARGET))


def _assert_normalized_findings(findings: object) -> None:
    if not isinstance(findings, list) or len(findings) > 100_000:
        raise RuntimeError("parser returned an unbounded or non-list finding result")
    if any(not isinstance(item, Finding) for item in findings):
        raise RuntimeError("parser returned a non-Finding result")
    normalized = json_ready(findings)
    encoded = canonical_bytes(normalized)
    if (
        strict_loads(encoded) != normalized
        or canonical_bytes(strict_loads(encoded)) != encoded
    ):
        raise RuntimeError("normalized findings do not have a stable strict-JSON form")
    for finding in findings:
        if (
            not finding.finding_id
            or not finding.fingerprint
            or "\x00" in finding.description
        ):
            raise RuntimeError("normalized finding identity or text is invalid")
        for location in finding.locations:
            path = str(location.path).replace("\\", "/")
            if (
                not path
                or "\x00" in path
                or path.startswith("/")
                or re.match(r"^[a-zA-Z]:/", path)
                or ".." in path.split("/")
            ):
                raise RuntimeError("normalized finding path escapes the repository")


def _selected_adapters(target: str) -> tuple[tuple[str, Any], ...]:
    if target.startswith("adapter:"):
        name = target.partition(":")[2]
        selected = tuple(item for item in _NAMED_ADAPTERS if item[0] == name)
    elif target.startswith("adapter-"):
        try:
            shard = int(target.partition("-")[2])
        except ValueError as exc:
            raise ValueError("invalid adapter fuzz shard") from exc
        if not 0 <= shard < _ADAPTER_SHARDS:
            raise ValueError("invalid adapter fuzz shard")
        selected = tuple(
            item
            for index, item in enumerate(_NAMED_ADAPTERS)
            if index % _ADAPTER_SHARDS == shard
        )
    else:
        raise ValueError(f"unsupported fuzz target: {target}")
    if not selected:
        raise ValueError(f"fuzz target selects no adapters: {target}")
    return selected


def _seed_target_corpus(target: str, destination: Path) -> None:
    """Add deterministic structured seeds for formats mutation cannot synthesize."""

    destination.mkdir(parents=True, exist_ok=True)
    if target == "zip-archive":
        zip_cases = (
            ("zip-safe", "reports/finding.json", b"{}", 0),
            ("zip-traversal", "../outside.json", b"{}", 0),
            ("zip-link", "reports/link", b"target", stat.S_IFLNK | 0o777),
            ("zip-ratio", "reports/zeros.bin", b"\0" * 1_048_576, 0),
        )
        for seed_name, member_name, payload, mode in zip_cases:
            with zipfile.ZipFile(
                destination / seed_name,
                "w",
                compression=zipfile.ZIP_DEFLATED,
            ) as archive:
                zip_info = zipfile.ZipInfo(member_name, date_time=(1980, 1, 1, 0, 0, 0))
                zip_info.compress_type = zipfile.ZIP_DEFLATED
                if mode:
                    zip_info.external_attr = mode << 16
                archive.writestr(zip_info, payload)
    elif target == "tar-archive":
        tar_cases = (
            ("tar-safe", "reports/finding.json", tarfile.REGTYPE),
            ("tar-traversal", "../outside.json", tarfile.REGTYPE),
            ("tar-link", "reports/link", tarfile.SYMTYPE),
        )
        for seed_name, member_name, member_type in tar_cases:
            with tarfile.open(destination / seed_name, "w") as archive:
                payload = b"{}" if member_type == tarfile.REGTYPE else b""
                tar_info = tarfile.TarInfo(member_name)
                tar_info.mtime = 0
                tar_info.size = len(payload)
                tar_info.type = member_type
                if member_type == tarfile.SYMTYPE:
                    tar_info.linkname = "target"
                archive.addfile(tar_info, io.BytesIO(payload))
    elif target == "benchmark-attestation":
        (destination / "minimal.json").write_text(
            json.dumps(
                {
                    "schema_version": "1.1",
                    "kind": "trusted-time",
                    "subject_sha256": "0" * 64,
                    "valid": True,
                    "authority": {
                        "organization_id": "fuzz-authority",
                        "role": "trusted-time",
                        "issued_at": "2026-01-01T00:00:00+00:00",
                        "expires_at": "2026-12-31T00:00:00+00:00",
                        "revocation_status_sha256": "1" * 64,
                    },
                    "claims": {
                        "rfc3161_verified": True,
                        "monotonic_state_verified": True,
                        "trusted_time_receipt_sha256": "2" * 64,
                        "observed_at": "2026-01-01T00:00:00+00:00",
                    },
                },
                sort_keys=True,
            ),
            encoding="utf-8",
        )


def main() -> None:
    global _TARGET_NAME
    if "--list-targets" in sys.argv:
        targets = [
            {
                "target": "strict-json",
                "artifact": "strict-json",
                "seconds": 300,
                "coverage_floor": 16,
            },
            {
                "target": "sarif",
                "artifact": "sarif",
                "seconds": 300,
                "coverage_floor": 16,
            },
            {
                "target": "strict-xml",
                "artifact": "strict-xml",
                "seconds": 420,
                "coverage_floor": 10,
            },
            {
                "target": "zip-archive",
                "artifact": "zip-archive",
                "seconds": 420,
                "coverage_floor": 10,
            },
            {
                "target": "tar-archive",
                "artifact": "tar-archive",
                "seconds": 420,
                "coverage_floor": 10,
            },
            {
                "target": "benchmark-attestation",
                "artifact": "benchmark-attestation",
                "seconds": 420,
                "coverage_floor": 12,
            },
            {
                "target": "benchmark-semantic-python",
                "artifact": "benchmark-semantic-python",
                "seconds": 420,
                "coverage_floor": 12,
            },
            {
                "target": "benchmark-authority-entry",
                "artifact": "benchmark-authority-entry",
                "seconds": 420,
                "coverage_floor": 12,
            },
            {
                "target": "benchmark-security-event",
                "artifact": "benchmark-security-event",
                "seconds": 420,
                "coverage_floor": 12,
            },
            {
                "target": "benchmark-adapter-conformance",
                "artifact": "benchmark-adapter-conformance",
                "seconds": 420,
                "coverage_floor": 12,
            },
        ]
        targets.extend(
            {
                "target": f"adapter:{name}",
                "artifact": f"adapter-{index:03d}-{re.sub(r'[^a-z0-9-]', '-', name.casefold())}",
                "seconds": 240,
                "coverage_floor": 12,
            }
            for index, (name, _adapter) in enumerate(_NAMED_ADAPTERS)
        )
        print(json.dumps(targets, separators=(",", ":"), sort_keys=True))
        return
    seed_arguments = [
        item for item in sys.argv[1:] if item.startswith("--seed-target=")
    ]
    if seed_arguments:
        destinations = [item for item in sys.argv[1:] if not item.startswith("-")]
        if len(seed_arguments) != 1 or len(destinations) != 1:
            raise ValueError("corpus seeding requires one target and destination")
        _seed_target_corpus(seed_arguments[0].partition("=")[2], Path(destinations[0]))
        return
    target_arguments = [item for item in sys.argv[1:] if item.startswith("--target=")]
    if len(target_arguments) > 1:
        raise ValueError("fuzzer accepts one --target argument")
    if target_arguments:
        _TARGET_NAME = target_arguments[0].partition("=")[2]
        sys.argv.remove(target_arguments[0])
    if _TARGET_NAME not in {
        "sarif",
        "strict-json",
        "strict-xml",
        "tar-archive",
        "zip-archive",
        "benchmark-attestation",
        "benchmark-semantic-python",
        "benchmark-authority-entry",
        "benchmark-security-event",
        "benchmark-adapter-conformance",
    }:
        _selected_adapters(_TARGET_NAME)
    if atheris is None:
        raise RuntimeError("Atheris is required to execute fuzz targets")
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
