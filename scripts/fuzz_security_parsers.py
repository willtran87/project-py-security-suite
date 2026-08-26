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
    from py_security_suite.config import ToolConfig
    from py_security_suite.models import Finding, json_ready
    from py_security_suite.strict_json import canonical_bytes
    from py_security_suite.strict_json import loads as strict_loads


_TARGET = Path("/fuzz-target")
_GITLEAKS_REPORT = Path(tempfile.gettempdir()) / "pysec-gitleaks-fuzz.json"
_NAMED_ADAPTERS: tuple[tuple[str, Any], ...] = tuple(
    (name, cast(Any, adapter_type)(ToolConfig(), 1024 * 1024))
    for name, adapter_type in sorted(ADAPTER_TYPES.items())
)
_TARGET_NAME = os.environ.get("PYSEC_FUZZ_TARGET", "strict-json")
_ADAPTER_SHARDS = 8


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
        try:
            zip_first = _inspect_zip(payload)
            zip_second = _inspect_zip(payload)
            if zip_first != zip_second:
                raise RuntimeError("ZIP inspection is nondeterministic")
        except (OSError, RuntimeError, ValueError, zipfile.BadZipFile):
            pass
        return
    if _TARGET_NAME == "tar-archive":
        try:
            tar_first = _inspect_tar(payload)
            tar_second = _inspect_tar(payload)
            if tar_first != tar_second:
                raise RuntimeError("TAR inspection is nondeterministic")
        except (EOFError, OSError, RuntimeError, ValueError, tarfile.TarError):
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


def _inspect_xml(payload: bytes) -> tuple[int, int, int]:
    root = safe_element_tree.fromstring(payload)
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


def _inspect_zip(payload: bytes) -> tuple[tuple[str, int, int], ...]:
    records: list[tuple[str, int, int]] = []
    total_size = 0
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
    return tuple(records)


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
    }:
        _selected_adapters(_TARGET_NAME)
    if atheris is None:
        raise RuntimeError("Atheris is required to execute fuzz targets")
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
