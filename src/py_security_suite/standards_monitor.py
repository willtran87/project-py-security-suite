from __future__ import annotations

import base64
import difflib
import hashlib
import io
import ipaddress
import json
import os
import re
import socket
import ssl
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable
from html.parser import HTMLParser
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener

from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from defusedxml import ElementTree  # type: ignore[import-untyped]
from pypdf import PdfReader

from .path_safety import (
    hold_parent_directory,
    read_regular_file,
    resolve_regular_file,
    resolve_unlinked_path,
)
from .strict_json import canonical_bytes, loads as strict_loads


_MAX_MANIFEST_BYTES = 2 * 1024 * 1024
_MAX_SOURCE_BYTES = 16 * 1024 * 1024
_MAX_TOTAL_BYTES = 128 * 1024 * 1024
_IDENTIFIER = re.compile(r"^[A-Z0-9][A-Z0-9._-]{0,127}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")


class StandardsMonitorError(ValueError):
    """Raised when a publisher snapshot cannot be acquired safely."""


def monitor_standard_sources(
    manifest_path: Path,
    output_directory: Path,
    *,
    network_authorized: bool,
    overwrite: bool = False,
    signing_key_path: Path | None = None,
    fetcher: Callable[[str, int, set[str]], tuple[bytes, str, str]] | None = None,
) -> dict[str, Any]:
    """Retrieve publisher sources into quarantine and report lifecycle changes.

    A changed source is never promoted automatically. The immutable, digest-named
    payload is retained in a quarantine directory and the signed report asks for a
    human review. Network retrieval is explicit and restricted to HTTPS publisher
    hosts declared in the manifest.
    """
    if not network_authorized and fetcher is None:
        raise StandardsMonitorError(
            "standards monitoring requires explicit --authorize-network"
        )
    manifest_file, payload = read_regular_file(
        manifest_path,
        "standards source manifest",
        maximum_bytes=_MAX_MANIFEST_BYTES,
    )
    try:
        manifest = strict_loads(payload)
    except (TypeError, ValueError) as exc:
        raise StandardsMonitorError(
            "standards source manifest is invalid JSON"
        ) from exc
    _validate_manifest(manifest)
    output = resolve_unlinked_path(output_directory, "standards snapshot output")
    if output.exists():
        if not output.is_dir():
            raise StandardsMonitorError("standards snapshot output is not a directory")
        if any(output.iterdir()) and not overwrite:
            raise StandardsMonitorError(
                "standards snapshot output is not empty; use --overwrite"
            )
    else:
        output.mkdir(parents=True)
    allowed_hosts = set(manifest["allowed_hosts"])
    retrieve = fetcher or _fetch_https
    entries: list[dict[str, Any]] = []
    total_bytes = 0
    for source in manifest["sources"]:
        try:
            content, final_url, content_type = retrieve(
                source["url"], source["maximum_bytes"], allowed_hosts
            )
            total_bytes += len(content)
            if total_bytes > _MAX_TOTAL_BYTES:
                raise StandardsMonitorError("publisher snapshot total exceeds limit")
            digest = hashlib.sha256(content).hexdigest()
            status = "unchanged" if digest == source["baseline_sha256"] else "changed"
            semantic_diff = _semantic_diff_for_source(
                source, content, manifest_file.parent
            )
            snapshot = _write_quarantined_snapshot(
                output, source["id"], digest, content, overwrite=overwrite
            )
            entries.append(
                {
                    "id": source["id"],
                    "baseline_version": source["baseline_version"],
                    "requested_url": source["url"],
                    "final_url": final_url,
                    "publisher": source["publisher"],
                    "content_type": content_type,
                    "baseline_sha256": source["baseline_sha256"],
                    "observed_sha256": digest,
                    "bytes": len(content),
                    "status": status,
                    "snapshot": snapshot.relative_to(output).as_posix(),
                    "promotion": "not-required"
                    if status == "unchanged"
                    else "human-review-required",
                    "semantic_diff": semantic_diff,
                    "impact": source["impact"],
                }
            )
        except (OSError, StandardsMonitorError, HTTPError, URLError) as exc:
            entries.append(
                {
                    "id": source["id"],
                    "baseline_version": source["baseline_version"],
                    "requested_url": source["url"],
                    "final_url": None,
                    "publisher": source["publisher"],
                    "content_type": None,
                    "baseline_sha256": source["baseline_sha256"],
                    "observed_sha256": None,
                    "bytes": 0,
                    "status": "unavailable",
                    "snapshot": None,
                    "promotion": "blocked",
                    "semantic_diff": {"status": "unavailable"},
                    "impact": source["impact"],
                    "error": str(exc)[:2048],
                }
            )
    changed = sum(item["status"] == "changed" for item in entries)
    unavailable = sum(item["status"] == "unavailable" for item in entries)
    report: dict[str, Any] = {
        "schema_version": "1.0",
        "analysis": "standards-publisher-lifecycle-monitor",
        "manifest_path": str(manifest_file),
        "manifest_sha256": hashlib.sha256(payload).hexdigest(),
        "observed_at": datetime.now(UTC).isoformat(),
        "sources_assessed": len(entries),
        "sources_changed": changed,
        "sources_unavailable": unavailable,
        "decision": (
            "incomplete" if unavailable else "review-required" if changed else "current"
        ),
        "promotion_policy": {
            "automatic_promotion": False,
            "human_approval_required": True,
            "semantic_diff_required": True,
            "licensed_requirement_review_required": True,
        },
        "sources": entries,
        "claim_boundary": (
            "Publisher payloads are quarantined observations. A matching digest "
            "supports currency evidence; a changed payload is not a new normative "
            "baseline until semantic review and human approval are recorded."
        ),
    }
    report["review_artifact"] = {
        "title": "Standards lifecycle semantic review",
        "required_source_ids": [
            item["id"] for item in entries if item["status"] == "changed"
        ],
        "approval_status": "pending" if changed else "not-required",
        "required_approvals": ["standards-owner", "affected-control-owner"],
    }
    report["report_sha256"] = hashlib.sha256(canonical_bytes(report)).hexdigest()
    if signing_key_path is not None:
        report["signature"] = _sign_report(report, signing_key_path)
    _write_json_atomic(output / "standards-monitor-report.json", report, overwrite)
    return report


def verify_standards_monitor_report(
    report_path: Path,
    public_key_path: Path,
    *,
    report_sha256: str,
) -> dict[str, Any]:
    """Verify the transport digest, internal digest, and Ed25519 report signature."""
    if not _DIGEST.fullmatch(report_sha256):
        raise StandardsMonitorError("standards monitor report digest is invalid")
    report_file, payload = read_regular_file(
        report_path, "standards monitor report", maximum_bytes=_MAX_MANIFEST_BYTES
    )
    if hashlib.sha256(payload).hexdigest() != report_sha256:
        raise StandardsMonitorError("standards monitor report digest does not match")
    try:
        document = strict_loads(payload)
    except (TypeError, ValueError) as exc:
        raise StandardsMonitorError("standards monitor report is invalid JSON") from exc
    if not isinstance(document, dict) or document.get("schema_version") != "1.0":
        raise StandardsMonitorError("standards monitor report contract is invalid")
    signature = document.get("signature")
    if (
        not isinstance(signature, dict)
        or set(signature)
        != {
            "algorithm",
            "key_id",
            "signature",
            "signed_payload_sha256",
        }
        or signature.get("algorithm") != "Ed25519"
    ):
        raise StandardsMonitorError("standards monitor signature is missing or invalid")
    unsigned = dict(document)
    unsigned.pop("signature")
    signed_payload = canonical_bytes(unsigned)
    if hashlib.sha256(signed_payload).hexdigest() != signature.get(
        "signed_payload_sha256"
    ):
        raise StandardsMonitorError("signed payload digest does not match")
    internal = dict(unsigned)
    internal_digest = internal.pop("report_sha256", None)
    if hashlib.sha256(canonical_bytes(internal)).hexdigest() != internal_digest:
        raise StandardsMonitorError("standards monitor internal digest does not match")
    _, key_payload = read_regular_file(
        public_key_path, "standards monitor public key", maximum_bytes=64 * 1024
    )
    try:
        key = serialization.load_pem_public_key(key_payload)
    except (TypeError, ValueError) as exc:
        raise StandardsMonitorError("public key is not valid PEM") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise StandardsMonitorError("standards monitor requires an Ed25519 public key")
    raw_public = key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    key_id = hashlib.sha256(raw_public).hexdigest()
    if key_id != signature.get("key_id"):
        raise StandardsMonitorError(
            "standards monitor signing key identity does not match"
        )
    try:
        encoded_signature = signature.get("signature")
        if not isinstance(encoded_signature, str):
            raise ValueError("signature is not a string")
        key.verify(base64.b64decode(encoded_signature, validate=True), signed_payload)
    except (InvalidSignature, ValueError) as exc:
        raise StandardsMonitorError("standards monitor signature is invalid") from exc
    return {
        "schema_version": "1.0",
        "analysis": "standards-monitor-signature-verification",
        "report_path": str(report_file),
        "report_sha256": report_sha256,
        "key_id": key_id,
        "signature_valid": True,
        "internal_digest_valid": True,
        "decision": "verified",
    }


def _validate_manifest(value: object) -> None:
    if not isinstance(value, dict) or set(value) != {
        "schema_version",
        "allowed_hosts",
        "sources",
    }:
        raise StandardsMonitorError("standards source manifest contract is invalid")
    if value["schema_version"] != "1.0":
        raise StandardsMonitorError("unsupported standards source manifest version")
    hosts = value["allowed_hosts"]
    if not isinstance(hosts, list) or not 1 <= len(hosts) <= 128:
        raise StandardsMonitorError("allowed_hosts must be a non-empty bounded array")
    normalized_hosts: set[str] = set()
    for host in hosts:
        if not isinstance(host, str) or not _valid_hostname(host):
            raise StandardsMonitorError("allowed publisher host is invalid")
        normalized = host.lower().rstrip(".")
        if normalized in normalized_hosts:
            raise StandardsMonitorError("allowed publisher hosts must be unique")
        normalized_hosts.add(normalized)
    sources = value["sources"]
    if not isinstance(sources, list) or not 1 <= len(sources) <= 512:
        raise StandardsMonitorError("sources must be a non-empty bounded array")
    seen: set[str] = set()
    for source in sources:
        if not isinstance(source, dict) or set(source) != {
            "id",
            "baseline_version",
            "publisher",
            "url",
            "baseline_sha256",
            "maximum_bytes",
            "baseline_path",
            "media_type",
            "impact",
        }:
            raise StandardsMonitorError("publisher source contract is invalid")
        identifier = source["id"]
        if (
            not isinstance(identifier, str)
            or not _IDENTIFIER.fullmatch(identifier)
            or identifier in seen
        ):
            raise StandardsMonitorError("publisher source id is invalid or duplicated")
        seen.add(identifier)
        for field in ("baseline_version", "publisher"):
            if not isinstance(source[field], str) or not 1 <= len(source[field]) <= 256:
                raise StandardsMonitorError(f"publisher source {field} is invalid")
        _validate_url(source["url"], normalized_hosts)
        if not isinstance(source["baseline_sha256"], str) or not _DIGEST.fullmatch(
            source["baseline_sha256"]
        ):
            raise StandardsMonitorError("publisher baseline digest is invalid")
        maximum = source["maximum_bytes"]
        if (
            not isinstance(maximum, int)
            or isinstance(maximum, bool)
            or not 1 <= maximum <= _MAX_SOURCE_BYTES
        ):
            raise StandardsMonitorError("publisher source maximum_bytes is invalid")
        if not isinstance(source["baseline_path"], str) or not source["baseline_path"]:
            raise StandardsMonitorError("publisher baseline_path is invalid")
        if source["media_type"] not in {
            "text/plain",
            "text/html",
            "application/json",
            "application/xml",
            "text/xml",
            "application/pdf",
        }:
            raise StandardsMonitorError("publisher media_type is unsupported")
        impact = source["impact"]
        if not isinstance(impact, dict) or set(impact) != {
            "profiles",
            "controls",
            "benchmarks",
        }:
            raise StandardsMonitorError("publisher source impact contract is invalid")
        for items in impact.values():
            if (
                not isinstance(items, list)
                or len(items) > 256
                or not all(
                    isinstance(item, str) and 1 <= len(item) <= 128 for item in items
                )
                or len(items) != len(set(items))
            ):
                raise StandardsMonitorError(
                    "publisher source impact values are invalid"
                )


def _validate_url(value: object, allowed_hosts: set[str]) -> str:
    if not isinstance(value, str) or len(value) > 4096:
        raise StandardsMonitorError("publisher URL is invalid")
    parsed = urlsplit(value)
    host = (parsed.hostname or "").lower().rstrip(".")
    if (
        parsed.scheme != "https"
        or not host
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or parsed.port not in {None, 443}
        or host not in allowed_hosts
    ):
        raise StandardsMonitorError("publisher URL violates the HTTPS host policy")
    return host


def _valid_hostname(value: str) -> bool:
    host = value.lower().rstrip(".")
    if not host or len(host) > 253 or host == "localhost":
        return False
    return all(
        re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
        for label in host.split(".")
    )


def _reject_non_public_host(host: str) -> None:
    try:
        addresses = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise StandardsMonitorError(
            f"publisher host cannot be resolved: {host}"
        ) from exc
    if not addresses:
        raise StandardsMonitorError(f"publisher host has no addresses: {host}")
    for address in addresses:
        ip = ipaddress.ip_address(address[4][0])
        if not ip.is_global:
            raise StandardsMonitorError(
                f"publisher host resolves to a non-public address: {host}"
            )


class _RestrictedRedirectHandler(HTTPRedirectHandler):
    def __init__(self, allowed_hosts: set[str]) -> None:
        super().__init__()
        self.allowed_hosts = allowed_hosts

    def redirect_request(
        self,
        req: Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> Request | None:
        target = urljoin(req.full_url, newurl)
        host = _validate_url(target, self.allowed_hosts)
        _reject_non_public_host(host)
        return super().redirect_request(req, fp, code, msg, headers, target)


def _fetch_https(
    url: str, maximum_bytes: int, allowed_hosts: set[str]
) -> tuple[bytes, str, str]:
    normalized_hosts = {item.lower().rstrip(".") for item in allowed_hosts}
    host = _validate_url(url, normalized_hosts)
    _reject_non_public_host(host)
    context = ssl.create_default_context()
    opener = build_opener(
        HTTPSHandler(context=context), _RestrictedRedirectHandler(normalized_hosts)
    )
    request = Request(  # noqa: S310 -- validated HTTPS publisher URL only
        url,
        headers={
            "Accept": "application/json, application/xml, text/html, text/plain, application/pdf;q=0.9, */*;q=0.1",
            "User-Agent": "py-security-suite-standards-monitor/1.0",
        },
        method="GET",
    )
    with opener.open(request, timeout=20) as response:  # noqa: S310 -- strict HTTPS/host/IP policy above
        final_url = response.geturl()
        final_host = _validate_url(final_url, normalized_hosts)
        _reject_non_public_host(final_host)
        declared = response.headers.get("Content-Length")
        if declared is not None and int(declared) > maximum_bytes:
            raise StandardsMonitorError(
                "publisher response exceeds declared size limit"
            )
        payload = response.read(maximum_bytes + 1)
        if len(payload) > maximum_bytes:
            raise StandardsMonitorError("publisher response exceeds size limit")
        return payload, final_url, response.headers.get_content_type()


def _write_quarantined_snapshot(
    output: Path, identifier: str, digest: str, payload: bytes, *, overwrite: bool
) -> Path:
    quarantine = output / "quarantine" / identifier
    quarantine.mkdir(parents=True, exist_ok=True)
    destination = quarantine / f"{digest}.snapshot"
    if destination.exists():
        _, current = read_regular_file(
            destination,
            "existing publisher snapshot",
            maximum_bytes=_MAX_SOURCE_BYTES,
            boundary=output,
        )
        if hashlib.sha256(current).hexdigest() == digest:
            return destination
        if not overwrite:
            raise StandardsMonitorError("existing publisher snapshot conflicts")
    _write_bytes_atomic(destination, payload, overwrite=True)
    return destination


def _semantic_diff_for_source(
    source: dict[str, Any], observed: bytes, manifest_directory: Path
) -> dict[str, Any]:
    baseline = resolve_regular_file(
        manifest_directory / source["baseline_path"],
        f"{source['id']} semantic baseline",
    )
    _, baseline_payload = read_regular_file(
        baseline,
        f"{source['id']} semantic baseline",
        maximum_bytes=source["maximum_bytes"],
        boundary=manifest_directory,
    )
    if hashlib.sha256(baseline_payload).hexdigest() != source["baseline_sha256"]:
        raise StandardsMonitorError(
            f"{source['id']} semantic baseline digest does not match manifest"
        )
    before = _extract_semantic_sections(baseline_payload, source["media_type"])
    after = _extract_semantic_sections(observed, source["media_type"])
    before_lines = [f"{key}\t{value}" for key, value in sorted(before.items())]
    after_lines = [f"{key}\t{value}" for key, value in sorted(after.items())]
    added = sorted(set(after) - set(before))
    removed = sorted(set(before) - set(after))
    modified = sorted(
        key for key in set(before) & set(after) if before[key] != after[key]
    )
    changed_text = [after[key] for key in [*added, *modified]] + [
        before[key] for key in [*removed, *modified]
    ]
    normative = sorted(
        {
            word
            for text_value in changed_text
            for word in re.findall(
                r"\b(?:MUST(?: NOT)?|SHALL(?: NOT)?|SHOULD(?: NOT)?|MAY|REQUIRED|PROHIBITED)\b",
                text_value.upper(),
            )
        }
    )
    lifecycle_terms = sorted(
        {
            word.casefold()
            for text_value in changed_text
            for word in re.findall(
                r"\b(?:withdrawn|superseded|deprecated|replaced|amended|corrigendum)\b",
                text_value,
                flags=re.IGNORECASE,
            )
        }
    )
    similarity = difflib.SequenceMatcher(
        None, "\n".join(before_lines), "\n".join(after_lines), autojunk=False
    ).ratio()
    return {
        "status": "unchanged" if before == after else "review-required",
        "parser": source["media_type"],
        "sections_before": len(before),
        "sections_after": len(after),
        "added_section_ids": added[:512],
        "removed_section_ids": removed[:512],
        "modified_section_ids": modified[:512],
        "normative_terms_changed": normative,
        "lifecycle_terms_changed": lifecycle_terms,
        "semantic_similarity": round(similarity, 12),
        "change_class": (
            "lifecycle"
            if lifecycle_terms
            else "normative"
            if normative
            else "editorial-or-informative"
        ),
    }


def _extract_semantic_sections(payload: bytes, media_type: str) -> dict[str, str]:
    if media_type == "application/json":
        try:
            value = strict_loads(payload)
        except (TypeError, ValueError) as exc:
            raise StandardsMonitorError(
                "publisher JSON cannot be parsed semantically"
            ) from exc
        sections: dict[str, str] = {}
        _flatten_json(value, "$", sections)
        return sections
    if media_type in {"application/xml", "text/xml"}:
        try:
            root = ElementTree.fromstring(payload)
        except (TypeError, ValueError, ElementTree.ParseError) as exc:
            raise StandardsMonitorError(
                "publisher XML cannot be parsed semantically"
            ) from exc
        sections = {}
        for index, element in enumerate(root.iter()):
            identifier = (
                element.attrib.get("id")
                or element.attrib.get("name")
                or f"{element.tag}[{index}]"
            )
            text_value = _normalize_text(" ".join(element.itertext()))
            if text_value:
                sections[str(identifier)] = text_value
        return sections
    if media_type == "text/html":
        parser = _SectionHTMLParser()
        try:
            parser.feed(payload.decode("utf-8", errors="strict"))
            parser.close()
        except (UnicodeError, ValueError) as exc:
            raise StandardsMonitorError(
                "publisher HTML cannot be parsed semantically"
            ) from exc
        return parser.sections()
    if media_type == "application/pdf":
        try:
            reader = PdfReader(io.BytesIO(payload), strict=True)
            return {
                f"page-{index + 1}": _normalize_text(page.extract_text() or "")
                for index, page in enumerate(reader.pages)
            }
        except Exception as exc:  # pypdf exposes multiple parser-specific exceptions
            raise StandardsMonitorError(
                "publisher PDF cannot be parsed semantically"
            ) from exc
    try:
        text_value = payload.decode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise StandardsMonitorError("publisher text is not UTF-8") from exc
    return {
        f"line-{index + 1}": normalized
        for index, line in enumerate(text_value.splitlines())
        if (normalized := _normalize_text(line))
    }


def _flatten_json(value: object, path: str, output: dict[str, str]) -> None:
    if isinstance(value, dict):
        for key in sorted(value):
            _flatten_json(value[key], f"{path}.{key}", output)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _flatten_json(item, f"{path}[{index}]", output)
    else:
        output[path] = json.dumps(value, ensure_ascii=False, sort_keys=True)


def _normalize_text(value: str) -> str:
    return " ".join(value.split())


class _SectionHTMLParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._current = "document"
        self._chunks: dict[str, list[str]] = {self._current: []}
        self._heading: str | None = None
        self._heading_chunks: list[str] = []
        self._counter = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = dict(attrs)
        if tag in {"section", "article"}:
            self._counter += 1
            self._current = attributes.get("id") or f"section-{self._counter}"
            self._chunks.setdefault(self._current, [])
        if tag in {"h1", "h2", "h3", "h4", "h5", "h6"}:
            self._heading = attributes.get("id")
            self._heading_chunks = []

    def handle_endtag(self, tag: str) -> None:
        if tag in {"h1", "h2", "h3", "h4", "h5", "h6"}:
            heading = _normalize_text(" ".join(self._heading_chunks))
            if heading:
                self._counter += 1
                self._current = (
                    self._heading or f"heading-{self._counter}-{heading[:48]}"
                )
                self._chunks.setdefault(self._current, []).extend(self._heading_chunks)
            self._heading = None
            self._heading_chunks = []

    def handle_data(self, data: str) -> None:
        if self._heading is not None or self._heading_chunks:
            self._heading_chunks.append(data)
        self._chunks.setdefault(self._current, []).append(data)

    def sections(self) -> dict[str, str]:
        return {
            key: normalized
            for key, chunks in self._chunks.items()
            if (normalized := _normalize_text(" ".join(chunks)))
        }


def _write_json_atomic(path: Path, value: dict[str, Any], overwrite: bool) -> None:
    payload = (
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False).encode("utf-8")
        + b"\n"
    )
    _write_bytes_atomic(path, payload, overwrite=overwrite)


def _write_bytes_atomic(path: Path, payload: bytes, *, overwrite: bool) -> None:
    destination = resolve_unlinked_path(path, "standards monitor output")
    if destination.exists() and not overwrite:
        raise StandardsMonitorError(f"output already exists: {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with hold_parent_directory(destination, "standards monitor output") as held:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent
        )
        temporary = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            if destination.exists():
                destination.unlink()
            held.rename(temporary, destination)
        finally:
            if temporary.exists():
                temporary.unlink()


def _sign_report(report: dict[str, Any], key_path: Path) -> dict[str, str]:
    _, payload = read_regular_file(
        key_path, "standards monitor signing key", maximum_bytes=64 * 1024
    )
    try:
        key = serialization.load_pem_private_key(payload, password=None)
    except (TypeError, ValueError) as exc:
        raise StandardsMonitorError(
            "signing key is not an unencrypted PEM key"
        ) from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise StandardsMonitorError("standards monitor requires an Ed25519 signing key")
    signed = canonical_bytes(report)
    public = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return {
        "algorithm": "Ed25519",
        "key_id": hashlib.sha256(public).hexdigest(),
        "signature": base64.b64encode(key.sign(signed)).decode("ascii"),
        "signed_payload_sha256": hashlib.sha256(signed).hexdigest(),
    }
