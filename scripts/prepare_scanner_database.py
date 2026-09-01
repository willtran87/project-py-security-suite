from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import ssl
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import HTTPSHandler, Request, build_opener


_DEFAULT_URL = "https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip"
_ALLOWED_HOST = "osv-vulnerabilities.storage.googleapis.com"
_MAXIMUM_BYTES = 512 * 1024 * 1024
_DIGEST = re.compile(r"^[0-9a-f]{64}$")


class ScannerDatabasePreparationError(ValueError):
    """Raised when a scanner database cannot be acquired and sealed safely."""


def prepare_database(
    output_directory: Path,
    *,
    url: str = _DEFAULT_URL,
    expected_sha256: str | None = None,
    maximum_bytes: int = _MAXIMUM_BYTES,
) -> dict[str, object]:
    """Acquire one authorized OSV snapshot and bind the exact bytes by digest."""

    parsed = urlsplit(url)
    if (
        parsed.scheme != "https"
        or parsed.hostname != _ALLOWED_HOST
        or parsed.username is not None
        or parsed.password is not None
        or parsed.port not in (None, 443)
        or parsed.query
        or parsed.fragment
        or parsed.path != "/PyPI/all.zip"
    ):
        raise ScannerDatabasePreparationError(
            "OSV database URL is outside the authorized HTTPS publisher endpoint"
        )
    if expected_sha256 is not None and not _DIGEST.fullmatch(expected_sha256):
        raise ScannerDatabasePreparationError("expected database digest is invalid")
    if maximum_bytes < 1 or maximum_bytes > _MAXIMUM_BYTES:
        raise ScannerDatabasePreparationError("database byte limit is invalid")

    output_directory.mkdir(parents=True, exist_ok=True)
    if output_directory.is_symlink():
        raise ScannerDatabasePreparationError("database output must not be a symlink")
    destination = output_directory / "osv-pypi-all.zip"
    metadata_path = output_directory / "metadata.json"
    digest_path = output_directory / "osv-pypi-all.zip.sha256"
    if any(path.exists() for path in (destination, metadata_path, digest_path)):
        raise ScannerDatabasePreparationError(
            "database output already exists; use a fresh preparation directory"
        )

    request = Request(  # noqa: S310 - URL is restricted above.
        url,
        headers={"User-Agent": "py-security-suite-database-preparer/1"},
        method="GET",
    )
    opener = build_opener(HTTPSHandler(context=ssl.create_default_context()))
    digest = hashlib.sha256()
    size = 0
    temporary: Path | None = None
    try:
        descriptor, raw_temporary = tempfile.mkstemp(
            prefix=".osv-pypi-", suffix=".part", dir=output_directory
        )
        temporary = Path(raw_temporary)
        with (
            os.fdopen(descriptor, "wb") as output,
            opener.open(  # noqa: S310
                request, timeout=60
            ) as response,
        ):
            final = urlsplit(response.geturl())
            if (
                final.scheme != "https"
                or final.hostname != _ALLOWED_HOST
                or final.path != "/PyPI/all.zip"
                or final.query
                or final.fragment
            ):
                raise ScannerDatabasePreparationError(
                    "OSV database redirect left the authorized publisher endpoint"
                )
            while chunk := response.read(1024 * 1024):
                size += len(chunk)
                if size > maximum_bytes:
                    raise ScannerDatabasePreparationError(
                        "OSV database exceeds the configured byte limit"
                    )
                digest.update(chunk)
                output.write(chunk)
            output.flush()
            os.fsync(output.fileno())
        observed = digest.hexdigest()
        if expected_sha256 is not None and observed != expected_sha256:
            raise ScannerDatabasePreparationError(
                "OSV database does not match the operator-supplied digest"
            )
        os.replace(temporary, destination)
        temporary = None
        metadata: dict[str, object] = {
            "schema_version": "1.0",
            "kind": "osv-pypi-database-snapshot",
            "source_url": url,
            "publisher_host": _ALLOWED_HOST,
            "acquired_at": datetime.now(UTC).isoformat(),
            "sha256": observed,
            "bytes": size,
            "maximum_bytes": maximum_bytes,
            "build_input": destination.name,
            "claim_boundary": (
                "This receipt binds the exact TLS-acquired snapshot bytes used by "
                "the image build; it does not assert publisher signature authority."
            ),
        }
        _write_new(metadata_path, json.dumps(metadata, indent=2, sort_keys=True) + "\n")
        _write_new(digest_path, f"{observed}  {destination.name}\n")
        return metadata
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def _write_new(path: Path, value: str) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(value)
        handle.flush()
        os.fsync(handle.fileno())


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Acquire and seal the exact OSV PyPI database used by a build."
    )
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--expected-sha256")
    arguments = parser.parse_args()
    metadata = prepare_database(
        arguments.output,
        expected_sha256=arguments.expected_sha256,
    )
    print(json.dumps(metadata, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
