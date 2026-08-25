from __future__ import annotations

import argparse
import hashlib
import os
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Any

try:
    from companion.deep_qualification import verify_area_receipt
    from companion.strict_json import dumps as strict_dumps
    from companion.strict_json import loads as strict_loads
except ModuleNotFoundError:
    from deep_qualification import verify_area_receipt  # type: ignore[import-not-found,no-redef]
    from strict_json import dumps as strict_dumps  # type: ignore[import-not-found,no-redef]
    from strict_json import loads as strict_loads  # type: ignore[import-not-found,no-redef]


_MANDATORY_MANIFEST_QUERIES = (
    "SELECT n.nspname, c.relname, c.relkind, c.relrowsecurity, c.relforcerowsecurity FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname NOT LIKE 'pg_%' AND n.nspname <> 'information_schema' ORDER BY 1,2,3",
    "SELECT n.nspname, c.relname, a.attname, format_type(a.atttypid,a.atttypmod), a.attnotnull FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE a.attnum>0 AND NOT a.attisdropped AND n.nspname NOT LIKE 'pg_%' ORDER BY 1,2,a.attnum",
    "SELECT schemaname, tablename, policyname, permissive, roles, cmd, qual, with_check FROM pg_policies ORDER BY 1,2,3",
    "SELECT grantee, table_schema, table_name, privilege_type, is_grantable FROM information_schema.role_table_grants ORDER BY 1,2,3,4",
    "SELECT extname, extversion FROM pg_extension ORDER BY 1",
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run an explicit migration/backup/restore drill against disposable PostgreSQL databases."
    )
    parser.add_argument("--contract", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--allow-destructive-disposable-drill", action="store_true")
    args = parser.parse_args(argv)
    if not args.allow_destructive_disposable_drill:
        raise ValueError("the destructive disposable drill requires explicit opt-in")
    _write(args.output, execute(_read(args.contract), context=args.contract))
    return 0


def execute(value: object, *, context: Path) -> dict[str, Any]:
    required = {
        "schema_version",
        "service_env",
        "database_prefix",
        "migration_file",
        "migration_sha256",
        "executables",
        "audit_query",
        "expected_audit_marker",
    }
    v2_extra = {
        "cluster_identity_query",
        "expected_cluster_identity_sha256",
        "manifest_queries",
    }
    v3_extra = v2_extra | {
        "qualification_receipt_file",
        "qualification_receipt_sha256",
    }
    if not isinstance(value, dict):
        raise TypeError("database drill must be an object")
    version = value.get("schema_version")
    if (
        (version == "2.0" and set(value) != required | v2_extra)
        or (version == "3.0" and set(value) != required | v3_extra)
        or version not in {"2.0", "3.0"}
    ):
        raise ValueError("database drill fields do not match a supported contract")
    service_env = _environment_name(value.get("service_env"))
    service = os.environ.get(service_env)
    if (
        not service
        or len(service) > 200
        or not re.fullmatch(r"[A-Za-z0-9_.-]+", service)
    ):
        raise ValueError("PostgreSQL service name is unavailable or invalid")
    prefix = str(value.get("database_prefix") or "")
    if not re.fullmatch(r"pysec_disposable_[a-z0-9_]{1,40}", prefix):
        raise ValueError("database drill prefix must use pysec_disposable_ namespace")
    primary, restored = f"{prefix}_migration", f"{prefix}_restore"
    migration = _pinned_sibling(
        context, value.get("migration_file"), value.get("migration_sha256"), "migration"
    )
    executables = _executables(value.get("executables"))
    audit_query = str(value.get("audit_query") or "").strip()
    if not re.fullmatch(r"(?is)select\b[^;]{1,2000}", audit_query):
        raise ValueError("database drill audit query must be one SELECT statement")
    marker = str(value.get("expected_audit_marker") or "")
    if (
        not marker
        or len(marker) > 200
        or any(ord(character) < 32 for character in marker)
    ):
        raise ValueError("database drill audit marker is invalid")
    environment = os.environ.copy()
    environment.update(
        {
            "PGSERVICE": service,
            "PGCONNECT_TIMEOUT": "10",
            "PGOPTIONS": "-c row_security=off -c statement_timeout=10000 -c lock_timeout=2000",
        }
    )
    manifest_queries = [audit_query]
    if version in {"2.0", "3.0"}:
        identity_query = _select_query(
            value.get("cluster_identity_query"), "cluster identity query"
        )
        expected_identity = str(value.get("expected_cluster_identity_sha256") or "")
        if os.environ.get("PYSEC_DB_CLUSTER_IDENTITY_SHA256", "") != expected_identity:
            raise ValueError("database drill cluster identity is not deployment-pinned")
        identity = _run(
            [
                executables["psql"],
                "--dbname",
                "postgres",
                "--no-align",
                "--tuples-only",
                "--command",
                identity_query,
            ],
            environment,
            capture=True,
        )
        if (
            len(expected_identity) != 64
            or hashlib.sha256(identity.encode()).hexdigest() != expected_identity
        ):
            raise ValueError(
                "database drill target is not the approved disposable cluster"
            )
        manifest_value = value.get("manifest_queries")
        if not isinstance(manifest_value, list) or not 1 <= len(manifest_value) <= 64:
            raise ValueError("database drill manifest queries are invalid")
        manifest_queries = [
            *_MANDATORY_MANIFEST_QUERIES,
            *[_select_query(item, "manifest query") for item in manifest_value],
        ]
    if version == "3.0":
        verify_area_receipt(
            context,
            area="postgresql",
            filename=value.get("qualification_receipt_file"),
            sha256=value.get("qualification_receipt_sha256"),
            target=value,
        )
    created: list[str] = []
    with tempfile.TemporaryDirectory(prefix="pysec-pg-drill-") as directory:
        dump = Path(directory) / "drill.dump"
        primary_manifest = ""
        try:
            for database in (primary, restored):
                _run(
                    [executables["createdb"], "--maintenance-db=postgres", database],
                    environment,
                )
                created.append(database)
                if database == primary:
                    _run(
                        [
                            executables["psql"],
                            "--dbname",
                            database,
                            "--set",
                            "ON_ERROR_STOP=1",
                            "--single-transaction",
                            "--file",
                            str(migration),
                        ],
                        environment,
                    )
                    primary_manifest = _database_manifest(
                        executables["psql"], database, manifest_queries, environment
                    )
                    _run(
                        [
                            executables["pg_dump"],
                            "--dbname",
                            database,
                            "--format=custom",
                            "--file",
                            str(dump),
                        ],
                        environment,
                    )
                else:
                    _run(
                        [
                            executables["pg_restore"],
                            "--dbname",
                            database,
                            "--exit-on-error",
                            "--single-transaction",
                            str(dump),
                        ],
                        environment,
                    )
            audit = _run(
                [
                    executables["psql"],
                    "--dbname",
                    restored,
                    "--no-align",
                    "--tuples-only",
                    "--command",
                    audit_query,
                ],
                environment,
                capture=True,
            )
            if marker not in audit:
                raise ValueError("database restore audit marker was not observed")
            restored_manifest = _database_manifest(
                executables["psql"], restored, manifest_queries, environment
            )
            if version == "2.0" and restored_manifest != primary_manifest:
                raise ValueError("database restore manifest does not match the source")
        finally:
            cleanup_errors: list[Exception] = []
            for database in reversed(created):
                try:
                    _run(
                        [
                            executables["dropdb"],
                            "--maintenance-db=postgres",
                            "--if-exists",
                            "--force",
                            database,
                        ],
                        environment,
                    )
                except (OSError, ValueError) as exc:
                    cleanup_errors.append(exc)
            remaining = _run(
                [
                    executables["psql"],
                    "--dbname",
                    "postgres",
                    "--no-align",
                    "--tuples-only",
                    "--command",
                    "SELECT count(*) FROM pg_database WHERE datname IN ('"  # noqa: S608 -- names are regex-constrained above.
                    + primary
                    + "','"
                    + restored
                    + "')",
                ],
                environment,
                capture=True,
            ).strip()
            if cleanup_errors or remaining != "0":
                raise ValueError("database drill cleanup did not remove every database")
    return {
        "schema_version": "1.0",
        "status": "completed",
        "migration_applied": True,
        "backup_created": True,
        "restore_verified": True,
        "audit_marker_observed": True,
        "disposable_databases_removed": True,
        "migration_sha256": hashlib.sha256(migration.read_bytes()).hexdigest(),
        "manifest_sha256": hashlib.sha256(primary_manifest.encode()).hexdigest(),
        "recovery_qualification": version == "3.0",
    }


def _executables(value: object) -> dict[str, str]:
    names = {"createdb", "dropdb", "psql", "pg_dump", "pg_restore"}
    if not isinstance(value, dict) or set(value) != names:
        raise ValueError("database drill executable records are incomplete")
    result: dict[str, str] = {}
    for name, record in value.items():
        if not isinstance(record, dict) or set(record) != {"path", "sha256"}:
            raise ValueError("database drill executable record is invalid")
        path = Path(str(record.get("path") or "")).expanduser().resolve()
        digest = str(record.get("sha256") or "")
        if (
            path.is_symlink()
            or not path.is_file()
            or hashlib.sha256(path.read_bytes()).hexdigest() != digest
        ):
            raise ValueError(f"database drill executable is not pinned: {name}")
        result[name] = str(path)
    return result


def _run(
    command: list[str],
    environment: dict[str, str],
    *,
    capture: bool = False,
    capture_limit: int = 4096,
) -> str:
    completed = subprocess.run(  # noqa: S603 - executable paths are SHA-256 pinned.
        command,
        check=False,
        shell=False,
        env=environment,
        capture_output=True,
        text=True,
        timeout=120,
    )
    if completed.returncode != 0:
        raise ValueError("database drill command failed")
    if capture and len(completed.stdout.encode()) > capture_limit:
        raise ValueError("database drill command output exceeds its bound")
    return completed.stdout if capture else ""


def _select_query(value: object, label: str) -> str:
    query = str(value or "").strip()
    if not re.fullmatch(r"(?is)select\b[^;]{1,2000}", query):
        raise ValueError(f"database drill {label} must be one SELECT statement")
    return query


def _database_manifest(
    psql: str,
    database: str,
    queries: list[str],
    environment: dict[str, str],
) -> str:
    parts = [
        _run(
            [
                psql,
                "--dbname",
                database,
                "--no-align",
                "--tuples-only",
                "--command",
                query,
            ],
            environment,
            capture=True,
            capture_limit=4 * 1024 * 1024,
        )
        for query in queries
    ]
    return hashlib.sha256("\x1e".join(parts).encode()).hexdigest()


def _pinned_sibling(context: Path, name: object, digest: object, label: str) -> Path:
    filename = str(name or "")
    expected = str(digest or "")
    if not filename or Path(filename).name != filename:
        raise ValueError(f"database drill {label} must be a sibling file")
    path = context.resolve().parent / filename
    if (
        path.is_symlink()
        or not path.is_file()
        or path.stat().st_size > 64 * 1024 * 1024
    ):
        raise ValueError(f"database drill {label} must be bounded")
    if len(expected) != 64 or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
        raise ValueError(f"database drill {label} digest does not match")
    return path


def _environment_name(value: object) -> str:
    result = str(value or "")
    if (
        not result
        or len(result) > 100
        or result.upper() != result
        or not result.replace("_", "").isalnum()
    ):
        raise ValueError("database drill service_env is invalid")
    return result


def _read(path: Path) -> object:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 1024 * 1024:
        raise ValueError("database drill contract must be a bounded regular file")
    return strict_loads(path.read_bytes())


def _write(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = (strict_dumps(value, indent=2) + "\n").encode()
    descriptor, name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(name)
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
