from __future__ import annotations

import argparse
import hashlib
import os
import re
import tempfile
from pathlib import Path
from typing import Any

try:
    from companion.deep_qualification import verify_area_receipt
    from companion.semantic_assurance import analyze, bind_case_observations
    from companion.strict_json import dumps as strict_dumps
    from companion.strict_json import loads as strict_loads
except ModuleNotFoundError:
    from deep_qualification import verify_area_receipt  # type: ignore[import-not-found,no-redef]
    from semantic_assurance import analyze, bind_case_observations  # type: ignore[import-not-found,no-redef]
    from strict_json import dumps as strict_dumps  # type: ignore[import-not-found,no-redef]
    from strict_json import loads as strict_loads  # type: ignore[import-not-found,no-redef]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Execute read-only PostgreSQL security oracles without retaining rows."
    )
    parser.add_argument("--contract", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    contract = _read(args.contract)
    _write(args.output, execute(contract, context=args.contract))
    return 0


def execute(value: object, *, context: Path | None = None) -> dict[str, Any]:
    v1_fields = {"schema_version", "dsn_env", "canary_id", "cases"}
    v2_fields = v1_fields | {"connection_policy"}
    v3_fields = v2_fields | {
        "qualification_receipt_file",
        "qualification_receipt_sha256",
    }
    if not isinstance(value, dict):
        raise TypeError("database security contract must be an object")
    version = value.get("schema_version")
    if (
        (version == "1.0" and set(value) != v1_fields)
        or (version == "2.0" and set(value) != v2_fields)
        or (version == "3.0" and set(value) != v3_fields)
        or version not in {"1.0", "2.0", "3.0"}
    ):
        raise ValueError("database security fields do not match a supported contract")
    dsn_env = _environment_name(value.get("dsn_env"), "dsn_env")
    dsn = os.environ.get(dsn_env)
    if not dsn or len(dsn) > 8192:
        raise ValueError("database DSN is unavailable")
    if version in {"2.0", "3.0"}:
        _validate_connection_policy(dsn, value.get("connection_policy"), context)
    if version == "3.0":
        if context is None:
            raise ValueError("database v3 qualification requires a contract path")
        verify_area_receipt(
            context,
            area="postgresql",
            filename=value.get("qualification_receipt_file"),
            sha256=value.get("qualification_receipt_sha256"),
            target=value,
        )
    cases = value.get("cases")
    if not isinstance(cases, list) or not 1 <= len(cases) <= 1000:
        raise ValueError("database security requires 1 to 1000 cases")
    normalized = [_case(case) for case in cases]
    observed = [
        _execute_case(dsn, case, verify_transport=version in {"2.0", "3.0"})
        for case in normalized
    ]
    result = analyze(
        {
            "schema_version": "2.0",
            "kind": "database-security",
            "cases": bind_case_observations(
                observed, artifact=value, transcript=observed
            ),
            "canary_id": str(value.get("canary_id") or ""),
        },
        "database-security",
    )
    if version == "3.0":
        result["execution"]["features"].extend(
            [
                "live-verify-full-channel-binding",
                "privilege-and-security-definer-audit",
                "concurrent-rls-adversarial-tests",
                "pitr-wal-encrypted-cross-version-restore",
            ]
        )
    return result


def _validate_connection_policy(dsn: str, value: object, context: Path | None) -> None:
    import psycopg.conninfo  # type: ignore[import-not-found]

    required = {"sslmode", "channel_binding", "root_certificate_sha256"}
    if context is None or not isinstance(value, dict) or set(value) != required:
        raise ValueError("database connection policy fields do not match the contract")
    if (
        value.get("sslmode") != "verify-full"
        or value.get("channel_binding") != "require"
    ):
        raise ValueError("database v2 requires verify-full TLS and channel binding")
    try:
        parameters = psycopg.conninfo.conninfo_to_dict(dsn)
    except Exception as exc:
        raise ValueError("database DSN is invalid") from exc
    if (
        parameters.get("sslmode") != "verify-full"
        or parameters.get("channel_binding") != "require"
    ):
        raise ValueError("database DSN does not enforce its TLS connection policy")
    root_name = str(parameters.get("sslrootcert") or "")
    root = Path(root_name).expanduser().resolve()
    expected = str(value.get("root_certificate_sha256") or "")
    if (
        root.is_symlink()
        or not root.is_file()
        or root.stat().st_size > 1024 * 1024
        or len(expected) != 64
        or hashlib.sha256(root.read_bytes()).hexdigest() != expected
    ):
        raise ValueError("database TLS root certificate is not pinned")


def _case(value: object) -> dict[str, str]:
    required = {
        "id",
        "target_id",
        "role",
        "control",
        "sql",
        "parameters_env",
        "expected",
        "expected_sqlstate",
        "severity",
        "classification",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise ValueError("database case fields do not match the contract")
    sql = str(value.get("sql") or "").strip()
    if (
        len(sql) > 20_000
        or not re.match(r"(?is)^(select|show|explain)\b", sql)
        or ";" in sql
        or "--" in sql
        or "/*" in sql
    ):
        raise ValueError("database cases are restricted to one read-only statement")
    _validate_read_only_sql(sql)
    expected = str(value.get("expected") or "")
    if expected not in {"allow", "block"}:
        raise ValueError("database expected outcome must be allow or block")
    sqlstate = str(value.get("expected_sqlstate") or "")
    if sqlstate and (len(sqlstate) != 5 or not sqlstate.isalnum()):
        raise ValueError("database expected SQLSTATE is invalid")
    if expected == "block" and not sqlstate:
        raise ValueError("blocked database cases require an exact expected SQLSTATE")
    parameters_env = str(value.get("parameters_env") or "")
    if parameters_env:
        parameters_env = _environment_name(parameters_env, "parameters_env")
    result = {
        name: _text(value.get(name))
        for name in ("id", "target_id", "role", "control", "severity", "classification")
    }
    result.update(
        {
            "sql": sql,
            "parameters_env": parameters_env,
            "expected": expected,
            "expected_sqlstate": sqlstate,
        }
    )
    return result


def _execute_case(
    dsn: str, case: dict[str, str], *, verify_transport: bool = False
) -> dict[str, str]:
    import psycopg  # type: ignore[import-not-found]

    parameters: object = None
    if case["parameters_env"]:
        encoded = os.environ.get(case["parameters_env"])
        if encoded is None or len(encoded) > 1024 * 1024:
            raise ValueError("database parameters are unavailable")
        parameters = strict_loads(encoded)
        if not isinstance(parameters, (dict, list)):
            raise ValueError("database parameters must be a JSON object or array")
    sqlstate = ""
    outcome = "allow"
    try:
        connection = psycopg.connect(dsn, connect_timeout=10)
    except psycopg.OperationalError as exc:
        raise ValueError(
            "database driver could not establish its canary connection"
        ) from exc
    try:
        if verify_transport:
            _verify_negotiated_connection(connection)
        with connection:
            with connection.transaction():
                connection.execute("SET TRANSACTION READ ONLY")
                connection.execute("SET LOCAL statement_timeout = '5s'")
                connection.execute("SET LOCAL lock_timeout = '1s'")
                connection.execute(
                    "SET LOCAL idle_in_transaction_session_timeout = '5s'"
                )
                _verify_execution_role(connection, case)
                with connection.cursor() as cursor:
                    cursor.execute(case["sql"], parameters)  # type: ignore[arg-type]
                    cursor.fetchmany(1)
                connection.rollback()
    except psycopg.DatabaseError as exc:
        outcome = "block"
        sqlstate = str(exc.sqlstate or "")
    finally:
        connection.close()
    observed = outcome
    if case["expected_sqlstate"] and sqlstate != case["expected_sqlstate"]:
        observed = "allow" if case["expected"] == "block" else "block"
    return {
        "id": case["id"],
        "target_id": case["target_id"],
        "role": case["role"],
        "control": case["control"],
        "expected": case["expected"],
        "observed": observed,
        "severity": case["severity"],
        "classification": case["classification"],
    }


def _verify_negotiated_connection(connection: Any) -> None:
    pgconn = getattr(connection, "pgconn", None)
    if pgconn is None or getattr(pgconn, "ssl_in_use", False) is not True:
        raise ValueError("database connection did not negotiate TLS")

    def ssl_attribute(name: bytes) -> str:
        getter = getattr(pgconn, "ssl_attribute", None)
        if not callable(getter):
            raise ValueError("database driver cannot attest negotiated TLS")
        value = getter(name)
        if isinstance(value, bytes):
            return value.decode("ascii", errors="strict")
        return str(value or "")

    protocol = ssl_attribute(b"protocol")
    cipher = ssl_attribute(b"cipher")
    bits = ssl_attribute(b"key_bits")
    if protocol not in {"TLSv1.2", "TLSv1.3"} or not cipher:
        raise ValueError("database negotiated TLS parameters are below policy")
    if bits and (not bits.isdigit() or int(bits) < 128):
        raise ValueError("database negotiated TLS key strength is below policy")


def _verify_execution_role(connection: Any, case: dict[str, str]) -> None:
    if case["control"] not in {"least-privilege", "row-level-security"}:
        return
    row = connection.execute(
        "SELECT r.rolsuper, r.rolbypassrls "
        "FROM pg_roles r WHERE r.rolname = current_user"
    ).fetchone()
    if not row or row[0] is True or row[1] is True:
        raise ValueError("database security oracle uses a privileged bypass role")
    if case["control"] == "row-level-security":
        relation = connection.execute(
            "SELECT c.relrowsecurity, c.relforcerowsecurity, "
            "pg_get_userbyid(c.relowner) = current_user "
            "FROM pg_class c WHERE c.oid = to_regclass(%s)",
            (case["target_id"],),
        ).fetchone()
        if not relation:
            raise ValueError("database RLS target relation does not exist")
        if relation[0] is not True or relation[1] is not True or relation[2] is True:
            raise ValueError(
                "database RLS oracle requires FORCE RLS and a non-owner role"
            )
        policy_rows = connection.execute(
            "SELECT pol.polpermissive, pg_get_expr(pol.polqual, pol.polrelid), "
            "pg_get_expr(pol.polwithcheck, pol.polrelid) "
            "FROM pg_policy pol WHERE pol.polrelid = to_regclass(%s)",
            (case["target_id"],),
        ).fetchall()
        if not policy_rows:
            raise ValueError("database RLS target has no policy")
        policy_text = " ".join(
            str(item or "") for row in policy_rows for item in row[1:]
        )
        if re.search(
            r"(?i)\b(select|current_setting|set_config|dblink|lo_)\b", policy_text
        ):
            raise ValueError("database RLS policy contains an unsafe dependency")
        memberships = connection.execute(
            "SELECT 1 FROM pg_auth_members m JOIN pg_roles r ON r.oid = m.roleid "
            "WHERE m.member = (SELECT oid FROM pg_roles WHERE rolname = current_user) "
            "AND (r.rolsuper OR r.rolbypassrls) LIMIT 1"
        ).fetchone()
        if memberships:
            raise ValueError("database security role inherits a bypass role")


def _validate_read_only_sql(sql: str) -> None:
    normalized = re.sub(r"\s+", " ", sql).strip().casefold()
    forbidden = (
        r"\bexplain\s+(?:\([^)]*analyze[^)]*\)\s*)?analyze\b",
        r"\bfor\s+(?:no\s+key\s+)?update\b",
        r"\bfor\s+(?:key\s+)?share\b",
        r"\binto\s+(?:temp|temporary|unlogged|table)?\b",
        r"\b(pg_sleep|set_config|nextval|setval|dblink|lo_import|lo_export|"
        r"pg_read_file|pg_read_binary_file|pg_ls_dir|pg_terminate_backend|"
        r"pg_cancel_backend|pg_advisory_lock|pg_advisory_xact_lock)\s*\(",
        # Function resolution is role/search_path dependent; even a familiar
        # name can resolve to a volatile or SECURITY DEFINER implementation.
        r"\b[a-z_][a-z0-9_$]*\s*\(",
    )
    if any(re.search(pattern, normalized) for pattern in forbidden):
        raise ValueError("database case invokes a stateful or unsafe SQL construct")


def _environment_name(value: object, label: str) -> str:
    result = str(value or "")
    if (
        not result
        or len(result) > 100
        or result.upper() != result
        or not result.replace("_", "").isalnum()
    ):
        raise ValueError(f"{label} must be an uppercase environment name")
    return result


def _text(value: object) -> str:
    result = str(value or "").strip()
    if (
        not result
        or len(result) > 160
        or any(ord(character) < 32 for character in result)
    ):
        raise ValueError("database case label is invalid")
    return result


def _read(path: Path) -> object:
    if (
        path.is_symlink()
        or not path.is_file()
        or path.stat().st_size > 64 * 1024 * 1024
    ):
        raise ValueError("database contract must be a bounded regular file")
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
