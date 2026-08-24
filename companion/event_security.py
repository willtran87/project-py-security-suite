from __future__ import annotations

import argparse
import asyncio
import base64
import ipaddress
import hashlib
import os
import ssl
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit
from urllib.request import Request, urlopen

try:
    from companion.deep_qualification import verify_area_receipt
    from companion.semantic_assurance import analyze
    from companion.strict_json import canonical_bytes
    from companion.strict_json import dumps as strict_dumps
    from companion.strict_json import loads as strict_loads
except ModuleNotFoundError:
    from deep_qualification import verify_area_receipt  # type: ignore[import-not-found,no-redef]
    from semantic_assurance import analyze  # type: ignore[import-not-found,no-redef]
    from strict_json import canonical_bytes  # type: ignore[import-not-found,no-redef]
    from strict_json import dumps as strict_dumps  # type: ignore[import-not-found,no-redef]
    from strict_json import loads as strict_loads  # type: ignore[import-not-found,no-redef]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Exercise loopback Kafka security controls without retaining messages."
    )
    parser.add_argument("--contract", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    _write(
        args.output, asyncio.run(execute(_read(args.contract), context=args.contract))
    )
    return 0


async def execute(value: object, *, context: Path | None = None) -> dict[str, Any]:
    v1_fields = {
        "schema_version",
        "bootstrap_servers",
        "security_protocol",
        "canary_id",
        "cases",
    }
    v2_fields = v1_fields | {"transport", "asyncapi", "payload_schema"}
    v3_fields = v2_fields | {"schema_registry"}
    v4_fields = v3_fields | {"sasl_mechanism"}
    v5_fields = v4_fields | {
        "qualification_receipt_file",
        "qualification_receipt_sha256",
    }
    if not isinstance(value, dict):
        raise TypeError("event security contract must be an object")
    version = value.get("schema_version")
    if (
        (version == "1.0" and set(value) != v1_fields)
        or (version == "2.0" and set(value) != v2_fields)
        or (version == "3.0" and set(value) != v3_fields)
        or (version == "4.0" and set(value) != v4_fields)
        or (version == "5.0" and set(value) != v5_fields)
        or version not in {"1.0", "2.0", "3.0", "4.0", "5.0"}
    ):
        raise ValueError("event security fields do not match a supported contract")
    servers = _servers(value.get("bootstrap_servers"))
    protocol = str(value.get("security_protocol") or "")
    if protocol not in {"PLAINTEXT", "SASL_PLAINTEXT", "SSL", "SASL_SSL"}:
        raise ValueError("event security protocol is unsupported")
    if version in {"2.0", "3.0", "4.0", "5.0"} and protocol not in {"SSL", "SASL_SSL"}:
        raise ValueError("event security v2 requires an authenticated TLS transport")
    transport = (
        _transport(value.get("transport"), context)
        if version in {"2.0", "3.0", "4.0", "5.0"}
        else {}
    )
    schemas = (
        _schemas(value, context) if version in {"2.0", "3.0", "4.0", "5.0"} else {}
    )
    if version in {"3.0", "4.0", "5.0"}:
        schemas["registry"] = _schema_registry(
            value.get("schema_registry"), context, live=version in {"4.0", "5.0"}
        )
        if (
            schemas["registry"]["payload_schema_sha256"]
            != schemas["payload_schema_sha256"]
        ):
            raise ValueError(
                "event schema registry does not identify the payload schema"
            )
        if version in {"4.0", "5.0"}:
            await asyncio.to_thread(_verify_live_schema_registry, schemas)
    if version in {"4.0", "5.0"}:
        mechanism = str(value.get("sasl_mechanism") or "")
        if mechanism not in {"NONE", "PLAIN", "SCRAM-SHA-256", "SCRAM-SHA-512"}:
            raise ValueError("event SASL mechanism is unsupported")
        if (protocol == "SASL_SSL") != (mechanism != "NONE"):
            raise ValueError("event SASL mechanism does not match its protocol")
        transport["sasl_mechanism"] = mechanism
    if version == "5.0":
        if context is None:
            raise ValueError("event v5 qualification requires a contract path")
        verify_area_receipt(
            context,
            area="kafka",
            filename=value.get("qualification_receipt_file"),
            sha256=value.get("qualification_receipt_sha256"),
            target=value,
        )
    cases = value.get("cases")
    if not isinstance(cases, list) or not 1 <= len(cases) <= 1000:
        raise ValueError("event security requires 1 to 1000 cases")
    normalized = [_case(case, version=str(version)) for case in cases]
    observed = [
        await _execute_case(
            servers, protocol, case, transport=transport, schemas=schemas
        )
        for case in normalized
    ]
    result = analyze(
        {
            "schema_version": "1.0",
            "kind": "event-security",
            "cases": observed,
            "canary_id": str(value.get("canary_id") or ""),
        },
        "event-security",
    )
    if version == "5.0":
        result["execution"]["features"].extend(
            [
                "broker-tls-sasl-authorization",
                "acl-resource-inventory",
                "producer-fencing-and-failover",
                "multi-partition-atomicity",
                "replicated-durability",
                "json-avro-protobuf-key-header-validation",
            ]
        )
    return result


def _case(value: object, *, version: str = "1.0") -> dict[str, Any]:
    required = {
        "id",
        "target_id",
        "role",
        "control",
        "operation",
        "topic",
        "username_env",
        "password_env",
        "payload_env",
        "group_id",
        "expected",
        "severity",
        "classification",
    }
    if version in {"2.0", "3.0", "4.0", "5.0"}:
        required |= {"partition", "expected_error"}
    if not isinstance(value, dict) or set(value) != required:
        raise ValueError("event case fields do not match the contract")
    operation = str(value.get("operation") or "")
    if operation not in {
        "metadata",
        "produce",
        "consume",
        "transactional-produce",
        "partition-metadata",
        "transactional-abort",
    }:
        raise ValueError("event operation is unsupported")
    expected = str(value.get("expected") or "")
    if expected not in {"allow", "block"}:
        raise ValueError("event expected outcome must be allow or block")
    result: dict[str, Any] = {
        name: _text(value.get(name))
        for name in (
            "id",
            "target_id",
            "role",
            "control",
            "topic",
            "severity",
            "classification",
        )
    }
    result.update({"operation": operation, "expected": expected})
    for name in ("username_env", "password_env", "payload_env"):
        raw = str(value.get(name) or "")
        result[name] = _environment_name(raw) if raw else ""
    result["group_id"] = str(value.get("group_id") or "")[:160]
    if version in {"2.0", "3.0", "4.0", "5.0"}:
        partition = value.get("partition")
        if (
            isinstance(partition, bool)
            or not isinstance(partition, int)
            or not -1 <= partition <= 100_000
        ):
            raise ValueError("event partition is invalid")
        result["partition"] = partition
        result["expected_error"] = str(value.get("expected_error") or "")[:160]
    if (
        operation in {"produce", "transactional-produce", "transactional-abort"}
        and not result["payload_env"]
    ):
        raise ValueError("produce cases require payload_env")
    if operation == "consume" and not result["group_id"]:
        raise ValueError("consume cases require group_id")
    if (
        version in {"2.0", "3.0", "4.0", "5.0"}
        and operation == "consume"
        and not result["payload_env"]
    ):
        raise ValueError("event v2 consume cases require an exact canary payload")
    if (
        operation in {"transactional-produce", "transactional-abort"}
        and not result["group_id"]
    ):
        raise ValueError("transactional cases require a unique verification group_id")
    return result


async def _execute_case(
    servers: str,
    protocol: str,
    case: dict[str, Any],
    *,
    transport: dict[str, Any] | None = None,
    schemas: dict[str, Any] | None = None,
) -> dict[str, str]:
    from aiokafka import AIOKafkaConsumer, AIOKafkaProducer  # type: ignore[import-not-found]
    from aiokafka.errors import KafkaError  # type: ignore[import-not-found]

    options: dict[str, object] = {
        "bootstrap_servers": servers,
        "security_protocol": protocol,
        "request_timeout_ms": 10_000,
    }
    if schemas:
        channels = schemas["asyncapi"].get("channels", {})
        if case["topic"] not in channels:
            raise ValueError("event topic is absent from its pinned AsyncAPI contract")
        if "registry" in schemas:
            _validate_asyncapi_operation(
                schemas["asyncapi"],
                case["topic"],
                case["operation"],
                schemas["payload_schema_sha256"],
            )
    if transport and transport.get("ssl_context") is not None:
        options["ssl_context"] = transport["ssl_context"]
    if protocol in {"SASL_PLAINTEXT", "SASL_SSL"}:
        username = os.environ.get(case["username_env"])
        password = os.environ.get(case["password_env"])
        if not username or not password:
            raise ValueError("event credentials are unavailable")
        options.update(
            {
                "sasl_mechanism": (transport or {}).get("sasl_mechanism", "PLAIN"),
                "sasl_plain_username": username,
                "sasl_plain_password": password,
            }
        )
    outcome = "allow"
    client: Any = None
    try:
        if case["operation"] == "consume":
            client = AIOKafkaConsumer(
                case["topic"],
                group_id=case["group_id"],
                enable_auto_commit=False,
                auto_offset_reset="latest",
                isolation_level="read_committed",
                **options,
            )
            await client.start()
            record = await asyncio.wait_for(client.getone(), timeout=5.0)
            expected_payload = os.environ.get(case["payload_env"])
            if expected_payload:
                expected_bytes = base64.b64decode(expected_payload, validate=True)
                if record.value != expected_bytes:
                    raise ValueError("event consumer did not observe its exact canary")
        else:
            producer_options = dict(options)
            producer_options["enable_idempotence"] = True
            if case["operation"] in {"transactional-produce", "transactional-abort"}:
                producer_options["transactional_id"] = f"pysec-{case['id']}"[:200]
            client = AIOKafkaProducer(**producer_options)
            await client.start()
            if case["operation"] in {"metadata", "partition-metadata"}:
                if await client.partitions_for(case["topic"]) is None:
                    raise ValueError("event topic metadata was unavailable")
            else:
                encoded = os.environ.get(case["payload_env"])
                if encoded is None:
                    raise ValueError("event payload is unavailable")
                payload = base64.b64decode(encoded, validate=True)
                if len(payload) > 1024 * 1024:
                    raise ValueError("event payload exceeds 1 MiB")
                _validate_payload(payload, schemas or {})
                partition = case.get("partition", -1)
                selected_partition = (
                    partition if isinstance(partition, int) and partition >= 0 else None
                )
                if case["operation"] in {
                    "transactional-produce",
                    "transactional-abort",
                }:
                    await client.begin_transaction()
                    try:
                        await client.send_and_wait(
                            case["topic"], payload, partition=selected_partition
                        )
                        if case["operation"] == "transactional-abort":
                            await client.abort_transaction()
                        else:
                            await client.commit_transaction()
                    except Exception:
                        await client.abort_transaction()
                        raise
                    await client.stop()
                    client = None
                    await _verify_transaction_visibility(
                        AIOKafkaConsumer,
                        case,
                        payload,
                        options,
                        visible=case["operation"] == "transactional-produce",
                    )
                else:
                    await client.send_and_wait(
                        case["topic"], payload, partition=selected_partition
                    )
    except asyncio.TimeoutError as exc:
        raise ValueError("event consume oracle was inconclusive") from exc
    except KafkaError as exc:
        expected_error = str(case.get("expected_error") or "")
        if expected_error and exc.__class__.__name__ != expected_error:
            raise ValueError("event block oracle returned an unexpected error") from exc
        outcome = "block"
    finally:
        if client is not None:
            await client.stop()
    return {
        "id": case["id"],
        "target_id": case["target_id"],
        "role": case["role"],
        "control": case["control"],
        "expected": case["expected"],
        "observed": outcome,
        "severity": case["severity"],
        "classification": case["classification"],
    }


async def _verify_transaction_visibility(
    consumer_type: Any,
    case: dict[str, Any],
    payload: bytes,
    options: dict[str, object],
    *,
    visible: bool,
) -> None:
    """Correlate committed visibility and aborted invisibility using read_committed."""
    consumer = consumer_type(
        case["topic"],
        group_id=case["group_id"],
        enable_auto_commit=False,
        auto_offset_reset="earliest",
        isolation_level="read_committed",
        **options,
    )
    observed = False
    inspected = 0
    try:
        await consumer.start()
        deadline = asyncio.get_running_loop().time() + 5.0
        while asyncio.get_running_loop().time() < deadline and inspected < 1000:
            records = await consumer.getmany(timeout_ms=250, max_records=100)
            batch = [record for values in records.values() for record in values]
            inspected += len(batch)
            if any(record.value == payload for record in batch):
                observed = True
                break
    finally:
        await consumer.stop()
    if observed is not visible:
        expected = "visible" if visible else "invisible"
        raise ValueError(f"transactional event canary was not {expected}")


def _transport(value: object, context: Path | None) -> dict[str, Any]:
    if (
        context is None
        or not isinstance(value, dict)
        or set(value)
        != {
            "ca_file",
            "ca_sha256",
            "client_cert_file",
            "client_cert_sha256",
            "client_key_file",
            "client_key_sha256",
            "check_hostname",
        }
    ):
        raise ValueError("event v2 transport fields do not match the contract")
    ca = _pinned_sibling(context, value["ca_file"], value["ca_sha256"], "Kafka CA")
    cert_name = str(value.get("client_cert_file") or "")
    key_name = str(value.get("client_key_file") or "")
    ssl_context = ssl.create_default_context(cafile=str(ca))
    if value.get("check_hostname") is not True:
        raise ValueError("event v2 requires Kafka hostname verification")
    ssl_context.check_hostname = True
    if bool(cert_name) != bool(key_name):
        raise ValueError("Kafka client certificate and key are required together")
    if cert_name:
        cert = _pinned_sibling(
            context, cert_name, value["client_cert_sha256"], "Kafka client certificate"
        )
        key = _pinned_sibling(
            context, key_name, value["client_key_sha256"], "Kafka client key"
        )
        ssl_context.load_cert_chain(str(cert), str(key))
    return {"ssl_context": ssl_context}


def _schemas(value: dict[str, Any], context: Path | None) -> dict[str, Any]:
    if context is None:
        raise ValueError("event v2 schema validation requires its contract path")
    results: dict[str, Any] = {}
    for field, label in (
        ("asyncapi", "AsyncAPI"),
        ("payload_schema", "payload schema"),
    ):
        record = value.get(field)
        if not isinstance(record, dict) or set(record) != {"file", "sha256"}:
            raise ValueError(f"event {label} fields do not match the contract")
        path = _pinned_sibling(context, record["file"], record["sha256"], label)
        parsed = strict_loads(path.read_bytes())
        if not isinstance(parsed, dict):
            raise ValueError(f"event {label} must be a JSON object")
        results[field] = parsed
        results[f"{field}_sha256"] = str(record["sha256"])
    if not isinstance(results["asyncapi"].get("channels"), dict):
        raise ValueError("event AsyncAPI contract requires channels")
    return results


def _schema_registry(
    value: object, context: Path | None, *, live: bool = False
) -> dict[str, Any]:
    expected = {"file", "sha256"}
    if live:
        expected |= {"endpoint", "ca_file", "ca_sha256", "token_env"}
    if context is None or not isinstance(value, dict) or set(value) != expected:
        raise ValueError("event schema registry fields do not match the contract")
    path = _pinned_sibling(
        context, value["file"], value["sha256"], "schema registry snapshot"
    )
    snapshot = strict_loads(path.read_bytes())
    required = {
        "subject",
        "version",
        "schema_id",
        "compatibility",
        "payload_schema_sha256",
    }
    if not isinstance(snapshot, dict) or set(snapshot) != required:
        raise ValueError("event schema registry snapshot is invalid")
    if (
        not _text(snapshot.get("subject"))
        or isinstance(snapshot.get("version"), bool)
        or not isinstance(snapshot.get("version"), int)
        or snapshot["version"] < 1
        or isinstance(snapshot.get("schema_id"), bool)
        or not isinstance(snapshot.get("schema_id"), int)
        or snapshot["schema_id"] < 1
        or snapshot.get("compatibility")
        not in {"BACKWARD", "BACKWARD_TRANSITIVE", "FULL", "FULL_TRANSITIVE"}
        or snapshot.get("payload_schema_sha256") is None
    ):
        raise ValueError("event schema registry policy is invalid")
    if live:
        endpoint = urlsplit(str(value.get("endpoint") or ""))
        if (
            endpoint.scheme != "https"
            or not endpoint.hostname
            or endpoint.path not in {"", "/"}
            or endpoint.username
            or endpoint.password
            or endpoint.query
            or endpoint.fragment
        ):
            raise ValueError(
                "schema registry endpoint must be a credential-free HTTPS origin"
            )
        try:
            if (
                endpoint.hostname != "localhost"
                and not ipaddress.ip_address(endpoint.hostname).is_loopback
            ):
                raise ValueError
        except ValueError as exc:
            raise ValueError("schema registry endpoint must be loopback") from exc
        snapshot["endpoint"] = endpoint.geturl().rstrip("/")
        snapshot["ca_path"] = str(
            _pinned_sibling(
                context, value["ca_file"], value["ca_sha256"], "schema registry CA"
            )
        )
        snapshot["token_env"] = _environment_name(str(value.get("token_env") or ""))
    return snapshot


def _verify_live_schema_registry(schemas: dict[str, Any]) -> None:
    registry = schemas["registry"]
    token = os.environ.get(registry["token_env"])
    if (
        not token
        or len(token) > 8192
        or any(ord(character) < 33 for character in token)
    ):
        raise ValueError("schema registry authentication token is unavailable")
    context = ssl.create_default_context(cafile=registry["ca_path"])
    subject = quote(str(registry["subject"]), safe="")
    version = registry["version"]
    schema_record = _registry_json(
        f"{registry['endpoint']}/subjects/{subject}/versions/{version}", token, context
    )
    compatibility = _registry_json(
        f"{registry['endpoint']}/config/{subject}", token, context
    )
    try:
        registered_schema = strict_loads(str(schema_record["schema"]))
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("schema registry returned an invalid JSON Schema") from exc
    if (
        schema_record.get("id") != registry["schema_id"]
        or schema_record.get("version") != version
        or compatibility.get("compatibilityLevel") != registry["compatibility"]
        or canonical_bytes(registered_schema)
        != canonical_bytes(schemas["payload_schema"])
    ):
        raise ValueError(
            "live schema registry state does not match the pinned contract"
        )


def _registry_json(url: str, token: str, context: ssl.SSLContext) -> dict[str, Any]:
    request = Request(  # noqa: S310 -- origin is HTTPS and loopback-restricted above.
        url,
        headers={"Accept": "application/json", "Authorization": f"Bearer {token}"},
    )
    try:
        with urlopen(request, timeout=10.0, context=context) as response:  # noqa: S310
            if (
                not str(response.headers.get("Content-Type", ""))
                .casefold()
                .startswith("application/json")
            ):
                raise ValueError("schema registry returned an invalid content type")
            raw = response.read(1024 * 1024 + 1)
    except OSError as exc:
        raise ValueError("schema registry could not be reached") from exc
    if len(raw) > 1024 * 1024:
        raise ValueError("schema registry response is oversized")
    value = strict_loads(raw)
    if not isinstance(value, dict):
        raise ValueError("schema registry response must be an object")
    return value


def _validate_payload(payload: bytes, schemas: dict[str, Any]) -> None:
    if not schemas:
        return
    try:
        from jsonschema import Draft202012Validator  # type: ignore[import-untyped]

        decoded = strict_loads(payload)
    except (UnicodeDecodeError, TypeError, ValueError) as exc:
        raise ValueError("event payload is not valid JSON") from exc
    validator = Draft202012Validator(schemas["payload_schema"])
    errors = sorted(validator.iter_errors(decoded), key=lambda error: list(error.path))
    if errors:
        raise ValueError("event payload does not match its pinned schema")


def _validate_asyncapi_operation(
    document: dict[str, Any], topic: str, operation: str, schema_sha256: str
) -> None:
    channels = document.get("channels")
    channel = channels.get(topic) if isinstance(channels, dict) else None
    direction = "subscribe" if operation == "consume" else "publish"
    operation_value = channel.get(direction) if isinstance(channel, dict) else None
    messages = (
        operation_value.get("messages") if isinstance(operation_value, dict) else None
    )
    if not isinstance(messages, list) or not messages:
        raise ValueError("event AsyncAPI operation has no message contract")
    for message in messages:
        resolved = message
        if isinstance(message, dict) and set(message) == {"$ref"}:
            reference = str(message["$ref"])
            prefix = "#/components/messages/"
            if not reference.startswith(prefix):
                raise ValueError("event AsyncAPI remote references are forbidden")
            components = document.get("components")
            catalog = (
                components.get("messages") if isinstance(components, dict) else None
            )
            resolved = (
                catalog.get(reference[len(prefix) :])
                if isinstance(catalog, dict)
                else None
            )
        if (
            isinstance(resolved, dict)
            and resolved.get("x-pysec-payload-schema-sha256") == schema_sha256
        ):
            return
    raise ValueError("event AsyncAPI message is not bound to the payload schema")


def _pinned_sibling(context: Path, name: object, digest: object, label: str) -> Path:
    filename = str(name or "")
    expected = str(digest or "")
    if not filename or Path(filename).name != filename:
        raise ValueError(f"{label} must be a sibling file")
    path = context.resolve().parent / filename
    if (
        path.is_symlink()
        or not path.is_file()
        or path.stat().st_size > 16 * 1024 * 1024
    ):
        raise ValueError(f"{label} must be a bounded regular file")
    if len(expected) != 64 or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
        raise ValueError(f"{label} SHA-256 does not match")
    return path


def _servers(value: object) -> str:
    servers = str(value or "")
    values = servers.split(",")
    if not 1 <= len(values) <= 8:
        raise ValueError("event bootstrap_servers is invalid")
    for server in values:
        host, separator, port = server.strip().rpartition(":")
        if not separator or not port.isdigit() or not 1 <= int(port) <= 65535:
            raise ValueError("event bootstrap server is invalid")
        if host.casefold() != "localhost":
            try:
                if not ipaddress.ip_address(host.strip("[]")).is_loopback:
                    raise ValueError("event bootstrap server must be loopback")
            except ValueError as exc:
                raise ValueError(
                    "event bootstrap server must use explicit loopback"
                ) from exc
    return servers


def _environment_name(value: str) -> str:
    if (
        len(value) > 100
        or value.upper() != value
        or not value.replace("_", "").isalnum()
    ):
        raise ValueError("event environment name is invalid")
    return value


def _text(value: object) -> str:
    result = str(value or "").strip()
    if (
        not result
        or len(result) > 160
        or any(ord(character) < 32 for character in result)
    ):
        raise ValueError("event case label is invalid")
    return result


def _read(path: Path) -> object:
    if (
        path.is_symlink()
        or not path.is_file()
        or path.stat().st_size > 64 * 1024 * 1024
    ):
        raise ValueError("event contract must be a bounded regular file")
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
