from __future__ import annotations

import asyncio
import os
import ssl
import uuid
from typing import Any

import pytest


pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        os.environ.get("PYSEC_RUN_SERVICE_INTEGRATION") != "1",
        reason="live service integration lane is opt-in",
    ),
]


def test_postgresql_row_security_blocks_cross_tenant_reads(
    socket_enabled: None,
) -> None:
    import psycopg
    from psycopg import sql
    from psycopg.conninfo import conninfo_to_dict, make_conninfo

    dsn = os.environ["PYSEC_TEST_POSTGRES_DSN"]
    suffix = uuid.uuid4().hex[:12]
    table = f"pysec_rls_{suffix}"
    roles = (f"pysec_a_{suffix}", f"pysec_b_{suffix}")
    passwords = (uuid.uuid4().hex, uuid.uuid4().hex)
    with psycopg.connect(dsn, autocommit=True) as admin:
        _assert_postgresql_tls(admin)
        try:
            for role, password in zip(roles, passwords, strict=True):
                admin.execute(
                    sql.SQL("CREATE ROLE {} LOGIN PASSWORD %s").format(
                        sql.Identifier(role)
                    ),
                    (password,),
                )
            admin.execute(
                sql.SQL("CREATE TABLE {} (tenant name, secret text)").format(
                    sql.Identifier(table)
                )
            )
            admin.execute(
                sql.SQL("ALTER TABLE {} ENABLE ROW LEVEL SECURITY").format(
                    sql.Identifier(table)
                )
            )
            admin.execute(
                sql.SQL("ALTER TABLE {} FORCE ROW LEVEL SECURITY").format(
                    sql.Identifier(table)
                )
            )
            admin.execute(
                sql.SQL(
                    "CREATE POLICY tenant_boundary ON {} USING (tenant = current_user)"
                ).format(sql.Identifier(table))
            )
            admin.execute(
                sql.SQL("GRANT SELECT ON {} TO {}, {}").format(
                    sql.Identifier(table),
                    sql.Identifier(roles[0]),
                    sql.Identifier(roles[1]),
                )
            )
            relation = admin.execute(
                "SELECT relrowsecurity, relforcerowsecurity "
                "FROM pg_class WHERE oid = to_regclass(%s)",
                (table,),
            ).fetchone()
            assert relation == (True, True)
            role_flags = admin.execute(
                "SELECT rolname, rolsuper, rolbypassrls FROM pg_roles "
                "WHERE rolname = ANY(%s) ORDER BY rolname",
                (list(roles),),
            ).fetchall()
            assert all(
                superuser is False and bypass is False
                for _, superuser, bypass in role_flags
            )
            admin.execute(
                sql.SQL("INSERT INTO {} VALUES (%s, %s), (%s, %s)").format(
                    sql.Identifier(table)
                ),
                (roles[0], "a", roles[1], "b"),
            )
            for role, password in zip(roles, passwords, strict=True):
                role_parameters = conninfo_to_dict(dsn)
                role_parameters.update({"user": role, "password": password})
                role_dsn = make_conninfo(**role_parameters)
                with psycopg.connect(role_dsn) as connection:
                    _assert_postgresql_tls(connection)
                    rows = connection.execute(
                        sql.SQL("SELECT tenant, secret FROM {}").format(
                            sql.Identifier(table)
                        )
                    ).fetchall()
                assert rows == [(role, "a" if role == roles[0] else "b")]
        finally:
            admin.execute(
                sql.SQL("DROP TABLE IF EXISTS {}").format(sql.Identifier(table))
            )
            for role in roles:
                admin.execute(
                    sql.SQL("DROP ROLE IF EXISTS {}").format(sql.Identifier(role))
                )


def _assert_postgresql_tls(connection: Any) -> None:
    pgconn = connection.pgconn
    assert pgconn.ssl_in_use is True
    protocol = pgconn.ssl_attribute(b"protocol")
    assert protocol in {b"TLSv1.2", b"TLSv1.3"}


def test_kafka_read_committed_hides_aborts_and_exposes_commits(
    socket_enabled: None,
) -> None:
    asyncio.run(_kafka_transaction_oracle())


async def _kafka_transaction_oracle() -> None:
    from aiokafka import AIOKafkaConsumer, AIOKafkaProducer
    from aiokafka.errors import KafkaError

    servers = os.environ["PYSEC_TEST_KAFKA_SERVERS"]
    options = _kafka_options()
    await _assert_kafka_tls(servers, options["ssl_context"])
    suffix = uuid.uuid4().hex
    topic = f"pysec-transactions-{suffix}"
    aborted = f"aborted-{suffix}".encode()
    committed = f"committed-{suffix}".encode()
    producer = AIOKafkaProducer(
        bootstrap_servers=servers,
        enable_idempotence=True,
        transactional_id=f"pysec-{suffix}",
        **options,
    )
    await producer.start()
    try:
        await producer.begin_transaction()
        await producer.send_and_wait(topic, aborted)
        await producer.abort_transaction()
        await producer.begin_transaction()
        await producer.send_and_wait(topic, committed)
        await producer.commit_transaction()
    finally:
        await producer.stop()

    consumer = AIOKafkaConsumer(
        topic,
        bootstrap_servers=servers,
        group_id=f"pysec-read-committed-{suffix}",
        auto_offset_reset="earliest",
        enable_auto_commit=False,
        isolation_level="read_committed",
        **options,
    )
    values: list[bytes] = []
    try:
        await consumer.start()
        deadline = asyncio.get_running_loop().time() + 10
        while asyncio.get_running_loop().time() < deadline and committed not in values:
            records = await consumer.getmany(timeout_ms=500, max_records=100)
            values.extend(
                record.value for batch in records.values() for record in batch
            )
    finally:
        await consumer.stop()
    assert committed in values
    assert aborted not in values

    restricted = AIOKafkaProducer(
        bootstrap_servers=servers,
        security_protocol="SASL_SSL",
        ssl_context=options["ssl_context"],
        sasl_mechanism="SCRAM-SHA-512",
        sasl_plain_username=os.environ["PYSEC_TEST_KAFKA_RESTRICTED_USER"],
        sasl_plain_password=os.environ["PYSEC_TEST_KAFKA_RESTRICTED_PASSWORD"],
    )
    await restricted.start()
    try:
        with pytest.raises(KafkaError):
            await restricted.send_and_wait(topic, b"must-be-denied")
    finally:
        await restricted.stop()

    fenced_id = f"pysec-fence-{suffix}"
    first = AIOKafkaProducer(
        bootstrap_servers=servers,
        transactional_id=fenced_id,
        **options,
    )
    second = AIOKafkaProducer(
        bootstrap_servers=servers,
        transactional_id=fenced_id,
        **options,
    )
    await first.start()
    await first.begin_transaction()
    await second.start()
    try:
        with pytest.raises(KafkaError):
            await first.send_and_wait(topic, b"fenced")
    finally:
        await first.stop()
        await second.stop()


def _kafka_options() -> dict[str, Any]:
    context = ssl.create_default_context(cafile=os.environ["PYSEC_TEST_KAFKA_CA"])
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    return {
        "security_protocol": "SASL_SSL",
        "ssl_context": context,
        "sasl_mechanism": "SCRAM-SHA-512",
        "sasl_plain_username": os.environ["PYSEC_TEST_KAFKA_USER"],
        "sasl_plain_password": os.environ["PYSEC_TEST_KAFKA_PASSWORD"],
    }


async def _assert_kafka_tls(servers: str, context: ssl.SSLContext) -> None:
    host, port_text = servers.split(":", 1)
    reader, writer = await asyncio.open_connection(
        host, int(port_text), ssl=context, server_hostname="localhost"
    )
    del reader
    ssl_object = writer.get_extra_info("ssl_object")
    try:
        assert ssl_object is not None
        assert ssl_object.version() == "TLSv1.3"
    finally:
        writer.close()
        await writer.wait_closed()
