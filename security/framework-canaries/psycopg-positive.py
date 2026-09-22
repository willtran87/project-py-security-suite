"""Positive detection canary for the governed Psycopg query model."""

import psycopg


def find_account(connection: psycopg.Connection, account_name: str):
    """Deliberately unsafe: the model must report this query composition."""
    return connection.execute(
        f"SELECT account_id FROM accounts WHERE account_name = '{account_name}'"  # noqa: S608  # nosec B608
    )
