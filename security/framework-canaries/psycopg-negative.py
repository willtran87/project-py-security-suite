"""Negative detection canary for the governed Psycopg query model."""

import psycopg


def find_account(connection: psycopg.Connection, account_name: str):
    return connection.execute(
        "SELECT account_id FROM accounts WHERE account_name = %s", (account_name,)
    )
