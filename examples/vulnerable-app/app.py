"""INTENTIONALLY VULNERABLE demo app. Do not copy any of this code.

Every function below contains a mistake SAFECODE is designed to catch. The
comment above each one names the checklist rule it triggers.
"""

import sqlite3

import requests

# SC-001: a hardcoded credential. (This is a random fake value, not a real key.)
PAYMENTS_API_KEY = "q7Zt2LmX9vR4kP8wN3bY6cJ1hF5dS0gA"

# SC-008: a cleartext http:// endpoint.
PAYMENTS_URL = "http://payments.internal-api.net/v1/charge"


def find_user(conn: sqlite3.Connection, username: str):
    # SC-003: SQL built with an f-string. username = "x' OR '1'='1" returns every user.
    return conn.execute(f"SELECT * FROM users WHERE name = '{username}'").fetchall()


def find_orders(conn: sqlite3.Connection, user_id: str):
    # SC-003: SQL built with string concatenation.
    query = "SELECT * FROM orders WHERE user_id = " + user_id
    return conn.cursor().execute(query).fetchall()


def calculate(expression: str):
    # SC-003: eval on user input runs arbitrary Python.
    return eval(expression)


def charge(amount: int):
    # SC-008: TLS certificate verification disabled.
    return requests.post(
        PAYMENTS_URL,
        json={"amount": amount},
        headers={"Authorization": f"Bearer {PAYMENTS_API_KEY}"},
        verify=False,
    )
