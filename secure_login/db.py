"""SQLite access.

Every query in this project passes its values as parameters (the ``?``
placeholders). Values are never formatted into the SQL text, which is what
makes SQL injection impossible rather than merely unlikely.
"""

import sqlite3

from flask import current_app, g


def connect(path):
    conn = sqlite3.connect(path, timeout=5)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def get_db():
    """The connection for the current request, opened on first use."""
    if "db" not in g:
        g.db = connect(current_app.config["DATABASE"])
    return g.db


def close_db(exception=None):
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


def init_db(app):
    with app.open_resource("schema.sql", "r") as f:
        schema = f.read()
    conn = connect(app.config["DATABASE"])
    try:
        conn.execute("PRAGMA journal_mode = WAL")
        conn.executescript(schema)
    finally:
        conn.close()
