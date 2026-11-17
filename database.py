"""
database.py - Database connection and initialization module for SentinelSOC.
CS50 Final Project.
"""

import os
import sqlite3
from flask import g, current_app, has_app_context

DEFAULT_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sentinel.db")


def get_db(db_path=None):
    """
    Get a database connection.
    If inside a Flask request/app context, caches connection in flask.g.
    If running as a standalone script or test, opens a direct sqlite3 connection.
    Configures Row factory and foreign keys.
    """
    if has_app_context():
        if "db" not in g:
            path = current_app.config.get("DATABASE", DEFAULT_DB_PATH)
            g.db = sqlite3.connect(path, detect_types=sqlite3.PARSE_DECLTYPES)
            g.db.row_factory = sqlite3.Row
            g.db.execute("PRAGMA foreign_keys = ON")
        return g.db

    # Standalone mode outside Flask context
    path = db_path or DEFAULT_DB_PATH
    conn = sqlite3.connect(path, detect_types=sqlite3.PARSE_DECLTYPES)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def close_db(e=None):
    """
    Close the database connection at the end of the request if open in flask.g.
    """
    if has_app_context():
        db = g.pop("db", None)
        if db is not None:
            db.close()


def init_db(db_path=DEFAULT_DB_PATH):
    """
    Initialize the database using schema.sql.
    """
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")

    schema_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "schema.sql")
    with open(schema_file, "r", encoding="utf-8") as f:
        conn.executescript(f.read())

    conn.commit()
    conn.close()


def query_db(query, args=(), one=False, db_path=None):
    """
    Convenience function to execute queries and fetch results.
    Prevents SQL injection by enforcing parameterized arguments.
    """
    standalone = not has_app_context()
    db = get_db(db_path)
    cur = db.execute(query, args)
    rv = cur.fetchall()
    cur.close()
    if standalone:
        db.close()
    return (rv[0] if rv else None) if one else rv


def execute_db(query, args=(), db_path=None):
    """
    Convenience function to execute INSERT, UPDATE, DELETE statements.
    Returns the lastrowid of the executed statement.
    """
    standalone = not has_app_context()
    db = get_db(db_path)
    cur = db.execute(query, args)
    db.commit()
    last_id = cur.lastrowid
    cur.close()
    if standalone:
        db.close()
    return last_id
