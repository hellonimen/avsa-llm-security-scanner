"""SQLite model layer for DVAI.

Sprint 1: clean foundation. Every query here is parameterised (`?` placeholders).
The deliberate SQL-injection in the login lookup is planted in Sprint 2, not here.
"""

import os
import sqlite3

from flask import g

# DB file lives next to this module: dvai/dvai.sqlite (git-ignored via *.sqlite).
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "dvai.sqlite")
SCHEMA_PATH = os.path.join(BASE_DIR, "schema.sql")


def get_db():
    """Return a per-request SQLite connection, creating it on first use."""
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row  # rows behave like dicts
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


def close_db(exception=None):
    """Close the request's connection. Registered as a Flask teardown handler."""
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    """Create the schema if the DB file does not yet exist."""
    if os.path.exists(DB_PATH):
        return
    with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
        sql = f.read()
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.executescript(sql)
        conn.commit()
    finally:
        conn.close()


# --- users -----------------------------------------------------------------

def create_user(username, password, display_name=None):
    """Insert a user. Returns the new user id. Raises sqlite3.IntegrityError
    if the username is already taken."""
    db = get_db()
    cur = db.execute(
        "INSERT INTO users (username, password, display_name) VALUES (?, ?, ?)",
        (username, password, display_name or username),
    )
    db.commit()
    return cur.lastrowid


def get_user_by_username(username):
    db = get_db()
    return db.execute(
        "SELECT * FROM users WHERE username = ?", (username,)
    ).fetchone()


def get_user_by_id(user_id):
    db = get_db()
    return db.execute(
        "SELECT * FROM users WHERE id = ?", (user_id,)
    ).fetchone()


def verify_login(username, password):
    """Credential check. Returns the user row or None.

    VULNERABLE BY DESIGN (DVAI_SPEC §4.1) — do NOT "fix" this. The username and
    password are concatenated straight into the SQL string instead of being passed
    as bound parameters, so the login form is SQL-injectable (e.g. a username of
    ' OR '1'='1' --  bypasses authentication). This is the SQLi sink AVSA detects.
    Every OTHER query in this module stays parameterised; only login is injectable.
    """
    db = get_db()
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    return db.execute(query).fetchone()


# --- chats -----------------------------------------------------------------

def create_chat(user_id, title=None):
    db = get_db()
    cur = db.execute(
        "INSERT INTO chats (user_id, title) VALUES (?, ?)",
        (user_id, title or "New chat"),
    )
    db.commit()
    return cur.lastrowid


def get_chats_for_user(user_id):
    db = get_db()
    return db.execute(
        "SELECT * FROM chats WHERE user_id = ? ORDER BY id DESC",
        (user_id,),
    ).fetchall()


def get_chat(chat_id):
    db = get_db()
    return db.execute(
        "SELECT * FROM chats WHERE id = ?", (chat_id,)
    ).fetchone()


# --- messages --------------------------------------------------------------

def add_message(chat_id, role, content):
    db = get_db()
    cur = db.execute(
        "INSERT INTO messages (chat_id, role, content) VALUES (?, ?, ?)",
        (chat_id, role, content),
    )
    db.commit()
    return cur.lastrowid


def get_messages(chat_id):
    db = get_db()
    return db.execute(
        "SELECT * FROM messages WHERE chat_id = ? ORDER BY id ASC",
        (chat_id,),
    ).fetchall()
