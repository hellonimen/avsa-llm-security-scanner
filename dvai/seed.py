"""Seed deterministic test data for DVAI (Sprint 2).

Creates two fixed users — alice and bob — each with one chat, so the IDOR on
GET /chat/<id> (DVAI_SPEC §4.2) has a reliable cross-user target. One of bob's
messages carries a stored-XSS proof payload (§4.3) so that opening bob's chat as
alice demonstrates IDOR *and* Stored XSS in a single view.

Run as a standalone script BEFORE starting the app:

    python seed.py

It talks to the SQLite file directly (it runs outside any Flask request, so it
must not use db.get_db()/g). The reset is idempotent: re-running wipes the data
tables and reinserts, giving stable IDs every time (alice=user 1 / chat 1,
bob=user 2 / chat 2).

NOTE: passwords are stored in plaintext on purpose — that is the schema's
by-design weakness, consistent with the rest of DVAI. This is a lab target.
"""

import sqlite3

import db  # for DB_PATH / SCHEMA_PATH and init_db()


# Fixed accounts. Plaintext passwords by design (see module docstring).
USERS = [
    # username, password, display_name
    ("alice", "password123", "Alice"),
    ("bob", "hunter2", "Bob"),
]

# A harmless-looking stored-XSS payload. Changing document.title is a quiet,
# screenshot-friendly proof that script ran — no alert() spam on every view.
XSS_PAYLOAD = "<img src=x onerror=\"document.title='XSS by bob'\">"

# chat title -> list of (role, content) messages, per user.
ALICE_CHAT = (
    "Order question",
    [
        ("user", "Hi, where is my order #1042?"),
        ("assistant", "Your order #1042 shipped today and arrives Thursday."),
    ],
)

BOB_CHAT = (
    "Refund request",
    [
        ("user", "I'd like a refund for my last purchase, please."),
        ("assistant", "No problem — I've started the refund. It posts in 3–5 days."),
        # Stored-XSS proof: this renders through the `| safe` sink in chat.html.
        ("user", XSS_PAYLOAD),
    ],
)


def reset(conn):
    """Wipe data tables and reset autoincrement so IDs are deterministic."""
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("DELETE FROM messages")
    conn.execute("DELETE FROM chats")
    conn.execute("DELETE FROM users")
    # Clear AUTOINCREMENT high-water marks so ids restart at 1.
    conn.execute("DELETE FROM sqlite_sequence WHERE name IN ('users', 'chats', 'messages')")
    conn.commit()


def seed_user(conn, username, password, display_name, chat):
    """Insert one user + one chat + its messages. Returns (user_id, chat_id)."""
    cur = conn.execute(
        "INSERT INTO users (username, password, display_name) VALUES (?, ?, ?)",
        (username, password, display_name),
    )
    user_id = cur.lastrowid

    title, messages = chat
    cur = conn.execute(
        "INSERT INTO chats (user_id, title) VALUES (?, ?)",
        (user_id, title),
    )
    chat_id = cur.lastrowid

    for role, content in messages:
        conn.execute(
            "INSERT INTO messages (chat_id, role, content) VALUES (?, ?, ?)",
            (chat_id, role, content),
        )

    conn.commit()
    return user_id, chat_id


def main():
    # Make sure the schema exists before we seed (no-op if the DB already exists).
    db.init_db()

    conn = sqlite3.connect(db.DB_PATH)
    try:
        reset(conn)
        alice_uid, alice_cid = seed_user(conn, *USERS[0], ALICE_CHAT)
        bob_uid, bob_cid = seed_user(conn, *USERS[1], BOB_CHAT)
    finally:
        conn.close()

    print("Seeded DVAI test data:")
    print(f"  alice / {USERS[0][1]}   (user id {alice_uid}, chat id {alice_cid})")
    print(f"  bob   / {USERS[1][1]}       (user id {bob_uid}, chat id {bob_cid})")
    print()
    print("IDOR target : log in as alice, open /chat/%d (bob's chat)." % bob_cid)
    print("Stored XSS  : bob's chat contains an <img onerror> payload.")


if __name__ == "__main__":
    main()
