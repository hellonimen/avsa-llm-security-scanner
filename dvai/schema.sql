-- DVAI SQLite schema. Source of truth: docs/DATABASE_SCHEMA.md §3.
-- One user -> many chats -> many messages.

CREATE TABLE users (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    username     TEXT NOT NULL UNIQUE,
    password     TEXT NOT NULL,                 -- plaintext BY DESIGN (intentional)
    display_name TEXT,
    created_at   TEXT DEFAULT (datetime('now'))
);

CREATE TABLE chats (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL,
    title      TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE messages (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    chat_id    INTEGER NOT NULL,
    role       TEXT NOT NULL CHECK (role IN ('user', 'assistant')),
    content    TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (chat_id) REFERENCES chats(id)
);
