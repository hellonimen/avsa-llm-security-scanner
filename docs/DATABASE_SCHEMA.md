# DATABASE_SCHEMA.md — DVAI SQLite Schema

> The database design for DVAI. This file is also the **source for your Chapter 4 ERD and class diagram** — three entities, two one-to-many relationships.

---

## 1. Overview

DVAI uses a single SQLite file (e.g. `dvai/dvai.sqlite`, git-ignored via `*.sqlite`). Three tables:

- **users** — accounts
- **chats** — a conversation belonging to a user
- **messages** — the individual turns inside a chat (user and assistant)

Relationship shape: **one user → many chats → many messages.**

---

## 2. Tables

### users
| Column | Type | Notes |
|---|---|---|
| `id` | INTEGER PK AUTOINCREMENT | |
| `username` | TEXT NOT NULL UNIQUE | used at login (SQLi target) |
| `password` | TEXT NOT NULL | **plaintext by design** — see §4 |
| `display_name` | TEXT | shown on the profile page |
| `created_at` | TEXT | timestamp |

### chats
| Column | Type | Notes |
|---|---|---|
| `id` | INTEGER PK AUTOINCREMENT | the `<id>` in `/chat/<id>` (IDOR target) |
| `user_id` | INTEGER NOT NULL → users.id | owner; **note: not checked on access by design** |
| `title` | TEXT | optional label |
| `created_at` | TEXT | timestamp |

### messages
| Column | Type | Notes |
|---|---|---|
| `id` | INTEGER PK AUTOINCREMENT | |
| `chat_id` | INTEGER NOT NULL → chats.id | parent conversation |
| `role` | TEXT NOT NULL | `'user'` or `'assistant'` |
| `content` | TEXT NOT NULL | **stored raw** — the stored-XSS / insecure-output sink |
| `created_at` | TEXT | timestamp |

---

## 3. schema.sql

```sql
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
    content    TEXT NOT NULL,                   -- stored raw; rendered with | safe
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (chat_id) REFERENCES chats(id)
);
```

---

## 4. Deliberate weaknesses (intentional, documented)

- **Plaintext passwords.** Passwords are stored as-is, not hashed. This is a deliberate simplification: it keeps the SQL-injection demonstration clean (dumping `users` shows readable credentials) and avoids extra moving parts. It is **not** counted as a seventh tested vulnerability — AVSA's scope remains the six. *(If you'd rather hash them and keep SQLi purely about the query construction, that's a one-line change — flag it and we adjust.)*
- **`content` stored raw.** Message content is never sanitised on the way in or out, so XSS persists and the bot's output renders unsafely.
- **No access scoping in queries.** Fetching a chat is done purely by `id`; the `user_id` owner is stored but deliberately not checked at `/chat/<id>` (that's the IDOR).

---

## 5. Seed data (optional but useful)

For testing IDOR you want **two different users each owning a chat**, so you can log in as user A and open user B's chat by ID. `seed.py` should create:

- user A (`alice`) with one chat + a couple of messages
- user B (`bob`) with one chat + a couple of messages

Then logging in as `alice` and visiting `bob`'s chat ID proves the IDOR.

---

## 6. ERD / class-diagram note for Chapter 4

This schema maps **directly** onto the diagrams Chapter 4 requires:

- **Entities:** `users`, `chats`, `messages`
- **Relationships:** `users` ──1:N── `chats` ──1:N── `messages`
- For the **class diagram**, the same three become classes with their attributes; the model layer (`db.py` functions) supplies the methods.

When you reach Chapter 4, you draw the ERD straight from this — no reverse-engineering needed.
