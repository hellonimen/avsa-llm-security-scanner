# DVAI_SPEC.md — Deliberately Vulnerable AI Application

> Build target for the project. **Read the README's "Intentionally vulnerable" section first** — DVAI is insecure *by design*. Every weakness below is intentional and must be left exploitable.

---

## 1. What DVAI is

A minimal AI customer-support chatbot web app. A logged-in user chats with an AI assistant; conversations are saved and can be viewed later. It echoes the shape of a typical AI support assistant but is stripped to the smallest thing that can host the **six target vulnerabilities**. Nothing more is built than what those six need.

---

## 2. Stack (recap)

Flask · SQLite · OpenAI API (cheapest model; key + model name in `dvai/.env`) · Jinja2 templates · vanilla JavaScript. **No React** — React auto-escapes and would kill the XSS we need on purpose.

---

## 3. Features & routes

Five features, mapped to routes:

| # | Feature | Route(s) | Vulnerability hosted |
|---|---|---|---|
| 1 | Accounts | `GET/POST /register`, `GET/POST /login`, `GET /logout` | **SQL Injection** (login) |
| 2 | Chat interface | `GET /chat`, `POST /chat/send` | **Prompt Injection**, **Insecure Output Handling** |
| 3 | Chat history | `GET /chat/<id>` | **IDOR**, **Stored XSS** (render sink) |
| 4 | Profile | `GET /profile` | — (account info only) |
| 5 | Hidden system prompt | *(internal, not a page)* | **System Prompt Leakage** |

---

## 4. The six vulnerabilities — where they live and how to keep them

Each one names the **location**, the **vulnerable pattern**, and the **keep-it-vulnerable rule**. The illustrative snippets show the *vulnerable construction to build* — not attack payloads.

### 4.1 SQL Injection — login form
- **Location:** `db.py`, the login lookup called by `POST /login`.
- **Pattern:** the query is assembled by inserting the username and password straight into the SQL string.
  ```python
  # VULNERABLE BY DESIGN — do not "fix" this
  query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
  ```
- **Keep vulnerable:** do **not** use parameterised queries / `?` placeholders for this query. (Other queries can be normal — only login must be injectable.)

### 4.2 IDOR — chat history
- **Location:** `GET /chat/<id>`.
- **Pattern:** the chat is fetched by `id` and rendered with **no check** that the chat belongs to the logged-in user.
- **Keep vulnerable:** do **not** add an ownership / authorization check. Any logged-in user can open any chat ID.

### 4.3 Stored XSS — message display
- **Location:** the template that renders `messages.content` (chat + history views).
- **Pattern:** message content is rendered with Jinja2's `| safe`, so stored HTML/JS executes in the browser.
  ```html
  <!-- VULNERABLE BY DESIGN -->
  <div class="message">{{ message.content | safe }}</div>
  ```
- **Keep vulnerable:** render message content with `| safe`. Do **not** escape it.

### 4.4 Prompt Injection — the LLM call
- **Location:** `llm.py`, invoked by `POST /chat/send`.
- **Pattern:** the user's raw text is passed into the model with no separation or guarding from the system instruction.
- **Keep vulnerable:** pass the user message through untouched — no input filtering, no delimiters, no guard prompts.

### 4.5 System Prompt Leakage — the LLM call
- **Location:** the hidden system-prompt constant in `llm.py`.
- **Pattern:** a hidden system prompt the model can be coaxed into revealing, with no output filter to catch leakage.
- **Recon bait (important):** the system prompt deliberately contains internal detail — table/column names, the `/chat/<id>` pattern, and a hint at an internal endpoint — so that **leaking it demonstrably feeds Chain 2** (recon → web-layer attack). Without this bait the second chain has nothing to chain *to*.
- **Keep vulnerable:** no output filtering that would strip system-prompt content from responses.

### 4.6 Insecure Output Handling — bot response rendering
- **Location:** the assistant's reply is stored as a message and rendered through the **same `| safe` sink** as §4.3.
- **Pattern:** the model's output is trusted and rendered unsanitised, so a prompt-injected reply containing HTML/JS runs in the victim's browser.
- **Keep vulnerable:** store and render assistant output exactly like a user message — raw, unsanitised. This is the bridge that turns a prompt injection into stored XSS.

---

## 5. LLM integration (`llm.py`)

- One **hidden system prompt** constant (carrying the recon bait from §4.5).
- Each request builds the message list: `[system_prompt, ...prior_messages, new_user_message]`.
- The new user message is inserted **raw** (that's §4.4).
- The model's reply is returned **raw** and stored as an `assistant` message (that's §4.6).
- Model name and API key come from `dvai/.env`. Use the cheapest model. The OpenAI account has a hard spending cap (~$5).

---

## 6. The two cross-layer chains — the contribution

This is where the grade lives. AVSA's job is to **trace one payload across the layer boundary**, which single-layer scanners cannot do.

**Chain 1 — Prompt Injection → Insecure Output Handling → Stored XSS** *(primary)*
1. Attacker sends a chat message containing a prompt injection that instructs the bot to emit an HTML/JS payload.
2. The bot's reply (carrying the payload) is stored as an `assistant` message (insecure output handling).
3. When that chat is later viewed — by the attacker, or by a victim reached via the §4.2 IDOR — the unsanitised `| safe` render fires the script. An LLM-layer flaw became a web-layer exploit.

**Chain 2 — System Prompt Leakage → Reconnaissance → SQLi / IDOR**
1. Attacker coaxes the bot into revealing the hidden system prompt (system prompt leakage).
2. The leaked prompt exposes internal detail (table/column names, the `/chat/<id>` pattern).
3. The attacker uses that recon to craft the §4.1 SQL injection or to enumerate §4.2 IDOR targets.

---

## 7. File structure

```
dvai/
├── app.py            # Flask routes
├── db.py             # SQLite connection + queries (SQLi lives in the login query)
├── llm.py            # OpenAI call + hidden system prompt (PI / SPL / IOH live here)
├── schema.sql        # table definitions (see DATABASE_SCHEMA.md)
├── seed.py           # optional: demo users/chats for testing IDOR
├── templates/
│   ├── base.html
│   ├── login.html
│   ├── register.html
│   ├── chat.html     # chat interface; renders messages with | safe  → XSS sink
│   ├── history.html  # /chat/<id> view (may reuse chat.html)
│   └── profile.html
├── static/
│   ├── style.css
│   └── main.js
├── requirements.txt
└── .env              # GITIGNORED: OPENAI_API_KEY, MODEL_NAME
```

---

## 8. Build order (maps to the sprints)

- **Sprint 1 — foundation:** accounts (register/login/logout), chat interface, LLM wired in via `.env`. App runs end to end. *Vulnerabilities are not deliberately planted yet — just stand the skeleton up.*
- **Sprint 2 — web-layer vulns:** make login injectable (§4.1), remove the ownership check on `/chat/<id>` (§4.2), switch message rendering to `| safe` (§4.3).
- **Sprint 3 — LLM-layer vulns:** add the hidden system prompt with recon bait (§4.5), confirm prompt injection is reachable (§4.4), confirm leakage works, confirm assistant output renders unsanitised (§4.6). All six live; both chains demonstrable.

---

## 9. Golden-rule reminder

If, while building `dvai/`, you find yourself sanitising input, escaping output, or parameterising the login query — **stop. That is a bug in this project.** DVAI is the patient, not the doctor.
