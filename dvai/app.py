"""DVAI — minimal AI customer-support chatbot (Flask).

Sprint 1: a CLEAN foundation. Register, log in, chat with the OpenAI-backed bot,
and have the conversation persisted. None of the six deliberate vulnerabilities
are planted yet — those arrive in Sprints 2–3. So the spots that later become
vulnerable are built the secure way here:
  * login uses a parameterised query        (SQLi planted in Sprint 2)
  * /chat/<id> enforces an ownership check   (IDOR planted in Sprint 2)
  * messages render with Jinja2 autoescape   (Stored XSS planted in Sprint 2)
"""

import os
import secrets
import sqlite3
from functools import wraps

from flask import (
    Flask, g, redirect, render_template, request, session, url_for, flash, abort
)

import db
import llm

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-secret-change-me")

# Create the SQLite schema on first boot, and close connections after requests.
with app.app_context():
    db.init_db()
app.teardown_appcontext(db.close_db)


# --- helpers ----------------------------------------------------------------

def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


@app.context_processor
def inject_user():
    """Make the current user available to every template (for the nav bar)."""
    user = None
    uid = session.get("user_id")
    if uid is not None:
        user = db.get_user_by_id(uid)
    return {"current_user": user}


# --- routes -----------------------------------------------------------------

@app.route("/")
def index():
    if session.get("user_id"):
        return redirect(url_for("chat"))
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        display_name = request.form.get("display_name", "").strip()

        if not username or not password:
            flash("Username and password are required.")
            return render_template("register.html")

        try:
            db.create_user(username, password, display_name or None)
        except sqlite3.IntegrityError:
            flash("That username is already taken.")
            return render_template("register.html")

        flash("Account created — please log in.")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = db.verify_login(username, password)
        if user is None:
            flash("Invalid username or password.")
            return render_template("login.html")

        session.clear()
        session["user_id"] = user["id"]
        return redirect(url_for("chat"))

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/guest")
def guest():
    if session.get("user_id") is None:
        guest_username = f"guest_{secrets.token_hex(4)}"
        guest_password = secrets.token_hex(8)
        user_id = db.create_user(guest_username, guest_password, "Guest")
        session.clear()
        session["user_id"] = user_id

    embed = request.args.get("embed")
    return redirect(url_for("chat", embed=embed) if embed else url_for("chat"))


@app.route("/chat")
@login_required
def chat():
    user_id = session["user_id"]
    chats = db.get_chats_for_user(user_id)

    # "New chat" (sidebar) links here with ?new=1 to force the blank-composer
    # state instead of reopening the most recent chat. No row is created here
    # -- chat_send() below already creates a chat lazily whenever it gets a
    # message with no chat_id, which this reuses unchanged.
    forced_new = request.args.get("new")

    # Show the most recent chat by default, unless a blank chat was
    # explicitly requested (or none exist yet).
    active_chat = None if forced_new else (chats[0] if chats else None)
    messages = db.get_messages(active_chat["id"]) if active_chat else []

    # embed=1 (set by the AVSA-page chat widget, via /guest) hides the topbar
    # and chat-list sidebar so DVAI's real chat fits a small embedded panel.
    # Purely presentational - every route below still runs exactly as normal.
    embed = request.args.get("embed")

    return render_template(
        "chat.html", chats=chats, active_chat=active_chat, messages=messages,
        embed=embed,
    )


@app.route("/chat/send", methods=["POST"])
@login_required
def chat_send():
    user_id = session["user_id"]
    content = request.form.get("content", "").strip()
    chat_id = request.form.get("chat_id", "").strip()

    embed = request.form.get("embed")

    if not content:
        flash("Message cannot be empty.")
        return redirect(url_for("chat", embed=embed) if embed else url_for("chat"))

    # Resolve the target chat: an existing owned one, or a freshly created one.
    target = None
    if chat_id:
        target = db.get_chat(chat_id)
        if target is None or target["user_id"] != user_id:
            target = None  # ignore someone else's id; fall through to new chat
    if target is None:
        new_id = db.create_chat(user_id, title=content[:40])
        target = db.get_chat(new_id)

    # Store the user's turn, ask the model, store the assistant's turn.
    db.add_message(target["id"], "user", content)
    history = [
        {"role": m["role"], "content": m["content"]}
        for m in db.get_messages(target["id"])
    ]
    reply = llm.get_reply(history)
    db.add_message(target["id"], "assistant", reply)

    return redirect(
        url_for("chat_history", chat_id=target["id"], embed=embed) if embed
        else url_for("chat_history", chat_id=target["id"])
    )


@app.route("/chat/<int:chat_id>")
@login_required
def chat_history(chat_id):
    user_id = session["user_id"]
    target = db.get_chat(chat_id)

    # VULNERABLE BY DESIGN (DVAI_SPEC §4.2) — IDOR. The chat is served by id with
    # NO ownership check, so any logged-in user can open any other user's chat by
    # guessing/enumerating the id (e.g. alice opening bob's /chat/2). Do NOT add an
    # authorization check here. The existence guard below is not auth — a missing id
    # legitimately 404s; it does not compare ownership.
    if target is None:
        abort(404)

    chats = db.get_chats_for_user(user_id)
    messages = db.get_messages(chat_id)
    embed = request.args.get("embed")
    return render_template(
        "chat.html", chats=chats, active_chat=target, messages=messages,
        embed=embed,
    )


@app.route("/profile")
@login_required
def profile():
    user = db.get_user_by_id(session["user_id"])
    return render_template("profile.html", user=user)


if __name__ == "__main__":
    # Local lab use only — never expose DVAI publicly.
    app.run(host="127.0.0.1", port=5000, debug=True)
