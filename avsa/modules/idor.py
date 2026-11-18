"""AVSA IDOR / Broken Access Control detection module (AVSA_SPEC §5.2).

Targets DVAI's chat-history view: /chat/<int:chat_id> (app.py:157) looks the chat
up by URL id with NO ownership check — db.get_chat / db.get_messages are keyed on
the id alone, never compared to the session user. So a logged-in user can read any
other user's conversation simply by changing the id. That is the IDOR.

Unlike the SQLi module (which proves an *external* flaw from a fresh, credential-
less session), IDOR is a privilege violation committed FROM a valid account: Alice
stays Alice and reaches data she is not entitled to. So this module deliberately
uses the probe's AUTHENTICATED session.

Method:
  1. Log in (the configured user — Alice in the seed).
  2. Establish the entitled baseline: the user's OWN chat ids, scraped from the
     sidebar on GET /chat (ul.chatlist links).
  3. Enumerate ids 1..ENUM_MAX; for each id NOT in the own-set, GET /chat/<id>.
  4. A hit = HTTP 200 whose CONVERSATION PANE contains rendered messages
     (div.message blocks). 404 means "no such chat" (not a hit).

Critical subtlety: the sidebar always shows the logged-in user's OWN chats, even
while viewing someone else's chat via the IDOR. Success is therefore judged on the
conversation pane (div.message), never the sidebar — otherwise the module would
confirm itself on its own chats.

Scope: /admin/chats is NOT probed. It does not exist in DVAI — it is a 404 recon-
bait honeypot (AVSA_SPEC §6.5). The genuine, reproducible IDOR is /chat/<id>
cross-user access only.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

from bs4 import BeautifulSoup


# How far to enumerate chat ids from the outside. Small on purpose: the seed uses
# low sequential integer PKs, and this is a proof of access control failure, not a
# bulk scrape.
ENUM_MAX = 20


# --- finding ----------------------------------------------------------------

@dataclass
class Finding:
    """One module's verdict. Module-local for now; centralised when the reporter
    is built (Sprint 6), same pattern as sqli.Finding."""

    id: str = "idor"
    name: str = "IDOR (Broken Access Control)"
    layer: str = "web"
    present: bool = False
    severity: str = "High"
    owasp: str = "A01:2021 - Broken Access Control"
    primitives: list[str] = field(default_factory=list)
    attempts: Optional[int] = None              # web layer is deterministic
    evidence: dict[str, str] = field(default_factory=dict)  # chat id -> evidence
    notes: str = ""


# --- deterministic helpers (pure; unit-tested without a server) -------------

def extract_own_ids(html: str) -> set[int]:
    """Return the set of chat ids the logged-in user owns, scraped from the
    sidebar (ul.chatlist links of the form /chat/<n>). This is the entitled
    baseline — ids reachable here are NOT IDOR."""
    soup = BeautifulSoup(html or "", "html.parser")
    ids: set[int] = set()
    for anchor in soup.select("ul.chatlist a"):
        match = re.search(r"/chat/(\d+)", anchor.get("href", ""))
        if match:
            ids.add(int(match.group(1)))
    return ids


def conversation_served(html: str) -> bool:
    """True if the page's CONVERSATION PANE rendered messages (div.message blocks).

    div.message only appears in the conversation pane in chat.html — the sidebar
    uses li/a — so its presence is a reliable signal that an actual conversation
    was served, independent of the always-present sidebar.
    """
    soup = BeautifulSoup(html or "", "html.parser")
    return len(soup.select("div.message")) > 0


def classify_idor(status_code: int, conversation_present: bool, owned: bool) -> bool:
    """Truth table for a single /chat/<id> probe:
      200 + conversation served + NOT owned -> IDOR hit
      owned (the user's own chat)            -> not a hit
      404 / anything else                    -> not a hit
    """
    return status_code == 200 and conversation_present and not owned


def _conversation_summary(html: str, limit: int = 150) -> tuple[int, str]:
    """(count of rendered messages, first ~limit chars of the first message body).
    Used for short evidence — never dumps a whole conversation."""
    soup = BeautifulSoup(html or "", "html.parser")
    messages = soup.select("div.message")
    first_content = ""
    if messages:
        content = messages[0].select_one("div.content")
        if content is not None:
            first_content = content.get_text().strip()[:limit]
    return len(messages), first_content


# --- runner -----------------------------------------------------------------

def run(probe) -> Finding:
    """Enumerate /chat/<id> from the authenticated session and report cross-user
    reads. Uses probe.login()/probe.get (the authenticated Alice session) — IDOR
    is committed from a valid account, so we do NOT use a throwaway session."""
    finding = Finding()

    if not probe.login():
        finding.notes = (
            "Could not authenticate as the configured user; IDOR is not testable "
            "without a valid session."
        )
        return finding

    # Entitled baseline: the user's own chat ids (sidebar). Reaching these is not
    # a violation, so they are excluded from the enumeration.
    own_page = probe.get("/chat")
    own_ids = extract_own_ids(own_page.text)

    for chat_id in range(1, ENUM_MAX + 1):
        if chat_id in own_ids:
            continue
        resp = probe.get(f"/chat/{chat_id}")
        served = conversation_served(resp.text)
        if classify_idor(resp.status_code, served, owned=False):
            count, snippet = _conversation_summary(resp.text)
            finding.evidence[str(chat_id)] = (
                f"GET /chat/{chat_id} -> HTTP {resp.status_code}; id not in own-set "
                f"{sorted(own_ids)}; conversation served ({count} message block(s)); "
                f"first message: {snippet!r}"
            )

    if finding.evidence:
        finding.primitives.append("cross_user_read")
    finding.present = bool(finding.primitives)

    finding.notes = (
        "IDOR via /chat/<id>: chat fetched by id with no ownership check "
        "(app.py:157, db.get_chat/get_messages keyed on id only). Success judged "
        "on the conversation pane (div.message), not the always-present sidebar. "
        "/admin/chats NOT probed — it is a 404 recon-bait honeypot, not a live "
        "route (AVSA_SPEC §6.5)."
    )
    return finding
