"""AVSA Probe / Session Layer.

The single point of contact between AVSA and the DVAI target. Every detection
module (built in later slices) sits on top of this layer and NEVER touches the
network directly — modules call Probe methods only.

AVSA treats DVAI strictly as a black box reached over HTTP. This module knows
only what an external attacker would: the login form fields, the chat endpoint,
and how a reply is rendered back into the page. It does not import DVAI, read its
source, or assume a route map / schema — those must be discovered or leaked by
later slices (that is the whole point of the project's contribution).
"""

from __future__ import annotations

import re
import secrets
import time
from dataclasses import dataclass
from typing import Any, Callable, Optional
from urllib.parse import urlsplit

import requests
from bs4 import BeautifulSoup


# --- configuration ----------------------------------------------------------

@dataclass
class Config:
    """Everything AVSA is allowed to know up front.

    Deliberately minimal — this is the black-box boundary. AVSA gets a base URL
    and ONE set of credentials, plus retry/timeout knobs. No route list, no
    wordlist, no schema, no second account: AVSA must discover or leak the rest
    in later slices, which is what makes a finding evidence rather than a given.
    """

    base_url: str
    username: str
    password: str
    default_retries: int = 3
    timeout: float = 60.0


# --- result objects ---------------------------------------------------------

@dataclass
class ChatResult:
    """Outcome of one chat() round-trip (POST /chat/send -> GET /chat/<id>)."""

    chat_id: Optional[str]
    reply: Optional[str]          # assistant text, tags stripped (.get_text())
    reply_html: Optional[str]     # raw inner markup of the assistant content div
    page_html: Optional[str]      # full GET /chat/<id> body
    status_ok: bool


@dataclass
class ConfirmResult:
    """Outcome of a confirm() harness run over a (possibly flaky) probe.

    LLM behaviour is non-deterministic, so a single try is not proof. confirm()
    repeats and records whether the invariant ever held, and on which attempt.
    """

    success: bool
    succeeded_on: Optional[int]   # 1-indexed attempt it first held on, else None
    n: int
    last_observation: Any = None

    @property
    def ratio(self) -> str:
        """e.g. leakage landing on try 4 of 5 -> "4/5"; never -> "0/5"."""
        if self.success and self.succeeded_on is not None:
            return f"{self.succeeded_on}/{self.n}"
        return f"0/{self.n}"


# --- the layer --------------------------------------------------------------

class Probe:
    """One authenticated HTTP session against DVAI, plus the primitives every
    detection module reuses: login, chat round-trips, and a retry harness."""

    def __init__(self, config: Config):
        self.config = config
        self.session = requests.Session()
        # One unique marker minted per run. Every module seeds its payloads with
        # this so injected content can be traced back to *this* AVSA run (and,
        # later, correlated across the layer boundary for chain detection).
        self.run_id = secrets.token_hex(3)

    @property
    def marker(self) -> str:
        """The per-run unique marker. Exposed so every module shares one value."""
        return self.run_id

    # -- url helper ----------------------------------------------------------

    def _url(self, path: str) -> str:
        """Join the configured base_url with a path, tolerant of trailing/leading
        slashes. A path that is already an absolute URL is returned unchanged."""
        if path.startswith(("http://", "https://")):
            return path
        return self.config.base_url.rstrip("/") + "/" + path.lstrip("/")

    # -- thin session wrappers ----------------------------------------------

    def get(self, path: str, **kwargs) -> requests.Response:
        kwargs.setdefault("timeout", self.config.timeout)
        return self.session.get(self._url(path), **kwargs)

    def post(self, path: str, data=None, allow_redirects: bool = True, **kwargs) -> requests.Response:
        kwargs.setdefault("timeout", self.config.timeout)
        return self.session.post(
            self._url(path), data=data, allow_redirects=allow_redirects, **kwargs
        )

    # -- auth ----------------------------------------------------------------

    def login(self) -> bool:
        """POST the credentials. DVAI signals success with a 302 whose Location
        points at /chat (and sets the session cookie on that response)."""
        resp = self.post(
            "/login",
            data={"username": self.config.username, "password": self.config.password},
            allow_redirects=False,
        )
        location = resp.headers.get("Location", "")
        return resp.status_code == 302 and "/chat" in location

    def is_authenticated(self) -> bool:
        """GET /chat without following redirects. An unauthenticated session is
        bounced to /login; an authenticated one renders the page (200)."""
        resp = self.get("/chat", allow_redirects=False)
        if resp.is_redirect and "/login" in resp.headers.get("Location", ""):
            return False
        return resp.status_code == 200

    # -- chat ----------------------------------------------------------------

    def chat(self, message: str, chat_id: Optional[str] = None) -> ChatResult:
        """Send one message and read the bot's reply.

        DVAI uses POST-redirect-GET: the reply is NOT in the POST response. We
        POST without following the redirect, read the new chat id from Location,
        then GET /chat/<id> and parse the last assistant message.

        With chat_id=None this creates a NEW chat (DVAI behaviour) — intended, so
        that an LLM probe run under confirm() gets a fresh, isolated chat per
        attempt rather than accumulating context across tries.
        """
        data = {"content": message}
        if chat_id is not None:
            data["chat_id"] = chat_id

        resp = self.post("/chat/send", data=data, allow_redirects=False)
        new_chat_id = self._extract_chat_id(resp.headers.get("Location", ""))
        if new_chat_id is None:
            # Empty/blank content hits DVAI's guard: it flashes and redirects to
            # /chat, not /chat/<id>. Nothing was stored; there is no reply to read.
            return ChatResult(
                chat_id=None, reply=None, reply_html=None, page_html=None, status_ok=False
            )

        page = self.get(f"/chat/{new_chat_id}")
        text, inner_html = self._parse_last_assistant(page.text)
        return ChatResult(
            chat_id=new_chat_id,
            reply=text,
            reply_html=inner_html,
            page_html=page.text,
            status_ok=page.status_code == 200,
        )

    # -- parsing helpers (pure; no network) ---------------------------------

    @staticmethod
    def _extract_chat_id(location: str) -> Optional[str]:
        """Pull the numeric <id> out of a /chat/<id> Location header (relative or
        a full URL). Returns None for /chat, "", /login, or anything without an id."""
        if not location:
            return None
        path = urlsplit(location).path
        match = re.search(r"/chat/(\d+)", path)
        return match.group(1) if match else None

    @staticmethod
    def _parse_last_assistant(html: str) -> tuple[Optional[str], Optional[str]]:
        """From a /chat/<id> page, return (text, inner_html) of the LAST assistant
        message's content div, or (None, None) if there isn't one.

        inner_html is the RAW inner markup: later modules use it to tell a live
        <script> node (DVAI rendered it with |safe) from text that was escaped to
        &lt;script&gt; — the difference between an XSS that fires and one that does not.
        """
        soup = BeautifulSoup(html, "html.parser")
        assistants = soup.select("div.message.assistant")
        if not assistants:
            return (None, None)
        content = assistants[-1].select_one("div.content")
        if content is None:
            return (None, None)
        return (content.get_text(), content.decode_contents())

    # -- non-determinism harness --------------------------------------------

    def confirm(
        self,
        probe: Callable[[], Any],
        invariant: Callable[[Any], bool],
        n: Optional[int] = None,
        delay: float = 0.0,
    ) -> ConfirmResult:
        """Run `probe()` up to n times; succeed if `invariant(observation)` holds
        on ANY attempt, recording which one. Defaults to Config.default_retries.

        This is the LLM non-determinism harness: a leakage/injection probe may
        only land on a later try, so the leakage detector will call this with n=5.
        """
        if n is None:
            n = self.config.default_retries

        last_observation: Any = None
        for attempt in range(1, n + 1):
            last_observation = probe()
            if invariant(last_observation):
                return ConfirmResult(
                    success=True, succeeded_on=attempt, n=n, last_observation=last_observation
                )
            if delay and attempt < n:
                time.sleep(delay)

        return ConfirmResult(
            success=False, succeeded_on=None, n=n, last_observation=last_observation
        )
