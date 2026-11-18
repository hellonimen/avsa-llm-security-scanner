# -*- coding: utf-8 -*-
"""Local, non-HTTP conversational adapter.

Implements the same login()/chat()/confirm() surface as avsa.probe.Probe, this
time against something that is NOT a web application at all: a plain local
Python object exchanging messages in-process -- no HTTP, no browser, no
server, no base_url.

This is the narrow, honest version of "abstract the transport": rather than
refactoring avsa/probe.py into a shared base class (weighed and deliberately
rejected as too risky late in the project), this adds a second, non-HTTP proof
that the LLM-layer modules' login()/chat()/confirm() contract is genuinely
transport-agnostic, without touching Probe or the DVAI scan at all.

WHAT THIS DOES NOT CLAIM: LocalToyAgent below is a deliberately simple,
deterministic stand-in -- not a real LLM, and not wired to OpenAI here (this
environment has no funded key to verify one against). The point being
proven is the SHAPE of the interface -- that prompt_injection.py /
system_prompt_leakage.py / insecure_output.py could run against ANY object
satisfying login()/chat()/confirm(), completely unmodified -- not a new
live-attack result. Swap LocalToyAgent for a real local/CLI-based
conversational AI (or a direct model-API client) without touching
LocalCliAdapter's own method shapes at all; that boundary is the actual
thing point 4 asks for. Pointing a real detection module at it, and running
it, is left to the user.
"""
from __future__ import annotations

import secrets
import time
from dataclasses import dataclass
from typing import Any, Callable, Optional

from avsa.probe import ChatResult, ConfirmResult


@dataclass
class LocalConfig:
    """Config for LocalCliAdapter. Deliberately has no base_url/HTTP fields at
    all -- there is no network boundary here, which is the whole point."""

    username: str = "local-user"
    default_retries: int = 3


class LocalToyAgent:
    """A deliberately minimal, deterministic stand-in for "some non-web
    conversational AI" -- e.g. what a CLI agent or a direct model-API
    integration would look like from the adapter's side. Per-chat_id history
    is kept (mirroring DVAI's own per-chat conversation model) purely so
    chat() has something real to round-trip against."""

    def __init__(self) -> None:
        self._history: dict[str, list[str]] = {}
        self._next_id = 1

    def send(self, message: str, chat_id: Optional[str]) -> tuple[str, str]:
        if chat_id is None:
            chat_id = str(self._next_id)
            self._next_id += 1
            self._history[chat_id] = []
        self._history.setdefault(chat_id, []).append(message)
        reply = f"(local agent) received: {message}"
        self._history[chat_id].append(reply)
        return chat_id, reply


class LocalCliAdapter:
    """Same login()/chat()/confirm() surface as avsa.probe.Probe, backed by a
    LocalToyAgent instead of an HTTP session -- see module docstring."""

    def __init__(
        self,
        config: Optional[LocalConfig] = None,
        agent: Optional[LocalToyAgent] = None,
    ) -> None:
        self.config = config or LocalConfig()
        self.agent = agent or LocalToyAgent()
        # Same per-run marker convention as Probe, so a module
        # run against this adapter still gets a real, correlatable token.
        self.run_id = secrets.token_hex(3)

    @property
    def marker(self) -> str:
        return self.run_id

    def login(self) -> bool:
        """No auth concept for a local, in-process agent -- always succeeds.
        Kept as a real method (rather than omitted) purely so this adapter
        stays interface-compatible with Probe's login()."""
        return True

    def chat(self, message: str, chat_id: Optional[str] = None) -> ChatResult:
        new_chat_id, reply = self.agent.send(message, chat_id)
        return ChatResult(
            chat_id=new_chat_id,
            reply=reply,
            reply_html=reply,
            page_html=None,
            status_ok=True,
        )

    # Duplicated from Probe, not shared via a base class -- same reasoning
    # as elsewhere in this module: ~15 lines of logic with zero target-specific
    # content, so duplicating it is cheaper and safer than refactoring the
    # file Track A depends on, this close to the deadline.
    def confirm(
        self,
        probe: Callable[[], Any],
        invariant: Callable[[Any], bool],
        n: Optional[int] = None,
        delay: float = 0.0,
    ) -> ConfirmResult:
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
        return ConfirmResult(success=False, succeeded_on=None, n=n, last_observation=last_observation)
