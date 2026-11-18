# -*- coding: utf-8 -*-
"""Tests for avsa/adapters/local_cli.py: a second,
genuinely non-HTTP adapter proving the LLM-layer modules' login()/chat()/
confirm() surface is transport-agnostic, not tied to avsa.probe.Probe's HTTP
implementation. These exercise the adapter directly (not through a live
detection-module attack run -- that stays the user's to perform)."""
from avsa.adapters.local_cli import LocalCliAdapter, LocalConfig, LocalToyAgent
from avsa.probe import ChatResult, ConfirmResult


def test_login_always_succeeds_no_http_involved():
    adapter = LocalCliAdapter()
    assert adapter.login() is True


def test_chat_returns_a_real_chat_result_shaped_object():
    adapter = LocalCliAdapter()
    result = adapter.chat("hello")
    # Same dataclass Probe returns -- not a re-implementation,
    # so any code written against Probe's ChatResult works unmodified here.
    assert isinstance(result, ChatResult)
    assert result.status_ok is True
    assert result.chat_id == "1"
    assert "hello" in result.reply


def test_chat_without_chat_id_starts_a_new_conversation_each_time():
    adapter = LocalCliAdapter()
    first = adapter.chat("first message")
    second = adapter.chat("second message")  # chat_id=None again -> new chat
    assert first.chat_id != second.chat_id


def test_chat_with_chat_id_continues_the_same_conversation():
    adapter = LocalCliAdapter()
    first = adapter.chat("first message")
    second = adapter.chat("follow-up", chat_id=first.chat_id)
    assert second.chat_id == first.chat_id
    assert adapter.agent._history[first.chat_id] == [
        "first message",
        "(local agent) received: first message",
        "follow-up",
        "(local agent) received: follow-up",
    ]


def test_each_adapter_instance_gets_its_own_run_id_marker():
    a = LocalCliAdapter()
    b = LocalCliAdapter()
    assert a.run_id != b.run_id
    assert a.marker == a.run_id


def test_confirm_succeeds_on_the_attempt_the_invariant_first_holds():
    adapter = LocalCliAdapter()
    calls = {"n": 0}

    def probe():
        calls["n"] += 1
        return calls["n"]

    result = adapter.confirm(probe, invariant=lambda obs: obs == 3, n=5)
    assert isinstance(result, ConfirmResult)
    assert result.success is True
    assert result.succeeded_on == 3
    assert result.ratio == "3/5"


def test_confirm_exhausts_all_attempts_when_invariant_never_holds():
    adapter = LocalCliAdapter()
    result = adapter.confirm(lambda: "nope", invariant=lambda obs: obs == "yes", n=3)
    assert result.success is False
    assert result.succeeded_on is None
    assert result.ratio == "0/3"


def test_custom_agent_can_be_injected():
    class EchoUpperAgent(LocalToyAgent):
        def send(self, message, chat_id):
            cid, _ = super().send(message, chat_id)
            return cid, message.upper()

    adapter = LocalCliAdapter(config=LocalConfig(username="tester"), agent=EchoUpperAgent())
    result = adapter.chat("shout this")
    assert result.reply == "SHOUT THIS"
