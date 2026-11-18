"""Unit tests for the deterministic oracle in avsa.modules.prompt_injection.

These cover the pure helper (marker_present) only — no live server, no bot calls.
The live end-to-end run against DVAI (the ladder actually firing through the
confirm() harness) is performed separately by the user, since it depends on the
non-deterministic model.
"""

from avsa.modules.prompt_injection import marker_present


MARKER = "PROMPTINJ-abc123"


# --- marker_present ---------------------------------------------------------

def test_marker_present_when_echoed():
    # The bot echoed our exact marker: injection landed.
    reply = f"Sure, here is the token: {MARKER}"
    assert marker_present(reply, MARKER) is True


def test_marker_absent_in_refusal():
    # A refusal carries no marker.
    reply = "I can't help with that."
    assert marker_present(reply, MARKER) is False


def test_empty_or_none_reply_is_false():
    assert marker_present("", MARKER) is False
    assert marker_present(None, MARKER) is False


def test_different_marker_is_false_for_our_marker():
    # Another run's marker is echoed, but it is not the marker WE minted.
    reply = "Here is the token: PROMPTINJ-999999"
    assert marker_present(reply, MARKER) is False
