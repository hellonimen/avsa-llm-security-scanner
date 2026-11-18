"""Unit tests for the served-HTML detection used by avsa.modules.insecure_output.

Detection reuses the proven live-node oracle (xss.is_payload_live_node); these
tests exercise it in THIS module's context with served-HTML fixtures that stand in
for what DVAI would render for BOT-authored output (same |safe sink as user input).
No live server, no bot calls — the live end-to-end run against DVAI (inducing the
bot to emit the payload and reading it back rendered) is performed separately by
the user, with browser screenshots for actual JS execution.
"""

from avsa.modules.insecure_output import is_payload_live_node


MARKER = "AVSA-OUTPUT-abc123"
PAYLOAD = f"<script>document.title='{MARKER}'</script>"


# --- served-unescaped bot output --------------------------------------------

def test_bot_output_live_script_is_true():
    # DVAI rendered the BOT's reply with |safe: the payload comes back as a real
    # <script> node — the app failed to encode model output.
    html = f"""
    <div class="message assistant"><div class="content">{PAYLOAD}</div></div>
    """
    assert is_payload_live_node(html, MARKER) is True


def test_escaped_bot_output_is_false():
    # Same payload, but HTML-escaped: inert text, not a <script> node (the defence
    # whose absence this module proves).
    html = (
        '<div class="message assistant"><div class="content">'
        f"&lt;script&gt;document.title='{MARKER}'&lt;/script&gt;"
        "</div></div>"
    )
    assert is_payload_live_node(html, MARKER) is False


def test_no_marker_is_false():
    # A live <script> exists but does not carry our marker -> not our hit.
    html = '<div class="content"><script>console.log("hi")</script></div>'
    assert is_payload_live_node(html, MARKER) is False


def test_different_runid_is_false_for_our_marker():
    # Another run's marker is live, but it is not the marker WE are looking for.
    other = "AVSA-OUTPUT-999999"
    html = f"<div class='content'><script>document.title='{other}'</script></div>"
    assert is_payload_live_node(html, MARKER) is False
