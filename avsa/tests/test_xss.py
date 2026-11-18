"""Unit tests for the deterministic parsing logic in avsa.modules.xss.

These cover the pure XSS oracle (is_payload_live_node) only — no live server is
required. The live end-to-end run against DVAI (storing the payload and reading it
back rendered) is performed separately by the user, with browser screenshots for
actual JS execution.
"""

from avsa.modules.xss import is_payload_live_node


MARKER = "AVSA-XSS-abc123"
PAYLOAD = f"<script>document.title='{MARKER}'</script>"


# --- is_payload_live_node ---------------------------------------------------

def test_live_script_with_marker_is_true():
    # DVAI rendered the payload with |safe: it comes back as a real <script> node.
    html = f"""
    <div class="message assistant"><div class="content">{PAYLOAD}</div></div>
    """
    assert is_payload_live_node(html, MARKER) is True


def test_escaped_payload_is_false():
    # Same payload, but HTML-escaped (the defence): inert text, not a <script> node.
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
    other = "AVSA-XSS-999999"
    html = f"<div class='content'><script>document.title='{other}'</script></div>"
    assert is_payload_live_node(html, MARKER) is False
