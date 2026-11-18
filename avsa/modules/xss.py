"""AVSA Stored XSS detection module (AVSA_SPEC §5.3).

Targets DVAI's message rendering: a stored message's content is rendered into the
chat page WITHOUT escaping (Jinja2 `| safe`), so HTML/JS placed in a stored message
comes back as a LIVE node rather than inert, escaped text. That is the stored XSS.

Unlike SQLi (proven from a fresh, credential-less session) this is committed FROM a
valid account: the attacker stores a payload as themselves and then reads it back
rendered. So this module uses the probe's AUTHENTICATED session.

Method:
  1. Log in (the configured user — Alice in the seed).
  2. Mint a per-run marker and wrap it in a <script> payload, then store it via
     probe.chat() (POST /chat/send -> a new chat id).
  3. GET /chat/<id> and parse the served HTML: the payload is a hit ONLY if the
     marker survives inside a LIVE <script> node (served unescaped). A marker that
     comes back as escaped text (&lt;script&gt;...) is NOT a hit — escaping is
     exactly the defence whose absence we are proving.

Honest scope: this proves the SERVED-UNESCAPED primitive (the page ships a live
script node carrying our marker). It does NOT drive a browser, so actual JS
execution is evidenced separately by manual screenshots. Cross-user delivery
(a victim rendering the attacker's payload) is Chain 1's job, not this module's.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from bs4 import BeautifulSoup


# --- finding ----------------------------------------------------------------

@dataclass
class Finding:
    """One module's verdict. Module-local for now; centralised when the reporter
    is built (Sprint 6), same pattern as sqli.Finding / idor.Finding."""

    id: str = "xss"
    name: str = "Stored XSS"
    layer: str = "web"
    present: bool = False
    severity: str = "High"
    owasp: str = "A03:2021 - Injection"
    primitives: list[str] = field(default_factory=list)
    attempts: Optional[int] = None              # web layer is deterministic
    evidence: dict[str, str] = field(default_factory=dict)
    notes: str = ""


# --- deterministic helpers (pure; unit-tested without a server) -------------

def is_payload_live_node(html: str, marker: str) -> bool:
    """True iff `marker` appears inside a LIVE <script> element in `html`.

    This is the whole XSS oracle. BeautifulSoup parses the served page the way a
    browser would: if DVAI rendered our payload with `| safe`, the marker lives
    inside a real <script> node and get_text() carries it. If DVAI escaped it, the
    "<script>" is inert text (the marker sits in a text node, never a <script>
    element) and this returns False — escaping is the defence we are disproving.
    """
    if not html or not marker:
        return False
    soup = BeautifulSoup(html, "html.parser")
    for script in soup.find_all("script"):
        if marker in script.get_text():
            return True
    return False


def _served_excerpt(html: str, marker: str, limit: int = 200) -> str:
    """Short excerpt of the served HTML around the marker, so evidence captures the
    offending fragment without dumping the whole page. Falls back to a plain
    head-of-page slice if the marker is absent."""
    if not html:
        return ""
    idx = html.find(marker)
    if idx == -1:
        return html[:limit].strip()
    start = max(0, idx - 20)
    return html[start:start + limit].strip()


# --- runner -----------------------------------------------------------------

def run(probe) -> Finding:
    """Store a marked <script> payload and check it is served back as a live node.

    Uses probe.login()/probe.chat()/probe.get() (the authenticated Alice session)
    — stored XSS is committed from a valid account, so we do NOT use a throwaway
    session.
    """
    finding = Finding()

    if not probe.login():
        finding.notes = (
            "Could not authenticate as the configured user; stored XSS is not "
            "testable without a valid session (the payload must be stored first)."
        )
        return finding

    # Per-run marker so the served payload traces back to THIS AVSA run (and, later,
    # can be correlated across the layer boundary for Chain 1 detection).
    marker = f"AVSA-XSS-{probe.run_id}"
    payload = f"<script>document.title='{marker}'</script>"

    result = probe.chat(payload)
    if result.chat_id is None:
        finding.notes = (
            "Payload POST did not yield a stored chat id (no /chat/<id> to read "
            "back); could not verify stored XSS."
        )
        return finding

    served_html = probe.get(f"/chat/{result.chat_id}").text
    live = is_payload_live_node(served_html, marker)

    if live:
        finding.primitives.append("stored_unescaped")

    finding.evidence["payload_sent"] = payload
    finding.evidence["run_marker"] = marker
    finding.evidence["bs4_verdict"] = "live_script_node" if live else "not_live"
    finding.evidence["served_fragment"] = _served_excerpt(served_html, marker)

    finding.present = bool(finding.primitives)
    finding.notes = (
        "Proves the SERVED-UNESCAPED primitive only: DVAI ships our stored payload "
        "back inside a live <script> node (no output escaping). Actual JS execution "
        "is evidenced by manual browser screenshots; cross-user delivery (a victim "
        "rendering the attacker's payload) is Chain 1's job, not this module's."
    )
    return finding
