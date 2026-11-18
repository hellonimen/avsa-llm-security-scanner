"""AVSA Chain Correlation Engine — CORE (shared-token detection).

This is the atomic operation both cross-layer chains are built on. The six
detection modules each embed a unique per-run marker in their evidence:

    * xss.py              -> "AVSA-XSS-<runid>"     (evidence["run_marker"])
    * insecure_output.py  -> "AVSA-OUTPUT-<runid>"  (evidence["marker"])
    * prompt_injection.py -> "PROMPTINJ-<runid>"    (evidence["marker"])

The <runid> is the SAME for every module in one AVSA run (it comes from
probe.run_id, a 6-char hex token from secrets.token_hex(3)). The engine proves a
chain by showing that the SAME <runid> threads through several findings — that
shared token is the causal proof (taint tracking), not coincidence.

The shared-token PRIMITIVE (extract_runid / find_shared_token) is the core; the
chain ASSERTIONS build on top of it. Slice 2 adds Chain 1 (assert_chain1);
Chain 2 is a later slice.

DESIGN — dependency injection: the engine is HANDED a list of findings; it never
fetches or runs anything. Every function here is pure and deterministic, so the
whole engine is unit-testable with fabricated findings and no live bot.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Optional

# --- marker grammar ---------------------------------------------------------

# Every AVSA marker is "<PREFIX>-<runid>" where <runid> is exactly 6 lowercase
# hex chars (secrets.token_hex(3)). We accept the three concrete prefixes the
# modules use today (AVSA-XSS-, AVSA-OUTPUT-, PROMPTINJ-) plus a generic
# AVSA-<WORD>- form so a new module's marker is picked up without touching this
# file. The runid is the trailing capture group — the shared part we correlate on.
_MARKER_RE = re.compile(
    r"(?:AVSA-[A-Z0-9]+|PROMPTINJ)-([0-9a-f]{6})\b"
)

# Evidence keys the modules are known to stash a marker in (directly, or inside a
# longer payload/injection string). We do not rely on this list being exhaustive
# — extract_runid also scans every string value in the evidence dict — but
# checking these first keeps the common case cheap and explicit.
_MARKER_KEYS = (
    "marker",
    "run_marker",
    "induced_payload",
    "payload_sent",
    "payload",
    "injection_sent",
)


# --- extractor --------------------------------------------------------------

def extract_runid(finding) -> Optional[str]:
    """Pull the shared per-run token (the <runid>) out of ANY finding.

    Regardless of which module produced the finding, this looks through its
    evidence for an AVSA marker and returns the trailing 6-hex-char runid, e.g.:

        "AVSA-XSS-7f3a2c"    -> "7f3a2c"
        "PROMPTINJ-7f3a2c"   -> "7f3a2c"
        "AVSA-OUTPUT-7f3a2c" -> "7f3a2c"
        "...verbatim: <script>...AVSA-OUTPUT-7f3a2c..." -> "7f3a2c"

    Returns None if the finding carries no recognisable marker.

    Tolerant by design: it checks the well-known evidence keys first, then falls
    back to scanning every string value in the evidence dict, so a marker buried
    inside a longer payload/injection string is still found.
    """
    evidence = getattr(finding, "evidence", None)
    if not isinstance(evidence, dict):
        return None

    # Preferred keys first (cheap, explicit).
    for key in _MARKER_KEYS:
        value = evidence.get(key)
        runid = _runid_from(value)
        if runid is not None:
            return runid

    # Fallback: any string value anywhere in the evidence dict.
    for value in evidence.values():
        runid = _runid_from(value)
        if runid is not None:
            return runid

    return None


def _runid_from(value) -> Optional[str]:
    """Return the runid captured from a single (possibly non-string) value, or None."""
    if not isinstance(value, str):
        return None
    match = _MARKER_RE.search(value)
    return match.group(1) if match else None


# --- correlation primitive --------------------------------------------------

def find_shared_token(findings: list) -> Optional[dict]:
    """Detect the SAME per-run token appearing across two or more findings.

    This is the core correlation primitive. It extracts the runid from each
    finding (skipping any that carry no token), and if two or more findings share
    the SAME runid it returns:

        {"runid": "<the shared runid>",
         "linked_finding_ids": [<id of each finding carrying it>]}

    Returns None if no two findings share a token — that None is the important
    negative: different runids mean the findings are unrelated (coincidence, not a
    chain), so nothing is linked.

    Pure and deterministic. For this slice we assume one AVSA run = one runid; if
    several runids somehow appear, the group sharing the MOST COMMON runid is
    linked and the others are noted under "other_runids", keeping the primitive
    simple and predictable.
    """
    # (runid, finding_id) for every finding that carries a marker, in input order.
    tagged: list[tuple[str, object]] = []
    for finding in findings:
        runid = extract_runid(finding)
        if runid is not None:
            tagged.append((runid, getattr(finding, "id", None)))

    if not tagged:
        return None

    counts = Counter(runid for runid, _ in tagged)
    # most_common(1) is deterministic: Counter preserves first-seen order for ties.
    shared_runid, occurrences = counts.most_common(1)[0]
    if occurrences < 2:
        return None

    result = {
        "runid": shared_runid,
        "linked_finding_ids": [
            fid for runid, fid in tagged if runid == shared_runid
        ],
    }

    other_runids = sorted(r for r in counts if r != shared_runid)
    if other_runids:
        result["other_runids"] = other_runids

    return result


# --- chain result -----------------------------------------------------------

@dataclass
class Chain:
    """The verdict for one cross-layer chain. Built ON TOP of the shared-token
    primitive: a chain is asserted only when its constituent findings are present
    AND the causal token link holds between the steps that must share it.

    `asserted` False always carries a `reason`; True carries the full custody
    trail, the literal shared runid, and the falsifiability argument."""

    id: str
    name: str
    asserted: bool = False
    constituents: list[str] = field(default_factory=list)
    shared_artifact: Optional[str] = None
    custody: list[str] = field(default_factory=list)
    provenance: dict = field(default_factory=dict)
    falsifiability_note: str = ""
    reason: str = ""


# --- Chain 1 assertion ------------------------------------------------------

_CHAIN1_NAME = "Chain 1: Prompt Injection -> Insecure Output -> IDOR delivery"


def _by_id(findings: list) -> dict:
    """Index findings by their .id (last one wins on a duplicate id)."""
    return {getattr(f, "id", None): f for f in findings}


def _present(finding) -> bool:
    """A finding counts as present only if it exists and its .present is True."""
    return finding is not None and bool(getattr(finding, "present", False))


def assert_chain1(findings: list) -> Chain:
    """Assert Chain 1 (AVSA_SPEC §6.4) from the findings handed in.

    Chain 1 is: prompt injection -> bot emits XSS payload -> insecure output
    handling serves it unescaped -> IDOR delivers it cross-user -> (manual) it
    fires in the victim's browser.

    The three AUTOMATED constituents are prompt_injection, insecure_output and
    idor. The proof it is a real chain (not coincidence) is the shared per-run
    token: prompt_injection induces the payload and insecure_output serves that
    SAME bot-authored payload, so those two must carry the SAME runid. IDOR is the
    cross-user delivery channel — it does NOT carry the XSS marker itself, so we
    require it to be present (an unowned cross-user read) but not token-bearing.
    Browser EXECUTION is not claimed by AVSA; it is carried by a manual,
    token-linked screenshot.

    Pure: operates only on the injected findings, no probe/network/bot code.
    """
    chain = Chain(id="chain1", name=_CHAIN1_NAME)

    index = _by_id(findings)
    injection = index.get("prompt_injection")
    insecure_output = index.get("insecure_output")
    idor = index.get("idor")

    # 1. All three constituents must exist and be present.
    for cid, finding in (
        ("prompt_injection", injection),
        ("insecure_output", insecure_output),
        ("idor", idor),
    ):
        if not _present(finding):
            state = "absent" if finding is None else "present but not confirmed (present=False)"
            chain.reason = f"constituent '{cid}' is {state}; Chain 1 cannot be asserted."
            return chain

    # 2. The token link: injection and insecure_output must share the same runid.
    #    (IDOR is the delivery channel and does not carry the XSS marker.)
    injection_runid = extract_runid(injection)
    output_runid = extract_runid(insecure_output)

    if (
        injection_runid is None
        or output_runid is None
        or injection_runid != output_runid
    ):
        chain.reason = (
            "constituents present but injection/insecure_output tokens do not "
            "match (coincidence, not a chain)"
        )
        return chain

    # 3. All present AND injection/insecure_output share the token -> asserted.
    runid = injection_runid
    chain.asserted = True
    chain.shared_artifact = runid
    chain.constituents = ["prompt_injection", "insecure_output", "idor"]
    chain.custody = [
        f"1. Prompt injection induced the bot to emit payload carrying token "
        f"{runid} (finding: prompt_injection).",
        f"2. Insecure output handling served that bot-authored payload unescaped, "
        f"same token {runid} (finding: insecure_output).",
        f"3. IDOR provides cross-user delivery of stored content (finding: idor).",
        f"4. (Manual) execution in the victim's browser is evidenced by "
        f"screenshot, linked by the same token {runid}.",
    ]
    chain.provenance = {
        "automated_steps": "strict-artifact-linked",
        "execution": "manually-evidenced-token-linked",
    }
    chain.falsifiability_note = (
        f"If this were coincidence, the served payload would contain token "
        f"{runid} without AVSA having injected it. Impossible: {runid} is minted "
        f"fresh at run start and exists nowhere until the injection places it. Its "
        f"presence across the injection and insecure-output findings can only be "
        f"explained by the upstream step causing it."
    )
    return chain


# --- Chain 2 assertion ------------------------------------------------------

_CHAIN2_NAME = "Chain 2: System Prompt Leakage -> recon -> web-layer attacks"

# The route the leak advertises but which does NOT resolve in DVAI — a 404
# recon-bait honeypot (AVSA_SPEC §6.5 committed revision). Leaked recon may name
# it, but it must never be counted as a live attack strand.
_HONEYPOT_ROUTE = "/admin/chats"
_CHAT_ID_ROUTE = "/chat/<id>"


def assert_chain2(findings: list) -> Chain:
    """Assert Chain 2 (AVSA_SPEC §6.5, incl. the committed honeypot revision).

    Chain 2 is: system prompt leakage spills recon (schema + routes) which then
    informs the web-layer attacks (SQLi via leaked columns like `password`; IDOR
    via the leaked /chat/<id> addressing pattern).

    HONESTLY WEAKER THAN CHAIN 1. Chain 1 rests on an unforgeable per-run taint
    token; Chain 2 rests on RECON OVERLAP — the leaked strings are things the web
    modules might plausibly have targeted anyway. So this link is labelled
    "correlated, provenance-qualified", never "strict-artifact-linked", and there
    is no single shared_artifact token.

    Honeypot handling: if the leak advertises /admin/chats it is recorded as a
    "leaked but dead recon lead" (a 404 recon-bait honeypot) and NOT counted as a
    live strand. The real chain rests on leaked SCHEMA -> SQLi and leaked
    /chat/<id> -> IDOR.

    Pure: operates only on the injected findings, no probe/network/bot code.
    """
    chain = Chain(id="chain2", name=_CHAIN2_NAME)

    index = _by_id(findings)
    leakage = index.get("system_prompt_leakage")

    # 1. Leakage must be present — no leak, no recon to drive anything.
    if not _present(leakage):
        chain.reason = (
            "system prompt leakage not present; no recon to drive web attacks"
        )
        return chain

    # 2. Structured recon must have been captured.
    recon = getattr(leakage, "leaked_recon", None) or {}
    if not recon:
        chain.reason = "leakage present but no structured recon captured"
        return chain

    schema = recon.get("schema", {}) or {}
    routes = recon.get("routes", []) or []

    # 3. Gather the present web findings the recon could have informed.
    sqli = index.get("sqli")
    idor = index.get("idor")

    # 4. Recon-overlap check — one strand per leaked lead that meets a present
    #    web finding. These are supporting strands, not taint proofs.
    strands: list[str] = []            # web finding ids that formed a strand
    custody: list[str] = [
        f"1. System prompt leakage disclosed recon: {_recon_summary(recon)} "
        f"(finding: system_prompt_leakage)."
    ]
    step = 2

    schema_leaked = bool(
        schema.get("tables")
        or schema.get("columns")
        or schema.get("plaintext_passwords")
    )
    if schema_leaked and _present(sqli):
        cols = schema.get("columns") or []
        detail = (
            "columns incl. password" if "password" in cols
            else "table/column names"
        )
        custody.append(
            f"{step}. Leaked schema ({detail}) informs the SQLi attack "
            f"(finding: sqli)."
        )
        strands.append("sqli")
        step += 1

    if _CHAT_ID_ROUTE in routes and _present(idor):
        custody.append(
            f"{step}. Leaked {_CHAT_ID_ROUTE} route informs the IDOR attack "
            f"(finding: idor)."
        )
        strands.append("idor")
        step += 1

    # 5. Honeypot: advertised by the leak but dead. Noted, never a live strand.
    if _HONEYPOT_ROUTE in routes:
        custody.append(
            f"{step}. Leaked {_HONEYPOT_ROUTE} is a 404 recon-bait honeypot "
            f"(AVSA_SPEC §6.5) — advertised by the leak but does not resolve to a "
            f"live route; did not drive a live attack."
        )
        step += 1

    # 6. At least one real strand is required.
    if not strands:
        chain.reason = (
            "leakage occurred but no leaked recon overlapped a present web finding "
            "(leak did not drive a web attack this run)"
        )
        return chain

    # 7. Asserted — populate, labelled honestly as recon-overlap.
    chain.asserted = True
    chain.constituents = ["system_prompt_leakage"] + strands
    chain.shared_artifact = None       # no single taint token; recon-overlap based
    chain.custody = custody
    chain.provenance = {
        "link_type": "recon-overlap",
        "strength": "correlated, provenance-qualified",
        "contrast": (
            "weaker than Chain 1's unforgeable taint token; leaked strings could "
            "plausibly be used independently"
        ),
    }
    chain.falsifiability_note = (
        "Unlike Chain 1, this is not proven by an unforgeable token. It is a "
        "correlation strengthened by shared recon: the exact internal details the "
        "leak disclosed (e.g. the password column, the /chat/<id> route) are the "
        "details the web attacks rely on. Stated honestly as provenance-qualified, "
        "not strict."
    )
    return chain


def _recon_summary(recon: dict) -> str:
    """Short human string of what the leak disclosed, for the custody trail."""
    parts: list[str] = []
    schema = recon.get("schema", {}) or {}
    if schema:
        bits: list[str] = []
        if schema.get("tables"):
            bits.append("tables " + ", ".join(schema["tables"]))
        if schema.get("columns"):
            bits.append("columns " + ", ".join(schema["columns"]))
        if schema.get("plaintext_passwords"):
            bits.append("plaintext-password fact")
        parts.append("schema (" + "; ".join(bits) + ")")
    if recon.get("routes"):
        parts.append("routes " + ", ".join(recon["routes"]))
    if recon.get("infra"):
        parts.append("infra " + ", ".join(recon["infra"]))
    return "; ".join(parts) if parts else "(none)"
