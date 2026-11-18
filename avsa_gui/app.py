"""AVSA GUI - a thin, clickable front end over avsa.run_all's orchestration.

Sprint 7 (AVSA), slice 1 (+ v2 visual/UX pass): this file has NO detection or
correlation logic of its own. It is exactly run_all.py's three-step pipeline -
run_scan() -> assert_chain1()/assert_chain2() -> build_report()/write_report()
- triggered by a browser button instead of `python -m avsa.run_all`, rendering
the same findings/chains data as an HTML page instead of terminal text.
Nothing about detection or correlation changes here.

Everything below `# --- presentation-only helpers ---` is exactly that:
formatting/aggregation of data the reporter already produced (icons, colour
classes, layer/severity counts, splitting an already-generated custody string
into a number + text for a timeline widget). None of it decides what a
finding IS or whether a chain holds - engine.py and reporter.py still own
that entirely, unmodified. These helpers run AFTER write_report(), on an
in-memory dict, so output/findings.json on disk is never touched by them -
it stays exactly what reporter.py defines, unmodified.

Run it (same env-var convention as run_all.py - see that file's docstring),
from the repo root - or just double-click start_avsa_gui.bat, which does this
for you:

    AVSA_USER=alice AVSA_PASS=password123 python -m avsa_gui.app

Then open http://127.0.0.1:5050/ in a browser. DVAI must already be running
at AVSA_BASE_URL (default http://127.0.0.1:5000). If AVSA_USER/AVSA_PASS
aren't set, this defaults to the seeded alice/password123 dev account (see
dvai/seed.py) rather than failing - see _config() below. The Target/User/
Password fields on the page itself override these per scan, so pointing at a
second target doesn't need an env var or a restart - see _config()'s
`overrides` param.
"""

from __future__ import annotations

import json
import math
import os
from dataclasses import asdict
from datetime import datetime, timezone

import requests
from flask import Flask, render_template, request, send_file

from avsa import engine, reporter
from avsa.probe import Config, Probe
from avsa.run_all import run_scan


app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-secret-change-me")

# Absolute, cwd-independent location for output/ - anchored to this file's own
# location (avsa_gui/app.py), never to the process's working directory. A bare
# relative "output" path resolves differently depending on how the server
# happens to be launched or auto-restarted (debug=True's reloader preserves
# whatever cwd the process originally started with) - this fixes that whole
# bug class once, for every route that touches output/.
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUTPUT_DIR = os.path.join(_REPO_ROOT, "output")


@app.context_processor
def inject_dvai_url():
    """Make the DVAI target URL available to every template, for the
    floating chat-widget bubble (bottom-right on every AVSA GUI page -- see
    static/dvai_widget.js). Reuses the exact same AVSA_BASE_URL env var
    _config() already reads below, so the widget always points at whichever
    target AVSA itself is currently configured to scan -- no separate
    setting to keep in sync, and it stays correct if that ever gets pointed
    at dvai_hardened (port 5001) instead for a Defend-phase demo."""
    return {"dvai_base_url": os.environ.get("AVSA_BASE_URL", "http://127.0.0.1:5000")}


def _config(overrides: dict | None = None) -> Config:
    # Defaults match dvai/seed.py's alice account (a fixed, intentionally
    # plaintext dev credential for the deliberately-insecure DVAI target - see
    # the project's golden rule; not a real secret). Still overridable via env
    # var, same as run_all.py. This is what was missing before: relying on
    # AVSA_USER/AVSA_PASS being set in the *same* shell the app was launched
    # from was a common first-run failure - a bare double-click of
    # start_avsa_gui.bat now works with zero env vars required.
    #
    # `overrides` (Sprint 7 slice 2): per-request values typed into the
    # Target/User/Password fields on the scan form. A blank field falls
    # through to the env-var/default chain below unchanged - this overrides a
    # single scan, it does not change the env-var defaults shown next time
    # the page loads. Lets AVSA point at a second target (e.g. a hardened
    # DVAI variant for the Defend-phase demo) with no restart, while nothing
    # downstream changes - Probe/engine/reporter don't know or care whether a
    # value came from an env var or a form field.
    overrides = overrides or {}
    return Config(
        base_url=overrides.get("base_url") or os.environ.get("AVSA_BASE_URL", "http://127.0.0.1:5000"),
        username=overrides.get("username") or os.environ.get("AVSA_USER", "alice"),
        password=overrides.get("password") or os.environ.get("AVSA_PASS", "password123"),
    )


# --- presentation-only helpers (formatting, not detection) -----------------

_ICONS = {
    "system_prompt_leakage": (
        '<path d="M7 10V7a5 5 0 0110 0" stroke="currentColor" stroke-width="1.6" '
        'fill="none" stroke-linecap="round"/>'
        '<rect x="5" y="10" width="14" height="9" rx="2" stroke="currentColor" '
        'stroke-width="1.6" fill="none"/>'
        '<circle cx="12" cy="14" r="1.3" fill="currentColor"/>'
        '<path d="M12 15.3V17" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/>'
    ),
    "prompt_injection": (
        '<path d="M14.5 3.5l6 6-1.6 1.6-1.2-1.2-2 2 1.2 1.2-1.6 1.6-1.2-1.2-4.6 4.6-3-3 '
        '4.6-4.6-1.2-1.2 1.6-1.6 1.2 1.2 2-2-1.2-1.2z" stroke="currentColor" '
        'stroke-width="1.3" fill="none" stroke-linejoin="round"/>'
        '<path d="M4 20l2.7-1 2-2-1.7-1.7-2 2z" stroke="currentColor" stroke-width="1.3" '
        'fill="none" stroke-linejoin="round"/>'
    ),
    "insecure_output": (
        '<path d="M9 8L4 12l5 4" stroke="currentColor" stroke-width="1.6" fill="none" '
        'stroke-linecap="round" stroke-linejoin="round"/>'
        '<path d="M15 8l5 4-5 4" stroke="currentColor" stroke-width="1.6" fill="none" '
        'stroke-linecap="round" stroke-linejoin="round"/>'
        '<circle cx="12" cy="12" r="1.5" fill="currentColor"/>'
    ),
    "sqli": (
        '<ellipse cx="12" cy="6.5" rx="7" ry="2.6" stroke="currentColor" stroke-width="1.6" fill="none"/>'
        '<path d="M5 6.5v11c0 1.4 3.1 2.6 7 2.6s7-1.2 7-2.6v-11" stroke="currentColor" '
        'stroke-width="1.6" fill="none"/>'
        '<path d="M5 12c0 1.4 3.1 2.6 7 2.6s7-1.2 7-2.6" stroke="currentColor" stroke-width="1.6" fill="none"/>'
    ),
    "idor": (
        '<circle cx="9" cy="8" r="3" stroke="currentColor" stroke-width="1.6" fill="none"/>'
        '<path d="M4 19c0-3 2.2-5 5-5s5 2 5 5" stroke="currentColor" stroke-width="1.6" '
        'fill="none" stroke-linecap="round"/>'
        '<path d="M14.5 8H20m-2.3-2.3L20 8l-2.3 2.3" stroke="currentColor" stroke-width="1.6" '
        'fill="none" stroke-linecap="round" stroke-linejoin="round"/>'
    ),
    "xss": (
        '<path d="M9 8L4 12l5 4" stroke="currentColor" stroke-width="1.6" fill="none" '
        'stroke-linecap="round" stroke-linejoin="round"/>'
        '<path d="M15 8l5 4-5 4" stroke="currentColor" stroke-width="1.6" fill="none" '
        'stroke-linecap="round" stroke-linejoin="round"/>'
        '<path d="M11 16l2-8" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/>'
    ),
}

_MANUAL_ICON = (
    '<circle cx="12" cy="8" r="3" stroke="currentColor" stroke-width="1.6" fill="none"/>'
    '<path d="M5 20c0-4 3-6 7-6s7 2 7 6" stroke="currentColor" stroke-width="1.6" '
    'fill="none" stroke-linecap="round"/>'
)

_BROKEN_LINK_ICON = (
    '<path d="M9 15l6-6" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/>'
    '<path d="M8 8l1.6-1.6a3 3 0 014.24 0l.4.4M8.4 15.2l-.4.4a3 3 0 004.24 4.24l1.6-1.6" '
    'stroke="currentColor" stroke-width="1.6" fill="none" stroke-linecap="round"/>'
)

_LAYER_LABEL = {"llm": "LLM layer", "web": "Web layer"}

_EXPLAINERS = {
    "system_prompt_leakage": "Can an attacker coax the bot into revealing its hidden system prompt, or confidential details inside it?",
    "prompt_injection": "Can attacker-supplied text override the bot's instructions and control what it says?",
    "insecure_output": "Does the app trust the bot's own output enough to render it as live markup, instead of escaped text?",
    "sqli": "Is the login query built by concatenating user input, so crafted input changes the query's logic?",
    "idor": "Does the app serve another user's data by ID alone, with no ownership check?",
    "xss": "Does a script stored in a message execute in another user's browser when they view it?",
}


def _severity_class(severity) -> str:
    return "sev-" + str(severity or "unknown").strip().lower()


def _enrich_findings(findings_json_obj: dict) -> dict:
    """Presentation-only: adds icon/explainer/css-class fields the templates
    use. Never changes what was found - purely decorates the already-built
    findings.json dict for display, and only ever runs on the in-memory copy,
    after write_report() has already written the unmodified original to disk."""
    for f in findings_json_obj["findings"]:
        f["icon"] = _ICONS.get(f["id"], "")
        f["explainer"] = _EXPLAINERS.get(f["id"], "")
        f["severity_class"] = _severity_class(f.get("severity"))
        f["layer_label"] = _LAYER_LABEL.get(f["layer"], f["layer"])
    return findings_json_obj


def _layer_summary(findings: list) -> dict:
    """llm vs web present/total counts, for the layer-comparison bars. Pure
    aggregation of the 'present' booleans reporter.py already decided - no
    new detection, just counting what's already there."""
    out = {}
    for layer in ("llm", "web"):
        layer_findings = [f for f in findings if f["layer"] == layer]
        present = sum(1 for f in layer_findings if f["present"])
        total = len(layer_findings)
        out[layer] = {
            "present": present,
            "total": total,
            "pct": round(present / total * 100) if total else 0,
        }
    return out


def _split_custody_step(step: str):
    """'1. Prompt injection induced...' -> ('1', 'Prompt injection induced...').
    Pure string split of reporter's already-generated custody text, so the
    timeline widget can put the number in its own circle without doubling up
    (the same double-numbering trap reporter.py's own markdown renderer
    already avoids for report.md - see reporter.py's comment on custody)."""
    if ". " in step:
        num, _, rest = step.partition(". ")
        if num.strip().isdigit():
            return num.strip(), rest
    return "", step


# The specific pair of constituents that actually shares the taint token, for
# the connector-level token label in the chain-flow diagram. NOT every
# connector in the flow is token-linked: engine.py's assert_chain1 proves the
# link only between prompt_injection and insecure_output - IDOR is the
# cross-user delivery channel and deliberately does NOT carry the XSS marker
# (see engine.py's assert_chain1 docstring/comments). Chain 2 never has a
# shared_artifact at all (recon-overlap, not token-based), so this never
# matches there - it stays None and no connector gets a token label.
_TOKEN_LINKED_PAIR = ("prompt_injection", "insecure_output")


def _token_connector_index(constituents: list):
    """Index of the ONE connector (between nodes[i] and nodes[i+1]) that is
    the actual shared-token link, or None if this chain has no such link."""
    for i in range(len(constituents) - 1):
        if (constituents[i], constituents[i + 1]) == _TOKEN_LINKED_PAIR:
            return i
    return None


def _prep_chain(chain_obj: dict, name_lookup: dict, layer_lookup: dict) -> dict:
    """Presentation-only prep for the chain flow diagram + timeline. Node
    labels use the real finding names (minus any parenthetical, so "IDOR
    (Broken Access Control)" -> "IDOR") rather than guessing a label from the
    id - "idor"/"sqli" title-cased letter-by-letter reads oddly for
    acronyms.

    Each node also carries its layer ("llm"/"web") straight from the same
    per-finding data _layer_summary() already uses - not a second, separately
    maintained mapping - purely so the chain-flow diagram can tint each node
    by layer. That two-colour system IS the cross-layer concept the chain is
    proving, not decoration."""
    chain_obj = dict(chain_obj)
    chain_obj["timeline"] = [
        {"n": n, "text": t}
        for n, t in (_split_custody_step(s) for s in chain_obj.get("custody", []))
    ]
    last = chain_obj["custody"][-1] if chain_obj.get("custody") else ""
    chain_obj["has_manual_step"] = "(Manual)" in last
    chain_obj["nodes"] = [
        {
            "id": cid,
            "icon": _ICONS.get(cid, ""),
            "label": name_lookup.get(cid, cid.replace("_", " ")).split(" (")[0],
            "layer": layer_lookup.get(cid, "web"),
        }
        for cid in chain_obj.get("constituents", [])
    ]
    chain_obj["token_connector_index"] = _token_connector_index(chain_obj.get("constituents", []))
    return chain_obj


_GAUGE_R = 52
_GAUGE_CIRCUMFERENCE = 2 * math.pi * _GAUGE_R


def _gauge(present: int, total: int) -> dict:
    frac = (present / total) if total else 0
    return {
        "r": _GAUGE_R,
        "circumference": round(_GAUGE_CIRCUMFERENCE, 1),
        "dash": round(frac * _GAUGE_CIRCUMFERENCE, 1),
    }


def _last_run_summary():
    """Best-effort read of the most recent output/findings.json, purely to
    give the landing page something real to show instead of empty space.
    Never raises - a missing/unreadable file just means no strip is shown."""
    path = os.path.join(OUTPUT_DIR, "findings.json")
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        return {
            "run_id": data.get("run_id"),
            "target": data.get("target"),
            "timestamp": data.get("timestamp"),
            "summary": data.get("summary", {}),
        }
    except Exception:
        return None


@app.get("/ping")
def ping_target():
    """Best-effort reachability check for a Target field - the live status
    dot next to it, NOT part of the scan pipeline and NOT a detector. Any
    HTTP response at all (even 404/401/a redirect) counts as reachable;
    only a connection failure or timeout means offline. Deliberately never
    raises - a bad/incomplete URL just reads as offline, same as a target
    that really is down."""
    url = request.args.get("url", "").strip()
    if not url:
        return {"reachable": False}
    try:
        requests.get(url, timeout=2.5)
        return {"reachable": True}
    except requests.exceptions.RequestException:
        return {"reachable": False}


@app.get("/download/json")
def download_findings_json():
    """Serve the most recent output/findings.json as a download - the exact
    unmodified file reporter.write_report() wrote after the last /scan run.
    Nothing new is generated here; this only exposes the existing file."""
    path = os.path.join(OUTPUT_DIR, "findings.json")
    if not os.path.exists(path):
        return "No scan has been run yet - run a scan first.", 404
    return send_file(path, as_attachment=True, download_name="avsa_findings.json")


@app.get("/download/md")
def download_report_md():
    """Serve the most recent output/report.md as a download - same file
    write_report() already wrote, just made downloadable from the browser."""
    path = os.path.join(OUTPUT_DIR, "report.md")
    if not os.path.exists(path):
        return "No scan has been run yet - run a scan first.", 404
    return send_file(path, as_attachment=True, download_name="avsa_report.md")


# --- Before/After comparison (Build -> Break -> Defend) --------------------
# A third, independent action: run the SAME six-module scan (run_scan +
# assert_chain1/assert_chain2) against two targets in one request and show
# them side by side. Defaults point at the real dvai (5000) and the
# Defend-phase dvai_hardened variant (5001), but either field can be
# repointed anywhere, same override pattern as the main scan form. Render-only
# (build_report but never write_report) so this can never collide with or
# overwrite output/findings.json, which the report pipeline depends on.

def _run_one_scan(base_url: str, username: str, password: str):
    """Run one full six-module scan + chain assertion against one target -
    the exact same three calls /scan makes. Returns (error_or_None, data)."""
    config = Config(base_url=base_url, username=username, password=password)
    probe = Probe(config)
    try:
        alive = probe.login()
    except Exception as exc:  # noqa: BLE001 - target not reachable/not running
        return (
            f"could not reach {base_url} ({type(exc).__name__}) - make sure "
            "it's running before comparing", None,
        )
    if not alive:
        return (
            f"login failed against {base_url} - check it's running and the "
            "user/password are correct", None,
        )
    findings = run_scan(probe)
    chain1 = engine.assert_chain1(findings)
    chain2 = engine.assert_chain2(findings)
    meta = {
        "run_id": probe.run_id,
        "target": base_url,
        "user": username or "(unset)",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    findings_json_obj, _ = reporter.build_report(findings, [chain1, chain2], meta)
    findings_json_obj = _enrich_findings(findings_json_obj)
    return None, findings_json_obj


@app.get("/compare")
def compare_form():
    return render_template(
        "compare.html",
        base_url_a=os.environ.get("AVSA_BASE_URL", "http://127.0.0.1:5000"),
        base_url_b="http://127.0.0.1:5001",
        username=os.environ.get("AVSA_USER", "alice"),
        password="",
    )


@app.post("/compare")
def compare_run():
    base_url_a = request.form.get("base_url_a", "").strip() or "http://127.0.0.1:5000"
    base_url_b = request.form.get("base_url_b", "").strip() or "http://127.0.0.1:5001"
    username = request.form.get("username", "").strip() or os.environ.get("AVSA_USER", "alice")
    password = request.form.get("password", "").strip() or os.environ.get("AVSA_PASS", "password123")

    def _back(error):
        return render_template(
            "compare.html", base_url_a=base_url_a, base_url_b=base_url_b,
            username=username, password="", error=error,
        )

    err_a, data_a = _run_one_scan(base_url_a, username, password)
    if err_a:
        return _back(f"Target A ({base_url_a}): {err_a}")

    err_b, data_b = _run_one_scan(base_url_b, username, password)
    if err_b:
        return _back(f"Target B ({base_url_b}): {err_b}")

    findings_b_by_id = {f["id"]: f for f in data_b["findings"]}
    rows = []
    for fa in data_a["findings"]:
        fb = findings_b_by_id.get(fa["id"], {})
        rows.append({
            "id": fa["id"],
            "name": fa["name"],
            "layer_label": fa.get("layer_label"),
            "icon": fa.get("icon"),
            "a_present": fa["present"],
            "b_present": fb.get("present", False),
            "changed": fa["present"] != fb.get("present", False),
        })

    chains_b_by_id = {c["id"]: c for c in data_b["chains"]}
    chain_rows = []
    for ca in data_a["chains"]:
        cb = chains_b_by_id.get(ca["id"], {})
        chain_rows.append({
            "id": ca["id"],
            "name": ca["name"],
            "a_asserted": ca["asserted"],
            "b_asserted": cb.get("asserted", False),
            "changed": ca["asserted"] != cb.get("asserted", False),
        })

    return render_template(
        "compare.html",
        base_url_a=base_url_a, base_url_b=base_url_b, username=username, password="",
        data_a=data_a, data_b=data_b, rows=rows, chain_rows=chain_rows,
    )


# --- routes ------------------------------------------------------------

@app.get("/")
def index():
    return render_template("index.html", config=_config(), last_run=_last_run_summary())


@app.post("/scan")
def scan():
    """Synchronous end-to-end scan - the click-to-run equivalent of
    avsa.run_all.main(). Same three steps, same order, same functions:

      1. run_scan(probe)                          - the six modules, in order
      2. engine.assert_chain1() / assert_chain2() - correlate the findings
      3. reporter.build_report() / write_report() - one source of truth

    The only difference from run_all.py is that the normalised dict
    build_report() returns is handed to a template (after the presentation-
    only enrichment above) instead of being printed to a terminal - and it is
    STILL written to output/ exactly as before, unmodified, so nothing that
    already depends on those files changes.
    """
    config = _config({
        "base_url": request.form.get("base_url", "").strip(),
        "username": request.form.get("username", "").strip(),
        "password": request.form.get("password", "").strip(),
    })
    probe = Probe(config)

    try:
        alive = probe.login()
    except Exception as exc:  # noqa: BLE001 - target not reachable/not running
        return render_template(
            "index.html",
            config=config,
            last_run=_last_run_summary(),
            error=(
                f"Could not reach {config.base_url} ({type(exc).__name__}). "
                "Check DVAI is running there and try again."
            ),
        )
    if not alive:
        return render_template(
            "index.html",
            config=config,
            last_run=_last_run_summary(),
            error=(
                "Login failed - could not reach the authenticated endpoints. "
                f"Check DVAI is running at {config.base_url} and that "
                "AVSA_USER / AVSA_PASS are set correctly (in the terminal "
                "the AVSA GUI was started from)."
            ),
        )

    findings = run_scan(probe)
    chain1 = engine.assert_chain1(findings)
    chain2 = engine.assert_chain2(findings)

    meta = {
        "run_id": probe.run_id,
        "target": config.base_url,
        "user": config.username or "(unset)",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    findings_json_obj, report_md_str = reporter.build_report(
        findings, [chain1, chain2], meta
    )
    json_path, md_path = reporter.write_report(findings_json_obj, report_md_str, out_dir=OUTPUT_DIR)
    # Presentation-only: show a clean relative path in the GUI footer instead
    # of the raw absolute filesystem path (download routes still use the real
    # OUTPUT_DIR-based paths above, untouched).
    json_path_display = "output/" + os.path.basename(json_path)
    md_path_display = "output/" + os.path.basename(md_path)

    # Everything from here on is presentation-only (see module docstring) and
    # runs on the in-memory dict AFTER the unmodified original was written.
    findings_json_obj = _enrich_findings(findings_json_obj)
    layer_summary = _layer_summary(findings_json_obj["findings"])
    name_lookup = {f["id"]: f["name"] for f in findings_json_obj["findings"]}
    layer_lookup = {f["id"]: f["layer"] for f in findings_json_obj["findings"]}
    chains_display = [_prep_chain(c, name_lookup, layer_lookup) for c in findings_json_obj["chains"]]
    gauge = _gauge(
        findings_json_obj["summary"]["findings_present"],
        findings_json_obj["summary"]["findings_total"],
    )

    return render_template(
        "results.html",
        data=findings_json_obj,
        layer_summary=layer_summary,
        chains_display=chains_display,
        gauge=gauge,
        manual_icon=_MANUAL_ICON,
        broken_link_icon=_BROKEN_LINK_ICON,
        json_path=json_path_display,
        md_path=md_path_display,
    )


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5050, debug=True)
