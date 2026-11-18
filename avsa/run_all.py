"""AVSA full end-to-end scan — the orchestrator (Sprint 6, slice 4).

Runs a COMPLETE assessment of DVAI: all six detection modules against the live
target, then hands the collected findings to the correlation engine to assert
both cross-layer chains, and prints one clean end-to-end summary.

This file is pure ORCHESTRATION — it has no detection logic of its own. It
imports and CALLS the frozen modules and engine; it never reimplements them.

NOT run automatically — it needs DVAI running locally AND a funded OpenAI key on
the DVAI side (the LLM modules drive the bot). Run it by hand from the repo root:

    python -m avsa.run_all

Config comes from environment variables (no credentials in code):
    AVSA_BASE_URL       (default http://127.0.0.1:5000)
    AVSA_USER           DVAI account username
    AVSA_PASS           DVAI account password
    AVSA_FAIL_ON_FINDING  opt-in CI/CD gate. Unset by
                        default, so every existing invocation (manual runs, the
                        GUI, the DVAI regression/demo scan) behaves exactly as
                        before. Set to a truthy value ("1", "true") ONLY when
                        pointing AVSA at a real deployment you are trying to
                        PROTECT -- against DVAI itself, finding all six
                        vulnerabilities + both chains is SUCCESS, so this must
                        stay opt-in rather than default-on.

CRITICAL DESIGN — ONE SHARED PROBE. A single Probe is created and logged in ONCE,
then handed to every module. All modules therefore share the same probe.run_id,
so their per-run markers carry the same <runid>. That shared token is exactly what
lets the engine link Chain 1 (strict taint). Creating a fresh Probe per module
would break correlation.

RUN ORDER (the one hard sequencing rule, per AVSA_SPEC): LLM modules FIRST, then
web modules, then correlation. Chain 2 needs the leaked recon to exist before the
web findings are correlated against it.
"""

from __future__ import annotations

import os
import sys
import time
from datetime import datetime, timezone
from dataclasses import dataclass, field
from typing import Optional

from avsa import engine, reporter
from avsa.modules import (
    idor,
    insecure_output,
    prompt_injection,
    sqli,
    system_prompt_leakage,
    xss,
)
from avsa.probe import Config, Probe


# The one hard sequencing rule: LLM modules first (so leaked recon exists), then
# web modules, then correlation. Each entry is (id, module); every module exposes
# run(probe) -> Finding.
_SCAN_ORDER = [
    ("system_prompt_leakage", system_prompt_leakage),
    ("prompt_injection", prompt_injection),
    ("insecure_output", insecure_output),
    ("sqli", sqli),
    ("idor", idor),
    ("xss", xss),
]


# --- errored-module placeholder ---------------------------------------------

@dataclass
class ErroredFinding:
    """Stand-in recorded when a module raises, so one hiccup doesn't abort the
    whole scan. present=False keeps it out of any chain assertion; it carries the
    exception text for the summary. Shaped like a real Finding for the printer and
    the engine (both read .id/.present/.evidence tolerantly)."""

    id: str
    error: str
    name: str = "(module errored)"
    layer: str = "?"
    present: bool = False
    severity: str = "n/a"
    owasp: str = "n/a"
    attempts: Optional[str] = None
    primitives: list = field(default_factory=list)
    evidence: dict = field(default_factory=dict)


# --- orchestration ----------------------------------------------------------

def run_scan(probe: Probe) -> list:
    """Run all six modules in order against the shared, already-authenticated
    probe, returning the six findings (errored modules become ErroredFinding).

    Kept separate from printing so the sequencing/ordering is the whole content of
    this function and nothing else."""
    findings = []
    for fid, module in _SCAN_ORDER:
        try:
            findings.append(module.run(probe))
        except Exception as exc:  # noqa: BLE001 — one module must not abort the scan
            print(f"  ! module '{fid}' errored: {exc!r} — continuing")
            findings.append(ErroredFinding(id=fid, error=repr(exc)))
    return findings


# --- printing ---------------------------------------------------------------

def _print_header(probe: Probe, config: Config) -> None:
    print("=== AVSA full scan ===")
    print(f"run_id / marker : {probe.run_id}")
    print(f"target          : {config.base_url}")
    print(f"user            : {config.username or '(unset)'}")
    print()


def _print_findings(findings: list) -> None:
    print(f"--- Findings ({len(findings)}) ---")
    for f in findings:
        # Errored modules print their exception instead of a verdict line.
        if isinstance(f, ErroredFinding):
            print(f"[{f.id}] {f.name} — ERRORED: {f.error}")
            continue
        present = "YES" if f.present else "no"
        line = f"[{f.id}] {f.name} ({f.layer}) — present: {present}"
        line += f", severity: {f.severity}, owasp: {f.owasp}"
        if f.attempts:
            line += f", attempts: {f.attempts}"
        prims = ", ".join(f.primitives) if f.primitives else "(none)"
        line += f", primitives: {prims}"
        print(line)
    print()


def _print_chain(label: str, chain) -> None:
    print(f"{label}: asserted {'YES' if chain.asserted else 'NO'}")
    if not chain.asserted:
        print(f"  reason          : {chain.reason}")
        return
    print(f"  shared_artifact : {chain.shared_artifact}")
    print(f"  constituents    : {', '.join(chain.constituents)}")
    print(f"  provenance      : {chain.provenance}")
    print("  custody:")
    for step in chain.custody:
        print(f"    - {step}")
    print(f"  falsifiability  : {chain.falsifiability_note}")


def _print_chains(chain1, chain2) -> None:
    print("--- Chains ---")
    _print_chain("Chain 1", chain1)
    _print_chain("Chain 2", chain2)
    print()


# --- entry point ------------------------------------------------------------

def main() -> None:
    config = Config(
        base_url=os.environ.get("AVSA_BASE_URL", "http://127.0.0.1:5000"),
        username=os.environ.get("AVSA_USER", ""),
        password=os.environ.get("AVSA_PASS", ""),
    )
    # Opt-in CI/CD gate — see module docstring for why
    # this must default OFF.
    fail_on_finding = os.environ.get("AVSA_FAIL_ON_FINDING", "").strip().lower() not in ("", "0", "false")

    start = time.perf_counter()

    # ONE shared probe for the whole scan (see module docstring).
    probe = Probe(config)
    _print_header(probe, config)

    if not probe.login():
        print(
            "login failed — cannot reach the authenticated endpoints. Check DVAI is "
            "running and AVSA_USER / AVSA_PASS are set correctly. Aborting scan."
        )
        # A scan that never ran must never look like a clean pass to anything that
        # reads the exit code (e.g. a CI step) — unconditional, not gated behind
        # AVSA_FAIL_ON_FINDING: "couldn't run" is not the same thing as "ran and
        # found nothing".
        sys.exit(2)

    # 1-6: run every module against the SAME probe, in the fixed order.
    findings = run_scan(probe)

    # Correlation: the engine is handed the collected findings (dependency
    # injection) and asserts both chains. LLM-first order means the leaked recon
    # for Chain 2 already exists in `findings` by the time we correlate.
    chain1 = engine.assert_chain1(findings)
    chain2 = engine.assert_chain2(findings)

    _print_findings(findings)
    _print_chains(chain1, chain2)

    duration_s = time.perf_counter() - start
    print("=== end of scan ===")
    print(f"scan duration   : {duration_s:.1f}s")

    # Reporter: build BOTH artefacts from the same in-memory findings/chains and
    # write them to output/ (one source of truth, §7.2). Terminal summary above
    # is unchanged; this only adds the two files and a final pointer line.
    meta = {
        "run_id": probe.run_id,
        "target": config.base_url,
        "user": config.username or "(unset)",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "duration_seconds": round(duration_s, 1),
    }
    findings_json_obj, report_md_str = reporter.build_report(
        findings, [chain1, chain2], meta
    )
    reporter.write_report(findings_json_obj, report_md_str)
    print("Report written: output/report.md and output/findings.json")

    if fail_on_finding:
        present = sum(1 for f in findings if getattr(f, "present", False))
        asserted = sum(1 for c in (chain1, chain2) if getattr(c, "asserted", False))
        if present or asserted:
            print(
                f"CI gate         : FAIL — {present} finding(s) present, "
                f"{asserted} chain(s) asserted (AVSA_FAIL_ON_FINDING is set)"
            )
            sys.exit(1)
        print("CI gate         : PASS — no findings present, no chains asserted")


if __name__ == "__main__":
    main()
