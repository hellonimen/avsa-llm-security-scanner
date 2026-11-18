"""AVSA reproducibility test - Chapter 5, Technique 3 (Live Reproducibility
Testing).

The 79 unit tests in avsa/tests/ prove the DETECTION LOGIC is correct against
fabricated findings - but they can't prove how consistently the six modules
and both chains behave against a REAL, non-deterministic LLM. This script
runs N independent full scans (a fresh Probe each time, so each run gets its
own run_id/marker - the same as N different people each running one scan
through the GUI) against the same target and tabulates how often each
finding and each chain came back the same way. That consistency rate IS the
Technique 3 result for Chapter 5 - complementary to unit testing, not a
replacement for it (unit tests prove correctness on known inputs;
reproducibility testing measures real-world stability).

NOT run automatically - same requirements as run_all.py: DVAI running
locally AND a funded OpenAI key on the DVAI side. Each run retries
internally same as a normal scan, so 8 runs takes several minutes. Run by
hand from the repo root:

    python -m avsa.run_reproducibility_test
    python -m avsa.run_reproducibility_test --runs 8 --base-url http://127.0.0.1:5000

Config comes from environment variables, same as run_all.py:
    AVSA_BASE_URL   (default http://127.0.0.1:5000)
    AVSA_USER       DVAI account username
    AVSA_PASS       DVAI account password

Pure orchestration, same as run_all.py - no detection logic of its own, only
calls the frozen run_scan()/engine.assert_chain1()/assert_chain2().
"""

from __future__ import annotations

import argparse
import os
from datetime import datetime, timezone

from avsa import engine
from avsa.probe import Config, Probe
from avsa.run_all import run_scan


_FINDING_IDS = [
    "system_prompt_leakage",
    "prompt_injection",
    "insecure_output",
    "sqli",
    "idor",
    "xss",
]


def _run_once(config: Config) -> dict:
    """One independent full scan + chain assertion - a fresh Probe (so a
    fresh run_id), same six modules, same two chains, exactly like one real
    person running one real scan through the GUI. Returns a dict with either
    an "error" key or the full result."""
    probe = Probe(config)
    if not probe.login():
        return {"error": f"login failed against {config.base_url}"}

    findings = run_scan(probe)
    chain1 = engine.assert_chain1(findings)
    chain2 = engine.assert_chain2(findings)

    by_id = {getattr(f, "id", None): f for f in findings}
    return {
        "run_id": probe.run_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "findings": {
            fid: bool(getattr(by_id.get(fid), "present", False))
            for fid in _FINDING_IDS
        },
        "chain1": bool(chain1.asserted),
        "chain2": bool(chain2.asserted),
    }


def _build_report(results: list, config: Config) -> str:
    """Build the Chapter 5-ready markdown: a consistency-rate summary table
    plus a per-run detail table. Pure - takes already-collected results, no
    I/O of its own."""
    lines = []
    lines.append("# AVSA Live Reproducibility Testing")
    lines.append("")
    lines.append(
        f"{len(results)} independent full scans against `{config.base_url}`, "
        f"run {datetime.now(timezone.utc).isoformat()}."
    )
    lines.append("")
    lines.append("## Consistency across runs")
    lines.append("")
    lines.append("| Finding / Chain | Count | Rate |")
    lines.append("|---|---|---|")
    for fid in _FINDING_IDS:
        n = sum(1 for r in results if r["findings"][fid])
        lines.append(f"| {fid} | {n}/{len(results)} | {100 * n / len(results):.0f}% |")
    n1 = sum(1 for r in results if r["chain1"])
    n2 = sum(1 for r in results if r["chain2"])
    lines.append(f"| Chain 1 asserted | {n1}/{len(results)} | {100 * n1 / len(results):.0f}% |")
    lines.append(f"| Chain 2 asserted | {n2}/{len(results)} | {100 * n2 / len(results):.0f}% |")
    lines.append("")
    lines.append("## Per-run detail")
    lines.append("")
    header = ["#", "run_id"] + _FINDING_IDS + ["chain1", "chain2"]
    lines.append("| " + " | ".join(header) + " |")
    lines.append("|" + "---|" * len(header))
    for i, r in enumerate(results, 1):
        row = [str(i), r["run_id"]]
        row += ["Y" if r["findings"][fid] else "n" for fid in _FINDING_IDS]
        row += ["ASSERTED" if r["chain1"] else "no", "ASSERTED" if r["chain2"] else "no"]
        lines.append("| " + " | ".join(row) + " |")
    lines.append("")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runs", type=int, default=8, help="number of independent scans (default 8)")
    parser.add_argument(
        "--base-url",
        default=os.environ.get("AVSA_BASE_URL", "http://127.0.0.1:5000"),
        help="target base URL (default: AVSA_BASE_URL env var, or http://127.0.0.1:5000)",
    )
    args = parser.parse_args()

    config = Config(
        base_url=args.base_url,
        username=os.environ.get("AVSA_USER", ""),
        password=os.environ.get("AVSA_PASS", ""),
    )

    print(f"=== AVSA reproducibility test: {args.runs} independent runs against {config.base_url} ===\n")

    results = []
    for i in range(1, args.runs + 1):
        print(f"--- run {i}/{args.runs} ---")
        r = _run_once(config)
        if "error" in r:
            print(f"  ! {r['error']} - aborting after {len(results)} completed run(s)")
            if not results:
                return
            break
        chain1_state = "ASSERTED" if r["chain1"] else "no"
        chain2_state = "ASSERTED" if r["chain2"] else "no"
        print(f"  run_id {r['run_id']} | chain1={chain1_state} | chain2={chain2_state}")
        results.append(r)

    report_md = _build_report(results, config)
    print("\n" + report_md)

    out_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir, "output")
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, "reproducibility_log.md")
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(report_md)
    print(f"Log written: output/reproducibility_log.md")
    print("Paste the two tables above into Chapter 5's Live Reproducibility Testing section.")


if __name__ == "__main__":
    main()
