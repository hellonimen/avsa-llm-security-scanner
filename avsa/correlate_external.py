# -*- coding: utf-8 -*-
"""AVSA external correlation API.

Exposes the chain-correlation engine (avsa/engine.py) as a small, documented,
standalone entry point that findings from OTHER TOOLS can be fed into and
checked for the same two cross-layer attack chains AVSA proves natively --
without needing AVSA's own detection modules, probe, or DVAI at all.

This is thin by design: engine.assert_chain1()/assert_chain2() were ALREADY
pure and dependency-injected (see engine.py's own module docstring -- "the
engine is handed a list of findings; it never fetches or runs anything") --
so making that pluggable is a documented input schema and a tiny adapter,
not new architecture.

INPUT SCHEMA -- a list of plain dicts, one per finding, matching AVSA's own
output/findings.json "findings" array shape (see reporter.py):

    {
        "id":       str,   # REQUIRED. The engine only actually correlates on
                            # six known ids -- prompt_injection,
                            # insecure_output, idor (Chain 1) and
                            # system_prompt_leakage plus the web findings it
                            # names (Chain 2). Any other id is accepted but
                            # ignored by both chains.
        "present":  bool,  # REQUIRED. Whether this finding was confirmed.
        "evidence": dict,  # REQUIRED for prompt_injection/insecure_output to
                            # link into Chain 1. Must carry the SAME shared
                            # token under one of engine._MARKER_KEYS
                            # ("marker", "run_marker", "induced_payload",
                            # "payload_sent", "payload", "injection_sent").
                            # This is the actual causal proof, not a
                            # formality -- a third-party scanner has to show
                            # the SAME artifact travelled through both steps,
                            # exactly as AVSA's own six modules do against
                            # DVAI.
        # name/layer/severity/owasp/attempts/primitives are optional -- only
        # used for the human-readable report if you render one, never read
        # by the correlation logic itself.
    }

USAGE -- as a library:

    from avsa.correlate_external import correlate
    result = correlate(external_findings, meta={"target": "https://example.com"})
    print(result["chains"][0]["asserted"])

USAGE -- as a CLI, against a findings.json-shaped file from another tool:

    python -m avsa.correlate_external path/to/external_findings.json

Either way the OUTPUT is the exact same shape as AVSA's own
output/findings.json (reporter.build_report's return value) -- the chain
correlation engine really is the same code AVSA's own scan uses against
DVAI, not a re-implementation for this entry point.
"""
from __future__ import annotations

import json
import sys
from types import SimpleNamespace

from avsa import engine, reporter


def _wrap(finding: dict) -> SimpleNamespace:
    """engine.py reads every finding via getattr(...), so a plain dict on its
    own won't work (dicts don't expose keys as attributes) -- SimpleNamespace
    is the whole adapter this needs."""
    return SimpleNamespace(
        id=finding.get("id"),
        name=finding.get("name"),
        layer=finding.get("layer"),
        present=bool(finding.get("present", False)),
        severity=finding.get("severity"),
        owasp=finding.get("owasp"),
        attempts=finding.get("attempts"),
        primitives=finding.get("primitives", []) or [],
        evidence=finding.get("evidence", {}) or {},
    )


def correlate(findings: list, meta: dict | None = None) -> dict:
    """Run AVSA's real chain-correlation engine against externally-supplied
    findings and return AVSA's own findings.json-shaped result (dict).

    findings: list of plain dicts -- see module docstring for the schema.
    meta: optional dict of run_id/target/user/timestamp, merged into the
          result the same way run_all.py's own meta dict is. All optional;
          anything omitted is simply null in the output.
    """
    wrapped = [_wrap(f) for f in findings]
    chain1 = engine.assert_chain1(wrapped)
    chain2 = engine.assert_chain2(wrapped)
    findings_json_obj, _ = reporter.build_report(wrapped, [chain1, chain2], meta or {})
    return findings_json_obj


def main() -> None:
    if len(sys.argv) != 2:
        print("usage: python -m avsa.correlate_external <findings.json>")
        sys.exit(1)
    with open(sys.argv[1], encoding="utf-8") as fh:
        data = json.load(fh)
    # Accept either a bare list of findings or a full findings.json (with a
    # "findings" key) -- both are reasonable shapes for another tool's output
    # to arrive in.
    if isinstance(data, dict) and "findings" in data:
        findings = data["findings"]
        meta = {k: data.get(k) for k in ("run_id", "target", "user", "timestamp")}
    else:
        findings = data
        meta = {}

    result = correlate(findings, meta)
    print(json.dumps(result, indent=2))
    asserted = sum(1 for c in result["chains"] if c["asserted"])
    print(f"\n{asserted}/2 chain(s) asserted.", file=sys.stderr)


if __name__ == "__main__":
    main()
