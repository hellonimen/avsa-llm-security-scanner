# -*- coding: utf-8 -*-
"""Tests for avsa/correlate_external.py: the
external-findings entry point around the chain correlation engine. These
exercise the SAME real engine.assert_chain1()/assert_chain2() AVSA's own
scan uses, just fed synthetic "another tool's findings.json" input instead
of DVAI's real findings -- proving the pluggable path produces the same
kind of verdict the internal path does, on both a positive and a negative
case."""
import json
import subprocess
import sys

from avsa.correlate_external import correlate


def chain1_positive_findings():
    """A synthetic external tool's findings that SHOULD assert Chain 1:
    prompt_injection and insecure_output share a token, idor is present."""
    return [
        {
            "id": "prompt_injection",
            "present": True,
            "evidence": {"marker": "PROMPTINJ-abc123"},
        },
        {
            "id": "insecure_output",
            "present": True,
            "evidence": {"marker": "PROMPTINJ-abc123"},
        },
        {"id": "idor", "present": True, "evidence": {}},
    ]


def test_correlate_asserts_chain1_on_matching_external_findings():
    result = correlate(chain1_positive_findings())
    chain1 = next(c for c in result["chains"] if c["id"] == "chain1")
    assert chain1["asserted"] is True
    assert chain1["shared_artifact"] == "abc123"


def test_correlate_does_not_assert_chain1_on_mismatched_tokens():
    """Same shape, but the two tokens differ -- must NOT assert (this is the
    actual causal-proof check, not a rubber stamp)."""
    findings = [
        {"id": "prompt_injection", "present": True, "evidence": {"marker": "PROMPTINJ-aaaaaa"}},
        {"id": "insecure_output", "present": True, "evidence": {"marker": "PROMPTINJ-bbbbbb"}},
        {"id": "idor", "present": True, "evidence": {}},
    ]
    result = correlate(findings)
    chain1 = next(c for c in result["chains"] if c["id"] == "chain1")
    assert chain1["asserted"] is False
    assert chain1["reason"]


def test_correlate_does_not_assert_chain1_when_a_constituent_is_absent():
    findings = chain1_positive_findings()[:2]  # drop idor entirely
    result = correlate(findings)
    chain1 = next(c for c in result["chains"] if c["id"] == "chain1")
    assert chain1["asserted"] is False


def test_correlate_output_shape_matches_avsa_own_findings_json():
    result = correlate(chain1_positive_findings(), meta={"target": "https://example.com"})
    for key in ("run_id", "target", "user", "timestamp", "summary", "findings", "chains"):
        assert key in result
    assert result["target"] == "https://example.com"
    assert result["summary"]["chains_asserted"] == 1


def test_cli_reads_findings_json_shaped_file(tmp_path):
    payload = {
        "target": "https://example.com",
        "findings": chain1_positive_findings(),
    }
    infile = tmp_path / "external_findings.json"
    infile.write_text(json.dumps(payload), encoding="utf-8")

    proc = subprocess.run(
        [sys.executable, "-m", "avsa.correlate_external", str(infile)],
        capture_output=True, text=True,
    )
    assert proc.returncode == 0, proc.stderr
    assert "1/2 chain(s) asserted." in proc.stderr
    out = json.loads(proc.stdout)
    assert out["target"] == "https://example.com"
