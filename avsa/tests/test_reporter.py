"""Unit tests for the AVSA Reporter (avsa.reporter).

No server, no bot. build_report is pure — it takes findings + chains + meta and
returns (findings_json_obj, report_md_str). We feed it fabricated findings and
fake Chain objects (SimpleNamespace stand-ins, same shape the real modules and
engine produce) and assert on the two artefacts.

The point of these tests is the §7.2 invariant: BOTH artefacts are built from the
same data, so we verify the locked json field names AND that the markdown carries
the required verdict, table, custody, and severity one-liners.
"""

from types import SimpleNamespace

from avsa.reporter import build_report, write_report


# --- fakes ------------------------------------------------------------------

def fake_finding(fid, name, layer, present, severity, owasp, attempts, primitives, evidence):
    return SimpleNamespace(
        id=fid, name=name, layer=layer, present=present, severity=severity,
        owasp=owasp, attempts=attempts, primitives=primitives, evidence=evidence,
    )


def fake_chain(cid, name, asserted, constituents=None, shared_artifact=None,
               custody=None, provenance=None, falsifiability_note="", reason=""):
    return SimpleNamespace(
        id=cid, name=name, asserted=asserted,
        constituents=constituents or [], shared_artifact=shared_artifact,
        custody=custody or [], provenance=provenance or {},
        falsifiability_note=falsifiability_note, reason=reason,
    )


def sample_findings():
    """Six findings mirroring the real modules — a mix of present/absent."""
    return [
        fake_finding("system_prompt_leakage", "System Prompt Leakage", "llm", True,
                     "Medium", "LLM07:2025", "4/5", ["schema_leaked"],
                     {"leak": "system prompt reveals password column"}),
        fake_finding("prompt_injection", "Prompt Injection", "llm", True,
                     "High", "LLM01:2025", "2/5", ["injection_marker_emitted"],
                     {"marker": "PROMPTINJ-abc123"}),
        fake_finding("insecure_output", "Insecure Output Handling", "llm", True,
                     "High", "LLM05:2025", "3/5", ["bot_output_served_unescaped"],
                     {"marker": "AVSA-OUTPUT-abc123"}),
        fake_finding("sqli", "SQL Injection", "web", True,
                     "Critical", "A03:2021 - Injection", None, ["auth_bypass"],
                     {"auth_bypass": "' OR '1'='1 logged in"}),
        fake_finding("idor", "IDOR (Broken Access Control)", "web", True,
                     "High", "A01:2021 - Broken Access Control", None, ["cross_user_read"],
                     {"cross_user_read": "read chat 7 owned by bob"}),
        fake_finding("xss", "Stored XSS", "web", False,
                     "High", "A03:2021 - Injection", None, [],
                     {"note": "not stored unescaped this run"}),
    ]


def sample_chains():
    chain1 = fake_chain(
        "chain1", "Chain 1: Prompt Injection -> Insecure Output -> IDOR delivery",
        True, constituents=["prompt_injection", "insecure_output", "idor"],
        shared_artifact="abc123",
        custody=["1. injection induced payload token abc123.",
                 "2. insecure output served it unescaped, same token abc123."],
        provenance={"automated_steps": "strict-artifact-linked"},
        falsifiability_note="token abc123 is minted fresh at run start; its presence proves the link.",
    )
    chain2 = fake_chain(
        "chain2", "Chain 2: System Prompt Leakage -> recon -> web-layer attacks",
        False, reason="leakage occurred but no leaked recon overlapped a present web finding",
    )
    return [chain1, chain2]


META = {
    "run_id": "abc123",
    "target": "http://127.0.0.1:5000",
    "user": "alice",
    "timestamp": "2026-07-06T12:00:00+00:00",
}


# --- tests ------------------------------------------------------------------

def test_build_report_returns_dict_and_str():
    obj, md = build_report(sample_findings(), sample_chains(), META)
    assert isinstance(obj, dict)
    assert isinstance(md, str)


def test_json_has_locked_top_level_keys():
    obj, _ = build_report(sample_findings(), sample_chains(), META)
    for key in ("run_id", "target", "user", "timestamp", "summary", "findings", "chains"):
        assert key in obj, f"missing locked top-level key: {key}"
    assert obj["run_id"] == "abc123"
    assert obj["target"] == "http://127.0.0.1:5000"
    assert obj["user"] == "alice"


def test_json_summary_counts_correct():
    obj, _ = build_report(sample_findings(), sample_chains(), META)
    summary = obj["summary"]
    assert summary["findings_total"] == 6
    assert summary["findings_present"] == 5   # xss is absent in the sample
    assert summary["chains_total"] == 2
    assert summary["chains_asserted"] == 1     # only chain1 asserted


def test_json_finding_has_locked_fields():
    obj, _ = build_report(sample_findings(), sample_chains(), META)
    f = obj["findings"][0]
    for key in ("id", "name", "layer", "present", "severity", "owasp",
                "attempts", "primitives", "evidence"):
        assert key in f, f"finding missing locked field: {key}"


def test_json_chain_fields_and_reason():
    obj, _ = build_report(sample_findings(), sample_chains(), META)
    chains = {c["id"]: c for c in obj["chains"]}
    # Asserted chain: reason is null, shared_artifact present.
    assert chains["chain1"]["asserted"] is True
    assert chains["chain1"]["reason"] is None
    assert chains["chain1"]["shared_artifact"] == "abc123"
    # Not-asserted chain: reason carried in the json.
    assert chains["chain2"]["asserted"] is False
    assert "no leaked recon overlapped" in chains["chain2"]["reason"]


def test_md_contains_verdict_line():
    _, md = build_report(sample_findings(), sample_chains(), META)
    assert "5/6 vulnerabilities present; 1/2 cross-layer chains asserted" in md


def test_md_contains_findings_table_header():
    _, md = build_report(sample_findings(), sample_chains(), META)
    assert "| id | name | layer | present | severity | OWASP | attempts | primitives |" in md


def test_md_contains_chain1_custody_and_falsifiability():
    _, md = build_report(sample_findings(), sample_chains(), META)
    assert "insecure output served it unescaped, same token abc123" in md
    assert "token abc123 is minted fresh at run start" in md


def test_md_contains_required_severity_one_liners():
    _, md = build_report(sample_findings(), sample_chains(), META)
    assert "chain-enabling impact rated in Chain 2, not here" in md
    assert "Chain 1 role rated in the chain, not here" in md


def test_md_renders_not_asserted_chain_reason():
    _, md = build_report(sample_findings(), sample_chains(), META)
    assert "NOT asserted" in md
    assert "no leaked recon overlapped a present web finding" in md


# --- general_guidance ---------------------------
#
# sample_findings() above already gives us exactly the fixture this needs: five
# present findings across all five guidance-bearing ids, and one absent one
# (xss) -- no separate fixture required.

def test_present_finding_gets_correct_general_guidance():
    obj, _ = build_report(sample_findings(), sample_chains(), META)
    findings = {f["id"]: f for f in obj["findings"]}
    assert "parameterised queries" in findings["sqli"]["general_guidance"]
    assert "ownership check" in findings["idor"]["general_guidance"]
    assert "structural separation" in findings["prompt_injection"]["general_guidance"]
    assert "no information an application would be unwilling to disclose" in (
        findings["system_prompt_leakage"]["general_guidance"]
    )


def test_absent_finding_has_no_general_guidance():
    """xss is the one absent finding in the sample -- nothing to point at."""
    obj, _ = build_report(sample_findings(), sample_chains(), META)
    findings = {f["id"]: f for f in obj["findings"]}
    assert findings["xss"]["present"] is False
    assert findings["xss"]["general_guidance"] is None


def test_xss_and_insecure_output_share_identical_guidance_text():
    """Both are the same underlying failure (unescaped output) per Section
    6.1.2 -- the dissertation gives them one shared bullet, not two, and this
    mapping must not silently fork that into two different sentences."""
    from avsa.reporter import _GENERAL_GUIDANCE
    assert _GENERAL_GUIDANCE["xss"] == _GENERAL_GUIDANCE["insecure_output"]


def test_unknown_finding_id_gets_no_guidance_not_a_crash():
    """A finding id this mapping doesn't recognise (e.g. a future module, or a
    third-party finding via correlate_external) must degrade to None, never
    raise -- the same tolerant-getattr discipline as every other field here."""
    weird = fake_finding("totally_new_module", "New Thing", "web", True,
                          "High", "A00:2021", None, [], {})
    obj, _ = build_report([weird], sample_chains(), META)
    assert obj["findings"][0]["general_guidance"] is None


def test_md_contains_general_guidance_line_for_present_findings():
    _, md = build_report(sample_findings(), sample_chains(), META)
    assert "**general guidance:**" in md
    assert "parameterised queries or prepared statements" in md
    # The absent finding (xss) must not get a guidance line of its own --
    # its guidance text is identical to insecure_output's, so we check the
    # per-finding JSON (already covered above) rather than grep the md for
    # absence of a shared string.


def test_md_methodology_reflects_the_guidance_exception():
    """The paragraph must still say ASSESSES ONLY / no invented fix, but no
    longer claim zero remediation-adjacent content now that the fixed
    guidance pointer exists."""
    _, md = build_report(sample_findings(), sample_chains(), META)
    assert "ASSESSES only" in md
    assert "never generates or prescribes a fix" in md
    assert "never patched" in md


def test_write_report_creates_both_files(tmp_path):
    obj, md = build_report(sample_findings(), sample_chains(), META)
    json_path, md_path = write_report(obj, md, out_dir=str(tmp_path / "output"))
    import json
    import os
    assert os.path.exists(json_path)
    assert os.path.exists(md_path)
    with open(json_path, encoding="utf-8") as fh:
        reloaded = json.load(fh)
    assert reloaded["run_id"] == "abc123"
    assert reloaded["summary"]["findings_present"] == 5
