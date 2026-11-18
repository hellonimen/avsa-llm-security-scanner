# AVSA_SPEC.md

**Automated Vulnerability Scanner & Assessor — Design Specification**

Project: Automated Security Assessment of LLM-Integrated Web Applications: A Cross-Layer Attack Chain Approach
Author: Marcus Ong — BSc (Hons) Cybersecurity, Asia Pacific University
Component: AVSA (the *Break* half; target is DVAI)
Status: Body locked (§§1–8). Two markers intentionally open — see *Open markers* below.

> **Authoring principle.** This spec was written *after* DVAI was built and every vulnerability and both chains were proven by hand against the live `gpt-4.1-mini` bot. It describes the real attack surface, not an imagined one. Where a design choice depends on DVAI's actual code, the relevant file/line is cited.

## Open markers (intentionally unresolved)

| Marker | Where | Meaning |
|--------|-------|---------|
| `[contract — confirm at build]` | §7.3 `findings.json` schema | Design intent / build target. Adjustable if building the reporter reveals a field that doesn't earn its place. |
| `[CONFIRM vs supervisor]` | §8.6 UAT format | Awaiting the supervisor's sign-off on task-based vs questionnaire UAT. Section is provisional until confirmed; does not block build. |

All OWASP mappings are **resolved and locked** (verified against the OWASP Gen AI Security Project, 2025 edition). No `[CONFIRM vs IR]` markers remain.

---

## 1. Purpose & Golden Rule

**What AVSA is.** The Automated Vulnerability Scanner & Assessor (AVSA) is the *Break* half of this project's contribution. Where DVAI is the deliberately vulnerable target, AVSA is the tool that **automatically detects and assesses** the six planted vulnerabilities and — crucially — **reconstructs the two cross-layer attack chains** that were already proven by hand against the live `gpt-4.1-mini` bot.

**What AVSA is not.** AVSA never remediates, patches, or hardens anything. It does not modify DVAI's source, database, or configuration. Its only writes to the target are the probe requests an external attacker would send over HTTP, plus the test data those probes create (e.g. an injected chat message).

**The Golden Rule, restated for this component.** DVAI stays insecure. AVSA's correctness is *defined by* DVAI remaining vulnerable — if a vulnerability were fixed, the corresponding AVSA module must report it as no-longer-present, not error out. AVSA observes; it does not defend.

**Novel contribution (the one sentence the examiners need).** AVSA does not merely report six independent findings; it proves that an LLM-layer weakness *causally drives* a web-layer exploit by capturing a shared evidence artifact that links the two findings into a single chain.

---

## 2. Scope

**In scope — the only things AVSA is built to find:**

| # | Vulnerability | Layer | OWASP mapping |
|---|---------------|-------|---------------|
| 1 | SQL Injection | Web | A03:2021 – Injection |
| 2 | IDOR | Web | A01:2021 – Broken Access Control |
| 3 | Stored XSS | Web | A03:2021 – Injection |
| 4 | Prompt Injection | LLM | LLM01:2025 |
| 5 | System Prompt Leakage | LLM | LLM07:2025 |
| 6 | Insecure Output Handling | LLM | LLM05:2025 (OWASP 2025 name: *Improper Output Handling*; this project uses *Insecure Output Handling*) |

**In scope — the two chains (the actual contribution):**

- **Chain 1 (LLM→Web, active delivery):** prompt injection → bot emits XSS payload → insecure output handling stores it raw → IDOR delivers it → payload fires in the victim's session.
- **Chain 2 (LLM→Web, recon-driven):** system prompt leakage spills the schema (table/column names, the plaintext-password fact, the `/chat/<id>` route, and the `/admin/chats` *bait*) → that recon parameterises the SQLi and IDOR probes. **[Audit note 2026-06-29: `/admin/chats` is a 404 honeypot, not a live route — see §6.5 callout. Chain 2's real payoff is leaked-schema→SQLi and the genuine `/chat/<id>` IDOR.]**

**Out of scope (explicit non-goals — these protect the timeline and the viva):**

- No vulnerability classes beyond the six above. No CSRF, SSRF, auth-bypass-by-other-means, rate-limiting, etc. — even if AVSA happens to brush against them.
- No remediation, no "suggested fixes" output beyond a neutral severity statement. AVSA assesses; the *Defend* discussion lives in the report's narrative chapters, not in AVSA's behaviour.
- No exploitation beyond what is needed to *prove* a finding (see §5.1 for the honest, surface-accurate statement of what "proof" means for SQLi — it is **not** an in-band data dump).
- No targets other than DVAI for the FYP build. A later phase could **reuse only the three LLM-layer modules** — unchanged — against a third-party bot, but only under written authorisation. Nothing new would be bolted on for it.
- No source-code access. AVSA is black-box (see §3).

---

## 3. Operating Model

**Stance: authenticated black-box.** AVSA treats DVAI strictly as a remote target reached over HTTP. It has no access to DVAI's source code, database file, or server configuration. It learns everything it knows about the target by sending requests and reading responses — exactly as an external attacker would. This is a deliberate academic choice: a finding AVSA produces black-box is a finding a real attacker could reproduce, which makes the assessment credible rather than a tautology where the tool "finds" bugs it was simply told about.

**Foothold: a valid low-privilege account.** "Authenticated" means AVSA starts with one set of ordinary user credentials — the foothold a real attacker obtains through phishing, credential stuffing, or simply by signing up. From that single legitimate session, AVSA attempts to reach data and behaviour it should not. This is what makes the IDOR and Chain 1 findings meaningful: they are privilege violations committed *from* a normal account.

**Configuration AVSA is given at launch (the threat-model boundary).** AVSA receives only what a real attacker with one foothold would have:

- The base URL of the target (e.g. `http://127.0.0.1:5000`).
- Credentials for its own foothold account (Alice).
- Nothing else. No second account, no route list, **no route wordlist**, no schema, no payload hints. AVSA must *discover* the routes and (for Chain 2) *leak* the schema itself.

The absence of any route wordlist is a load-bearing design constraint, not an omission: it is what makes Chain 2's provenance structurally airtight (§6.5).

**Verification through the vulnerability itself.** AVSA never holds the victim's credentials. It proves IDOR and Chain 1 delivery using the IDOR hole as its own verification channel: from Alice's foothold session, AVSA requests the victim's chat by id (`/chat/<id>`) and observes the content served where it should not be — including, for Chain 1, the stored XSS payload sitting in the victim's conversation. The vulnerability is the proof. This is the stronger black-box claim: the breach and its confirmation use only attacker-reachable surface, with no victim login anywhere in the loop. Bob exists purely as seeded target data (`seed.py`); his password is never given to AVSA.

**Session handling.** AVSA maintains a single authenticated session (cookie jar) — Alice's. There is no victim session, so cross-contamination is not a concern.

**LLM non-determinism — a first-class design constraint.** This is the one operating reality that separates AVSA from a classic web scanner, and it is designed for, not patched around. The target bot is `gpt-4.1-mini`, which is non-deterministic: the *same* prompt-injection probe may succeed on one attempt and not the next, and the bot's wording will vary even when the attack works. Two consequences are baked into the operating model:

- **Detection is confirmation-based, not single-shot.** Every LLM-layer probe runs up to *N* attempts and is judged on whether the *invariant signal* appears in any attempt — not on exact string matching. The invariant for prompt injection is "did the bot perform the injected instruction" (e.g. emit the exact marker payload planted), not "did it reply with specific prose."
- **Findings record attempt counts.** The report states e.g. "succeeded on 2/3 attempts" so the assessment is honest about reliability and reproducible for the examiner. This is a genuine data point in Ch5 validation, not a hidden flaky test.

**Retry budget.** Default **N = 3** attempts per LLM-layer probe. **Override: N = 5 for System Prompt Leakage (§5.5)** — justified by the manual result that leakage took four tries by hand; N = 3 would risk a false negative on a vulnerability known to exist, and Chain 2's entire spine depends on the leak firing. Attempt counts are reported honestly regardless (e.g. "leaked on 4/5").

**Write-footprint and the honest proof rule.** AVSA's only writes to DVAI are (a) the probe requests themselves and (b) the chat messages it must store to demonstrate stored-XSS and Chain 1. For SQLi proof, AVSA captures the **bypassed / identity-pivoted session** and, where present, the **error-page SQL disclosure** — **never a UNION row dump, which DVAI's surface does not permit** (the injectable login query's result is never rendered to any page; see §5.1). The plaintext-password fact — the reason the SQLi finding is severe — is evidenced separately via manual DB inspection in Ch5, not pulled to screen by AVSA. Injected test artifacts are left in place deliberately as evidence (not cleaned up), which is acceptable because DVAI is a disposable target, not production.

---

## 4. Architecture

**Shape of the system.** AVSA is a linear pipeline with one feedback edge. Findings flow left to right; the only thing that loops back is *leaked recon* from the LLM layer feeding the web-layer probes (that feedback edge is Chain 2, and it is the whole point — so the architecture surfaces it rather than hiding it).

```
                    +------------------------------------------------+
                    |                  AVSA                          |
                    |                                                |
  config ----------->  [1] Probe / Session Layer                    |
 (base URL,         |        |  authenticated HTTP, cookie jar,      |
  Alice creds)      |        |  N-retry harness for LLM probes       |
                    |        v                                       |
                    |   [2] Detection Modules (six, independent)     |
                    |        |                                       |
                    |   web: SQLi . IDOR . Stored XSS                |
                    |   llm: PromptInj . SysPromptLeak . InsecOut    |
                    |        |                                       |
                    |        |   leaked schema/routes (Chain 2 edge) |
                    |        +---------------+                       |
                    |        v               | feeds                 |
                    |   [3] Chain Correlation Engine <---------------+
                    |        |  links findings via shared evidence   |
                    |        v                                       |
                    |   [4] Reporter (JSON + human-readable)         |
                    +------------------------------------------------+
                             |
                             v
                   findings.json + report.md + evidence/ artifacts
```

**[1] Probe / Session Layer.** The single point of contact with DVAI. Owns Alice's authenticated session (login, cookie jar, CSRF token handling if present). Exposes a thin HTTP surface to the modules — `get(path)`, `post(path, data)`, `chat(message)` — so no module talks to the network directly. Critically, it owns the **N-retry harness**: any LLM-layer probe is issued through a `confirm(probe, invariant, n=3)` helper that runs up to *n* attempts, returns success if the invariant signal appears in any attempt, and records the attempt count. This is where the §3 house rule physically lives, so every LLM module inherits it for free and none can forget it. (The leakage module passes `n=5`.)

**[2] Detection Modules.** Six independent, single-responsibility units — three web, three LLM. Each module has the same contract: it receives the probe layer, runs its detection, and emits a structured `Finding` (or a null result if the vuln is absent). Modules do not know about each other. Independence matters for two reasons: it keeps each module unit-testable in isolation for Ch5, and it means the chain logic is *not* smuggled inside the modules — chains are assembled one layer up, by the engine, from the evidence the modules produce.

**[3] Chain Correlation Engine.** The novel contribution and the reason the architecture exists. It consumes the six modules' findings plus their evidence artifacts and decides whether a genuine chain is present — not by assuming "we found injection and we found XSS, therefore Chain 1," but by checking that a **shared evidence artifact** ties the findings together (full mechanism in §6). It also owns the Chain 2 feedback edge: it takes the schema/route recon leaked by the System Prompt Leakage module and hands it to the SQLi/IDOR modules so their probes are *parameterised by the leak*.

> **Dependency-injectable by design.** The engine accepts findings and evidence artifacts as **injected inputs** rather than reaching out to gather them itself. This is a deliberate commitment so that the engine — the heart of the contribution — is fully unit-testable with fabricated fixtures, with **no live LLM required** (see §8.3). The engine is pure logic over its inputs: same inputs → same chain verdict, every time.

**[4] Reporter.** Serialises everything two ways: `findings.json` (machine-readable) and `report.md` (human-readable, examiner-facing, with a dedicated chain view). Evidence artifacts (captured payloads, the bounded SQLi evidence, raw HTTP exchanges) are written to an `evidence/` directory so every claim in the report is backed by a file on disk.

**Run order — the one hard sequencing rule.** Because Chain 2 requires leaked recon *before* the SQLi/IDOR probes can be parameterised by it, the engine runs **LLM-layer modules first, then web-layer modules, then correlation**. This is the only sequencing dependency; within each layer, module order does not matter.

**Deliberately minimal stack.** Python standard library + `requests` for HTTP + `beautifulsoup4` for detecting whether an XSS payload landed unescaped in served HTML. No scanning frameworks, no headless browser. XSS/insecure-output detection is by HTML parsing (payload present as a live node vs inert escaped text); actual cross-user *execution* is carried by manual screenshots in Ch4/Ch5 (the agreed split: AVSA proves served-unescaped, the author proves execution).

---

## 5. Detection Modules

Every module is independent and single-responsibility. A module finds *its* vuln and emits *its* evidence; it never reasons about other modules or about chains. Chain assembly happens one layer up (§6). Each `Finding` carries: vuln id, present/absent, severity, OWASP mapping, evidence pointer, and (for LLM modules) attempt count. Each module is specified as **signal → probe → evidence → OWASP mapping**.

### 5.1 SQL Injection module (web)

**Signal it hunts.** A single injectable sink — the login query in `verify_login` (`db.py:86`), which builds its SQL by f-string interpolation. Every other query in DVAI uses bound `?` placeholders and is **not** injectable; AVSA targets login and nothing else. Injection is confirmed through any of three independent primitives (the module reports each one it lands):

1. **Authentication bypass** — `' OR '1'='1' -- ` in the username field (trailing space after `--` required to comment out the password predicate). Logs in as the first user (Alice) without valid credentials. *[confirmed by hand]*
2. **Boolean-blind differential** — submit payloads that vary the injected predicate's truth value and observe the binary oracle: a successful login state vs the `Invalid username or password` response. A reliable login/no-login differential across crafted true/false predicates is the recognised signature of blind SQL injection.
3. **Error-based disclosure** — because DVAI runs `debug=True` and the `db.execute` call is not wrapped in try/except, a deliberately malformed payload surfaces a `sqlite3.OperationalError` on the Werkzeug debug page, echoing the offending SQL back to the attacker. Genuine information disclosure of query structure.

**Identity-pivot primitive (UNION, but not for exfiltration).** AVSA can also use `UNION SELECT <target_id> -- ` to place a chosen value in the `id` column the login query returns, causing `session["user_id"]` to be set to a victim's id. The session then reads that victim's data through DVAI's *safe, parameterised* profile/chat pages. **This is UNION used for identity selection, never for in-band column exfiltration** — a UNION-to-screen data dump is not achievable here (the login query result is never rendered), and specifying one would fail live at the viva.

**Evidence it captures.** Honest artefacts only, no row dump:
- `evidence/sqli_authbypass.txt` — the bypass payload + the HTTP exchange showing an authenticated session obtained without credentials.
- `evidence/sqli_blind.txt` — the true/false payload pair and the differential responses (the oracle).
- `evidence/sqli_error_disclosure.txt` — the malformed payload and the captured debug-page SQL echo.
- `evidence/sqli_identity_pivot.txt` (if exercised) — the UNION payload, the resulting session identity, and a sample of the victim data now reachable via the safe pages.

**What AVSA explicitly does *not* claim.** It does not extract the password column to screen. The plaintext-password fact — the reason bypass/identity-pivot is *severe* — is carried in the report narrative and evidenced by manual DB/seed inspection in Ch5, not by an AVSA dump. The module is honest about being a **blind / auth-bypass / error-based** injection finding, not in-band UNION.

**OWASP mapping.** A03:2021 – Injection.

> *Note for §6 (de-duplication).* The identity-pivot primitive and the IDOR module can both terminate at "read the victim's chat," but via **different root causes** — SQLi *changes who Alice is* (session id rewritten), whereas IDOR *keeps Alice as Alice* and dereferences an id she is not entitled to. The correlation engine treats these as distinct findings and does not double-count one "read victim data" as two chains.

### 5.2 IDOR module (web)

**Signal it hunts.** An object reference (chat id) that Alice can dereference to read data belonging to another user, from her own foothold session, with no authorisation check.

**Probe it sends.**
1. Enumerate Alice's *own* legitimate chat ids from her dashboard (establish the baseline set she is entitled to).
2. Request `/chat/<id>` for ids *outside* that set from Alice's session (**enumeration is the primary acquisition path** — keeps the finding genuinely black-box and self-contained; a leak-supplied id from Chain 2 is accepted only as corroboration).
3. Success signal: a chat that is not Alice's is served in full to Alice.
4. ~~Secondary check: request `/admin/chats` from Alice's non-admin session (forced browsing of an admin-only route — same A01 class).~~ **REMOVED per code audit (2026-06-29): `/admin/chats` does not exist in DVAI (404 / recon bait only — see §6.5 callout). The IDOR module proves IDOR via `/chat/<id>` cross-user access only.**

**Evidence it captures.** The id requested, proof it is not in Alice's entitled set, and the served content that should have been denied → `evidence/idor_<id>.html`. ~~For `/admin/chats`: the served admin listing.~~ (admin listing removed — route does not exist; see §6.5.)

**OWASP mapping.** A01:2021 – Broken Access Control.

> *Note for §6.* This module is also the **verification channel** for Chain 1 — but it does not know that. It simply proves "Alice can fetch chat `<id>` she should not." The engine later notices the fetched content contains the injected payload. The module stays dumb; the engine is smart.

### 5.3 Stored XSS module (web)

**Signal it hunts.** A payload that is *stored* via one request and later *served back unescaped* in an HTML response, where a browser would execute it.

**Probe it sends.**
1. Store a **unique per-run marker** payload as a chat message: `<script>document.title='AVSA-XSS-<runid>'</script>`, where `<runid>` is a fresh random id minted at run start.
2. Re-fetch the conversation and parse the served HTML with `beautifulsoup4`.
3. Success signal: the payload is present **unescaped** — i.e. it parses as a live `<script>` element / event-handler attribute in the DOM, not as inert escaped text (`&lt;script&gt;`).

**Evidence it captures.** The stored payload string, the raw served HTML fragment showing it unescaped, and the bs4 parse result confirming a live node → `evidence/xss_served.html`.

**Scope boundary (the clean split).** This module proves *served-unescaped*, deterministically and automatably. It does **not** prove execution — that is carried by manual screenshots (tab flips to `AVSA-XSS-<runid>` in the victim's session) in Ch4/Ch5. The unique per-run marker is what makes the §6 "genuine chain, not coincidence" proof airtight: the exact string AVSA *injected* is the exact string it later *observes* served via IDOR, and a per-run id rules out accidental matching against leftover hand-test data.

**OWASP mapping.** A03:2021 – Injection.

### 5.4 Prompt Injection module (LLM)

**Signal it hunts.** The bot performs an attacker-supplied instruction that overrides its system directive — proven by the bot emitting a **unique benign marker** it would not otherwise produce (e.g. `PROMPTINJ-<runid>`). The invariant is *"did the bot do what the injection told it"*, never specific prose.

**Probe it sends.** A framed injection delivered through the chat, run under N = 3 via the confirmation harness. The manual result — naive injection refused, framed injection succeeded — is the design justification: the module carries a small escalation ladder (naive → framed) and reports the first framing that lands plus the attempt count.

**Evidence it captures.** The injection prompt(s), the bot reply containing the marker, the attempt count → `evidence/promptinj.txt`.

**OWASP mapping.** LLM01:2025.

> *Division-of-labour note for §6.* This module proves injection **generically** with a benign marker. Chain 1's *active* step — inducing the bot to emit the actual XSS payload — reuses this module's injection *capability* but is composed by the engine, not baked into the standalone finding.

### 5.5 System Prompt Leakage module (LLM)

**Signal it hunts.** The bot reveals its system-prompt contents — specifically the recon confirmed by hand: table names (`users` / `chats` / `messages`), the `username` / `password` columns, the plaintext-password fact, and the non-obvious routes `/chat/<id>` and `/admin/chats`. The invariant is the **presence of these schema/route tokens** in the bot's output, matched structurally (not by exact wording).

**Probe it sends.** A leakage-elicitation ladder run under the confirmation harness with the **N = 5 override** (manual experience: leakage took four tries).

**Evidence it captures.** The eliciting prompt(s), the leaked output, the attempt count (e.g. "4/5"), **and the recon extracted as structured data** (table list, column list, route list) → `evidence/leak.txt` plus a parsed `leaked_recon` object. That structured object is the **Chain 2 feedback edge**: it is what parameterises the web-layer probes in §6.

**OWASP mapping.** LLM07:2025.

### 5.6 Insecure Output Handling module (LLM)

**Signal it hunts.** DVAI trusts the *bot's* output and stores/serves it without output-encoding. **Same sink as §5.3, different source.** Verified against the code: `chat.html` renders messages through a single role-agnostic loop (`chat.html:27–35`, render line `:34`) with `{{ m['content'] | safe }}` applied **unconditionally to both roles** — role affects only a cosmetic CSS class and label. This is the *only* `|safe` sink for message bodies (the flash sink at `base.html:28` uses plain `{{ m }}`, which is autoescaped). So the vulnerability is localized and deliberate: user-supplied content (§5.3) and bot-emitted content (this module) hit the *identical* `{{ content | safe }}` expression. That shared sink is exactly the Insecure Output Handling → Stored XSS bridge for Chain 1.

**Probe it sends.** Induce the bot (via the §5.4 injection capability) to emit a distinctive benign HTML marker, then re-fetch the conversation and bs4-parse whether the **bot-authored** marker is served **unescaped** (live node) vs escaped (inert text).

**Evidence it captures.** The induced bot output, the served HTML fragment, the bs4 verdict on escaped-vs-raw → `evidence/insecure_output.txt`.

**OWASP mapping.** LLM05:2025 — OWASP 2025 names this *Improper Output Handling*; this project uses *Insecure Output Handling*.

---

## 6. Chain Correlation Engine

### 6.1 The problem this section answers

The six modules can all fire and still tell you *nothing* about chains. "Prompt injection works" and "stored XSS works" co-occurring is **correlation**. The novel claim of this project is **causation**: that an LLM-layer weakness *drives* a web-layer exploit. An examiner will ask, point-blank: *"You found six things. How do you know Chain 1 is a real chain and not two unrelated findings that happen to both be present?"* This section is the answer, and the answer is not narrative — it is a **shared evidence artifact** whose identity across two findings is the proof of causal flow.

### 6.2 The mechanism: unique-marker taint propagation

AVSA proves a chain the way dynamic taint analysis proves data flow — with a **unique marker** that can only exist downstream if it travelled there from upstream.

The upstream step **mints a token unique to this run** (`<runid>` — a fresh random id per AVSA execution). The engine asserts a chain **only if that exact token is observed in the downstream finding's evidence**. Because the token is unique-per-run and random, the probability of it appearing downstream *by coincidence* is effectively zero — so its presence downstream can *only* be explained by propagation from upstream. That identity **is** the causal proof.

This reframes "is it a chain?" from a judgement call into a **string-identity check on captured evidence**: chain ⟺ `token_minted_upstream == token_observed_downstream`. The engine never *assumes* a chain from two present findings; it *verifies* one from a matched artifact, or it declines to assert it.

### 6.3 The chain predicate (formal assertion condition)

The engine asserts a chain **iff all three hold**:

1. **Both constituent findings are independently present** (each module returned a non-null `Finding`).
2. **Shared-artifact identity:** a designated artifact minted by the upstream finding is found, byte-for-byte, in the downstream finding's captured evidence.
3. **Provenance / necessity:** the downstream observation could not have been produced *without* the upstream step — established either by the artifact's uniqueness (Chain 1) or by a structural constraint on what AVSA could otherwise have known (Chain 2, §6.5).

If 1–2 hold but 3 is weak, the engine reports a **"correlated, provenance-qualified"** chain and states the caveat rather than overclaiming. Honesty over a clean-looking result — this is Ch5 validation, not marketing.

### 6.4 Chain 1 — LLM→Web, active delivery

**Causal story:** prompt injection → bot emits the XSS payload → insecure output handling stores it raw (`{{ content | safe }}`) → the payload is served unescaped cross-boundary → (manual) fires in the victim browser.

**The shared artifact:** the **unique XSS payload string** `<script>document.title='AVSA-XSS-<runid>'</script>`.

**The composed structure (refined model).** Because AVSA holds only Alice's foothold and never the victim's credentials, and because Alice re-reading her *own* chat would not be IDOR, Chain 1 is proven as a **composition of three genuine findings welded by the shared token**, with cross-user *execution* supplied by manual evidence:

- **A — induce (upstream).** The injection capability (§5.4) induces the *bot* to emit the payload carrying this run's `<runid>`. Captured in `evidence/promptinj.txt`. This single fact spans two findings: prompt injection (the bot obeyed) *and* insecure output handling (§5.6: bot-emitted active content enters the `|safe` sink).
- **B — served unescaped (downstream).** The payload is re-fetched and bs4 confirms it parses as a **live node**, not inert escaped text — `evidence/xss_served.html`.
- **C — genuine IDOR on an unowned chat.** The IDOR module (§5.2) *independently* proves Alice can fetch a chat she does **not** own and receive content she is not entitled to.

**IDOR-target constraint (locked, anti-phantom-IDOR).** The chat AVSA dereferences in step C — and the chat whose served-unescaped payload welds the chain — **must be a chat Alice does not own** (the seeded Bob chat), reached by enumeration and confirmed *not in Alice's entitled set* before use. The engine **refuses to assert** Chain 1's IDOR step against any id that resolves to Alice's own chats. A real boundary is crossed, or the step is null. The automated demo must never quietly point the payload-bearing read at Alice's own id.

**What the engine asserts.** Steps 1–4 below are the automated, strict-artifact-linked assertion; step 5 is the manual execution coda, linked by the same token:

1. mint + induce → `promptinj.txt` (token `AVSA-XSS-<runid>` present in bot reply)
2. served unescaped via `|safe` → `xss_served.html` (same token, live node)
3. genuine IDOR on unowned (Bob) chat → `idor_<bobid>.html` (boundary crossed)
4. **artifact identity check:** token at step 1 `==` token at step 2 → automated chain asserted (**strict-artifact-linked**)
5. **execution coda (manual):** the same `<runid>` shown firing in the victim's session → Ch4/Ch5 screenshot (**manually-evidenced, token-linked**)

**Why it is not coincidence.** `<runid>` is fresh-random this run. It did not exist before AVSA started, so it cannot match leftover data from manual tests or a previous run. If it appears in a served chat response, the only path it could have got there is: injection induced it → the `|safe` sink stored it → the read endpoint served it. The string's presence downstream is unforgeable evidence of the full upstream flow.

### 6.5 Chain 2 — LLM→Web, recon-driven

> ⚠️ **SPEC REVISION PENDING — read before implementing Chain 2 (discovered during the IDOR code audit, 2026-06-29).**
> This section as originally written anchors Chain 2's spine on forced-browsing **`/admin/chats`** as a real, non-self-discoverable admin route. **CODE AUDIT FINDING: `/admin/chats` does NOT exist in DVAI.** It is **recon BAIT** planted inside the hidden system prompt (`llm.py:62`); requesting it returns a plain **404**. DVAI has no admin route and no roles at all.
> **Consequences to apply when the chain engine is built:**
> 1. The `/admin/chats` "forced-browsing spine" below is **invalid as a live route** — do NOT implement Chain 2 against `/admin/chats` as if it serves data.
> 2. The leak still *advertises* `/admin/chats` (that is the deliberate honeypot), so the honest revised story is: **leak emits the `/admin/chats` bait → AVSA follows the lead → it resolves to 404 (the honeypot does not pay off)**, recorded as a leaked-but-dead recon lead.
> 3. The genuine web-layer payoff of the leak must be re-anchored on what is real: the leaked **schema** parameterising **SQLi**, and the leaked **`/chat/<id>` pattern + the plaintext-password fact** informing the genuine **`/chat/<id>` IDOR**. The "structural necessity / no-wordlist" argument must be rebuilt around these, since it can no longer rest on `/admin/chats` resolving to data.
> 4. Every other mention of `/admin/chats` as a live forced-browse target in this document (§5.2, §6.6, §7.6, §8.3, §8.4, §8.5, §8.7) inherits this revision — treat them as superseded by this callout until the Chain-2 slice rewrites them.
> The text below is **retained as-is for history**; it is the pre-audit design and is NOT the build target.

**Causal story:** system prompt leakage spills routes + schema → that recon parameterises web-layer probes that AVSA *could not otherwise have aimed*.

**The spine (strong necessity): leaked route → forced-browsing access, anchored on `/admin/chats`.**

- `/chat/<id>` is **self-discoverable** — Alice's own dashboard links to her chats via that route, so AVSA could learn the pattern from normal navigation *without* the leak. Anchoring necessity on `/chat/<id>` is therefore **weak**; it is demoted to a supporting detail.
- `/admin/chats` is **not self-discoverable** from a non-admin session — nothing Alice can legitimately see links to it. The **only** way AVSA learns this route is the leak.

So the spine anchors on **`/admin/chats`**: System Prompt Leakage emits the exact string `/admin/chats` → the web layer forced-browses precisely that string → admin-only data is served to non-admin Alice. Shared artifact = the exact route string the leak produced `==` the route the forced-browse hit.

**The structural guarantee that makes provenance unarguable.** AVSA **carries no route wordlist and no route list in its config** (§3: config is base URL + Alice only). Its sole source of any non-self-discoverable route is the leak module's output. Therefore, if AVSA hit `/admin/chats`, it is *structurally impossible* for it to have learned that route any other way — there is no wordlist to have guessed it from. This converts "you could've guessed it" into "the tool provably had no other source."

**The supporting strand (weaker necessity): leaked schema → SQLi.** The leak also spills table/column names, which *inform* the SQLi module (e.g. the identity-pivot UNION's column position, or interpreting the error-based disclosure). But auth-bypass (`' OR '1'='1' -- `) works **without** the leak, so the leak is *not necessary* for SQLi to succeed. The engine therefore reports leaked-schema→SQLi as **"correlated, provenance-qualified"** (§6.3 case), not as a strict-necessity spine. Honest framing: the leak *strengthens and guides* SQLi; it *enables* the `/admin/chats` access.

### 6.6 Coincidence rule-out, stated for the viva

The engine emits, per chain, an explicit **falsifiability note** — what would have to be true if the chain were *not* real, and why the evidence rules it out:

- **Chain 1:** *If* this were coincidence, the served chat would contain `AVSA-XSS-<runid>` without AVSA having injected it. Impossible: `<runid>` is minted fresh at run start and exists nowhere until injection places it. (Negative control: a run with the injection step skipped produces **zero** occurrences of `<runid>` anywhere — §8.5.)
- **Chain 2:** *If* this were coincidence, AVSA would have hit `/admin/chats` without the leak. Impossible: AVSA holds no route wordlist; the string entered its knowledge only via the leak module's parsed output. (Negative control: a run with the leak's route output suppressed never hits the route — §8.5.)

### 6.7 De-duplication (the §5.1 note, discharged)

The SQLi **identity-pivot** primitive and the **IDOR** module can both terminate at "read the victim's data," but the engine must not count one outcome as two chains. They are distinguished by **root cause**, recorded in each finding:

- **IDOR:** Alice *stays Alice*; an unentitled object reference is dereferenced (broken access control, A01).
- **SQLi identity-pivot:** Alice *is rewritten into the victim* (`session["user_id"]` set via injection); the subsequent read goes through *safe* parameterised pages (injection, A03).

Same endpoint reached, different vulnerability. The engine keys findings on root cause, not on the terminal data read, so "read the victim's chat" surfaces once per genuine root cause and never inflates the chain count.

### 6.8 Engine output

For each asserted chain the engine emits a structured `Chain` record: chain id, the ordered constituent findings, the **shared artifact** (the literal matched string), the **provenance class** (strict-necessity vs provenance-qualified vs manually-evidenced-token-linked), the falsifiability note, and pointers to every evidence file in the custody trace. The reporter (§7) renders this as the examiner-facing chain view — each chain told as a custody story from minted token to downstream observation.

---

## 7. Reporting

### 7.1 Purpose and audience

The reporter turns AVSA's internal findings into two artefacts with two readers: a **machine-readable** record (`findings.json`) for reproducibility, and a **human-readable** record (`report.md`) written for the *examiner* — it must tell the six findings and, above all, the two chains as evidence-backed stories. Per the Golden Rule and §6.3, it states attempt counts, provenance classes, and caveats plainly. A finding that is weak is *labelled* weak.

### 7.2 Two outputs, one source of truth

Both outputs serialise from the same in-memory finding/chain objects, so they can never disagree. `report.md` is a rendering of `findings.json` plus narrative — not a separately-authored document. The JSON is the testable ground truth; the Markdown is its readable projection.

### 7.3 `findings.json` — structure `[contract — confirm at build]`

A single run object containing run metadata, the vulnerability findings, and the asserted chains. Shape (illustrative — the field set is the build target, adjustable if building the reporter reveals a field that does not earn its place):

```json
{
  "run_id": "AVSA-XSS-7f3a2c",
  "target": "http://127.0.0.1:5000",
  "started_at": "...",
  "findings": [
    {
      "id": "sqli",
      "name": "SQL Injection",
      "layer": "web",
      "present": true,
      "severity": "Critical",
      "owasp": "A03:2021 - Injection",
      "primitives": ["auth_bypass", "boolean_blind", "error_based"],
      "attempts": null,
      "evidence": ["evidence/sqli_authbypass.txt", "evidence/sqli_error_disclosure.txt"]
    }
  ],
  "chains": [
    {
      "id": "chain1",
      "name": "Prompt Injection -> Insecure Output -> IDOR delivery",
      "constituents": ["prompt_injection", "insecure_output", "idor"],
      "shared_artifact": "AVSA-XSS-7f3a2c",
      "provenance": {
        "automated_steps": "strict-artifact-linked",
        "execution": "manually-evidenced-token-linked"
      },
      "falsifiability_note": "...",
      "custody": ["evidence/promptinj.txt", "evidence/xss_served.html", "evidence/idor_2.html"]
    }
  ]
}
```

Key fields:
- **`attempts`** — populated for LLM-layer findings (e.g. `"4/5"` for leakage), `null` for deterministic web findings. The §3 house rule surfacing in the output.
- **`shared_artifact`** — the literal run token whose cross-finding identity *is* the chain proof (§6.2). Printed verbatim so a reader can grep the evidence files and verify the match.
- **`provenance`** — per-chain honesty label.
- **`severity`** — see §7.5.
- **`evidence` / `custody`** — relative paths into `evidence/`; every claim is backed by a file on disk.

### 7.4 `report.md` — structure

Examiner-facing, in this order:

1. **Run header** — target, run id, timestamp, one-line verdict ("6/6 vulnerabilities present; 2/2 chains asserted").
2. **Methodology note** — black-box stance, single foothold (Alice), the confirmation-based N-retry rule for LLM probes, and the no-route-wordlist constraint. Three sentences; it pre-empts the obvious viva questions.
3. **Findings table** — the six, each: name, layer, present, severity, OWASP mapping, attempt count where applicable.
4. **Per-finding detail** — for each: signal, the probe sent, what was observed, evidence pointer. Paraphrased, not raw dumps inline (raw lives in `evidence/`).
5. **Chain view** — the centrepiece (§7.6).
6. **Honesty / limitations footer** — explicit caveats: LLM non-determinism and how attempt counts reflect it; provenance-qualified strands (leaked-schema→SQLi); the AVSA-proves-served-unescaped / manual-proves-execution split for Chain 1.

### 7.5 Severity

A small, defensible scheme rather than a borrowed CVSS apparatus. Each finding gets **Critical / High / Medium**, assigned by a fixed rule printed in the report so it is not arbitrary:

- **Critical** — direct compromise of confidentiality/integrity across a trust boundary (SQLi auth-bypass; IDOR cross-user read; both chains).
- **High** — significant weakness exploitable but bounded (stored XSS served-unescaped; insecure output handling; prompt injection).
- **Medium** — information disclosure that enables other attacks (system prompt leakage; error-based SQL disclosure as a sub-primitive).

**Standalone severity ≠ chain severity.** To avoid double-counting the same risk, a finding's chain-enabling power is rated in the *chain's* Critical rating, not inflated into the standalone finding. The report prints a one-line note next to the relevant labels to pre-empt the examiner's obvious question:

- System Prompt Leakage — **Medium** · *"chain-enabling impact rated in Chain 2, not here."*
- Prompt Injection — **High** · *"Chain 1 role rated in the chain, not here."*

### 7.6 The chain view (the centrepiece)

For each chain the report renders a **custody story**: the ordered steps, each naming the evidence file and the shared token, ending with the falsifiability note from §6.6.

Chain 1 reads as a five-row custody trace:

1. mint + induce → `promptinj.txt` (token `AVSA-XSS-<runid>` in bot reply)
2. served unescaped via `|safe` → `xss_served.html` (same token, live node)
3. genuine IDOR on unowned (Bob) chat → `idor_<bobid>.html` (boundary crossed)
4. **artifact identity check:** token@1 `==` token@2 → automated chain asserted (strict)
5. **execution coda (manual):** same token firing in the victim's session → Ch4/Ch5 screenshot (token-linked)

Chain 2 reads as a spine-plus-strand trace: leak emits `/admin/chats` → forced-browse hits exactly that string → admin data served to non-admin Alice (spine, strict-necessity via the no-wordlist guarantee), with leaked-schema→SQLi shown as a provenance-qualified supporting strand. Each chain ends with its explicit "if this were coincidence… / impossible because…" note.

### 7.7 What the reporter does not do

No remediation advice, no "suggested fixes" (Golden Rule — AVSA assesses; the Defend discussion lives in the report's narrative chapters). No severity inflation. No full data dumps (the no-UNION-dump rule from §5.1 holds). The reporter renders what was proven, labelled honestly, and nothing more.

---

## 8. Validation Plan

> Feeds Chapter 5 directly (unit testing + UAT).

### 8.1 What validation must establish

AVSA's validation answers one question in two halves: **does AVSA automatically reproduce what was proven by hand, and does it do so without hallucinating findings or chains that are not there?** The first half is *sensitivity* (it finds what is real); the second is *specificity* (it does not assert what is false). A scanner that flags everything is as useless as one that flags nothing — so the anti-false-positive evidence (§8.5) is treated as first-class.

### 8.2 The two-layer test strategy (key design decision)

AVSA is part deterministic, part non-deterministic, and the validation must not pretend otherwise:

- **Deterministic surface** — the three web modules (fixed DVAI state → same probe → same result) **and the entire Chain Correlation Engine** (pure logic over findings + artifacts: same inputs → same chain verdict). Tested with classic, repeatable unit tests that pass or fail deterministically.
- **Non-deterministic surface** — the three LLM modules, whose pass/fail varies run to run. Validated *statistically* via the confirmation harness: success is "invariant signal appeared within N attempts," and the reported metric is the **success rate across repeated runs** (e.g. "leakage confirmed in 9/10 independent runs, mean 3.4 attempts"), not a single pass/fail.

Separating these is what makes Ch5 rigorous: the **logic** of the contribution (chain correlation) is proven with deterministic unit tests, while the **probing** of a non-deterministic target is proven with honest success-rate statistics.

### 8.3 Unit testing (Chapter 5 core)

**Web modules** — each tested in isolation against a known DVAI state:
- SQLi: auth-bypass yields an authenticated session; boolean-blind pair yields the expected differential; malformed payload surfaces the `sqlite3.OperationalError` disclosure. Each primitive is its own test case.
- IDOR: enumeration finds an unowned (Bob) chat id; fetching it from Alice's session returns content not in Alice's entitled set; `/admin/chats` is reachable from a non-admin session. **Negative case:** a chat id Alice *does* own is correctly classified as **not** an IDOR.
- Stored XSS: a unique-marker payload is stored and bs4 confirms it served as a live node. **Negative case:** a properly-escaped string is correctly classified as **not** vulnerable.

**Chain Correlation Engine — the centrepiece of the unit suite.** Because the engine is pure logic and dependency-injectable (§4), it is tested **with fabricated finding/artifact fixtures, no live LLM required**:
- *Positive:* two findings sharing an identical `<runid>` → asserts the chain, strict provenance.
- *Negative (no false chain):* two genuine findings whose tokens **differ** → must **refuse** to assert a chain. This is the single most important test in the suite — it directly proves "AVSA detects causation, not mere co-occurrence."
- *Provenance labelling:* the leaked-schema→SQLi case → labelled *provenance-qualified*, not strict.
- *De-dup:* a SQLi identity-pivot and an IDOR both terminating at "read Bob" → recorded as two distinct root causes, not one inflated chain.
- *Boundary guard (§6.4):* a Chain-1 candidate whose IDOR id resolves to Alice's *own* chat → engine refuses the IDOR step (no phantom IDOR).

That the engine is unit-testable *without* touching the LLM is a deliberate payoff of keeping modules dumb and correlation separate. The novel contribution gets the most rigorous, most repeatable tests in the project.

### 8.4 Integration testing (live, against real DVAI)

End-to-end runs against the running DVAI + live `gpt-4.1-mini`, reproducing the hand-proven results: full six-module run → all six findings present; Chain 1 automated portion (steps 1–4) asserted via shared `<runid>`; Chain 2 spine asserted via leaked `/admin/chats` → forced-browse; each run records LLM attempt counts feeding the §8.2 statistics. Integration runs are repeated (**≥10 runs**) so the LLM-layer success rates are real measurements, not a single lucky pass.

### 8.5 Negative controls (anti-overclaim evidence)

Two controls, run as **formal repeatable tests in the automated suite** (not just manual viva demos):
- **Injection-skipped control (Chain 1):** run with the injection step disabled → the `<runid>` token appears **nowhere** in any served response → engine asserts **no** Chain 1. Proves the token's downstream presence in a real run is caused by injection, nothing else.
- **No-wordlist control (Chain 2):** run with the leak module's route output suppressed → AVSA has no source for `/admin/chats` → it never hits that route → no Chain 2 spine. Demonstrates the §6.5 structural guarantee rather than merely asserting it.

These controls convert "we found a chain" into "we found a chain *and proved it could not be coincidence*."

### 8.6 User Acceptance Testing (min. 3 users) `[CONFIRM vs supervisor]`

UAT for a security tool is **task-based acceptance**, not a satisfaction survey — and it must be **genuinely conducted, never fabricated** (real participants, real runs, real recorded feedback). Format is pending the supervisor's sign-off (task-based vs questionnaire); the table form the supervisor requires is retained alongside the task-based criteria below; this section stays provisional until she replies but does not block the build.

- **Participants:** ≥3 competent peers (e.g. fellow APU cybersecurity students) — the relevant acceptance population for a developer/security tool.
- **Task:** each participant independently (a) runs AVSA against a fresh DVAI instance, (b) reads `report.md`, and (c) checks the report's findings against the ground truth (the known six vulns + two chains).
- **Measured acceptance criteria:** Did the tool run to completion without hand-holding? Could the participant locate each finding's evidence file and confirm it? Could they understand the chain view well enough to explain, in their own words, *why* it is a chain and not coincidence? Was the report's honesty labelling (attempt counts, provenance) clear?
- **Collected data:** a short structured form per participant (task completion yes/no per criterion + free-text clarity feedback). Honest results recorded as-is — if a participant found the chain view confusing, that goes in Ch5 as a finding and a future-work item, not airbrushed.

### 8.7 The validation matrix (hand-proven → automated reproduction)

The spine of Ch5. The "Expected" column is the **target**; actual figures come from real runs per §8.4 (not pre-filled).

| Hand-proven result | AVSA module/engine | Test type | Expected |
|---|---|---|---|
| SQLi auth-bypass (`' OR '1'='1' -- `) | SQLi / auth_bypass | unit + integration | session obtained |
| Boolean-blind differential | SQLi / boolean_blind | unit | login/no-login oracle |
| Error-based SQL disclosure | SQLi / error_based | unit + integration | `OperationalError` echoed |
| IDOR cross-user read | IDOR / enumeration | unit + integration | unowned chat served |
| `/admin/chats` forced browse | IDOR (folded) | unit + integration | admin data to non-admin |
| Stored XSS served unescaped | XSS | unit + integration | live node via bs4 |
| Prompt injection (naive✗ / framed✓) | PromptInj | integration | marker emitted, attempts logged |
| System prompt leakage (4 tries by hand) | SysPromptLeak (N=5) | integration | recon parsed, ~k/5 reported |
| Insecure output (bot→`\|safe`) | InsecureOutput | integration | bot marker served unescaped |
| Chain 1 (inj→output→IDOR) | Engine | unit (fixtures) + integration | asserted via shared `<runid>` |
| Chain 1 cross-user execution | *manual* | screenshot, token-linked | tab flips to `AVSA-XSS-<runid>` |
| Chain 2 (leak→`/admin/chats`) | Engine | unit (fixtures) + integration | spine asserted, strict |
| Chain 2 leak→SQLi strand | Engine | unit (fixtures) | labelled provenance-qualified |

### 8.8 Honest limitations of the validation

Stated plainly in Ch5, because naming limits is itself a mark of rigour: LLM-layer results are statistical, not guaranteed (a future model or API change could shift success rates); UAT is small-n (≥3) and its participants are peers, not an independent security audit; AVSA proves served-unescaped, with cross-user *execution* carried by manual evidence (the agreed split); and the validation is against a single, self-built target (DVAI), so AVSA's generality beyond DVAI is explicitly *not* claimed by this project (Track B would be the first external test, later, under authorisation).

---

*End of AVSA_SPEC.md*
