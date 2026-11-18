# AVSA + DVAI

**A vulnerability scanner that follows an attack across the AI/web boundary, and the deliberately vulnerable AI app it was built to break.**

Most scanners find isolated bugs. In an LLM-integrated web app, the interesting attacks are chains: a manipulated model reply becomes stored XSS, or a leaked system prompt tells an attacker exactly where to point SQLi and IDOR. **AVSA** (Automated Vulnerability Scanner & Assessor) detects those cross-layer chains and shows the evidence linking each step.

This is my final year project (BSc Cybersecurity, Asia Pacific University): *Automated Security Assessment of LLM-Integrated Web Applications: A Cross-Layer Attack Chain Approach.*

> **Lab use only.** DVAI is insecure on purpose, the same idea as DVWA or OWASP Juice Shop. Run it on localhost, never expose it to a network, and only point AVSA at systems you own or have written permission to test.

## What's in the repo

| Folder | What it is |
|---|---|
| `dvai/` | **The target.** A minimal AI customer-support chatbot (Flask, SQLite, OpenAI API) with six planted vulnerabilities. Port 5000. |
| `dvai_hardened/` | The same app with one defence added (prompt-injection datamarking, "spotlighting"). The web-layer flaws are left in, so a before/after scan isolates what that single fix changes. Port 5001. |
| `avsa/` | **The scanner.** Six detection modules, a chain-correlation engine and a reporter. Black-box: talks to the target over HTTP only and never reads its source. |
| `avsa_gui/` | A small Flask dashboard to run scans, view findings and attack chains, download reports, and compare two targets side by side. Port 5050. |
| `docs/` | Design specs (`AVSA_SPEC.md`, `DVAI_SPEC.md`, database schema) and a sample scan report. |
| `.github/workflows/` | An example CI/CD security gate that fails a build if AVSA finds anything. |

## The two attack chains

1. **Prompt Injection -> Insecure Output Handling -> Stored XSS.** An injected instruction makes the bot emit a payload. The app stores it and renders it without escaping, so it runs in the next viewer's browser. AVSA plants a unique per-run marker and proves the same marker travels from the model reply to the rendered page.
2. **System Prompt Leakage -> Recon -> SQLi / IDOR.** Coaxing the hidden system prompt out of the bot reveals internal details (schema hints, endpoints) that guide a web-layer attack. AVSA checks that what leaked is what the later attack used.

## Intentionally vulnerable (DVAI)

| Vulnerability | Layer | Where | OWASP |
|---|---|---|---|
| System prompt leakage | LLM | Hidden system prompt, no output filtering | LLM07:2025 |
| Prompt injection | LLM | User input goes straight into the prompt | LLM01:2025 |
| Insecure output handling | LLM | Model output rendered unsanitised | LLM05:2025 |
| SQL injection | Web | Login query built with string concatenation | A03:2021 |
| IDOR | Web | `/chat/<id>` has no ownership check | A01:2021 |
| Stored XSS | Web | Messages rendered with `\| safe` | A03:2021 |

Passwords are stored in plaintext and the Flask secret is a dev default. All of it is on purpose, so there is something real for AVSA to find.

## Sample result

Against DVAI the scanner reports **6/6 vulnerabilities present and 2/2 cross-layer chains asserted**, with custody evidence for each step. See [`docs/sample_report/sample_report.md`](docs/sample_report/sample_report.md).

## Quick start

Needs Python 3.10+. Commands are for Windows PowerShell; on Linux/macOS use `source .venv/bin/activate` and `export` in place of `set`.

**1. Start the target**

```powershell
cd dvai
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env      # add your own OpenAI key (see note below)
python seed.py              # creates users alice / bob with fixed IDs
python app.py               # http://127.0.0.1:5000
```

Demo accounts: `alice` / `password123` and `bob` / `hunter2`. Without an OpenAI key DVAI returns a canned reply, so the web-layer modules (SQLi, IDOR, XSS) still work. The LLM-layer modules need a funded key on the DVAI side. Set a hard spending cap on that key and use a cheap model (`MODEL_NAME` in `.env`).

**2. Run the scanner** (new terminal, repo root)

```powershell
pip install -r avsa/requirements.txt
set AVSA_USER=alice
set AVSA_PASS=password123
python -m avsa.run_all      # writes output/report.md and output/findings.json
```

Each module also runs on its own, e.g. `python -m avsa.run_sqli`.

**3. Or use the dashboard**

```powershell
pip install flask
python -m avsa_gui.app      # http://127.0.0.1:5050
```

**4. Before/after comparison.** Start `dvai_hardened` (`cd dvai_hardened`, `python seed.py`, `python app.py`) and use *Compare two targets* in the dashboard. Only prompt injection should flip to "absent".

`start_avsa_gui.bat` and `start_dvai_hardened.bat` are Windows shortcuts for steps 3 and 4 once `dvai\.venv` exists.

## Tests

```powershell
pip install -r avsa/requirements.txt
python -m pytest avsa/tests
```

102 unit tests cover every detection module, the chain-correlation engine, the reporter and the non-HTTP adapter. They run without a live target.

## How AVSA is built

- **Black-box by design.** AVSA never imports DVAI. It logs in as one low-privilege user and attacks over HTTP, like an outside attacker.
- **One shared probe per run.** Every module shares a run ID, so the markers it plants carry the same token. That shared token is what lets the engine link findings into a chain instead of reporting them as unrelated bugs.
- **Confirmation over guesswork.** LLM probes are non-deterministic, so each module retries and reports attempts (e.g. `1/3`). Findings come with evidence, not just a verdict.
- **Transport-agnostic LLM modules.** `avsa/adapters/local_cli.py` runs the same login/chat/confirm contract against a plain in-process object with no HTTP at all.
- **CI/CD gate.** Setting `AVSA_FAIL_ON_FINDING=1` makes `run_all` exit non-zero when anything is found. The example workflow in `.github/workflows/` uses it, triggered manually against a target you supply.

## Stack

Python, Flask, SQLite, OpenAI API, `requests`, BeautifulSoup, pytest, GitHub Actions.

## License

MIT. See [LICENSE](LICENSE). Educational use only; see the lab-use note at the top.
