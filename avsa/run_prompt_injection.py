"""Live driver for the AVSA Prompt Injection module (avsa.modules.prompt_injection).

NOT run automatically — it needs DVAI running locally AND a funded OpenAI key on
the DVAI side (this is the first driver that actually talks to the bot). Run it by
hand from the repo root:

    python -m avsa.run_prompt_injection

Config comes from environment variables (no credentials in code):
    AVSA_BASE_URL   (default http://127.0.0.1:5000)
    AVSA_USER       DVAI account username
    AVSA_PASS       DVAI account password

Note: prompt injection is committed FROM a valid account — the module logs in as
AVSA_USER/AVSA_PASS and drives the bot. Because the bot is non-deterministic, the
module confirms over N=3 attempts per rung; the reported `attempts` value is that
confirm() ratio (e.g. "2/3" = landed on the 2nd of 3 tries).
"""

import os

from avsa.modules import prompt_injection
from avsa.probe import Config, Probe


def main() -> None:
    config = Config(
        base_url=os.environ.get("AVSA_BASE_URL", "http://127.0.0.1:5000"),
        username=os.environ.get("AVSA_USER", ""),
        password=os.environ.get("AVSA_PASS", ""),
    )
    probe = Probe(config)
    print(f"run_id / marker : {probe.run_id}")
    print(f"target          : {config.base_url}")
    print(f"user            : {config.username or '(unset)'}")
    print()

    finding = prompt_injection.run(probe)

    print(f"[{finding.id}] {finding.name}  ({finding.layer} layer)")
    print(f"  present     : {'YES' if finding.present else 'no'}")
    print(f"  attempts    : {finding.attempts or '(n/a)'}")
    print(f"  severity    : {finding.severity}")
    print(f"  owasp       : {finding.owasp}")
    print(f"  primitives  : {', '.join(finding.primitives) if finding.primitives else '(none landed)'}")
    print()

    if finding.evidence:
        print("  evidence:")
        for name, detail in finding.evidence.items():
            print(f"    - {name}: {detail}")
    else:
        print("  evidence    : (none)")

    print()
    print(f"  notes       : {finding.notes}")


if __name__ == "__main__":
    main()
