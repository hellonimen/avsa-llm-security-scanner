"""Live driver for the AVSA System Prompt Leakage module
(avsa.modules.system_prompt_leakage).

NOT run automatically — it needs DVAI running locally AND a funded OpenAI key on
the DVAI side (it actually talks to the bot). Run it by hand from the repo root:

    python -m avsa.run_system_prompt_leakage

Config comes from environment variables (no credentials in code):
    AVSA_BASE_URL   (default http://127.0.0.1:5000)
    AVSA_USER       DVAI account username
    AVSA_PASS       DVAI account password

The module logs in as AVSA_USER/AVSA_PASS and climbs a direct -> indirect ladder
against the bot. Because leakage is non-deterministic (and stubborn), the module
confirms over N=5 attempts per rung; the reported `attempts` value is that
confirm() ratio (e.g. "4/5" = leaked on the 4th of 5 tries). On a landing it also
returns `leaked_recon` — the structured schema/route/infra detail that seeds Chain 2.
"""

import json
import os

from avsa.modules import system_prompt_leakage
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

    finding = system_prompt_leakage.run(probe)

    print(f"[{finding.id}] {finding.name}  ({finding.layer} layer)")
    print(f"  present     : {'YES' if finding.present else 'no'}")
    print(f"  attempts    : {finding.attempts or '(n/a)'}")
    print(f"  severity    : {finding.severity}")
    print(f"  owasp       : {finding.owasp}")
    print(f"  primitives  : {', '.join(finding.primitives) if finding.primitives else '(none landed)'}")
    print()

    print("  leaked_recon (structured — the Chain 2 seed):")
    if finding.leaked_recon:
        for line in json.dumps(finding.leaked_recon, indent=2).splitlines():
            print(f"    {line}")
    else:
        print("    (nothing leaked)")
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
