"""Live driver for the AVSA IDOR module (avsa.modules.idor).

NOT run automatically — it needs DVAI running locally. Run it by hand from the
repo root:

    python -m avsa.run_idor

Config comes from environment variables (no credentials in code):
    AVSA_BASE_URL   (default http://127.0.0.1:5000)
    AVSA_USER       DVAI account username
    AVSA_PASS       DVAI account password

Note: unlike the SQLi driver, IDOR is committed FROM a valid account — the module
logs in as AVSA_USER/AVSA_PASS and enumerates other users' chats from that
authenticated session. Valid credentials are required for this check to fire.

Tip: re-seed DVAI (python seed.py) first for a clean result — then logging in as
alice (owns chat 1) should flag chat 2 (bob's) as the cross-user read.
"""

import os

from avsa.modules import idor
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

    finding = idor.run(probe)

    print(f"[{finding.id}] {finding.name}  ({finding.layer} layer)")
    print(f"  present     : {'YES' if finding.present else 'no'}")
    print(f"  severity    : {finding.severity}")
    print(f"  owasp       : {finding.owasp}")
    print(f"  primitives  : {', '.join(finding.primitives) if finding.primitives else '(none landed)'}")
    print()

    if finding.evidence:
        print(f"  evidence ({len(finding.evidence)} cross-user read(s)):")
        for chat_id, detail in finding.evidence.items():
            print(f"    - chat {chat_id}: {detail}")
    else:
        print("  evidence    : (none)")

    print()
    print(f"  notes       : {finding.notes}")


if __name__ == "__main__":
    main()
