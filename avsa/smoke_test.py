"""Live end-to-end smoke test for the AVSA probe layer.

This is NOT a unit test and is NOT run automatically. It needs DVAI running
locally AND a working OpenAI key configured in DVAI (so chat() gets a real bot
reply rather than the stub). Run it by hand from the repo root:

    python -m avsa.smoke_test

Config comes from environment variables so no credentials live in code:
    AVSA_BASE_URL   (default http://127.0.0.1:5000)
    AVSA_USER       DVAI account username (e.g. a seeded user)
    AVSA_PASS       DVAI account password

It exercises the full happy path: login -> is_authenticated -> chat, then prints
the run marker, the chat id that was created, and the bot's reply.
"""

import os

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

    if not probe.login():
        print("login           : FAILED — check AVSA_USER/AVSA_PASS and that DVAI is up.")
        return
    print("login           : OK")
    print(f"authenticated   : {probe.is_authenticated()}")

    result = probe.chat("hello from AVSA smoke test")
    print(f"chat_id         : {result.chat_id}")
    print(f"status_ok       : {result.status_ok}")
    print(f"bot reply       : {result.reply}")


if __name__ == "__main__":
    main()
