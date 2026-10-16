"""Shared helpers for the ledger tests."""

from pathlib import Path

from purpleteam.audit.keys import AgentKeyring
from purpleteam.audit.ledger import AuditLedger


def make_ledger(path: Path, keyring: AgentKeyring | None = None, events: int = 5) -> AuditLedger:
    ledger = AuditLedger(path, keyring=keyring)
    for i in range(events):
        ledger.append("attacker" if i % 2 == 0 else "oracle", "attack", {"n": i})
    return ledger


def log_lines(ledger: AuditLedger) -> list[str]:
    return ledger.path.read_text().splitlines()


def rewrite_log(ledger: AuditLedger, lines: list[str]) -> None:
    ledger.path.write_text("\n".join(lines) + "\n")
