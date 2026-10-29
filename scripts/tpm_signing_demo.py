"""Manual demo of hardware-backed checkpoint signing: run on a machine with a real Windows TPM to
see a live signature, not a mocked one (tests/test_tpm_windows.py and tests/test_hardware_signer.py
both mock the hardware deliberately, so this is the only place that touches real silicon).

Deletes its own demo ledger file first so repeat runs never append to stale, mismatched state.

Run:  uv run python scripts/tpm_signing_demo.py
"""

import os
from pathlib import Path

from purpleteam.audit.ledger import AuditLedger
from purpleteam.gateway_crypto import hardware

LEDGER_PATH = Path("tpm_demo_ledger.jsonl")

os.environ["GATEWAY_HARDWARE_SIGNING"] = "preferred"
signer = hardware()
print()

LEDGER_PATH.unlink(missing_ok=True)
LEDGER_PATH.with_suffix(".lock").unlink(missing_ok=True)

ledger = AuditLedger(LEDGER_PATH, hardware=signer)
ledger.append("demo", "event", {"note": "this is the event the checkpoint below covers"})

checkpoint = ledger.checkpoint()
print("checkpoint:", checkpoint)
print()
print("hwkid  (the TPM key id):", checkpoint.get("hwkid"))
print("hwsig  (the TPM-produced signature):", checkpoint.get("hwsig"))

trust = ledger.export_trust()
print()
print("trust file hardware block:", trust["hardware"])
