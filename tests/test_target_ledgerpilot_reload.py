"""After its source is edited (or restored), LedgerPilot must be re-imported from disk, and every
target built afterwards must run that code -- never a reference bound before the edit."""

import sys

import pytest

from purpleteam.patches.base import Blocked, HoldForReview
from purpleteam.targets import ledgerpilot as target_module


@pytest.fixture(autouse=True)
def _keep_loaded_modules(monkeypatch):
    """reload_source swaps sys.modules entries; put the originals back so no other test sees them."""
    monkeypatch.setenv("LEDGERPILOT_LLM_API_KEY", "test-key-never-sent")
    saved = {name: mod for name, mod in sys.modules.items() if name.startswith("ledgerpilot")}
    yield
    for name in [m for m in sys.modules if m.startswith("ledgerpilot")]:
        del sys.modules[name]
    sys.modules.update(saved)


def test_reload_source_imports_ledgerpilot_afresh():
    before = sys.modules["ledgerpilot.db.repositories"]
    target_module.reload_source()
    assert sys.modules["ledgerpilot.db.repositories"] is not before


def test_a_target_built_after_a_reload_uses_the_reloaded_code():
    target_module.reload_source()
    target = target_module.LedgerPilotTarget()
    assert target._repos is sys.modules["ledgerpilot.db.repositories"]


class _Raising:
    def __init__(self, error):
        self._error = error

    def authorize(self, agent, tool, args):
        raise self._error

    def screen(self, agent, text, source):
        raise self._error


def test_the_guard_adapter_raises_the_ports_exceptions_of_the_code_it_was_built_with():
    target_module.reload_source()
    ports = sys.modules["ledgerpilot.ports"]
    with pytest.raises(ports.ReviewRequired):
        target_module._GuardAdapter(_Raising(HoldForReview("held")), ports).authorize("a", "t", {})
    with pytest.raises(ports.Blocked):
        target_module._GuardAdapter(_Raising(Blocked("no")), ports).screen("a", "text", "input")
