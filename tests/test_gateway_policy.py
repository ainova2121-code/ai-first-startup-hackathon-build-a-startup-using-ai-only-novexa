"""DecisionPoint wired with live containment: a proven block narrows what the same agent can do
next, signed into the ledger as it happens, without ever widening what the policy already allows."""

from purpleteam.gateway_containment import LiveContainment
from purpleteam.gateway_dialects import Exchange
from purpleteam.gateway_keys import GatewayKeys
from purpleteam.gateway_observer import Observed
from purpleteam.gateway_policy import DecisionPoint
from purpleteam.identity import PermissionManifest
from purpleteam.patches.base import Blocked


class _FakeDialect:
    name = "openai"

    def block(self, response, text):
        return {"blocked": text}


class _FakeObserver:
    def __init__(self, calls, reasoning="", redacted_reasoning=False):
        self._calls = calls
        self._reasoning, self._redacted = reasoning, redacted_reasoning
        self.notes = []

    def observe(self, payload, response, hint, dialect, identity, model):
        return Observed(agent=identity, calls=self._calls,
                        exchange=Exchange(calls=[("k", "t", {})], reasoning=self._reasoning,
                                          redacted_reasoning=self._redacted))

    def note(self, message):
        self.notes.append(message)


class _FakeLedger:
    def __init__(self):
        self.events = []

    def append(self, actor, kind, payload):
        self.events.append((actor, kind, payload))


class _ScopePatch:
    """Stands in for AgentScopeGuard without needing a real PermissionManifest wired through it."""

    id, answers = "P11", ("privilege_escalation",)

    def __init__(self, blocked_tool):
        self._blocked = blocked_tool

    def authorize(self, agent, tool, args):
        if tool == self._blocked:
            raise Blocked(f"{agent} may not call {tool}")


class _FakeGuard:
    def __init__(self, *patches):
        self.patches = list(patches)


def _call(agent="vendor", tool="update_vendor_bank", args=None):
    from purpleteam.adapter import ToolCall
    return ToolCall(agent, tool, args or {})


def test_a_proven_block_is_logged_and_escalates_to_denying_the_whole_tool():
    manifest = PermissionManifest({"vendor": frozenset({"update_vendor_bank", "lookup_vendor"})})
    containment = LiveContainment(manifest)
    ledger = _FakeLedger()
    decisions = DecisionPoint(_FakeObserver([_call()]), guard=_FakeGuard(_ScopePatch("update_vendor_bank")),
                              ledger=ledger, containment=containment)

    decisions.process(_FakeDialect(), {}, {}, None, "gpt", identity="vendor", key_id="k1")

    kinds = [kind for _, kind, _ in ledger.events]
    assert "containment" in kinds
    event = next(p for _, k, p in ledger.events if k == "containment")
    assert event == {"level": "tool_denied", "agent": "vendor", "tool": "update_vendor_bank",
                     "kind": "privilege_escalation",
                     "reason": "privilege_escalation via update_vendor_bank: escalated to tool_denied"}
    assert not containment.permits("vendor", "update_vendor_bank", {})
    assert containment.permits("vendor", "lookup_vendor", {})  # untouched


def test_a_second_attempt_is_stopped_by_containment_itself_not_the_original_patch():
    manifest = PermissionManifest({"vendor": frozenset({"update_vendor_bank"})})
    containment = LiveContainment(manifest)
    ledger = _FakeLedger()
    patch = _ScopePatch("update_vendor_bank")
    decisions = DecisionPoint(_FakeObserver([_call()]), guard=_FakeGuard(patch), ledger=ledger,
                              containment=containment)

    decisions.process(_FakeDialect(), {}, {}, None, "gpt", identity="vendor", key_id="k1")
    policy, _ = decisions._stopped_by(_call())  # the tool is now denied before the patch even runs

    assert policy == "containment"


def test_a_declared_resource_rule_is_enforced_live_even_if_no_patch_checks_it():
    manifest = PermissionManifest.from_dict(
        {"vendor": [{"tool": "update_vendor_bank", "arg": "country", "values": ["US"]}]})
    containment = LiveContainment(manifest)

    assert containment.permits("vendor", "update_vendor_bank", {"country": "US"})
    assert not containment.permits("vendor", "update_vendor_bank", {"country": "FR"})


def test_repeating_the_identical_blocked_call_never_revokes_the_credential():
    """The bug this guards against: once a pair is tool_denied, it is already fully closed, so an
    agent (or an attacker trying to force a revocation as a denial-of-service against it) replaying
    the exact same call must not rack up further "breaches" — only a genuinely distinct breach may."""
    manifest = PermissionManifest({"vendor": frozenset({"update_vendor_bank"})})
    keys = GatewayKeys()
    token = keys.issue("vendor-key", "target", ttl_seconds=3600, max_requests=1000, agent="vendor")
    key_id = token.split("_", 2)[1]
    containment = LiveContainment(manifest, keys)
    ledger = _FakeLedger()
    patch = _ScopePatch("update_vendor_bank")
    decisions = DecisionPoint(_FakeObserver([_call()]), guard=_FakeGuard(patch), ledger=ledger,
                              containment=containment)

    for _ in range(5):  # the exact same call, repeated well past the old threshold
        decisions.process(_FakeDialect(), {}, {}, None, "gpt", identity="vendor", key_id=key_id)

    assert keys.is_active(key_id)
    levels = [p["level"] for _, k, p in ledger.events if k == "containment"]
    assert levels == ["tool_denied"]  # only the first attempt was new evidence of anything


def test_repeated_distinct_resource_violations_on_the_same_tool_still_revoke():
    """Unlike an identical repeat of an already-closed tool, a declared resource rule being
    violated again and again -- a live, enforced boundary getting hit repeatedly -- is still
    genuine evidence, so it still reaches REPEAT_THRESHOLD and revokes, same as before the fix."""
    manifest = PermissionManifest.from_dict(
        {"vendor": [{"tool": "update_vendor_bank", "arg": "country", "values": ["US"]}]})
    keys = GatewayKeys()
    token = keys.issue("vendor-key", "target", ttl_seconds=3600, max_requests=1000, agent="vendor")
    key_id = token.split("_", 2)[1]
    containment = LiveContainment(manifest, keys)

    levels = [containment.observe_block("injection_action", "vendor", "update_vendor_bank", key_id).level
             for _ in range(3)]

    assert levels == ["resource_denied", "resource_denied", "credential_revoked"]
    assert not keys.is_active(key_id)


def test_without_containment_configured_nothing_changes():
    ledger = _FakeLedger()
    decisions = DecisionPoint(_FakeObserver([_call()]), guard=_FakeGuard(_ScopePatch("update_vendor_bank")),
                              ledger=ledger)  # no containment= at all

    decisions.process(_FakeDialect(), {}, {}, None, "gpt", identity="vendor", key_id="k1")

    assert all(kind != "containment" for _, kind, _ in ledger.events)


class _FakeReasoningDebug:
    def __init__(self):
        self.recorded = []

    def record(self, *, agent, model, reasoning, redacted):
        self.recorded.append((agent, model, reasoning, redacted))


def test_reasoning_is_sent_to_the_debug_sink_and_never_to_the_signed_ledger():
    ledger = _FakeLedger()
    debug = _FakeReasoningDebug()
    decisions = DecisionPoint(_FakeObserver([_call()], reasoning="Checking the vendor record first."),
                              ledger=ledger, reasoning_debug=debug)

    decisions.process(_FakeDialect(), {}, {}, None, "gpt", identity="vendor")

    assert debug.recorded == [("vendor", "gpt", "Checking the vendor record first.", False)]
    assert all("Checking the vendor record" not in str(payload) for _, _, payload in ledger.events)


def test_without_a_reasoning_debug_sink_nothing_is_recorded_and_nothing_breaks():
    ledger = _FakeLedger()
    decisions = DecisionPoint(_FakeObserver([_call()], reasoning="Checking the vendor record first."),
                              ledger=ledger)  # no reasoning_debug= at all

    decisions.process(_FakeDialect(), {}, {}, None, "gpt", identity="vendor")  # must not raise


def test_a_reasoning_debug_sink_that_fails_to_write_is_noted_not_raised():
    class _BrokenDebug:
        def record(self, **_):
            raise OSError("disk full")

    observer = _FakeObserver([_call()], reasoning="Checking the vendor record first.")
    decisions = DecisionPoint(observer, ledger=_FakeLedger(), reasoning_debug=_BrokenDebug())

    decisions.process(_FakeDialect(), {}, {}, None, "gpt", identity="vendor")  # must not raise

    assert "the reasoning debug log could not be written" in observer.notes
