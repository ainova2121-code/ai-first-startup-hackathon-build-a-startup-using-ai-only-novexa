"""FleetPoller.run_once(): one poll cycle per registered target, advancing each one's cursor,
deriving its status from the real signed ledger (never persisting raw events), and publishing an
update either way -- including when a target is unreachable or its credentials are now wrong."""

import asyncio
import json

import httpx
from pydantic import SecretStr

from purpleteam.audit.ledger import AuditLedger
from purpleteam.console.db.repositories import TargetRepository, connect
from purpleteam.console.events import Broadcaster
from purpleteam.console.poller import PAGE_SIZE, FleetPoller
from purpleteam.console.registry import FleetRegistry
from purpleteam.gateway import Provider, create_gateway
from purpleteam.gateway_keys import ADMIN, GatewayKeys
from purpleteam.gateway_observer import GatewayObserver

_BIG = {"ttl_seconds": 3600, "max_requests": 10**6, "per_minute": 10**6}


def _registry(tmp_path):
    from purpleteam.console import crypto
    return FleetRegistry(TargetRepository(connect(tmp_path / "console.db")), crypto.derive_key("secret"))


def _real_gateway_client(ledger):
    keys = GatewayKeys()
    admin_token = keys.issue("admin", ADMIN, **_BIG)
    app = create_gateway(GatewayObserver(), keys=keys, openai=Provider("https://provider.test/v1", SecretStr("x")),
                         ledger=ledger)
    client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")
    return client, admin_token


def test_a_real_gateway_is_polled_end_to_end_and_status_derives_from_a_sealed_run(tmp_path):
    ledger = AuditLedger(tmp_path / "audit.jsonl")
    ledger.append("attacker", "attack", {"id": "t1"})
    ledger.append("oracle", "breach", {"kind": "injection_action"})
    ledger.append("audit", "seal", {"merkle_root": ledger.seal()})

    client, admin_token = _real_gateway_client(ledger)
    registry = _registry(tmp_path)
    target_id = registry.add_target("demo", "http://test", admin_token)
    broadcaster = Broadcaster()
    inbox = broadcaster.subscribe()
    poller = FleetPoller(registry, broadcaster, client)

    asyncio.run(poller.run_once())

    target = registry.get_target(target_id)
    assert target.status == "ok" and target.last_seq == 2 and target.log_id == ledger.log_id
    status = registry.get_status(target_id)
    assert status["size"] == 3
    assert json.loads(status["breach_kinds_json"]) == ["injection_action"]
    assert inbox.get_nowait() == {"target_id": target_id}


def test_a_second_cycle_only_advances_past_what_it_already_saw(tmp_path):
    ledger = AuditLedger(tmp_path / "audit.jsonl")
    ledger.append("test", "event", {"n": 0})
    client, admin_token = _real_gateway_client(ledger)
    registry = _registry(tmp_path)
    target_id = registry.add_target("demo", "http://test", admin_token)
    poller = FleetPoller(registry, Broadcaster(), client)
    asyncio.run(poller.run_once())
    assert registry.get_target(target_id).last_seq == 0

    asyncio.run(poller.run_once())  # nothing new happened
    assert registry.get_target(target_id).last_seq == 0  # cursor did not move backward or duplicate


def test_an_unreachable_gateway_is_recorded_and_still_published(tmp_path):
    registry = _registry(tmp_path)
    target_id = registry.add_target("demo", "http://unreachable.invalid", "ptgw_x_y")
    client = httpx.AsyncClient(transport=httpx.MockTransport(lambda r: (_ for _ in ()).throw(httpx.ConnectError("no"))))
    broadcaster = Broadcaster()
    inbox = broadcaster.subscribe()
    poller = FleetPoller(registry, broadcaster, client)

    asyncio.run(poller.run_once())

    target = registry.get_target(target_id)
    assert target.status == "unreachable" and target.last_error
    assert inbox.get_nowait() == {"target_id": target_id}


def test_a_rejected_admin_key_is_recorded_as_an_error_not_unreachable(tmp_path):
    registry = _registry(tmp_path)
    target_id = registry.add_target("demo", "http://gw.example", "ptgw_x_wrong")
    client = httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(403, json={})))
    poller = FleetPoller(registry, Broadcaster(), client)

    asyncio.run(poller.run_once())

    assert registry.get_target(target_id).status == "error"


def test_one_targets_failure_does_not_affect_another(tmp_path):
    ledger = AuditLedger(tmp_path / "audit.jsonl")
    ledger.append("test", "event", {"n": 0})
    good_client, admin_token = _real_gateway_client(ledger)
    registry = _registry(tmp_path)
    good_id = registry.add_target("good", "http://test", admin_token)
    bad_id = registry.add_target("bad", "http://unreachable.invalid", "ptgw_x_y")

    class _Routed(httpx.AsyncClient):
        async def get(self, url, **kwargs):
            if "unreachable.invalid" in url:
                raise httpx.ConnectError("no")
            return await good_client.get(url, **kwargs)

    poller = FleetPoller(registry, Broadcaster(), _Routed())
    asyncio.run(poller.run_once())

    assert registry.get_target(good_id).status == "ok"
    assert registry.get_target(bad_id).status == "unreachable"


def _serving(ledger, edit=lambda events: events):
    """A gateway that serves ``ledger``'s real signed events, after ``edit`` (a tamperer on disk or the wire)."""
    calls = []

    def handler(request):
        if request.url.path == "/ledger/trust":
            return httpx.Response(200, json={"log_id": ledger.log_id, **ledger.public_trust()})
        after = int(request.url.params["after_seq"])
        calls.append(after)
        events = edit([e for e in ledger.events() if e["seq"] > after])[:PAGE_SIZE]
        return httpx.Response(200, json={"log_id": ledger.log_id, "size": ledger.count(), "events": events,
                                         "next_seq": events[-1]["seq"] if len(events) == PAGE_SIZE else None})
    return httpx.AsyncClient(transport=httpx.MockTransport(handler)), calls


def test_drain_pages_forward_until_caught_up_verifying_every_page(tmp_path):
    """Exercises the multi-page catch-up loop directly: more events than one page holds, each page verified
    against the state the previous one left."""
    ledger = AuditLedger(tmp_path / "audit.jsonl")
    for n in range(PAGE_SIZE + 1):
        ledger.append("test", "event", {"n": n})
    client, calls = _serving(ledger)
    registry = _registry(tmp_path)
    target_id = registry.add_target("demo", "https://gw.example", "ptgw_x_y")
    poller = FleetPoller(registry, Broadcaster(), client)

    asyncio.run(poller.run_once())

    assert calls == [-1, PAGE_SIZE - 1]  # two pages fetched in the one cycle
    target = registry.get_target(target_id)
    assert target.status == "ok" and target.last_seq == PAGE_SIZE and target.trust_source == "first use"


def test_a_tampered_event_stops_verification_there_and_nothing_after_it_counts(tmp_path):
    ledger = AuditLedger(tmp_path / "audit.jsonl")
    ledger.append("attacker", "attack", {"id": "t1"})
    ledger.append("oracle", "breach", {"kind": "injection_action"})
    ledger.append("audit", "seal", {"merkle_root": ledger.seal()})

    def hide_the_breach(events):
        return [{**e, "payload": {"kind": "none"}} if e["kind"] == "breach" else e for e in events]

    client, _ = _serving(ledger, hide_the_breach)
    registry = _registry(tmp_path)
    target_id = registry.add_target("demo", "https://gw.example", "ptgw_x_y")
    asyncio.run(FleetPoller(registry, Broadcaster(), client).run_once())

    target = registry.get_target(target_id)
    assert target.status == "untrusted" and "event 1: content altered" in target.last_error
    assert target.last_seq == 0 and registry.get_status(target_id) is None  # no verdict from unverified events


def test_events_signed_by_any_key_but_the_pinned_one_are_refused(tmp_path):
    """A man in the middle (or a swapped gateway) re-signs a whole fabricated log with its own keys."""
    real, forged = AuditLedger(tmp_path / "real.jsonl"), AuditLedger(tmp_path / "forged.jsonl")
    real.append("audit", "seal", {"merkle_root": real.seal()})
    forged.append("audit", "seal", {"merkle_root": forged.seal()})
    registry = _registry(tmp_path)
    target_id = registry.add_target("demo", "https://gw.example", "ptgw_x_y", trust=real.public_trust())
    client, _ = _serving(forged)

    asyncio.run(FleetPoller(registry, Broadcaster(), client).run_once())

    target = registry.get_target(target_id)
    assert target.trust_source == "operator" and target.status == "untrusted"
    assert "invalid signature or unknown key" in target.last_error


def test_a_target_registered_before_verification_existed_is_pinned_and_verified_from_the_start(tmp_path):
    import sqlite3
    db = tmp_path / "console.db"
    old = sqlite3.connect(db)  # the targets table as it was, without the trust columns
    old.execute("CREATE TABLE targets (id TEXT PRIMARY KEY, name TEXT NOT NULL, base_url TEXT NOT NULL, "
                "admin_key_enc BLOB NOT NULL, log_id TEXT, last_seq INTEGER NOT NULL DEFAULT -1, status TEXT NOT "
                "NULL DEFAULT 'unknown', last_error TEXT, created_at REAL NOT NULL, polled_at REAL)")
    old.commit()
    old.close()
    ledger = AuditLedger(tmp_path / "audit.jsonl")
    ledger.append("test", "event", {"n": 0})
    registry = _registry(tmp_path)
    target_id = registry.add_target("demo", "https://gw.example", "ptgw_x_y")
    client, _ = _serving(ledger)

    asyncio.run(FleetPoller(registry, Broadcaster(), client).run_once())

    assert registry.get_target(target_id).status == "ok"


def test_a_failing_cycle_never_stops_the_poller(tmp_path, monkeypatch):
    registry = _registry(tmp_path)
    poller = FleetPoller(registry, Broadcaster(), httpx.AsyncClient(), interval=0)
    cycles = []

    async def failing_cycle():
        cycles.append(1)
        if len(cycles) == 3:
            raise asyncio.CancelledError
        raise RuntimeError("an unexpected bug")

    monkeypatch.setattr(poller, "run_once", failing_cycle)
    try:
        asyncio.run(poller.run_forever())
    except asyncio.CancelledError:
        pass
    assert len(cycles) == 3  # it kept polling after each failure
