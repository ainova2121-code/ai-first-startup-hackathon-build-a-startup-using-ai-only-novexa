"""fetch_events: turns a gateway's /ledger/export HTTP response into a typed ExportPage, or a
typed error -- the poller never has to know httpx's own exception/status-code vocabulary."""

import asyncio

import httpx
import pytest

from purpleteam.console.gateway_client import GatewayAuthError, GatewayUnreachable, fetch_events


def _client(handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def test_a_successful_page_is_parsed():
    def handler(request):
        assert request.url.params["after_seq"] == "-1" and request.url.params["limit"] == "500"
        assert request.headers["authorization"] == "Bearer admin-key"
        return httpx.Response(200, json={"log_id": "abc", "size": 3, "events": [{"seq": 0}], "next_seq": None})

    page = asyncio.run(fetch_events(_client(handler), "https://gw.example", "admin-key"))
    assert (page.log_id, page.size, page.next_seq) == ("abc", 3, None)
    assert page.events == [{"seq": 0}]


def test_a_trailing_slash_on_base_url_does_not_double_up():
    seen = {}

    def handler(request):
        seen["path"] = request.url.path
        return httpx.Response(200, json={"log_id": None, "size": 0, "events": [], "next_seq": None})

    asyncio.run(fetch_events(_client(handler), "https://gw.example/", "k"))
    assert seen["path"] == "/ledger/export"


def test_401_and_403_are_a_gateway_auth_error():
    for status in (401, 403):
        client = _client(lambda request, status=status: httpx.Response(status, json={}))
        with pytest.raises(GatewayAuthError):
            asyncio.run(fetch_events(client, "https://gw.example", "bad-key"))


def test_other_non_200_is_gateway_unreachable():
    client = _client(lambda request: httpx.Response(500, json={}))
    with pytest.raises(GatewayUnreachable):
        asyncio.run(fetch_events(client, "https://gw.example", "k"))


def test_a_connection_error_is_gateway_unreachable():
    def handler(request):
        raise httpx.ConnectError("refused")

    with pytest.raises(GatewayUnreachable):
        asyncio.run(fetch_events(_client(handler), "https://gw.example", "k"))


def test_after_seq_and_limit_are_forwarded():
    def handler(request):
        assert request.url.params["after_seq"] == "9" and request.url.params["limit"] == "2"
        return httpx.Response(200, json={"log_id": None, "size": 0, "events": [], "next_seq": None})

    asyncio.run(fetch_events(_client(handler), "https://gw.example", "k", after_seq=9, limit=2))
