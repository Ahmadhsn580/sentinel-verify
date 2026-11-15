from __future__ import annotations

import asyncio

import pytest

from sentinel.http import HttpClient, HttpError
from sentinel.scope import Budget, BudgetExceeded, RateLimiter, ScopePolicy


def make_client(url: str) -> HttpClient:
    from urllib.parse import urlsplit

    host = urlsplit(url).hostname or "127.0.0.1"
    return HttpClient(
        policy=ScopePolicy(host, allow_private=True),
        budget=Budget(100),
        limiter=RateLimiter(1000),
    )


def test_get_returns_body(server_url: str) -> None:
    client = make_client(server_url)
    resp = asyncio.run(client.request("GET", server_url + "/"))
    assert resp.status == 200
    assert b"hello" in resp.body


def test_header_lookup_is_case_insensitive(server_url: str) -> None:
    client = make_client(server_url)
    resp = asyncio.run(client.request("GET", server_url + "/cookies"))
    assert resp.header("SET-COOKIE") is not None


def test_signature_ignores_date(server_url: str) -> None:
    client = make_client(server_url)
    a = asyncio.run(client.request("GET", server_url + "/"))
    b = asyncio.run(client.request("GET", server_url + "/"))
    assert a.signature() == b.signature()


def test_budget_enforced(server_url: str) -> None:
    client = make_client(server_url)
    client.budget = Budget(1)
    asyncio.run(client.request("GET", server_url + "/"))
    with pytest.raises(BudgetExceeded):
        asyncio.run(client.request("GET", server_url + "/"))


def test_connection_refused() -> None:
    client = HttpClient(
        policy=ScopePolicy("127.0.0.1", allow_private=True),
        budget=Budget(5),
        limiter=RateLimiter(1000),
        retries=0,
        timeout=1.0,
    )
    with pytest.raises(HttpError):
        asyncio.run(client.request("GET", "http://127.0.0.1:1/"))
