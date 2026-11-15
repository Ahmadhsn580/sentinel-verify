from __future__ import annotations

import pytest

from sentinel.scope import (
    Budget,
    BudgetExceeded,
    RateLimiter,
    ScopePolicy,
    ScopeViolation,
    registrable_domain,
)


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("a.example.com", "example.com"),
        ("example.com", "example.com"),
        ("x.y.example.co.uk", "example.co.uk"),
        ("127.0.0.1", "127.0.0.1"),
    ],
)
def test_registrable_domain(host: str, expected: str) -> None:
    assert registrable_domain(host) == expected


def test_scope_allows_same_registrable_domain() -> None:
    policy = ScopePolicy("www.example.com")
    assert policy.allows("api.example.com")
    with pytest.raises(ScopeViolation):
        policy.assert_allowed("example.net")


def test_scope_blocks_private_by_default() -> None:
    policy = ScopePolicy("127.0.0.1")
    with pytest.raises(ScopeViolation):
        policy.check_target_host("127.0.0.1")


def test_budget_raises_when_exceeded() -> None:
    import asyncio

    budget = Budget(2)
    asyncio.run(budget.spend())
    asyncio.run(budget.spend())
    with pytest.raises(BudgetExceeded):
        asyncio.run(budget.spend())


def test_rate_limiter_serialises() -> None:
    import asyncio
    import time

    async def run() -> float:
        limiter = RateLimiter(20)
        start = time.monotonic()
        for _ in range(5):
            await limiter.acquire()
        return time.monotonic() - start

    assert asyncio.run(run()) >= 0.15