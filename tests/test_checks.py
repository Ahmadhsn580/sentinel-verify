from __future__ import annotations

import asyncio

from sentinel.checks.base import all_checks
from sentinel.http import HttpClient
from sentinel.models import ParsedTarget
from sentinel.scope import Budget, RateLimiter, ScopePolicy
from sentinel.verify import Engine, run_checks


def make_engine(url: str) -> Engine:
    target = ParsedTarget.parse(url)
    client = HttpClient(
        policy=ScopePolicy(target.host, allow_private=True),
        budget=Budget(200),
        limiter=RateLimiter(1000),
        concurrency=2,
    )
    return Engine(client, target)


def test_registry_is_populated() -> None:
    registry = all_checks()
    assert "hdr.hsts" in registry
    assert "inj.xss_reflected" in registry
    assert len(registry) > 30


def test_every_check_has_metadata() -> None:
    for check_id, cls in all_checks().items():
        assert cls.title, check_id
        assert cls.cwe.startswith("CWE-"), check_id
        assert cls.description, check_id


def test_header_checks_find_missing_headers(server_url: str) -> None:
    engine = make_engine(server_url + "/")
    registry = all_checks()
    checks = [registry[c]() for c in ("hdr.hsts", "hdr.xcto", "hdr.frame_ancestors")]
    asyncio.run(run_checks(engine, checks, concurrency=1))
    ids = {f.check_id for f in engine.findings}
    assert any(i.startswith("hdr.frame_ancestors") for i in ids)
    assert any(i.startswith("hdr.xcto") for i in ids)


def test_cookie_checks_flag_attributes(server_url: str) -> None:
    engine = make_engine(server_url + "/cookies")
    registry = all_checks()
    asyncio.run(run_checks(engine, [registry["cookie.secure"]()], concurrency=1))
    assert engine.findings


def test_cors_reflection_detected(server_url: str) -> None:
    engine = make_engine(server_url + "/cors")
    registry = all_checks()
    asyncio.run(run_checks(engine, [registry["cors.reflection"]()], concurrency=1))
    assert any("cors" in f.check_id for f in engine.findings)


def test_reflected_xss_detected(server_url: str) -> None:
    engine = make_engine(server_url + "/xss?q=1")
    registry = all_checks()
    asyncio.run(run_checks(engine, [registry["inj.xss_reflected"]()], concurrency=1))
    assert any("xss" in f.check_id for f in engine.findings)
