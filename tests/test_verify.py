from __future__ import annotations

from sentinel.verify import Engine


def test_delay_significance_detects_outlier() -> None:
    assert Engine.delay_is_significant([0.10, 0.11, 0.12], [3.2, 3.1, 3.3])


def test_delay_significance_ignores_noise() -> None:
    assert not Engine.delay_is_significant([0.10, 0.11, 0.12], [0.13, 0.14, 0.15])


def test_delay_significance_needs_samples() -> None:
    assert not Engine.delay_is_significant([0.1], [5.0])


def test_report_counts_and_worst(server_url: str) -> None:
    import asyncio

    from sentinel.http import HttpClient
    from sentinel.models import Confidence, Severity
    from sentinel.scope import Budget, RateLimiter, ScopePolicy
    from sentinel.models import ParsedTarget

    target = ParsedTarget.parse(server_url)
    client = HttpClient(
        policy=ScopePolicy(target.host, allow_private=True),
        budget=Budget(10),
        limiter=RateLimiter(1000),
    )
    engine = Engine(client, target)
    engine.record(
        check_id="x",
        title="t",
        severity=Severity.HIGH,
        confidence=Confidence.CONFIRMED,
        cwe="CWE-1",
        description="d",
        remediation="r",
    )
    report = engine.build_report("now", "safe", "0.0.0")
    assert report.counts()["high"] == 1
    assert report.worst() is Severity.HIGH
    assert report.to_dict()["findings"][0]["fingerprint"]