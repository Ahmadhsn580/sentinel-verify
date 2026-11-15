"""Host header and cache-key checks."""

from __future__ import annotations

from ..http import HttpError
from ..models import Confidence, Severity, Tier
from ..verify import Engine
from .base import Check, register

EVIL_HOST = "sentinel-probe.example"


@register
class HostHeaderInjection(Check):
    id = "host.header_injection"
    title = "Host header injection"
    cwe = "CWE-20"
    tier = Tier.STANDARD
    description = "The supplied Host value is echoed into absolute URLs or links."

    async def run(self, engine: Engine) -> None:
        try:
            resp = await engine.fetch(
                engine.target.url, headers=[("Host", EVIL_HOST)], follow_redirects=False
            )
        except HttpError:
            return
        location = resp.header("location") or ""
        if EVIL_HOST in location:
            engine.record(
                check_id=f"{self.id}.redirect",
                title="Host header controls the redirect target",
                severity=Severity.MEDIUM,
                confidence=Confidence.CONFIRMED,
                cwe=self.cwe,
                description=f"Location became {location}",
                remediation="Pin the canonical host in configuration; validate Host against an allowlist.",
                response=resp,
            )
            return
        if EVIL_HOST in resp.text:
            engine.record(
                check_id=f"{self.id}.body",
                title="Host header reflected into the page",
                severity=Severity.LOW,
                confidence=Confidence.LIKELY,
                cwe=self.cwe,
                description="Absolute links in the body use the attacker-supplied host.",
                remediation="Emit absolute URLs from a configured canonical host.",
                response=resp,
            )


@register
class CachePoisoning(Check):
    id = "host.cache_poison"
    title = "Cache key does not include a reflected header"
    cwe = "CWE-524"
    tier = Tier.AGGRESSIVE
    description = "An unkeyed header changes the body but is not reflected in cache variance."

    async def run(self, engine: Engine) -> None:
        probes = (
            ("X-Forwarded-Host", EVIL_HOST),
            ("X-Forwarded-Scheme", "http"),
            ("X-Original-URL", "/sentinel-probe"),
        )
        for header, value in probes:
            try:
                resp = await engine.fetch(engine.target.url, headers=[(header, value)])
            except HttpError:
                continue
            if value in resp.text or value in (resp.header("location") or ""):
                engine.record(
                    check_id=f"{self.id}.{header.lower().replace('-', '_')}",
                    title=f"Unkeyed header reflected: {header}",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.LIKELY,
                    cwe=self.cwe,
                    description=f"{header}: {value} changed the response; check cache variance config.",
                    remediation="Add the header to the cache key or normalize it at the edge.",
                    response=resp,
                )


@register
class ForwardedTrust(Check):
    id = "host.xforwarded_trust"
    title = "X-Forwarded-For trusted without validation"
    cwe = "CWE-348"
    tier = Tier.STANDARD
    description = "Spoofed client IP changes rate-limit or access decisions."

    async def run(self, engine: Engine) -> None:
        try:
            resp = await engine.fetch(
                engine.target.url, headers=[("X-Forwarded-For", "203.0.113.77")]
            )
        except HttpError:
            return
        if "203.0.113.77" not in resp.text:
            return
        engine.record(
            check_id=self.id,
            title="X-Forwarded-For echoed into the response",
            severity=Severity.LOW,
            confidence=Confidence.LIKELY,
            cwe=self.cwe,
            description="Client-supplied address is treated as authoritative somewhere in the stack.",
            remediation="Trust XFF only from known proxies; take the right-most trusted hop.",
            response=resp,
        )
