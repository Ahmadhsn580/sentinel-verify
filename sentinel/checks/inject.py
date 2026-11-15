"""Injection verification: XSS, SQLi, CRLF, traversal."""

from __future__ import annotations

import random
import re
import string
from urllib.parse import parse_qsl, quote, urlencode, urlsplit

from ..http import HttpError
from ..models import Confidence, Severity, Tier
from ..verify import Engine
from .base import Check, register


def _token(n: int = 8) -> str:
    return "".join(random.choice(string.ascii_lowercase) for _ in range(n))


def _replace_param(url: str, key: str, value: str) -> str:
    parts = urlsplit(url)
    pairs = [(k, value if k == key else v) for k, v in parse_qsl(parts.query, keep_blank_values=True)]
    return parts._replace(query=urlencode(pairs)).geturl()


def _params(engine: Engine) -> list[str]:
    return [k for k, _ in parse_qsl(engine.target.query, keep_blank_values=True)]


@register
class ReflectedXss(Check):
    id = "inj.xss_reflected"
    title = "Reflected cross-site scripting"
    cwe = "CWE-79"
    tier = Tier.STANDARD
    description = "A unique marker is reflected unescaped into an executable context."

    async def run(self, engine: Engine) -> None:
        for param in _params(engine)[:5]:
            marker = _token()
            payload = f"{marker}<svg/onload=alert(1)>"
            url = _replace_param(engine.target.url, param, payload)
            try:
                resp = await engine.fetch(url)
            except HttpError:
                continue
            body = resp.text
            if marker not in body:
                continue
            raw = f"{marker}<svg/onload=alert(1)>" in body
            encoded = f"{marker}&lt;svg" in body
            if not raw:
                if not encoded:
                    continue
                engine.record(
                    check_id=f"{self.id}.encoded.{param}",
                    title=f"Reflected value HTML-escaped in '{param}'",
                    severity=Severity.INFO,
                    confidence=Confidence.CONFIRMED,
                    cwe=self.cwe,
                    description="Marker reflected with entities intact; escaping appears correct.",
                    remediation="Confirm the sink context; keep escaping output-encoding.",
                    response=resp,
                )
                continue
            content_type = (resp.header("content-type") or "").lower()
            if "html" not in content_type:
                continue
            engine.record(
                check_id=f"{self.id}.{param}",
                title=f"Reflected XSS via '{param}'",
                severity=Severity.HIGH,
                confidence=Confidence.CONFIRMED,
                cwe=self.cwe,
                description=f"Payload {payload!r} appears verbatim in the HTML response.",
                remediation="HTML-encode reflected values; pair with a nonce-based CSP.",
                response=resp,
            )


@register
class ErrorBasedSqli(Check):
    id = "inj.sqli_error"
    title = "SQL injection (error based)"
    cwe = "CWE-89"
    tier = Tier.STANDARD
    description = "A quote breaks the query and a driver error surfaces."

    async def run(self, engine: Engine) -> None:
        patterns = re.compile(
            r"(SQL syntax|mysqli?_|ORA-\d{4,5}|PostgreSQL.*ERROR|SQLite3?::|"
            r"unclosed quotation mark|SequelizeDatabaseError|SQLSTATE)",
            re.IGNORECASE,
        )
        for param in _params(engine)[:5]:
            for suffix in ("'", '"'):
                url = _replace_param(engine.target.url, param, f"sv{_token(4)}{suffix}")
                try:
                    resp = await engine.fetch(url)
                except HttpError:
                    continue
                match = patterns.search(resp.text)
                if not match:
                    continue
                engine.record(
                    check_id=f"{self.id}.{param}",
                    title=f"SQL error surfaced via '{param}'",
                    severity=Severity.HIGH,
                    confidence=Confidence.LIKELY,
                    cwe=self.cwe,
                    description=f"Driver error signature matched: {match.group(0)}",
                    remediation="Use parameterized queries and suppress driver errors in production.",
                    response=resp,
                )
                return


@register
class TimeBasedSqli(Check):
    id = "inj.sqli_time"
    title = "SQL injection (time based)"
    cwe = "CWE-89"
    tier = Tier.AGGRESSIVE
    description = "Blind payload introduces a reproducible multi-second delay."

    PAYLOADS = (
        "' AND SLEEP(3)-- -",
        "'; SELECT pg_sleep(3)-- -",
        "'; WAITFOR DELAY '0:0:3'-- -",
    )

    async def run(self, engine: Engine) -> None:
        params = _params(engine)
        if not params:
            return
        param = params[0]
        for payload in self.PAYLOADS:
            url = _replace_param(engine.target.url, param, payload)
            try:
                base, probed = await engine.timing_samples(
                    lambda u=url: engine.fetch(u, timeout=20.0), samples=3
                )
            except HttpError:
                continue
            if engine.delay_is_significant(base, probed, floor=0.8):
                resp = await engine.fetch(url, timeout=20.0)
                engine.record(
                    check_id=f"{self.id}.{param}",
                    title=f"Time-based SQLi via '{param}'",
                    severity=Severity.HIGH,
                    confidence=Confidence.CONFIRMED,
                    cwe=self.cwe,
                    description=(
                        f"Probe mean {sum(probed)/len(probed):.2f}s vs baseline "
                        f"{sum(base)/len(base):.2f}s with payload {payload!r}."
                    ),
                    remediation="Parameterize the query and cap execution time.",
                    response=resp,
                )
                return


@register
class CrlfInjection(Check):
    id = "inj.crlf"
    title = "CRLF / header injection"
    cwe = "CWE-113"
    tier = Tier.STANDARD
    description = "Encoded CRLF in a parameter materializes as a new response header."

    async def run(self, engine: Engine) -> None:
        for param in _params(engine)[:4]:
            token = _token(6)
            payload = f"x%0d%0aX-Sentinel-{token}%3a1"
            url = _replace_param(engine.target.url, param, payload)
            try:
                resp = await engine.fetch(url, follow_redirects=False)
            except HttpError:
                continue
            if resp.header(f"x-sentinel-{token}") is None:
                continue
            engine.record(
                check_id=f"{self.id}.{param}",
                title=f"CRLF injection via '{param}'",
                severity=Severity.MEDIUM,
                confidence=Confidence.CONFIRMED,
                cwe=self.cwe,
                description=f"Header X-Sentinel-{token} was injected into the response.",
                remediation="Strip or encode CR/LF from values copied into headers.",
                response=resp,
            )
            return


@register
class PathTraversal(Check):
    id = "inj.traversal"
    title = "Path traversal"
    cwe = "CWE-22"
    tier = Tier.STANDARD
    description = "A file parameter escapes the intended directory."

    async def run(self, engine: Engine) -> None:
        for param in _params(engine)[:4]:
            url = _replace_param(engine.target.url, param, quote("../../../../etc/passwd", safe=""))
            try:
                resp = await engine.fetch(url)
            except HttpError:
                continue
            text = resp.text
            if "root:x:0:0" not in text and "root:.*:0:0" not in text:
                continue
            engine.record(
                check_id=f"{self.id}.{param}",
                title=f"Path traversal via '{param}'",
                severity=Severity.HIGH,
                confidence=Confidence.CONFIRMED,
                cwe=self.cwe,
                description="/etc/passwd contents returned in the response body.",
                remediation="Canonicalize the resolved path and verify the prefix.",
                response=resp,
            )
            return
