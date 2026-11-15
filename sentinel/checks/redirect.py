"""Open redirect checks."""

from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urlsplit

from ..http import HttpError
from ..models import Confidence, Severity, Tier
from ..verify import Engine
from .base import Check, register

REDIRECT_PARAMS = (
    "next", "url", "redirect", "redirect_uri", "return", "returnurl",
    "return_url", "goto", "dest", "destination", "continue", "target",
)
EVIL = "https://sentinel-probe.example/pwned"


def _set_param(url: str, key: str, value: str) -> str:
    parts = urlsplit(url)
    pairs = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True) if k != key]
    pairs.append((key, value))
    return parts._replace(query=urlencode(pairs)).geturl()


@register
class OpenRedirect(Check):
    id = "redir.open"
    title = "Open redirect"
    cwe = "CWE-601"
    tier = Tier.STANDARD
    description = "A parameter drives a redirect to an attacker-controlled origin."

    async def run(self, engine: Engine) -> None:
        params = [k for k, _ in parse_qsl(engine.target.query, keep_blank_values=True)]
        candidates = [p for p in params if p.lower() in REDIRECT_PARAMS] or list(REDIRECT_PARAMS[:6])
        for param in candidates[:6]:
            url = _set_param(engine.target.url, param, EVIL)
            try:
                resp = await engine.fetch(url, follow_redirects=False)
            except HttpError:
                continue
            if resp.status not in (301, 302, 303, 307, 308):
                continue
            location = resp.header("location") or ""
            if "sentinel-probe.example" in location:
                engine.record(
                    check_id=f"{self.id}.{param}",
                    title=f"Open redirect via '{param}'",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.CONFIRMED,
                    cwe=self.cwe,
                    description=f"Redirected to {location} without validation.",
                    remediation="Constrain redirect targets to an allowlist or relative paths only.",
                    response=resp,
                )
                return


@register
class ProtocolRelativeRedirect(Check):
    id = "redir.proto_relative"
    title = "Protocol-relative redirect accepted"
    cwe = "CWE-601"
    tier = Tier.STANDARD
    description = "//evil.tld passes a naive same-origin check."

    async def run(self, engine: Engine) -> None:
        params = [k for k, _ in parse_qsl(engine.target.query, keep_blank_values=True)]
        candidates = [p for p in params if p.lower() in REDIRECT_PARAMS] or list(REDIRECT_PARAMS[:4])
        for param in candidates[:4]:
            url = _set_param(engine.target.url, param, "//sentinel-probe.example/x")
            try:
                resp = await engine.fetch(url, follow_redirects=False)
            except HttpError:
                continue
            if resp.status in (301, 302, 303, 307, 308) and "sentinel-probe.example" in (
                resp.header("location") or ""
            ):
                engine.record(
                    check_id=f"{self.id}.{param}",
                    title=f"Protocol-relative redirect via '{param}'",
                    severity=Severity.LOW,
                    confidence=Confidence.CONFIRMED,
                    cwe=self.cwe,
                    description="Off-host redirect accepted with a scheme-relative target.",
                    remediation="Normalize to absolute URLs and compare parsed hostnames.",
                    response=resp,
                )
                return
