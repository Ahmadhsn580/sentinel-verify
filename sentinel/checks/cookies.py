"""Cookie attribute checks."""

from __future__ import annotations

from ..models import Confidence, Severity, Tier
from ..verify import Engine
from .base import Check, register


def _parse_cookie(raw: str) -> tuple[str, dict[str, str]]:
    parts = [p.strip() for p in raw.split(";")]
    name = parts[0].split("=", 1)[0].strip()
    attrs: dict[str, str] = {}
    for part in parts[1:]:
        key, _, value = part.partition("=")
        attrs[key.strip().lower()] = value.strip()
    return name, attrs


def _cookies(engine: Engine):
    return engine.baseline()


@register
class CookieSecure(Check):
    id = "cookie.secure"
    title = "Cookie without Secure flag"
    cwe = "CWE-614"
    tier = Tier.SAFE
    needs_https = True
    description = "Session cookies transmit over plaintext if the site is downgraded."

    async def run(self, engine: Engine) -> None:
        resp = await _cookies(engine)
        for raw in resp.header_all("set-cookie"):
            name, attrs = _parse_cookie(raw)
            if "secure" in attrs or name.startswith("__Secure-"):
                continue
            engine.record(
                check_id=self.id,
                title=f"Cookie '{name}' missing Secure",
                severity=Severity.MEDIUM,
                confidence=Confidence.CONFIRMED,
                cwe=self.cwe,
                description=f"Set-Cookie for {name} has no Secure attribute.",
                remediation="Add the Secure attribute (and __Secure- prefix for session cookies).",
                response=resp,
            )


@register
class CookieHttpOnly(Check):
    id = "cookie.httponly"
    title = "Cookie without HttpOnly flag"
    cwe = "CWE-1004"
    tier = Tier.SAFE
    description = "Script can read the cookie, so XSS escalates to session theft."

    async def run(self, engine: Engine) -> None:
        resp = await _cookies(engine)
        for raw in resp.header_all("set-cookie"):
            name, attrs = _parse_cookie(raw)
            if "httponly" in attrs or name.startswith("__Host-"):
                continue
            engine.record(
                check_id=self.id,
                title=f"Cookie '{name}' missing HttpOnly",
                severity=Severity.MEDIUM,
                confidence=Confidence.CONFIRMED,
                cwe=self.cwe,
                description=f"Set-Cookie for {name} is readable from JavaScript.",
                remediation="Add HttpOnly to all cookies that are not read client-side.",
                response=resp,
            )


@register
class CookieSameSite(Check):
    id = "cookie.samesite"
    title = "Cookie with weak SameSite"
    cwe = "CWE-1275"
    tier = Tier.SAFE
    description = "Missing or None SameSite leaves the cookie open to cross-site sends."

    async def run(self, engine: Engine) -> None:
        resp = await _cookies(engine)
        for raw in resp.header_all("set-cookie"):
            name, attrs = _parse_cookie(raw)
            same = attrs.get("samesite", "").lower()
            if same in ("strict", "lax"):
                continue
            if same == "none" and "secure" in attrs:
                continue
            engine.record(
                check_id=self.id,
                title=f"Cookie '{name}' SameSite={same or 'unset'}",
                severity=Severity.LOW,
                confidence=Confidence.CONFIRMED,
                cwe=self.cwe,
                description=f"Cookie {name} is sent on cross-site requests.",
                remediation="Set SameSite=Lax (or Strict) unless cross-site use is required.",
                response=resp,
            )


@register
class CookiePrefix(Check):
    id = "cookie.prefix"
    title = "Session cookie without a hardening prefix"
    cwe = "CWE-16"
    tier = Tier.STANDARD
    needs_https = True
    description = "Session-looking cookies lack __Host- / __Secure- enforcement."

    async def run(self, engine: Engine) -> None:
        resp = await _cookies(engine)
        for raw in resp.header_all("set-cookie"):
            name, attrs = _parse_cookie(raw)
            lowered = name.lower()
            if not any(token in lowered for token in ("sess", "auth", "token", "sid", "jwt")):
                continue
            if name.startswith(("__Host-", "__Secure-")):
                continue
            engine.record(
                check_id=self.id,
                title=f"Session cookie '{name}' has no security prefix",
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                cwe=self.cwe,
                description="Prefixes make the browser enforce Secure/Path/Domain constraints.",
                remediation="Rename to __Host-<name> with Path=/ and no Domain attribute.",
                response=resp,
            )