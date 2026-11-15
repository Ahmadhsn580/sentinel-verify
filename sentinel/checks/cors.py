"""CORS misconfiguration checks."""

from __future__ import annotations

from ..models import Confidence, Severity, Tier
from ..verify import Engine
from .base import Check, register

EVIL = "https://sentinel-probe.example"


@register
class CorsReflection(Check):
    id = "cors.reflection"
    title = "Arbitrary origin reflected in CORS"
    cwe = "CWE-942"
    tier = Tier.SAFE
    description = "Access-Control-Allow-Origin echoes the caller's Origin."

    async def run(self, engine: Engine) -> None:
        changed, stable, ev = await engine.differential(
            probe=lambda: engine.fetch(engine.target.url, headers=[("Origin", EVIL)]),
            signal=lambda r: (r.header("access-control-allow-origin") or "").lower(),
        )
        if not changed:
            return
        resp = await engine.fetch(engine.target.url, headers=[("Origin", EVIL)])
        allow = (resp.header("access-control-allow-origin") or "").lower()
        if allow not in (EVIL, "*"):
            return
        creds = (resp.header("access-control-allow-credentials") or "").lower() == "true"
        engine.record(
            check_id=self.id,
            title="Origin reflected with credentials" if creds else "Origin reflected",
            severity=Severity.HIGH if creds else Severity.MEDIUM,
            confidence=Confidence.CONFIRMED if stable else Confidence.LIKELY,
            cwe=self.cwe,
            description=(
                f"ACAO mirrors the supplied Origin ({EVIL}); "
                + ("credentials are allowed, so any site can read authenticated responses." if creds
                   else "authenticated reads still depend on credential mode.")
            ),
            remediation="Validate Origin against an allowlist rather than reflecting blindly.",
            response=resp,
            evidence=ev,
        )


@register
class CorsNullOrigin(Check):
    id = "cors.null_origin"
    title = "Null origin trusted"
    cwe = "CWE-942"
    tier = Tier.STANDARD
    description = "Origin: null is accepted, reachable from sandboxed iframes and file://."

    async def run(self, engine: Engine) -> None:
        resp = await engine.fetch(engine.target.url, headers=[("Origin", "null")])
        allow = (resp.header("access-control-allow-origin") or "").lower()
        if allow != "null":
            return
        engine.record(
            check_id=self.id,
            title="ACAO: null accepted",
            severity=Severity.MEDIUM,
            confidence=Confidence.CONFIRMED,
            cwe=self.cwe,
            description="Any sandboxed iframe or local file can read the response.",
            remediation="Include 'null' only deliberately; prefer a strict allowlist.",
            response=resp,
        )


@register
class CorsWildcardCredentials(Check):
    id = "cors.credentialed_wildcard"
    title = "Wildcard origin with credentials"
    cwe = "CWE-942"
    tier = Tier.STANDARD
    description = "ACAO '*' plus Allow-Credentials true."

    async def run(self, engine: Engine) -> None:
        resp = await engine.fetch(engine.target.url, headers=[("Origin", EVIL)])
        allow = (resp.header("access-control-allow-origin") or "").strip()
        creds = (resp.header("access-control-allow-credentials") or "").lower() == "true"
        if allow != "*" or not creds:
            return
        engine.record(
            check_id=self.id,
            title="ACAO '*' combined with credentials",
            severity=Severity.LOW,
            confidence=Confidence.CONFIRMED,
            cwe=self.cwe,
            description="Wildcard plus credentials works only for cookieless reads; it also cannot be narrowed.",
            remediation="Reflect a validated origin instead of '*' when credentials matter.",
            response=resp,
        )
