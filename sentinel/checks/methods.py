"""HTTP method and verb handling checks."""

from __future__ import annotations

from ..http import HttpError
from ..models import Confidence, Severity, Tier
from ..verify import Engine
from .base import Check, register


@register
class Options(Check):
    id = "http.options"
    title = "Advertised methods via OPTIONS"
    cwe = "CWE-16"
    tier = Tier.SAFE
    description = "Allow header reveals write verbs."

    async def run(self, engine: Engine) -> None:
        try:
            resp = await engine.send("OPTIONS", engine.target.url, follow_redirects=False)
        except HttpError:
            return
        allow = resp.header("allow")
        if not allow:
            return
        risky = [m for m in allow.split(",") if m.strip().upper() in ("PUT", "DELETE", "TRACE", "PATCH")]
        if not risky:
            return
        engine.record(
            check_id=self.id,
            title=f"Write methods advertised: {', '.join(risky)}",
            severity=Severity.INFO,
            confidence=Confidence.CONFIRMED,
            cwe=self.cwe,
            description=f"Allow: {allow}",
            remediation="Confirm each advertised verb is authenticated and intended.",
            response=resp,
        )


@register
class Trace(Check):
    id = "http.trace"
    title = "TRACE method enabled"
    cwe = "CWE-693"
    tier = Tier.SAFE
    description = "TRACE can aid cross-site tracing attacks."

    async def run(self, engine: Engine) -> None:
        try:
            resp = await engine.send("TRACE", engine.target.url, follow_redirects=False)
        except HttpError:
            return
        if resp.status != 200 or "TRACE" not in resp.text[:200]:
            return
        engine.record(
            check_id=self.id,
            title="TRACE returns 200 with the request echoed",
            severity=Severity.INFO,
            confidence=Confidence.CONFIRMED,
            cwe=self.cwe,
            description="Server reflects the request line, enabling XST in older clients.",
            remediation="Disable TRACE unless required.",
            response=resp,
        )


@register
class VerbTamper(Check):
    id = "http.verb_tamper"
    title = "Access control differs by verb"
    cwe = "CWE-288"
    tier = Tier.STANDARD
    description = "A non-GET verb returns protected content where GET is challenged."

    async def run(self, engine: Engine) -> None:
        base = await engine.baseline()
        if base.status != 401 and base.status != 403:
            return
        for method in ("POST", "PUT", "PATCH", "HEAD"):
            try:
                resp = await engine.send(method, engine.target.url, follow_redirects=False)
            except HttpError:
                continue
            if resp.status in (200, 201, 204):
                engine.record(
                    check_id=f"{self.id}.{method.lower()}",
                    title=f"{method} bypasses the {base.status} challenge",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.CONFIRMED,
                    cwe=self.cwe,
                    description=f"GET returned {base.status} but {method} returned {resp.status}.",
                    remediation="Apply the auth middleware to all verbs, not just GET.",
                    response=resp,
                )
