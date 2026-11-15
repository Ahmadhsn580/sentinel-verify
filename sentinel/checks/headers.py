"""Response security header checks."""

from __future__ import annotations

import re

from ..models import Confidence, Severity, Tier
from ..verify import Engine
from .base import Check, register

INSECURE_CSP = ("unsafe-inline", "unsafe-eval", "data:", "*")


@register
class Hsts(Check):
    id = "hdr.hsts"
    title = "HSTS missing or weak"
    cwe = "CWE-319"
    tier = Tier.SAFE
    needs_https = True
    description = "Strict-Transport-Security absent, short, or lacking subDomains."

    async def run(self, engine: Engine) -> None:
        resp = await engine.baseline()
        value = resp.header("strict-transport-security")
        if value is None:
            engine.record(
                check_id=self.id,
                title="HSTS header missing",
                severity=Severity.MEDIUM,
                confidence=Confidence.CONFIRMED,
                cwe=self.cwe,
                description="No Strict-Transport-Security header; the first request can be downgraded.",
                remediation="Send 'Strict-Transport-Security: max-age=31536000; includeSubDomains'.",
                response=resp,
            )
            return
        match = re.search(r"max-age=(\d+)", value)
        age = int(match.group(1)) if match else 0
        if age < 15_552_000:
            engine.record(
                check_id=f"{self.id}.short",
                title=f"HSTS max-age too short ({age}s)",
                severity=Severity.LOW,
                confidence=Confidence.CONFIRMED,
                cwe=self.cwe,
                description=f"max-age below the 180-day preload floor: {value[:120]}",
                remediation="Raise max-age to at least 31536000.",
                response=resp,
            )
        if "includesubdomains" not in value.lower():
            engine.record(
                check_id=f"{self.id}.subdomains",
                title="HSTS lacks includeSubDomains",
                severity=Severity.LOW,
                confidence=Confidence.CONFIRMED,
                cwe=self.cwe,
                description="Subdomains remain downgradable.",
                remediation="Add includeSubDomains once all subdomains serve HTTPS.",
                response=resp,
            )


@register
class Csp(Check):
    id = "hdr.csp"
    title = "Content-Security-Policy missing or permissive"
    cwe = "CWE-1021"
    tier = Tier.SAFE
    description = "No CSP, or a policy relying on unsafe-inline / wildcards."

    async def run(self, engine: Engine) -> None:
        resp = await engine.baseline()
        value = resp.header("content-security-policy")
        if value is None:
            report_only = resp.header("content-security-policy-report-only")
            engine.record(
                check_id=self.id,
                title="CSP header missing" + (" (report-only only)" if report_only else ""),
                severity=Severity.MEDIUM,
                confidence=Confidence.CONFIRMED,
                cwe=self.cwe,
                description="No enforcing CSP, so injected script is unrestricted.",
                remediation="Ship a nonce-based script-src policy, starting in report-only.",
                response=resp,
            )
            return
        lowered = value.lower()
        weak = [token for token in INSECURE_CSP if token in lowered]
        if "script-src" not in lowered:
            weak.append("no script-src")
        if weak:
            engine.record(
                check_id=f"{self.id}.weak",
                title=f"CSP allows weak sources: {', '.join(weak)}",
                severity=Severity.LOW,
                confidence=Confidence.CONFIRMED,
                cwe=self.cwe,
                description=f"Policy weakens XSS mitigation: {value[:200]}",
                remediation="Replace unsafe-inline with nonces/hashes and drop wildcard sources.",
                response=resp,
            )
        if "object-src" not in lowered and "default-src" not in lowered:
            engine.record(
                check_id=f"{self.id}.object_src",
                title="CSP has no object-src or default-src fallback",
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                cwe=self.cwe,
                description="Plugin content is unrestricted.",
                remediation="Add 'object-src 'none''.",
                response=resp,
            )


@register
class FrameAncestors(Check):
    id = "hdr.frame_ancestors"
    title = "Clickjacking protection missing"
    cwe = "CWE-1021"
    tier = Tier.SAFE
    description = "Neither frame-ancestors nor X-Frame-Options constrains framing."

    async def run(self, engine: Engine) -> None:
        resp = await engine.baseline()
        csp = (resp.header("content-security-policy") or "").lower()
        xfo = resp.header("x-frame-options")
        if "frame-ancestors" in csp:
            return
        if xfo and xfo.lower().strip() in ("deny", "sameorigin"):
            return
        engine.record(
            check_id=self.id,
            title="Page can be framed by any origin",
            severity=Severity.MEDIUM,
            confidence=Confidence.CONFIRMED,
            cwe=self.cwe,
            description="No frame-ancestors directive and no usable X-Frame-Options.",
            remediation="Send 'Content-Security-Policy: frame-ancestors 'self''.",
            response=resp,
        )


@register
class ContentTypeOptions(Check):
    id = "hdr.xcto"
    title = "MIME sniffing not disabled"
    cwe = "CWE-430"
    tier = Tier.SAFE
    description = "X-Content-Type-Options is absent."

    async def run(self, engine: Engine) -> None:
        resp = await engine.baseline()
        if resp.header("x-content-type-options"):
            return
        engine.record(
            check_id=self.id,
            title="X-Content-Type-Options missing",
            severity=Severity.LOW,
            confidence=Confidence.CONFIRMED,
            cwe=self.cwe,
            description="Browsers may sniff uploaded content into an executable type.",
            remediation="Send 'X-Content-Type-Options: nosniff'.",
            response=resp,
        )


@register
class ReferrerPolicy(Check):
    id = "hdr.referrer_policy"
    title = "Referrer leakage possible"
    cwe = "CWE-200"
    tier = Tier.SAFE
    description = "No Referrer-Policy, so full URLs may leak cross-origin."

    async def run(self, engine: Engine) -> None:
        resp = await engine.baseline()
        if resp.header("referrer-policy"):
            return
        engine.record(
            check_id=self.id,
            title="Referrer-Policy missing",
            severity=Severity.LOW,
            confidence=Confidence.CONFIRMED,
            cwe=self.cwe,
            description="Sensitive path and query data can leak to third parties.",
            remediation="Send 'Referrer-Policy: strict-origin-when-cross-origin'.",
            response=resp,
        )


@register
class PermissionsPolicy(Check):
    id = "hdr.permissions_policy"
    title = "Permissions-Policy missing"
    cwe = "CWE-16"
    tier = Tier.STANDARD
    description = "Browser features are left enabled by default."

    async def run(self, engine: Engine) -> None:
        resp = await engine.baseline()
        if resp.header("permissions-policy"):
            return
        engine.record(
            check_id=self.id,
            title="Permissions-Policy missing",
            severity=Severity.INFO,
            confidence=Confidence.CONFIRMED,
            cwe=self.cwe,
            description="Camera, microphone and geolocation default to enabled.",
            remediation="Send 'Permissions-Policy: camera=(), microphone=(), geolocation=()'.",
            response=resp,
        )


@register
class InfoDisclosure(Check):
    id = "hdr.info_disclosure"
    title = "Version or technology disclosure in headers"
    cwe = "CWE-200"
    tier = Tier.SAFE
    description = "Server, X-Powered-By or similar leaks precise versions."

    async def run(self, engine: Engine) -> None:
        resp = await engine.baseline()
        leaked = []
        for name in ("server", "x-powered-by", "x-aspnet-version", "x-generator", "via"):
            value = resp.header(name)
            if value and (re.search(r"\d", value) or name != "server"):
                leaked.append(f"{name}: {value}")
        if not leaked:
            return
        engine.record(
            check_id=self.id,
            title=f"Technology disclosed: {len(leaked)} header(s)",
            severity=Severity.INFO,
            confidence=Confidence.CONFIRMED,
            cwe=self.cwe,
            description="; ".join(leaked)[:300],
            remediation="Trim version strings in the server config.",
            response=resp,
        )