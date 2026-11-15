"""Stack, WAF and CVE-candidate fingerprinting."""

from __future__ import annotations

import re

from ..models import Confidence, Severity, Tier
from ..verify import Engine
from .base import Check, register

WAF_SIGNATURES = {
    "cloudflare": "cloudflare",
    "akamai": "akamai",
    "imperva": "incap_ses",
    "sucuri": "x-sucuri-id",
    "fastly": "fastly",
    "aws waf": "awswaf",
}

CVE_TABLE = {
    "php/7.0": ("CVE-2019-11043", "PHP-FPM underflow RCE"),
    "php/7.1": ("CVE-2019-11043", "PHP-FPM underflow RCE"),
    "apache/2.4.49": ("CVE-2021-41773", "Apache path traversal"),
    "apache/2.4.50": ("CVE-2021-42013", "Apache path traversal"),
    "nginx/1.20": ("CVE-2021-23017", "nginx resolver off-by-one"),
    "openssh/8.2": ("CVE-2020-14145", "OpenSSH host key leak"),
    "jquery/1.12": ("CVE-2020-11022", "jQuery XSS in htmlPrefilter"),
    "jquery/2.2": ("CVE-2020-11022", "jQuery XSS in htmlPrefilter"),
}


@register
class StackFingerprint(Check):
    id = "fp.stack"
    title = "Technology stack fingerprint"
    cwe = "CWE-200"
    tier = Tier.SAFE
    description = "Server and framework versions identified from headers and cookies."

    async def run(self, engine: Engine) -> None:
        resp = await engine.baseline()
        found = []
        for name in ("server", "x-powered-by", "x-aspnet-version", "x-runtime", "x-generator"):
            value = resp.header(name)
            if value:
                found.append(f"{name}: {value}")
        for raw in resp.header_all("set-cookie"):
            cookie_name = raw.split("=", 1)[0].strip().lower()
            if cookie_name in ("phpsessid", "jsessionid", "asp.net_sessionid", "laravel_session"):
                found.append(f"cookie: {cookie_name}")
        if not found:
            return
        engine.record(
            check_id=self.id,
            title=f"Stack identified ({len(found)} signals)",
            severity=Severity.INFO,
            confidence=Confidence.CONFIRMED,
            cwe=self.cwe,
            description="; ".join(found)[:300],
            remediation="Match versions against CVE feeds and patch on a schedule.",
            response=resp,
        )


@register
class WafDetection(Check):
    id = "fp.waf"
    title = "Edge protection present"
    cwe = "CWE-693"
    tier = Tier.SAFE
    description = "A WAF or CDN signature is visible; useful context for later findings."

    async def run(self, engine: Engine) -> None:
        resp = await engine.baseline()
        blob = " ".join(f"{k}: {v}" for k, v in resp.headers).lower() + resp.text[:2000].lower()
        for label, signature in WAF_SIGNATURES.items():
            if signature in blob:
                engine.record(
                    check_id=f"{self.id}.{label.replace(' ', '_')}",
                    title=f"Edge protection detected: {label}",
                    severity=Severity.INFO,
                    confidence=Confidence.LIKELY,
                    cwe=self.cwe,
                    description=f"Signature {signature!r} present in the response.",
                    remediation="Verify WAF rules are in blocking, not monitor, mode.",
                    response=resp,
                )
                return


@register
class CveCandidates(Check):
    id = "fp.cve_candidates"
    title = "CVE candidates for the detected version"
    cwe = "CWE-1395"
    tier = Tier.STANDARD
    description = "Detected version matches a known-vulnerable release range."

    async def run(self, engine: Engine) -> None:
        resp = await engine.baseline()
        banner = (resp.header("server") or "").lower()
        powered = (resp.header("x-powered-by") or "").lower()
        haystack = f"{banner} {powered}"
        if not haystack.strip():
            return
        for needle, (cve, summary) in CVE_TABLE.items():
            if needle in haystack:
                engine.record(
                    check_id=f"{self.id}.{cve.lower()}",
                    title=f"{cve} candidate: {summary}",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.LIKELY,
                    cwe=self.cwe,
                    description=f"Banner '{haystack.strip()}' matches the affected range.",
                    remediation=f"Confirm the exact build against {cve} and patch.",
                    response=resp,
                )


@register
class ServerErrorLeak(Check):
    id = "fp.error_leak"
    title = "Stack trace leaked on error"
    cwe = "CWE-209"
    tier = Tier.STANDARD
    description = "A malformed path surfaces framework internals."

    async def run(self, engine: Engine) -> None:
        from .inject import _token

        url = engine.target.with_path(f"/sentinel-{_token(10)}")
        try:
            resp = await engine.fetch(url)
        except Exception:
            return
        if resp.status != 500:
            return
        if not re.search(r"(Traceback|at [\w.]+\(|Stack trace|Fatal error)", resp.text):
            return
        engine.record(
            check_id=self.id,
            title="500 response exposes a stack trace",
            severity=Severity.LOW,
            confidence=Confidence.CONFIRMED,
            cwe=self.cwe,
            description="Internal paths, framework names or line numbers are visible.",
            remediation="Serve a generic 500 page and log details server-side.",
            response=resp,
        )
