"""TLS transport checks: versions, ciphers, certificates, CT logs."""

from __future__ import annotations

import asyncio
import hashlib
import ssl
from datetime import datetime, timezone

from ..http import HttpError
from ..models import Confidence, Severity, Tier
from ..verify import Engine
from .base import Check, register

DEPRECATED_CIPHERS = ("RC4", "3DES", "DES", "NULL", "EXPORT", "MD5")


@register
class MinTlsVersion(Check):
    id = "tls.min_version"
    title = "Deprecated TLS protocol version accepted"
    cwe = "CWE-326"
    tier = Tier.SAFE
    needs_https = True
    description = "Server still completes a handshake on TLS 1.0 or 1.1."

    async def run(self, engine: Engine) -> None:
        for version, label in (("1.0", "TLS 1.0"), ("1.1", "TLS 1.1")):
            try:
                resp = await engine.fetch(engine.target.url, tls_max=version, tls_min=version)
            except HttpError:
                continue
            engine.record(
                check_id=f"{self.id}.{version.replace('.', '')}",
                title=f"{label} accepted",
                severity=Severity.LOW,
                confidence=Confidence.CONFIRMED,
                cwe=self.cwe,
                description=f"The server completed a handshake negotiating {label}.",
                remediation="Set the minimum TLS version to 1.2 in the listener configuration.",
                response=resp,
            )
            return


@register
class WeakCiphers(Check):
    id = "tls.weak_ciphers"
    title = "Weak cipher suite negotiated"
    cwe = "CWE-327"
    tier = Tier.STANDARD
    needs_https = True
    description = "Handshake succeeded with a legacy or export-grade cipher."

    async def run(self, engine: Engine) -> None:
        legacy = "AES128-SHA:AES256-SHA:DES-CBC3-SHA:RC4-SHA:RC4-MD5"
        try:
            resp = await engine.fetch(engine.target.url, tls_max="1.2", ciphers=legacy)
        except HttpError:
            return
        cipher = resp.tls_cipher
        if not cipher:
            return
        if any(bad in cipher for bad in DEPRECATED_CIPHERS):
            engine.record(
                check_id=self.id,
                title=f"Weak cipher negotiated: {cipher}",
                severity=Severity.MEDIUM,
                confidence=Confidence.CONFIRMED,
                cwe=self.cwe,
                description=f"Only legacy ciphers were offered and {cipher} was selected.",
                remediation="Restrict the cipher list to AEAD suites (AES-GCM, CHACHA20).",
                response=resp,
            )


@register
class CertExpiry(Check):
    id = "tls.cert_expiry"
    title = "Certificate validity window problem"
    cwe = "CWE-298"
    tier = Tier.SAFE
    needs_https = True
    description = "Certificate is expired, not yet valid, or expires within 21 days."

    async def run(self, engine: Engine) -> None:
        resp = await engine.fetch(engine.target.url)
        der = resp.peer_cert_der
        if not der:
            return
        try:
            pem = ssl.DER_cert_to_PEM_cert(der)
            decoded = ssl._ssl._test_decode_cert(_write_tmp(pem))  # type: ignore[attr-defined]
        except (ssl.SSLError, OSError):
            return
        not_after = decoded.get("notAfter")
        not_before = decoded.get("notBefore")
        if not not_after:
            return
        expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        days = (expiry - now).days
        if days < 0:
            engine.record(
                check_id=self.id,
                title="TLS certificate expired",
                severity=Severity.HIGH,
                confidence=Confidence.CONFIRMED,
                cwe=self.cwe,
                description=f"Certificate expired {abs(days)} day(s) ago ({not_after}).",
                remediation="Renew and redeploy the certificate.",
                response=resp,
            )
        elif days <= 21:
            engine.record(
                check_id=self.id,
                title=f"TLS certificate expires in {days} day(s)",
                severity=Severity.LOW,
                confidence=Confidence.CONFIRMED,
                cwe=self.cwe,
                description=f"Certificate notAfter is {not_after}; automated renewal may be broken.",
                remediation="Verify ACME/cron renewal is healthy.",
                response=resp,
            )
        if not_before:
            start = datetime.strptime(not_before, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            if start > now:
                engine.record(
                    check_id=f"{self.id}.not_yet_valid",
                    title="TLS certificate not yet valid",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.CONFIRMED,
                    cwe=self.cwe,
                    description=f"Certificate notBefore is {not_before}, in the future.",
                    remediation="Correct the server clock or the issued validity window.",
                    response=resp,
                )


@register
class CertChain(Check):
    id = "tls.cert_chain"
    title = "Certificate chain does not verify"
    cwe = "CWE-295"
    tier = Tier.SAFE
    needs_https = True
    description = "Default trust store rejects the presented chain."

    async def run(self, engine: Engine) -> None:
        try:
            resp = await engine.fetch(engine.target.url, follow_redirects=False)
        except HttpError as exc:
            engine.record(
                check_id=self.id,
                title="TLS chain verification failed",
                severity=Severity.HIGH,
                confidence=Confidence.LIKELY,
                cwe=self.cwe,
                description=f"Handshake failed against the system trust store: {exc}",
                remediation="Serve the full intermediate chain and use a publicly trusted issuer.",
            )
            return
        if not resp.peer_cert_der:
            return
        engine.record(
            check_id=f"{self.id}.spki",
            title="Certificate SPKI recorded",
            severity=Severity.INFO,
            confidence=Confidence.INFO,
            cwe=self.cwe,
            description="Chain verified; SPKI pin captured for future comparison.",
            remediation="Add HPKP-style pinning if the client fleet supports it.",
            response=resp,
            evidence=__import__("sentinel.models", fromlist=["Evidence"]).Evidence(
                note="sha256(spki)=" + hashlib.sha256(resp.peer_cert_der).hexdigest()[:32]
            ),
        )


@register
class SniRequired(Check):
    id = "tls.sni"
    title = "Default virtual host served without SNI"
    cwe = "CWE-16"
    tier = Tier.STANDARD
    needs_https = True
    description = "Connecting by IP without SNI exposes a different (often stale) vhost."

    async def run(self, engine: Engine) -> None:
        import socket

        try:
            infos = await asyncio.get_running_loop().run_in_executor(
                None, socket.getaddrinfo, engine.target.host, 443, socket.AF_INET
            )
        except socket.gaierror:
            return
        if not infos:
            return
        ip = infos[0][4][0]
        url = f"https://{ip}/"
        try:
            resp = await engine.client.request(
                "GET", url, headers=[("Host", engine.target.host)], follow_redirects=False
            )
        except HttpError:
            return
        if resp.status < 500:
            return
        engine.record(
            check_id=self.id,
            title="SNI-less request returns a server error",
            severity=Severity.INFO,
            confidence=Confidence.LIKELY,
            cwe=self.cwe,
            description=f"Direct IP request to {ip} failed with {resp.status}, indicating no default vhost.",
            remediation="Configure an explicit default server block that returns 444 or a valid cert.",
            response=resp,
        )


@register
class CertificateTransparency(Check):
    id = "tls.ct_logs"
    title = "Unexpected subdomains in Certificate Transparency logs"
    cwe = "CWE-200"
    tier = Tier.STANDARD
    needs_https = True
    description = "crt.sh shows hostnames under the same domain that may be forgotten assets."

    async def run(self, engine: Engine) -> None:
        from ..scope import registrable_domain

        domain = registrable_domain(engine.target.host)
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        try:
            resp = await engine.fetch(url, timeout=20.0)
        except HttpError:
            return
        if resp.status != 200:
            return
        try:
            import json

            rows = json.loads(resp.text)
        except ValueError:
            return
        names: set[str] = set()
        for row in rows[:400]:
            for name in str(row.get("name_value", "")).splitlines():
                name = name.strip().lower().lstrip("*.")
                if name.endswith(domain) and name != engine.target.host:
                    names.add(name)
        if not names:
            return
        listed = ", ".join(sorted(names)[:15])
        engine.record(
            check_id=self.id,
            title=f"{len(names)} additional hostname(s) in CT logs",
            severity=Severity.INFO,
            confidence=Confidence.CONFIRMED,
            cwe=self.cwe,
            description=f"Certificate transparency records expose: {listed}",
            remediation="Inventory each name; retire or lock down the ones out of use.",
            response=resp,
        )


def _write_tmp(pem: str) -> str:
    import os
    import tempfile

    fd, path = tempfile.mkstemp(suffix=".pem")
    with os.fdopen(fd, "w") as handle:
        handle.write(pem)
    return path
