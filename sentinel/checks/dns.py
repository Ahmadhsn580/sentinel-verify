"""DNS hygiene and dangling-record checks."""

from __future__ import annotations

import asyncio
import ipaddress
import struct

from ..http import HttpError
from ..models import Confidence, Severity, Tier
from ..scope import registrable_domain
from ..verify import Engine
from .base import Check, register

Q_TYPES = {"A": 1, "AAAA": 28, "CNAME": 5, "NS": 2, "TXT": 16, "CAA": 257, "DS": 43, "MX": 15}

TAKEOVER_FINGERPRINTS = {
    "amazonaws.com": "NoSuchBucket",
    "herokudns.com": "No such app",
    "herokuapp.com": "No such app",
    "github.io": "There isn't a GitHub Pages site here",
    "cloudfront.net": "Bad request",
    "azurewebsites.net": "Error 404",
    "trafficmanager.net": "Not Found",
    "fastly.net": "Fastly error: unknown domain",
    "pantheonsite.io": "The gods are wise",
    "readme.io": "Project doesnt exist",
    "surge.sh": "project not found",
    "bitbucket.io": "Repository not found",
    "netlify.app": "Not Found - Request ID",
    "vercel.app": "The deployment could not be found",
}


class DnsError(Exception):
    pass


def _nameservers() -> list[str]:
    import os

    servers = ["1.1.1.1", "9.9.9.9"]
    for path in ("/etc/resolv.conf", os.environ.get("PREFIX", "") + "/etc/resolv.conf"):
        try:
            with open(path, encoding="utf-8") as handle:
                for line in handle:
                    parts = line.split()
                    if len(parts) >= 2 and parts[0] == "nameserver":
                        try:
                            ipaddress.ip_address(parts[1])
                        except ValueError:
                            continue
                        servers.insert(0, parts[1])
        except OSError:
            continue
    return servers[:3]


def _encode_name(name: str) -> bytes:
    out = b""
    for label in name.rstrip(".").split("."):
        raw = label.encode("idna") if label else b""
        if len(raw) > 63:
            raise DnsError(f"label too long: {label}")
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def _parse_name(buf: bytes, offset: int) -> tuple[str, int]:
    labels: list[str] = []
    jumped = False
    end = offset
    hops = 0
    while True:
        if offset >= len(buf):
            raise DnsError("truncated name")
        length = buf[offset]
        if length == 0:
            offset += 1
            if not jumped:
                end = offset
            break
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(buf):
                raise DnsError("truncated pointer")
            pointer = struct.unpack("!H", buf[offset : offset + 2])[0] & 0x3FFF
            if not jumped:
                end = offset + 2
            offset = pointer
            jumped = True
            hops += 1
            if hops > 32:
                raise DnsError("compression loop")
            continue
        offset += 1
        labels.append(buf[offset : offset + length].decode("idna", errors="replace"))
        offset += length
    return ".".join(labels), end


async def query(name: str, rtype: str, timeout: float = 5.0) -> list[tuple[str, object]]:
    """Return [(kind, value)] answers. kind is A/AAAA/CNAME/TXT/CAA/DS/MX/NS."""
    qtype = Q_TYPES[rtype]
    ident = struct.unpack("!H", b"\x00\x00")[0] | (hash(name) & 0xFFFF)
    header = struct.pack("!HHHHHH", ident, 0x0100, 1, 0, 0, 1)
    question = _encode_name(name) + struct.pack("!HH", qtype, 1)
    edns = b"\x00" + struct.pack("!HHIH", 41, 4096, 0x00008000, 0)
    packet = header + question + edns

    loop = asyncio.get_running_loop()
    last: Exception | None = None
    for server in _nameservers():
        try:
            answers = await asyncio.wait_for(
                _udp_exchange(loop, server, packet, ident, name), timeout=timeout
            )
            return answers
        except (OSError, asyncio.TimeoutError, DnsError) as exc:
            last = exc
            continue
    raise DnsError(f"query failed for {name}/{rtype}: {last}")


async def _udp_exchange(
    loop: asyncio.AbstractEventLoop, server: str, packet: bytes, ident: int, name: str
) -> list[tuple[str, object]]:
    import socket

    family = socket.AF_INET6 if ":" in server else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_DGRAM)
    sock.setblocking(False)
    try:
        await loop.sock_sendto(sock, packet, (server, 53))
        data = await loop.sock_recv(sock, 4096)
    finally:
        sock.close()
    return _parse_response(data, ident, name)


def _parse_response(data: bytes, ident: int, name: str) -> list[tuple[str, object]]:
    if len(data) < 12:
        raise DnsError("short response")
    rid, flags, qd, an, _ns, _ar = struct.unpack("!HHHHHH", data[:12])
    if rid != ident:
        raise DnsError("id mismatch")
    if flags & 0x000F not in (0, 3):
        raise DnsError(f"rcode {flags & 0x000F}")
    offset = 12
    for _ in range(qd):
        _, offset = _parse_name(data, offset)
        offset += 4
    out: list[tuple[str, object]] = []
    for _ in range(an):
        owner, offset = _parse_name(data, offset)
        if offset + 10 > len(data):
            break
        rtype, _rclass, _ttl, rdlen = struct.unpack("!HHIH", data[offset : offset + 10])
        offset += 10
        rdata = data[offset : offset + rdlen]
        offset += rdlen
        if rtype == 1 and rdlen == 4:
            out.append(("A", str(ipaddress.IPv4Address(rdata))))
        elif rtype == 28 and rdlen == 16:
            out.append(("AAAA", str(ipaddress.IPv6Address(rdata))))
        elif rtype in (5, 2):
            target, _ = _parse_name(data, offset - rdlen)
            out.append(("CNAME" if rtype == 5 else "NS", target))
        elif rtype == 16:
            out.append(("TXT", rdata[1:].decode("utf-8", "replace")))
        elif rtype == 257 and len(rdata) >= 2:
            tag_len = rdata[1]
            tag = rdata[2 : 2 + tag_len].decode("ascii", "replace")
            value = rdata[2 + tag_len :].decode("utf-8", "replace")
            out.append(("CAA", (tag, value)))
        elif rtype == 43:
            out.append(("DS", rdata.hex()))
        elif rtype == 15:
            target, _ = _parse_name(data, offset - rdlen)
            out.append(("MX", target))
    return out


def txt_values(answers: list[tuple[str, object]]) -> list[str]:
    return [str(v) for k, v in answers if k == "TXT"]


@register
class Spf(Check):
    id = "dns.spf"
    title = "SPF record missing or permissive"
    cwe = "CWE-290"
    tier = Tier.SAFE
    description = "Domain lacks a hard-fail SPF policy, enabling sender spoofing."

    async def run(self, engine: Engine) -> None:
        domain = registrable_domain(engine.target.host)
        try:
            answers = await query(domain, "TXT")
        except DnsError:
            return
        spf = [v for v in txt_values(answers) if v.startswith("v=spf1")]
        if not spf:
            engine.record(
                check_id=self.id,
                title="No SPF record",
                severity=Severity.MEDIUM,
                confidence=Confidence.CONFIRMED,
                cwe=self.cwe,
                description=f"{domain} publishes no SPF TXT record.",
                remediation=f"Publish 'v=spf1 ... -all' for {domain}.",
            )
            return
        record = spf[0]
        if record.rstrip().endswith(("~all", "?all", "+all")):
            engine.record(
                check_id=f"{self.id}.softfail",
                title="SPF uses a soft or permissive qualifier",
                severity=Severity.LOW,
                confidence=Confidence.CONFIRMED,
                cwe=self.cwe,
                description=f"SPF record ends with a non-hard-fail qualifier: {record[:160]}",
                remediation="Change the terminal mechanism to -all once senders are enumerated.",
            )
        if record.count(" ") > 10:
            engine.record(
                check_id=f"{self.id}.lookups",
                title="SPF record likely exceeds the 10-DNS-lookup limit",
                severity=Severity.LOW,
                confidence=Confidence.LIKELY,
                cwe=self.cwe,
                description=f"Record contains {record.count(' ')} mechanisms.",
                remediation="Flatten or split the record across subdomains.",
            )


@register
class Dmarc(Check):
    id = "dns.dmarc"
    title = "DMARC record missing"
    cwe = "CWE-290"
    tier = Tier.SAFE
    description = "No DMARC policy means receivers cannot enforce alignment."

    async def run(self, engine: Engine) -> None:
        domain = registrable_domain(engine.target.host)
        try:
            answers = await query(f"_dmarc.{domain}", "TXT")
        except DnsError:
            answers = []
        records = [v for v in txt_values(answers) if v.startswith("v=DMARC1")]
        if not records:
            engine.record(
                check_id=self.id,
                title="No DMARC record",
                severity=Severity.MEDIUM,
                confidence=Confidence.CONFIRMED,
                cwe=self.cwe,
                description=f"_dmarc.{domain} has no DMARC TXT record.",
                remediation="Publish 'v=DMARC1; p=quarantine; rua=mailto:dmarc@...' and ramp to p=reject.",
            )
            return
        if "p=none" in records[0]:
            engine.record(
                check_id=f"{self.id}.monitor_only",
                title="DMARC policy is p=none",
                severity=Severity.LOW,
                confidence=Confidence.CONFIRMED,
                cwe=self.cwe,
                description="DMARC is monitor-only, so spoofed mail is still delivered.",
                remediation="Move to p=quarantine then p=reject after reviewing aggregate reports.",
            )


@register
class Dkim(Check):
    id = "dns.dkim"
    title = "No common DKIM selector found"
    cwe = "CWE-290"
    tier = Tier.STANDARD
    description = "Probes a small set of default selectors for DKIM keys."

    async def run(self, engine: Engine) -> None:
        domain = registrable_domain(engine.target.host)
        for selector in ("default", "google", "selector1", "selector2", "k1", "s1", "mail"):
            try:
                answers = await query(f"{selector}._domainkey.{domain}", "TXT")
            except DnsError:
                continue
            if any("p=" in v for v in txt_values(answers)):
                return
        engine.record(
            check_id=self.id,
            title="No DKIM key on common selectors",
            severity=Severity.LOW,
            confidence=Confidence.LIKELY,
            cwe=self.cwe,
            description=f"None of default/google/selector1/selector2/k1/s1/mail resolved for {domain}.",
            remediation="Publish a DKIM key and sign outbound mail; confirm the selector name.",
        )


@register
class Caa(Check):
    id = "dns.caa"
    title = "No CAA record"
    cwe = "CWE-295"
    tier = Tier.STANDARD
    description = "Any CA may issue for this domain without a CAA restriction."

    async def run(self, engine: Engine) -> None:
        domain = registrable_domain(engine.target.host)
        try:
            answers = await query(domain, "CAA")
        except DnsError:
            return
        if any(k == "CAA" for k, _ in answers):
            return
        engine.record(
            check_id=self.id,
            title="No CAA record restricts issuance",
            severity=Severity.LOW,
            confidence=Confidence.CONFIRMED,
            cwe=self.cwe,
            description=f"{domain} has no CAA record.",
            remediation="Add 'CAA 0 issue \"letsencrypt.org\"' (and iodef) for your CAs only.",
        )


@register
class Dnssec(Check):
    id = "dns.dnssec"
    title = "DNSSEC not enabled"
    cwe = "CWE-350"
    tier = Tier.STANDARD
    description = "No DS record at the parent, so responses are unsigned."

    async def run(self, engine: Engine) -> None:
        domain = registrable_domain(engine.target.host)
        try:
            answers = await query(domain, "DS")
        except DnsError:
            return
        if any(k == "DS" for k, _ in answers):
            return
        engine.record(
            check_id=self.id,
            title="Zone is not DNSSEC signed",
            severity=Severity.INFO,
            confidence=Confidence.LIKELY,
            cwe=self.cwe,
            description=f"No DS record found for {domain}.",
            remediation="Enable DNSSEC at the registrar and publish DS at the parent zone.",
        )


@register
class DanglingCname(Check):
    id = "dns.dangling_cname"
    title = "Potential subdomain takeover"
    cwe = "CWE-350"
    tier = Tier.STANDARD
    description = "CNAME points at a SaaS provider whose claim page is unclaimed."

    async def run(self, engine: Engine) -> None:
        try:
            answers = await query(engine.target.host, "CNAME")
        except DnsError:
            return
        targets = [str(v) for k, v in answers if k == "CNAME"]
        if not targets:
            return
        for target in targets:
            for suffix, marker in TAKEOVER_FINGERPRINTS.items():
                if not target.endswith(suffix):
                    continue
                try:
                    resp = await engine.fetch(f"http://{target}/", timeout=12.0)
                except HttpError:
                    continue
                if marker.lower() in resp.text.lower():
                    engine.record(
                        check_id=self.id,
                        title=f"Subdomain takeover candidate via {suffix}",
                        severity=Severity.HIGH,
                        confidence=Confidence.CONFIRMED,
                        cwe=self.cwe,
                        description=(
                            f"{engine.target.host} CNAMEs to {target}, which returns the "
                            f"unclaimed-app marker {marker!r}."
                        ),
                        remediation="Register the resource at the provider or remove the CNAME.",
                        response=resp,
                    )
                    return